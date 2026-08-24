package update

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"atum/cli/config"
)

const (
	openSearchNamespace = "opensearch"
	operatorNamespace   = "opensearch-operator"
	fluentBitNamespace  = "fluentbit"
	openSearchPort      = 9200
)

// currentWrapperContractValues keeps a pre-migration artifact baseline
// renderable when the operational values have enabled wrappers but the stale
// lock has not yet acquired its Big-Bang-owned support source. Wrapper charts
// contain no application containers, so excluding those unresolved releases
// preserves the existing runtime image contract while the candidate performs
// the ownership cutover.
func currentWrapperContractValues(
	values map[string]any,
	platform config.Platform,
	supportSources []config.SupportSource,
) (map[string]any, error) {
	consumers, err := config.ActiveWrapperConsumers(platform, values)
	if err != nil || len(consumers) == 0 || len(supportSources) != 0 {
		return values, err
	}
	result := cloneMap(values)
	if err := setScalar(result, "wrapper.sourceType", "helmRepo"); err != nil {
		return nil, err
	}
	for _, consumer := range consumers {
		if err := setNestedValue(result, consumer.ValuesPath+".wrapper.enabled", false); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// validatePlatformMeshContract defines compatibility in rendered behavior.
// Big Bang remains authoritative for integrated packages and for the wrapper
// values passed to external chart releases.
func validatePlatformMeshContract(
	bigBang resolvedGit,
	platform config.Platform,
	packages []resolvedPackage,
	supportSources []resolvedSupportSource,
	values map[string]any,
	kubernetesVersion string,
) error {
	consumers, err := config.ActiveWrapperConsumers(platform, values)
	if err != nil {
		return err
	}
	networkPoliciesEnabled, _ := mapAt(values, "networkPolicies")["enabled"].(bool)
	if len(consumers) == 0 && !networkPoliciesEnabled {
		return nil
	}
	if len(consumers) != 0 && len(consumers) != 2 {
		return fmt.Errorf("wrapper mesh contract requires exactly two active consumers, rendered %d", len(consumers))
	}
	var support resolvedSupportSource
	if len(consumers) != 0 {
		support, err = activeWrapperSupport(supportSources)
		if err != nil {
			return err
		}
	}
	collector := newReleaseValueCollector("bigbang").captureResources()
	if _, err := renderChart(
		filepath.Join(bigBang.Checkout, "chart"),
		kubernetesVersion,
		values,
		collector,
		releaseOptions("bigbang", "bigbang"),
		nil,
	); err != nil {
		return fmt.Errorf("render selected Big Bang mesh contract: %w", err)
	}
	if networkPoliciesEnabled {
		controlPlaneCIDR, _ := mapAt(values, "networkPolicies")["controlPlaneCidr"].(string)
		if err := validateIstiodWebhookIngress(
			collector, packages, kubernetesVersion, controlPlaneCIDR); err != nil {
			return err
		}
	}
	if len(consumers) == 0 {
		return nil
	}
	if err := validateSharedWrapperSource(collector, platform.Sources, support.Support); err != nil {
		return err
	}
	if err := validateWrapperReleaseTopology(collector, consumers, support.Support); err != nil {
		return err
	}
	for _, namespace := range []string{fluentBitNamespace, operatorNamespace, openSearchNamespace} {
		if !hasInjectedNamespace(collector.rendered, namespace) {
			return fmt.Errorf("selected Big Bang does not enable Istio injection for namespace %s", namespace)
		}
	}

	for _, consumer := range consumers {
		release, err := exactRenderedRelease(collector, consumer.ReleaseName, consumer.Namespace)
		if err != nil {
			return err
		}
		releaseValues, err := collector.resolveReleaseValues(release)
		if err != nil {
			return fmt.Errorf("resolve %s values: %w", consumer.ReleaseName, err)
		}
		rendered := newReleaseValueCollector(consumer.Namespace).captureResources()
		inspection, err := renderChart(
			filepath.Join(support.Checkout, filepath.FromSlash(support.Support.ChartPath)),
			kubernetesVersion,
			releaseValues,
			rendered,
			releaseOptions(release.releaseName, consumer.Namespace),
			release.postRenderers,
		)
		if err != nil {
			return fmt.Errorf("render %s contract: %w", consumer.ReleaseName, err)
		}
		if len(inspection.Images) != 0 {
			return fmt.Errorf("%s wrapper introduced runtime images", consumer.ReleaseName)
		}
		if err := validateNamespaceWrapper(rendered.rendered, consumer.Namespace); err != nil {
			return fmt.Errorf("%s: %w", consumer.ReleaseName, err)
		}
		switch consumer.Namespace {
		case operatorNamespace:
			cidr, _ := mapAt(values, "networkPolicies")["controlPlaneCidr"].(string)
			if !hasControlPlaneEgress(rendered.rendered, cidr) {
				return fmt.Errorf("%s has no exact control-plane egress policy for %s", consumer.ReleaseName, cidr)
			}
		case openSearchNamespace:
			if !hasOpenSearchIngress(rendered.rendered) {
				return fmt.Errorf("%s has no exact Fluent Bit ingress policy on TCP 9200", consumer.ReleaseName)
			}
			if !hasFluentBitAuthorization(rendered.rendered) {
				return fmt.Errorf("%s has no exact Fluent Bit authorization policy on port 9200", consumer.ReleaseName)
			}
		default:
			return fmt.Errorf("unexpected wrapper namespace %s", consumer.Namespace)
		}
	}

	if err := validateMainReleaseDependencies(collector, consumers); err != nil {
		return err
	}
	if err := validateFluentBitEgress(
		collector, packages, platform.Sources, kubernetesVersion,
	); err != nil {
		return err
	}
	return nil
}

func validateIstiodWebhookIngress(
	bigBang *releaseValueCollector,
	packages []resolvedPackage,
	kubernetesVersion, controlPlaneCIDR string,
) error {
	var pkg *resolvedPackage
	for index := range packages {
		if packages[index].Package.ID == "istiod" {
			pkg = &packages[index]
			break
		}
	}
	if pkg == nil {
		return fmt.Errorf("platform mesh contract requires the Istiod package")
	}
	release, err := exactRenderedRelease(bigBang, "istiod", "bigbang")
	if err != nil {
		return fmt.Errorf("resolve Istiod release: %w", err)
	}
	values, err := bigBang.resolveReleaseValues(release)
	if err != nil {
		return fmt.Errorf("resolve Istiod values: %w", err)
	}
	rendered := newReleaseValueCollector("istio-system").captureResources()
	if _, err := renderChart(
		filepath.Join(pkg.Checkout, "chart"),
		kubernetesVersion,
		values,
		rendered,
		releaseOptions(release.releaseName, "istio-system"),
		release.postRenderers,
	); err != nil {
		return fmt.Errorf("render Istiod admission contract: %w", err)
	}
	if !hasIstiodWebhookIngress(rendered.rendered, controlPlaneCIDR) {
		return fmt.Errorf(
			"Istiod has no exact kube-apiserver ingress policy for %s on TCP 443 and 15017",
			controlPlaneCIDR,
		)
	}
	return nil
}

func activeWrapperSupport(sources []resolvedSupportSource) (resolvedSupportSource, error) {
	if len(sources) != 1 || sources[0].Support.ID != "wrapper" {
		return resolvedSupportSource{}, fmt.Errorf("wrapper mesh contract requires one resolved wrapper support source")
	}
	return sources[0], nil
}

func validateSharedWrapperSource(
	collector *releaseValueCollector,
	registry config.SourceRegistry,
	support config.SupportSource,
) error {
	key := resourceKey{namespace: "bigbang", name: "bigbang-wrapper", kind: "GitRepository"}
	source, found := collector.repositories[key]
	if !found {
		return fmt.Errorf("selected Big Bang rendered no shared wrapper GitRepository")
	}
	count := 0
	for _, resource := range collector.rendered {
		if resource.key == key {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("selected Big Bang rendered %d shared wrapper GitRepositories, require one", count)
	}
	expectedURL := internalSourceURL(registry, registry.UpstreamOrganization, support.ID)
	if normalizedSourceURL(source.url) != normalizedSourceURL(expectedURL) ||
		source.refTag != "" || source.refBranch != support.Source.Branch ||
		source.refCommit != support.Source.Commit {
		return fmt.Errorf(
			"shared wrapper GitRepository does not exactly pin internal source %s at %s/%s",
			expectedURL, support.Source.Branch, support.Source.Commit,
		)
	}
	for candidate := range collector.repositories {
		if candidate.kind == "GitRepository" && strings.HasSuffix(candidate.name, "-wrapper") && candidate != key {
			return fmt.Errorf("selected Big Bang rendered unexpected wrapper source %s/%s", candidate.namespace, candidate.name)
		}
	}
	return nil
}

func validateWrapperReleaseTopology(
	collector *releaseValueCollector,
	consumers []config.WrapperConsumer,
	support config.SupportSource,
) error {
	expected := make(map[resourceKey]config.WrapperConsumer, len(consumers))
	for _, consumer := range consumers {
		expected[resourceKey{namespace: consumer.Namespace, name: consumer.ReleaseName}] = consumer
	}
	count := 0
	for _, releases := range collector.releases {
		for _, release := range releases {
			if !strings.HasSuffix(release.key.name, "-wrapper") {
				continue
			}
			count++
			if _, found := expected[release.key]; !found {
				return fmt.Errorf("selected Big Bang rendered unexpected wrapper HelmRelease %s/%s", release.key.namespace, release.key.name)
			}
			if release.source != (resourceKey{namespace: "bigbang", name: "bigbang-wrapper", kind: "GitRepository"}) ||
				release.chart != support.ChartPath || release.reconcile != "Revision" {
				return fmt.Errorf("wrapper HelmRelease %s/%s has an inexact source binding", release.key.namespace, release.key.name)
			}
			delete(expected, release.key)
		}
	}
	if count != len(consumers) || len(expected) != 0 {
		return fmt.Errorf("selected Big Bang rendered %d canonical wrapper HelmReleases, require %d", count, len(consumers))
	}
	return nil
}

func exactRenderedRelease(collector *releaseValueCollector, name, namespace string) (releaseValues, error) {
	var found []releaseValues
	for _, candidate := range collector.releases[name] {
		if candidate.key.namespace == namespace {
			found = append(found, candidate)
		}
	}
	if len(found) != 1 {
		return releaseValues{}, fmt.Errorf("require exactly one HelmRelease %s/%s, rendered %d", namespace, name, len(found))
	}
	return found[0], nil
}

func validateNamespaceWrapper(resources []renderedResource, namespace string) error {
	if count := countResources(resources, namespace, "PeerAuthentication"); count != 1 {
		return fmt.Errorf("namespace %s rendered %d PeerAuthentications, require one", namespace, count)
	}
	if !hasStrictPeerAuthentication(resources, namespace) {
		return fmt.Errorf("namespace %s has no strict PeerAuthentication", namespace)
	}
	if !hasSameNamespaceAuthorization(resources, namespace) {
		return fmt.Errorf("namespace %s has no same-namespace authorization", namespace)
	}
	required := [...]struct {
		description string
		predicate   func(map[string]any) bool
	}{
		{description: "default deny", predicate: isDefaultDeny},
		{description: "DNS egress", predicate: isDNSEgress},
		{description: "intra-namespace", predicate: isIntraNamespace},
		{description: "Istio sidecar", predicate: isIstioSidecar},
	}
	for _, policy := range required {
		if !hasResource(resources, namespace, "NetworkPolicy", policy.predicate) {
			return fmt.Errorf("namespace %s has no %s network policy", namespace, policy.description)
		}
	}
	expectedAuthorizationPolicies := 1
	if namespace == openSearchNamespace {
		expectedAuthorizationPolicies = 2
	}
	if count := countResources(resources, namespace, "AuthorizationPolicy"); count != expectedAuthorizationPolicies {
		return fmt.Errorf("namespace %s rendered %d AuthorizationPolicies, require %d",
			namespace, count, expectedAuthorizationPolicies)
	}
	if count := countResources(resources, namespace, "NetworkPolicy"); count != 5 {
		return fmt.Errorf("namespace %s rendered %d NetworkPolicies, require five", namespace, count)
	}
	return nil
}

func validateMainReleaseDependencies(
	collector *releaseValueCollector,
	consumers []config.WrapperConsumer,
) error {
	for _, consumer := range consumers {
		release, err := exactRenderedRelease(collector, consumer.PackageKey, consumer.Namespace)
		if err != nil {
			return fmt.Errorf("resolve wrapped package dependency: %w", err)
		}
		required := resourceKey{namespace: consumer.Namespace, name: consumer.ReleaseName}
		if !slices.Contains(release.dependencies, required) {
			return fmt.Errorf("HelmRelease %s/%s does not depend on wrapper %s/%s",
				release.key.namespace, release.key.name, required.namespace, required.name)
		}
	}
	dashboards, err := exactRenderedRelease(collector, "opensearch-dashboards", openSearchNamespace)
	if err != nil {
		return fmt.Errorf("resolve OpenSearch Dashboards dependency: %w", err)
	}
	for _, dependency := range dashboards.dependencies {
		if strings.HasSuffix(dependency.name, "-wrapper") {
			return fmt.Errorf("OpenSearch Dashboards must not depend on a separate wrapper")
		}
	}
	if !slices.Contains(dashboards.dependencies, resourceKey{namespace: openSearchNamespace, name: "opensearch"}) {
		return fmt.Errorf("OpenSearch Dashboards does not depend on OpenSearch")
	}
	return nil
}

func validateFluentBitEgress(
	bigBang *releaseValueCollector,
	packages []resolvedPackage,
	registry config.SourceRegistry,
	kubernetesVersion string,
) error {
	var pkg *resolvedPackage
	for i := range packages {
		if packages[i].Package.ID == "fluent-bit" {
			pkg = &packages[i]
			break
		}
	}
	if pkg == nil {
		return fmt.Errorf("wrapper mesh contract requires the Fluent Bit package")
	}
	bindings, _, err := artifactBindings(
		"", registry, config.Registry{}, []config.Package{pkg.Package}, nil, map[string]any{
			pkg.Package.ValuesPath: map[string]any{
				"git": map[string]any{"path": "chart"},
			},
		}, nil,
	)
	if err != nil {
		return err
	}
	// Preserve the selected Big Bang path declaration instead of assuming the
	// package chart lives at a version-specific location.
	packageRelease, err := exactRenderedRelease(bigBang, "fluentbit", "bigbang")
	if err != nil {
		return fmt.Errorf("resolve Fluent Bit release: %w", err)
	}
	for i := range bindings {
		bindings[i].chart = packageRelease.chart
	}
	instances, err := bigBang.valuesForArtifacts(bindings)
	if err != nil {
		return fmt.Errorf("resolve Fluent Bit policy values: %w", err)
	}
	fluentInstances := instances[pkg.Package.ID]
	if len(fluentInstances) != 1 {
		return fmt.Errorf("require exactly one Fluent Bit release, rendered %d", len(fluentInstances))
	}
	rendered := newReleaseValueCollector(fluentBitNamespace).captureResources()
	if _, err := renderChart(
		filepath.Join(pkg.Checkout, "chart"),
		kubernetesVersion,
		fluentInstances[0].values,
		rendered,
		releaseOptions(fluentInstances[0].name, fluentInstances[0].namespace),
		fluentInstances[0].renderers,
	); err != nil {
		return fmt.Errorf("render Fluent Bit source egress contract: %w", err)
	}
	if !hasFluentBitEgress(rendered.rendered) {
		return fmt.Errorf("Fluent Bit has no exact OpenSearch source egress policy on TCP 9200")
	}
	return nil
}

func hasResource(resources []renderedResource, namespace, kind string, predicate func(map[string]any) bool) bool {
	for _, resource := range resources {
		if resource.key.namespace == namespace && resource.key.kind == kind && predicate(resource.object) {
			return true
		}
	}
	return false
}

func countResources(resources []renderedResource, namespace, kind string) int {
	count := 0
	for _, resource := range resources {
		if resource.key.namespace == namespace && resource.key.kind == kind {
			count++
		}
	}
	return count
}

func hasInjectedNamespace(resources []renderedResource, namespace string) bool {
	for _, resource := range resources {
		if resource.key.kind != "Namespace" || resource.key.name != namespace {
			continue
		}
		metadata := mapAt(resource.object, "metadata")
		return stringAt(metadata, "labels", "istio-injection") == "enabled"
	}
	return false
}

func hasStrictPeerAuthentication(resources []renderedResource, namespace string) bool {
	return hasResource(resources, namespace, "PeerAuthentication", func(object map[string]any) bool {
		return stringAt(mapAt(object, "spec"), "mtls", "mode") == "STRICT"
	})
}

func hasSameNamespaceAuthorization(resources []renderedResource, namespace string) bool {
	return hasResource(resources, namespace, "AuthorizationPolicy", func(object map[string]any) bool {
		spec := mapAt(object, "spec")
		if action, _ := spec["action"].(string); action != "" && action != "ALLOW" {
			return false
		}
		if selector, exists := spec["selector"]; exists && !emptyMap(selector) {
			return false
		}
		rules := mapSlice(spec["rules"])
		if len(rules) != 1 || len(rules[0]) != 1 {
			return false
		}
		from := mapSlice(rules[0]["from"])
		if len(from) != 1 || len(from[0]) != 1 {
			return false
		}
		source := mapAt(from[0], "source")
		namespaces := stringSlice(source["namespaces"])
		return len(source) == 1 && len(namespaces) == 1 && namespaces[0] == namespace
	})
}

func isDefaultDeny(object map[string]any) bool {
	spec := mapAt(object, "spec")
	return emptyMap(spec["podSelector"]) &&
		containsStrings(stringSlice(spec["policyTypes"]), "Ingress", "Egress") &&
		emptySlice(spec["ingress"]) && emptySlice(spec["egress"])
}

func isDNSEgress(object map[string]any) bool {
	for _, rule := range mapSlice(mapAt(object, "spec")["egress"]) {
		for _, port := range mapSlice(rule["ports"]) {
			if portNumber(port["port"]) == 53 && stringAt(port, "protocol") == "UDP" {
				return true
			}
		}
	}
	return false
}

func isIntraNamespace(object map[string]any) bool {
	spec := mapAt(object, "spec")
	return rulesContainEmptyPodSelector(spec["ingress"], "from") &&
		rulesContainEmptyPodSelector(spec["egress"], "to")
}

func isIstioSidecar(object map[string]any) bool {
	for _, rule := range mapSlice(mapAt(object, "spec")["egress"]) {
		if !rulesContainPort([]map[string]any{rule}, 15012, "") {
			continue
		}
		for _, target := range mapSlice(rule["to"]) {
			if stringAt(mapAt(target, "podSelector"), "matchLabels", "istio") == "pilot" {
				return true
			}
		}
	}
	return false
}

func hasControlPlaneEgress(resources []renderedResource, cidr string) bool {
	return cidr != "" && hasResource(resources, operatorNamespace, "NetworkPolicy", func(object map[string]any) bool {
		spec := mapAt(object, "spec")
		if !emptyMap(spec["podSelector"]) || !reflectsOnly(stringSlice(spec["policyTypes"]), "Egress") {
			return false
		}
		rules := mapSlice(spec["egress"])
		if len(rules) != 1 {
			return false
		}
		targets := mapSlice(rules[0]["to"])
		if len(targets) != 1 || len(targets[0]) != 1 {
			return false
		}
		ipBlock := mapAt(targets[0], "ipBlock")
		if stringAt(ipBlock, "cidr") != cidr {
			return false
		}
		except := stringSlice(ipBlock["except"])
		if cidr == "0.0.0.0/0" {
			return len(ipBlock) == 2 && len(except) == 1 && except[0] == "169.254.169.254/32"
		}
		return len(ipBlock) == 1
	})
}

func hasIstiodWebhookIngress(resources []renderedResource, cidr string) bool {
	if cidr == "" {
		return false
	}
	exact := false
	broad := false
	for _, resource := range resources {
		if resource.key.namespace != "istio-system" || resource.key.kind != "NetworkPolicy" {
			continue
		}
		for _, rule := range mapSlice(mapAt(resource.object, "spec")["ingress"]) {
			if !rulesContainPort([]map[string]any{rule}, 443, "TCP") ||
				!rulesContainPort([]map[string]any{rule}, 15017, "TCP") {
				continue
			}
			for _, source := range mapSlice(rule["from"]) {
				sourceCIDR := stringAt(mapAt(source, "ipBlock"), "cidr")
				exact = exact || sourceCIDR == cidr
				broad = broad || sourceCIDR == "0.0.0.0/0"
			}
		}
	}
	return exact && (cidr == "0.0.0.0/0" || !broad)
}

func hasOpenSearchIngress(resources []renderedResource) bool {
	return hasResource(resources, openSearchNamespace, "NetworkPolicy", func(object map[string]any) bool {
		spec := mapAt(object, "spec")
		if !exactAppSelector(spec["podSelector"], "opensearch") ||
			!reflectsOnly(stringSlice(spec["policyTypes"]), "Ingress") {
			return false
		}
		rules := mapSlice(spec["ingress"])
		if len(rules) != 1 || !hasExactPort(rules[0]["ports"], openSearchPort, "TCP") {
			return false
		}
		from := mapSlice(rules[0]["from"])
		return len(from) == 1 &&
			exactLabelSelector(from[0]["namespaceSelector"], "kubernetes.io/metadata.name", fluentBitNamespace) &&
			exactAppSelector(from[0]["podSelector"], "fluent-bit")
	})
}

func hasFluentBitAuthorization(resources []renderedResource) bool {
	const principal = "cluster.local/ns/fluentbit/sa/fluentbit-fluent-bit"
	return hasResource(resources, openSearchNamespace, "AuthorizationPolicy", func(object map[string]any) bool {
		spec := mapAt(object, "spec")
		if action, _ := spec["action"].(string); action != "ALLOW" {
			return false
		}
		if !exactAppSelector(spec["selector"], "opensearch") {
			return false
		}
		rules := mapSlice(spec["rules"])
		if len(rules) != 1 {
			return false
		}
		from := mapSlice(rules[0]["from"])
		to := mapSlice(rules[0]["to"])
		if len(from) != 1 || len(to) != 1 {
			return false
		}
		source := mapAt(from[0], "source")
		principals := stringSlice(source["principals"])
		operation := mapAt(to[0], "operation")
		ports := stringSlice(operation["ports"])
		return len(source) == 1 && len(principals) == 1 && principals[0] == principal &&
			len(operation) == 1 && len(ports) == 1 && ports[0] == strconv.Itoa(openSearchPort)
	})
}

func hasFluentBitEgress(resources []renderedResource) bool {
	return hasResource(resources, fluentBitNamespace, "NetworkPolicy", func(object map[string]any) bool {
		spec := mapAt(object, "spec")
		if !exactAppSelector(spec["podSelector"], "fluent-bit") ||
			!reflectsOnly(stringSlice(spec["policyTypes"]), "Egress") {
			return false
		}
		rules := mapSlice(spec["egress"])
		if len(rules) != 1 || !hasExactPort(rules[0]["ports"], openSearchPort, "TCP") {
			return false
		}
		to := mapSlice(rules[0]["to"])
		return len(to) == 1 &&
			exactLabelSelector(to[0]["namespaceSelector"], "kubernetes.io/metadata.name", openSearchNamespace) &&
			exactAppSelector(to[0]["podSelector"], "opensearch")
	})
}

func exactAppSelector(value any, name string) bool {
	return exactLabelSelector(value, "app.kubernetes.io/name", name)
}

func exactLabelSelector(value any, key, expected string) bool {
	selector, ok := value.(map[string]any)
	if !ok || len(selector) != 1 {
		return false
	}
	labels := mapAt(selector, "matchLabels")
	actual, _ := labels[key].(string)
	return len(labels) == 1 && actual == expected
}

func hasExactPort(value any, port int, protocol string) bool {
	ports := mapSlice(value)
	return len(ports) == 1 && portNumber(ports[0]["port"]) == port &&
		stringAt(ports[0], "protocol") == protocol
}

func reflectsOnly(values []string, expected string) bool {
	return len(values) == 1 && values[0] == expected
}

func rulesContainEmptyPodSelector(raw any, direction string) bool {
	for _, rule := range mapSlice(raw) {
		for _, endpoint := range mapSlice(rule[direction]) {
			if emptyMap(endpoint["podSelector"]) {
				return true
			}
		}
	}
	return false
}

func rulesContainPort(rules []map[string]any, expected int, protocol string) bool {
	for _, rule := range rules {
		for _, port := range mapSlice(rule["ports"]) {
			if portNumber(port["port"]) == expected &&
				(protocol == "" || stringAt(port, "protocol") == protocol) {
				return true
			}
		}
	}
	return false
}

func mapAt(value map[string]any, path ...string) map[string]any {
	current := value
	for _, key := range path {
		next, _ := current[key].(map[string]any)
		if next == nil {
			return map[string]any{}
		}
		current = next
	}
	return current
}

func stringAt(value map[string]any, path ...string) string {
	if len(path) == 0 {
		return ""
	}
	parent := mapAt(value, path[:len(path)-1]...)
	result, _ := parent[path[len(path)-1]].(string)
	return result
}

func mapSlice(value any) []map[string]any {
	raw, _ := value.([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		if object, ok := entry.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func stringSlice(value any) []string {
	switch raw := value.(type) {
	case []any:
		result := make([]string, 0, len(raw))
		for _, entry := range raw {
			if text, ok := entry.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return raw
	default:
		return nil
	}
}

func portNumber(value any) int {
	switch value := value.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		result, _ := strconv.Atoi(value)
		return result
	default:
		return 0
	}
}

func emptyMap(value any) bool {
	mapped, ok := value.(map[string]any)
	return ok && len(mapped) == 0
}

func emptySlice(value any) bool {
	slice, ok := value.([]any)
	return ok && len(slice) == 0
}

func containsStrings(values []string, expected ...string) bool {
	for _, value := range expected {
		if !slices.Contains(values, value) {
			return false
		}
	}
	return true
}
