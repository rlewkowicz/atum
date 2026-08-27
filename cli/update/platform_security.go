package update

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type platformSecurityObservation struct {
	Namespaces            []namespaceSecurityObservation
	Workloads             []workloadSecurityObservation
	Services              []serviceSecurityObservation
	PeerAuthentications   []peerAuthenticationObservation
	AuthorizationPolicies []authorizationPolicyObservation
	NetworkPolicies       []networkPolicyObservation
	ProbeRewrites         []probeRewriteObservation
	Overflow              *renderedResource
}

const (
	maxSecurityResources     = 128
	maxSecurityListItems     = 64
	maxSecurityMetadataItems = 32
	maxSecuritySelectorItems = 16
	maxSecurityStringBytes   = 512
	maxSecurityCommandBytes  = 4096
)

type renderedResource struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Path       string
}

func (r renderedResource) String() string {
	name := r.Name
	if r.Namespace != "" {
		name = r.Namespace + "/" + name
	}
	return r.APIVersion + "/" + r.Kind + " " + name + " at " + r.Path
}

func (r renderedResource) key() string {
	return r.Namespace + "/" + r.Kind + "/" + r.Name + "/" + r.Path
}

type selectorObservation struct {
	Present bool
	Valid   bool
	Labels  map[string]string
}

type namespaceSecurityObservation struct {
	Resource          renderedResource
	InjectionEligible bool
	MetadataValid     bool
}

type workloadSecurityObservation struct {
	Resource           renderedResource
	Selector           selectorObservation
	PodLabels          map[string]string
	Capture            captureObservation
	MetadataValid      bool
	ServiceAccount     string
	HostNetwork        bool
	HostNetworkValid   bool
	StartupPort        int
	ReadinessPort      int
	InitContainerCount int
	ConfigInitCount    int
	InitValid          bool
	ConfigInitLocal    bool
}

type captureObservation struct {
	Values map[string]string
	Valid  bool
}

type serviceSecurityObservation struct {
	Resource renderedResource
	Selector selectorObservation
	Ports    []servicePortObservation
}

type servicePortObservation struct {
	Port            int
	PortValid       bool
	TargetPort      int
	TargetPortValid bool
}

type peerAuthenticationObservation struct {
	Resource   renderedResource
	Selector   selectorObservation
	Mode       string
	ModeValid  bool
	PortModes  []peerPortModeObservation
	PortsValid bool
}

type peerPortModeObservation struct {
	Port int
	Mode string
}

type authorizationPolicyObservation struct {
	Resource     renderedResource
	Selector     selectorObservation
	Action       string
	ActionValid  bool
	RulesPresent bool
	RulesValid   bool
	Rules        []authorizationRuleObservation
}

type authorizationRuleObservation struct {
	FromPresent bool
	FromValid   bool
	From        []authorizationSourceObservation
	ToPresent   bool
	ToValid     bool
	To          []authorizationOperationObservation
	OtherFields bool
}

type authorizationSourceObservation struct {
	PrincipalsPresent bool
	PrincipalsValid   bool
	Principals        []string
	OtherFields       bool
}

type authorizationOperationObservation struct {
	PortsPresent bool
	PortsValid   bool
	Ports        []int
	OtherFields  bool
}

type networkPolicyObservation struct {
	Resource           renderedResource
	Selector           selectorObservation
	PolicyTypesPresent bool
	PolicyTypesValid   bool
	PolicyTypes        []string
	IngressPresent     bool
	IngressValid       bool
	Ingress            []networkRuleObservation
	EgressPresent      bool
	EgressValid        bool
	Egress             []networkRuleObservation
}

type networkRuleObservation struct {
	PeersPresent bool
	PeersValid   bool
	Peers        []networkPeerObservation
	PortsPresent bool
	PortsValid   bool
	Ports        []networkPortObservation
	OtherFields  bool
}

type networkPeerObservation struct {
	NamespaceSelector selectorObservation
	PodSelector       selectorObservation
	IPBlockPresent    bool
	OtherFields       bool
}

type networkPortObservation struct {
	Port            int
	PortValid       bool
	Protocol        string
	ProtocolPresent bool
	ProtocolValid   bool
	OtherFields     bool
}

type probeRewriteObservation struct {
	Resource renderedResource
	Enabled  bool
}

type attributedMeshObservation[T any] struct {
	Artifact string
	Value    T
}

type attributedMeshResource struct {
	Artifact string
	Resource renderedResource
}

type openSearchMeshProjection struct {
	Namespaces            []attributedMeshObservation[namespaceSecurityObservation]
	Workloads             []attributedMeshObservation[workloadSecurityObservation]
	Services              []attributedMeshObservation[serviceSecurityObservation]
	PeerAuthentications   []attributedMeshObservation[peerAuthenticationObservation]
	AuthorizationPolicies []attributedMeshObservation[authorizationPolicyObservation]
	NetworkPolicies       []attributedMeshObservation[networkPolicyObservation]
	ProbeRewrites         []attributedMeshObservation[probeRewriteObservation]
}

var selectedMeshArtifactIDs = [...]string{
	"bigbang",
	"wrapper/wrapper",
	"chart/opensearch",
	"chart/opensearch-dashboards",
	"package/fluentbit",
	"package/istiod",
}

var (
	selectedOpenSearchNamespaceIdentity = renderedResource{
		APIVersion: "v1", Kind: "Namespace", Name: "opensearch",
	}
	selectedFluentBitNamespaceIdentity = renderedResource{
		APIVersion: "v1", Kind: "Namespace", Name: "fluentbit",
	}
	selectedOpenSearchWorkloadIdentity = renderedResource{
		APIVersion: "apps/v1", Kind: "StatefulSet", Namespace: "opensearch",
		Name: "opensearch-cluster-master",
	}
	selectedOpenSearchServiceIdentity = renderedResource{
		APIVersion: "v1", Kind: "Service", Namespace: "opensearch",
		Name: "opensearch-cluster-master",
	}
	selectedFluentBitWorkloadIdentity = renderedResource{
		APIVersion: "apps/v1", Kind: "DaemonSet", Namespace: "fluentbit",
		Name: "fluentbit-fluent-bit",
	}
	selectedDashboardsWorkloadIdentity = renderedResource{
		APIVersion: "apps/v1", Kind: "Deployment", Namespace: "opensearch",
		Name: "opensearch-dashboards",
	}
	selectedOpenSearchPeerIdentity = renderedResource{
		APIVersion: "security.istio.io/v1beta1", Kind: "PeerAuthentication",
		Namespace: "opensearch", Name: "opensearch",
	}
	selectedOpenSearchAuthorizationIdentity = renderedResource{
		APIVersion: "security.istio.io/v1", Kind: "AuthorizationPolicy",
		Namespace: "opensearch", Name: "allow-fluentbit-opensearch",
	}
	selectedOpenSearchIngressIdentity = renderedResource{
		APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy",
		Namespace: "opensearch", Name: "allow-fluentbit-opensearch",
	}
	selectedFluentBitEgressIdentity = renderedResource{
		APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy",
		Namespace: "fluentbit",
		Name:      "allow-egress-from-fluent-bit-to-ns-opensearch-pod-opensearch-tcp-port-9200",
	}
	selectedIstiodValuesIdentity = renderedResource{
		APIVersion: "v1", Kind: "ConfigMap", Namespace: "istio-system",
		Name: "values",
	}
)

func selectedMeshResource(artifact string, resource renderedResource) attributedMeshResource {
	return attributedMeshResource{Artifact: artifact, Resource: resource}
}

func observePlatformSecurity(value any, path string, observation *platformSecurityObservation) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	metadata, _ := object["metadata"].(map[string]any)
	apiVersion, _ := object["apiVersion"].(string)
	kind, _ := object["kind"].(string)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if name == "" {
		return
	}
	resource := renderedResource{
		APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, Path: path,
	}
	if !boundedSecurityStrings(apiVersion, kind, namespace, name, path) {
		observation.reject(resource)
		return
	}
	switch kind {
	case "ConfigMap":
		data, _ := object["data"].(map[string]any)
		merged, _ := data["merged-values"].(string)
		if strings.Contains(merged, `"rewriteAppHTTPProbe"`) {
			if !observation.admit(resource, len(observation.ProbeRewrites)) {
				return
			}
			observation.ProbeRewrites = append(
				observation.ProbeRewrites,
				probeRewriteObservation{
					Resource: resource,
					Enabled:  strings.Contains(merged, `"rewriteAppHTTPProbe": true`),
				},
			)
		}
	case "Namespace":
		if name == "opensearch" || name == "fluentbit" {
			if !observation.admit(resource, len(observation.Namespaces)) {
				return
			}
			eligible, valid := observeInjectionMetadata(metadata)
			observation.Namespaces = append(observation.Namespaces,
				namespaceSecurityObservation{
					Resource:          resource,
					InjectionEligible: eligible,
					MetadataValid:     valid,
				},
			)
		}
	case "Deployment", "DaemonSet", "StatefulSet":
		if namespace != "opensearch" && namespace != "fluentbit" {
			return
		}
		spec, _ := object["spec"].(map[string]any)
		template, _ := spec["template"].(map[string]any)
		podMetadata, _ := template["metadata"].(map[string]any)
		podSpec, _ := template["spec"].(map[string]any)
		workload := workloadSecurityObservation{
			Resource: resource, Selector: observeSelector(spec, "selector"),
			HostNetworkValid: true, InitValid: true,
		}
		workload.PodLabels, workload.MetadataValid = proofStringMap(
			podMetadata["labels"],
			"app.kubernetes.io/name",
			"app.kubernetes.io/instance",
		)
		workload.Capture = observeCaptureMetadata(podMetadata)
		workload.MetadataValid = workload.MetadataValid && workload.Capture.Valid
		workload.ServiceAccount, _ = podSpec["serviceAccountName"].(string)
		workload.MetadataValid = workload.MetadataValid &&
			boundedSecurityStrings(workload.ServiceAccount)
		if raw, found := podSpec["hostNetwork"]; found {
			workload.HostNetwork, workload.HostNetworkValid = raw.(bool)
		}
		containers, containersValid := boundedSecurityMapSlice(podSpec["containers"])
		workload.MetadataValid = workload.MetadataValid && containersValid
		for _, container := range containers {
			if workload.StartupPort == 0 {
				workload.StartupPort = tcpProbePort(container["startupProbe"])
			}
			if workload.ReadinessPort == 0 {
				workload.ReadinessPort = tcpProbePort(container["readinessProbe"])
			}
		}
		initContainers, initValid := boundedSecurityMapSlice(podSpec["initContainers"])
		workload.InitValid = initValid
		workload.InitContainerCount = len(initContainers)
		for _, container := range initContainers {
			containerName, _ := container["name"].(string)
			if !boundedSecurityStrings(containerName) {
				workload.InitValid = false
			}
			if containerName == "configfile" {
				workload.ConfigInitCount++
				workload.ConfigInitLocal, initValid = observeLocalConfigInit(container)
				workload.InitValid = workload.InitValid && initValid
			}
		}
		if observation.admit(resource, len(observation.Workloads)) {
			observation.Workloads = append(observation.Workloads, workload)
		}
	case "Service":
		if namespace != "opensearch" {
			return
		}
		spec, _ := object["spec"].(map[string]any)
		service := serviceSecurityObservation{
			Resource: resource, Selector: observeDirectSelector(spec, "selector"),
		}
		ports, portsValid := boundedSecurityMapSlice(spec["ports"])
		if !portsValid {
			observation.reject(resource)
			return
		}
		for _, value := range ports {
			port, portValid := exactInteger(value["port"])
			targetPort, targetPortValid := exactInteger(value["targetPort"])
			if _, found := value["targetPort"]; !found {
				targetPort, targetPortValid = port, portValid
			}
			service.Ports = append(service.Ports, servicePortObservation{
				Port: port, PortValid: portValid,
				TargetPort: targetPort, TargetPortValid: targetPortValid,
			})
		}
		if observation.admit(resource, len(observation.Services)) {
			observation.Services = append(observation.Services, service)
		}
	case "PeerAuthentication":
		if namespace == "opensearch" {
			spec, _ := object["spec"].(map[string]any)
			if !observation.admit(resource, len(observation.PeerAuthentications)) {
				return
			}
			observation.PeerAuthentications = append(observation.PeerAuthentications,
				observePeerAuthentication(resource, spec),
			)
		}
	case "AuthorizationPolicy":
		if namespace != "opensearch" {
			return
		}
		spec, _ := object["spec"].(map[string]any)
		policy := authorizationPolicyObservation{
			Resource: resource, Selector: observeSelector(spec, "selector"),
		}
		policy.Action, policy.ActionValid = spec["action"].(string)
		policy.ActionValid = policy.ActionValid &&
			boundedSecurityStrings(policy.Action)
		var rules []map[string]any
		policy.RulesPresent, policy.RulesValid, rules =
			observeMapList(spec, "rules")
		for _, rule := range rules {
			policy.Rules = append(policy.Rules, observeAuthorizationRule(rule))
		}
		if observation.admit(resource, len(observation.AuthorizationPolicies)) {
			observation.AuthorizationPolicies = append(observation.AuthorizationPolicies, policy)
		}
	case "NetworkPolicy":
		if namespace != "opensearch" && namespace != "fluentbit" {
			return
		}
		spec, _ := object["spec"].(map[string]any)
		policy := networkPolicyObservation{
			Resource: resource, Selector: observeDirectSelector(spec, "podSelector"),
		}
		policy.PolicyTypesPresent, policy.PolicyTypesValid, policy.PolicyTypes =
			observeStringList(spec, "policyTypes")
		policy.IngressPresent, policy.IngressValid, policy.Ingress =
			observeNetworkRules(spec, "ingress", "from")
		policy.EgressPresent, policy.EgressValid, policy.Egress =
			observeNetworkRules(spec, "egress", "to")
		if observation.admit(resource, len(observation.NetworkPolicies)) {
			observation.NetworkPolicies = append(observation.NetworkPolicies, policy)
		}
	}
}

func (observation *platformSecurityObservation) admit(
	resource renderedResource,
	count int,
) bool {
	if observation.Overflow != nil {
		return false
	}
	if count < maxSecurityResources {
		return true
	}
	copy := resource
	observation.Overflow = &copy
	return false
}

func (observation *platformSecurityObservation) reject(resource renderedResource) {
	if observation.Overflow == nil {
		copy := resource
		observation.Overflow = &copy
	}
}

var captureAnnotationKeys = []string{
	"sidecar.istio.io/inject",
	"sidecar.istio.io/interceptionMode",
	"traffic.sidecar.istio.io/excludeInboundPorts",
	"traffic.sidecar.istio.io/excludeOutboundPorts",
	"traffic.sidecar.istio.io/includeInboundPorts",
	"traffic.sidecar.istio.io/includeOutboundPorts",
	"traffic.sidecar.istio.io/excludeOutboundIPRanges",
	"traffic.sidecar.istio.io/includeOutboundIPRanges",
	"traffic.sidecar.istio.io/kubevirtInterfaces",
	"traffic.sidecar.istio.io/excludeInterfaces",
}

func observeInjectionMetadata(metadata map[string]any) (bool, bool) {
	labels, valid := boundedStringMap(metadata["labels"], maxSecurityMetadataItems)
	if !valid {
		return false, false
	}
	return labels["istio-injection"] == "enabled" || labels["istio.io/rev"] != "", true
}

func observeCaptureMetadata(metadata map[string]any) captureObservation {
	source, present := metadata["annotations"]
	if !present {
		return captureObservation{Valid: true}
	}
	annotations, ok := source.(map[string]any)
	if !ok || len(annotations) > maxSecurityMetadataItems {
		return captureObservation{}
	}
	result := captureObservation{Values: make(map[string]string), Valid: true}
	for _, key := range captureAnnotationKeys {
		value, present := annotations[key]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok || !boundedSecurityStrings(key, text) {
			return captureObservation{}
		}
		result.Values[key] = text
	}
	return result
}

func boundedStringMap(value any, limit int) (map[string]string, bool) {
	source, ok := value.(map[string]any)
	if !ok || len(source) > limit {
		return nil, false
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		text, ok := value.(string)
		if !ok || !boundedSecurityStrings(key, text) {
			return nil, false
		}
		result[key] = text
	}
	return result, true
}

func proofStringMap(value any, retainedKeys ...string) (map[string]string, bool) {
	source, ok := value.(map[string]any)
	if !ok || len(source) > maxSecurityMetadataItems {
		return nil, false
	}
	result := make(map[string]string, len(retainedKeys))
	for key, value := range source {
		text, ok := value.(string)
		if !ok || !boundedSecurityStrings(key, text) {
			return nil, false
		}
		for _, retained := range retainedKeys {
			if key == retained {
				result[key] = text
				break
			}
		}
	}
	return result, true
}

func boundedSecurityMapSlice(value any) ([]map[string]any, bool) {
	if value == nil {
		return nil, true
	}
	source, ok := value.([]any)
	if !ok || len(source) > maxSecurityListItems {
		return nil, false
	}
	result := make([]map[string]any, 0, len(source))
	for _, value := range source {
		mapped, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		result = append(result, mapped)
	}
	return result, true
}

func observeLocalConfigInit(container map[string]any) (bool, bool) {
	foundCopy := false
	total := 0
	for _, field := range []string{"command", "args"} {
		values, valid := boundedSecurityStringSlice(container[field])
		if !valid {
			return false, false
		}
		for _, text := range values {
			total += len(text)
			if total > maxSecurityCommandBytes ||
				strings.Contains(text, "http://") ||
				strings.Contains(text, "https://") ||
				strings.Contains(text, "curl ") ||
				strings.Contains(text, "wget ") {
				return false, total <= maxSecurityCommandBytes
			}
			foundCopy = foundCopy ||
				strings.Contains(text, "cp -r /tmp/configfolder/*  /tmp/config/")
		}
	}
	return foundCopy, true
}

func boundedSecurityStringSlice(value any) ([]string, bool) {
	if value == nil {
		return nil, true
	}
	source, ok := value.([]any)
	if !ok || len(source) > maxSecurityListItems {
		return nil, false
	}
	result := make([]string, 0, len(source))
	for _, value := range source {
		text, ok := value.(string)
		if !ok || !boundedSecurityStrings(text) {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func boundedSecurityStrings(values ...string) bool {
	for _, value := range values {
		if len(value) > maxSecurityStringBytes {
			return false
		}
	}
	return true
}

func observePeerAuthentication(
	resource renderedResource,
	spec map[string]any,
) peerAuthenticationObservation {
	peer := peerAuthenticationObservation{
		Resource:   resource,
		Selector:   observeSelector(spec, "selector"),
		ModeValid:  true,
		PortsValid: true,
	}
	mtls, mtlsPresent := spec["mtls"].(map[string]any)
	if raw, present := spec["mtls"]; present && !mtlsPresent {
		_ = raw
		peer.ModeValid = false
	} else if mtlsPresent {
		peer.Mode, peer.ModeValid = observedMTLSMode(mtls)
	}
	rawPorts, present := spec["portLevelMtls"]
	if !present {
		return peer
	}
	ports, ok := rawPorts.(map[string]any)
	if !ok || len(ports) > maxSecurityListItems {
		peer.PortsValid = false
		return peer
	}
	for rawPort, value := range ports {
		port, err := strconv.Atoi(rawPort)
		mtls, ok := value.(map[string]any)
		mode, valid := observedMTLSMode(mtls)
		if err != nil || port <= 0 || port > 65535 || !ok || !valid {
			peer.PortsValid = false
			continue
		}
		peer.PortModes = append(peer.PortModes, peerPortModeObservation{Port: port, Mode: mode})
	}
	sort.Slice(peer.PortModes, func(i, j int) bool {
		return peer.PortModes[i].Port < peer.PortModes[j].Port
	})
	return peer
}

func observedMTLSMode(value map[string]any) (string, bool) {
	if hasOtherFields(value, "mode") {
		return "", false
	}
	mode, present := value["mode"].(string)
	if !present || !boundedSecurityStrings(mode) {
		return "", false
	}
	switch mode {
	case "UNSET", "DISABLE", "PERMISSIVE", "STRICT":
		return mode, true
	default:
		return mode, false
	}
}

func observeAuthorizationRule(value map[string]any) authorizationRuleObservation {
	rule := authorizationRuleObservation{OtherFields: hasOtherFields(value, "from", "to")}
	var sources []map[string]any
	rule.FromPresent, rule.FromValid, sources = observeMapList(value, "from")
	for _, raw := range sources {
		source, sourceValid := raw["source"].(map[string]any)
		item := authorizationSourceObservation{
			OtherFields: !sourceValid || hasOtherFields(raw, "source") ||
				hasOtherFields(source, "principals"),
		}
		item.PrincipalsPresent, item.PrincipalsValid, item.Principals =
			observeStringList(source, "principals")
		rule.From = append(rule.From, item)
	}
	var operations []map[string]any
	rule.ToPresent, rule.ToValid, operations = observeMapList(value, "to")
	for _, raw := range operations {
		operation, operationValid := raw["operation"].(map[string]any)
		item := authorizationOperationObservation{
			OtherFields: !operationValid || hasOtherFields(raw, "operation") ||
				hasOtherFields(operation, "ports"),
		}
		var ports []string
		item.PortsPresent, item.PortsValid, ports = observeStringList(operation, "ports")
		for _, rawPort := range ports {
			port, err := strconv.Atoi(rawPort)
			if err != nil || port <= 0 {
				item.PortsValid = false
			} else {
				item.Ports = append(item.Ports, port)
			}
		}
		rule.To = append(rule.To, item)
	}
	return rule
}

func observeNetworkRules(
	spec map[string]any, field string, peerField string,
) (bool, bool, []networkRuleObservation) {
	present, valid, values := observeMapList(spec, field)
	rules := make([]networkRuleObservation, 0, len(values))
	for _, value := range values {
		rule := networkRuleObservation{OtherFields: hasOtherFields(value, peerField, "ports")}
		var peers []map[string]any
		rule.PeersPresent, rule.PeersValid, peers = observeMapList(value, peerField)
		for _, raw := range peers {
			_, ipBlockPresent := raw["ipBlock"]
			rule.Peers = append(rule.Peers, networkPeerObservation{
				NamespaceSelector: observeDirectSelector(raw, "namespaceSelector"),
				PodSelector:       observeDirectSelector(raw, "podSelector"),
				IPBlockPresent:    ipBlockPresent,
				OtherFields:       hasOtherFields(raw, "namespaceSelector", "podSelector", "ipBlock"),
			})
		}
		var ports []map[string]any
		rule.PortsPresent, rule.PortsValid, ports = observeMapList(value, "ports")
		for _, raw := range ports {
			port, portValid := exactInteger(raw["port"])
			_, portPresent := raw["port"]
			protocol, protocolPresent := raw["protocol"].(string)
			rule.Ports = append(rule.Ports, networkPortObservation{
				Port: port, PortValid: portPresent && portValid,
				Protocol: protocol, ProtocolPresent: protocolPresent,
				ProtocolValid: !protocolPresent || protocol == "TCP" ||
					protocol == "UDP" || protocol == "SCTP",
				OtherFields: hasOtherFields(raw, "port", "protocol"),
			})
		}
		rules = append(rules, rule)
	}
	return present, valid, rules
}

func observeSelector(parent map[string]any, field string) selectorObservation {
	raw, present := parent[field]
	if !present {
		return selectorObservation{}
	}
	selector, valid := raw.(map[string]any)
	if !valid || hasOtherFields(selector, "matchLabels") {
		return selectorObservation{Present: true}
	}
	if len(selector) == 0 {
		return selectorObservation{Present: true, Valid: true}
	}
	labels, labelsValid := exactStringMap(selector["matchLabels"])
	_, labelsPresent := selector["matchLabels"]
	return selectorObservation{
		Present: true, Valid: labelsPresent && labelsValid, Labels: labels,
	}
}

func observeDirectSelector(parent map[string]any, field string) selectorObservation {
	raw, present := parent[field]
	if !present {
		return selectorObservation{}
	}
	labels, valid := exactStringMap(raw)
	return selectorObservation{Present: true, Valid: valid, Labels: labels}
}

func observeMapList(parent map[string]any, field string) (bool, bool, []map[string]any) {
	raw, present := parent[field]
	if !present {
		return false, true, nil
	}
	values, valid := raw.([]any)
	if !valid {
		return true, false, nil
	}
	if len(values) > maxSecurityListItems {
		return true, false, nil
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		mapped, ok := value.(map[string]any)
		if !ok {
			valid = false
		} else {
			result = append(result, mapped)
		}
	}
	return true, valid, result
}

func observeStringList(parent map[string]any, field string) (bool, bool, []string) {
	raw, present := parent[field]
	if !present {
		return false, true, nil
	}
	values, valid := raw.([]any)
	if !valid {
		return true, false, nil
	}
	if len(values) > maxSecurityListItems {
		return true, false, nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || !boundedSecurityStrings(text) {
			valid = false
		} else {
			result = append(result, text)
		}
	}
	return true, valid, result
}

func exactStringMap(value any) (map[string]string, bool) {
	return boundedStringMap(value, maxSecuritySelectorItems)
}

func hasOtherFields(value map[string]any, permitted ...string) bool {
	if len(value) > len(permitted) {
		return true
	}
	for key := range value {
		found := false
		for _, candidate := range permitted {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func mergePlatformSecurityObservation(
	target *platformSecurityObservation,
	source platformSecurityObservation,
	pathPrefix string,
) {
	if target.Overflow != nil {
		return
	}
	if source.Overflow != nil {
		overflow := *source.Overflow
		overflow.Path = pathPrefix + overflow.Path
		target.Overflow = &overflow
		return
	}
	if !mergeSecurityObservations(
		&target.Namespaces, source.Namespaces, &target.Overflow, pathPrefix,
		func(value *namespaceSecurityObservation) *renderedResource {
			return &value.Resource
		},
	) || !mergeSecurityObservations(
		&target.Workloads, source.Workloads, &target.Overflow, pathPrefix,
		func(value *workloadSecurityObservation) *renderedResource {
			return &value.Resource
		},
	) || !mergeSecurityObservations(
		&target.Services, source.Services, &target.Overflow, pathPrefix,
		func(value *serviceSecurityObservation) *renderedResource {
			return &value.Resource
		},
	) || !mergeSecurityObservations(
		&target.PeerAuthentications, source.PeerAuthentications,
		&target.Overflow, pathPrefix,
		func(value *peerAuthenticationObservation) *renderedResource {
			return &value.Resource
		},
	) || !mergeSecurityObservations(
		&target.AuthorizationPolicies, source.AuthorizationPolicies,
		&target.Overflow, pathPrefix,
		func(value *authorizationPolicyObservation) *renderedResource {
			return &value.Resource
		},
	) || !mergeSecurityObservations(
		&target.NetworkPolicies, source.NetworkPolicies,
		&target.Overflow, pathPrefix,
		func(value *networkPolicyObservation) *renderedResource {
			return &value.Resource
		},
	) {
		return
	}
	mergeSecurityObservations(
		&target.ProbeRewrites, source.ProbeRewrites,
		&target.Overflow, pathPrefix,
		func(value *probeRewriteObservation) *renderedResource {
			return &value.Resource
		},
	)
}

func mergeSecurityObservations[T any](
	target *[]T,
	source []T,
	overflow **renderedResource,
	pathPrefix string,
	resource func(*T) *renderedResource,
) bool {
	if *overflow != nil {
		return false
	}
	available := maxSecurityResources - len(*target)
	if len(source) > available {
		index := available
		if index >= len(source) {
			index = len(source) - 1
		}
		failed := *resource(&source[index])
		failed.Path = pathPrefix + failed.Path
		*overflow = &failed
		return false
	}
	for _, observed := range source {
		copy := observed
		valueResource := resource(&copy)
		valueResource.Path = pathPrefix + valueResource.Path
		*target = append(*target, copy)
	}
	return true
}

func normalizePlatformSecurity(observation *platformSecurityObservation) {
	sort.Slice(observation.Namespaces, func(i, j int) bool {
		return observation.Namespaces[i].Resource.key() < observation.Namespaces[j].Resource.key()
	})
	sort.Slice(observation.Workloads, func(i, j int) bool {
		return observation.Workloads[i].Resource.key() < observation.Workloads[j].Resource.key()
	})
	sort.Slice(observation.Services, func(i, j int) bool {
		return observation.Services[i].Resource.key() < observation.Services[j].Resource.key()
	})
	sort.Slice(observation.PeerAuthentications, func(i, j int) bool {
		return observation.PeerAuthentications[i].Resource.key() <
			observation.PeerAuthentications[j].Resource.key()
	})
	sort.Slice(observation.AuthorizationPolicies, func(i, j int) bool {
		return observation.AuthorizationPolicies[i].Resource.key() <
			observation.AuthorizationPolicies[j].Resource.key()
	})
	sort.Slice(observation.NetworkPolicies, func(i, j int) bool {
		return observation.NetworkPolicies[i].Resource.key() <
			observation.NetworkPolicies[j].Resource.key()
	})
	sort.Slice(observation.ProbeRewrites, func(i, j int) bool {
		return observation.ProbeRewrites[i].Resource.key() <
			observation.ProbeRewrites[j].Resource.key()
	})
}

func projectOpenSearchMesh(
	inspections map[string]chartInspection,
) (openSearchMeshProjection, error) {
	var projection openSearchMeshProjection
	for _, artifact := range selectedMeshArtifactIDs {
		inspection, found := inspections[artifact]
		if !found {
			return openSearchMeshProjection{}, candidateRenderError(
				artifact, errors.New("mesh contract has no selected render"),
			)
		}
		if inspection.Security.Overflow != nil {
			return openSearchMeshProjection{}, meshResourceError(
				artifact, *inspection.Security.Overflow,
				"security render observation exceeded a hard proof bound",
			)
		}
		if err := appendAttributedMeshObservations(
			&projection.Namespaces, artifact, inspection.Security.Namespaces,
			func(value namespaceSecurityObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
		if err := appendAttributedMeshObservations(
			&projection.Workloads, artifact, inspection.Security.Workloads,
			func(value workloadSecurityObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
		if err := appendAttributedMeshObservations(
			&projection.Services, artifact, inspection.Security.Services,
			func(value serviceSecurityObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
		if err := appendAttributedMeshObservations(
			&projection.PeerAuthentications, artifact,
			inspection.Security.PeerAuthentications,
			func(value peerAuthenticationObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
		if err := appendAttributedMeshObservations(
			&projection.AuthorizationPolicies, artifact,
			inspection.Security.AuthorizationPolicies,
			func(value authorizationPolicyObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
		if err := appendAttributedMeshObservations(
			&projection.NetworkPolicies, artifact, inspection.Security.NetworkPolicies,
			func(value networkPolicyObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
		if err := appendAttributedMeshObservations(
			&projection.ProbeRewrites, artifact, inspection.Security.ProbeRewrites,
			func(value probeRewriteObservation) renderedResource {
				return value.Resource
			},
		); err != nil {
			return openSearchMeshProjection{}, err
		}
	}
	return projection, nil
}

func appendAttributedMeshObservations[T any](
	target *[]attributedMeshObservation[T],
	artifact string,
	source []T,
	resource func(T) renderedResource,
) error {
	available := maxSecurityResources - len(*target)
	if len(source) > available {
		index := available
		if index >= len(source) {
			index = len(source) - 1
		}
		return meshResourceError(
			artifact, resource(source[index]),
			"mesh projection exceeded a hard proof bound",
		)
	}
	for _, value := range source {
		*target = append(*target, attributedMeshObservation[T]{
			Artifact: artifact,
			Value:    value,
		})
	}
	return nil
}

func validateOpenSearchMeshContract(inspections map[string]chartInspection) error {
	projection, err := projectOpenSearchMesh(inspections)
	if err != nil {
		return err
	}
	for _, namespace := range []attributedMeshResource{
		selectedMeshResource("bigbang", selectedOpenSearchNamespaceIdentity),
		selectedMeshResource("bigbang", selectedFluentBitNamespaceIdentity),
	} {
		if resource, reason := injectedNamespace(projection, namespace); reason != "" {
			return attributedMeshResourceError(resource, reason)
		}
	}

	openSearchLabels := selectedOpenSearchLabels()
	fluentLabels := selectedFluentBitLabels()
	dashboardsLabels := selectedDashboardsLabels()
	openSearchWorkload, resource, reason := exactWorkload(
		projection,
		selectedMeshResource("chart/opensearch", selectedOpenSearchWorkloadIdentity),
	)
	if reason != "" {
		return attributedMeshResourceError(resource, reason)
	}
	if !exactSelector(openSearchWorkload.Value.Selector, openSearchLabels) ||
		!labelsContain(openSearchWorkload.Value.PodLabels, openSearchLabels) {
		return meshResourceError(openSearchWorkload.Artifact, openSearchWorkload.Value.Resource,
			"OpenSearch selected workload labels drifted")
	}
	if reason := meshCaptureFailure(openSearchWorkload.Value, 9200, true, false); reason != "" {
		return meshResourceError(
			openSearchWorkload.Artifact, openSearchWorkload.Value.Resource, reason,
		)
	}
	if service, reason := selectedServiceFailure(
		projection,
		selectedMeshResource("chart/opensearch", selectedOpenSearchServiceIdentity),
		openSearchLabels, 9200,
	); reason != "" {
		return attributedMeshResourceError(service, reason)
	}

	dashboardsWorkload, resource, reason := exactWorkload(
		projection,
		selectedMeshResource(
			"chart/opensearch-dashboards", selectedDashboardsWorkloadIdentity,
		),
	)
	if reason != "" {
		return attributedMeshResourceError(resource, reason)
	}
	if !exactSelector(dashboardsWorkload.Value.Selector, dashboardsLabels) ||
		!labelsContain(dashboardsWorkload.Value.PodLabels, dashboardsLabels) {
		return meshResourceError(
			dashboardsWorkload.Artifact, dashboardsWorkload.Value.Resource,
			"OpenSearch Dashboards selected workload labels drifted")
	}
	if reason := meshCaptureFailure(
		dashboardsWorkload.Value, 9200, false, true,
	); reason != "" {
		return meshResourceError(
			dashboardsWorkload.Artifact, dashboardsWorkload.Value.Resource, reason,
		)
	}

	fluentWorkload, resource, reason := exactWorkload(
		projection,
		selectedMeshResource("package/fluentbit", selectedFluentBitWorkloadIdentity),
	)
	if reason != "" {
		return attributedMeshResourceError(resource, reason)
	}
	if !exactSelector(fluentWorkload.Value.Selector, fluentLabels) ||
		!labelsContain(fluentWorkload.Value.PodLabels, fluentLabels) {
		return meshResourceError(fluentWorkload.Artifact, fluentWorkload.Value.Resource,
			"Fluent Bit selected workload labels drifted")
	}
	if fluentWorkload.Value.ServiceAccount != "fluentbit-fluent-bit" {
		return meshResourceError(fluentWorkload.Artifact, fluentWorkload.Value.Resource,
			"Fluent Bit ServiceAccount drifted")
	}
	if reason := meshCaptureFailure(fluentWorkload.Value, 9200, false, true); reason != "" {
		return meshResourceError(
			fluentWorkload.Artifact, fluentWorkload.Value.Resource, reason,
		)
	}
	if peer, reason := strictPeerFailure(
		projection, openSearchLabels, 9200,
	); reason != "" {
		return attributedMeshResourceError(peer, reason)
	}
	if policy, reason := authorizationPathFailure(
		projection, openSearchLabels,
		"cluster.local/ns/fluentbit/sa/fluentbit-fluent-bit", 9200,
	); reason != "" {
		return attributedMeshResourceError(policy, reason)
	}
	if policy, reason := fluentEgressFailure(
		projection, fluentLabels, openSearchLabels, 9200,
	); reason != "" {
		return attributedMeshResourceError(policy, reason)
	}
	if policy, reason := openSearchIngressFailure(
		projection, openSearchLabels, fluentLabels, 9200,
	); reason != "" {
		return attributedMeshResourceError(policy, reason)
	}
	if openSearchWorkload.Value.StartupPort != 9200 ||
		openSearchWorkload.Value.ReadinessPort != 9200 ||
		!openSearchWorkload.Value.InitValid ||
		openSearchWorkload.Value.InitContainerCount != 1 ||
		openSearchWorkload.Value.ConfigInitCount != 1 ||
		!openSearchWorkload.Value.ConfigInitLocal {
		return meshResourceError(
			openSearchWorkload.Artifact, openSearchWorkload.Value.Resource,
			"OpenSearch probe or local-only init contract drifted")
	}
	if rewrite, reason := probeRewriteFailure(
		projection,
		selectedMeshResource("package/istiod", selectedIstiodValuesIdentity),
	); reason != "" {
		return attributedMeshResourceError(rewrite, reason)
	}
	return nil
}

func inspectionsByArtifactID(
	artifacts []chartArtifact, inspections []chartInspection,
) (map[string]chartInspection, error) {
	if len(artifacts) != len(inspections) {
		return nil, errors.New("chart artifact and inspection counts differ")
	}
	result := make(map[string]chartInspection, len(artifacts))
	for index := range artifacts {
		if _, exists := result[artifacts[index].ID]; exists {
			return nil, fmt.Errorf("chart inspection %s is duplicated", artifacts[index].ID)
		}
		result[artifacts[index].ID] = inspections[index]
	}
	return result, nil
}

func selectedOpenSearchLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "opensearch",
		"app.kubernetes.io/instance": "opensearch",
	}
}

func selectedFluentBitLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "fluent-bit",
		"app.kubernetes.io/instance": "fluentbit",
	}
}

func selectedDashboardsLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "opensearch-dashboards",
		"app.kubernetes.io/instance": "opensearch-dashboards",
	}
}

func injectedNamespace(
	projection openSearchMeshProjection, expected attributedMeshResource,
) (attributedMeshResource, string) {
	var selected *attributedMeshObservation[namespaceSecurityObservation]
	lookalike := expected
	for index := range projection.Namespaces {
		namespace := &projection.Namespaces[index]
		if namespace.Value.Resource.Kind != expected.Resource.Kind {
			continue
		}
		if lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: namespace.Artifact, Resource: namespace.Value.Resource,
			}
		}
		if namespace.Value.Resource.APIVersion != expected.Resource.APIVersion ||
			namespace.Value.Resource.Name != expected.Resource.Name {
			continue
		}
		if selected != nil {
			return attributedMeshResource{
				Artifact: namespace.Artifact, Resource: namespace.Value.Resource,
			}, "selected namespace identity is duplicated"
		}
		selected = namespace
	}
	if selected == nil {
		return lookalike, "selected namespace " + expected.Resource.Name + " is missing"
	}
	resource := attributedMeshResource{
		Artifact: selected.Artifact, Resource: selected.Value.Resource,
	}
	if selected.Artifact != expected.Artifact {
		return resource, "selected namespace is rendered by an unexpected artifact"
	}
	if !selected.Value.MetadataValid {
		return resource, "namespace injection metadata is malformed or oversized"
	}
	if selected.Value.InjectionEligible {
		return resource, ""
	}
	return resource, "namespace is not injection-eligible"
}

func exactWorkload(
	projection openSearchMeshProjection,
	expected attributedMeshResource,
) (*attributedMeshObservation[workloadSecurityObservation], attributedMeshResource, string) {
	var selected *attributedMeshObservation[workloadSecurityObservation]
	lookalike := expected
	for index := range projection.Workloads {
		workload := &projection.Workloads[index]
		if workload.Value.Resource.Kind != expected.Resource.Kind ||
			workload.Value.Resource.Namespace != expected.Resource.Namespace {
			continue
		}
		if lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: workload.Artifact, Resource: workload.Value.Resource,
			}
		}
		if workload.Value.Resource.APIVersion != expected.Resource.APIVersion ||
			workload.Value.Resource.Name != expected.Resource.Name {
			continue
		}
		if selected != nil {
			return nil, attributedMeshResource{
				Artifact: workload.Artifact, Resource: workload.Value.Resource,
			}, "selected workload identity is duplicated"
		}
		selected = workload
	}
	if selected == nil {
		return nil, lookalike, "selected workload " + expected.Resource.Namespace + "/" +
			expected.Resource.Name + " is missing"
	}
	if selected.Artifact != expected.Artifact {
		return nil, attributedMeshResource{
			Artifact: selected.Artifact, Resource: selected.Value.Resource,
		}, "selected workload is rendered by an unexpected artifact"
	}
	return selected, attributedMeshResource{
		Artifact: selected.Artifact, Resource: selected.Value.Resource,
	}, ""
}

func meshCaptureFailure(
	workload workloadSecurityObservation,
	port int,
	inbound bool,
	outbound bool,
) string {
	if !workload.MetadataValid || !workload.Capture.Valid {
		return "workload proof metadata is malformed or exceeds its bound"
	}
	if !workload.HostNetworkValid {
		return "workload hostNetwork is not boolean"
	}
	if workload.HostNetwork {
		return "workload hostNetwork bypasses sidecar capture"
	}
	annotations := workload.Capture.Values
	if value, present := annotations["sidecar.istio.io/inject"]; present {
		if value == "false" {
			return "workload disables sidecar injection"
		}
		if value != "true" {
			return "workload sidecar injection annotation is malformed"
		}
	}
	if value, present := annotations["sidecar.istio.io/interceptionMode"]; present &&
		value != "REDIRECT" && value != "TPROXY" {
		return "workload interception mode can bypass sidecar capture"
	}
	for _, key := range []string{
		"traffic.sidecar.istio.io/kubevirtInterfaces",
		"traffic.sidecar.istio.io/excludeInterfaces",
	} {
		if value, present := annotations[key]; present {
			if strings.TrimSpace(value) == "" {
				return key + " is malformed"
			}
			return key + " can bypass sidecar capture"
		}
	}
	if outbound {
		if value, present := annotations["traffic.sidecar.istio.io/excludeOutboundIPRanges"]; present {
			if strings.TrimSpace(value) == "" {
				return "excludeOutboundIPRanges is malformed"
			}
			return "excludeOutboundIPRanges cannot prove capture of the selected Service"
		}
		if value, present := annotations["traffic.sidecar.istio.io/includeOutboundIPRanges"]; present && strings.TrimSpace(value) != "*" {
			return "includeOutboundIPRanges does not prove capture of the selected Service"
		}
	}
	needle := strconv.Itoa(port)
	if inbound {
		if failure := capturePortFailure(annotations, "Inbound", port, needle); failure != "" {
			return failure
		}
	}
	if outbound {
		if failure := capturePortFailure(annotations, "Outbound", port, needle); failure != "" {
			return failure
		}
	}
	return ""
}

func capturePortFailure(
	annotations map[string]string,
	direction string,
	port int,
	needle string,
) string {
	excludeKey := "traffic.sidecar.istio.io/exclude" + direction + "Ports"
	if value, present := annotations[excludeKey]; present {
		valid, excluded := inclusivePort(value, port)
		if !valid {
			return excludeKey + " is not a numeric port list or wildcard"
		}
		if excluded {
			return excludeKey + " excludes TCP " + needle
		}
	}
	includeKey := "traffic.sidecar.istio.io/include" + direction + "Ports"
	if value, present := annotations[includeKey]; present {
		valid, included := inclusivePort(value, port)
		if !valid {
			return includeKey + " is not a numeric port list or wildcard"
		}
		if !included {
			return includeKey + " omits TCP " + needle
		}
	}
	return ""
}

func inclusivePort(value string, port int) (bool, bool) {
	value = strings.TrimSpace(value)
	if value == "*" {
		return true, true
	}
	if value == "" {
		return false, false
	}
	included := false
	for _, candidate := range strings.Split(value, ",") {
		number, err := strconv.Atoi(strings.TrimSpace(candidate))
		if err != nil || number <= 0 || number > 65535 {
			return false, false
		}
		if number == port {
			included = true
		}
	}
	return true, included
}

func strictPeerFailure(
	projection openSearchMeshProjection,
	workloadLabels map[string]string,
	port int,
) (attributedMeshResource, string) {
	expected := selectedMeshResource("wrapper/wrapper", selectedOpenSearchPeerIdentity)
	selectedCount := 0
	lookalike := expected
	for _, observed := range projection.PeerAuthentications {
		peer := observed.Value
		resource := attributedMeshResource{
			Artifact: observed.Artifact, Resource: peer.Resource,
		}
		if peer.Resource.Namespace != expected.Resource.Namespace {
			continue
		}
		if sameResourceCoordinate(peer.Resource, expected.Resource) &&
			lookalike.Resource.Path == "" {
			lookalike = resource
		}
		if !peer.ModeValid || !peer.PortsValid ||
			peer.Selector.Present && !peer.Selector.Valid {
			return resource, "applicable PeerAuthentication is malformed"
		}
		if sameResourceIdentity(peer.Resource, expected.Resource) {
			selectedCount++
			if selectedCount > 1 {
				return resource,
					"selected wrapper STRICT PeerAuthentication is duplicated"
			}
			if observed.Artifact != expected.Artifact {
				return resource,
					"selected wrapper STRICT PeerAuthentication is rendered by an unexpected artifact"
			}
			if peer.Selector.Present || peer.Mode != "STRICT" {
				return resource,
					"selected wrapper PeerAuthentication is not namespace-wide STRICT"
			}
		}
		if peer.Selector.Present &&
			!selectorApplies(peer.Selector, workloadLabels) {
			continue
		}
		if peer.Mode == "PERMISSIVE" || peer.Mode == "DISABLE" {
			return resource,
				"PeerAuthentication weakens selected OpenSearch mTLS"
		}
		for _, portMode := range peer.PortModes {
			if portMode.Port == port &&
				portMode.Mode != "STRICT" &&
				portMode.Mode != "UNSET" {
				return resource,
					"PeerAuthentication weakens selected OpenSearch TCP 9200 mTLS"
			}
		}
	}
	if selectedCount == 0 {
		return lookalike, "selected wrapper STRICT PeerAuthentication is missing"
	}
	return expected, ""
}

func selectorApplies(selector selectorObservation, labels map[string]string) bool {
	if !selector.Present || !selector.Valid {
		return false
	}
	for key, value := range selector.Labels {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func sameResourceIdentity(actual renderedResource, expected renderedResource) bool {
	return actual.APIVersion == expected.APIVersion &&
		actual.Kind == expected.Kind &&
		actual.Namespace == expected.Namespace &&
		actual.Name == expected.Name
}

func sameResourceCoordinate(actual renderedResource, expected renderedResource) bool {
	return actual.Kind == expected.Kind &&
		actual.Namespace == expected.Namespace &&
		actual.Name == expected.Name
}

func authorizationPathFailure(
	projection openSearchMeshProjection,
	selector map[string]string,
	principal string,
	port int,
) (attributedMeshResource, string) {
	expected := selectedMeshResource(
		"wrapper/wrapper", selectedOpenSearchAuthorizationIdentity,
	)
	var selected *attributedMeshObservation[authorizationPolicyObservation]
	lookalike := expected
	for index := range projection.AuthorizationPolicies {
		observed := &projection.AuthorizationPolicies[index]
		policy := observed.Value
		if sameResourceCoordinate(
			policy.Resource, expected.Resource,
		) && lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: observed.Artifact, Resource: policy.Resource,
			}
		}
		if !sameResourceIdentity(
			policy.Resource, expected.Resource,
		) {
			continue
		}
		if selected != nil {
			return attributedMeshResource{
				Artifact: observed.Artifact, Resource: policy.Resource,
			}, "OpenSearch Fluent Bit authorization policy is duplicated"
		}
		selected = observed
	}
	if selected == nil {
		return lookalike, "OpenSearch Fluent Bit authorization policy is missing"
	}
	policy := selected.Value
	resource := attributedMeshResource{
		Artifact: selected.Artifact, Resource: policy.Resource,
	}
	if selected.Artifact != expected.Artifact {
		return resource,
			"OpenSearch Fluent Bit authorization policy is rendered by an unexpected artifact"
	}
	expectedRule := authorizationRuleObservation{
		FromPresent: true, FromValid: true,
		From: []authorizationSourceObservation{{
			PrincipalsPresent: true, PrincipalsValid: true,
			Principals: []string{principal},
		}},
		ToPresent: true, ToValid: true,
		To: []authorizationOperationObservation{{
			PortsPresent: true, PortsValid: true, Ports: []int{port},
		}},
	}
	if !policy.ActionValid || !policy.RulesPresent || !policy.RulesValid ||
		policy.Action != "ALLOW" || !exactSelector(policy.Selector, selector) ||
		!reflect.DeepEqual(policy.Rules, []authorizationRuleObservation{expectedRule}) {
		return resource,
			"OpenSearch authorization policy is not the sole exact Fluent Bit principal-to-9200 rule"
	}
	return resource, ""
}

func fluentEgressFailure(
	projection openSearchMeshProjection,
	fluentSelector map[string]string,
	openSearchSelector map[string]string,
	port int,
) (attributedMeshResource, string) {
	expected := selectedMeshResource(
		"package/fluentbit", selectedFluentBitEgressIdentity,
	)
	var selected *attributedMeshObservation[networkPolicyObservation]
	lookalike := expected
	for index := range projection.NetworkPolicies {
		observed := &projection.NetworkPolicies[index]
		policy := observed.Value
		if sameResourceCoordinate(
			policy.Resource, expected.Resource,
		) && lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: observed.Artifact, Resource: policy.Resource,
			}
		}
		if !sameResourceIdentity(policy.Resource, expected.Resource) {
			continue
		}
		if selected != nil {
			return attributedMeshResource{
				Artifact: observed.Artifact, Resource: policy.Resource,
			}, "selected Fluent Bit TCP 9200 policy is duplicated"
		}
		selected = observed
	}
	if selected == nil {
		return lookalike, "Fluent Bit selected egress policy is missing"
	}
	policy := selected.Value
	resource := attributedMeshResource{
		Artifact: selected.Artifact, Resource: policy.Resource,
	}
	if selected.Artifact != expected.Artifact {
		return resource, "Fluent Bit egress policy is rendered by an unexpected artifact"
	}
	if !exactSelector(policy.Selector, fluentSelector) {
		return resource, "Fluent Bit TCP 9200 policy selector drifted"
	}
	if !policy.PolicyTypesPresent || !policy.PolicyTypesValid ||
		!reflect.DeepEqual(policy.PolicyTypes, []string{"Egress"}) ||
		policy.IngressPresent {
		return resource, "Fluent Bit TCP 9200 policy type drifted"
	}
	if !policy.EgressPresent || !policy.EgressValid {
		return resource, "Fluent Bit egress rules are missing or invalid"
	}
	if len(policy.Egress) != 1 ||
		!exactNetworkRule(policy.Egress[0], "opensearch", openSearchSelector, port) {
		return resource,
			"Fluent Bit TCP 9200 egress policy is not the sole exact OpenSearch destination rule"
	}
	return resource, ""
}

func openSearchIngressFailure(
	projection openSearchMeshProjection,
	openSearchSelector map[string]string,
	fluentSelector map[string]string,
	port int,
) (attributedMeshResource, string) {
	expected := selectedMeshResource(
		"wrapper/wrapper", selectedOpenSearchIngressIdentity,
	)
	var selected *attributedMeshObservation[networkPolicyObservation]
	lookalike := expected
	for index := range projection.NetworkPolicies {
		observed := &projection.NetworkPolicies[index]
		policy := observed.Value
		if sameResourceCoordinate(
			policy.Resource, expected.Resource,
		) && lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: observed.Artifact, Resource: policy.Resource,
			}
		}
		if !sameResourceIdentity(
			policy.Resource, expected.Resource,
		) {
			continue
		}
		if selected != nil {
			return attributedMeshResource{
				Artifact: observed.Artifact, Resource: policy.Resource,
			}, "OpenSearch Fluent Bit ingress policy is duplicated"
		}
		selected = observed
	}
	if selected == nil {
		return lookalike, "OpenSearch Fluent Bit ingress policy is missing"
	}
	policy := selected.Value
	resource := attributedMeshResource{
		Artifact: selected.Artifact, Resource: policy.Resource,
	}
	if selected.Artifact != expected.Artifact {
		return resource, "OpenSearch ingress policy is rendered by an unexpected artifact"
	}
	if !exactSelector(policy.Selector, openSearchSelector) ||
		!policy.PolicyTypesPresent || !policy.PolicyTypesValid ||
		!reflect.DeepEqual(policy.PolicyTypes, []string{"Ingress"}) ||
		!policy.IngressPresent || !policy.IngressValid ||
		len(policy.Ingress) != 1 || policy.EgressPresent ||
		!exactNetworkRule(policy.Ingress[0], "fluentbit", fluentSelector, port) {
		return resource,
			"OpenSearch ingress policy is not the sole exact Fluent Bit TCP 9200 rule"
	}
	return resource, ""
}

func exactNetworkRule(
	rule networkRuleObservation, namespace string, podSelector map[string]string, port int,
) bool {
	return !rule.OtherFields &&
		rule.PeersPresent && rule.PeersValid && len(rule.Peers) == 1 &&
		exactNetworkPeer(rule.Peers[0], namespace, podSelector) &&
		rule.PortsPresent && rule.PortsValid &&
		reflect.DeepEqual(rule.Ports, []networkPortObservation{{
			Port: port, PortValid: true, Protocol: "TCP",
			ProtocolPresent: true, ProtocolValid: true,
		}})
}

func exactNetworkPeer(
	peer networkPeerObservation, namespace string, podSelector map[string]string,
) bool {
	return !peer.IPBlockPresent && !peer.OtherFields &&
		exactSelector(peer.NamespaceSelector,
			map[string]string{"kubernetes.io/metadata.name": namespace}) &&
		exactSelector(peer.PodSelector, podSelector)
}

func selectedServiceFailure(
	projection openSearchMeshProjection,
	expected attributedMeshResource,
	selector map[string]string,
	port int,
) (attributedMeshResource, string) {
	var selected *attributedMeshObservation[serviceSecurityObservation]
	lookalike := expected
	for index := range projection.Services {
		service := &projection.Services[index]
		if service.Value.Resource.Kind != expected.Resource.Kind ||
			service.Value.Resource.Namespace != expected.Resource.Namespace {
			continue
		}
		if lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: service.Artifact, Resource: service.Value.Resource,
			}
		}
		if service.Value.Resource.APIVersion != expected.Resource.APIVersion ||
			service.Value.Resource.Name != expected.Resource.Name {
			continue
		}
		if selected != nil {
			return attributedMeshResource{
				Artifact: service.Artifact, Resource: service.Value.Resource,
			}, "selected OpenSearch Service identity is duplicated"
		}
		selected = service
	}
	if selected == nil {
		return lookalike, "selected OpenSearch Service " + expected.Resource.Namespace + "/" +
			expected.Resource.Name + " is missing"
	}
	service := selected.Value
	resource := attributedMeshResource{
		Artifact: selected.Artifact, Resource: service.Resource,
	}
	if selected.Artifact != expected.Artifact {
		return resource, "selected OpenSearch Service is rendered by an unexpected artifact"
	}
	if !exactSelector(service.Selector, selector) {
		return resource, "selected OpenSearch Service selector drifted"
	}
	for _, candidate := range service.Ports {
		if candidate.PortValid && candidate.Port == port {
			if candidate.TargetPortValid && candidate.TargetPort == port {
				return resource, ""
			}
			return resource, "OpenSearch Service targetPort drifted from TCP 9200"
		}
	}
	return resource, "OpenSearch Service does not expose TCP 9200"
}

func probeRewriteFailure(
	projection openSearchMeshProjection,
	expected attributedMeshResource,
) (attributedMeshResource, string) {
	var selected *attributedMeshObservation[probeRewriteObservation]
	lookalike := expected
	for index := range projection.ProbeRewrites {
		rewrite := &projection.ProbeRewrites[index]
		if rewrite.Value.Resource.Kind != expected.Resource.Kind ||
			rewrite.Value.Resource.Namespace != expected.Resource.Namespace {
			continue
		}
		if lookalike.Resource.Path == "" {
			lookalike = attributedMeshResource{
				Artifact: rewrite.Artifact, Resource: rewrite.Value.Resource,
			}
		}
		if rewrite.Value.Resource.APIVersion != expected.Resource.APIVersion ||
			rewrite.Value.Resource.Name != expected.Resource.Name {
			continue
		}
		if selected != nil {
			return attributedMeshResource{
				Artifact: rewrite.Artifact, Resource: rewrite.Value.Resource,
			}, "selected Istiod probe-rewrite ConfigMap is duplicated"
		}
		selected = rewrite
	}
	if selected == nil {
		return lookalike, "selected Istiod probe-rewrite ConfigMap is missing"
	}
	resource := attributedMeshResource{
		Artifact: selected.Artifact, Resource: selected.Value.Resource,
	}
	if selected.Artifact != expected.Artifact {
		return resource,
			"selected Istiod probe-rewrite ConfigMap is rendered by an unexpected artifact"
	}
	if !selected.Value.Enabled {
		return resource, "Istiod probe rewrite is disabled"
	}
	return resource, ""
}

func exactSelector(observation selectorObservation, expected map[string]string) bool {
	return observation.Present && observation.Valid &&
		reflect.DeepEqual(observation.Labels, expected)
}

func labelsContain(labels map[string]string, expected map[string]string) bool {
	for key, value := range expected {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func meshResourceError(
	artifact string, resource renderedResource, reason string,
) error {
	if resource.Name == "" {
		if resource.Path != "" {
			return candidateRenderError(
				artifact,
				fmt.Errorf("%s: %s", resource.Path, reason),
			)
		}
		return candidateRenderError(artifact, errors.New(reason))
	}
	return candidateRenderError(artifact, fmt.Errorf("%s: %s", resource.String(), reason))
}

func attributedMeshResourceError(resource attributedMeshResource, reason string) error {
	return meshResourceError(resource.Artifact, resource.Resource, reason)
}

func exactInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, typed > 0
	case int64:
		return int(typed), typed > 0
	case float64:
		converted := int(typed)
		return converted, typed == float64(converted) && converted > 0
	case string:
		number, err := strconv.Atoi(typed)
		return number, err == nil && number > 0
	default:
		return 0, false
	}
}

func integer(value any) int {
	number, _ := exactInteger(value)
	return number
}

func tcpProbePort(value any) int {
	probe, _ := value.(map[string]any)
	return integer(mapAt(probe, "tcpSocket")["port"])
}
