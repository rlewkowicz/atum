package update

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"sort"
	"strings"

	fluxchartutil "github.com/fluxcd/pkg/chartutil"
	"gopkg.in/yaml.v3"
)

type resourceKey struct {
	namespace string
	name      string
	kind      string
}

type valueResource struct {
	data map[string]string
}

type repositoryResource struct {
	key       resourceKey
	url       string
	refTag    string
	refBranch string
	refCommit string
}

type repositoryIdentity struct {
	kind      string
	url       string
	refTag    string
	refBranch string
	refCommit string
}

type repositoryNamedIdentity struct {
	identity  repositoryIdentity
	name      string
	namespace string
}

type sourceResolution struct {
	key   resourceKey
	count int
}

type releaseBindingKey struct {
	source           resourceKey
	chart            string
	version          string
	reconcile        string
	releaseName      string
	releaseNamespace string
}

type artifactBinding struct {
	id                string
	sourceKind        string
	sourceName        string
	sourceNamespace   string
	sourceURL         string
	sourceTag         string
	sourceBranch      string
	sourceCommit      string
	chart             string
	version           string
	reconcileStrategy string
	defaultReconcile  bool
	releaseName       string
	releaseNamespace  string
}

type releaseValueSource struct {
	kind       string
	name       string
	valuesKey  string
	targetPath string
	optional   bool
	literal    bool
}

type releaseValues struct {
	key             resourceKey
	source          resourceKey
	chart           string
	version         string
	reconcile       string
	releaseName     string
	targetNamespace string
	valuesFrom      []releaseValueSource
	inline          map[string]any
}

type releaseValueInstance struct {
	identity  string
	name      string
	namespace string
	values    map[string]any
}

type releaseValueRenderedResource struct {
	key    resourceKey
	object map[string]any
}

type releaseValueCollector struct {
	defaultNamespace string
	resources        map[resourceKey]valueResource
	repositories     map[resourceKey]repositoryResource
	releases         map[string][]releaseValues
	rendered         []releaseValueRenderedResource
	captureRendered  bool
}

func newReleaseValueCollector(defaultNamespace string) *releaseValueCollector {
	return &releaseValueCollector{
		defaultNamespace: defaultNamespace,
		resources:        make(map[resourceKey]valueResource),
		repositories:     make(map[resourceKey]repositoryResource),
		releases:         make(map[string][]releaseValues),
	}
}

func (collector *releaseValueCollector) captureResources() *releaseValueCollector {
	collector.captureRendered = true
	return collector
}

func (collector *releaseValueCollector) observe(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if kind, _ := object["kind"].(string); kind == "List" {
		items, _ := object["items"].([]any)
		for _, item := range items {
			if err := collector.observe(item); err != nil {
				return err
			}
		}
		return nil
	}
	metadata, _ := object["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	if name == "" {
		return nil
	}
	namespace, _ := metadata["namespace"].(string)
	if namespace == "" {
		namespace = collector.defaultNamespace
	}
	kind, _ := object["kind"].(string)
	if collector.captureRendered && kind != "" {
		collector.rendered = append(collector.rendered, releaseValueRenderedResource{
			key:    resourceKey{namespace: namespace, name: name, kind: kind},
			object: object,
		})
	}
	switch kind {
	case "Secret", "ConfigMap":
		return collector.observeValuesResource(resourceKey{namespace: namespace, name: name, kind: kind}, object)
	case "GitRepository", "HelmRepository", "OCIRepository":
		return collector.observeRepository(resourceKey{namespace: namespace, name: name, kind: kind}, object)
	case "HelmRelease":
		return collector.observeHelmRelease(resourceKey{namespace: namespace, name: name}, object)
	default:
		return nil
	}
}

func (collector *releaseValueCollector) observeRepository(key resourceKey, object map[string]any) error {
	spec, _ := object["spec"].(map[string]any)
	url, _ := spec["url"].(string)
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("%s %s/%s has no source URL", key.kind, key.namespace, key.name)
	}
	ref, _ := spec["ref"].(map[string]any)
	resolved := repositoryResource{key: key, url: strings.TrimSpace(url)}
	resolved.refTag, _ = ref["tag"].(string)
	resolved.refBranch, _ = ref["branch"].(string)
	resolved.refCommit, _ = ref["commit"].(string)
	if key.kind == "GitRepository" {
		if resolved.refTag == "" && resolved.refCommit == "" {
			return fmt.Errorf("GitRepository %s/%s has no immutable release reference", key.namespace, key.name)
		}
		for field := range ref {
			if field != "tag" && field != "branch" && field != "commit" {
				return fmt.Errorf("GitRepository %s/%s uses unsupported ref.%s", key.namespace, key.name, field)
			}
		}
	}
	if previous, exists := collector.repositories[key]; exists && !reflect.DeepEqual(previous, resolved) {
		return fmt.Errorf("rendered source %s %s/%s is ambiguous", key.kind, key.namespace, key.name)
	}
	collector.repositories[key] = resolved
	return nil
}

func (collector *releaseValueCollector) observeValuesResource(key resourceKey, object map[string]any) error {
	values := make(map[string]string)
	fields := [...]struct {
		name    string
		encoded bool
	}{
		{name: "data", encoded: key.kind == "Secret"},
		{name: "stringData"},
	}
	for _, field := range fields {
		entries, _ := object[field.name].(map[string]any)
		for name, raw := range entries {
			text, ok := raw.(string)
			if !ok {
				return fmt.Errorf("%s %s/%s key %s is not text", key.kind, key.namespace, key.name, name)
			}
			if field.encoded {
				decoded, err := base64.StdEncoding.DecodeString(text)
				if err != nil {
					return fmt.Errorf("decode %s %s/%s key %s: %w", key.kind, key.namespace, key.name, name, err)
				}
				text = string(decoded)
			}
			values[name] = text
		}
	}
	candidate := valueResource{data: values}
	if previous, exists := collector.resources[key]; exists && !reflect.DeepEqual(previous, candidate) {
		return fmt.Errorf("rendered values resource %s/%s is ambiguous", key.namespace, key.name)
	}
	collector.resources[key] = candidate
	return nil
}

func (collector *releaseValueCollector) observeHelmRelease(key resourceKey, object map[string]any) error {
	spec, _ := object["spec"].(map[string]any)
	resolved := releaseValues{key: key}
	resolved.targetNamespace, _ = spec["targetNamespace"].(string)
	if resolved.targetNamespace == "" {
		resolved.targetNamespace = key.namespace
	}
	resolved.releaseName, _ = spec["releaseName"].(string)
	if resolved.releaseName == "" {
		if target, _ := spec["targetNamespace"].(string); target != "" {
			resolved.releaseName = target + "-" + key.name
		} else {
			resolved.releaseName = key.name
		}
	}
	resolved.releaseName = shortenReleaseName(resolved.releaseName)
	chart, _ := spec["chart"].(map[string]any)
	chartSpec, _ := chart["spec"].(map[string]any)
	sourceRef, _ := chartSpec["sourceRef"].(map[string]any)
	resolved.source.kind, _ = sourceRef["kind"].(string)
	resolved.source.name, _ = sourceRef["name"].(string)
	resolved.source.namespace, _ = sourceRef["namespace"].(string)
	if resolved.source.namespace == "" {
		resolved.source.namespace = key.namespace
	}
	resolved.chart, _ = chartSpec["chart"].(string)
	resolved.version, _ = chartSpec["version"].(string)
	resolved.reconcile, _ = chartSpec["reconcileStrategy"].(string)
	if resolved.source.kind == "" || resolved.source.name == "" || resolved.chart == "" {
		return fmt.Errorf("HelmRelease %s/%s has an incomplete chart source binding", key.namespace, key.name)
	}
	if inline, ok := spec["values"].(map[string]any); ok {
		resolved.inline = cloneMap(inline)
	}
	entries, _ := spec["valuesFrom"].([]any)
	resolved.valuesFrom = make([]releaseValueSource, 0, len(entries))
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("HelmRelease %s/%s has an invalid valuesFrom entry", key.namespace, key.name)
		}
		source := releaseValueSource{valuesKey: "values.yaml"}
		source.kind, _ = entry["kind"].(string)
		source.name, _ = entry["name"].(string)
		if valuesKey, _ := entry["valuesKey"].(string); valuesKey != "" {
			source.valuesKey = valuesKey
		}
		source.targetPath, _ = entry["targetPath"].(string)
		source.optional, _ = entry["optional"].(bool)
		source.literal, _ = entry["literal"].(bool)
		if (source.kind != "Secret" && source.kind != "ConfigMap") || source.name == "" {
			return fmt.Errorf("HelmRelease %s/%s has an unsupported values source", key.namespace, key.name)
		}
		resolved.valuesFrom = append(resolved.valuesFrom, source)
	}
	collector.releases[key.name] = append(collector.releases[key.name], resolved)
	return nil
}

func (collector *releaseValueCollector) valuesForArtifacts(bindings []artifactBinding) (map[string][]releaseValueInstance, error) {
	result := make(map[string][]releaseValueInstance, len(bindings))
	matched := make(map[string][]releaseValues, len(bindings))
	byIdentity := make(map[repositoryIdentity]sourceResolution, len(collector.repositories))
	byName := make(map[repositoryNamedIdentity]sourceResolution, len(collector.repositories))
	byNamespace := make(map[repositoryNamedIdentity]sourceResolution, len(collector.repositories))
	byExact := make(map[repositoryNamedIdentity]resourceKey, len(collector.repositories))
	for key, repository := range collector.repositories {
		identity := repositoryIdentity{
			kind:      key.kind,
			url:       normalizedSourceURL(repository.url),
			refTag:    repository.refTag,
			refBranch: repository.refBranch,
			refCommit: repository.refCommit,
		}
		addSourceResolution(byIdentity, identity, key)
		addSourceResolution(byName, repositoryNamedIdentity{
			identity: identity, name: key.name,
		}, key)
		addSourceResolution(byNamespace, repositoryNamedIdentity{
			identity: identity, namespace: key.namespace,
		}, key)
		byExact[repositoryNamedIdentity{
			identity: identity, name: key.name, namespace: key.namespace,
		}] = key
	}
	bindingIndex := make(map[releaseBindingKey]int, len(bindings)*2)
	for index := range bindings {
		binding := bindings[index]
		identity := repositoryIdentity{
			kind:      binding.sourceKind,
			url:       normalizedSourceURL(binding.sourceURL),
			refTag:    binding.sourceTag,
			refBranch: binding.sourceBranch,
			refCommit: binding.sourceCommit,
		}
		source, found, ambiguous := resolveSourceResource(
			identity, binding.sourceName, binding.sourceNamespace,
			byIdentity, byName, byNamespace, byExact,
		)
		if ambiguous {
			return nil, fmt.Errorf("rendered source for artifact %s is ambiguous", binding.id)
		}
		if !found {
			return nil, fmt.Errorf(
				"Big Bang rendered no exact %s source url=%q tag=%q branch=%q commit=%q for artifact %s",
				binding.sourceKind,
				binding.sourceURL,
				binding.sourceTag,
				binding.sourceBranch,
				binding.sourceCommit,
				binding.id,
			)
		}
		key := releaseBindingKey{
			source: source, chart: binding.chart, version: binding.version,
			reconcile:        binding.reconcileStrategy,
			releaseName:      binding.releaseName,
			releaseNamespace: binding.releaseNamespace,
		}
		if err := addReleaseBinding(bindingIndex, key, index, bindings); err != nil {
			return nil, err
		}
		if binding.defaultReconcile {
			key.reconcile = ""
			if err := addReleaseBinding(bindingIndex, key, index, bindings); err != nil {
				return nil, err
			}
		}
	}
	for _, candidates := range collector.releases {
		for _, candidate := range candidates {
			index, found, ambiguous := resolveReleaseBinding(bindingIndex, candidate)
			if ambiguous {
				return nil, fmt.Errorf(
					"rendered HelmRelease %s/%s matches multiple artifact bindings",
					candidate.key.namespace, candidate.key.name,
				)
			}
			if found {
				binding := bindings[index]
				matched[binding.id] = append(matched[binding.id], candidate)
			}
		}
	}
	for _, binding := range bindings {
		matches := matched[binding.id]
		if len(matches) == 0 {
			return nil, fmt.Errorf("Big Bang rendered no exactly-bound HelmRelease for artifact %s", binding.id)
		}
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].key.namespace != matches[j].key.namespace {
				return matches[i].key.namespace < matches[j].key.namespace
			}
			return matches[i].key.name < matches[j].key.name
		})
		for i := 1; i < len(matches); i++ {
			if matches[i-1].key == matches[i].key {
				return nil, fmt.Errorf("Big Bang rendered duplicate HelmRelease %s/%s", matches[i].key.namespace, matches[i].key.name)
			}
		}
		instances := make([]releaseValueInstance, len(matches))
		for i := range matches {
			values, err := collector.resolveReleaseValues(matches[i])
			if err != nil {
				return nil, err
			}
			instances[i] = releaseValueInstance{
				identity:  matches[i].key.namespace + "/" + matches[i].key.name,
				name:      matches[i].releaseName,
				namespace: matches[i].targetNamespace,
				values:    values,
			}
		}
		result[binding.id] = instances
	}
	return result, nil
}

func addSourceResolution[K comparable](
	index map[K]sourceResolution,
	identity K,
	key resourceKey,
) {
	resolution := index[identity]
	if resolution.count == 0 {
		resolution.key = key
	}
	resolution.count++
	index[identity] = resolution
}

func resolveSourceResource(
	identity repositoryIdentity,
	name string,
	namespace string,
	byIdentity map[repositoryIdentity]sourceResolution,
	byName map[repositoryNamedIdentity]sourceResolution,
	byNamespace map[repositoryNamedIdentity]sourceResolution,
	byExact map[repositoryNamedIdentity]resourceKey,
) (resourceKey, bool, bool) {
	if name != "" && namespace != "" {
		key, found := byExact[repositoryNamedIdentity{
			identity: identity, name: name, namespace: namespace,
		}]
		return key, found, false
	}
	var resolution sourceResolution
	switch {
	case name != "":
		resolution = byName[repositoryNamedIdentity{identity: identity, name: name}]
	case namespace != "":
		resolution = byNamespace[repositoryNamedIdentity{
			identity: identity, namespace: namespace,
		}]
	default:
		resolution = byIdentity[identity]
	}
	return resolution.key, resolution.count == 1, resolution.count > 1
}

func addReleaseBinding(
	index map[releaseBindingKey]int,
	key releaseBindingKey,
	bindingIndex int,
	bindings []artifactBinding,
) error {
	if previous, exists := index[key]; exists && previous != bindingIndex {
		return fmt.Errorf(
			"artifact bindings %s and %s have the same rendered release identity",
			bindings[previous].id,
			bindings[bindingIndex].id,
		)
	}
	index[key] = bindingIndex
	return nil
}

func resolveReleaseBinding(
	index map[releaseBindingKey]int,
	release releaseValues,
) (int, bool, bool) {
	base := releaseBindingKey{
		source: release.source, chart: release.chart, version: release.version,
		reconcile: release.reconcile,
	}
	keys := [...]releaseBindingKey{
		{
			source: base.source, chart: base.chart, version: base.version,
			reconcile:   base.reconcile,
			releaseName: release.key.name, releaseNamespace: release.key.namespace,
		},
		{
			source: base.source, chart: base.chart, version: base.version,
			reconcile: base.reconcile, releaseName: release.key.name,
		},
		{
			source: base.source, chart: base.chart, version: base.version,
			reconcile: base.reconcile, releaseNamespace: release.key.namespace,
		},
		base,
	}
	selected := 0
	found := false
	for _, key := range keys {
		candidate, exists := index[key]
		if !exists {
			continue
		}
		if found && candidate != selected {
			return 0, false, true
		}
		selected, found = candidate, true
	}
	return selected, found, false
}

func normalizedSourceURL(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	return strings.TrimSuffix(value, ".git")
}

func (collector *releaseValueCollector) resolveReleaseValues(release releaseValues) (map[string]any, error) {
	name := release.key.name
	values := make(map[string]any)
	for _, source := range release.valuesFrom {
		resource, exists := collector.resources[resourceKey{namespace: release.key.namespace, name: source.name, kind: source.kind}]
		if !exists {
			if source.optional {
				continue
			}
			return nil, fmt.Errorf("HelmRelease %s/%s values source %s is missing", release.key.namespace, name, source.name)
		}
		content, exists := resource.data[source.valuesKey]
		if !exists {
			if source.optional {
				continue
			}
			return nil, fmt.Errorf("HelmRelease %s/%s values source %s has no key %s", release.key.namespace, name, source.name, source.valuesKey)
		}
		if source.targetPath != "" {
			mergeInto(values, release.inline)
			if err := setReleaseTarget(values, source.targetPath, content, source.literal); err != nil {
				return nil, fmt.Errorf("apply HelmRelease %s/%s values source %s: %w", release.key.namespace, name, source.name, err)
			}
			continue
		}
		decoded, err := decodeReleaseValues(content)
		if err != nil {
			return nil, fmt.Errorf("decode HelmRelease %s/%s values source %s key %s: %w", release.key.namespace, name, source.name, source.valuesKey, err)
		}
		mergeInto(values, decoded)
	}
	mergeInto(values, release.inline)
	return values, nil
}

func decodeReleaseValues(content string) (map[string]any, error) {
	var values map[string]any
	if err := yaml.Unmarshal([]byte(content), &values); err != nil {
		return nil, err
	}
	if values == nil {
		values = make(map[string]any)
	}
	return values, nil
}

func setReleaseTarget(values map[string]any, target, value string, literal bool) error {
	if literal {
		return fluxchartutil.ReplacePathLiteralValue(values, target, value)
	}
	return fluxchartutil.ReplacePathValue(values, target, value)
}

func shortenReleaseName(name string) string {
	if len(name) <= 53 {
		return name
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(name)))
	return name[:40] + "-" + digest[:12]
}
