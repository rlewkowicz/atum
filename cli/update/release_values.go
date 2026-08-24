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
	dependencies    []resourceKey
	valuesFrom      []releaseValueSource
	inline          map[string]any
	postRenderers   []releasePostRenderer
}

type releaseDependencyPosition struct {
	namespace string
	name      string
	index     int
}

type releaseValueInstance struct {
	identity  string
	name      string
	namespace string
	values    map[string]any
	renderers []releasePostRenderer
}

type renderedResource struct {
	key    resourceKey
	object map[string]any
}

type releaseValueCollector struct {
	defaultNamespace string
	resources        map[resourceKey]valueResource
	repositories     map[resourceKey]repositoryResource
	releases         map[string][]releaseValues
	rendered         []renderedResource
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
		collector.rendered = append(collector.rendered, renderedResource{
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
	if raw, exists := spec["postRenderers"]; exists {
		postRenderers, err := decodePostRenderers(raw)
		if err != nil {
			return fmt.Errorf("HelmRelease %s/%s has invalid postRenderers: %w", key.namespace, key.name, err)
		}
		resolved.postRenderers = postRenderers
	}
	dependencies, _ := spec["dependsOn"].([]any)
	resolved.dependencies = make([]resourceKey, 0, len(dependencies))
	for i, raw := range dependencies {
		dependency, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("HelmRelease %s/%s has an invalid dependency at index %d", key.namespace, key.name, i)
		}
		name, _ := dependency["name"].(string)
		if name == "" {
			return fmt.Errorf("HelmRelease %s/%s dependency %d has no name", key.namespace, key.name, i)
		}
		namespace, _ := dependency["namespace"].(string)
		if namespace == "" {
			namespace = key.namespace
		}
		resolved.dependencies = append(resolved.dependencies, resourceKey{namespace: namespace, name: name})
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

func (collector *releaseValueCollector) dependencyPositions(namespace, name string) []releaseDependencyPosition {
	positions := make([]releaseDependencyPosition, 0, len(collector.releases))
	for _, releases := range collector.releases {
		for _, release := range releases {
			for i, dependency := range release.dependencies {
				if dependency.namespace != namespace || dependency.name != name {
					continue
				}
				positions = append(positions, releaseDependencyPosition{
					namespace: release.key.namespace,
					name:      release.key.name,
					index:     i,
				})
			}
		}
	}
	sort.Slice(positions, func(i, j int) bool {
		if positions[i].namespace != positions[j].namespace {
			return positions[i].namespace < positions[j].namespace
		}
		if positions[i].index != positions[j].index {
			return positions[i].index < positions[j].index
		}
		return positions[i].name < positions[j].name
	})
	return positions
}

func (collector *releaseValueCollector) valuesForArtifacts(bindings []artifactBinding) (map[string][]releaseValueInstance, error) {
	result := make(map[string][]releaseValueInstance, len(bindings))
	matched := make(map[string][]releaseValues, len(bindings))
	sources := make(map[string]resourceKey, len(bindings))
	for _, binding := range bindings {
		source, err := collector.artifactSource(binding)
		if err != nil {
			return nil, err
		}
		sources[binding.id] = source
	}
	for _, candidates := range collector.releases {
		for _, candidate := range candidates {
			for _, binding := range bindings {
				if candidate.source != sources[binding.id] {
					continue
				}
				if binding.releaseName != "" &&
					(candidate.key.name != binding.releaseName ||
						candidate.key.namespace != binding.releaseNamespace) {
					continue
				}
				reconcileMatches := candidate.reconcile == binding.reconcileStrategy ||
					(binding.defaultReconcile && candidate.reconcile == "")
				if candidate.chart != binding.chart || candidate.version != binding.version || !reconcileMatches {
					continue
				}
				matched[binding.id] = append(matched[binding.id], candidate)
				break
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
				renderers: matches[i].postRenderers,
			}
		}
		result[binding.id] = instances
	}
	return result, nil
}

func (collector *releaseValueCollector) artifactSource(binding artifactBinding) (resourceKey, error) {
	var match resourceKey
	found := false
	for key, repository := range collector.repositories {
		if key.kind != binding.sourceKind ||
			(binding.sourceName != "" && key.name != binding.sourceName) ||
			(binding.sourceNamespace != "" && key.namespace != binding.sourceNamespace) ||
			normalizedSourceURL(repository.url) != normalizedSourceURL(binding.sourceURL) ||
			repository.refTag != binding.sourceTag || repository.refBranch != binding.sourceBranch ||
			repository.refCommit != binding.sourceCommit {
			continue
		}
		if found {
			return resourceKey{}, fmt.Errorf("rendered source for artifact %s is ambiguous", binding.id)
		}
		match = key
		found = true
	}
	if !found {
		return resourceKey{}, fmt.Errorf(
			"Big Bang rendered no exact %s source url=%q tag=%q branch=%q commit=%q for artifact %s",
			binding.sourceKind, binding.sourceURL, binding.sourceTag, binding.sourceBranch, binding.sourceCommit, binding.id,
		)
	}
	return match, nil
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
