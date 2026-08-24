package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	containername "github.com/google/go-containerregistry/pkg/name"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v4/pkg/chart/common"
	commonutil "helm.sh/helm/v4/pkg/chart/common/util"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/engine"
	releaseutil "helm.sh/helm/v4/pkg/release/v1/util"
)

type chartInspection struct {
	Name              string
	Version           string
	AppVersion        string
	KubeVersion       string
	Images            []string
	SourceImages      []string
	Declared          []string
	Invocations       []containerInvocation
	ContractSHA       string
	IstioDependencies []releaseDependencyPosition
}

type containerInvocation struct {
	Location   string
	Name       string
	Repository string
	Command    any
	Args       any
}

type runtimeContract struct {
	AnnotatedRepositories []string      `json:"annotatedRepositories"`
	Pods                  []podContract `json:"pods"`
}

type podContract struct {
	Location       string              `json:"location"`
	Metadata       map[string]any      `json:"metadata,omitempty"`
	Runtime        map[string]any      `json:"runtime,omitempty"`
	Containers     []containerContract `json:"containers"`
	InitContainers []containerContract `json:"initContainers,omitempty"`
	Ephemeral      []containerContract `json:"ephemeralContainers,omitempty"`
}

type containerContract struct {
	Name           string         `json:"name"`
	Repository     string         `json:"repository"`
	Runtime        map[string]any `json:"runtime,omitempty"`
	LiteralCommand any            `json:"-"`
	LiteralArgs    any            `json:"-"`
}

type annotatedImage struct {
	Image string `yaml:"image"`
}

type releaseInstanceContract struct {
	Identity   string `json:"identity"`
	Release    string `json:"release"`
	Namespace  string `json:"namespace"`
	RuntimeSHA string `json:"runtimeSha256"`
}

func readChartMetadata(path string) (chartInspection, error) {
	loaded, err := loader.Load(path)
	if err != nil {
		return chartInspection{}, fmt.Errorf("load Helm chart %s: %w", path, err)
	}
	if loaded.Metadata == nil {
		return chartInspection{}, fmt.Errorf("Helm chart %s has no metadata", path)
	}
	return chartInspection{
		Name:        loaded.Metadata.Name,
		Version:     loaded.Metadata.Version,
		AppVersion:  loaded.Metadata.AppVersion,
		KubeVersion: normalizeConstraint(loaded.Metadata.KubeVersion),
	}, nil
}

func inspectChart(path, kubernetesVersion string, values map[string]any) (chartInspection, error) {
	return renderChart(path, kubernetesVersion, values, nil, releaseOptions("atum-contract", "atum-contract"), nil)
}

func inspectChartInstances(
	path string,
	kubernetesVersion string,
	instances []releaseValueInstance,
) (chartInspection, error) {
	if len(instances) == 0 {
		return chartInspection{}, errors.New("chart has no Big Bang release instances")
	}
	contracts := make([]releaseInstanceContract, len(instances))
	var combined chartInspection
	for i := range instances {
		inspection, err := renderChart(
			path,
			kubernetesVersion,
			instances[i].values,
			nil,
			releaseOptions(instances[i].name, instances[i].namespace),
			instances[i].renderers,
		)
		if err != nil {
			return chartInspection{}, fmt.Errorf("render release %s: %w", instances[i].identity, err)
		}
		if i == 0 {
			combined.Name = inspection.Name
			combined.Version = inspection.Version
			combined.AppVersion = inspection.AppVersion
			combined.KubeVersion = inspection.KubeVersion
		} else if combined.Name != inspection.Name || combined.Version != inspection.Version ||
			combined.AppVersion != inspection.AppVersion || combined.KubeVersion != inspection.KubeVersion {
			return chartInspection{}, errors.New("release instances resolved inconsistent chart metadata")
		}
		combined.Images = append(combined.Images, inspection.Images...)
		combined.SourceImages = append(combined.SourceImages, inspection.SourceImages...)
		combined.Declared = append(combined.Declared, inspection.Declared...)
		for _, invocation := range inspection.Invocations {
			invocation.Location = instances[i].identity + "/" + invocation.Location
			combined.Invocations = append(combined.Invocations, invocation)
		}
		contracts[i] = releaseInstanceContract{
			Identity:   instances[i].identity,
			Release:    instances[i].name,
			Namespace:  instances[i].namespace,
			RuntimeSHA: inspection.ContractSHA,
		}
	}
	combined.Images = compactSorted(combined.Images)
	combined.SourceImages = compactSorted(combined.SourceImages)
	combined.Declared = compactSorted(combined.Declared)
	sort.Slice(combined.Invocations, func(i, j int) bool {
		return combined.Invocations[i].Location < combined.Invocations[j].Location
	})
	encoded, err := json.Marshal(contracts)
	if err != nil {
		return chartInspection{}, fmt.Errorf("encode release instance contracts: %w", err)
	}
	digest := sha256.Sum256(encoded)
	combined.ContractSHA = hex.EncodeToString(digest[:])
	return combined, nil
}

func renderChart(
	path string,
	kubernetesVersion string,
	values map[string]any,
	collector *releaseValueCollector,
	options common.ReleaseOptions,
	postRenderers []releasePostRenderer,
) (chartInspection, error) {
	loaded, err := loader.Load(path)
	if err != nil {
		return chartInspection{}, fmt.Errorf("load Helm chart %s: %w", path, err)
	}
	return inspectLoadedChart(loaded, kubernetesVersion, values, collector, options, postRenderers)
}

func inspectLoadedChart(
	loaded *chart.Chart,
	kubernetesVersion string,
	values map[string]any,
	collector *releaseValueCollector,
	options common.ReleaseOptions,
	postRenderers []releasePostRenderer,
) (chartInspection, error) {
	if loaded.Metadata == nil {
		return chartInspection{}, errors.New("Helm chart has no metadata")
	}
	values = cloneMap(values)
	pruneShadowedScalarDefaults(loaded, values)
	if err := chartutil.ProcessDependencies(loaded, common.Values(values)); err != nil {
		return chartInspection{}, fmt.Errorf("resolve Helm dependencies for %s: %w", loaded.Name(), err)
	}
	annotated, err := annotatedImages(loaded)
	if err != nil {
		return chartInspection{}, err
	}
	kubeVersion, err := common.ParseKubeVersion(kubernetesVersion)
	if err != nil {
		return chartInspection{}, fmt.Errorf("parse Kubernetes version %s: %w", kubernetesVersion, err)
	}
	capabilities := common.DefaultCapabilities.Copy()
	capabilities.KubeVersion = *kubeVersion
	renderValues, err := commonutil.ToRenderValues(loaded, values, options, capabilities)
	if err != nil {
		return chartInspection{}, fmt.Errorf("resolve Helm values for %s: %w", loaded.Name(), err)
	}
	rendered, err := engine.Render(loaded, renderValues)
	if err != nil {
		return chartInspection{}, fmt.Errorf("render Helm chart %s: %w", loaded.Name(), err)
	}
	sourceImages, distinctSource, err := inspectSourceImages(rendered, annotated, postRenderers)
	if err != nil {
		return chartInspection{}, fmt.Errorf("inspect source images for Helm chart %s: %w", loaded.Name(), err)
	}
	if len(postRenderers) != 0 {
		rendered, err = applyPostRenderers(rendered, postRenderers)
		if err != nil {
			return chartInspection{}, fmt.Errorf("post-render Helm chart %s: %w", loaded.Name(), err)
		}
	}

	images, invocations, contractSHA, err := inspectRenderedResources(rendered, nil, annotated, collector)
	if err != nil {
		return chartInspection{}, err
	}
	if !distinctSource {
		sourceImages = images
	}
	var istioDependencies []releaseDependencyPosition
	if collector != nil {
		istioDependencies = collector.dependencyPositions("bigbang", "istiod")
	}
	return chartInspection{
		Name:              loaded.Metadata.Name,
		Version:           loaded.Metadata.Version,
		AppVersion:        loaded.Metadata.AppVersion,
		KubeVersion:       normalizeConstraint(loaded.Metadata.KubeVersion),
		Images:            images,
		SourceImages:      sourceImages,
		Declared:          annotated,
		Invocations:       invocations,
		ContractSHA:       contractSHA,
		IstioDependencies: istioDependencies,
	}, nil
}

func inspectSourceImages(
	rendered map[string]string,
	annotated []string,
	renderers []releasePostRenderer,
) ([]string, bool, error) {
	sourceRenderers, changed := postRenderersWithoutImages(renderers)
	if !changed {
		return nil, false, nil
	}
	sourceRendered, err := applyPostRenderers(rendered, sourceRenderers)
	if err != nil {
		return nil, false, err
	}
	images, _, _, err := inspectRenderedResources(sourceRendered, nil, annotated, nil)
	if err != nil {
		return nil, false, err
	}
	return images, true, nil
}

func observedSourceImages(inspection chartInspection) []string {
	if inspection.SourceImages != nil {
		return inspection.SourceImages
	}
	return inspection.Images
}

// pruneShadowedScalarDefaults removes lower-priority scalar defaults that Helm
// would ignore when an object override has already replaced them. Helm logs
// those valid type migrations as warnings during each coalescing pass.
func pruneShadowedScalarDefaults(loaded *chart.Chart, overrides map[string]any) {
	pruneShadowedScalars(loaded.Values, overrides)
	for _, dependency := range loaded.Dependencies() {
		dependencyOverrides, ok := overrides[dependency.Name()].(map[string]any)
		if ok {
			pruneShadowedScalarDefaults(dependency, dependencyOverrides)
		}
	}
}

func pruneShadowedScalars(defaults, overrides map[string]any) {
	for key, override := range overrides {
		overrideMap, overrideIsMap := override.(map[string]any)
		if !overrideIsMap {
			continue
		}
		value, exists := defaults[key]
		if !exists {
			continue
		}
		defaultMap, defaultIsMap := value.(map[string]any)
		if defaultIsMap {
			pruneShadowedScalars(defaultMap, overrideMap)
			continue
		}
		if value != nil {
			delete(defaults, key)
		}
	}
}

func releaseOptions(name, namespace string) common.ReleaseOptions {
	return common.ReleaseOptions{
		Name:      name,
		Namespace: namespace,
		Revision:  1,
		IsInstall: true,
	}
}

func inspectManifestData(name string, data []byte) (chartInspection, error) {
	images, contractSHA, err := inspectRendered(map[string]string{name: string(data)}, nil)
	if err != nil {
		return chartInspection{}, err
	}
	return chartInspection{Images: images, ContractSHA: contractSHA}, nil
}

func inspectRendered(rendered map[string]string, images []string) ([]string, string, error) {
	images, _, contractSHA, err := inspectRenderedResources(rendered, images, nil, nil)
	return images, contractSHA, err
}

func inspectRenderedResources(
	rendered map[string]string,
	images []string,
	annotated []string,
	collector *releaseValueCollector,
) ([]string, []containerInvocation, string, error) {
	contract := runtimeContract{}
	for _, image := range annotated {
		contract.AnnotatedRepositories = append(contract.AnnotatedRepositories, imageRepository(image))
	}
	filenames := make([]string, 0, len(rendered))
	for filename := range rendered {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	for _, filename := range filenames {
		if strings.HasSuffix(filename, "NOTES.txt") {
			continue
		}
		documents := releaseutil.SplitManifests(rendered[filename])
		keys := make([]string, 0, len(documents))
		for key := range documents {
			keys = append(keys, key)
		}
		sort.Sort(releaseutil.BySplitManifestsOrder(keys))
		for document, key := range keys {
			var value any
			if err := yaml.Unmarshal([]byte(documents[key]), &value); err != nil {
				return nil, nil, "", fmt.Errorf("decode rendered object %s: %w", filename, err)
			}
			if collector != nil {
				if err := collector.observe(value); err != nil {
					return nil, nil, "", fmt.Errorf("inspect rendered object %s: %w", filename, err)
				}
			}
			walkRuntime(value, filename+fmt.Sprintf("#%d", document), nil, &contract, &images)
		}
	}
	contract.AnnotatedRepositories = compactSorted(contract.AnnotatedRepositories)
	images = compactSorted(images)
	sort.Slice(contract.Pods, func(i, j int) bool { return contract.Pods[i].Location < contract.Pods[j].Location })
	invocations := applicationInvocations(contract.Pods)
	encoded, err := json.Marshal(contract)
	if err != nil {
		return nil, nil, "", fmt.Errorf("encode runtime contract: %w", err)
	}
	hash := sha256.Sum256(encoded)
	return images, invocations, hex.EncodeToString(hash[:]), nil
}

func applicationInvocations(pods []podContract) []containerInvocation {
	count := 0
	for i := range pods {
		count += len(pods[i].Containers) + len(pods[i].InitContainers) + len(pods[i].Ephemeral)
	}
	invocations := make([]containerInvocation, 0, count)
	for i := range pods {
		appendContainers := func(kind string, containers []containerContract) {
			for j := range containers {
				invocations = append(invocations, containerInvocation{
					Location:   pods[i].Location + "/" + kind + "/" + containers[j].Name,
					Name:       containers[j].Name,
					Repository: containers[j].Repository,
					Command:    containers[j].LiteralCommand,
					Args:       containers[j].LiteralArgs,
				})
			}
		}
		appendContainers("containers", pods[i].Containers)
		appendContainers("initContainers", pods[i].InitContainers)
		appendContainers("ephemeralContainers", pods[i].Ephemeral)
	}
	return invocations
}

func annotatedImages(loaded *chart.Chart) ([]string, error) {
	charts := []*chart.Chart{loaded}
	images := make([]string, 0, 16)
	for len(charts) != 0 {
		current := charts[len(charts)-1]
		charts = charts[:len(charts)-1]
		charts = append(charts, current.Dependencies()...)
		if current.Metadata == nil || current.Metadata.Annotations == nil {
			continue
		}
		declaration := current.Metadata.Annotations["helm.sh/images"]
		if strings.TrimSpace(declaration) == "" {
			continue
		}
		var entries []annotatedImage
		if err := yaml.Unmarshal([]byte(declaration), &entries); err != nil {
			return nil, fmt.Errorf("decode helm.sh/images for %s: %w", current.Name(), err)
		}
		for _, entry := range entries {
			if !validImageReference(entry.Image) {
				return nil, fmt.Errorf("helm.sh/images for %s contains invalid image %q", current.Name(), entry.Image)
			}
			images = append(images, entry.Image)
		}
	}
	return images, nil
}

func walkRuntime(value any, location string, inheritedMetadata any, contract *runtimeContract, images *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		if containers, hasContainers := typed["containers"].([]any); hasContainers && len(containers) != 0 {
			runtime := make(map[string]any, max(0, len(typed)-3))
			for key, field := range typed {
				if key == "containers" || key == "initContainers" || key == "ephemeralContainers" {
					continue
				}
				runtime[key] = normalizeRuntime(field, images)
			}
			pod := podContract{
				Location:       location,
				Metadata:       runtimeMetadata(inheritedMetadata, images),
				Runtime:        runtime,
				Containers:     extractContainers(typed["containers"], images),
				InitContainers: extractContainers(typed["initContainers"], images),
				Ephemeral:      extractContainers(typed["ephemeralContainers"], images),
			}
			contract.Pods = append(contract.Pods, pod)
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			metadata := any(nil)
			if key == "spec" {
				metadata = typed["metadata"]
			}
			walkRuntime(typed[key], location+"/"+key, metadata, contract, images)
		}
	case []any:
		for i := range typed {
			walkRuntime(typed[i], fmt.Sprintf("%s/%d", location, i), nil, contract, images)
		}
	}
}

func runtimeMetadata(value any, images *[]string) map[string]any {
	metadata, _ := value.(map[string]any)
	result := make(map[string]any, 2)
	for _, field := range [...]string{"labels", "annotations"} {
		entries, _ := metadata[field].(map[string]any)
		filtered := make(map[string]any, len(entries))
		for key, entry := range entries {
			if key == "helm.sh/chart" || key == "app.kubernetes.io/version" || key == "app.kubernetes.io/managed-by" ||
				strings.HasPrefix(key, "checksum/") {
				continue
			}
			filtered[key] = normalizeRuntime(entry, images)
		}
		if len(filtered) != 0 {
			result[field] = filtered
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func extractContainers(value any, images *[]string) []containerContract {
	entries, ok := value.([]any)
	if !ok {
		return nil
	}
	containers := make([]containerContract, 0, len(entries))
	for _, entry := range entries {
		container, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		image, _ := container["image"].(string)
		// Istio's gateway chart deliberately uses this sentinel; istiod's
		// mutating webhook replaces it with the locked proxy image at admission.
		if image != "auto" && validImageReference(image) {
			*images = append(*images, image)
		}
		runtime := make(map[string]any, max(0, len(container)-2))
		for key, field := range container {
			if key == "image" || key == "name" {
				continue
			}
			runtime[key] = normalizeRuntime(field, images)
		}
		name, _ := container["name"].(string)
		containers = append(containers, containerContract{
			Name:           name,
			Repository:     imageRepository(image),
			Runtime:        runtime,
			LiteralCommand: container["command"],
			LiteralArgs:    container["args"],
		})
	}
	return containers
}

func normalizeRuntime(value any, images *[]string) any {
	switch typed := value.(type) {
	case string:
		prefix, reference, ok := embeddedImageReference(typed)
		if !ok {
			return typed
		}
		*images = append(*images, reference)
		return prefix + imageRepository(reference)
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = normalizeRuntime(item, images)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i := range typed {
			result[i] = normalizeRuntime(typed[i], images)
		}
		return result
	default:
		return value
	}
}

func embeddedImageReference(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	type candidate struct {
		prefix    string
		reference string
	}
	candidates := [2]candidate{{reference: trimmed}}
	if separator := strings.IndexByte(trimmed, '='); separator >= 0 {
		candidates[0] = candidate{prefix: trimmed[:separator+1], reference: trimmed[separator+1:]}
		candidates[1] = candidate{reference: trimmed}
	}
	for _, candidate := range candidates {
		if !strings.Contains(candidate.reference, "/") || imageTag(candidate.reference) == "" || !validImageReference(candidate.reference) {
			continue
		}
		return candidate.prefix, candidate.reference, true
	}
	return "", "", false
}

func imageRepository(reference string) string {
	reference = strings.TrimSpace(strings.Trim(reference, `"'`))
	if at := strings.IndexByte(reference, '@'); at >= 0 {
		reference = reference[:at]
	}
	lastSlash := strings.LastIndexByte(reference, '/')
	if colon := strings.LastIndexByte(reference, ':'); colon > lastSlash {
		reference = reference[:colon]
	}
	if reference == "" || reference == "auto" {
		return reference
	}
	registry, remainder, qualified := strings.Cut(reference, "/")
	if !qualified {
		return "docker.io/library/" + reference
	}
	if registry == "docker.io" || registry == "index.docker.io" {
		return "docker.io/" + remainder
	}
	if registry != "localhost" && !strings.ContainsAny(registry, ".:") {
		return "docker.io/" + reference
	}
	return reference
}

func imageTag(reference string) string {
	reference = strings.TrimSpace(strings.Trim(reference, `"'`))
	if at := strings.IndexByte(reference, '@'); at >= 0 {
		return reference[at+1:]
	}
	lastSlash := strings.LastIndexByte(reference, '/')
	if colon := strings.LastIndexByte(reference, ':'); colon > lastSlash {
		return reference[colon+1:]
	}
	return ""
}

func replaceImageTag(reference, tag string) (string, error) {
	if !validImageReference(reference) || strings.Contains(reference, "@") || tag == "" || strings.ContainsAny(tag, "@/: ") {
		return "", fmt.Errorf("cannot replace tag in image reference %q", reference)
	}
	repository := imageRepository(reference)
	candidate := repository + ":" + tag
	if _, err := containername.NewTag(candidate, containername.WeakValidation); err != nil {
		return "", fmt.Errorf("replace tag in image reference %q: %w", reference, err)
	}
	return candidate, nil
}

func validImageReference(reference string) bool {
	reference = strings.TrimSpace(strings.Trim(reference, `"'`))
	if reference == "" || strings.Contains(reference, "://") || strings.Contains(reference, "{{") || strings.ContainsAny(reference, " \t\r\n$") {
		return false
	}
	_, err := containername.ParseReference(reference, containername.WeakValidation)
	return err == nil
}

func compactSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value == "" || (len(result) > 0 && result[len(result)-1] == value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func readValues(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read values %s: %w", path, err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("decode values %s: %w", path, err)
	}
	if values == nil {
		values = make(map[string]any)
	}
	return values, nil
}

func mergeValues(base, overlay map[string]any) map[string]any {
	result := cloneMap(base)
	mergeInto(result, overlay)
	return result
}

func mergeInto(destination, source map[string]any) {
	for key, value := range source {
		sourceMap, sourceIsMap := value.(map[string]any)
		destinationMap, destinationIsMap := destination[key].(map[string]any)
		if sourceIsMap && destinationIsMap {
			mergeInto(destinationMap, sourceMap)
			continue
		}
		destination[key] = value
	}
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for i := range typed {
			cloned[i] = cloneValue(typed[i])
		}
		return cloned
	default:
		return value
	}
}

func valuesAt(root map[string]any, path string) (map[string]any, error) {
	current := root
	for _, component := range strings.Split(path, ".") {
		value, exists := current[component]
		if !exists {
			return nil, fmt.Errorf("values path %s does not exist", path)
		}
		nested, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("values path %s is not an object", path)
		}
		current = nested
	}
	return current, nil
}
