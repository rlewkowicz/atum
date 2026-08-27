package update

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"atum/cli/config"

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

const (
	maxMountedConfigFileBytes  = 1 << 20
	maxMountedConfigTotalBytes = 8 << 20
)

type chartInspection struct {
	Name         string
	Description  string
	Home         string
	Sources      []string
	Version      string
	AppVersion   string
	KubeVersion  string
	Images       []string
	SourceImages []string
	Declared     []string
	Invocations  []containerInvocation
	ContractSHA  string
	Security     platformSecurityObservation
	FormerWait   formerWaitObservation
}

type containerInvocation struct {
	Location              string
	Name                  string
	Reference             string
	Repository            string
	Command               any
	Args                  any
	Runtime               map[string]any
	PodRuntime            map[string]any
	PodMountPaths         []string
	MountedFiles          []mountedConfigFile
	RuntimeContractSHA256 string
}

type runtimeContract struct {
	AnnotatedRepositories []string             `json:"annotatedRepositories"`
	Pods                  []podContract        `json:"pods"`
	ImageFields           []imageFieldContract `json:"imageFields,omitempty"`
}

type imageFieldContract struct {
	Location  string `json:"location"`
	Reference string `json:"reference"`
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
	Name           string              `json:"name"`
	Reference      string              `json:"-"`
	Repository     string              `json:"repository"`
	Runtime        map[string]any      `json:"runtime,omitempty"`
	MountedFiles   []mountedConfigFile `json:"mountedFiles,omitempty"`
	LiteralCommand any                 `json:"-"`
	LiteralArgs    any                 `json:"-"`
}

type mountedConfigFile struct {
	Source      string `json:"source"`
	Key         string `json:"key"`
	Destination string `json:"destination"`
	SHA256      string `json:"sha256"`
	Content     []byte `json:"-"`
}

type renderedConfigFile struct {
	key     string
	content []byte
	sha256  string
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

type chartValueSelection struct {
	identity string
	values   map[string]any
}

type normalizationRequirement struct {
	receipt config.ChartNormalization
	owner   string
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
		Description: loaded.Metadata.Description,
		Home:        loaded.Metadata.Home,
		Sources:     append([]string(nil), loaded.Metadata.Sources...),
		Version:     loaded.Metadata.Version,
		AppVersion:  loaded.Metadata.AppVersion,
		KubeVersion: normalizeConstraint(loaded.Metadata.KubeVersion),
	}, nil
}

func inspectChart(path, kubernetesVersion string, values map[string]any) (chartInspection, error) {
	return renderChart(path, kubernetesVersion, values, nil, releaseOptions("atum-contract", "atum-contract"))
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
		mergePlatformSecurityObservation(
			&combined.Security,
			inspection.Security,
			instances[i].identity+"/",
		)
		mergeFormerWaitObservation(
			&combined.FormerWait,
			inspection.FormerWait,
			instances[i].identity+"/",
		)
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
	normalizePlatformSecurity(&combined.Security)
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
) (chartInspection, error) {
	loaded, _, err := loadNormalizedChart(path, []chartValueSelection{{
		identity: options.Namespace + "/" + options.Name,
		values:   values,
	}})
	if err != nil {
		return chartInspection{}, err
	}
	return inspectLoadedChart(loaded, kubernetesVersion, values, collector, options)
}

func inspectLoadedChart(
	loaded *chart.Chart,
	kubernetesVersion string,
	values map[string]any,
	collector *releaseValueCollector,
	options common.ReleaseOptions,
) (chartInspection, error) {
	if loaded.Metadata == nil {
		return chartInspection{}, errors.New("Helm chart has no metadata")
	}
	values = cloneMap(values)
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
	images, invocations, contractSHA, security, formerWait, err := inspectRenderedResources(
		rendered, nil, annotated, collector, options.Namespace,
	)
	if err != nil {
		return chartInspection{}, err
	}
	return chartInspection{
		Name:         loaded.Metadata.Name,
		Description:  loaded.Metadata.Description,
		Home:         loaded.Metadata.Home,
		Sources:      append([]string(nil), loaded.Metadata.Sources...),
		Version:      loaded.Metadata.Version,
		AppVersion:   loaded.Metadata.AppVersion,
		KubeVersion:  normalizeConstraint(loaded.Metadata.KubeVersion),
		Images:       images,
		SourceImages: images,
		Declared:     annotated,
		Invocations:  invocations,
		ContractSHA:  contractSHA,
		Security:     security,
		FormerWait:   formerWait,
	}, nil
}

func loadNormalizedChart(
	chartPath string,
	selections []chartValueSelection,
) (*chart.Chart, []config.ChartNormalization, error) {
	ordered := append([]chartValueSelection(nil), selections...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].identity < ordered[j].identity
	})
	if len(ordered) == 0 {
		ordered = []chartValueSelection{{identity: "default"}}
	}

	requirements := make(map[string]normalizationRequirement)
	selectionRequirements := make([]map[string]config.ChartNormalization, len(ordered))
	chartName := ""
	for index := range ordered {
		probe, err := loader.Load(chartPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load Helm chart %s: %w", chartPath, err)
		}
		if probe.Metadata == nil {
			return nil, nil, fmt.Errorf("Helm chart %s has no metadata", chartPath)
		}
		chartName = probe.Name()
		receipts, err := normalizePlaceholderDefaults(
			probe,
			cloneMap(ordered[index].values),
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"normalize Helm defaults for %s: %w",
				ordered[index].identity,
				err,
			)
		}
		selectionRequirements[index] = make(
			map[string]config.ChartNormalization,
			len(receipts),
		)
		for _, receipt := range receipts {
			selectionRequirements[index][receipt.Path] = receipt
			previous, exists := requirements[receipt.Path]
			if exists && previous.receipt != receipt {
				return nil, nil, fmt.Errorf(
					"value %s requires incompatible archive normalizations for %s and %s (%s to %s, %s to %s)",
					receipt.Path,
					previous.owner,
					ordered[index].identity,
					previous.receipt.From,
					previous.receipt.To,
					receipt.From,
					receipt.To,
				)
			}
			if !exists {
				requirements[receipt.Path] = normalizationRequirement{
					receipt: receipt,
					owner:   ordered[index].identity,
				}
			}
		}
	}
	requirementPaths := make([]string, 0, len(requirements))
	for valuePath := range requirements {
		requirementPaths = append(requirementPaths, valuePath)
	}
	sort.Strings(requirementPaths)
	for _, valuePath := range requirementPaths {
		requirement := requirements[valuePath]
		for index := range ordered {
			if receipt, exists := selectionRequirements[index][valuePath]; exists {
				if receipt == requirement.receipt {
					continue
				}
				return nil, nil, fmt.Errorf(
					"value %s requires incompatible archive normalizations for %s and %s",
					valuePath,
					requirement.owner,
					ordered[index].identity,
				)
			}
			if scalarOverrideCoversNormalization(
				ordered[index].values,
				chartName,
				valuePath,
			) {
				continue
			}
			return nil, nil, fmt.Errorf(
				"value %s required by %s changes Helm semantics for %s",
				valuePath,
				requirement.owner,
				ordered[index].identity,
			)
		}
	}

	normalized, err := loader.Load(chartPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load Helm chart %s: %w", chartPath, err)
	}
	for index := range ordered {
		if _, err := normalizePlaceholderDefaults(
			normalized,
			cloneMap(ordered[index].values),
		); err != nil {
			return nil, nil, fmt.Errorf(
				"normalize Helm defaults for %s: %w",
				ordered[index].identity,
				err,
			)
		}
	}
	receipts := make([]config.ChartNormalization, 0, len(requirementPaths))
	for _, valuePath := range requirementPaths {
		receipts = append(receipts, requirements[valuePath].receipt)
	}
	return normalized, receipts, nil
}

func scalarOverrideCoversNormalization(
	values map[string]any,
	root string,
	valuePath string,
) bool {
	relative := strings.TrimPrefix(valuePath, root+".")
	var current any = values
	for _, key := range strings.Split(relative, ".") {
		mapping, ok := current.(map[string]any)
		if !ok {
			return !isCollectionShape(helmValueShape(current))
		}
		current, ok = mapping[key]
		if !ok {
			return false
		}
	}
	return !isCollectionShape(helmValueShape(current))
}

// normalizePlaceholderDefaults aligns upstream placeholder defaults with the
// selected value shape before Helm coalesces a chart and its dependencies.
// Helm always retains the explicit value in these cases; this only fixes empty
// container and boolean-sentinel defaults that otherwise produce a warning.
func normalizePlaceholderDefaults(loaded *chart.Chart, overrides map[string]any) ([]config.ChartNormalization, error) {
	var receipts []config.ChartNormalization
	if err := normalizePlaceholderValueMap(loaded.Values, overrides, loaded.Name(), &receipts); err != nil {
		return nil, err
	}
	requirements := make(map[string][]*chart.Dependency, len(loaded.Metadata.Dependencies))
	for _, requirement := range loaded.Metadata.Dependencies {
		requirements[requirement.Name] = append(requirements[requirement.Name], requirement)
	}
	for _, dependency := range loaded.Dependencies() {
		for _, requirement := range requirements[dependency.Name()] {
			if !chartutil.IsCompatibleRange(requirement.Version, dependency.Metadata.Version) {
				continue
			}
			key := requirement.Name
			if requirement.Alias != "" {
				key = requirement.Alias
			}
			defaults, _ := loaded.Values[key].(map[string]any)
			selected, _ := overrides[key].(map[string]any)
			dependencyReceipts, err := normalizePlaceholderDefaults(dependency, mergeValues(defaults, selected))
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", loaded.Name(), key, err)
			}
			for index := range dependencyReceipts {
				suffix := strings.TrimPrefix(
					dependencyReceipts[index].Path, dependency.Name(),
				)
				dependencyReceipts[index].Path = loaded.Name() + "." + key + suffix
			}
			receipts = append(receipts, dependencyReceipts...)
		}
	}
	return receipts, nil
}

func normalizePlaceholderValueMap(
	defaults, overrides map[string]any,
	path string,
	receipts *[]config.ChartNormalization,
) error {
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		override := overrides[key]
		defaultValue, exists := defaults[key]
		if !exists {
			continue
		}
		valuePath := path + "." + key
		overrideShape := helmValueShape(override)
		defaultShape := helmValueShape(defaultValue)
		overrideMap, overrideIsMap := override.(map[string]any)
		defaultMap, defaultIsMap := defaultValue.(map[string]any)
		switch {
		case overrideIsMap && defaultIsMap:
			if err := normalizePlaceholderValueMap(defaultMap, overrideMap, valuePath, receipts); err != nil {
				return err
			}
		case !isCollectionShape(overrideShape):
			// Scalar overrides use Helm's ordinary replacement semantics.
			continue
		case overrideShape == defaultShape:
			continue
		case isSemanticallyEmpty(defaultValue) ||
			isBooleanEnabledMap(defaultValue, override) ||
			isCollectionShape(defaultShape) && isSemanticallyEmpty(override):
			defaults[key] = emptyValueForShape(overrideShape)
			*receipts = append(*receipts, config.ChartNormalization{
				Path: valuePath, From: defaultShape, To: overrideShape,
			})
		default:
			return fmt.Errorf(
				"value %s selects %s over incompatible non-empty %s default",
				valuePath, overrideShape, defaultShape,
			)
		}
	}
	return nil
}

func isBooleanEnabledMap(defaultValue, override any) bool {
	if _, ok := defaultValue.(bool); !ok {
		return false
	}
	overrideMap, ok := override.(map[string]any)
	if !ok || len(overrideMap) != 1 {
		return false
	}
	_, ok = overrideMap["enabled"].(bool)
	return ok
}

func isSemanticallyEmpty(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case bool:
		return !typed
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	default:
		return false
	}
}

func isCollectionShape(shape string) bool {
	return shape == "map" || shape == "list"
}

func emptyValueForShape(shape string) any {
	if shape == "map" {
		return map[string]any{}
	}
	return []any{}
}

func helmValueShape(value any) string {
	switch value.(type) {
	case map[string]any:
		return "map"
	case []any:
		return "list"
	case bool:
		return "boolean"
	case string:
		return "string"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", value)
	}
}

func observedSourceImages(inspection chartInspection) []string {
	if inspection.SourceImages != nil {
		return inspection.SourceImages
	}
	return inspection.Images
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
	images, invocations, contractSHA, security, formerWait, err := inspectRenderedResources(
		map[string]string{name: string(data)},
		nil,
		nil,
		nil,
		"",
	)
	if err != nil {
		return chartInspection{}, err
	}
	return chartInspection{
		Images: images, SourceImages: images,
		Invocations: invocations, ContractSHA: contractSHA,
		Security:   security,
		FormerWait: formerWait,
	}, nil
}

func inspectRendered(rendered map[string]string, images []string) ([]string, string, error) {
	images, _, contractSHA, _, _, err := inspectRenderedResources(rendered, images, nil, nil, "")
	return images, contractSHA, err
}

func inspectRenderedResources(
	rendered map[string]string,
	images []string,
	annotated []string,
	collector *releaseValueCollector,
	defaultNamespace string,
) (
	[]string,
	[]containerInvocation,
	string,
	platformSecurityObservation,
	formerWaitObservation,
	error,
) {
	contract := runtimeContract{}
	var security platformSecurityObservation
	var formerWait formerWaitObservation
	configMaps := make(map[string][]renderedConfigFile)
	var mountedConfigBytes int64
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
				return nil, nil, "", security, formerWait, fmt.Errorf("decode rendered object %s: %w", filename, err)
			}
			if !installActiveHelmResource(value) {
				continue
			}
			if collector != nil {
				if err := collector.observe(value); err != nil {
					return nil, nil, "", security, formerWait, fmt.Errorf("inspect rendered object %s: %w", filename, err)
				}
			}
			location := filename + fmt.Sprintf("#%d", document)
			observePlatformSecurity(value, location, defaultNamespace, &security)
			observeFormerWaitResource(value, location, defaultNamespace, &formerWait)
			if err := collectRenderedConfigFiles(value, configMaps, &mountedConfigBytes); err != nil {
				return nil, nil, "", security, formerWait, fmt.Errorf("inspect rendered object %s: %w", filename, err)
			}
			collectControllerConfigImages(value, location, &contract, &images)
			walkRuntime(value, location, nil, &contract, &images)
		}
	}
	if err := attachMountedConfigFiles(contract.Pods, configMaps); err != nil {
		return nil, nil, "", security, formerWait, err
	}
	contract.AnnotatedRepositories = compactSorted(contract.AnnotatedRepositories)
	sort.Slice(contract.ImageFields, func(i, j int) bool {
		if contract.ImageFields[i].Location != contract.ImageFields[j].Location {
			return contract.ImageFields[i].Location < contract.ImageFields[j].Location
		}
		return contract.ImageFields[i].Reference < contract.ImageFields[j].Reference
	})
	compactImageFields := contract.ImageFields[:0]
	for _, field := range contract.ImageFields {
		if len(compactImageFields) != 0 &&
			compactImageFields[len(compactImageFields)-1] == field {
			continue
		}
		compactImageFields = append(compactImageFields, field)
	}
	contract.ImageFields = compactImageFields
	images = compactSorted(images)
	sort.Slice(contract.Pods, func(i, j int) bool { return contract.Pods[i].Location < contract.Pods[j].Location })
	invocations, err := applicationInvocations(contract.Pods, contract.ImageFields)
	if err != nil {
		return nil, nil, "", security, formerWait, err
	}
	encoded, err := json.Marshal(contract)
	if err != nil {
		return nil, nil, "", security, formerWait, fmt.Errorf("encode runtime contract: %w", err)
	}
	hash := sha256.Sum256(encoded)
	normalizePlatformSecurity(&security)
	return images, invocations, hex.EncodeToString(hash[:]), security, formerWait, nil
}

func collectControllerConfigImages(
	value any,
	location string,
	contract *runtimeContract,
	images *[]string,
) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	kind, _ := object["kind"].(string)
	if kind != "ConfigMap" {
		return
	}
	for _, section := range []string{"data", "binaryData"} {
		entries, _ := object[section].(map[string]any)
		for key, raw := range entries {
			content, ok := raw.(string)
			if !ok || section == "binaryData" {
				continue
			}
			var decoded any
			if err := yaml.Unmarshal([]byte(content), &decoded); err != nil {
				continue
			}
			hub, tag := structuredImageDefaults(decoded)
			collectStructuredControllerImages(
				decoded,
				hub,
				tag,
				location+"/data/"+key,
				contract,
				images,
			)
		}
	}
}

func structuredImageDefaults(value any) (string, string) {
	switch typed := value.(type) {
	case map[string]any:
		if global, ok := typed["global"].(map[string]any); ok {
			hub, _ := global["hub"].(string)
			tag, _ := global["tag"].(string)
			if hub != "" && tag != "" {
				return hub, tag
			}
		}
		for _, nested := range typed {
			if hub, tag := structuredImageDefaults(nested); hub != "" && tag != "" {
				return hub, tag
			}
		}
	case []any:
		for _, nested := range typed {
			if hub, tag := structuredImageDefaults(nested); hub != "" && tag != "" {
				return hub, tag
			}
		}
	}
	return "", ""
}

func collectStructuredControllerImages(
	value any,
	inheritedHub string,
	inheritedTag string,
	location string,
	contract *runtimeContract,
	images *[]string,
) {
	switch typed := value.(type) {
	case map[string]any:
		hub, _ := typed["hub"].(string)
		if hub == "" {
			hub = inheritedHub
		}
		tag, _ := typed["tag"].(string)
		if tag == "" {
			tag = inheritedTag
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			field := typed[key]
			if key == "image" {
				imageName, _ := field.(string)
				reference := ""
				if strings.Contains(imageName, "/") {
					reference = imageName
				} else if imageName != "" && hub != "" && tag != "" {
					reference = strings.TrimSuffix(hub, "/") + "/" +
						imageName + ":" + strings.TrimPrefix(tag, "v")
				}
				if validImageReference(reference) {
					*images = append(*images, reference)
					contract.ImageFields = append(
						contract.ImageFields,
						imageFieldContract{
							Location:  location + "/" + key,
							Reference: reference,
						},
					)
				}
			}
			collectStructuredControllerImages(
				field,
				hub,
				tag,
				location+"/"+key,
				contract,
				images,
			)
		}
	case []any:
		for index, entry := range typed {
			collectStructuredControllerImages(
				entry,
				inheritedHub,
				inheritedTag,
				fmt.Sprintf("%s/%d", location, index),
				contract,
				images,
			)
		}
	}
}

// installActiveHelmResource keeps only objects that Helm can create during
// the selected install render. Hook annotations are lifecycle declarations,
// not image inventory. A resource with hooks is install-active only when at
// least one install hook is present.
func installActiveHelmResource(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return true
	}
	metadata, _ := object["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	hooks, _ := annotations["helm.sh/hook"].(string)
	if strings.TrimSpace(hooks) == "" {
		return true
	}
	for _, hook := range strings.Split(hooks, ",") {
		switch strings.TrimSpace(hook) {
		case "pre-install", "post-install":
			return true
		}
	}
	return false
}

func applicationInvocations(
	pods []podContract,
	imageFields []imageFieldContract,
) ([]containerInvocation, error) {
	count := len(imageFields)
	for i := range pods {
		count += len(pods[i].Containers) + len(pods[i].InitContainers) + len(pods[i].Ephemeral)
	}
	invocations := make([]containerInvocation, 0, count)
	for i := range pods {
		podMountPaths := podContainerMountPaths(pods[i])
		appendContainers := func(kind string, containers []containerContract) error {
			for j := range containers {
				runtimeContractSHA256, err := invocationRuntimeContractSHA256(
					pods[i],
					kind,
					containers[j],
				)
				if err != nil {
					return err
				}
				invocations = append(invocations, containerInvocation{
					Location:              pods[i].Location + "/" + kind + "/" + containers[j].Name,
					Name:                  containers[j].Name,
					Reference:             containers[j].Reference,
					Repository:            containers[j].Repository,
					Command:               containers[j].LiteralCommand,
					Args:                  containers[j].LiteralArgs,
					Runtime:               containers[j].Runtime,
					PodRuntime:            pods[i].Runtime,
					PodMountPaths:         podMountPaths,
					MountedFiles:          cloneMountedConfigFiles(containers[j].MountedFiles),
					RuntimeContractSHA256: runtimeContractSHA256,
				})
			}
			return nil
		}
		for _, group := range []struct {
			kind       string
			containers []containerContract
		}{
			{kind: "containers", containers: pods[i].Containers},
			{kind: "initContainers", containers: pods[i].InitContainers},
			{kind: "ephemeralContainers", containers: pods[i].Ephemeral},
		} {
			if err := appendContainers(group.kind, group.containers); err != nil {
				return nil, err
			}
		}
	}
	for _, field := range imageFields {
		encoded, err := json.Marshal(field)
		if err != nil {
			return nil, fmt.Errorf("encode image field contract %s: %w", field.Location, err)
		}
		digest := sha256.Sum256(encoded)
		invocations = append(invocations, containerInvocation{
			Location:              field.Location,
			Reference:             field.Reference,
			Repository:            imageRepository(field.Reference),
			Runtime:               map[string]any{},
			PodRuntime:            map[string]any{},
			RuntimeContractSHA256: hex.EncodeToString(digest[:]),
		})
	}
	sort.Slice(invocations, func(i, j int) bool {
		if invocations[i].Location != invocations[j].Location {
			return invocations[i].Location < invocations[j].Location
		}
		return invocations[i].Reference < invocations[j].Reference
	})
	return invocations, nil
}

func podContainerMountPaths(pod podContract) []string {
	containers := make([]containerContract, 0,
		len(pod.Containers)+len(pod.InitContainers)+len(pod.Ephemeral))
	containers = append(containers, pod.Containers...)
	containers = append(containers, pod.InitContainers...)
	containers = append(containers, pod.Ephemeral...)
	var paths []string
	for index := range containers {
		paths = append(paths, invocationMountPaths(containers[index].Runtime)...)
	}
	return compactSorted(paths)
}

func collectRenderedConfigFiles(
	value any,
	destination map[string][]renderedConfigFile,
	totalBytes *int64,
) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if kind, _ := object["kind"].(string); kind == "ConfigMap" {
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if name != "" {
			files, err := renderedConfigFiles(object, totalBytes)
			if err != nil {
				return fmt.Errorf("ConfigMap %s/%s: %w", namespace, name, err)
			}
			if len(files) != 0 {
				destination[namespacedObjectKey(namespace, name)] = files
			}
		}
	}
	for _, field := range object {
		switch nested := field.(type) {
		case map[string]any:
			if err := collectRenderedConfigFiles(nested, destination, totalBytes); err != nil {
				return err
			}
		case []any:
			for _, entry := range nested {
				if err := collectRenderedConfigFiles(entry, destination, totalBytes); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func renderedConfigFiles(
	object map[string]any,
	totalBytes *int64,
) ([]renderedConfigFile, error) {
	files := make(map[string][]byte)
	data, _ := object["data"].(map[string]any)
	for key, raw := range data {
		content, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("data key %q is not a string", key)
		}
		files[key] = []byte(content)
	}
	binaryData, _ := object["binaryData"].(map[string]any)
	for key, raw := range binaryData {
		encoded, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("binaryData key %q is not a string", key)
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode binaryData key %q: %w", key, err)
		}
		files[key] = content
	}
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]renderedConfigFile, 0, len(keys))
	for _, key := range keys {
		content := files[key]
		if len(content) > maxMountedConfigFileBytes {
			return nil, fmt.Errorf(
				"key %q exceeds %d bytes",
				key,
				maxMountedConfigFileBytes,
			)
		}
		*totalBytes += int64(len(content))
		if *totalBytes > maxMountedConfigTotalBytes {
			return nil, fmt.Errorf(
				"mounted ConfigMap content exceeds %d bytes",
				maxMountedConfigTotalBytes,
			)
		}
		digest := sha256.Sum256(content)
		result = append(result, renderedConfigFile{
			key:     key,
			content: append([]byte(nil), content...),
			sha256:  hex.EncodeToString(digest[:]),
		})
	}
	return result, nil
}

func attachMountedConfigFiles(
	pods []podContract,
	configMaps map[string][]renderedConfigFile,
) error {
	configMapsByName := make(map[string][]renderedConfigFile, len(configMaps))
	for key, files := range configMaps {
		_, name, found := strings.Cut(key, "\x00")
		if !found {
			continue
		}
		configMapsByName[name] = append(configMapsByName[name], files...)
	}
	for name := range configMapsByName {
		sort.Slice(configMapsByName[name], func(i, j int) bool {
			return configMapsByName[name][i].key < configMapsByName[name][j].key
		})
	}
	for podIndex := range pods {
		namespace, _ := pods[podIndex].Metadata["namespace"].(string)
		volumes, _ := pods[podIndex].Runtime["volumes"].([]any)
		type configVolume struct {
			name  string
			items map[string]string
		}
		configMapByVolume := make(map[string]configVolume, len(volumes))
		for _, rawVolume := range volumes {
			volume, _ := rawVolume.(map[string]any)
			name, _ := volume["name"].(string)
			configMap, _ := volume["configMap"].(map[string]any)
			configMapName, _ := configMap["name"].(string)
			if name != "" && configMapName != "" {
				items := make(map[string]string)
				rawItems, _ := configMap["items"].([]any)
				for _, rawItem := range rawItems {
					item, _ := rawItem.(map[string]any)
					key, _ := item["key"].(string)
					destination, _ := item["path"].(string)
					if key == "" || destination == "" ||
						path.IsAbs(destination) || path.Clean(destination) == ".." ||
						strings.HasPrefix(path.Clean(destination), "../") {
						return fmt.Errorf("ConfigMap volume %s has invalid item projection", name)
					}
					items[key] = path.Clean(destination)
				}
				configMapByVolume[name] = configVolume{name: configMapName, items: items}
			}
		}
		for _, containers := range [...]*[]containerContract{
			&pods[podIndex].Containers,
			&pods[podIndex].InitContainers,
			&pods[podIndex].Ephemeral,
		} {
			for containerIndex := range *containers {
				mounts, _ := (*containers)[containerIndex].Runtime["volumeMounts"].([]any)
				var mounted []mountedConfigFile
				for _, rawMount := range mounts {
					mount, _ := rawMount.(map[string]any)
					volumeName, _ := mount["name"].(string)
					volume, found := configMapByVolume[volumeName]
					if !found {
						continue
					}
					mountPath, _ := mount["mountPath"].(string)
					if !path.IsAbs(mountPath) {
						return fmt.Errorf("ConfigMap volume %s has non-absolute mountPath", volumeName)
					}
					subPath, _ := mount["subPath"].(string)
					files := renderedConfigMapFiles(
						configMaps,
						configMapsByName,
						namespace,
						volume.name,
					)
					for _, file := range files {
						projected := file.key
						if len(volume.items) != 0 {
							var selected bool
							projected, selected = volume.items[file.key]
							if !selected {
								continue
							}
						}
						destination := path.Join(mountPath, projected)
						if subPath != "" {
							if subPath != file.key && subPath != projected {
								continue
							}
							destination = path.Clean(mountPath)
						}
						mounted = append(mounted, mountedConfigFile{
							Source:      namespacedObjectKey(namespace, volume.name),
							Key:         file.key,
							Destination: destination,
							SHA256:      file.sha256,
							Content:     append([]byte(nil), file.content...),
						})
					}
				}
				sort.Slice(mounted, func(i, j int) bool {
					if mounted[i].Destination != mounted[j].Destination {
						return mounted[i].Destination < mounted[j].Destination
					}
					return mounted[i].Key < mounted[j].Key
				})
				(*containers)[containerIndex].MountedFiles = mounted
			}
		}
	}
	return nil
}

func renderedConfigMapFiles(
	configMaps map[string][]renderedConfigFile,
	configMapsByName map[string][]renderedConfigFile,
	namespace, name string,
) []renderedConfigFile {
	if files := configMaps[namespacedObjectKey(namespace, name)]; len(files) != 0 {
		return files
	}
	if files := configMaps[namespacedObjectKey("", name)]; len(files) != 0 {
		return files
	}
	return configMapsByName[name]
}

func cloneMountedConfigFiles(files []mountedConfigFile) []mountedConfigFile {
	result := make([]mountedConfigFile, len(files))
	for i := range files {
		result[i] = files[i]
		result[i].Content = append([]byte(nil), files[i].Content...)
	}
	return result
}

func namespacedObjectKey(namespace, name string) string {
	return namespace + "\x00" + name
}

func invocationRuntimeContractSHA256(
	pod podContract,
	kind string,
	container containerContract,
) (string, error) {
	contract := struct {
		Metadata  map[string]any    `json:"metadata,omitempty"`
		Pod       map[string]any    `json:"pod,omitempty"`
		Kind      string            `json:"kind"`
		Container containerContract `json:"container"`
	}{
		Metadata:  pod.Metadata,
		Pod:       pod.Runtime,
		Kind:      kind,
		Container: container,
	}
	encoded, err := json.Marshal(contract)
	if err != nil {
		return "", fmt.Errorf("encode runtime contract for %s/%s: %w", pod.Location, container.Name, err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
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
		collectResourceImageFields(typed, location, contract, images)
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

func collectResourceImageFields(
	value map[string]any,
	location string,
	contract *runtimeContract,
	images *[]string,
) {
	containerName, _ := value["name"].(string)
	for _, field := range [...]string{"image", "imageName", "image_name"} {
		reference, _ := value[field].(string)
		if field == "image_name" && imageTag(reference) == "" {
			if version, _ := value["image_version"].(string); version != "" {
				reference += ":" + version
			}
		}
		if reference != "auto" && validImageReference(reference) {
			*images = append(*images, reference)
			if field == "image" && containerName != "" {
				continue
			}
			contract.ImageFields = append(contract.ImageFields, imageFieldContract{
				Location:  location + "/" + field,
				Reference: reference,
			})
		}
	}
}

func runtimeMetadata(value any, images *[]string) map[string]any {
	metadata, _ := value.(map[string]any)
	result := make(map[string]any, 3)
	if namespace, _ := metadata["namespace"].(string); namespace != "" {
		result["namespace"] = namespace
	}
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
			Reference:      image,
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
	if result == nil {
		return []string{}
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
