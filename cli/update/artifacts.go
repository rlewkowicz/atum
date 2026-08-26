package update

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"atum/cli/config"

	"golang.org/x/sync/errgroup"
)

type artifactInput struct {
	ID        string
	Path      string
	Values    map[string]any
	Instances []releaseValueInstance
	Bindings  []artifactBinding
	Sources   []map[string]any
}

type artifactRenderError struct {
	id        string
	candidate bool
	err       error
}

func (err *artifactRenderError) Error() string { return err.err.Error() }

func (err *artifactRenderError) Unwrap() error { return err.err }

func candidateRenderError(id string, err error) error {
	return &artifactRenderError{id: id, candidate: true, err: err}
}

func artifactBindings(
	chartRegistry config.Registry,
	packages []config.Package,
	charts []config.TrackedChart,
	values map[string]any,
) ([]artifactBinding, []map[string]any, error) {
	bindings := make([]artifactBinding, 0, len(packages)+len(charts))
	for _, pkg := range packages {
		packageValues, err := valuesAt(values, pkg.ValuesPath)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve package %s source binding: %w", pkg.ID, err)
		}
		helmValues, _ := packageValues["helmRepo"].(map[string]any)
		repositoryName, _ := helmValues["repoName"].(string)
		chartName, _ := helmValues["chartName"].(string)
		version, _ := helmValues["tag"].(string)
		sourceType, _ := packageValues["sourceType"].(string)
		if sourceType != "helmRepo" || repositoryName == "" ||
			chartName == "" || version == "" {
			return nil, nil, fmt.Errorf(
				"package %s has an incomplete Harbor Helm repository binding", pkg.ID,
			)
		}
		binding := artifactBinding{
			id:                pkg.ID,
			sourceKind:        "HelmRepository",
			sourceName:        repositoryName,
			sourceNamespace:   "bigbang",
			sourceURL:         "oci://" + chartRegistry.Host + "/" + chartRegistry.Project,
			chart:             chartName,
			version:           version,
			reconcileStrategy: "Revision",
		}
		bindings = append(bindings, binding)
	}
	for _, chart := range charts {
		chartValues, err := valuesAt(values, chart.ValuesPath)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve chart %s source binding: %w", chart.ID, err)
		}
		helmValues, _ := chartValues["helmRepo"].(map[string]any)
		repositoryName, _ := helmValues["repoName"].(string)
		chartName, _ := helmValues["chartName"].(string)
		version, _ := helmValues["tag"].(string)
		sourceType, _ := chartValues["sourceType"].(string)
		if sourceType != "helmRepo" || repositoryName != "atum" ||
			chartName != chart.Name || version != chart.Version {
			return nil, nil, fmt.Errorf("chart %s has an incomplete Helm repository binding", chart.ID)
		}
		expectedURL := "oci://" + chartRegistry.Host + "/" + chartRegistry.Project
		bindings = append(bindings, artifactBinding{
			id:                chart.ID,
			sourceKind:        "HelmRepository",
			sourceName:        repositoryName,
			sourceNamespace:   "bigbang",
			sourceURL:         expectedURL,
			chart:             chartName,
			version:           version,
			reconcileStrategy: "Revision",
		})
	}
	return bindings, nil, nil
}

func candidateArtifacts(
	bigBang resolvedGit,
	chartRegistry config.Registry,
	packages []resolvedPackage,
	charts []resolvedTrackedChart,
	bootstrap []resolvedBootstrapChart,
	renderValues map[string]any,
	root string,
	files map[string][]byte,
) ([]artifactInput, error) {
	inputs := make([]artifactInput, 0, 1+len(packages)+len(charts)+len(bootstrap))
	configuredPackages := make([]config.Package, len(packages))
	for i := range packages {
		configuredPackages[i] = packages[i].Package
	}
	configuredCharts := make([]config.TrackedChart, len(charts))
	for i := range charts {
		configuredCharts[i] = charts[i].Chart
	}
	bindings, sources, err := artifactBindings(chartRegistry, configuredPackages, configuredCharts, renderValues)
	if err != nil {
		return nil, err
	}
	inputs = append(inputs, artifactInput{
		ID: "bigbang", Path: filepath.Join(bigBang.Checkout, "chart"), Values: renderValues,
		Bindings: bindings, Sources: sources,
	})
	for _, pkg := range packages {
		inputs = append(inputs, artifactInput{
			ID:   "package/" + pkg.Package.ID,
			Path: filepath.Join(pkg.Checkout, filepath.FromSlash(pkg.Package.RepositoryChartPath())),
		})
	}
	for _, chart := range charts {
		inputs = append(inputs, artifactInput{
			ID:   "chart/" + chart.Chart.ID,
			Path: chart.ArchivePath,
		})
	}
	for _, chart := range bootstrap {
		values, err := readManagedYAML(root, files, chart.Chart.Values)
		if err != nil {
			return nil, err
		}
		source, err := bootstrapSourceValues(root, chart.Chart, files)
		if err != nil {
			return nil, err
		}
		instance, err := readBootstrapRelease(root, chart.Chart, values, source, files)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, artifactInput{
			ID:        "bootstrap/" + chart.Chart.ID,
			Path:      chart.ArchivePath,
			Instances: []releaseValueInstance{instance},
		})
	}
	return inputs, nil
}

func selectedArtifacts(inputs []artifactInput) ([]chartArtifact, error) {
	ids := make(map[string]struct{}, len(inputs))
	artifacts := make([]chartArtifact, len(inputs))
	for index := range inputs {
		if _, duplicate := ids[inputs[index].ID]; duplicate {
			return nil, fmt.Errorf("selected chart %s is duplicated", inputs[index].ID)
		}
		ids[inputs[index].ID] = struct{}{}
		artifacts[index] = chartArtifact{
			ID:        inputs[index].ID,
			Path:      inputs[index].Path,
			Values:    inputs[index].Values,
			Instances: inputs[index].Instances,
			Bindings:  inputs[index].Bindings,
			Sources:   inputs[index].Sources,
		}
	}
	return artifacts, nil
}

func inspectArtifacts(
	ctx context.Context,
	parallelism int,
	kubernetesVersion string,
	artifacts []chartArtifact,
	report func(string, int, int),
) ([]chartInspection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inspections := make([]chartInspection, len(artifacts))
	bigBangIndex := -1
	for index := range artifacts {
		if artifacts[index].ID == "bigbang" {
			bigBangIndex = index
			break
		}
	}
	if bigBangIndex < 0 {
		return nil, errors.New("artifact set has no Big Bang chart")
	}
	collector := newReleaseValueCollector("bigbang")
	for _, source := range artifacts[bigBangIndex].Sources {
		if err := collector.observe(source); err != nil {
			return nil, fmt.Errorf("observe selected Big Bang source: %w", err)
		}
	}
	inspection, err := renderChart(
		artifacts[bigBangIndex].Path,
		kubernetesVersion,
		artifacts[bigBangIndex].Values,
		collector,
		releaseOptions("bigbang", "bigbang"),
	)
	if err != nil {
		return nil, candidateRenderError("bigbang", fmt.Errorf("render bigbang: %w", err))
	}
	inspections[bigBangIndex] = inspection
	completed := 0
	var progressMu sync.Mutex
	if report != nil {
		completed++
		report(artifacts[bigBangIndex].ID, completed, len(artifacts))
	}
	releaseValues, err := collector.valuesForArtifacts(artifacts[bigBangIndex].Bindings)
	if err != nil {
		return nil, err
	}
	for index := range artifacts {
		if !strings.HasPrefix(artifacts[index].ID, "package/") &&
			!strings.HasPrefix(artifacts[index].ID, "chart/") {
			continue
		}
		releaseName := strings.SplitN(artifacts[index].ID, "/", 2)[1]
		instances := releaseValues[releaseName]
		artifacts[index].Instances = append(
			artifacts[index].Instances[:0],
			instances...,
		)
	}

	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for index := range artifacts {
		index := index
		if index == bigBangIndex {
			continue
		}
		group.Go(func() error {
			if err := groupContext.Err(); err != nil {
				return err
			}
			artifact := artifacts[index]
			var selected chartInspection
			var renderErr error
			if strings.HasPrefix(artifact.ID, "package/") ||
				strings.HasPrefix(artifact.ID, "chart/") {
				releaseName := strings.SplitN(artifact.ID, "/", 2)[1]
				selected, renderErr = inspectChartInstances(
					artifact.Path,
					kubernetesVersion,
					releaseValues[releaseName],
				)
			} else if len(artifact.Instances) != 0 {
				selected, renderErr = inspectChartInstances(
					artifact.Path,
					kubernetesVersion,
					artifact.Instances,
				)
			} else {
				selected, renderErr = inspectChart(
					artifact.Path,
					kubernetesVersion,
					artifact.Values,
				)
			}
			if renderErr != nil {
				return candidateRenderError(
					artifact.ID,
					fmt.Errorf("render %s: %w", artifact.ID, renderErr),
				)
			}
			inspections[index] = selected
			if report != nil {
				progressMu.Lock()
				completed++
				report(artifact.ID, completed, len(artifacts))
				progressMu.Unlock()
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return inspections, nil
}

func inspectAppliedArtifacts(
	ctx context.Context,
	parallelism int,
	kubernetesVersion string,
	root string,
	desired config.Document,
	operational map[string]any,
	generated map[string]any,
	profile map[string]any,
	bootstrapValues map[string]map[string]any,
	artifacts []chartArtifact,
	files map[string][]byte,
	report func(string, int, int),
) ([]chartArtifact, []chartInspection, error) {
	exact := make([]chartArtifact, len(artifacts))
	copy(exact, artifacts)
	bootstrapByID := make(map[string]config.Chart, len(desired.Platform.Bootstrap.Charts))
	for _, chart := range desired.Platform.Bootstrap.Charts {
		if _, duplicate := bootstrapByID[chart.ID]; duplicate {
			return nil, nil, fmt.Errorf("candidate bootstrap chart %s is duplicated", chart.ID)
		}
		bootstrapByID[chart.ID] = chart
	}
	for i := range exact {
		switch {
		case exact[i].ID == "bigbang":
			var err error
			exact[i].Values, err = config.MergePlatformValues(
				operational, generated, profile,
			)
			if err != nil {
				return nil, nil, err
			}
			bindings, sources, err := artifactBindings(
				desired.Platform.Bootstrap.Registry,
				desired.Platform.Packages,
				desired.Platform.Charts,
				exact[i].Values,
			)
			if err != nil {
				return nil, nil, err
			}
			exact[i].Bindings, exact[i].Sources = bindings, sources
		case strings.HasPrefix(exact[i].ID, "bootstrap/"):
			id := strings.TrimPrefix(exact[i].ID, "bootstrap/")
			chart, exists := bootstrapByID[id]
			if !exists {
				return nil, nil, fmt.Errorf("candidate bootstrap chart %s is missing", id)
			}
			source, err := bootstrapSourceValues(root, chart, files)
			if err != nil {
				return nil, nil, err
			}
			instance, err := readBootstrapRelease(root, chart, bootstrapValues[id], source, files)
			if err != nil {
				return nil, nil, err
			}
			exact[i].Instances = []releaseValueInstance{instance}
		}
	}
	inspections, err := inspectArtifacts(
		ctx,
		parallelism,
		kubernetesVersion,
		exact,
		report,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("render exact deployed values: %w", err)
	}
	allowed := make(map[string]struct{}, len(desired.Delivery.Images))
	for _, image := range desired.Delivery.Images {
		allowed[image.Target] = struct{}{}
	}
	var untracked []string
	for i := range exact {
		for _, reference := range inspections[i].Images {
			if _, exists := allowed[reference]; !exists {
				untracked = append(untracked, exact[i].ID+"="+reference)
			}
		}
	}
	if len(untracked) != 0 {
		sort.Strings(untracked)
		return nil, nil, fmt.Errorf(
			"exact applied values render untracked runtime images: %s",
			strings.Join(untracked, ", "),
		)
	}
	return exact, inspections, nil
}

func readBootstrapRelease(
	root string,
	chart config.Chart,
	values map[string]any,
	sourceOverride map[string]any,
	files map[string][]byte,
) (releaseValueInstance, error) {
	relative := filepath.Join(filepath.Dir(chart.Values), "helmrelease.yaml")
	release, err := readManagedYAML(root, files, relative)
	if err != nil {
		return releaseValueInstance{}, err
	}
	apiVersion, _ := release["apiVersion"].(string)
	kind, _ := release["kind"].(string)
	metadata, _ := release["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if apiVersion != "helm.toolkit.fluxcd.io/v2" || kind != "HelmRelease" || name == "" || namespace == "" {
		return releaseValueInstance{}, fmt.Errorf("bootstrap chart %s HelmRelease requires name and namespace", chart.ID)
	}
	spec, _ := release["spec"].(map[string]any)
	targetNamespace, _ := spec["targetNamespace"].(string)
	if targetNamespace == "" {
		targetNamespace = namespace
	}
	releaseName, _ := spec["releaseName"].(string)
	if releaseName == "" {
		if configuredTarget, _ := spec["targetNamespace"].(string); configuredTarget != "" {
			releaseName = configuredTarget + "-" + name
		} else {
			releaseName = name
		}
	}
	releaseName = shortenReleaseName(releaseName)
	chartRef, _ := spec["chartRef"].(map[string]any)
	sourceKind, _ := chartRef["kind"].(string)
	sourceName, _ := chartRef["name"].(string)
	sourceNamespace, _ := chartRef["namespace"].(string)
	if sourceKind != "OCIRepository" || sourceName != chart.ID || sourceNamespace != namespace {
		return releaseValueInstance{}, fmt.Errorf("bootstrap chart %s HelmRelease has an invalid OCI chartRef", chart.ID)
	}
	valuesFrom, _ := spec["valuesFrom"].([]any)
	if len(valuesFrom) != 1 {
		return releaseValueInstance{}, fmt.Errorf("bootstrap chart %s HelmRelease must have one valuesFrom entry", chart.ID)
	}
	valueSource, _ := valuesFrom[0].(map[string]any)
	valueKind, _ := valueSource["kind"].(string)
	valueName, _ := valueSource["name"].(string)
	valueKey, _ := valueSource["valuesKey"].(string)
	if valueKind != "ConfigMap" || valueName != chart.ID+"-values" || valueKey != "values.yaml" {
		return releaseValueInstance{}, fmt.Errorf("bootstrap chart %s HelmRelease does not bind its managed values ConfigMap", chart.ID)
	}
	if sourceOverride == nil {
		sourceOverride, err = readManagedYAML(root, files, chart.FluxSource)
		if err != nil {
			return releaseValueInstance{}, err
		}
	}
	if err := validateBootstrapSource(chart, namespace, sourceOverride); err != nil {
		return releaseValueInstance{}, err
	}
	return releaseValueInstance{
		identity:  namespace + "/" + name,
		name:      releaseName,
		namespace: targetNamespace,
		values:    values,
	}, nil
}

func bootstrapSourceValues(root string, chart config.Chart, files map[string][]byte) (map[string]any, error) {
	current, err := readManagedYAML(root, files, chart.FluxSource)
	if err != nil {
		return nil, err
	}
	candidate := cloneMap(current)
	if err := setScalar(candidate, "spec.url", bootstrapOCIURL(chart.Target)); err != nil {
		return nil, fmt.Errorf("update bootstrap source %s URL: %w", chart.ID, err)
	}
	if err := setScalar(candidate, "spec.ref.tag", chart.Version); err != nil {
		return nil, fmt.Errorf("update bootstrap source %s tag: %w", chart.ID, err)
	}
	return candidate, nil
}

func validateBootstrapSource(chart config.Chart, namespace string, source map[string]any) error {
	apiVersion, _ := source["apiVersion"].(string)
	kind, _ := source["kind"].(string)
	metadata, _ := source["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	sourceNamespace, _ := metadata["namespace"].(string)
	spec, _ := source["spec"].(map[string]any)
	url, _ := spec["url"].(string)
	insecure, _ := spec["insecure"].(bool)
	interval, _ := spec["interval"].(string)
	provider, _ := spec["provider"].(string)
	timeout, _ := spec["timeout"].(string)
	ref, _ := spec["ref"].(map[string]any)
	tag, _ := ref["tag"].(string)
	layer, _ := spec["layerSelector"].(map[string]any)
	mediaType, _ := layer["mediaType"].(string)
	operation, _ := layer["operation"].(string)
	if apiVersion != "source.toolkit.fluxcd.io/v1" || kind != "OCIRepository" ||
		name != chart.ID || sourceNamespace != namespace || url != bootstrapOCIURL(chart.Target) || tag != chart.Version ||
		!insecure || interval != "30m" || provider != "generic" || timeout != "60s" || len(spec) != 7 ||
		len(ref) != 1 || len(layer) != 2 || mediaType != "application/vnd.cncf.helm.chart.content.v1.tar+gzip" || operation != "copy" {
		return fmt.Errorf("bootstrap chart %s OCIRepository does not exactly bind target %s", chart.ID, chart.Target)
	}
	return nil
}

func bootstrapOCIURL(target string) string {
	return "oci://" + imageRepository(target)
}
