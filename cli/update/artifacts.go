package update

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/gitcache"

	"golang.org/x/sync/errgroup"
)

type artifactInput struct {
	ID                     string
	Path                   string
	InvocationBaselinePath string
	InvocationRepositories []string
	Values                 map[string]any
	Instances              []releaseValueInstance
	Bindings               []artifactBinding
	Sources                []map[string]any
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
	root string,
	registry config.SourceRegistry,
	chartRegistry config.Registry,
	packages []config.Package,
	charts []config.TrackedChart,
	values map[string]any,
	files map[string][]byte,
) ([]artifactBinding, []map[string]any, error) {
	bindings := make([]artifactBinding, 0, len(packages)+len(charts))
	sources := make([]map[string]any, 0, len(charts))
	for _, pkg := range packages {
		packageValues, err := valuesAt(values, pkg.ValuesPath)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve package %s source binding: %w", pkg.ID, err)
		}
		gitValues, _ := packageValues["git"].(map[string]any)
		chartPath, _ := gitValues["path"].(string)
		if strings.TrimSpace(chartPath) == "" {
			chartPath = "./chart"
		}
		bindings = append(bindings, artifactBinding{
			id:                pkg.ID,
			sourceKind:        "GitRepository",
			sourceURL:         internalSourceURL(registry, registry.UpstreamOrganization, pkg.ID),
			sourceTag:         renderedPackageGitTag(pkg.Source),
			sourceBranch:      pkg.Source.Branch,
			sourceCommit:      pkg.Source.Commit,
			chart:             chartPath,
			reconcileStrategy: "Revision",
			defaultReconcile:  true,
		})
	}
	loadedSources := make(map[string]map[string]any, len(charts))
	for _, chart := range charts {
		chartValues, err := valuesAt(values, chart.ValuesPath)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve chart %s source binding: %w", chart.ID, err)
		}
		helmValues, _ := chartValues["helmRepo"].(map[string]any)
		repositoryName, _ := helmValues["repoName"].(string)
		chartName, _ := helmValues["chartName"].(string)
		version, _ := helmValues["tag"].(string)
		if repositoryName == "" || chartName == "" || version == "" {
			return nil, nil, fmt.Errorf("chart %s has an incomplete Helm repository binding", chart.ID)
		}
		source, exists := loadedSources[chart.FluxSource]
		if !exists {
			source, err = readManagedYAML(root, files, chart.FluxSource)
			if err != nil {
				return nil, nil, fmt.Errorf("decode chart %s Flux source: %w", chart.ID, err)
			}
			loadedSources[chart.FluxSource] = source
			sources = append(sources, source)
		}
		metadata, _ := source["metadata"].(map[string]any)
		sourceName, _ := metadata["name"].(string)
		sourceNamespace, _ := metadata["namespace"].(string)
		kind, _ := source["kind"].(string)
		spec, _ := source["spec"].(map[string]any)
		sourceURL, _ := spec["url"].(string)
		sourceType, _ := spec["type"].(string)
		insecure, _ := spec["insecure"].(bool)
		interval, _ := spec["interval"].(string)
		provider, _ := spec["provider"].(string)
		expectedURL := "oci://" + chartRegistry.Host + "/" + chartRegistry.Project
		if kind != "HelmRepository" || sourceName != repositoryName || sourceNamespace == "" ||
			sourceType != "oci" || normalizedChartRepositoryURL(sourceURL) != expectedURL ||
			insecure == chartRegistry.TLSVerify || interval != "30m" || provider != "generic" || len(spec) != 5 {
			return nil, nil, fmt.Errorf("chart %s Flux source does not exactly bind internal HelmRepository %s at %s", chart.ID, repositoryName, expectedURL)
		}
		bindings = append(bindings, artifactBinding{
			id:                chart.ID,
			sourceKind:        kind,
			sourceName:        sourceName,
			sourceNamespace:   sourceNamespace,
			sourceURL:         sourceURL,
			chart:             chartName,
			version:           version,
			reconcileStrategy: "Revision",
		})
	}
	return bindings, sources, nil
}

func renderedPackageGitTag(source config.GitSource) string {
	if source.Commit != "" && source.Branch != "" {
		return ""
	}
	return sourceGitTag(source)
}

func (service *Service) currentArtifacts(
	ctx context.Context,
	desired config.Document,
	renderValues map[string]any,
	parallelism int,
	files map[string][]byte,
) (map[string]artifactInput, error) {
	var bigBangPath string
	var packagePaths map[string]string
	var chartPaths map[string]string
	var bootstrapPaths map[string]string
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(4)
	group.Go(func() error {
		var err error
		bigBangPath, err = service.cache.Hydrate(groupContext, "bigbang", desired.Platform.BigBang.URL, gitcache.Release{
			Version: sourceGitTag(desired.Platform.BigBang),
			Commit:  desired.Platform.BigBang.Commit,
		})
		return err
	})
	group.Go(func() error {
		var err error
		packagePaths, err = hydrateConfiguredGit(groupContext, service.cache, parallelism, desired.Platform.Packages)
		return err
	})
	group.Go(func() error {
		var err error
		chartPaths, err = fetchConfiguredTrackedCharts(groupContext, service.charts, parallelism, desired.Platform.Charts)
		return err
	})
	group.Go(func() error {
		var err error
		bootstrapPaths, err = fetchConfiguredBootstrapCharts(groupContext, service.charts, parallelism, desired.Platform.Bootstrap.Charts)
		return err
	})
	if err := group.Wait(); err != nil {
		return nil, err
	}
	bindings, sources, err := artifactBindings(service.root, desired.Platform.Sources, desired.Platform.Bootstrap.Registry, desired.Platform.Packages, desired.Platform.Charts, renderValues, files)
	if err != nil {
		return nil, err
	}
	inputs := make(map[string]artifactInput, 1+len(desired.Platform.Packages)+len(desired.Platform.Charts)+len(desired.Platform.Bootstrap.Charts))
	inputs["bigbang"] = artifactInput{
		ID: "bigbang", Path: filepath.Join(bigBangPath, "chart"), Values: renderValues,
		Bindings: bindings, Sources: sources,
	}
	for _, pkg := range desired.Platform.Packages {
		id := "package/" + pkg.ID
		inputs[id] = artifactInput{ID: id, Path: filepath.Join(packagePaths[pkg.ID], "chart")}
	}
	for _, chart := range desired.Platform.Charts {
		id := "chart/" + chart.ID
		inputs[id] = artifactInput{ID: id, Path: chartPaths[chart.ID]}
	}
	for _, chart := range desired.Platform.Bootstrap.Charts {
		values, err := readManagedYAML(service.root, files, chart.Values)
		if err != nil {
			return nil, err
		}
		id := "bootstrap/" + chart.ID
		instance, err := readBootstrapRelease(service.root, chart, values, nil, files)
		if err != nil {
			return nil, err
		}
		inputs[id] = artifactInput{ID: id, Path: bootstrapPaths[chart.ID], Instances: []releaseValueInstance{instance}}
	}
	return inputs, nil
}

func candidateArtifacts(
	bigBang resolvedGit,
	registry config.SourceRegistry,
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
	bindings, sources, err := artifactBindings(root, registry, chartRegistry, configuredPackages, configuredCharts, renderValues, files)
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
			Path: filepath.Join(pkg.Checkout, "chart"),
		})
	}
	for _, chart := range charts {
		inputs = append(inputs, artifactInput{
			ID:                     "chart/" + chart.Chart.ID,
			Path:                   chart.ArchivePath,
			InvocationBaselinePath: chart.InvocationBaselinePath,
			InvocationRepositories: chart.InvocationRepositories,
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

func pairArtifacts(current map[string]artifactInput, candidate []artifactInput) ([]chartArtifact, error) {
	paired := make([]chartArtifact, len(candidate))
	for i := range candidate {
		old, exists := current[candidate[i].ID]
		if !exists {
			return nil, fmt.Errorf("candidate chart %s has no current contract", candidate[i].ID)
		}
		paired[i] = chartArtifact{
			ID:                     candidate[i].ID,
			CurrentPath:            old.Path,
			CandidatePath:          candidate[i].Path,
			InvocationBaselinePath: candidate[i].InvocationBaselinePath,
			InvocationRepositories: candidate[i].InvocationRepositories,
			CurrentValues:          old.Values,
			CandidateValues:        candidate[i].Values,
			CurrentInstances:       old.Instances,
			CandidateInstances:     candidate[i].Instances,
			CurrentBindings:        old.Bindings,
			CandidateBindings:      candidate[i].Bindings,
			CurrentSources:         old.Sources,
			CandidateSources:       candidate[i].Sources,
		}
	}
	return paired, nil
}

func inspectCompatibleArtifacts(
	ctx context.Context,
	parallelism int,
	releases []kubernetesRelease,
	artifacts []chartArtifact,
) (kubernetesRelease, []chartInspection, []chartInspection, error) {
	renderParallelism := min(parallelism, 4)
	var failures []string
	for _, release := range releases {
		current, candidate, err := inspectArtifactPairs(ctx, renderParallelism, release.Version, artifacts)
		if err != nil {
			failures = append(failures, release.Version+": "+err.Error())
			continue
		}
		return release, current, candidate, nil
	}
	return kubernetesRelease{}, nil, nil, fmt.Errorf("no compatible Kubernetes version rendered the selected charts: %s", strings.Join(failures, "; "))
}

func inspectArtifactPairs(
	ctx context.Context,
	parallelism int,
	kubernetesVersion string,
	artifacts []chartArtifact,
) ([]chartInspection, []chartInspection, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	currentInspections := make([]chartInspection, len(artifacts))
	candidateInspections := make([]chartInspection, len(artifacts))
	bigBangIndex := -1
	for i := range artifacts {
		if artifacts[i].ID == "bigbang" {
			bigBangIndex = i
			break
		}
	}
	if bigBangIndex < 0 {
		return nil, nil, fmt.Errorf("artifact set has no Big Bang chart")
	}
	currentCollector := newReleaseValueCollector("bigbang")
	candidateCollector := newReleaseValueCollector("bigbang")
	for _, source := range artifacts[bigBangIndex].CandidateSources {
		if err := candidateCollector.observe(source); err != nil {
			return nil, nil, fmt.Errorf("observe candidate Big Bang source: %w", err)
		}
	}
	candidate, err := renderChart(
		artifacts[bigBangIndex].CandidatePath,
		kubernetesVersion,
		artifacts[bigBangIndex].CandidateValues,
		candidateCollector,
		releaseOptions("bigbang", "bigbang"),
		nil,
	)
	if err != nil {
		return nil, nil, candidateRenderError("bigbang", fmt.Errorf("render bigbang: %w", err))
	}
	candidateInspections[bigBangIndex] = candidate
	if artifacts[bigBangIndex].CurrentPath == artifacts[bigBangIndex].CandidatePath &&
		reflect.DeepEqual(artifacts[bigBangIndex].CurrentValues, artifacts[bigBangIndex].CandidateValues) {
		currentInspections[bigBangIndex] = candidate
		currentCollector = candidateCollector
	} else {
		for _, source := range artifacts[bigBangIndex].CurrentSources {
			if err := currentCollector.observe(source); err != nil {
				return nil, nil, fmt.Errorf("observe current Big Bang source: %w", err)
			}
		}
		current, err := renderChart(
			artifacts[bigBangIndex].CurrentPath,
			kubernetesVersion,
			artifacts[bigBangIndex].CurrentValues,
			currentCollector,
			releaseOptions("bigbang", "bigbang"),
			nil,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("render current bigbang: %w", err)
		}
		currentInspections[bigBangIndex] = current
	}
	currentReleaseValues, err := currentCollector.valuesForArtifacts(artifacts[bigBangIndex].CurrentBindings)
	if err != nil {
		return nil, nil, err
	}
	candidateReleaseValues, err := candidateCollector.valuesForArtifacts(artifacts[bigBangIndex].CandidateBindings)
	if err != nil {
		return nil, nil, err
	}

	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for i := range artifacts {
		i := i
		if i == bigBangIndex {
			continue
		}
		group.Go(func() error {
			if err := groupContext.Err(); err != nil {
				return err
			}
			managedRelease := strings.HasPrefix(artifacts[i].ID, "package/") || strings.HasPrefix(artifacts[i].ID, "chart/")
			if managedRelease {
				releaseName := strings.SplitN(artifacts[i].ID, "/", 2)[1]
				candidate, err := inspectChartInstances(artifacts[i].CandidatePath, kubernetesVersion, candidateReleaseValues[releaseName])
				if err != nil {
					return candidateRenderError(artifacts[i].ID, fmt.Errorf("render %s: %w", artifacts[i].ID, err))
				}
				if artifacts[i].InvocationBaselinePath != "" {
					baseline := candidate
					if artifacts[i].InvocationBaselinePath != artifacts[i].CandidatePath {
						baseline, err = inspectChartInstances(
							artifacts[i].InvocationBaselinePath,
							kubernetesVersion,
							candidateReleaseValues[releaseName],
						)
						if err != nil {
							return candidateRenderError(
								artifacts[i].ID,
								fmt.Errorf("render application invocation baseline for %s: %w", artifacts[i].ID, err),
							)
						}
					}
					if err := validateApplicationInvocation(
						artifacts[i].ID,
						candidate.AppVersion,
						artifacts[i].InvocationRepositories,
						baseline,
						candidate,
					); err != nil {
						return candidateRenderError(artifacts[i].ID, err)
					}
				}
				candidateInspections[i] = candidate
				if artifacts[i].CurrentPath == artifacts[i].CandidatePath &&
					reflect.DeepEqual(currentReleaseValues[releaseName], candidateReleaseValues[releaseName]) {
					currentInspections[i] = candidate
					return nil
				}
				current, err := inspectChartInstances(artifacts[i].CurrentPath, kubernetesVersion, currentReleaseValues[releaseName])
				if err != nil {
					return fmt.Errorf("render current %s: %w", artifacts[i].ID, err)
				}
				currentInspections[i] = current
				return nil
			}
			if len(artifacts[i].CandidateInstances) != 0 {
				candidate, err := inspectChartInstances(artifacts[i].CandidatePath, kubernetesVersion, artifacts[i].CandidateInstances)
				if err != nil {
					return candidateRenderError(artifacts[i].ID, fmt.Errorf("render %s: %w", artifacts[i].ID, err))
				}
				candidateInspections[i] = candidate
				if artifacts[i].CurrentPath == artifacts[i].CandidatePath &&
					reflect.DeepEqual(artifacts[i].CurrentInstances, artifacts[i].CandidateInstances) {
					currentInspections[i] = candidate
					return nil
				}
				current, err := inspectChartInstances(artifacts[i].CurrentPath, kubernetesVersion, artifacts[i].CurrentInstances)
				if err != nil {
					return fmt.Errorf("render current %s: %w", artifacts[i].ID, err)
				}
				currentInspections[i] = current
				return nil
			}
			candidate, err := inspectChart(artifacts[i].CandidatePath, kubernetesVersion, artifacts[i].CandidateValues)
			if err != nil {
				return candidateRenderError(artifacts[i].ID, fmt.Errorf("render %s: %w", artifacts[i].ID, err))
			}
			candidateInspections[i] = candidate
			if artifacts[i].CurrentPath == artifacts[i].CandidatePath && reflect.DeepEqual(artifacts[i].CurrentValues, artifacts[i].CandidateValues) {
				currentInspections[i] = candidate
				return nil
			}
			current, err := inspectChart(artifacts[i].CurrentPath, kubernetesVersion, artifacts[i].CurrentValues)
			if err != nil {
				return fmt.Errorf("render current %s: %w", artifacts[i].ID, err)
			}
			currentInspections[i] = current
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, nil, err
	}
	return currentInspections, candidateInspections, nil
}

type mappedInvocation struct {
	Command any
	Args    any
	key     string
}

func validateApplicationInvocation(
	artifact string,
	appVersion string,
	repositories []string,
	baseline chartInspection,
	candidate chartInspection,
) error {
	expected := mappedApplicationInvocations(baseline.Invocations, repositories)
	if len(expected) == 0 {
		return fmt.Errorf(
			"%s application %s invocation baseline has no container mapped to repositories %s",
			artifact, appVersion, strings.Join(repositories, ", "),
		)
	}
	actual := mappedApplicationInvocations(candidate.Invocations, repositories)
	if len(actual) == 0 {
		return fmt.Errorf(
			"%s chart %s has no container invocation mapped to application %s",
			artifact, candidate.Version, appVersion,
		)
	}
	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf(
			"%s chart %s changes the mapped application %s container command or arguments from its chart introduction",
			artifact, candidate.Version, appVersion,
		)
	}
	return nil
}

func mappedApplicationInvocations(
	invocations []containerInvocation,
	repositories []string,
) []mappedInvocation {
	result := make([]mappedInvocation, 0, len(invocations))
	for i := range invocations {
		if !containsString(repositories, invocations[i].Repository) {
			continue
		}
		result = append(result, mappedInvocation{
			Command: invocations[i].Command,
			Args:    invocations[i].Args,
			key:     fmt.Sprintf("%v\x00%v", invocations[i].Command, invocations[i].Args),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].key < result[j].key
	})
	return result
}

func validateAppliedArtifacts(
	ctx context.Context,
	parallelism int,
	kubernetesVersion string,
	root string,
	currentDesired config.Document,
	candidateDesired config.Document,
	operational map[string]any,
	currentGenerated map[string]any,
	candidateGenerated map[string]any,
	profile map[string]any,
	bootstrapValues map[string]map[string]any,
	artifacts []chartArtifact,
	files map[string][]byte,
) error {
	exact := make([]chartArtifact, len(artifacts))
	copy(exact, artifacts)
	for i := range exact {
		switch {
		case exact[i].ID == "bigbang":
			var err error
			exact[i].CurrentValues, err = config.MergePlatformValues(operational, currentGenerated, profile)
			if err != nil {
				return err
			}
			exact[i].CandidateValues, err = config.MergePlatformValues(operational, candidateGenerated, profile)
			if err != nil {
				return err
			}
			bindings, sources, err := artifactBindings(root, currentDesired.Platform.Sources, currentDesired.Platform.Bootstrap.Registry, currentDesired.Platform.Packages, currentDesired.Platform.Charts, exact[i].CurrentValues, files)
			if err != nil {
				return err
			}
			exact[i].CurrentBindings, exact[i].CurrentSources = bindings, sources
			bindings, sources, err = artifactBindings(root, candidateDesired.Platform.Sources, candidateDesired.Platform.Bootstrap.Registry, candidateDesired.Platform.Packages, candidateDesired.Platform.Charts, exact[i].CandidateValues, files)
			if err != nil {
				return err
			}
			exact[i].CandidateBindings, exact[i].CandidateSources = bindings, sources
		case strings.HasPrefix(exact[i].ID, "bootstrap/"):
			id := strings.TrimPrefix(exact[i].ID, "bootstrap/")
			chart, exists := bootstrapChartByID(candidateDesired.Platform.Bootstrap.Charts, id)
			if !exists {
				return fmt.Errorf("candidate bootstrap chart %s is missing", id)
			}
			source, err := bootstrapSourceValues(root, chart, files)
			if err != nil {
				return err
			}
			instance, err := readBootstrapRelease(root, chart, bootstrapValues[id], source, files)
			if err != nil {
				return err
			}
			exact[i].CandidateInstances = []releaseValueInstance{instance}
		}
	}
	_, candidate, err := inspectArtifactPairs(ctx, min(parallelism, 4), kubernetesVersion, exact)
	if err != nil {
		return fmt.Errorf("render exact deployed values: %w", err)
	}
	allowed := make(map[string]struct{}, len(candidateDesired.Delivery.Images))
	for _, image := range candidateDesired.Delivery.Images {
		allowed[image.Target] = struct{}{}
	}
	for i := range exact {
		for _, reference := range candidate[i].Images {
			if _, exists := allowed[reference]; !exists {
				return fmt.Errorf("exact applied %s values render untracked runtime image %s", exact[i].ID, reference)
			}
		}
	}
	return nil
}

func bootstrapChartByID(charts []config.Chart, id string) (config.Chart, bool) {
	for _, chart := range charts {
		if chart.ID == id {
			return chart, true
		}
	}
	return config.Chart{}, false
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
	var renderers []releasePostRenderer
	if raw, exists := spec["postRenderers"]; exists {
		renderers, err = decodePostRenderers(raw)
		if err != nil {
			return releaseValueInstance{}, fmt.Errorf("bootstrap chart %s has invalid postRenderers: %w", chart.ID, err)
		}
	}
	return releaseValueInstance{
		identity:  namespace + "/" + name,
		name:      releaseName,
		namespace: targetNamespace,
		values:    values,
		renderers: renderers,
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
