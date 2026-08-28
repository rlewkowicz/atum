package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitcache"
	"atum/cli/identity"
	"atum/cli/kube"
	"atum/cli/process"
	"atum/cli/progress"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Service struct {
	root   string
	cache  *gitcache.Manager
	charts *chartClient
	logger *slog.Logger
	runner process.Runner
}

type Options struct {
	Check         bool
	BigBangCommit string
	Parallelism   int
}

type Result struct {
	Changed []string
	Applied bool
}

type chartArtifact struct {
	ID        string
	Path      string
	Values    map[string]any
	Instances []releaseValueInstance
	Bindings  []artifactBinding
	Sources   []map[string]any
}

func NewService(root string, logger *slog.Logger) *Service {
	return &Service{
		root:   root,
		cache:  gitcache.New(root),
		charts: newChartClient(root),
		logger: logger,
		runner: process.ExecRunner{},
	}
}

func (service *Service) Pull(ctx context.Context, options Options) (Result, error) {
	unlock, err := service.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if _, err := recoverTransactions(service.root); err != nil {
		return Result{}, err
	}
	updateInput, err := config.LoadUpdateInput(service.root, config.LoadOptions{
		AllowStale: true, AllowMissingGeneratedIdentity: true,
		AllowMissingFluxSecrets: true,
	})
	if err != nil {
		return Result{}, err
	}
	project := updateInput.Project
	compatibilityReceipts := updateInput.CompatibilityReceipts
	desired, lock, err := cloneState(project.Desired, project.Lock)
	if err != nil {
		return Result{}, err
	}
	if options.Parallelism < 0 || options.Parallelism > 24 {
		return Result{}, fmt.Errorf(
			"update parallelism %d must be zero or between 1 and 24",
			options.Parallelism,
		)
	}
	if options.Parallelism != 0 {
		desired.Updates.Parallelism = options.Parallelism
	}
	resetRenderedImageInventory(&desired)
	previousImages := make(map[string]config.Image, len(desired.Delivery.Images))
	for index := range desired.Delivery.Images {
		image := desired.Delivery.Images[index]
		previousImages[image.ID] = image
	}
	initialImageTargets := imageTargetsByID(desired.Delivery.Images)
	currentClusterTarget, err := desired.Orchestration.TargetRelease()
	if err != nil {
		return Result{}, err
	}
	historicalBigBang := options.BigBangCommit != ""
	clusterResolutionFloor := currentClusterTarget
	if historicalBigBang {
		if err := validateGitCommit(options.BigBangCommit); err != nil {
			return Result{}, fmt.Errorf("select Big Bang commit: %w", err)
		}
		clusterResolutionFloor = desired.Orchestration.Releases[0]
	}
	tree := newCandidateTree(service.root)
	if err := trackUpdateInputs(tree, project.Desired); err != nil {
		return Result{}, fmt.Errorf("snapshot managed update inputs: %w", err)
	}
	if err := projectImageEvidenceSchema(tree); err != nil {
		return Result{}, err
	}
	desiredSnapshot, _ := tree.Data(config.DesiredFilename)
	lockSnapshot, _ := tree.Data(config.LockFilename)
	if !bytes.Equal(desiredSnapshot, project.DesiredData) || !bytes.Equal(lockSnapshot, project.LockData) {
		return Result{}, errors.New("declarative state changed while the updater was loading it; retry without discarding the concurrent edit")
	}
	managedFiles := tree.filesView()
	identityContract, err := loadCandidateIdentity(tree, desired)
	if err != nil {
		return Result{}, err
	}
	generatedIdentityValues, err := identityValues(identityContract)
	if err != nil {
		return Result{}, err
	}
	parallelism := config.EffectiveWorkLimit(
		options.Parallelism,
		desired.Updates.Parallelism,
		config.DefaultWorkLimit,
	)
	if len(desired.Platform.Flux.Assets) != 1 || desired.Platform.Flux.Assets[0].ID != "install-manifest" {
		return Result{}, errors.New("Flux source must define exactly one install-manifest asset")
	}
	platformValues, err := desired.ResolvePlatformValues(tree.YAML)
	if err != nil {
		return Result{}, err
	}
	operational := platformValues.Operational
	obsoleteChartPaths, err := canonicalizeGenericChartInventory(
		&desired,
		operational,
	)
	if err != nil {
		return Result{}, err
	}
	currentGenerated := platformValues.Generated
	generated := make(map[string]any)
	profileValues := platformValues.Profile
	if err := validateNoConfiguredStatefulCredentials(operational, currentGenerated); err != nil {
		return Result{}, err
	}
	if collision := firstNestedCollision(profileValues, generatedIdentityValues, nil); collision != "" {
		return Result{}, fmt.Errorf("profile value %s is owned by the local identity contract", collision)
	}
	statefulValues, err := loadStatefulValuesOverlay(managedFiles, desired)
	if err != nil {
		return Result{}, err
	}
	renderedStatefulValues, err := renderStatefulValuesOverlay(statefulValues, operational)
	if err != nil {
		return Result{}, err
	}
	if collision := firstNestedCollision(renderedStatefulValues, generatedIdentityValues, nil); collision != "" {
		return Result{}, fmt.Errorf(
			"stateful value %s collides with the local identity projection",
			collision,
		)
	}
	profileWithStateful := cloneMap(profileValues)
	mergeMaps(profileWithStateful, renderedStatefulValues)
	profileRenderValues, err := mergeIdentityValues(
		profileWithStateful,
		generatedIdentityValues,
	)
	if err != nil {
		return Result{}, err
	}
	profileRenderValues, err = renderFluxSubstitutedValues(
		desired,
		identityContract,
		profileRenderValues,
	)
	if err != nil {
		return Result{}, err
	}
	service.logger.InfoContext(ctx, "resolving stable upstream Git releases")
	progress.Update(ctx, progress.Platform, "update-releases", "Upstream releases",
		"resolving stable release candidates", 0, 3)
	var bigBang, kubespray, flux resolvedGit
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(min(parallelism, 3))
	var resolvedSources atomic.Int64
	reportResolvedSource := func(id string) {
		completed := int(resolvedSources.Add(1))
		progress.Update(ctx, progress.Platform, "update-releases", "Upstream releases",
			"resolved stable source "+id, completed, 3)
	}
	group.Go(func() error {
		var resolveErr error
		if historicalBigBang {
			bigBang, resolveErr = resolvePinnedGit(
				groupContext, service.cache, "bigbang", desired.Platform.BigBang, options.BigBangCommit,
			)
		} else {
			bigBang, resolveErr = resolveLatestGit(groupContext, service.cache, "bigbang", desired.Platform.BigBang)
		}
		if resolveErr == nil {
			reportResolvedSource("bigbang")
		}
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		kubespray, resolveErr = resolveLatestGit(groupContext, service.cache, "kubespray", clusterResolutionFloor.Kubespray)
		if resolveErr == nil {
			reportResolvedSource("kubespray")
		}
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		flux, resolveErr = resolveLatestGit(groupContext, service.cache, "flux", desired.Platform.Flux)
		if resolveErr == nil {
			reportResolvedSource("flux")
		}
		return resolveErr
	})
	if err := group.Wait(); err != nil {
		return Result{}, err
	}
	service.logger.InfoContext(ctx, "resolved stable upstream Git releases",
		"completed", 3, "total", 3,
		"bigBangCandidates", len(bigBang.Releases),
		"kubesprayCandidates", len(kubespray.Releases),
		"fluxCandidates", len(flux.Releases))
	bigBangDefaults, err := readBigBangValues(bigBang.Checkout)
	if err != nil {
		return Result{}, fmt.Errorf("read Big Bang %s values: %w", bigBang.Source.Version, err)
	}
	renderOperational := operational
	discoveryGenerated, err := trackedChartDiscoveryValues(desired.Platform.Charts)
	if err != nil {
		return Result{}, err
	}
	configuredValues, err := config.MergePlatformValues(
		renderOperational, discoveryGenerated, profileRenderValues,
	)
	if err != nil {
		return Result{}, err
	}
	admittedBigBang, err := admitBigBangPackageSelection(
		bigBang,
		bigBangDefaults,
		configuredValues,
		desired.Platform,
		currentClusterTarget.Kubernetes,
	)
	if err != nil {
		return Result{}, err
	}
	flux, fluxManifest, candidateFluxInspection, err := service.selectCompatibleFlux(
		ctx, desired.Platform.Flux, flux, desired,
	)
	if err != nil {
		return Result{}, err
	}
	service.logger.InfoContext(ctx, "resolving selected chart and vendor releases")
	var trackedChartCatalogs []*chartCatalog
	var bootstrapChartCatalogs []*chartCatalog
	var vendors []resolvedVendor
	group, groupContext = errgroup.WithContext(ctx)
	group.SetLimit(min(parallelism, 3))
	group.Go(func() error {
		var resolveErr error
		vendors, resolveErr = resolveVendors(groupContext, service.cache, service.root, parallelism, desired.Platform.Vendors)
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		trackedChartCatalogs, resolveErr = resolveTrackedChartCatalogs(
			groupContext, service.charts, parallelism, desired.Platform.Charts,
		)
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		bootstrapChartCatalogs, resolveErr = resolveBootstrapChartCatalogs(groupContext, service.charts, parallelism, desired.Platform.Bootstrap.Charts)
		return resolveErr
	})
	if err := group.Wait(); err != nil {
		return Result{}, err
	}

	desired.Platform.Flux = flux.Source
	for i := range vendors {
		desired.Platform.Vendors[i] = vendors[i].Vendor
	}

	service.logger.InfoContext(ctx, "selecting compatible Kubernetes and charts for the newest Big Bang")
	selection, err := service.selectCompatiblePlatform(
		ctx,
		admittedBigBang,
		kubespray,
		desired,
		lock,
		renderOperational,
		configuredValues,
		generated,
		profileRenderValues,
		trackedChartCatalogs,
		bootstrapChartCatalogs,
		parallelism,
		managedFiles,
		historicalBigBang,
		identityContract,
	)
	if err != nil {
		return Result{}, err
	}
	bigBang = selection.bigBang
	packages := selection.packages
	supportSources := selection.supportSources
	constraints := selection.constraints
	candidateGenerated := selection.generated
	trackedCharts := selection.charts
	bootstrapCharts := selection.bootstrap
	artifacts := selection.artifacts
	selectedKubernetes := selection.kubernetes
	inspections := selection.inspections
	desired.Platform.BigBang = bigBang.Source
	desired.Platform.Packages = make([]config.Package, len(packages))
	for i := range packages {
		desired.Platform.Packages[i] = packages[i].Package
	}
	desired.Orchestration.Releases = selection.clusterReleases
	for i := range trackedCharts {
		desired.Platform.Charts[i] = trackedCharts[i].Chart
	}
	for i := range bootstrapCharts {
		desired.Platform.Bootstrap.Charts[i] = bootstrapCharts[i].Chart
	}
	desired.Delivery.Kubespray, err = service.reconstructKubesprayReleaseArtifacts(
		ctx,
		&desired,
		selection.clusterReleases,
		selection.kubespray,
		parallelism,
	)
	if err != nil {
		return Result{}, err
	}
	containerdValues, err := kubesprayRegistryValues(desired)
	if err != nil {
		return Result{}, err
	}
	containerdPath := filepath.Join(
		desired.Orchestration.Inventory,
		"group_vars",
		"all",
		"containerd.yml",
	)
	if err := tree.SetYAML(containerdPath, containerdValues); err != nil {
		return Result{}, err
	}
	imageArtifacts := append([]chartArtifact(nil), artifacts...)
	imageArtifacts = append(imageArtifacts, chartArtifact{ID: "flux"})
	imageInspections := append([]chartInspection(nil), inspections...)
	imageInspections = append(imageInspections, candidateFluxInspection)
	_, err = reconstructRenderedImages(
		ctx, &desired, imageArtifacts, imageInspections,
		selectedKubernetes.Version,
	)
	if err != nil {
		return Result{}, err
	}

	_, err = reconcileBootstrapImageVersions(&desired, &lock, bootstrapCharts)
	if err != nil {
		return Result{}, err
	}
	replacements, err := imageTargetReplacements(
		initialImageTargets,
		desired.Delivery.Images,
	)
	if err != nil {
		return Result{}, err
	}
	fluxReplacements, err := renderedImageTargetReplacements(desired.Delivery.Images)
	if err != nil {
		return Result{}, err
	}
	for _, replacement := range fluxReplacements {
		fluxManifest = bytes.ReplaceAll(
			fluxManifest,
			[]byte(replacement.Old),
			[]byte(replacement.New),
		)
	}
	desired.Platform.Flux.Assets[0].SHA256 = config.SHA256(fluxManifest)
	if err := replaceImageReferences(candidateGenerated, replacements); err != nil {
		return Result{}, err
	}
	if err := projectSelectedImageValues(candidateGenerated, desired); err != nil {
		return Result{}, err
	}
	const bigBangHelmReleasePath = "platform/apps/bigbang/helmrelease.yaml"
	currentBigBangHelmRelease, err := tree.YAML(bigBangHelmReleasePath)
	if err != nil {
		return Result{}, err
	}
	candidateBigBangHelmRelease := cloneMap(currentBigBangHelmRelease)
	if err := configurePlatformValuesFrom(candidateBigBangHelmRelease); err != nil {
		return Result{}, err
	}
	if err := configureBigBangChartRef(
		candidateBigBangHelmRelease,
		desired.Platform.Bootstrap.Registry,
		desired.Platform.BigBang.Version,
	); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(
		tree,
		bigBangHelmReleasePath,
		currentBigBangHelmRelease,
		candidateBigBangHelmRelease,
	); err != nil {
		return Result{}, err
	}
	if err := renderIdentityManifests(
		tree, desired, identityContract, generatedIdentityValues,
	); err != nil {
		return Result{}, fmt.Errorf("render updater-owned identity manifests: %w", err)
	}
	fluxKustomizationPath := filepath.Join(filepath.Dir(desired.Platform.Flux.Assets[0].File), "kustomization.yaml")
	fluxSyncPath := filepath.Join(filepath.Dir(desired.Platform.Flux.Assets[0].File), "gotk-sync.yaml")
	fluxSecretSourcePath := filepath.Join(
		desired.Platform.Directory,
		"clusters",
		desired.Project.Cluster,
		"platform-secrets.yaml",
	)
	candidateFluxSync, err := renderFluxSync(desired)
	if err != nil {
		return Result{}, err
	}
	candidateFluxSecretSource, err := renderFluxSecretKustomization(desired)
	if err != nil {
		return Result{}, err
	}
	fluxKustomization, err := tree.YAML(fluxKustomizationPath)
	if err != nil {
		return Result{}, err
	}
	candidateFluxKustomization := cloneMap(fluxKustomization)
	delete(candidateFluxKustomization, "images")
	if err := replaceImageReferences(candidateFluxKustomization, replacements); err != nil {
		return Result{}, err
	}
	candidateFluxKustomizationData, err := yaml.Marshal(candidateFluxKustomization)
	if err != nil {
		return Result{}, fmt.Errorf("encode candidate Flux Kustomization: %w", err)
	}
	fluxProfilePatchPath := filepath.Join(filepath.Dir(desired.Platform.Flux.Assets[0].File), "platform-profile.yaml")
	currentFluxProfilePatch, err := tree.YAML(fluxProfilePatchPath)
	if err != nil {
		return Result{}, err
	}
	activeTarget, exists := desired.ActiveTarget()
	if !exists {
		return Result{}, fmt.Errorf("active infrastructure target %q is not defined", desired.Infrastructure.Active)
	}
	candidateFluxProfilePatch, err := fluxProfilePatch(currentFluxProfilePatch, activeTarget)
	if err != nil {
		return Result{}, err
	}
	candidateFluxProfilePatchData, err := yaml.Marshal(candidateFluxProfilePatch)
	if err != nil {
		return Result{}, fmt.Errorf("encode candidate Flux profile patch: %w", err)
	}
	fluxOverlayDirectory := filepath.Join(service.root, filepath.Dir(desired.Platform.Flux.Assets[0].File))
	candidateFluxOverlay, err := service.renderFluxOverlay(
		fluxOverlayDirectory,
		filepath.Base(desired.Platform.Flux.Assets[0].File),
		fluxManifest,
		candidateFluxKustomizationData,
		filepath.Base(fluxProfilePatchPath),
		candidateFluxProfilePatchData,
	)
	if err != nil {
		return Result{}, fmt.Errorf("render candidate Flux overlay: %w", err)
	}
	finalFluxInspection, err := inspectManifestData("flux-overlay", candidateFluxOverlay)
	if err != nil {
		return Result{}, fmt.Errorf("inspect candidate Flux overlay: %w", err)
	}

	bootstrapValues, err := readBootstrapValues(service.root, desired.Platform.Bootstrap.Charts, managedFiles)
	if err != nil {
		return Result{}, err
	}
	for _, values := range bootstrapValues {
		if err := replaceImageReferences(values, replacements); err != nil {
			return Result{}, err
		}
	}
	service.logger.InfoContext(ctx, "rendering exact applied Helm contracts",
		"completed", 0, "total", len(artifacts), "parallelism", parallelism)
	progress.Update(ctx, progress.Platform, "update-exact-render", "Exact applied rendering",
		"rendering exact applied Helm contracts", 0, len(artifacts))
	finalArtifacts, finalInspections, err := inspectAppliedArtifacts(
		ctx,
		parallelism,
		selectedKubernetes.Version,
		service.root,
		desired,
		operational,
		candidateGenerated,
		profileRenderValues,
		supportSourceValues(supportSources),
		bootstrapValues,
		artifacts,
		tree.filesView(),
		func(id string, completed, total int) {
			service.logger.InfoContext(ctx, "rendered exact applied Helm contract",
				"artifact", id, "completed", completed, "total", total)
			progress.Update(
				ctx,
				progress.Platform,
				"update-exact-render",
				"Exact applied rendering",
				"rendered exact applied chart "+id,
				completed,
				total,
			)
		},
	)
	if err != nil {
		return Result{}, err
	}
	chartInputs, err := selectedChartPackageInputs(
		bigBang, packages, supportSources, trackedCharts, bootstrapCharts, finalArtifacts,
	)
	if err != nil {
		return Result{}, err
	}
	service.logger.InfoContext(ctx, "packaging immutable Helm chart inventory",
		"completed", 0, "total", len(chartInputs), "parallelism", parallelism)
	progress.Update(ctx, progress.Platform, "update-charts", "Chart packaging",
		"packaging immutable Helm charts", 0, len(chartInputs))
	lockedCharts, err := packageChartInventory(
		ctx,
		service.root,
		desired.Platform.Bootstrap.Registry,
		parallelism,
		chartInputs,
		func(completed, total int) {
			service.logger.InfoContext(ctx, "packaged immutable Helm chart inventory",
				"completed", completed, "total", total)
			progress.Update(ctx, progress.Platform, "update-charts", "Chart packaging",
				"packaged immutable Helm charts", completed, total)
		},
	)
	if err != nil {
		return Result{}, err
	}
	packagedByID := make(map[string]config.ChartArtifact, len(lockedCharts))
	for index := range lockedCharts {
		packagedByID[lockedCharts[index].ID] = lockedCharts[index]
	}
	if err := projectPackagedPackageVersions(
		candidateGenerated,
		packages,
		packagedByID,
	); err != nil {
		return Result{}, err
	}
	for index := range finalArtifacts {
		packaged, exists := packagedByID[finalArtifacts[index].ID]
		if !exists {
			return Result{}, fmt.Errorf("packaged chart inventory is missing %s", finalArtifacts[index].ID)
		}
		finalArtifacts[index].Path = filepath.Join(service.root, filepath.FromSlash(packaged.File))
	}
	service.logger.InfoContext(ctx, "rendering exact packaged Helm contracts",
		"completed", 0, "total", len(finalArtifacts), "parallelism", parallelism)
	progress.Update(ctx, progress.Platform, "update-packaged-render", "Packaged chart rendering",
		"rendering exact packaged Helm contracts", 0, len(finalArtifacts))
	finalArtifacts, finalInspections, err = inspectAppliedArtifacts(
		ctx,
		parallelism,
		selectedKubernetes.Version,
		service.root,
		desired,
		operational,
		candidateGenerated,
		profileRenderValues,
		supportSourceValues(supportSources),
		bootstrapValues,
		finalArtifacts,
		tree.filesView(),
		func(id string, completed, total int) {
			service.logger.InfoContext(ctx, "rendered exact packaged Helm contract",
				"artifact", id, "completed", completed, "total", total)
			progress.Update(
				ctx,
				progress.Platform,
				"update-packaged-render",
				"Packaged chart rendering",
				"rendered exact packaged chart "+id,
				completed,
				total,
			)
		},
	)
	if err != nil {
		return Result{}, fmt.Errorf("render exact packaged chart inventory: %w", err)
	}
	finalArtifacts = append(finalArtifacts, chartArtifact{ID: "flux"})
	finalInspections = append(finalInspections, finalFluxInspection)
	renderContractsUnchanged :=
		reflect.DeepEqual(project.Desired.Platform.Sources, desired.Platform.Sources) &&
			reflect.DeepEqual(project.Desired.Platform.BigBang, desired.Platform.BigBang) &&
			reflect.DeepEqual(project.Desired.Platform.Flux, desired.Platform.Flux) &&
			reflect.DeepEqual(project.Desired.Platform.Packages, desired.Platform.Packages) &&
			reflect.DeepEqual(project.Desired.Platform.Charts, desired.Platform.Charts) &&
			reflect.DeepEqual(project.Desired.Platform.Bootstrap, desired.Platform.Bootstrap) &&
			reflect.DeepEqual(project.Desired.Delivery.Policy, desired.Delivery.Policy) &&
			reflect.DeepEqual(currentGenerated, candidateGenerated) &&
			currentClusterTarget.Kubernetes == selectedKubernetes.Version &&
			reflect.DeepEqual(currentClusterTarget.Checksums, selectedKubernetes.Checksums) &&
			reflect.DeepEqual(currentBigBangHelmRelease, candidateBigBangHelmRelease) &&
			reflect.DeepEqual(fluxKustomization, candidateFluxKustomization) &&
			reflect.DeepEqual(currentFluxProfilePatch, candidateFluxProfilePatch) &&
			bytes.Equal(
				managedFiles[project.Desired.Platform.Flux.Assets[0].File],
				fluxManifest,
			)
	if renderContractsUnchanged {
		for _, chart := range desired.Platform.Bootstrap.Charts {
			currentValues, valuesErr := readManagedYAML(
				service.root,
				managedFiles,
				chart.Values,
			)
			if valuesErr != nil {
				return Result{}, valuesErr
			}
			if !reflect.DeepEqual(currentValues, bootstrapValues[chart.ID]) {
				renderContractsUnchanged = false
				break
			}
		}
	}
	service.logger.InfoContext(ctx, "verifying official image runtime contracts",
		"images", len(desired.Delivery.Images),
		"parallelism", parallelism,
		"reuse", renderContractsUnchanged,
	)
	progress.Update(ctx, progress.Platform, "update-images", "Image admission",
		"verifying official image runtime contracts", 0, len(desired.Delivery.Images))
	lastAdmissionProgress := 0
	if err := admitFinalRenderedImages(
		ctx,
		parallelism,
		&desired,
		finalArtifacts,
		finalInspections,
		previousImages,
		compatibilityReceipts,
		renderContractsUnchanged,
		func(completed, total int) {
			if completed <= lastAdmissionProgress {
				return
			}
			lastAdmissionProgress = completed
			service.logger.InfoContext(ctx, "verified official image runtime contracts",
				"completed", completed,
				"total", total,
			)
			progress.Update(ctx, progress.Platform, "update-images", "Image admission",
				"verified official image runtime contracts", completed, total)
		},
	); err != nil {
		return Result{}, err
	}
	service.logger.InfoContext(ctx, "finalizing public linux/amd64 image digests")
	if _, err := refreshMirrorDigests(ctx, parallelism, &project.Desired, &desired, &lock); err != nil {
		return Result{}, err
	}
	buildGraph, err := renderBuildGraph(desired)
	if err != nil {
		return Result{}, fmt.Errorf("render canonical delivery build graph: %w", err)
	}
	if err := tree.Set(buildGraphFile, buildGraph); err != nil {
		return Result{}, err
	}
	candidateProject := *project
	candidateProject.Desired = desired
	candidateProject.Lock = lock
	graphSHA, err := config.DeliveryGraphSHA256WithFiles(&candidateProject, lock.Delivery.Profile, tree.filesView())
	if err != nil {
		return Result{}, fmt.Errorf("resolve candidate delivery graph: %w", err)
	}
	contentReplacements, err := projectContentAddressedBuildTargets(
		&desired,
		lock.Delivery.Profile,
		graphSHA,
	)
	if err != nil {
		return Result{}, err
	}
	if err := replaceImageReferences(candidateGenerated, contentReplacements); err != nil {
		return Result{}, err
	}
	if err := projectSelectedImageValues(candidateGenerated, desired); err != nil {
		return Result{}, err
	}
	for _, values := range bootstrapValues {
		if err := replaceImageReferences(values, contentReplacements); err != nil {
			return Result{}, err
		}
	}
	if err := projectOperatorImage(tree, desired.Delivery.Images); err != nil {
		return Result{}, err
	}
	buildGraph, err = renderBuildGraph(desired)
	if err != nil {
		return Result{}, fmt.Errorf("render content-addressed delivery build graph: %w", err)
	}
	if err := tree.Set(buildGraphFile, buildGraph); err != nil {
		return Result{}, err
	}
	candidateProject.Desired = desired
	contentGraphSHA, err := config.DeliveryGraphSHA256WithFiles(
		&candidateProject,
		lock.Delivery.Profile,
		tree.filesView(),
	)
	if err != nil {
		return Result{}, fmt.Errorf("resolve content-addressed delivery graph: %w", err)
	}
	if contentGraphSHA != graphSHA {
		return Result{}, fmt.Errorf(
			"content-addressed build targets changed delivery graph identity from %s to %s",
			graphSHA,
			contentGraphSHA,
		)
	}
	if len(finalArtifacts) == 0 || finalArtifacts[len(finalArtifacts)-1].ID != "flux" {
		return Result{}, errors.New("final rendered artifact set has no Flux boundary")
	}
	if _, _, err := inspectAppliedArtifacts(
		ctx,
		parallelism,
		selectedKubernetes.Version,
		service.root,
		desired,
		operational,
		candidateGenerated,
		profileRenderValues,
		supportSourceValues(supportSources),
		bootstrapValues,
		finalArtifacts[:len(finalArtifacts)-1],
		tree.filesView(),
		nil,
	); err != nil {
		return Result{}, fmt.Errorf(
			"verify content-addressed applied image projection: %w",
			err,
		)
	}
	lock.Delivery.GraphSHA256 = graphSHA
	if err := resolveImageLock(&desired, &lock); err != nil {
		return Result{}, err
	}

	lock.Resolved = config.Resolved{
		ClusterReleases: desired.Orchestration.Releases,
		Kubespray:       desired.Delivery.Kubespray,
		BigBang:         desired.Platform.BigBang,
		Flux:            desired.Platform.Flux,
		Packages:        desired.Platform.Packages,
		SupportSources:  supportSourceValues(supportSources),
		Charts:          desired.Platform.Charts,
		Artifacts:       lockedCharts,
		Vendors:         desired.Platform.Vendors,
		Bootstrap:       desired.Platform.Bootstrap,
	}
	lock.Compatibility = config.Compatibility{
		KubernetesVersion: selectedKubernetes.Version,
		BigBangConstraint: desired.Platform.BigBang.KubeVersion,
		Status:            "compatible",
		Constraints:       lockConstraints(constraints),
		Checksums:         selectedKubernetes.Checksums,
	}
	finalPackages, err := renderFinalPackages(
		desired,
		lock,
		packages,
		trackedCharts,
		bootstrapCharts,
	)
	if err != nil {
		return Result{}, fmt.Errorf("render final package snapshot: %w", err)
	}
	if err := tree.Set(finalPackagesPath, finalPackages); err != nil {
		return Result{}, err
	}
	deliverySHA, err := desired.DeliverySHA256()
	if err != nil {
		return Result{}, err
	}
	desiredSHA, err := desired.DesiredSHA256()
	if err != nil {
		return Result{}, err
	}
	lock.DesiredSHA256 = desiredSHA
	lock.Delivery.InventorySHA256 = deliverySHA
	if len(desired.Platform.Flux.Assets) != 1 {
		return Result{}, errors.New("resolved Flux source must contain exactly one install asset")
	}
	if err := tree.Set(desired.Platform.Flux.Assets[0].File, fluxManifest); err != nil {
		return Result{}, err
	}
	if err := tree.Set(fluxSyncPath, candidateFluxSync); err != nil {
		return Result{}, err
	}
	if err := tree.Set(fluxSecretSourcePath, candidateFluxSecretSource); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, fluxKustomizationPath, fluxKustomization, candidateFluxKustomization); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, fluxProfilePatchPath, currentFluxProfilePatch, candidateFluxProfilePatch); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, desired.Platform.Values.Generated, currentGenerated, candidateGenerated); err != nil {
		return Result{}, err
	}
	rootChart, exists := packagedByID["bigbang"]
	if !exists {
		return Result{}, errors.New("locked chart inventory has no Big Bang root")
	}
	bigBangSource, err := bigBangSourceValues(
		service.root, desired.Platform.Bootstrap.Registry, rootChart, tree.filesView())
	if err != nil {
		return Result{}, err
	}
	currentBigBangSource, err := tree.YAML("platform/apps/bigbang/source-bigbang.yaml")
	if err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, "platform/apps/bigbang/source-bigbang.yaml", currentBigBangSource, bigBangSource); err != nil {
		return Result{}, err
	}
	if err := removeKustomizationResources(
		tree,
		"platform/apps/prep/kustomization.yaml",
		[]string{"cert-manager"},
	); err != nil {
		return Result{}, err
	}
	for _, path := range obsoleteChartPaths {
		if err := tree.Delete(path); err != nil {
			return Result{}, err
		}
	}
	for _, chart := range desired.Platform.Bootstrap.Charts {
		currentValues, err := tree.YAML(chart.Values)
		if err != nil {
			return Result{}, err
		}
		if err := setCandidateYAML(tree, chart.Values, currentValues, bootstrapValues[chart.ID]); err != nil {
			return Result{}, err
		}
		currentSource, err := tree.YAML(chart.FluxSource)
		if err != nil {
			return Result{}, err
		}
		candidateSource, err := bootstrapSourceValues(service.root, chart, managedFiles)
		if err != nil {
			return Result{}, err
		}
		if err := setCandidateYAML(tree, chart.FluxSource, currentSource, candidateSource); err != nil {
			return Result{}, err
		}
	}
	for _, vendor := range vendors {
		if err := tree.ReplaceDirectory(vendor.Vendor.Directory, vendor.Directory); err != nil {
			return Result{}, err
		}
	}
	desiredData, err := config.MarshalJSON(desired)
	if err != nil {
		return Result{}, err
	}
	lockData, err := config.MarshalJSON(lock)
	if err != nil {
		return Result{}, err
	}
	if err := tree.Set(config.DesiredFilename, desiredData); err != nil {
		return Result{}, err
	}
	if err := tree.Set(config.LockFilename, lockData); err != nil {
		return Result{}, err
	}
	_, desiredData, lockData, err = config.ValidateCandidate(service.root, desired, lock, tree.ValidationFiles())
	if err != nil {
		return Result{}, fmt.Errorf("candidate state is invalid: %w", err)
	}
	if err := tree.Set(config.DesiredFilename, desiredData); err != nil {
		return Result{}, err
	}
	if err := tree.Set(config.LockFilename, lockData); err != nil {
		return Result{}, err
	}
	transaction, err := tree.Transaction()
	if err != nil {
		return Result{}, err
	}
	changed := transaction.Changed()
	result := Result{Changed: changed}
	if options.Check || len(changed) == 0 {
		if err := transaction.Verify(); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	if err := transaction.Commit(); err != nil {
		return Result{}, err
	}
	result.Applied = true
	return result, nil
}

func trackedChartDiscoveryValues(charts []config.TrackedChart) (map[string]any, error) {
	values := make(map[string]any)
	for _, chart := range charts {
		if err := projectGenericChartDefaults(values, chart); err != nil {
			return nil, err
		}
		if err := pinChartRepository(
			values,
			chart.ValuesPath,
			chart.Name,
			chart.Version,
		); err != nil {
			return nil, fmt.Errorf("prepare chart %s discovery values: %w", chart.ID, err)
		}
	}
	return values, nil
}

func canonicalizeGenericChartInventory(
	desired *config.Document,
	operational map[string]any,
) ([]string, error) {
	if desired == nil {
		return nil, errors.New("desired state is required")
	}
	var obsolete []string
	certManagerIndex := -1
	charts := desired.Platform.Charts[:0]
	for index := range desired.Platform.Charts {
		chart := desired.Platform.Charts[index]
		if chart.ID != "cert-manager" {
			if _, err := valuesAt(operational, chart.ValuesPath); err != nil {
				continue
			}
		}
		if chart.ValuesPath == "" {
			continue
		}
		charts = append(charts, chart)
	}
	desired.Platform.Charts = charts
	for index := range desired.Platform.Charts {
		chart := &desired.Platform.Charts[index]
		if chart.ID == "cert-manager" {
			certManagerIndex = index
		}
	}
	bootstrap := desired.Platform.Bootstrap.Charts[:0]
	for index := range desired.Platform.Bootstrap.Charts {
		chart := desired.Platform.Bootstrap.Charts[index]
		if chart.ID != "cert-manager" {
			bootstrap = append(bootstrap, chart)
			continue
		}
		if certManagerIndex >= 0 {
			return nil, errors.New("cert-manager is duplicated across bootstrap and generic chart inventories")
		}
		if len(chart.Profiles) != 0 {
			return nil, errors.New("cert-manager generic package cannot be profile-scoped")
		}
		desired.Platform.Charts = append(desired.Platform.Charts, config.TrackedChart{
			ID:            chart.ID,
			Name:          chart.Name,
			ValuesPath:    "packages.cert-manager",
			Version:       chart.Version,
			AppVersion:    chart.AppVersion,
			License:       chart.License,
			KubeVersion:   chart.KubeVersion,
			Source:        chart.Source,
			ArchiveSHA256: chart.ArchiveSHA256,
		})
		certManagerIndex = len(desired.Platform.Charts) - 1
		directory := filepath.Dir(chart.Values)
		obsolete = append(
			obsolete,
			chart.Values,
			chart.FluxSource,
			filepath.Join(directory, "helmrelease.yaml"),
			filepath.Join(directory, "kustomization.yaml"),
			filepath.Join(directory, "namespace.yaml"),
		)
	}
	desired.Platform.Bootstrap.Charts = bootstrap
	if certManagerIndex < 0 {
		return nil, errors.New("canonical generic chart inventory has no cert-manager")
	}
	sort.Slice(desired.Platform.Charts, func(i, j int) bool {
		return desired.Platform.Charts[i].ID < desired.Platform.Charts[j].ID
	})
	sort.Strings(obsolete)
	return slices.Compact(obsolete), nil
}

func projectGenericChartDefaults(values map[string]any, chart config.TrackedChart) error {
	if chart.ID != "cert-manager" {
		return nil
	}
	entry, err := ensureNestedMap(values, chart.ValuesPath)
	if err != nil {
		return fmt.Errorf("prepare chart %s generic values: %w", chart.ID, err)
	}
	entry["enabled"] = true
	entry["bbCommonValues"] = false
	entry["namespace"] = map[string]any{
		"name": "cert-manager",
	}
	entry["istio"] = map[string]any{
		"injection": "disabled",
	}
	chartValues, err := ensureNestedMap(values, chart.ValuesPath+".values")
	if err != nil {
		return fmt.Errorf("prepare chart %s public values: %w", chart.ID, err)
	}
	chartValues["crds"] = map[string]any{"enabled": true}
	return nil
}

func removeKustomizationResources(
	tree *candidateTree,
	path string,
	obsolete []string,
) error {
	current, err := tree.YAML(path)
	if err != nil {
		return err
	}
	resources, _ := current["resources"].([]any)
	remove := make(map[string]struct{}, len(obsolete))
	for _, resource := range obsolete {
		remove[resource] = struct{}{}
	}
	filtered := make([]any, 0, len(resources))
	for _, raw := range resources {
		resource, _ := raw.(string)
		if _, found := remove[resource]; found {
			continue
		}
		filtered = append(filtered, raw)
	}
	candidate := cloneMap(current)
	candidate["resources"] = filtered
	return setCandidateYAML(tree, path, current, candidate)
}

func (service *Service) lock(ctx context.Context) (func(), error) {
	return lockUpdates(ctx, service.root)
}

func lockUpdates(ctx context.Context, root string) (func(), error) {
	unlock, err := fssecure.LockContext(ctx, root, filepath.Join(".atum", "state", "updates.lock"), 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("lock upstream update: %w", err)
	}
	return unlock, nil
}

func LockProject(ctx context.Context, root string) (func(), error) {
	return lockUpdates(ctx, root)
}

func cloneState(desired config.Document, lock config.Lock) (config.Document, config.Lock, error) {
	data, err := json.Marshal(struct {
		Desired config.Document `json:"desired"`
		Lock    config.Lock     `json:"lock"`
	}{Desired: desired, Lock: lock})
	if err != nil {
		return config.Document{}, config.Lock{}, fmt.Errorf("clone Atum state: %w", err)
	}
	var cloned struct {
		Desired config.Document `json:"desired"`
		Lock    config.Lock     `json:"lock"`
	}
	if err := json.Unmarshal(data, &cloned); err != nil {
		return config.Document{}, config.Lock{}, fmt.Errorf("clone Atum state: %w", err)
	}
	return cloned.Desired, cloned.Lock, nil
}

type kubernetesCandidate struct {
	kubespray  resolvedGit
	kubernetes kubernetesRelease
}

func buildReleaseLadder(
	current []config.ClusterRelease,
	candidates []kubernetesCandidate,
	selected kubernetesCandidate,
) ([]config.ClusterRelease, error) {
	if len(current) == 0 {
		return []config.ClusterRelease{{
			Kubernetes: selected.kubernetes.Version,
			Kubespray:  selected.kubespray.Source,
			Checksums:  selected.kubernetes.Checksums,
		}}, nil
	}
	result := append([]config.ClusterRelease(nil), current...)
	terminal, err := semver.NewVersion(current[len(current)-1].Kubernetes)
	if err != nil {
		return nil, fmt.Errorf("parse current terminal Kubernetes release: %w", err)
	}
	candidate, err := semver.NewVersion(selected.kubernetes.Version)
	if err != nil {
		return nil, fmt.Errorf("parse selected Kubernetes release: %w", err)
	}
	if candidate.LessThan(terminal) {
		return nil, fmt.Errorf("selected Kubernetes %s is older than release ladder target %s", candidate, terminal)
	}
	if candidate.Equal(terminal) {
		return result, nil
	}
	if candidate.Major() == terminal.Major() && candidate.Minor() == terminal.Minor() {
		result = append(result, config.ClusterRelease{
			Kubernetes: selected.kubernetes.Version,
			Kubespray:  selected.kubespray.Source,
			Checksums:  selected.kubernetes.Checksums,
		})
		return result, nil
	}
	if candidate.Major() != terminal.Major() {
		return nil, fmt.Errorf("selected Kubernetes %s changes major version from %s", candidate, terminal)
	}
	type releaseCoordinate struct {
		major uint64
		minor uint64
	}
	byCoordinate := make(map[releaseCoordinate]kubernetesCandidate, len(candidates))
	for _, step := range candidates {
		version, parseErr := semver.NewVersion(step.kubernetes.Version)
		if parseErr != nil {
			return nil, fmt.Errorf(
				"parse compatible Kubernetes release %s: %w",
				step.kubernetes.Version,
				parseErr,
			)
		}
		coordinate := releaseCoordinate{
			major: version.Major(),
			minor: version.Minor(),
		}
		if _, exists := byCoordinate[coordinate]; !exists {
			byCoordinate[coordinate] = step
		}
	}
	for minor := terminal.Minor() + 1; minor <= candidate.Minor(); minor++ {
		step, found := byCoordinate[releaseCoordinate{
			major: terminal.Major(),
			minor: minor,
		}]
		if !found {
			return nil, fmt.Errorf("no exact Kubespray release is compatible with Kubernetes %d.%d", terminal.Major(), minor)
		}
		result = append(result, config.ClusterRelease{
			Kubernetes: step.kubernetes.Version,
			Kubespray:  step.kubespray.Source,
			Checksums:  step.kubernetes.Checksums,
		})
	}
	return result, nil
}

func (service *Service) resolveKubernetesCandidates(
	ctx context.Context,
	latest resolvedGit,
	constraints []versionConstraint,
	minimum config.ClusterRelease,
) ([]kubernetesCandidate, error) {
	minimumKubernetes, err := semver.NewVersion(minimum.Kubernetes)
	if err != nil {
		return nil, err
	}
	minimumKubespray, err := semver.NewVersion(strings.TrimPrefix(minimum.Kubespray.Version, "v"))
	if err != nil {
		return nil, err
	}
	byKubernetes := make(map[string]kubernetesCandidate)
	var oidcFailures []string
	for index, release := range latest.Releases {
		candidate := latest
		if index != 0 {
			checkout, err := service.cache.Hydrate(ctx, "kubespray", latest.Source.URL, release)
			if err != nil {
				return nil, err
			}
			candidate.Source.Version = release.Version
			candidate.Source.Commit = release.Commit
			candidate.Checkout = checkout
		}
		matrix, err := readKubesprayMatrix(candidate.Checkout)
		if err != nil {
			return nil, err
		}
		compatible, err := compatibleKubernetes(matrix, constraints)
		if err != nil {
			if errors.Is(err, errNoCompatibleKubernetes) {
				continue
			}
			return nil, err
		}
		compatible, err = requireKubernetesFloor(compatible, minimum.Kubernetes)
		if err != nil && !errors.Is(err, errNoCompatibleKubernetes) {
			return nil, err
		}
		kubesprayVersion, err := semver.NewVersion(strings.TrimPrefix(candidate.Source.Version, "v"))
		if err != nil {
			return nil, err
		}
		for _, kubernetes := range compatible {
			if err := kube.ValidateKubesprayScopedAnonymousLifecycle(
				candidate.Checkout,
				kubernetes.Version,
			); err != nil {
				oidcFailures = append(oidcFailures,
					candidate.Source.Version+"/Kubernetes "+kubernetes.Version+": "+err.Error())
				continue
			}
			kubernetesVersion, _ := semver.NewVersion(kubernetes.Version)
			delta := int64(kubernetesVersion.Minor()) - int64(minimumKubernetes.Minor())
			if kubernetesVersion.Major() != minimumKubernetes.Major() || delta < 0 ||
				kubesprayVersion.Major() != minimumKubespray.Major() ||
				int64(kubesprayVersion.Minor()) != int64(minimumKubespray.Minor())+delta {
				continue
			}
			if _, exists := byKubernetes[kubernetes.Version]; !exists {
				byKubernetes[kubernetes.Version] = kubernetesCandidate{kubespray: candidate, kubernetes: kubernetes}
			}
		}
	}
	if len(byKubernetes) == 0 {
		if len(oidcFailures) != 0 {
			return nil, fmt.Errorf("%w for the selected Big Bang package set: %s",
				errNoCompatibleKubernetes, strings.Join(oidcFailures, "; "))
		}
		return nil, fmt.Errorf("%w for the selected Big Bang package set", errNoCompatibleKubernetes)
	}
	result := make([]kubernetesCandidate, 0, len(byKubernetes))
	for _, candidate := range byKubernetes {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool {
		left, _ := semver.NewVersion(result[i].kubernetes.Version)
		right, _ := semver.NewVersion(result[j].kubernetes.Version)
		return left.GreaterThan(right)
	})
	return result, nil
}

type platformSelection struct {
	bigBang         resolvedGit
	packages        []resolvedPackage
	charts          []resolvedTrackedChart
	bootstrap       []resolvedBootstrapChart
	supportSources  []resolvedSupportSource
	constraints     []versionConstraint
	generated       map[string]any
	artifacts       []chartArtifact
	kubespray       resolvedGit
	kubernetes      kubernetesRelease
	inspections     []chartInspection
	clusterReleases []config.ClusterRelease
}

type admittedBigBangSelection struct {
	candidate          resolvedGit
	defaults           map[string]any
	platform           config.Platform
	packages           []config.Package
	wrapperRequirement config.WrapperSourceRequirement
}

func incompatibleBigBangError(version string, pinned bool, failures []string) error {
	selection := "newest Big Bang"
	if pinned {
		selection = "pinned Big Bang"
	}
	return fmt.Errorf("%s %s is incompatible: %s", selection, version, strings.Join(failures, "; "))
}

// latestOnlyBigBangCandidate removes the release catalog after resolution so
// platform selection cannot reinterpret older stable tags as candidates.
func latestOnlyBigBangCandidate(latest resolvedGit) resolvedGit {
	latest.Releases = nil
	return latest
}

func admitBigBangPackageSelection(
	resolved resolvedGit,
	defaults map[string]any,
	configured map[string]any,
	platform config.Platform,
	kubernetesVersion string,
) (admittedBigBangSelection, error) {
	candidate := latestOnlyBigBangCandidate(resolved)
	packages, wrapperRequirement, err := discoverBigBangPackages(
		candidate.Checkout,
		kubernetesVersion,
		defaults,
		configured,
	)
	if err != nil {
		return admittedBigBangSelection{}, fmt.Errorf(
			"Big Bang %s package inventory: %w", candidate.Source.Version, err,
		)
	}
	candidatePlatform := platform
	candidatePlatform.Packages = append([]config.Package(nil), packages...)
	return admittedBigBangSelection{
		candidate:          candidate,
		defaults:           defaults,
		platform:           candidatePlatform,
		packages:           packages,
		wrapperRequirement: wrapperRequirement,
	}, nil
}

func (service *Service) selectCompatiblePlatform(
	ctx context.Context,
	admitted admittedBigBangSelection,
	kubesprayLatest resolvedGit,
	desired config.Document,
	lock config.Lock,
	renderOperational map[string]any,
	configuredValues map[string]any,
	generated map[string]any,
	profile map[string]any,
	trackedChartCatalogs []*chartCatalog,
	bootstrapChartCatalogs []*chartCatalog,
	parallelism int,
	files map[string][]byte,
	resetToPinnedBigBang bool,
	identityContract *identity.Contract,
) (platformSelection, error) {
	if identityContract == nil {
		return platformSelection{}, errors.New("canonical local identity contract is unavailable")
	}
	minimumRelease, err := desired.Orchestration.TargetRelease()
	if err != nil {
		return platformSelection{}, err
	}
	if resetToPinnedBigBang {
		minimumRelease = desired.Orchestration.Releases[0]
	}
	var failures []string
	if err := ctx.Err(); err != nil {
		return platformSelection{}, err
	}
	candidate := admitted.candidate
	bigBangValues := admitted.defaults
	selectedPackages := admitted.packages
	metadata, err := readChartMetadata(filepath.Join(candidate.Checkout, "chart"))
	if err != nil {
		return platformSelection{}, fmt.Errorf("inspect Big Bang chart %s: %w", candidate.Source.Version, err)
	}
	if metadata.Version != candidate.Source.Version {
		return platformSelection{}, fmt.Errorf("Big Bang tag %s contains chart version %s", candidate.Source.Version, metadata.Version)
	}
	if metadata.KubeVersion == "" {
		failures = append(failures, candidate.Source.Version+": Big Bang chart has no Kubernetes compatibility constraint")
		return platformSelection{}, incompatibleBigBangError(
			candidate.Source.Version, resetToPinnedBigBang, failures,
		)
	}
	candidate.Source.KubeVersion = metadata.KubeVersion
	effectiveValues := mergeValues(bigBangValues, configuredValues)
	if err := verifyTrackedChartBindings(effectiveValues, desired.Platform.Charts); err != nil {
		return platformSelection{}, fmt.Errorf("Big Bang %s chart sources: %w", candidate.Source.Version, err)
	}
	candidatePlatform := admitted.platform
	supportSources, err := resolveWrapperSupportSource(
		ctx,
		service.cache,
		candidate,
		admitted.wrapperRequirement,
		lock.Resolved,
	)
	if err != nil {
		failures = append(
			failures,
			candidate.Source.Version+": wrapper source contract: "+err.Error(),
		)
		return platformSelection{}, incompatibleBigBangError(
			candidate.Source.Version, resetToPinnedBigBang, failures,
		)
	}
	packages, err := resolvePackages(
		ctx, service.cache, parallelism, selectedPackages,
		desired.Platform.Packages, resetToPinnedBigBang,
	)
	if err != nil {
		return platformSelection{}, fmt.Errorf(
			"resolve Big Bang %s packages: %w", candidate.Source.Version, err,
		)
	}
	candidateDesired := desired
	candidateDesired.Platform = candidatePlatform
	candidateDesired.Platform.BigBang = candidate.Source
	candidateDesired.Platform.Packages = make([]config.Package, len(packages))
	for i := range packages {
		candidateDesired.Platform.Packages[i] = packages[i].Package
	}
	baseConstraints := collectSourceConstraints(&candidateDesired)
	kubernetesCandidates, err := service.resolveKubernetesCandidates(
		ctx, kubesprayLatest, baseConstraints, minimumRelease,
	)
	if err != nil {
		if errors.Is(err, errNoCompatibleKubernetes) {
			failures = append(failures, candidate.Source.Version+": "+err.Error())
			return platformSelection{}, incompatibleBigBangError(
				candidate.Source.Version, resetToPinnedBigBang, failures,
			)
		}
		return platformSelection{}, fmt.Errorf(
			"resolve Kubernetes candidates for Big Bang %s: %w",
			candidate.Source.Version, err,
		)
	}
	failures = make([]string, 0, len(kubernetesCandidates))
	if resetToPinnedBigBang {
		slices.Reverse(kubernetesCandidates)
	}
	for _, kubernetesCandidate := range kubernetesCandidates {
		coordinate := candidate.Source.Version + "/Kubernetes " +
			kubernetesCandidate.kubernetes.Version
		trackedOffsets := make(map[string]int, len(desired.Platform.Charts))
		bootstrapOffsets := make(map[string]int, len(desired.Platform.Bootstrap.Charts))
		for attempt := 1; ; attempt++ {
			attemptDesired := candidateDesired
			attemptDesired.Platform.Charts = append([]config.TrackedChart(nil), desired.Platform.Charts...)
			attemptDesired.Platform.Bootstrap.Charts = append([]config.Chart(nil), desired.Platform.Bootstrap.Charts...)
			trackedCharts, err := resolveTrackedChartsForKubernetes(
				ctx, service.charts, parallelism, desired.Platform.Charts, trackedChartCatalogs,
				kubernetesCandidate.kubernetes.Version, trackedOffsets,
			)
			if err != nil {
				if errors.Is(err, errNoCompatibleKubernetes) {
					failures = append(failures, coordinate+": "+err.Error())
					break
				}
				return platformSelection{}, fmt.Errorf(
					"resolve tracked charts for %s: %w", coordinate, err,
				)
			}
			bootstrapCharts, err := resolveBootstrapChartsForKubernetes(
				ctx, service.charts, parallelism, desired.Platform.Bootstrap.Charts, bootstrapChartCatalogs,
				kubernetesCandidate.kubernetes.Version, bootstrapOffsets,
			)
			if err != nil {
				if errors.Is(err, errNoCompatibleKubernetes) {
					failures = append(failures, coordinate+": "+err.Error())
					break
				}
				return platformSelection{}, fmt.Errorf(
					"resolve bootstrap charts for %s: %w", coordinate, err,
				)
			}
			for i := range trackedCharts {
				attemptDesired.Platform.Charts[i] = trackedCharts[i].Chart
			}
			for i := range bootstrapCharts {
				attemptDesired.Platform.Bootstrap.Charts[i] = bootstrapCharts[i].Chart
			}
			constraints := collectConstraints(&attemptDesired)
			if _, err := compatibleKubernetes([]kubernetesRelease{kubernetesCandidate.kubernetes}, constraints); err != nil {
				failures = append(failures, coordinate+": "+err.Error())
				break
			}
			candidateGenerated := cloneMap(generated)
			if err := updateGeneratedVersions(
				candidateGenerated,
				attemptDesired.Platform.Bootstrap.Registry,
				packages,
				supportSources,
				trackedCharts,
			); err != nil {
				return platformSelection{}, fmt.Errorf(
					"prepare generated values for %s: %w", coordinate, err,
				)
			}
			candidateConfiguredValues, err := config.MergePlatformValues(
				renderOperational, candidateGenerated, profile,
			)
			if err != nil {
				return platformSelection{}, fmt.Errorf(
					"merge platform values for %s: %w", coordinate, err,
				)
			}
			candidateRenderValues := cloneMap(candidateConfiguredValues)
			candidateInputs, err := candidateArtifacts(
				candidate, attemptDesired.Platform.Bootstrap.Registry,
				packages, supportSources, trackedCharts, bootstrapCharts,
				candidateRenderValues, service.root, files,
			)
			if err != nil {
				return platformSelection{}, fmt.Errorf(
					"assemble candidate artifacts for %s: %w", coordinate, err,
				)
			}
			artifacts, err := selectedArtifacts(candidateInputs)
			if err != nil {
				return platformSelection{}, fmt.Errorf(
					"assemble selected artifacts for %s: %w", coordinate, err,
				)
			}
			service.logger.InfoContext(ctx, "rendering candidate Helm contracts",
				"bigbang", candidate.Source.Version,
				"kubernetes", kubernetesCandidate.kubernetes.Version,
				"attempt", attempt,
				"candidates", len(artifacts),
			)
			progress.Update(ctx, progress.Platform, "update-render", "Candidate rendering",
				"rendering candidate Helm contracts", 0, len(artifacts))
			inspections, err := inspectArtifacts(
				ctx,
				parallelism,
				kubernetesCandidate.kubernetes.Version,
				artifacts,
				func(id string, completed, total int) {
					progress.Update(
						ctx,
						progress.Platform,
						"update-render",
						"Candidate rendering",
						"rendered candidate chart "+id,
						completed,
						total,
					)
				},
			)
			if err != nil {
				var renderErr *artifactRenderError
				if errors.As(err, &renderErr) && renderErr.candidate &&
					backtrackChart(renderErr.id, trackedOffsets, bootstrapOffsets) {
					service.logger.WarnContext(ctx, "candidate chart render failed; trying the next compatible release",
						"artifact", renderErr.id,
						"error", renderErr.err,
					)
					continue
				}
				failures = append(failures, coordinate+": "+err.Error())
				break
			}
			inspectionsByID, err := inspectionsByArtifactID(artifacts, inspections)
			if err != nil {
				return platformSelection{}, err
			}
			if err := validateOpenSearchMeshContract(inspectionsByID); err != nil {
				var meshErr *artifactRenderError
				if errors.As(err, &meshErr) && meshErr.candidate &&
					backtrackChart(meshErr.id, trackedOffsets, bootstrapOffsets) {
					service.logger.WarnContext(
						ctx,
						"candidate strict-mesh contract failed; trying the next compatible release",
						"artifact", meshErr.id,
						"error", meshErr.err,
					)
					continue
				}
				failures = append(failures, coordinate+": "+err.Error())
				break
			}
			if err := validateFormerWaitResourceAbsence(inspectionsByID); err != nil {
				var waitErr *artifactRenderError
				if errors.As(err, &waitErr) && waitErr.candidate &&
					backtrackChart(waitErr.id, trackedOffsets, bootstrapOffsets) {
					service.logger.WarnContext(
						ctx,
						"candidate former wait resource detected; trying the next compatible release",
						"artifact", waitErr.id,
						"error", waitErr.err,
					)
					continue
				}
				failures = append(failures, coordinate+": "+err.Error())
				break
			}
			currentReleases := desired.Orchestration.Releases
			if resetToPinnedBigBang {
				currentReleases = nil
			}
			clusterReleases, err := buildReleaseLadder(
				currentReleases,
				kubernetesCandidates,
				kubernetesCandidate,
			)
			if err != nil {
				failures = append(failures, coordinate+": "+err.Error())
				break
			}
			return platformSelection{
				bigBang:         candidate,
				packages:        packages,
				charts:          trackedCharts,
				bootstrap:       bootstrapCharts,
				supportSources:  supportSources,
				constraints:     constraints,
				generated:       candidateGenerated,
				artifacts:       artifacts,
				kubespray:       kubernetesCandidate.kubespray,
				kubernetes:      kubernetesCandidate.kubernetes,
				inspections:     inspections,
				clusterReleases: clusterReleases,
			}, nil
		}
	}
	return platformSelection{}, incompatibleBigBangError(
		candidate.Source.Version, resetToPinnedBigBang, failures,
	)
}

func backtrackChart(id string, tracked, bootstrap map[string]int) bool {
	prefix, name, found := strings.Cut(id, "/")
	if !found {
		return false
	}
	switch prefix {
	case "chart":
		if _, exists := tracked[name]; !exists {
			tracked[name] = 0
		}
		tracked[name]++
		return true
	case "bootstrap":
		if _, exists := bootstrap[name]; !exists {
			bootstrap[name] = 0
		}
		bootstrap[name]++
		return true
	default:
		return false
	}
}

func collectConstraints(desired *config.Document) []versionConstraint {
	constraints := make([]versionConstraint, 0, 1+len(desired.Platform.Packages)+len(desired.Platform.Charts)+len(desired.Platform.Bootstrap.Charts))
	appendConstraint := func(id, value string) {
		if normalized := normalizeConstraint(value); normalized != "" {
			constraints = append(constraints, versionConstraint{ID: id, Value: normalized})
		}
	}
	appendConstraint("bigbang", desired.Platform.BigBang.KubeVersion)
	for _, pkg := range desired.Platform.Packages {
		appendConstraint("package/"+pkg.ID, pkg.Source.KubeVersion)
	}
	for _, chart := range desired.Platform.Charts {
		appendConstraint("chart/"+chart.ID, chart.KubeVersion)
	}
	for _, chart := range desired.Platform.Bootstrap.Charts {
		appendConstraint("bootstrap/"+chart.ID, chart.KubeVersion)
	}
	sort.Slice(constraints, func(i, j int) bool { return constraints[i].ID < constraints[j].ID })
	return constraints
}

func collectSourceConstraints(desired *config.Document) []versionConstraint {
	constraints := make([]versionConstraint, 0, 1+len(desired.Platform.Packages))
	if normalized := normalizeConstraint(desired.Platform.BigBang.KubeVersion); normalized != "" {
		constraints = append(constraints, versionConstraint{ID: "bigbang", Value: normalized})
	}
	for _, pkg := range desired.Platform.Packages {
		if normalized := normalizeConstraint(pkg.Source.KubeVersion); normalized != "" {
			constraints = append(constraints, versionConstraint{ID: "package/" + pkg.ID, Value: normalized})
		}
	}
	sort.Slice(constraints, func(i, j int) bool { return constraints[i].ID < constraints[j].ID })
	return constraints
}

func lockConstraints(constraints []versionConstraint) []config.CompatibilityConstraint {
	result := make([]config.CompatibilityConstraint, len(constraints))
	for i := range constraints {
		result[i] = config.CompatibilityConstraint{ID: constraints[i].ID, Constraint: constraints[i].Value}
	}
	return result
}

func updateGeneratedVersions(
	generated map[string]any,
	registry config.Registry,
	packages []resolvedPackage,
	supportSources []resolvedSupportSource,
	charts []resolvedTrackedChart,
) error {
	delete(generated, "wrapper")
	generated["offline"] = true
	generated["helmRepositories"] = []any{map[string]any{
		"name":       "atum",
		"repository": "oci://" + registry.Host + "/" + registry.Project,
		"type":       "oci",
		"username":   "",
		"password":   "",
	}}
	for _, pkg := range packages {
		if err := pinChartRepository(
			generated, pkg.Package.ValuesPath,
			pkg.ChartName, pkg.ChartVersion,
		); err != nil {
			return fmt.Errorf("update generated package %s source: %w", pkg.Package.ID, err)
		}
	}
	for _, support := range supportSources {
		if err := pinChartRepository(
			generated, support.Support.ValuesPath,
			support.Support.ID, support.Support.Source.Version,
		); err != nil {
			return fmt.Errorf("update generated support source %s: %w", support.Support.ID, err)
		}
	}
	for _, chart := range charts {
		if err := projectGenericChartDefaults(generated, chart.Chart); err != nil {
			return err
		}
		if err := pinChartRepository(
			generated,
			chart.Chart.ValuesPath,
			chart.Chart.Name,
			chart.Chart.Version,
		); err != nil {
			return fmt.Errorf("update generated chart %s source: %w", chart.Chart.ID, err)
		}
	}
	return nil
}

func projectPackagedPackageVersions(
	generated map[string]any,
	packages []resolvedPackage,
	artifacts map[string]config.ChartArtifact,
) error {
	for _, pkg := range packages {
		artifact, exists := artifacts["package/"+pkg.Package.ID]
		if !exists {
			return fmt.Errorf(
				"packaged chart inventory is missing package/%s",
				pkg.Package.ID,
			)
		}
		if err := pinChartRepository(
			generated,
			pkg.Package.ValuesPath,
			artifact.Name,
			artifact.Version,
		); err != nil {
			return fmt.Errorf(
				"project packaged chart version for package %s: %w",
				pkg.Package.ID,
				err,
			)
		}
	}
	return nil
}

func pinChartRepository(
	values map[string]any,
	valuesPath, chartName, version string,
) error {
	entry, err := ensureNestedMap(values, valuesPath)
	if err != nil {
		return err
	}
	delete(entry, "git")
	entry["sourceType"] = "helmRepo"
	entry["helmRepo"] = map[string]any{
		"repoName":  "atum",
		"chartName": chartName,
		"tag":       version,
	}
	return nil
}

func supportSourceValues(sources []resolvedSupportSource) []config.SupportSource {
	result := make([]config.SupportSource, len(sources))
	for i := range sources {
		result[i] = sources[i].Support
	}
	return result
}

func setNestedValue(root map[string]any, path string, value any) error {
	components := strings.Split(path, ".")
	current, err := ensureNestedComponents(root, path, components[:len(components)-1])
	if err != nil {
		return err
	}
	leaf := components[len(components)-1]
	if leaf == "" {
		return fmt.Errorf("path %s is invalid", path)
	}
	current[leaf] = value
	return nil
}

func ensureNestedMap(root map[string]any, path string) (map[string]any, error) {
	return ensureNestedComponents(root, path, strings.Split(path, "."))
}

func ensureNestedComponents(root map[string]any, path string, components []string) (map[string]any, error) {
	current := root
	for _, component := range components {
		if component == "" {
			return nil, fmt.Errorf("path %s is invalid", path)
		}
		next, exists := current[component]
		if !exists {
			created := make(map[string]any)
			current[component] = created
			current = created
			continue
		}
		nested, ok := next.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("path %s conflicts at %s", path, component)
		}
		current = nested
	}
	return current, nil
}

func setScalar(root map[string]any, path string, value string) error {
	components := strings.Split(path, ".")
	current := root
	for _, component := range components[:len(components)-1] {
		next, ok := current[component].(map[string]any)
		if !ok {
			return fmt.Errorf("path %s does not exist", path)
		}
		current = next
	}
	leaf := components[len(components)-1]
	if _, exists := current[leaf]; !exists {
		return fmt.Errorf("path %s does not exist", path)
	}
	current[leaf] = value
	return nil
}

func compactReplacements(replacements []imageReplacement) ([]imageReplacement, error) {
	byOld := make(map[string]string, len(replacements))
	for _, replacement := range replacements {
		if existing, exists := byOld[replacement.Old]; exists && existing != replacement.New {
			return nil, fmt.Errorf("image %s has conflicting replacements %s and %s", replacement.Old, existing, replacement.New)
		}
		byOld[replacement.Old] = replacement.New
	}
	resolved := make(map[string]string, len(byOld))
	state := make(map[string]uint8, len(byOld))
	var resolve func(string) (string, error)
	resolve = func(old string) (string, error) {
		if final, exists := resolved[old]; exists {
			return final, nil
		}
		if state[old] == 1 {
			return "", fmt.Errorf("image replacement cycle includes %s", old)
		}
		state[old] = 1
		final := byOld[old]
		if _, chained := byOld[final]; chained {
			var err error
			final, err = resolve(final)
			if err != nil {
				return "", err
			}
		}
		state[old] = 2
		resolved[old] = final
		return final, nil
	}
	oldReferences := make([]string, 0, len(byOld))
	for old := range byOld {
		oldReferences = append(oldReferences, old)
	}
	sort.Strings(oldReferences)
	result := make([]imageReplacement, 0, len(oldReferences))
	for _, old := range oldReferences {
		final, err := resolve(old)
		if err != nil {
			return nil, err
		}
		if old != final {
			result = append(result, imageReplacement{Old: old, New: final})
		}
	}
	return result, nil
}

func readBootstrapValues(root string, charts []config.Chart, files map[string][]byte) (map[string]map[string]any, error) {
	result := make(map[string]map[string]any, len(charts))
	for _, chart := range charts {
		values, err := readManagedYAML(root, files, chart.Values)
		if err != nil {
			return nil, err
		}
		result[chart.ID] = values
	}
	return result, nil
}

func setCandidateYAML(tree *candidateTree, relative string, current, candidate map[string]any) error {
	if reflect.DeepEqual(current, candidate) {
		return nil
	}
	return tree.SetYAML(relative, candidate)
}
