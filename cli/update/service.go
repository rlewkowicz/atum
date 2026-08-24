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
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitcache"
	"atum/cli/identity"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Service struct {
	root   string
	cache  *gitcache.Manager
	charts *chartClient
	logger *slog.Logger
}

type Options struct {
	Check                  bool
	BigBangCommit          string
	ApproveAuxiliaryImages []string
}

type Result struct {
	Changed []string
	Applied bool
}

type chartArtifact struct {
	ID                     string
	CurrentPath            string
	CandidatePath          string
	InvocationBaselinePath string
	InvocationRepositories []string
	CurrentValues          map[string]any
	CandidateValues        map[string]any
	CurrentInstances       []releaseValueInstance
	CandidateInstances     []releaseValueInstance
	CurrentBindings        []artifactBinding
	CandidateBindings      []artifactBinding
	CurrentSources         []map[string]any
	CandidateSources       []map[string]any
}

func NewService(root string, logger *slog.Logger) *Service {
	return &Service{
		root:   root,
		cache:  gitcache.New(root),
		charts: newChartClient(root),
		logger: logger,
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
	project, err := config.LoadWithOptions(service.root, config.LoadOptions{
		AllowStale: true, AllowMissingGeneratedIdentity: true,
	})
	if err != nil {
		return Result{}, err
	}
	desired, lock, err := cloneState(project.Desired, project.Lock)
	if err != nil {
		return Result{}, err
	}
	if err := approveAuxiliaryImages(&desired, options.ApproveAuxiliaryImages); err != nil {
		return Result{}, err
	}
	reconcileDeliveryEvidence(&desired)
	sourceSnapshotChanged := false
	if project.Lock.Bundle != nil {
		currentSourceSHA, err := config.AtumSourceSHA256(project)
		if err != nil {
			return Result{}, fmt.Errorf("identify current deployment source: %w", err)
		}
		sourceSnapshotChanged = currentSourceSHA != project.Lock.Bundle.AtumSourceSHA256
	}
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
	desiredSnapshot, _ := tree.Data(config.DesiredFilename)
	lockSnapshot, _ := tree.Data(config.LockFilename)
	if !bytes.Equal(desiredSnapshot, project.DesiredData) || !bytes.Equal(lockSnapshot, project.LockData) {
		return Result{}, errors.New("declarative state changed while the updater was loading it; retry without discarding the concurrent edit")
	}
	managedFiles := tree.Files()
	identityContract, err := loadCandidateIdentity(tree, desired)
	if err != nil {
		return Result{}, err
	}
	generatedIdentityValues, err := identityValues(identityContract)
	if err != nil {
		return Result{}, err
	}
	parallelism := desired.Updates.Parallelism
	if len(desired.Platform.Flux.Assets) != 1 || desired.Platform.Flux.Assets[0].ID != "install-manifest" {
		return Result{}, errors.New("Flux source must define exactly one install-manifest asset")
	}
	platformValues, err := desired.ResolvePlatformValues(tree.YAML)
	if err != nil {
		return Result{}, err
	}
	operational := platformValues.Operational
	generated := platformValues.Generated
	profileValues := platformValues.Profile
	if collision := firstNestedCollision(profileValues, generatedIdentityValues, nil); collision != "" {
		return Result{}, fmt.Errorf("profile value %s is owned by the local identity contract", collision)
	}
	profileRenderValues, err := mergeIdentityValues(profileValues, generatedIdentityValues)
	if err != nil {
		return Result{}, err
	}
	mergedRenderValues, err := config.MergePlatformValues(operational, generated, profileRenderValues)
	if err != nil {
		return Result{}, err
	}
	if err := verifySelectedPackages(mergedRenderValues, desired.Platform.Packages, desired.Platform.Charts); err != nil {
		return Result{}, err
	}
	if err := verifyTrackedChartBindings(service.root, mergedRenderValues, desired.Platform.Bootstrap.Registry, desired.Platform.Charts, managedFiles); err != nil {
		return Result{}, err
	}
	currentRenderValues, err := sourceVersionValues(
		mergedRenderValues,
		desired.Platform.Sources,
		desired.Platform.Packages,
		lock.Resolved.SupportSources,
		desired.Platform.Charts,
		desired.Delivery.Images,
	)
	if err != nil {
		return Result{}, err
	}
	currentRenderValues, err = currentWrapperContractValues(
		currentRenderValues,
		desired.Platform,
		lock.Resolved.SupportSources,
	)
	if err != nil {
		return Result{}, err
	}

	service.logger.InfoContext(ctx, "resolving stable upstream Git releases")
	var bigBang, kubespray, flux resolvedGit
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(3)
	group.Go(func() error {
		var resolveErr error
		if historicalBigBang {
			bigBang, resolveErr = resolvePinnedGit(
				groupContext, service.cache, "bigbang", desired.Platform.BigBang, options.BigBangCommit,
			)
		} else {
			bigBang, resolveErr = resolveLatestGit(groupContext, service.cache, "bigbang", desired.Platform.BigBang)
		}
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		kubespray, resolveErr = resolveLatestGit(groupContext, service.cache, "kubespray", clusterResolutionFloor.Kubespray)
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		flux, resolveErr = resolveLatestGit(groupContext, service.cache, "flux", desired.Platform.Flux)
		return resolveErr
	})
	if err := group.Wait(); err != nil {
		return Result{}, err
	}
	currentFluxManifest, err := tree.Data(project.Desired.Platform.Flux.Assets[0].File)
	if err != nil {
		return Result{}, fmt.Errorf("read current Flux install manifest: %w", err)
	}
	currentFluxInspection, err := inspectManifestData("flux", currentFluxManifest)
	if err != nil {
		return Result{}, fmt.Errorf("inspect current Flux install manifest: %w", err)
	}
	flux, fluxManifest, candidateFluxInspection, err := service.selectCompatibleFlux(
		ctx, desired.Platform.Flux, flux, currentFluxInspection, desired,
	)
	if err != nil {
		return Result{}, err
	}
	service.logger.InfoContext(ctx, "resolving selected chart and vendor releases")
	var trackedChartCatalogs []*chartCatalog
	var bootstrapChartCatalogs []*chartCatalog
	var vendors []resolvedVendor
	applicationRepositories := directChartApplicationRepositories(&desired)
	group, groupContext = errgroup.WithContext(ctx)
	group.SetLimit(3)
	group.Go(func() error {
		var resolveErr error
		vendors, resolveErr = resolveVendors(groupContext, service.cache, service.root, parallelism, desired.Platform.Vendors)
		return resolveErr
	})
	group.Go(func() error {
		var resolveErr error
		trackedChartCatalogs, resolveErr = resolveTrackedChartCatalogs(
			groupContext, service.charts, parallelism, desired.Platform.Charts, applicationRepositories,
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

	currentInputs, err := service.currentArtifacts(ctx, project.Desired, currentRenderValues, parallelism, managedFiles)
	if err != nil {
		return Result{}, err
	}
	inferredMappings, err := inferTrackedChartVersionMappings(
		ctx,
		parallelism,
		service.cache,
		tree,
		&desired,
		currentInputs,
		currentClusterTarget.Kubernetes,
	)
	if err != nil {
		return Result{}, err
	}
	if inferredMappings > 0 {
		service.logger.InfoContext(ctx, "inferred tracked chart delivery mappings", "count", inferredMappings)
	}
	service.logger.InfoContext(ctx, "selecting newest compatible Big Bang and Kubernetes pair")
	selection, err := service.selectCompatiblePlatform(
		ctx,
		bigBang,
		kubespray,
		desired,
		lock,
		operational,
		generated,
		profileRenderValues,
		trackedChartCatalogs,
		bootstrapChartCatalogs,
		currentInputs,
		applicationRepositories,
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
	currentInspections := selection.currentInspections
	candidateInspections := selection.candidateInspections
	renderedImages := renderedImageIDs(desired.Delivery.Images, candidateInspections)
	desired.Platform.BigBang = bigBang.Source
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

	replacements, err := reconcileBootstrapImageVersions(&desired, &lock, bootstrapCharts)
	if err != nil {
		return Result{}, err
	}
	for i := range artifacts {
		if strings.HasPrefix(artifacts[i].ID, "bootstrap/") {
			continue
		}
		artifactReplacements, err := reconcileImageContract(
			ctx,
			service.cache,
			tree,
			&desired,
			&lock,
			artifacts[i].ID,
			currentInspections[i],
			candidateInspections[i],
			renderedImages,
			true,
			historicalBigBang,
		)
		if err != nil {
			return Result{}, err
		}
		replacements = append(replacements, artifactReplacements...)
	}
	fluxReplacements, err := reconcileImageContract(
		ctx,
		service.cache,
		tree,
		&desired,
		&lock,
		"flux",
		currentFluxInspection,
		candidateFluxInspection,
		nil,
		true,
		false,
	)
	if err != nil {
		return Result{}, err
	}
	replacements = append(replacements, fluxReplacements...)
	kubernetesReplacements, err := reconcileKubernetesImages(&desired, &lock, selectedKubernetes.Version)
	if err != nil {
		return Result{}, err
	}
	replacements = append(replacements, kubernetesReplacements...)
	replacements, err = compactReplacements(replacements)
	if err != nil {
		return Result{}, err
	}
	if err := replaceImageReferences(candidateGenerated, replacements); err != nil {
		return Result{}, err
	}
	auxiliaryChanges, err := projectTrackedChartAuxiliaryImages(
		generated,
		candidateGenerated,
		trackedCharts,
		artifacts,
		candidateInspections,
		desired.Delivery.Images,
	)
	if err != nil {
		return Result{}, err
	}
	for _, change := range auxiliaryChanges {
		service.logger.WarnContext(
			ctx,
			"tracked chart auxiliary runtime contract changed",
			"artifact", change.Artifact,
			"added", change.Added,
			"removed", change.Removed,
		)
	}
	const bigBangHelmReleasePath = "platform/apps/bigbang/helmrelease.yaml"
	currentBigBangHelmRelease, err := tree.YAML(bigBangHelmReleasePath)
	if err != nil {
		return Result{}, err
	}
	candidateBigBangHelmRelease := cloneMap(currentBigBangHelmRelease)
	if err := configureIdentityValuesFrom(candidateBigBangHelmRelease); err != nil {
		return Result{}, err
	}
	if err := pinIstioHelmReleaseGates(
		candidateBigBangHelmRelease,
		packages,
		bigBangIstioDependencies(artifacts, candidateInspections),
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
	candidateFluxSync, err := renderFluxSync(desired)
	if err != nil {
		return Result{}, err
	}
	fluxKustomization, err := tree.YAML(fluxKustomizationPath)
	if err != nil {
		return Result{}, err
	}
	candidateFluxKustomization := cloneMap(fluxKustomization)
	if err := replaceImageReferences(candidateFluxKustomization, replacements); err != nil {
		return Result{}, err
	}
	currentFluxKustomizationData, err := tree.Data(fluxKustomizationPath)
	if err != nil {
		return Result{}, fmt.Errorf("read current Flux Kustomization: %w", err)
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
	currentFluxProfilePatchData, err := tree.Data(fluxProfilePatchPath)
	if err != nil {
		return Result{}, err
	}
	candidateFluxProfilePatchData, err := yaml.Marshal(candidateFluxProfilePatch)
	if err != nil {
		return Result{}, fmt.Errorf("encode candidate Flux profile patch: %w", err)
	}
	fluxOverlayDirectory := filepath.Join(service.root, filepath.Dir(desired.Platform.Flux.Assets[0].File))
	currentFluxOverlay, err := service.renderFluxOverlay(
		fluxOverlayDirectory,
		filepath.Base(desired.Platform.Flux.Assets[0].File),
		currentFluxManifest,
		currentFluxKustomizationData,
		filepath.Base(fluxProfilePatchPath),
		currentFluxProfilePatchData,
	)
	if err != nil {
		return Result{}, fmt.Errorf("render current Flux overlay: %w", err)
	}
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
	currentFluxOverlayInspection, err := inspectManifestData("flux-overlay", currentFluxOverlay)
	if err != nil {
		return Result{}, fmt.Errorf("inspect current Flux overlay: %w", err)
	}
	candidateFluxOverlayInspection, err := inspectManifestData("flux-overlay", candidateFluxOverlay)
	if err != nil {
		return Result{}, fmt.Errorf("inspect candidate Flux overlay: %w", err)
	}
	if currentFluxOverlayInspection.ContractSHA != candidateFluxOverlayInspection.ContractSHA {
		return Result{}, fmt.Errorf(
			"runtime contract changed for the applied Flux overlay (%s -> %s); update aborted for explicit compatibility review",
			currentFluxOverlayInspection.ContractSHA,
			candidateFluxOverlayInspection.ContractSHA,
		)
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
	if err := validateAppliedArtifacts(
		ctx,
		parallelism,
		selectedKubernetes.Version,
		service.root,
		project.Desired,
		desired,
		operational,
		generated,
		candidateGenerated,
		profileRenderValues,
		bootstrapValues,
		artifacts,
		tree.Files(),
	); err != nil {
		return Result{}, err
	}
	desired.Delivery.RenderedBaseline.BigBang = config.VersionedCommit{
		Version: desired.Platform.BigBang.Version,
		Commit:  desired.Platform.BigBang.Commit,
	}
	desired.Delivery.LegacyCrosswalk.BigBang = desired.Delivery.RenderedBaseline.BigBang

	service.logger.InfoContext(ctx, "resolving public linux/amd64 image digests")
	if _, err := refreshMirrorDigests(ctx, parallelism, &project.Desired, &desired, &lock); err != nil {
		return Result{}, err
	}
	candidateProject := *project
	candidateProject.Desired = desired
	candidateProject.Lock = lock
	graphSHA, err := config.DeliveryGraphSHA256WithFiles(&candidateProject, lock.Delivery.Profile, tree.Files())
	if err != nil {
		return Result{}, fmt.Errorf("resolve candidate delivery graph: %w", err)
	}
	lock.Delivery.GraphSHA256 = graphSHA
	deliveryCurrent, err := refreshImageInputHashes(&desired, &lock)
	if err != nil {
		return Result{}, err
	}

	lock.Resolved = config.Resolved{
		ClusterReleases: desired.Orchestration.Releases,
		BigBang:         desired.Platform.BigBang,
		Flux:            desired.Platform.Flux,
		Packages:        desired.Platform.Packages,
		SupportSources:  supportSourceValues(supportSources),
		Charts:          desired.Platform.Charts,
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
	materialChanged := materialStateChanged(project, &desired, &lock)
	if !deliveryCurrent {
		lock.Delivery = config.ImageLock{
			SchemaVersion:   "atum.dev/image-lock/v3",
			Profile:         lock.Delivery.Profile,
			Platform:        desired.Project.Platform,
			InventorySHA256: deliverySHA,
			GraphSHA256:     graphSHA,
			Images:          []config.LockedImage{},
		}
	}
	if materialChanged || !deliveryCurrent || sourceSnapshotChanged {
		lock.Bundle = nil
	}

	if len(desired.Platform.Flux.Assets) != 1 {
		return Result{}, errors.New("resolved Flux source must contain exactly one install asset")
	}
	if err := tree.Set(desired.Platform.Flux.Assets[0].File, fluxManifest); err != nil {
		return Result{}, err
	}
	if err := tree.Set(fluxSyncPath, candidateFluxSync); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, fluxKustomizationPath, fluxKustomization, candidateFluxKustomization); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, fluxProfilePatchPath, currentFluxProfilePatch, candidateFluxProfilePatch); err != nil {
		return Result{}, err
	}
	if err := setCandidateYAML(tree, desired.Platform.Values.Generated, generated, candidateGenerated); err != nil {
		return Result{}, err
	}
	bigBangSource, err := bigBangSourceValues(
		service.root, desired.Platform.Sources, desired.Platform.BigBang, tree.Files())
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
	for minor := terminal.Minor() + 1; minor <= candidate.Minor(); minor++ {
		found := false
		for _, step := range candidates {
			version, _ := semver.NewVersion(step.kubernetes.Version)
			if version.Major() != terminal.Major() || version.Minor() != minor {
				continue
			}
			result = append(result, config.ClusterRelease{
				Kubernetes: step.kubernetes.Version,
				Kubespray:  step.kubespray.Source,
				Checksums:  step.kubernetes.Checksums,
			})
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("no exact Kubespray release is compatible with Kubernetes %d.%d", terminal.Major(), minor)
		}
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
			if err := validateKubesprayOIDCLifecycle(candidate.Checkout, kubernetes.Version); err != nil {
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
	bigBang              resolvedGit
	packages             []resolvedPackage
	charts               []resolvedTrackedChart
	bootstrap            []resolvedBootstrapChart
	supportSources       []resolvedSupportSource
	constraints          []versionConstraint
	generated            map[string]any
	artifacts            []chartArtifact
	kubernetes           kubernetesRelease
	currentInspections   []chartInspection
	candidateInspections []chartInspection
	clusterReleases      []config.ClusterRelease
}

// recordWrapperCandidateFailure is the candidate-selection boundary for
// wrapper incompatibility. Ordinary resolution records the rejected
// coordinate and continues the catalog; an exact historical selection has no
// fallback candidate and returns the incompatibility directly.
func recordWrapperCandidateFailure(
	failures *[]string,
	bigBangVersion string,
	candidateCoordinate string,
	pinned bool,
	err error,
) error {
	if pinned {
		return fmt.Errorf(
			"pinned Big Bang %s has an incompatible wrapper contract: %w",
			bigBangVersion,
			err,
		)
	}
	*failures = append(*failures, candidateCoordinate+": "+err.Error())
	return nil
}

func (service *Service) selectCompatiblePlatform(
	ctx context.Context,
	bigBangLatest resolvedGit,
	kubesprayLatest resolvedGit,
	desired config.Document,
	lock config.Lock,
	operational map[string]any,
	generated map[string]any,
	profile map[string]any,
	trackedChartCatalogs []*chartCatalog,
	bootstrapChartCatalogs []*chartCatalog,
	currentInputs map[string]artifactInput,
	applicationRepositories map[string][]string,
	parallelism int,
	files map[string][]byte,
	resetToPinnedBigBang bool,
	identityContract *identity.Contract,
) (platformSelection, error) {
	if identityContract == nil {
		return platformSelection{}, errors.New("canonical local identity contract is unavailable")
	}
	openSearchIdentity, found := identityContract.ClientForApplication(identity.OpenSearch)
	if !found {
		return platformSelection{}, errors.New(
			"identity contract has no OpenSearch application projection")
	}
	minimumRelease, err := desired.Orchestration.TargetRelease()
	if err != nil {
		return platformSelection{}, err
	}
	if resetToPinnedBigBang {
		minimumRelease = desired.Orchestration.Releases[0]
	}
	configuredValues, err := config.MergePlatformValues(operational, generated, profile)
	if err != nil {
		return platformSelection{}, err
	}
	failures := make([]string, 0, len(bigBangLatest.Releases))
	for index := range bigBangLatest.Releases {
		if err := ctx.Err(); err != nil {
			return platformSelection{}, err
		}
		candidate := bigBangLatest
		if index != 0 {
			var err error
			candidate, err = resolveGitRelease(ctx, service.cache, "bigbang", desired.Platform.BigBang, bigBangLatest.Releases, index)
			if err != nil {
				return platformSelection{}, err
			}
		}
		metadata, err := readChartMetadata(filepath.Join(candidate.Checkout, "chart"))
		if err != nil {
			return platformSelection{}, fmt.Errorf("inspect Big Bang chart %s: %w", candidate.Source.Version, err)
		}
		if metadata.Version != candidate.Source.Version {
			return platformSelection{}, fmt.Errorf("Big Bang tag %s contains chart version %s", candidate.Source.Version, metadata.Version)
		}
		if metadata.KubeVersion == "" {
			failures = append(failures, candidate.Source.Version+": Big Bang chart has no Kubernetes compatibility constraint")
			continue
		}
		candidate.Source.KubeVersion = metadata.KubeVersion
		bigBangValues, err := readBigBangValues(candidate.Checkout)
		if err != nil {
			return platformSelection{}, err
		}
		effectiveValues := mergeValues(bigBangValues, configuredValues)
		if err := verifySelectedPackages(effectiveValues, desired.Platform.Packages, desired.Platform.Charts); err != nil {
			return platformSelection{}, fmt.Errorf("Big Bang %s selection: %w", candidate.Source.Version, err)
		}
		if err := verifyTrackedChartBindings(service.root, effectiveValues, desired.Platform.Bootstrap.Registry, desired.Platform.Charts, files); err != nil {
			return platformSelection{}, fmt.Errorf("Big Bang %s chart sources: %w", candidate.Source.Version, err)
		}
		supportSources, err := resolveWrapperSupportSource(
			ctx, service.cache, candidate, desired.Platform, bigBangValues, effectiveValues, lock.Resolved,
		)
		if err != nil {
			terminalErr := recordWrapperCandidateFailure(
				&failures,
				candidate.Source.Version,
				candidate.Source.Version,
				resetToPinnedBigBang,
				fmt.Errorf("wrapper source contract: %w", err),
			)
			if terminalErr != nil {
				return platformSelection{}, terminalErr
			}
			continue
		}
		packages, err := resolvePackages(
			ctx, service.cache, parallelism, bigBangValues, desired.Platform.Packages, resetToPinnedBigBang,
		)
		if err != nil {
			return platformSelection{}, err
		}
		candidateDesired := desired
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
				continue
			}
			return platformSelection{}, err
		}
		if resetToPinnedBigBang {
			slices.Reverse(kubernetesCandidates)
		}
		for _, kubernetesCandidate := range kubernetesCandidates {
			trackedOffsets := make(map[string]int, len(desired.Platform.Charts))
			bootstrapOffsets := make(map[string]int, len(desired.Platform.Bootstrap.Charts))
			for attempt := 1; ; attempt++ {
				attemptDesired := candidateDesired
				attemptDesired.Platform.Charts = append([]config.TrackedChart(nil), desired.Platform.Charts...)
				attemptDesired.Platform.Bootstrap.Charts = append([]config.Chart(nil), desired.Platform.Bootstrap.Charts...)
				trackedCharts, err := resolveTrackedChartsForKubernetes(
					ctx, service.charts, parallelism, desired.Platform.Charts, trackedChartCatalogs,
					kubernetesCandidate.kubernetes.Version, trackedOffsets, applicationRepositories,
				)
				if err != nil {
					if errors.Is(err, errNoCompatibleKubernetes) {
						failures = append(failures, candidate.Source.Version+"/Kubernetes "+kubernetesCandidate.kubernetes.Version+": "+err.Error())
						break
					}
					return platformSelection{}, err
				}
				bootstrapCharts, err := resolveBootstrapChartsForKubernetes(
					ctx, service.charts, parallelism, desired.Platform.Bootstrap.Charts, bootstrapChartCatalogs,
					kubernetesCandidate.kubernetes.Version, bootstrapOffsets,
				)
				if err != nil {
					if errors.Is(err, errNoCompatibleKubernetes) {
						failures = append(failures, candidate.Source.Version+"/Kubernetes "+kubernetesCandidate.kubernetes.Version+": "+err.Error())
						break
					}
					return platformSelection{}, err
				}
				for i := range trackedCharts {
					attemptDesired.Platform.Charts[i] = trackedCharts[i].Chart
				}
				for i := range bootstrapCharts {
					attemptDesired.Platform.Bootstrap.Charts[i] = bootstrapCharts[i].Chart
				}
				constraints := collectConstraints(&attemptDesired)
				if _, err := compatibleKubernetes([]kubernetesRelease{kubernetesCandidate.kubernetes}, constraints); err != nil {
					failures = append(failures, candidate.Source.Version+"/Kubernetes "+kubernetesCandidate.kubernetes.Version+": "+err.Error())
					break
				}
				candidateGenerated := cloneMap(generated)
				if err := updateGeneratedVersions(
					candidateGenerated,
					attemptDesired.Platform.Sources,
					packages,
					supportSources,
					trackedCharts,
					attemptDesired.Delivery.Images,
				); err != nil {
					return platformSelection{}, err
				}
				candidateConfiguredValues, err := config.MergePlatformValues(operational, candidateGenerated, profile)
				if err != nil {
					return platformSelection{}, err
				}
				candidateRenderValues, err := sourceVersionValues(
					candidateConfiguredValues,
					attemptDesired.Platform.Sources,
					attemptDesired.Platform.Packages,
					supportSourceValues(supportSources),
					attemptDesired.Platform.Charts,
					attemptDesired.Delivery.Images,
				)
				if err != nil {
					return platformSelection{}, err
				}
				candidateInputs, err := candidateArtifacts(
					candidate, attemptDesired.Platform.Sources, attemptDesired.Platform.Bootstrap.Registry,
					packages, trackedCharts, bootstrapCharts, candidateRenderValues, service.root, files,
				)
				if err != nil {
					return platformSelection{}, err
				}
				artifacts, err := pairArtifacts(currentInputs, candidateInputs)
				if err != nil {
					return platformSelection{}, err
				}
				service.logger.InfoContext(ctx, "rendering candidate Helm contracts",
					"bigbang", candidate.Source.Version,
					"kubernetes", kubernetesCandidate.kubernetes.Version,
					"attempt", attempt,
					"candidates", len(artifacts),
				)
				currentInspections, candidateInspections, err := inspectArtifactPairs(
					ctx, min(parallelism, 4), kubernetesCandidate.kubernetes.Version, artifacts,
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
					failures = append(failures, candidate.Source.Version+"/Kubernetes "+kubernetesCandidate.kubernetes.Version+": "+err.Error())
					break
				}
				retryChart := false
				incompatible := ""
				renderedImages := renderedImageIDs(attemptDesired.Delivery.Images, candidateInspections)
				for i := range artifacts {
					err := validateImageContract(
						&attemptDesired,
						artifacts[i].ID,
						currentInspections[i],
						candidateInspections[i],
						renderedImages,
						resetToPinnedBigBang,
					)
					if err == nil {
						continue
					}
					if backtrackChart(artifacts[i].ID, trackedOffsets, bootstrapOffsets) {
						service.logger.WarnContext(ctx, "candidate chart contract changed; trying the next compatible release",
							"artifact", artifacts[i].ID,
							"error", err,
						)
						retryChart = true
					} else {
						incompatible = err.Error()
					}
					break
				}
				if retryChart {
					continue
				}
				if incompatible != "" {
					service.logger.WarnContext(ctx, "candidate platform contract is incompatible",
						"bigbang", candidate.Source.Version,
						"kubernetes", kubernetesCandidate.kubernetes.Version,
						"error", incompatible,
					)
					failures = append(failures, candidate.Source.Version+"/Kubernetes "+kubernetesCandidate.kubernetes.Version+": "+incompatible)
					break
				}
				if err := validatePlatformMeshContract(
					candidate,
					attemptDesired.Platform,
					packages,
					supportSources,
					candidateRenderValues,
					kubernetesCandidate.kubernetes.Version,
					openSearchIdentity.Host,
				); err != nil {
					contractErr := fmt.Errorf("platform mesh contract: %w", err)
					coordinate := candidate.Source.Version + "/Kubernetes " + kubernetesCandidate.kubernetes.Version
					terminalErr := recordWrapperCandidateFailure(
						&failures,
						candidate.Source.Version,
						coordinate,
						resetToPinnedBigBang,
						contractErr,
					)
					if terminalErr != nil {
						return platformSelection{}, terminalErr
					}
					service.logger.WarnContext(ctx, "candidate Big Bang mesh contract is incompatible",
						"bigbang", candidate.Source.Version,
						"kubernetes", kubernetesCandidate.kubernetes.Version,
						"error", err,
					)
					break
				}
				if err := validatePlatformIdentityContract(
					artifacts,
					identityContract,
					attemptDesired,
					kubernetesCandidate.kubernetes.Version,
					files,
					service.root,
				); err != nil {
					coordinate := candidate.Source.Version + "/Kubernetes " +
						kubernetesCandidate.kubernetes.Version
					contractErr := fmt.Errorf("platform identity contract: %w", err)
					if resetToPinnedBigBang {
						return platformSelection{}, fmt.Errorf(
							"pinned Big Bang %s has an incompatible identity contract: %w",
							candidate.Source.Version, contractErr)
					}
					failures = append(failures, coordinate+": "+contractErr.Error())
					service.logger.WarnContext(
						ctx, "candidate Big Bang identity contract is incompatible",
						"bigbang", candidate.Source.Version,
						"kubernetes", kubernetesCandidate.kubernetes.Version,
						"error", err,
					)
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
					failures = append(failures, candidate.Source.Version+"/Kubernetes "+kubernetesCandidate.kubernetes.Version+": "+err.Error())
					break
				}
				return platformSelection{
					bigBang:              candidate,
					packages:             packages,
					charts:               trackedCharts,
					bootstrap:            bootstrapCharts,
					supportSources:       supportSources,
					constraints:          constraints,
					generated:            candidateGenerated,
					artifacts:            artifacts,
					kubernetes:           kubernetesCandidate.kubernetes,
					currentInspections:   currentInspections,
					candidateInspections: candidateInspections,
					clusterReleases:      clusterReleases,
				}, nil
			}
		}
	}
	return platformSelection{}, fmt.Errorf("no stable compatible Big Bang/Kubernetes pair: %s", strings.Join(failures, "; "))
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

func verifySelectedPackages(operational map[string]any, packages []config.Package, charts []config.TrackedChart) error {
	selected := make(map[string]struct{}, len(packages)+len(charts))
	for _, pkg := range packages {
		selected[pkg.ValuesPath] = struct{}{}
		values, err := valuesAt(operational, pkg.ValuesPath)
		if err != nil {
			return fmt.Errorf("selected package %s: %w", pkg.ID, err)
		}
		if enabled, _ := values["enabled"].(bool); !enabled {
			return fmt.Errorf("selected package %s is not enabled in operational values", pkg.ID)
		}
		if sourceType, _ := values["sourceType"].(string); sourceType != "git" {
			return fmt.Errorf("selected package %s uses sourceType %q, want git", pkg.ID, sourceType)
		}
	}
	for _, chart := range charts {
		selected[chart.ValuesPath] = struct{}{}
		values, err := valuesAt(operational, chart.ValuesPath)
		if err != nil {
			return fmt.Errorf("selected chart %s: %w", chart.ID, err)
		}
		if enabled, _ := values["enabled"].(bool); !enabled {
			return fmt.Errorf("selected chart %s is not enabled in operational values", chart.ID)
		}
		if sourceType, _ := values["sourceType"].(string); sourceType != "helmRepo" {
			return fmt.Errorf("selected chart %s uses sourceType %q, want helmRepo", chart.ID, sourceType)
		}
	}
	var walk func(map[string]any, string) error
	walk = func(values map[string]any, prefix string) error {
		for key, raw := range values {
			nested, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			enabled, hasEnabled := nested["enabled"].(bool)
			sourceType, _ := nested["sourceType"].(string)
			if hasEnabled && enabled && sourceType != "" {
				if sourceType != "git" && sourceType != "helmRepo" {
					return fmt.Errorf("enabled Big Bang source %s uses unsupported sourceType %q", path, sourceType)
				}
				if _, exists := selected[path]; !exists {
					return fmt.Errorf("enabled Big Bang source %s is absent from the declarative package inventory", path)
				}
			}
			if err := walk(nested, path); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(operational, "")
}

func updateGeneratedVersions(
	generated map[string]any,
	sources config.SourceRegistry,
	packages []resolvedPackage,
	supportSources []resolvedSupportSource,
	charts []resolvedTrackedChart,
	images []config.Image,
) error {
	rolloutPaths := make([]string, 0, len(packages)+len(charts))
	istioVersion := ""
	keycloakPath := ""
	kyvernoReporterPath := ""
	delete(generated, "wrapper")
	for _, pkg := range packages {
		if err := pinPackageSource(generated, sources, pkg.Package); err != nil {
			return fmt.Errorf("update generated package %s source: %w", pkg.Package.ID, err)
		}
		switch pkg.Package.ID {
		case "istiod":
			istioVersion = pkg.Package.Source.Version
		case "keycloak":
			keycloakPath = pkg.Package.ValuesPath
		case "kyverno-reporter":
			kyvernoReporterPath = pkg.Package.ValuesPath
		default:
			rolloutPaths = append(rolloutPaths, pkg.Package.ValuesPath)
		}
	}
	for _, support := range supportSources {
		if err := pinSupportSource(generated, sources, support.Support); err != nil {
			return fmt.Errorf("update generated support source %s: %w", support.Support.ID, err)
		}
	}
	for _, chart := range charts {
		if err := setScalar(generated, chart.Chart.ValuesPath+".helmRepo.tag", chart.Chart.Version); err != nil {
			return fmt.Errorf("update generated chart %s: %w", chart.Chart.ID, err)
		}
		rolloutPaths = append(rolloutPaths, chart.Chart.ValuesPath)
	}
	proxyImage, err := istioProxyImage(images, istioVersion)
	if err != nil {
		return err
	}
	if err := pinKeycloakIstioProxy(generated, keycloakPath, proxyImage); err != nil {
		return err
	}
	if err := pinKyvernoReporterIstioProxy(generated, kyvernoReporterPath, proxyImage); err != nil {
		return err
	}
	return pinIstioWorkloadRollouts(generated, istioVersion, proxyImage, rolloutPaths)
}

func sourceVersionValues(
	operational map[string]any,
	sources config.SourceRegistry,
	packages []config.Package,
	supportSources []config.SupportSource,
	charts []config.TrackedChart,
	images []config.Image,
) (map[string]any, error) {
	values := cloneMap(operational)
	rolloutPaths := make([]string, 0, len(packages)+len(charts))
	istioVersion := ""
	keycloakPath := ""
	kyvernoReporterPath := ""
	for _, pkg := range packages {
		if err := pinPackageSource(values, sources, pkg); err != nil {
			return nil, fmt.Errorf("pin package source %s: %w", pkg.ID, err)
		}
		switch pkg.ID {
		case "istiod":
			istioVersion = pkg.Source.Version
		case "keycloak":
			keycloakPath = pkg.ValuesPath
		case "kyverno-reporter":
			kyvernoReporterPath = pkg.ValuesPath
		default:
			rolloutPaths = append(rolloutPaths, pkg.ValuesPath)
		}
	}
	for _, support := range supportSources {
		if err := pinSupportSource(values, sources, support); err != nil {
			return nil, fmt.Errorf("pin support source %s: %w", support.ID, err)
		}
	}
	for _, chart := range charts {
		if err := setNestedValue(values, chart.ValuesPath+".helmRepo.tag", chart.Version); err != nil {
			return nil, fmt.Errorf("pin chart source %s: %w", chart.ID, err)
		}
		rolloutPaths = append(rolloutPaths, chart.ValuesPath)
	}
	proxyImage, err := istioProxyImage(images, istioVersion)
	if err != nil {
		return nil, err
	}
	if err := pinKeycloakIstioProxy(values, keycloakPath, proxyImage); err != nil {
		return nil, err
	}
	if err := pinKyvernoReporterIstioProxy(values, kyvernoReporterPath, proxyImage); err != nil {
		return nil, err
	}
	if err := pinIstioWorkloadRollouts(values, istioVersion, proxyImage, rolloutPaths); err != nil {
		return nil, err
	}
	return values, nil
}

func pinPackageSource(values map[string]any, sources config.SourceRegistry, pkg config.Package) error {
	fields := [...]struct {
		name  string
		value string
	}{
		{name: "repo", value: internalSourceURL(sources, sources.UpstreamOrganization, pkg.ID)},
		{name: "tag", value: ""},
		{name: "semver", value: pkg.Source.Version},
		{name: "branch", value: pkg.Source.Branch},
		{name: "commit", value: pkg.Source.Commit},
	}
	for _, field := range fields {
		if err := setNestedValue(values, pkg.ValuesPath+".git."+field.name, field.value); err != nil {
			return fmt.Errorf("set %s: %w", field.name, err)
		}
	}
	return nil
}

func pinSupportSource(values map[string]any, sources config.SourceRegistry, support config.SupportSource) error {
	fields := [...]struct {
		name  string
		value string
	}{
		{name: "repo", value: internalSourceURL(sources, sources.UpstreamOrganization, support.ID)},
		{name: "tag", value: ""},
		{name: "semver", value: support.Source.Version},
		{name: "branch", value: support.Source.Branch},
		{name: "commit", value: support.Source.Commit},
		{name: "path", value: support.ChartPath},
	}
	for _, field := range fields {
		if err := setNestedValue(values, support.ValuesPath+".git."+field.name, field.value); err != nil {
			return fmt.Errorf("set %s: %w", field.name, err)
		}
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

func pinIstioWorkloadRollouts(values map[string]any, version, proxyImage string, valuePaths []string) error {
	version, _, _ = strings.Cut(version, "-bb.")
	if version == "" {
		return nil
	}
	if proxyImage == "" {
		return errors.New("Istio proxy image is empty")
	}
	renderers := istioWorkloadRolloutRenderers(version, proxyImage)
	for _, path := range valuePaths {
		if err := setNestedValue(values, path+".postRenderers", cloneValue(renderers)); err != nil {
			return fmt.Errorf("pin Istio workload rollout for %s: %w", path, err)
		}
	}
	return nil
}

func istioProxyImage(images []config.Image, version string) (string, error) {
	version, _, _ = strings.Cut(version, "-bb.")
	if version == "" {
		return "", errors.New("selected packages do not define an Istiod version")
	}
	for _, image := range images {
		if image.ID != "istio-proxy" {
			continue
		}
		tagSeparator := strings.LastIndexByte(image.Target, ':')
		pathSeparator := strings.LastIndexByte(image.Target, '/')
		if tagSeparator <= pathSeparator || tagSeparator == len(image.Target)-1 {
			return "", fmt.Errorf("Istio proxy target %q has no replaceable tag", image.Target)
		}
		return image.Target[:tagSeparator+1] + version, nil
	}
	return "", errors.New("delivery images do not define istio-proxy")
}

func pinKeycloakIstioProxy(values map[string]any, path, proxyImage string) error {
	if path == "" {
		return errors.New("selected packages do not define Keycloak")
	}
	annotations, err := ensureNestedMap(values, path+".values.upstream.podAnnotations")
	if err != nil {
		return fmt.Errorf("pin Keycloak Istio proxy image: %w", err)
	}
	annotations["sidecar.istio.io/proxyImage"] = proxyImage
	annotations["atum.dev/istio-version"] = strings.TrimPrefix(proxyImage[strings.LastIndexByte(proxyImage, ':')+1:], "v")
	return nil
}

func pinKyvernoReporterIstioProxy(values map[string]any, path, proxyImage string) error {
	if path == "" {
		return errors.New("selected packages do not define Kyverno Reporter")
	}
	for _, suffix := range [...]string{
		"values.upstream.podAnnotations",
		"values.upstream.ui.podAnnotations",
		"values.upstream.plugin.kyverno.podAnnotations",
	} {
		annotations, err := ensureNestedMap(values, path+"."+suffix)
		if err != nil {
			return fmt.Errorf("pin Kyverno Reporter Istio proxy image: %w", err)
		}
		annotations["sidecar.istio.io/proxyImage"] = proxyImage
		annotations["atum.dev/istio-version"] = strings.TrimPrefix(proxyImage[strings.LastIndexByte(proxyImage, ':')+1:], "v")
	}
	return nil
}

func pinIstioHelmReleaseGates(
	helmRelease map[string]any,
	packages []resolvedPackage,
	dependencies []releaseDependencyPosition,
) error {
	istioVersion := ""
	for _, pkg := range packages {
		if pkg.Package.ID == "istiod" {
			istioVersion = pkg.Package.Source.Version
		}
	}
	istioVersion, _, _ = strings.Cut(istioVersion, "-bb.")
	if istioVersion == "" {
		return errors.New("selected packages do not define an Istiod version")
	}
	if len(dependencies) == 0 {
		return errors.New("selected packages do not define an Istio-dependent Helm release")
	}
	readyExpr := fmt.Sprintf(`dep.status.history.exists(e,
  e.status == 'deployed' &&
  (e.chartVersion == %q || e.chartVersion.startsWith(%q))) &&
  dep.status.conditions.filter(e, e.type == 'Ready').all(e, e.status == 'True')`,
		istioVersion, istioVersion+"-",
	)
	patches := make([]any, 0, len(dependencies))
	for start := 0; start < len(dependencies); {
		end := start + 1
		for end < len(dependencies) &&
			dependencies[end].namespace == dependencies[start].namespace &&
			dependencies[end].index == dependencies[start].index {
			end++
		}
		quotedNames := make([]string, end-start)
		for i := start; i < end; i++ {
			quotedNames[i-start] = regexp.QuoteMeta(dependencies[i].name)
		}
		patch, err := yaml.Marshal([]any{
			map[string]any{
				"op":    "add",
				"path":  "/metadata/annotations/atum.dev~1istio-version",
				"value": istioVersion,
			},
			map[string]any{
				"op":    "add",
				"path":  fmt.Sprintf("/spec/dependsOn/%d/readyExpr", dependencies[start].index),
				"value": readyExpr,
			},
		})
		if err != nil {
			return fmt.Errorf("encode Istio HelmRelease dependency gate: %w", err)
		}
		patches = append(patches, map[string]any{
			"patch": string(patch),
			"target": map[string]any{
				"group":     "helm.toolkit.fluxcd.io",
				"version":   "v2",
				"kind":      "HelmRelease",
				"name":      "^(" + strings.Join(quotedNames, "|") + ")$",
				"namespace": dependencies[start].namespace,
			},
		})
		start = end
	}
	renderers := []any{map[string]any{
		"kustomize": map[string]any{
			"patches": patches,
		},
	}}
	if err := setNestedValue(helmRelease, "spec.postRenderers", renderers); err != nil {
		return fmt.Errorf("pin Istio HelmRelease dependency gates: %w", err)
	}
	return nil
}

func bigBangIstioDependencies(
	artifacts []chartArtifact,
	inspections []chartInspection,
) []releaseDependencyPosition {
	for i := range artifacts {
		if artifacts[i].ID == "bigbang" {
			return inspections[i].IstioDependencies
		}
	}
	return nil
}

func istioWorkloadRolloutRenderers(version, proxyImage string) []any {
	patches := make([]any, 0, 3)
	for _, kind := range [...]string{"Deployment", "StatefulSet", "DaemonSet"} {
		patches = append(patches, map[string]any{
			"patch": fmt.Sprintf(`apiVersion: apps/v1
kind: %s
metadata:
  name: atum-istio-rollout
spec:
  template:
    metadata:
      annotations:
        atum.dev/istio-version: %q
        sidecar.istio.io/proxyImage: %q
`, kind, version, proxyImage),
			"target": map[string]any{
				"group": "apps", "version": "v1", "kind": kind,
			},
		})
	}
	return []any{map[string]any{
		"kustomize": map[string]any{"patches": patches},
	}}
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

func nestedMap(root map[string]any, path string) (map[string]any, error) {
	current := root
	for _, component := range strings.Split(path, ".") {
		next, exists := current[component]
		if !exists {
			return nil, fmt.Errorf("path %s is missing at %s", path, component)
		}
		nested, ok := next.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("path %s is not a map at %s", path, component)
		}
		current = nested
	}
	return current, nil
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

func materialStateChanged(project *config.Project, desired *config.Document, lock *config.Lock) bool {
	return !reflect.DeepEqual(project.Desired, *desired) ||
		!reflect.DeepEqual(project.Lock.Resolved, lock.Resolved) ||
		!reflect.DeepEqual(project.Lock.Compatibility, lock.Compatibility) ||
		!reflect.DeepEqual(project.Lock.Delivery, lock.Delivery)
}

func compactReplacements(replacements []imageReplacement) ([]imageReplacement, error) {
	byOld := make(map[string]string, len(replacements))
	for _, replacement := range replacements {
		if existing, exists := byOld[replacement.Old]; exists && existing != replacement.New {
			return nil, fmt.Errorf("image %s has conflicting replacements %s and %s", replacement.Old, existing, replacement.New)
		}
		byOld[replacement.Old] = replacement.New
	}
	oldReferences := make([]string, 0, len(byOld))
	for old := range byOld {
		oldReferences = append(oldReferences, old)
	}
	sort.Strings(oldReferences)
	result := make([]imageReplacement, 0, len(oldReferences))
	for _, old := range oldReferences {
		seen := map[string]struct{}{old: {}}
		final := byOld[old]
		for {
			next, exists := byOld[final]
			if !exists {
				break
			}
			if _, cycle := seen[final]; cycle {
				return nil, fmt.Errorf("image replacement cycle includes %s", final)
			}
			seen[final] = struct{}{}
			final = next
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
