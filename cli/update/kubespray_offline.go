package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitcache"
	"atum/cli/process"
	"atum/cli/progress"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
)

const (
	kubesprayListLimit = 16 << 20
)

type kubesprayOfflineVars struct {
	KubernetesVersion         string `json:"kube_version"`
	GCRImageRepo              string `json:"gcr_image_repo"`
	KubeImageRepo             string `json:"kube_image_repo"`
	KubeadmImageRepo          string `json:"kubeadm_image_repo"`
	DockerImageRepo           string `json:"docker_image_repo"`
	QuayImageRepo             string `json:"quay_image_repo"`
	GitHubImageRepo           string `json:"github_image_repo"`
	CiliumImageTag            string `json:"cilium_image_tag"`
	CiliumHubbleEnvoyImageTag string `json:"cilium_hubble_envoy_image_tag"`
	CiliumOperatorImageTag    string `json:"cilium_operator_image_tag"`
}

type discoveredKubesprayFile struct {
	variable  string
	source    string
	localPath string
}

type kubesprayReleaseArtifacts struct {
	inventory config.KubesprayArtifactInventory
	images    []config.Image
}

type kubesprayRuntimeImage struct {
	source              string
	digest              string
	discoveryRepository string
}

func (service *Service) reconstructKubesprayReleaseArtifacts(
	ctx context.Context,
	desired *config.Document,
	releases []config.ClusterRelease,
	terminal resolvedGit,
	parallelism int,
	mirrorReceipts map[string]config.ImageMirrorReceipt,
) ([]config.KubesprayArtifactInventory, error) {
	if desired == nil || len(releases) == 0 {
		return nil, errors.New("Kubespray release ladder is empty")
	}
	results := make([]kubesprayReleaseArtifacts, len(releases))
	baseImages := append([]config.Image(nil), desired.Delivery.Images...)
	workLimit := config.EffectiveWorkLimit(
		parallelism, desired.Updates.Parallelism, config.DefaultWorkLimit,
	)
	releaseLimit := min(workLimit, len(releases))
	perReleaseLimit := max(1, workLimit/releaseLimit)
	checkoutLocks := make(map[string]*sync.Mutex, len(releases))
	for _, release := range releases {
		if checkoutLocks[release.Kubespray.Commit] == nil {
			checkoutLocks[release.Kubespray.Commit] = &sync.Mutex{}
		}
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(releaseLimit)
	for index := range releases {
		index := index
		group.Go(func() error {
			release := releases[index]
			checkoutLock := checkoutLocks[release.Kubespray.Commit]
			checkoutLock.Lock()
			defer checkoutLock.Unlock()
			resolved := terminal
			if resolved.Source.Commit != release.Kubespray.Commit {
				checkout, err := service.cache.Hydrate(
					groupContext,
					"kubespray",
					release.Kubespray.URL,
					gitcache.Release{
						Version: release.Kubespray.Version,
						Commit:  release.Kubespray.Commit,
					},
				)
				if err != nil {
					return err
				}
				resolved = resolvedGit{
					Source: release.Kubespray, Checkout: checkout,
				}
			}
			candidate := *desired
			candidate.Delivery.Images = append(
				[]config.Image(nil), baseImages...,
			)
			inventory, err := service.reconstructKubesprayArtifacts(
				groupContext,
				&candidate,
				resolved,
				release.Kubernetes,
				perReleaseLimit,
				mirrorReceipts,
			)
			if err != nil {
				return err
			}
			results[index] = kubesprayReleaseArtifacts{
				inventory: inventory,
				images: append(
					[]config.Image(nil),
					candidate.Delivery.Images[len(baseImages):]...,
				),
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	byID := make(map[string]config.Image, len(baseImages))
	for _, image := range baseImages {
		byID[image.ID] = image
	}
	inventories := make([]config.KubesprayArtifactInventory, len(results))
	for index := range results {
		inventories[index] = results[index].inventory
		for _, image := range results[index].images {
			if current, found := byID[image.ID]; found {
				if current.Target != image.Target ||
					current.Delivery.Default.Source !=
						image.Delivery.Default.Source ||
					current.Delivery.Default.Digest !=
						image.Delivery.Default.Digest {
					return nil, fmt.Errorf(
						"Kubespray image %s conflicts across release inventories",
						image.ID,
					)
				}
				continue
			}
			desired.Delivery.Images = append(desired.Delivery.Images, image)
			byID[image.ID] = image
		}
	}
	return inventories, nil
}

func (service *Service) reconstructKubesprayArtifacts(
	ctx context.Context,
	desired *config.Document,
	resolved resolvedGit,
	kubernetesVersion string,
	parallelism int,
	mirrorReceipts map[string]config.ImageMirrorReceipt,
) (config.KubesprayArtifactInventory, error) {
	if desired == nil || resolved.Checkout == "" || resolved.Source.Commit == "" {
		return config.KubesprayArtifactInventory{}, errors.New(
			"exact Kubespray source is required for offline artifact discovery",
		)
	}
	ciliumVersion, err := service.kubesprayCiliumVersion(desired)
	if err != nil {
		return config.KubesprayArtifactInventory{}, err
	}
	runtimeImages, err := service.kubesprayChartRuntimeImages(
		ctx,
		ciliumVersion,
	)
	if err != nil {
		return config.KubesprayArtifactInventory{}, err
	}
	runtimeTags, err := kubesprayCiliumRuntimeTagsFromImages(runtimeImages)
	if err != nil {
		return config.KubesprayArtifactInventory{}, err
	}
	files, sources, officialImages, scriptSHA256, err := service.runKubesprayOfflineWorkflow(
		ctx, desired, resolved, kubernetesVersion, runtimeTags, parallelism,
	)
	if err != nil {
		return config.KubesprayArtifactInventory{}, err
	}
	if err := validateKubesprayRuntimeDiscovery(sources, runtimeImages); err != nil {
		return config.KubesprayArtifactInventory{}, err
	}
	chartDigests := make(map[string]string, len(runtimeImages))
	runtimeSources := make([]string, len(runtimeImages))
	for index, image := range runtimeImages {
		chartDigests[image.source] = image.digest
		runtimeSources[index] = image.source
	}
	sources = mergeKubesprayRuntimeImages(sources, runtimeImages)
	images := make([]config.Image, len(sources))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism, desired.Updates.Parallelism, config.DefaultWorkLimit,
	))
	var completed atomic.Int64
	for index := range sources {
		index := index
		group.Go(func() error {
			source := sources[index]
			reference, err := name.ParseReference(source)
			if err != nil {
				return fmt.Errorf("parse Kubespray image %s: %w", source, err)
			}
			repository := reference.Context().Name()
			tag := reference.Identifier()
			idDigest := config.SHA256([]byte(source))
			component := sanitizeKubesprayImageID(filepath.Base(repository))
			imageID := "kubespray-" + component + "-" + idDigest[:12]
			digest := chartDigests[source]
			resolvedFromCache := false
			if receipt, found := mirrorReceipts[imageID]; found &&
				(digest == "" || digest == receipt.Digest) {
				_, reusable, cacheErr := openReusableOfficialImageCache(
					groupContext,
					service.root,
					imageID,
					source,
					receipt,
				)
				if cacheErr != nil {
					return fmt.Errorf(
						"open exact Kubespray image cache %s: %w",
						source,
						cacheErr,
					)
				}
				if reusable {
					digest = receipt.Digest
					resolvedFromCache = true
				}
			}
			if digest == "" {
				resolvedDigest, resolveErr := resolveImageDigest(groupContext, source)
				if resolveErr != nil {
					return fmt.Errorf(
						"resolve Kubespray image %s: %w",
						source,
						resolveErr,
					)
				}
				digest = resolvedDigest
			} else if !resolvedFromCache {
				resolved, resolveErr := resolveImageDigests(groupContext, source)
				if resolveErr != nil {
					return fmt.Errorf(
						"resolve chart-pinned Kubespray image %s: %w",
						source,
						resolveErr,
					)
				}
				if resolved.tag != digest {
					return fmt.Errorf(
						"chart-pinned Kubespray image %s resolves to root %s, want %s",
						source,
						resolved.tag,
						digest,
					)
				}
			}
			images[index] = config.Image{
				ID:      imageID,
				Family:  "kubernetes",
				Version: strings.TrimPrefix(tag, "v"),
				Target: strings.TrimSuffix(
					desired.Delivery.Policy.RuntimeRegistryPrefix, "/",
				) + "/kubespray/" + repository + ":" + tag,
				Scopes:  []string{"kubespray"},
				Runtime: true,
				License: "upstream project license",
				Provenance: resolved.Source.URL + " @ " + resolved.Source.Commit +
					" / contrib/offline/generate_list.sh",
				Consumers:   []string{"kubespray"},
				BigBangRefs: []string{},
				Discovery:   "kubespray",
				Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
					Type: "mirror", Source: source, Digest: digest,
				}},
			}
			progress.Update(
				groupContext, progress.Platform, "kubespray-artifacts",
				"Kubespray artifacts", "resolved image "+source,
				int(completed.Add(1)), len(sources),
			)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		progress.Fail(
			ctx, progress.Platform, "kubespray-artifacts",
			"Kubespray artifacts", err,
		)
		return config.KubesprayArtifactInventory{}, err
	}
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
	imageIDs := make([]string, len(images))
	for index := range images {
		imageIDs[index] = images[index].ID
	}
	existing := make(map[string]config.Image, len(desired.Delivery.Images))
	for _, image := range desired.Delivery.Images {
		existing[image.ID] = image
	}
	for _, image := range images {
		if current, found := existing[image.ID]; found {
			if current.Target != image.Target ||
				current.Delivery.Default.Source != image.Delivery.Default.Source ||
				current.Delivery.Default.Digest != image.Delivery.Default.Digest {
				return config.KubesprayArtifactInventory{}, fmt.Errorf(
					"Kubespray image %s has conflicting canonical records",
					image.ID,
				)
			}
			continue
		}
		desired.Delivery.Images = append(desired.Delivery.Images, image)
		existing[image.ID] = image
	}
	inventory := config.KubesprayArtifactInventory{
		SchemaVersion:        config.KubesprayArtifactSchema,
		KubernetesVersion:    kubernetesVersion,
		KubesprayCommit:      resolved.Source.Commit,
		OfficialScript:       config.KubesprayOfficialScript,
		OfficialScriptSHA256: scriptSHA256,
		InventoryScope:       config.KubesprayFullOfflineInventory,
		OfficialImages:       officialImages,
		RuntimeImages:        runtimeSources,
		Files:                files,
		Images:               imageIDs,
	}
	inventory.InventorySHA256, err = config.KubesprayInventorySHA256(inventory)
	if err != nil {
		return config.KubesprayArtifactInventory{}, fmt.Errorf(
			"identify Kubespray artifact inventory: %w", err,
		)
	}
	progress.Done(
		ctx, progress.Platform, "kubespray-artifacts", "Kubespray artifacts",
		fmt.Sprintf("%d files and %d images locked", len(files), len(images)),
	)
	return inventory, nil
}

func (service *Service) kubesprayCiliumVersion(
	desired *config.Document,
) (string, error) {
	if desired == nil || desired.Orchestration.Inventory == "" {
		return "", errors.New("Kubespray inventory is required")
	}
	path, err := fssecure.Resolve(
		service.root,
		filepath.Join(
			desired.Orchestration.Inventory,
			"group_vars", "k8s_cluster", "k8s-cluster.yml",
		),
		false,
	)
	if err != nil {
		return "", fmt.Errorf("resolve Kubespray Cilium configuration: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Kubespray Cilium configuration: %w", err)
	}
	var variables map[string]any
	if err := yaml.Unmarshal(data, &variables); err != nil {
		return "", fmt.Errorf("decode Kubespray Cilium configuration: %w", err)
	}
	configured, ok := variables["cilium_version"].(string)
	if !ok {
		return "", errors.New("Kubespray cilium_version must be one string")
	}
	configured = strings.TrimSpace(configured)
	version := strings.TrimPrefix(configured, "v")
	if version == "" || strings.ContainsAny(version, " \t\r\n{}") {
		return "", fmt.Errorf(
			"Kubespray cilium_version %q is not an exact version",
			configured,
		)
	}
	return version, nil
}

func (service *Service) kubesprayChartRuntimeImages(
	ctx context.Context,
	version string,
) ([]kubesprayRuntimeImage, error) {
	if version == "" {
		return nil, errors.New("Kubespray Cilium version is required")
	}
	releases, err := service.charts.HTTPSReleases(
		ctx,
		"https://helm.cilium.io/index.yaml",
		"cilium",
	)
	if err != nil {
		return nil, fmt.Errorf("resolve Cilium chart %s: %w", version, err)
	}
	var selected chartRelease
	for _, release := range releases {
		if equivalentTag(release.Version, version) {
			selected = release
			break
		}
	}
	if selected.Version == "" {
		return nil, fmt.Errorf(
			"Cilium chart %s is absent from its official repository",
			version,
		)
	}
	selected, err = service.charts.Fetch(ctx, selected)
	if err != nil {
		return nil, fmt.Errorf("fetch Cilium chart %s: %w", version, err)
	}
	chart, err := loader.Load(selected.ArchivePath)
	if err != nil {
		return nil, fmt.Errorf("load Cilium chart %s: %w", version, err)
	}
	type binding struct {
		path      string
		digestKey string
		suffix    string
	}
	bindings := [...]binding{
		{path: "image", digestKey: "digest"},
		{path: "envoy.image", digestKey: "digest"},
		{
			path:      "operator.image",
			digestKey: "genericDigest",
			suffix:    "-generic",
		},
	}
	runtime := make([]kubesprayRuntimeImage, 0, len(bindings))
	seenSources := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		image, err := valuesAt(chart.Values, binding.path)
		if err != nil {
			return nil, fmt.Errorf(
				"read Cilium chart image %s: %w",
				binding.path,
				err,
			)
		}
		repository, _ := image["repository"].(string)
		tag, _ := image["tag"].(string)
		digest, _ := image[binding.digestKey].(string)
		if repository == "" || tag == "" ||
			!strings.HasPrefix(digest, "sha256:") {
			return nil, fmt.Errorf(
				"Cilium chart image %s is incomplete",
				binding.path,
			)
		}
		source := repository + binding.suffix + ":" + tag
		if current, duplicate := seenSources[source]; duplicate {
			if current != digest {
				return nil, fmt.Errorf(
					"Cilium chart runtime image %s has conflicting digests",
					source,
				)
			}
			continue
		}
		seenSources[source] = digest
		runtime = append(runtime, kubesprayRuntimeImage{
			source:              source,
			digest:              digest,
			discoveryRepository: repository,
		})
	}
	sort.Slice(runtime, func(i, j int) bool {
		return runtime[i].source < runtime[j].source
	})
	return runtime, nil
}

func validateKubesprayRuntimeDiscovery(
	sources []string,
	runtime []kubesprayRuntimeImage,
) error {
	sourceByRepository := make(map[string]string, len(sources))
	for _, source := range sources {
		reference, err := name.ParseReference(source)
		if err != nil {
			return fmt.Errorf("parse Kubespray image %s: %w", source, err)
		}
		repository := reference.Context().Name()
		if existing, duplicate := sourceByRepository[repository]; duplicate &&
			existing != source {
			return fmt.Errorf(
				"Kubespray image repository %s has multiple tags",
				repository,
			)
		}
		sourceByRepository[repository] = source
	}
	for _, image := range runtime {
		runtimeReference, err := name.ParseReference(image.source)
		if err != nil {
			return fmt.Errorf(
				"parse Cilium chart runtime image %s: %w",
				image.source,
				err,
			)
		}
		discovered, present := sourceByRepository[image.discoveryRepository]
		if !present {
			return fmt.Errorf(
				"Cilium chart runtime repository %s is absent from Kubespray discovery",
				image.discoveryRepository,
			)
		}
		discoveredReference, err := name.ParseReference(discovered)
		if err != nil {
			return fmt.Errorf("parse Kubespray image %s: %w", discovered, err)
		}
		if discoveredReference.Identifier() != runtimeReference.Identifier() {
			return fmt.Errorf(
				"Cilium chart runtime image %s does not match Kubespray discovery %s",
				image.source,
				discovered,
			)
		}
	}
	return nil
}

func mergeKubesprayRuntimeImages(
	official []string,
	runtime []kubesprayRuntimeImage,
) []string {
	merged := make([]string, 0, len(official)+len(runtime))
	merged = append(merged, official...)
	for _, image := range runtime {
		merged = append(merged, image.source)
	}
	sort.Strings(merged)
	return compactSorted(merged)
}

func (service *Service) runKubesprayOfflineWorkflow(
	ctx context.Context,
	desired *config.Document,
	resolved resolvedGit,
	kubernetesVersion string,
	runtimeTags map[string]string,
	parallelism int,
) (
	files []config.KubesprayFile,
	images []string,
	officialImages []string,
	scriptSHA256 string,
	resultErr error,
) {
	offlineRoot := filepath.Join(resolved.Checkout, "contrib", "offline")
	scriptPath := filepath.Join(offlineRoot, "generate_list.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"read Kubespray official offline script: %w",
			err,
		)
	}
	scriptSHA256 = config.SHA256(script)
	tempRoot := filepath.Join(offlineRoot, "temp")
	downloadRoot := filepath.Join(offlineRoot, "offline-files")
	downloadArchive := filepath.Join(offlineRoot, "offline-files.tar.gz")
	transientPlaybook := filepath.Join(resolved.Checkout, "generate_list.yml")
	if err := removeKubesprayGeneratedOutput(
		service.root,
		resolved.Checkout,
		tempRoot,
		downloadRoot,
		downloadArchive,
		transientPlaybook,
	); err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"clean interrupted Kubespray offline workflow: %w",
			err,
		)
	}
	defer func() {
		cleanupErr := removeKubesprayGeneratedOutput(
			service.root, resolved.Checkout, tempRoot, downloadRoot,
			downloadArchive, transientPlaybook,
		)
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	invocationParent := filepath.Join(
		".atum", "invocations", "kubespray-offline",
	)
	invocationParentPath, err := fssecure.EnsureDirectory(
		service.root, invocationParent, 0o700,
	)
	if err != nil {
		return nil, nil, nil, "", err
	}
	invocationPath, err := os.MkdirTemp(invocationParentPath, "generate-list-")
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"create Kubespray offline invocation directory: %w", err,
		)
	}
	invocationRelative, err := fssecure.Relative(filepath.Join(
		invocationParent,
		filepath.Base(invocationPath),
	))
	if err != nil {
		return nil, nil, nil, "", errors.Join(
			err,
			fssecure.RemoveTree(service.root, filepath.Join(
				invocationParent,
				filepath.Base(invocationPath),
			)),
		)
	}
	invocationPresent := true
	cleanupInvocation := func() error {
		if !invocationPresent {
			return nil
		}
		cleanupErr := fssecure.RemoveTree(service.root, invocationRelative)
		if cleanupErr == nil {
			invocationPresent = false
		}
		return cleanupErr
	}
	defer func() {
		resultErr = errors.Join(resultErr, cleanupInvocation())
	}()
	vars := kubesprayOfflineVars{
		KubernetesVersion:         strings.TrimPrefix(kubernetesVersion, "v"),
		GCRImageRepo:              "gcr.io",
		KubeImageRepo:             "registry.k8s.io",
		KubeadmImageRepo:          "registry.k8s.io",
		DockerImageRepo:           "docker.io",
		QuayImageRepo:             "quay.io",
		GitHubImageRepo:           "ghcr.io",
		CiliumImageTag:            runtimeTags["cilium_image_tag"],
		CiliumHubbleEnvoyImageTag: runtimeTags["cilium_hubble_envoy_image_tag"],
		CiliumOperatorImageTag:    runtimeTags["cilium_operator_image_tag"],
	}
	varsData, err := json.Marshal(vars)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("encode Kubespray offline variables: %w", err)
	}
	varsData = append(varsData, '\n')
	varsRelative := filepath.Join(invocationRelative, "upstream-vars.json")
	if err := fssecure.WriteRegular(
		service.root, varsRelative, varsData, 0o600,
	); err != nil {
		return nil, nil, nil, "", err
	}
	groupVars := []string{
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "all", "all.yml"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "all", "containerd.yml"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "k8s_cluster", "addons.yml"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "k8s_cluster", "k8s-cluster.yml"),
	}
	groupVarPaths := make([]string, len(groupVars))
	for index := range groupVars {
		groupVarPaths[index], err = fssecure.Resolve(
			service.root, groupVars[index], false,
		)
		if err != nil {
			return nil, nil, nil, "", fmt.Errorf(
				"resolve Kubespray inventory variables %s: %w",
				groupVars[index], err,
			)
		}
	}
	varsPath, err := fssecure.Resolve(service.root, varsRelative, false)
	if err != nil {
		return nil, nil, nil, "", err
	}
	progress.Start(
		ctx, progress.Platform, "kubespray-artifacts", "Kubespray artifacts",
		"running the pinned official offline workflow",
	)
	arguments := make([]string, 0, 2+len(groupVarPaths)*2)
	for _, path := range groupVarPaths {
		arguments = append(arguments, "--extra-vars", "@"+path)
	}
	arguments = append(arguments, "--extra-vars", "@"+varsPath)
	ansibleBin, err := fssecure.Resolve(
		service.root,
		filepath.Join(
			".atum", "cache", "tools", "kubespray",
			resolved.Source.Commit, "venv", "bin",
		),
		false,
	)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"resolve exact Kubespray toolchain for offline discovery: %w",
			err,
		)
	}
	if err := service.runner.Run(ctx, process.Command{
		Name: scriptPath,
		Args: arguments,
		Dir:  resolved.Checkout,
		Env: []string{
			"PATH=" + ansibleBin + string(os.PathListSeparator) +
				os.Getenv("PATH"),
			"ANSIBLE_INVENTORY_UNPARSED_WARNING=False",
			"ANSIBLE_LOCALHOST_WARNING=False",
		},
		Activity: progress.Target{
			Phase: progress.Platform, ID: "kubespray-offline",
			Label: "Kubespray offline discovery",
		},
	}); err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"run Kubespray official offline discovery: %w", err,
		)
	}
	if err := cleanupInvocation(); err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"remove Kubespray offline invocation input: %w", err,
		)
	}
	fileSources, _, err := readKubesprayList(
		filepath.Join(tempRoot, "files.list"), false,
	)
	if err != nil {
		return nil, nil, nil, "", err
	}
	variables, err := readKubesprayFileVariables(
		filepath.Join(
			resolved.Checkout,
			"roles", "kubespray_defaults", "defaults", "main", "download.yml",
		),
	)
	if err != nil {
		return nil, nil, nil, "", err
	}
	if len(variables) != len(fileSources) {
		return nil, nil, nil, "", fmt.Errorf(
			"Kubespray official file template produced %d variables and %d sources",
			len(variables), len(fileSources),
		)
	}
	discovered := make([]discoveredKubesprayFile, len(fileSources))
	seenVariables := make(map[string]struct{}, len(fileSources))
	seenSources := make(map[string]struct{}, len(fileSources))
	seenLocalPaths := make(map[string]struct{}, len(fileSources))
	for index, source := range fileSources {
		localPath, err := kubesprayOfflinePath(source)
		if err != nil {
			return nil, nil, nil, "", err
		}
		variable := variables[index]
		if _, duplicate := seenVariables[variable]; duplicate {
			return nil, nil, nil, "", fmt.Errorf(
				"Kubespray offline variable %s is duplicated", variable,
			)
		}
		if _, duplicate := seenSources[source]; duplicate {
			return nil, nil, nil, "", fmt.Errorf(
				"Kubespray offline source %s is duplicated", source,
			)
		}
		if _, duplicate := seenLocalPaths[localPath]; duplicate {
			return nil, nil, nil, "", fmt.Errorf(
				"Kubespray offline path %s is ambiguous", localPath,
			)
		}
		seenVariables[variable] = struct{}{}
		seenSources[source] = struct{}{}
		seenLocalPaths[localPath] = struct{}{}
		discovered[index] = discoveredKubesprayFile{
			variable: variable, source: source, localPath: localPath,
		}
	}
	images, officialImages, err = readKubesprayList(
		filepath.Join(tempRoot, "images.list"), true,
	)
	if err != nil {
		return nil, nil, nil, "", err
	}
	sort.Strings(images)
	images = compactSorted(images)
	archiveRelative, err := filepath.Rel(service.root, downloadArchive)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"resolve Kubespray transient archive path: %w", err,
		)
	}
	if err := fssecure.WriteRegular(
		service.root, archiveRelative, []byte{}, 0o600,
	); err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"prepare Kubespray transient archive: %w", err,
		)
	}
	if err := service.runner.Run(ctx, process.Command{
		Name: filepath.Join(offlineRoot, "manage-offline-files.sh"),
		Dir:  offlineRoot,
		Env: []string{
			"FILES_LIST=" + filepath.Join(tempRoot, "files.list"),
			"NO_HTTP_SERVER=1",
		},
		Activity: progress.Target{
			Phase: progress.Platform, ID: "kubespray-offline",
			Label: "Kubespray offline acquisition",
		},
	}); err != nil {
		return nil, nil, nil, "", fmt.Errorf(
			"run Kubespray official offline acquisition: %w", err,
		)
	}
	files, err = acquireKubesprayFiles(
		ctx, service.root, downloadRoot, discovered,
		config.EffectiveWorkLimit(
			parallelism, desired.Updates.Parallelism, config.DefaultWorkLimit,
		),
	)
	if err != nil {
		return nil, nil, nil, "", err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Variable < files[j].Variable
	})
	progress.Update(
		ctx, progress.Platform, "kubespray-artifacts", "Kubespray artifacts",
		fmt.Sprintf(
			"%d files acquired and %d images discovered",
			len(files), len(images),
		),
		0, len(images),
	)
	return files, images, officialImages, scriptSHA256, nil
}

func readKubesprayList(path string, imageList bool) ([]string, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open Kubespray offline list %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, kubesprayListLimit+1))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	entries := make([]string, 0, 64)
	official := make([]string, 0, 64)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" {
			continue
		}
		if strings.ContainsAny(entry, " \t\r\x00") {
			return nil, nil, fmt.Errorf(
				"Kubespray offline list contains invalid entry %q", entry,
			)
		}
		official = append(official, entry)
		if imageList {
			if strings.Contains(entry, "@") {
				return nil, nil, fmt.Errorf(
					"Kubespray image %s does not retain its upstream tag", entry,
				)
			}
			reference, err := name.ParseReference(entry)
			if _, tagged := reference.(name.Tag); err != nil || !tagged {
				return nil, nil, fmt.Errorf(
					"Kubespray offline list contains invalid image %q", entry,
				)
			}
			entry = reference.Name()
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read Kubespray offline list %s: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > kubesprayListLimit {
		return nil, nil, fmt.Errorf(
			"Kubespray offline list exceeds %d bytes", kubesprayListLimit,
		)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("Kubespray offline list %s is empty", path)
	}
	return entries, official, nil
}

func readKubesprayFileVariables(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > kubesprayListLimit {
		return nil, fmt.Errorf(
			"Kubespray download defaults are empty or exceed %d bytes",
			kubesprayListLimit,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, kubesprayListLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > kubesprayListLimit {
		return nil, fmt.Errorf(
			"Kubespray download defaults exceed %d bytes",
			kubesprayListLimit,
		)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode Kubespray download defaults: %w", err)
	}
	if len(document.Content) != 1 ||
		document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New(
			"Kubespray download defaults are not one YAML mapping",
		)
	}
	mapping := document.Content[0]
	variables := make([]string, 0, len(mapping.Content)/2)
	seen := make(map[string]struct{}, cap(variables))
	for index := 0; index < len(mapping.Content); index += 2 {
		key := mapping.Content[index]
		if key.Kind != yaml.ScalarNode ||
			!strings.HasSuffix(key.Value, "_download_url") {
			continue
		}
		if !validKubesprayURLVariable(key.Value) {
			return nil, fmt.Errorf(
				"Kubespray offline URL variable %q is invalid", key.Value,
			)
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return nil, fmt.Errorf(
				"Kubespray offline URL variable %q is duplicated", key.Value,
			)
		}
		seen[key.Value] = struct{}{}
		variables = append(variables, key.Value)
	}
	if len(variables) == 0 {
		return nil, errors.New(
			"Kubespray download defaults define no offline URL variables",
		)
	}
	return variables, nil
}

func validKubesprayURLVariable(value string) bool {
	if !strings.HasSuffix(value, "_url") || len(value) <= len("_url") {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			index > 0 && character >= '0' && character <= '9' ||
			index > 0 && character == '_' {
			continue
		}
		return false
	}
	return true
}

func kubesprayOfflinePath(source string) (string, error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf(
			"Kubespray offline source %q is not a supported immutable HTTPS path",
			source,
		)
	}
	path := filepath.ToSlash(filepath.Clean(parsed.Path))
	path = strings.TrimPrefix(path, "/")
	if path == "" || path == "." || path == ".." ||
		strings.HasPrefix(path, "../") {
		return "", fmt.Errorf(
			"Kubespray offline source %q has no safe path", source,
		)
	}
	return parsed.Host + "/" + path, nil
}

func acquireKubesprayFiles(
	ctx context.Context,
	root, downloadRoot string,
	discovered []discoveredKubesprayFile,
	parallelism int,
) ([]config.KubesprayFile, error) {
	result := make([]config.KubesprayFile, len(discovered))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism, 0, config.DefaultWorkLimit,
	))
	var completed atomic.Int64
	for index := range discovered {
		index := index
		group.Go(func() error {
			record := discovered[index]
			sourcePath := filepath.Join(
				downloadRoot, filepath.FromSlash(record.localPath),
			)
			info, err := os.Lstat(sourcePath)
			if err != nil {
				return fmt.Errorf(
					"inspect Kubespray offline file %s: %w", record.source, err,
				)
			}
			if !info.Mode().IsRegular() || info.Size() <= 0 {
				return fmt.Errorf(
					"Kubespray offline file %s is not a non-empty regular file",
					record.source,
				)
			}
			input, err := os.Open(sourcePath)
			if err != nil {
				return err
			}
			hash := sha256.New()
			size, readErr := io.Copy(hash, input)
			closeErr := input.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if size != info.Size() {
				return fmt.Errorf(
					"Kubespray offline file %s changed while hashing",
					record.source,
				)
			}
			digest := hex.EncodeToString(hash.Sum(nil))
			cacheRelative := filepath.ToSlash(filepath.Join(
				".atum", "cache", "kubespray-offline", "sha256", digest,
			))
			if err := retainKubesprayFile(
				root, sourcePath, cacheRelative, digest, size,
			); err != nil {
				return err
			}
			result[index] = config.KubesprayFile{
				Variable: record.variable, Source: record.source,
				LocalPath: record.localPath, CacheFile: cacheRelative,
				SHA256: digest, Size: size,
			}
			progress.Update(
				groupContext, progress.Platform, "kubespray-artifacts",
				"Kubespray artifacts", "content-pinned "+record.variable,
				int(completed.Add(1)), len(discovered),
			)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return result, nil
}

func retainKubesprayFile(
	root, sourcePath, cacheRelative, expectedSHA string, expectedSize int64,
) error {
	existing, err := fssecure.OpenRegular(root, cacheRelative)
	if err == nil {
		valid, verifyErr := verifyKubesprayFile(
			existing, expectedSHA, expectedSize,
		)
		if verifyErr != nil {
			return verifyErr
		}
		if !valid {
			return fmt.Errorf(
				"content-addressed Kubespray file %s is corrupt",
				cacheRelative,
			)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	written, err := fssecure.WriteRegularFrom(
		root, cacheRelative, source, 0o600,
	)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf(
			"retained Kubespray file %s is %d bytes, want %d",
			cacheRelative, written, expectedSize,
		)
	}
	retained, err := fssecure.OpenRegular(root, cacheRelative)
	if err != nil {
		return err
	}
	valid, err := verifyKubesprayFile(retained, expectedSHA, expectedSize)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf(
			"retained Kubespray file %s changed during publication",
			cacheRelative,
		)
	}
	return nil
}

func verifyKubesprayFile(
	file *os.File,
	expectedSHA string,
	expectedSize int64,
) (bool, error) {
	hash := sha256.New()
	size, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	return size == expectedSize &&
		hex.EncodeToString(hash.Sum(nil)) == expectedSHA, nil
}

func sanitizeKubesprayImageID(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	builder.Grow(min(len(value), 32))
	separator := false
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if valid {
			if separator && builder.Len() != 0 {
				builder.WriteByte('-')
			}
			builder.WriteRune(character)
			separator = false
			continue
		}
		separator = true
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "image"
	}
	if len(result) > 32 {
		return strings.TrimRight(result[:32], "-")
	}
	return result
}

func removeKubesprayGeneratedOutput(
	root, checkout string,
	paths ...string,
) error {
	var result error
	for _, path := range paths {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if path == checkout || !strings.HasPrefix(
			filepath.Clean(path),
			filepath.Clean(checkout)+string(filepath.Separator),
		) {
			result = errors.Join(result, fmt.Errorf(
				"refuse to remove Kubespray path outside its exact checkout: %s",
				path,
			))
			continue
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if info.IsDir() {
			err = fssecure.RemoveTree(root, relative)
		} else if info.Mode().IsRegular() {
			err = fssecure.RemoveRegular(root, relative)
		} else {
			err = fmt.Errorf(
				"Kubespray generated output %s has unsafe type", path,
			)
		}
		result = errors.Join(result, err)
	}
	return result
}

func kubesprayRegistryValues(desired config.Document) (map[string]any, error) {
	selected, repositories, targetHost, err := kubesprayCanonicalImages(desired)
	if err != nil {
		return nil, err
	}
	registry := desired.Delivery.Registry
	if targetHost != registry.Host {
		return nil, fmt.Errorf(
			"Kubespray Harbor target host %s does not match %s",
			targetHost,
			registry.Host,
		)
	}
	scheme := "https://"
	if !registry.TLSVerify {
		scheme = "http://"
	}
	harborHost := scheme + targetHost
	mirrors := make([]any, 0, len(repositories)+1)
	mirrors = append(mirrors, map[string]any{
		"prefix": targetHost,
		"server": harborHost,
		"mirrors": []any{map[string]any{
			"host": harborHost, "capabilities": []any{"pull", "resolve"},
			"skip_verify": !registry.TLSVerify,
		}},
	})
	sources := make([]string, 0, len(repositories))
	for source := range repositories {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		target := repositories[source]
		targetURL := scheme + target
		mirrors = append(mirrors, map[string]any{
			"prefix": source,
			"server": targetURL,
			"mirrors": []any{map[string]any{
				"host": targetURL, "capabilities": []any{"pull", "resolve"},
				"skip_verify": !registry.TLSVerify, "override_path": true,
			}},
		})
	}
	expectedImages := make(map[string]struct{})
	for _, inventory := range desired.Delivery.Kubespray {
		for _, id := range inventory.Images {
			expectedImages[id] = struct{}{}
		}
	}
	if len(selected) != len(expectedImages) {
		return nil, errors.New("Kubespray canonical image graph is incomplete")
	}
	values := map[string]any{
		"containerd_registries_mirrors": mirrors,
	}
	for source, variable := range map[string]string{
		"gcr.io": "gcr_image_repo", "registry.k8s.io": "kube_image_repo",
		"index.docker.io": "docker_image_repo", "quay.io": "quay_image_repo",
		"ghcr.io": "github_image_repo",
	} {
		if target, found := repositories[source]; found {
			values[variable] = target
			if variable == "kube_image_repo" {
				values["kubeadm_image_repo"] = target
			}
		}
	}
	targetRelease, err := desired.Orchestration.TargetRelease()
	if err != nil {
		return nil, err
	}
	var targetInventory *config.KubesprayArtifactInventory
	for index := range desired.Delivery.Kubespray {
		inventory := &desired.Delivery.Kubespray[index]
		if inventory.KubernetesVersion != targetRelease.Kubernetes ||
			inventory.KubesprayCommit != targetRelease.Kubespray.Commit {
			continue
		}
		if targetInventory != nil {
			return nil, errors.New(
				"target Kubespray chart runtime inventory is duplicated",
			)
		}
		targetInventory = inventory
	}
	if targetInventory == nil {
		return nil, errors.New(
			"target Kubespray chart runtime inventory is absent",
		)
	}
	runtimeTags, err := kubesprayCiliumRuntimeTags(*targetInventory)
	if err != nil {
		return nil, err
	}
	for variable, tag := range runtimeTags {
		values[variable] = tag
	}
	return values, nil
}

func kubesprayCiliumRuntimeTags(
	inventory config.KubesprayArtifactInventory,
) (map[string]string, error) {
	tags := make(map[string]string, 3)
	for _, source := range inventory.RuntimeImages {
		if err := addKubesprayCiliumRuntimeTag(tags, source); err != nil {
			return nil, err
		}
	}
	return completeKubesprayCiliumRuntimeTags(tags)
}

func kubesprayCiliumRuntimeTagsFromImages(
	images []kubesprayRuntimeImage,
) (map[string]string, error) {
	tags := make(map[string]string, 3)
	for _, image := range images {
		if err := addKubesprayCiliumRuntimeTag(tags, image.source); err != nil {
			return nil, err
		}
	}
	return completeKubesprayCiliumRuntimeTags(tags)
}

func addKubesprayCiliumRuntimeTag(
	tags map[string]string,
	source string,
) error {
	reference, err := name.ParseReference(source)
	if err != nil {
		return fmt.Errorf(
			"parse Kubespray chart runtime image %s: %w",
			source,
			err,
		)
	}
	var variable string
	switch reference.Context().Name() {
	case "quay.io/cilium/cilium":
		variable = "cilium_image_tag"
	case "quay.io/cilium/cilium-envoy":
		variable = "cilium_hubble_envoy_image_tag"
	case "quay.io/cilium/operator-generic":
		variable = "cilium_operator_image_tag"
	default:
		return nil
	}
	if current, duplicate := tags[variable]; duplicate &&
		current != reference.Identifier() {
		return fmt.Errorf(
			"Kubespray chart runtime variable %s is ambiguous",
			variable,
		)
	}
	tags[variable] = reference.Identifier()
	return nil
}

func completeKubesprayCiliumRuntimeTags(
	tags map[string]string,
) (map[string]string, error) {
	if len(tags) != 3 {
		return nil, errors.New(
			"Kubespray Cilium chart runtime image graph is incomplete",
		)
	}
	return tags, nil
}

func kubesprayCanonicalImages(
	desired config.Document,
) (map[string]config.Image, map[string]string, string, error) {
	all := make(map[string]config.Image, len(desired.Delivery.Images))
	for _, image := range desired.Delivery.Images {
		if _, duplicate := all[image.ID]; duplicate {
			return nil, nil, "", fmt.Errorf("delivery image %s is duplicated", image.ID)
		}
		all[image.ID] = image
	}
	imageIDs := make(map[string]struct{})
	for _, inventory := range desired.Delivery.Kubespray {
		for _, id := range inventory.Images {
			imageIDs[id] = struct{}{}
		}
	}
	selected := make(map[string]config.Image, len(imageIDs))
	repositories := make(map[string]string)
	targetHost := ""
	for id := range imageIDs {
		image, found := all[id]
		if !found || image.Discovery != "kubespray" ||
			image.Delivery.Default.Type != "mirror" ||
			image.Delivery.Default.Source == "" ||
			image.Delivery.Default.Digest == "" {
			return nil, nil, "", fmt.Errorf(
				"Kubespray canonical image %s is missing or incomplete", id,
			)
		}
		if _, duplicate := selected[id]; duplicate {
			return nil, nil, "", fmt.Errorf(
				"Kubespray canonical image %s is duplicated", id,
			)
		}
		source, err := name.ParseReference(image.Delivery.Default.Source)
		if err != nil {
			return nil, nil, "", err
		}
		sourceRegistry := source.Context().RegistryStr()
		sourceRepository := source.Context().Name()
		target, err := name.ParseReference(image.Target)
		if err != nil {
			return nil, nil, "", err
		}
		if targetHost == "" {
			targetHost = target.Context().RegistryStr()
		} else if target.Context().RegistryStr() != targetHost {
			return nil, nil, "", fmt.Errorf(
				"Kubespray image %s targets a second registry %s",
				id,
				target.Context().RegistryStr(),
			)
		}
		targetRepository := target.Context().Name()
		suffix := "/" + sourceRepository
		if !strings.HasSuffix(targetRepository, suffix) {
			return nil, nil, "", fmt.Errorf(
				"Kubespray image %s target %s is not derived from %s",
				id, image.Target, image.Delivery.Default.Source,
			)
		}
		targetRoot := strings.TrimSuffix(targetRepository, suffix)
		if !strings.HasSuffix(targetRoot, "/kubespray") {
			return nil, nil, "", fmt.Errorf(
				"Kubespray image %s target %s has no canonical namespace",
				id,
				image.Target,
			)
		}
		targetRepository = targetRoot + "/" + sourceRegistry
		if existing, duplicate := repositories[sourceRegistry]; duplicate &&
			existing != targetRepository {
			return nil, nil, "", fmt.Errorf(
				"Kubespray source registry %s has ambiguous Harbor targets",
				sourceRegistry,
			)
		}
		repositories[sourceRegistry] = targetRepository
		selected[id] = image
	}
	if targetHost == "" {
		return nil, nil, "", errors.New("Kubespray canonical image graph is empty")
	}
	return selected, repositories, targetHost, nil
}
