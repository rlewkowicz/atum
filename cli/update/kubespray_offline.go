package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitcache"
	"atum/cli/kubespray"
	"atum/cli/process"
	"atum/cli/progress"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/errgroup"
)

const (
	kubesprayListLimit = 16 << 20
	kubesprayFileLimit = 1 << 30
)

type kubespraySourceOverrides struct {
	GCRImageRepo     string `json:"gcr_image_repo"`
	KubeImageRepo    string `json:"kube_image_repo"`
	KubeadmImageRepo string `json:"kubeadm_image_repo"`
	DockerImageRepo  string `json:"docker_image_repo"`
	QuayImageRepo    string `json:"quay_image_repo"`
	GitHubImageRepo  string `json:"github_image_repo"`
}

type kubespraySelectionVars struct {
	KubernetesVersion string `json:"kube_version"`
	GCRImageRepo      string `json:"gcr_image_repo"`
	KubeImageRepo     string `json:"kube_image_repo"`
	KubeadmImageRepo  string `json:"kubeadm_image_repo"`
	DockerImageRepo   string `json:"docker_image_repo"`
	QuayImageRepo     string `json:"quay_image_repo"`
	GitHubImageRepo   string `json:"github_image_repo"`
	ProjectionPath    string `json:"atum_projection_path"`
	KubeadmTemplate   string `json:"atum_kubeadm_template"`
}

type discoveredKubesprayFile struct {
	id        string
	source    string
	localPath string
	checksum  string
}

type kubesprayReleaseArtifacts struct {
	inventory config.KubesprayArtifactInventory
	images    []config.Image
}

type kubesprayEvaluatedDownload struct {
	Enabled   bool     `json:"enabled"`
	File      bool     `json:"file"`
	Container bool     `json:"container"`
	Repo      *string  `json:"repo"`
	Tag       *string  `json:"tag"`
	URL       *string  `json:"url"`
	Checksum  *string  `json:"checksum"`
	Groups    []string `json:"groups"`
}

type kubespraySelectionProjection struct {
	Downloads     map[string]kubesprayEvaluatedDownload `json:"downloads"`
	KubeadmConfig string                                `json:"kubeadmConfig"`
}

func kubespraySelectionInputSHA256(
	kubernetesVersion string,
	kubesprayCommit string,
	inventoryData []byte,
	playbookData []byte,
	sourceOverrides kubespraySourceOverrides,
	kubeadmTemplateData []byte,
	groupVars map[string]string,
) (string, error) {
	selectionIdentity, err := config.CanonicalJSON(struct {
		KubernetesVersion     string                   `json:"kubernetesVersion"`
		KubesprayCommit       string                   `json:"kubesprayCommit"`
		InventorySHA256       string                   `json:"inventorySha256"`
		PlaybookSHA256        string                   `json:"playbookSha256"`
		SourceOverrides       kubespraySourceOverrides `json:"sourceOverrides"`
		KubeadmTemplateSHA256 string                   `json:"kubeadmTemplateSha256"`
		GroupVars             map[string]string        `json:"groupVars"`
	}{
		KubernetesVersion:     kubernetesVersion,
		KubesprayCommit:       kubesprayCommit,
		InventorySHA256:       config.SHA256(inventoryData),
		PlaybookSHA256:        config.SHA256(playbookData),
		SourceOverrides:       sourceOverrides,
		KubeadmTemplateSHA256: config.SHA256(kubeadmTemplateData),
		GroupVars:             groupVars,
	})
	if err != nil {
		return "", err
	}
	return config.SHA256(selectionIdentity), nil
}

func (service *Service) reconstructKubesprayReleaseArtifacts(
	ctx context.Context,
	desired *config.Document,
	releases []config.ClusterRelease,
	terminal resolvedGit,
	parallelism int,
	mirrorReceipts map[string]config.ImageMirrorReceipt,
	selectionFiles map[string][]byte,
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
				selectionFiles,
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
	selectionFiles map[string][]byte,
) (config.KubesprayArtifactInventory, error) {
	if desired == nil || resolved.Checkout == "" || resolved.Source.Commit == "" {
		return config.KubesprayArtifactInventory{}, errors.New(
			"exact Kubespray source is required for offline artifact discovery",
		)
	}
	files, sources, selectionInputSHA256, err :=
		service.runKubespraySelectionWorkflow(
			ctx, desired, resolved, kubernetesVersion, parallelism,
			selectionFiles,
		)
	if err != nil {
		return config.KubesprayArtifactInventory{}, err
	}
	if len(files) == 0 || len(sources) == 0 {
		return config.KubesprayArtifactInventory{}, errors.New(
			"Kubespray selected-runtime inventory is empty",
		)
	}
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
			imageID, err := config.KubesprayImageID(source)
			if err != nil {
				return fmt.Errorf("identify Kubespray image %s: %w", source, err)
			}
			digest := ""
			resolvedFromCache := false
			if receipt, found := mirrorReceipts[imageID]; found {
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
			if !resolvedFromCache {
				resolvedDigest, resolveErr := resolveImageDigest(groupContext, source)
				if resolveErr != nil {
					return fmt.Errorf(
						"resolve Kubespray image %s: %w",
						source,
						resolveErr,
					)
				}
				digest = resolvedDigest
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
					" / evaluated roles/kubespray_defaults and roles/download",
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
		InventoryScope:       config.KubespraySelectedRuntimeInventory,
		SelectionInputSHA256: selectionInputSHA256,
		Files:                files,
		Images:               imageIDs,
	}
	inventory.SelectedInventorySHA256, err =
		config.KubesprayInventorySHA256(inventory)
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

func (service *Service) runKubespraySelectionWorkflow(
	ctx context.Context,
	desired *config.Document,
	resolved resolvedGit,
	kubernetesVersion string,
	parallelism int,
	selectionFiles map[string][]byte,
) (
	files []config.KubesprayFile,
	images []string,
	selectionInputSHA256 string,
	resultErr error,
) {
	invocationParent := filepath.Join(
		".atum", "invocations", "kubespray-selection",
	)
	invocationParentPath, err := fssecure.EnsureDirectory(
		service.root, invocationParent, 0o700,
	)
	if err != nil {
		return nil, nil, "", err
	}
	invocationPath, err := os.MkdirTemp(invocationParentPath, "evaluate-")
	if err != nil {
		return nil, nil, "", fmt.Errorf(
			"create Kubespray selection invocation directory: %w", err,
		)
	}
	invocationRelative, err := fssecure.Relative(filepath.Join(
		invocationParent,
		filepath.Base(invocationPath),
	))
	if err != nil {
		return nil, nil, "", errors.Join(
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
	projectionRelative := filepath.Join(invocationRelative, "projection.json")
	projectionPath := filepath.Join(service.root, projectionRelative)
	kubeadmTemplate := filepath.Join(
		resolved.Checkout, "roles", "download", "templates",
		"kubeadm-images.yaml.j2",
	)
	sourceOverrides := kubespraySourceOverrides{
		GCRImageRepo:     "gcr.io",
		KubeImageRepo:    "registry.k8s.io",
		KubeadmImageRepo: "registry.k8s.io",
		DockerImageRepo:  "docker.io",
		QuayImageRepo:    "quay.io",
		GitHubImageRepo:  "ghcr.io",
	}
	vars := kubespraySelectionVars{
		KubernetesVersion: strings.TrimPrefix(kubernetesVersion, "v"),
		GCRImageRepo:      sourceOverrides.GCRImageRepo,
		KubeImageRepo:     sourceOverrides.KubeImageRepo,
		KubeadmImageRepo:  sourceOverrides.KubeadmImageRepo,
		DockerImageRepo:   sourceOverrides.DockerImageRepo,
		QuayImageRepo:     sourceOverrides.QuayImageRepo,
		GitHubImageRepo:   sourceOverrides.GitHubImageRepo,
		ProjectionPath:    projectionPath,
		KubeadmTemplate:   kubeadmTemplate,
	}
	varsData, err := json.Marshal(vars)
	if err != nil {
		return nil, nil, "", fmt.Errorf(
			"encode Kubespray selection variables: %w", err,
		)
	}
	varsData = append(varsData, '\n')
	varsRelative := filepath.Join(invocationRelative, "upstream-vars.json")
	if err := fssecure.WriteRegular(
		service.root, varsRelative, varsData, 0o600,
	); err != nil {
		return nil, nil, "", err
	}
	inventoryData := kubespray.SelectionInventory()
	inventoryRelative := filepath.Join(invocationRelative, "inventory.yml")
	if err := fssecure.WriteRegular(
		service.root, inventoryRelative, inventoryData, 0o600,
	); err != nil {
		return nil, nil, "", err
	}
	const projectionPlaybook = `---
- name: Evaluate exact selected Kubespray downloads
  hosts: all
  gather_facts: false
  become: false
  roles:
    - role: kubespray_defaults
      when: false
    - role: download
      when: false
  tasks:
    - name: Select enabled downloads applicable to this host
      ansible.builtin.set_fact:
        atum_selected_downloads: >-
          {{ atum_selected_downloads | default({})
             | combine({item.key: download_defaults | combine(item.value)}) }}
      loop: "{{ downloads | dict2items }}"
      when:
        - item.value.enabled | bool
        - group_names | intersect(item.value.groups) | length > 0

    - name: Write evaluated selected-runtime projection
      ansible.builtin.copy:
        dest: "{{ atum_projection_path }}"
        mode: "0600"
        content: >-
          {{ {'downloads': atum_selected_downloads | default({}),
              'kubeadmConfig': lookup('template', atum_kubeadm_template)}
             | to_json }}
`
	playbookRelative := filepath.Join(invocationRelative, "select.yml")
	if err := fssecure.WriteRegular(
		service.root, playbookRelative, []byte(projectionPlaybook), 0o600,
	); err != nil {
		return nil, nil, "", err
	}
	groupVars := config.KubespraySelectionGroupVarPaths(*desired)
	groupVarPaths := make([]string, len(groupVars))
	selectionInputs := make(map[string]string, len(groupVars))
	if _, err := fssecure.EnsureDirectory(
		service.root,
		filepath.Join(invocationRelative, "group-vars"),
		0o700,
	); err != nil {
		return nil, nil, "", fmt.Errorf(
			"create private Kubespray inventory variable directory: %w",
			err,
		)
	}
	for index := range groupVars {
		clean, cleanErr := fssecure.Relative(groupVars[index])
		if cleanErr != nil {
			return nil, nil, "", cleanErr
		}
		data, found := selectionFiles[filepath.Clean(clean)]
		if !found || len(data) == 0 {
			return nil, nil, "", fmt.Errorf(
				"snapshotted Kubespray inventory variables %s are absent",
				clean,
			)
		}
		copyRelative := filepath.Join(
			invocationRelative,
			"group-vars",
			fmt.Sprintf("%d.yml", index),
		)
		if err := fssecure.WriteRegular(
			service.root, copyRelative, data, 0o600,
		); err != nil {
			return nil, nil, "", fmt.Errorf(
				"write private Kubespray inventory variables %s: %w",
				clean, err,
			)
		}
		groupVarPaths[index], err = fssecure.Resolve(
			service.root, copyRelative, false,
		)
		if err != nil {
			return nil, nil, "", fmt.Errorf(
				"resolve private Kubespray inventory variables %s: %w",
				clean, err,
			)
		}
		selectionInputs[filepath.ToSlash(clean)] = config.SHA256(data)
	}
	varsPath, err := fssecure.Resolve(service.root, varsRelative, false)
	if err != nil {
		return nil, nil, "", err
	}
	inventoryPath, err := fssecure.Resolve(service.root, inventoryRelative, false)
	if err != nil {
		return nil, nil, "", err
	}
	playbookPath, err := fssecure.Resolve(service.root, playbookRelative, false)
	if err != nil {
		return nil, nil, "", err
	}
	kubeadmTemplateData, err := os.ReadFile(kubeadmTemplate)
	if err != nil {
		return nil, nil, "", fmt.Errorf(
			"read pinned Kubespray kubeadm image template: %w", err,
		)
	}
	selectionInputSHA256, err = kubespraySelectionInputSHA256(
		kubernetesVersion,
		resolved.Source.Commit,
		inventoryData,
		[]byte(projectionPlaybook),
		sourceOverrides,
		kubeadmTemplateData,
		selectionInputs,
	)
	if err != nil {
		return nil, nil, "", fmt.Errorf(
			"identify Kubespray selection inputs: %w", err,
		)
	}
	progress.Start(
		ctx, progress.Platform, "kubespray-artifacts", "Kubespray artifacts",
		"evaluating the pinned selected-runtime downloads",
	)
	arguments := make([]string, 0, 5+len(groupVarPaths)*2)
	arguments = append(arguments, "-i", inventoryPath, playbookPath)
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
		return nil, nil, "", fmt.Errorf(
			"resolve exact Kubespray toolchain for selection: %w",
			err,
		)
	}
	if err := service.runner.Run(ctx, process.Command{
		Name: filepath.Join(ansibleBin, "ansible-playbook"),
		Args: arguments,
		Dir:  resolved.Checkout,
		Env: []string{
			"PATH=" + ansibleBin + string(os.PathListSeparator) +
				os.Getenv("PATH"),
		},
		Activity: progress.Target{
			Phase: progress.Platform, ID: "kubespray-offline",
			Label: "Kubespray selected-runtime discovery",
		},
	}); err != nil {
		return nil, nil, "", fmt.Errorf(
			"evaluate Kubespray selected-runtime downloads: %w", err,
		)
	}
	projectionData, err := os.ReadFile(projectionPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf(
			"read Kubespray selected-runtime projection: %w", err,
		)
	}
	if int64(len(projectionData)) > kubesprayListLimit {
		return nil, nil, "", fmt.Errorf(
			"Kubespray selected-runtime projection exceeds %d bytes",
			kubesprayListLimit,
		)
	}
	var projection kubespraySelectionProjection
	if err := json.Unmarshal(projectionData, &projection); err != nil {
		return nil, nil, "", fmt.Errorf(
			"decode Kubespray selected-runtime projection: %w", err,
		)
	}
	discoveredFiles, selectedImages, err :=
		selectKubesprayDownloads(projection.Downloads)
	if err != nil {
		return nil, nil, "", err
	}
	files, acquired, err := service.acquireKubesprayFiles(
		ctx, invocationRelative, discoveredFiles,
		config.EffectiveWorkLimit(
			parallelism, desired.Updates.Parallelism, config.DefaultWorkLimit,
		),
	)
	if err != nil {
		return nil, nil, "", err
	}
	kubeadmPath, found := acquired["kubeadm"]
	if !found {
		return nil, nil, "", errors.New(
			"Kubespray selected files omit the required kubeadm binary",
		)
	}
	kubeadmImages, err := service.kubeadmSelectedImages(
		ctx, invocationRelative, kubeadmPath, projection.KubeadmConfig,
	)
	if err != nil {
		return nil, nil, "", err
	}
	images, err = mergeKubespraySelectedImages(selectedImages, kubeadmImages)
	if err != nil {
		return nil, nil, "", err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].ID < files[j].ID
	})
	progress.Update(
		ctx, progress.Platform, "kubespray-artifacts", "Kubespray artifacts",
		fmt.Sprintf(
			"%d files acquired and %d images discovered",
			len(files), len(images),
		),
		0, len(images),
	)
	return files, images, selectionInputSHA256, nil
}

func selectKubesprayDownloads(
	downloads map[string]kubesprayEvaluatedDownload,
) ([]discoveredKubesprayFile, []string, error) {
	if len(downloads) == 0 {
		return nil, nil, errors.New("Kubespray evaluated downloads are empty")
	}
	localGroups := kubespray.LocalNodeGroups()
	selectedGroups := make(map[string]struct{}, len(localGroups))
	for _, group := range localGroups {
		selectedGroups[group] = struct{}{}
	}
	ids := make([]string, 0, len(downloads))
	for id := range downloads {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	files := make([]discoveredKubesprayFile, 0, len(ids))
	images := make([]string, 0, len(ids))
	seenSources := make(map[string]string, len(ids))
	seenPaths := make(map[string]string, len(ids))
	for _, id := range ids {
		download := downloads[id]
		if !download.Enabled || !kubesprayGroupsIntersect(
			download.Groups, selectedGroups,
		) {
			continue
		}
		if !config.ValidKubesprayDownloadID(id) {
			return nil, nil, fmt.Errorf(
				"Kubespray selected download id %q is invalid", id,
			)
		}
		if download.File == download.Container {
			return nil, nil, fmt.Errorf(
				"Kubespray selected download %s must be exactly one file or container",
				id,
			)
		}
		if download.File {
			source := stringValue(download.URL)
			checksum := normalizeKubesprayChecksum(
				stringValue(download.Checksum),
			)
			if source == "" || checksum == "" {
				return nil, nil, fmt.Errorf(
					"Kubespray selected file %s has no URL or SHA-256 checksum",
					id,
				)
			}
			repositoryPath, err := config.KubesprayFileRepositoryPath(source)
			if err != nil {
				return nil, nil, err
			}
			if previous, duplicate := seenSources[source]; duplicate {
				return nil, nil, fmt.Errorf(
					"Kubespray selected source %s is duplicated by %s and %s",
					source, previous, id,
				)
			}
			if previous, duplicate := seenPaths[repositoryPath]; duplicate {
				return nil, nil, fmt.Errorf(
					"Kubespray repository path %s is ambiguous for %s and %s",
					repositoryPath, previous, id,
				)
			}
			seenSources[source] = id
			seenPaths[repositoryPath] = id
			files = append(files, discoveredKubesprayFile{
				id: id, source: source, localPath: repositoryPath,
				checksum: checksum,
			})
			continue
		}
		source := stringValue(download.Repo) + ":" + stringValue(download.Tag)
		reference, err := name.ParseReference(source)
		if _, tagged := reference.(name.Tag); err != nil || !tagged ||
			strings.Contains(source, "@") {
			return nil, nil, fmt.Errorf(
				"Kubespray selected image %s has invalid source %q",
				id, source,
			)
		}
		source = reference.Name()
		if previous, duplicate := seenSources[source]; duplicate {
			return nil, nil, fmt.Errorf(
				"Kubespray selected source %s is duplicated by %s and %s",
				source, previous, id,
			)
		}
		seenSources[source] = id
		images = append(images, source)
	}
	return files, images, nil
}

func kubesprayGroupsIntersect(
	groups []string,
	selected map[string]struct{},
) bool {
	for _, group := range groups {
		if _, found := selected[group]; found {
			return true
		}
	}
	return false
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func normalizeKubesprayChecksum(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	if len(value) != sha256.Size*2 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return strings.ToLower(value)
}

func (service *Service) kubeadmSelectedImages(
	ctx context.Context,
	invocationRelative, kubeadmPath, kubeadmConfig string,
) ([]string, error) {
	if strings.TrimSpace(kubeadmConfig) == "" {
		return nil, errors.New("Kubespray kubeadm image configuration is empty")
	}
	configRelative := filepath.Join(invocationRelative, "kubeadm-images.yaml")
	if err := fssecure.WriteRegular(
		service.root, configRelative, []byte(kubeadmConfig), 0o600,
	); err != nil {
		return nil, err
	}
	configPath, err := fssecure.Resolve(service.root, configRelative, false)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	if err := service.runner.Run(ctx, process.Command{
		Name: kubeadmPath,
		Args: []string{
			"config", "images", "list", "--config=" + configPath,
		},
		Dir:    service.root,
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		return nil, fmt.Errorf(
			"derive Kubespray kubeadm images: %w: %s",
			err, strings.TrimSpace(stderr.String()),
		)
	}
	lines := strings.Split(stdout.String(), "\n")
	images := make([]string, 0, len(lines))
	for _, line := range lines {
		source := strings.TrimSpace(line)
		if source == "" ||
			strings.Contains(source, "coredns") ||
			strings.Contains(source, "pause") {
			continue
		}
		reference, err := name.ParseReference(source)
		if _, tagged := reference.(name.Tag); err != nil || !tagged ||
			strings.Contains(source, "@") {
			return nil, fmt.Errorf(
				"kubeadm returned invalid selected image %q", source,
			)
		}
		images = append(images, reference.Name())
	}
	if len(images) == 0 {
		return nil, errors.New("kubeadm returned no selected control-plane images")
	}
	sort.Strings(images)
	for index := 1; index < len(images); index++ {
		if images[index-1] == images[index] {
			return nil, fmt.Errorf(
				"kubeadm selected image %s more than once", images[index],
			)
		}
	}
	return images, nil
}

func mergeKubespraySelectedImages(groups ...[]string) ([]string, error) {
	count := 0
	for _, group := range groups {
		count += len(group)
	}
	images := make([]string, 0, count)
	for _, group := range groups {
		images = append(images, group...)
	}
	sort.Strings(images)
	for index := 1; index < len(images); index++ {
		if images[index-1] == images[index] {
			return nil, fmt.Errorf(
				"Kubespray selected image source %s is duplicated",
				images[index],
			)
		}
	}
	return images, nil
}

func (service *Service) acquireKubesprayFiles(
	ctx context.Context,
	invocationRelative string,
	discovered []discoveredKubesprayFile,
	parallelism int,
) ([]config.KubesprayFile, map[string]string, error) {
	if _, err := fssecure.EnsureDirectory(
		service.root,
		filepath.Join(invocationRelative, "downloads"),
		0o700,
	); err != nil {
		return nil, nil, fmt.Errorf(
			"create Kubespray selected file directory: %w", err,
		)
	}
	result := make([]config.KubesprayFile, len(discovered))
	acquired := make(map[string]string, len(discovered))
	var acquiredMu sync.Mutex
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism, 0, config.DefaultWorkLimit,
	))
	var completed atomic.Int64
	for index := range discovered {
		index := index
		group.Go(func() error {
			record := discovered[index]
			sourceRelative := filepath.Join(
				invocationRelative, "downloads", record.id,
			)
			var size int64
			hash := sha256.New()
			err := fssecure.CreateRegularWith(
				service.root, sourceRelative, 0o700,
				func(destination io.Writer) error {
					counter := &countingWriter{writer: destination}
					if err := service.charts.copyHTTPS(
						groupContext,
						record.source,
						io.MultiWriter(counter, hash),
						kubesprayFileLimit,
					); err != nil {
						return err
					}
					size = counter.written
					return nil
				},
			)
			if err != nil {
				return fmt.Errorf("acquire Kubespray file %s: %w", record.id, err)
			}
			if size <= 0 {
				return fmt.Errorf("Kubespray file %s is empty", record.id)
			}
			digest := hex.EncodeToString(hash.Sum(nil))
			if digest != record.checksum {
				return fmt.Errorf(
					"Kubespray file %s has SHA-256 %s, want %s",
					record.id, digest, record.checksum,
				)
			}
			sourcePath, err := fssecure.Resolve(
				service.root, sourceRelative, false,
			)
			if err != nil {
				return err
			}
			cacheRelative := filepath.ToSlash(filepath.Join(
				".atum", "cache", "kubespray-offline", "sha256", digest,
			))
			if err := retainKubesprayFile(
				service.root, sourcePath, cacheRelative, digest, size,
			); err != nil {
				return err
			}
			result[index] = config.KubesprayFile{
				ID: record.id, Source: record.source,
				RepositoryPath: record.localPath, CacheFile: cacheRelative,
				SHA256: digest, Size: size,
			}
			acquiredMu.Lock()
			acquired[record.id] = sourcePath
			acquiredMu.Unlock()
			progress.Update(
				groupContext, progress.Platform, "kubespray-artifacts",
				"Kubespray artifacts", "content-pinned "+record.id,
				int(completed.Add(1)), len(discovered),
			)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, nil, err
	}
	return result, acquired, nil
}

type countingWriter struct {
	writer  io.Writer
	written int64
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	written, err := writer.writer.Write(data)
	writer.written += int64(written)
	return written, err
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
	return values, nil
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
