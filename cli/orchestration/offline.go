package orchestration

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"atum/cli/config"
	"atum/cli/delivery"
	atumoci "atum/cli/oci"

	"golang.org/x/sync/errgroup"
)

func (service Service) kubesprayHandoffInputs(
	ctx context.Context,
	toolchain Toolchain,
) (map[string]any, error) {
	var inventory *config.KubesprayArtifactInventory
	for index := range service.Project.Desired.Delivery.Kubespray {
		candidate := &service.Project.Desired.Delivery.Kubespray[index]
		if candidate.KubernetesVersion != toolchain.Release.Kubernetes ||
			candidate.KubesprayCommit != toolchain.Release.Kubespray.Commit {
			continue
		}
		if inventory != nil {
			return nil, fmt.Errorf(
				"Kubespray artifact inventory %s/%s is duplicated",
				candidate.KubernetesVersion,
				candidate.KubesprayCommit,
			)
		}
		inventory = candidate
	}
	if inventory == nil {
		return nil, fmt.Errorf(
			"Kubespray artifact inventory is absent for %s/%s",
			toolchain.Release.Kubernetes,
			toolchain.Release.Kubespray.Commit,
		)
	}
	receipt, err := delivery.LoadReceipt(service.Project)
	if err != nil {
		return nil, fmt.Errorf(
			"load required publication receipt: %w",
			err,
		)
	}
	publishedImages, err := validatePublishedKubesprayImages(
		*inventory,
		service.Project.Desired.Delivery.Images,
		receipt.Delivery,
	)
	if err != nil {
		return nil, err
	}
	if err := verifyLiveKubesprayImages(
		ctx,
		service.Project.Desired.Delivery.Registry,
		publishedImages,
		config.EffectiveWorkLimit(
			0,
			service.Project.Desired.Updates.Parallelism,
			config.DefaultWorkLimit,
		),
		service.RootCAPEM,
	); err != nil {
		return nil, err
	}
	variables, fileProjection, err := kubesprayFileRepositoryInputs(
		service.Project.Desired.Delivery.Seed.KubesprayFiles.URL,
		inventory.Files,
	)
	if err != nil {
		return nil, err
	}
	if err := delivery.ObserveKubesprayFileProjection(
		ctx,
		service.Project.Desired.Delivery.Seed.KubesprayFiles.URL,
		fileProjection,
		config.EffectiveWorkLimit(
			0,
			service.Project.Desired.Updates.Parallelism,
			config.DefaultWorkLimit,
		),
	); err != nil {
		return nil, err
	}
	registryVariables, err := config.KubesprayRegistryValues(
		service.Project.Desired,
	)
	if err != nil {
		return nil, err
	}
	for key, value := range registryVariables {
		if _, duplicate := variables[key]; duplicate {
			return nil, fmt.Errorf("managed Kubespray variable %s is duplicated", key)
		}
		variables[key] = value
	}
	// Each node uses Kubespray's checksum-enforcing get_url path directly.
	variables["download_container"] = true
	variables["download_force_cache"] = false
	variables["download_localhost"] = false
	variables["download_run_once"] = false
	return variables, nil
}

func kubesprayFileRepositoryInputs(
	endpoint string,
	files []config.KubesprayFile,
) (map[string]any, delivery.KubesprayFileProjection, error) {
	endpoint = strings.TrimSuffix(endpoint, "/")
	variables := map[string]any{"files_repo": endpoint}
	for _, file := range files {
		repositoryPath, variable, err := config.KubesprayFileRepository(
			file.Source,
		)
		if err != nil || repositoryPath != file.RepositoryPath {
			return nil, delivery.KubesprayFileProjection{}, fmt.Errorf(
				"Kubespray file %s has an invalid repository path",
				file.ID,
			)
		}
		domain, path, found := strings.Cut(repositoryPath, "/")
		if !found || variable == "" || path == "" {
			return nil, delivery.KubesprayFileProjection{}, fmt.Errorf(
				"Kubespray file %s is not beneath a documented files_repo domain root",
				file.ID,
			)
		}
		root := endpoint + "/" + domain
		if existing, set := variables[variable]; set && existing != root {
			return nil, delivery.KubesprayFileProjection{}, fmt.Errorf(
				"Kubespray files_repo variable %s is ambiguous",
				variable,
			)
		}
		variables[variable] = root
	}
	projection, err := delivery.SelectedKubesprayFileProjection(files)
	if err != nil {
		return nil, delivery.KubesprayFileProjection{}, err
	}
	return variables, projection, nil
}

func validatePublishedKubesprayImages(
	inventory config.KubesprayArtifactInventory,
	desired []config.Image,
	lock config.ImageLock,
) ([]config.LockedImage, error) {
	desiredByID := make(map[string]config.Image, len(desired))
	for _, image := range desired {
		if _, duplicate := desiredByID[image.ID]; duplicate {
			return nil, fmt.Errorf("desired image %s is duplicated", image.ID)
		}
		desiredByID[image.ID] = image
	}
	lockedByID := make(map[string]config.LockedImage, len(lock.Images))
	for _, image := range lock.Images {
		if _, duplicate := lockedByID[image.ID]; duplicate {
			return nil, fmt.Errorf("published image %s is duplicated", image.ID)
		}
		lockedByID[image.ID] = image
	}
	selected := make([]config.LockedImage, 0, len(inventory.Images))
	selectedIDs := make(map[string]struct{}, len(inventory.Images))
	selectedTargets := make(map[string]string, len(inventory.Images))
	for _, id := range inventory.Images {
		if _, duplicate := selectedIDs[id]; duplicate {
			return nil, fmt.Errorf("Kubespray image %s is selected more than once", id)
		}
		selectedIDs[id] = struct{}{}
		wanted, found := desiredByID[id]
		if !found {
			return nil, fmt.Errorf("Kubespray image %s is absent from desired state", id)
		}
		published, found := lockedByID[id]
		if !found ||
			published.Target != wanted.Target ||
			published.Digest != wanted.Delivery.Default.Digest ||
			published.Delivery.Type != "mirror" ||
			published.Delivery.Source != wanted.Delivery.Default.Source {
			return nil, fmt.Errorf(
				"Kubespray image %s is not published at its exact Harbor target",
				id,
			)
		}
		if current, duplicate := selectedTargets[published.Target]; duplicate {
			return nil, fmt.Errorf(
				"Kubespray images %s and %s share Harbor target %s",
				current,
				id,
				published.Target,
			)
		}
		selectedTargets[published.Target] = id
		selected = append(selected, published)
	}
	return selected, nil
}

func verifyLiveKubesprayImages(
	ctx context.Context,
	registry config.Registry,
	images []config.LockedImage,
	parallelism int,
	rootCAPEM []byte,
) error {
	if len(images) == 0 {
		return errors.New("Kubespray has no receipt-bound Harbor images")
	}
	client, err := atumoci.NewClient(registry, atumoci.Credentials{
		CACert: rootCAPEM,
	})
	if err != nil {
		return fmt.Errorf("open Harbor observer for Kubespray admission: %w", err)
	}
	defer client.Clear()
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism,
		0,
		config.DefaultWorkLimit,
	))
	for index := range images {
		image := images[index]
		group.Go(func() error {
			descriptor, err := client.Resolve(groupContext, image.Target)
			if err != nil {
				return fmt.Errorf(
					"resolve required Kubespray image %s from Harbor: %w",
					image.ID,
					err,
				)
			}
			if descriptor.Digest.String() != image.Digest {
				return fmt.Errorf(
					"Kubespray image %s resolves to %s, want receipt digest %s",
					image.ID,
					descriptor.Digest,
					image.Digest,
				)
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return fmt.Errorf("verify live Kubespray Harbor admission: %w", err)
	}
	return nil
}
