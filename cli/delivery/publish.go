package delivery

import (
	"context"
	"fmt"
	"sync"

	"atum/cli/config"
	atumoci "atum/cli/oci"
	"atum/cli/update"

	"golang.org/x/sync/errgroup"
)

func (service *Service) Publish(ctx context.Context, options PublishOptions) (PublishResult, error) {
	unlock, err := update.LockProject(ctx, service.root)
	if err != nil {
		return PublishResult{}, fmt.Errorf("lock project state: %w", err)
	}
	defer unlock()
	if err := update.RecoverLocked(service.root); err != nil {
		return PublishResult{}, fmt.Errorf("recover interrupted update: %w", err)
	}
	project, err := config.LoadWithOptions(service.root, config.LoadOptions{AllowStale: true})
	if err != nil {
		return PublishResult{}, err
	}
	return service.publishLocked(ctx, project, options)
}

func (service *Service) publishLocked(ctx context.Context, project *config.Project, options PublishOptions) (PublishResult, error) {
	profile := options.Profile
	if profile == "" {
		profile = project.Desired.Delivery.Policy.DefaultProfile
	}
	graphSHA, err := config.DeliveryGraphSHA256(project, profile)
	if err != nil {
		return PublishResult{}, fmt.Errorf("resolve delivery graph: %w", err)
	}
	selected, selectedIDs, err := resolveSelection(project, options, graphSHA)
	if err != nil {
		return PublishResult{}, err
	}
	if len(selectedIDs) != len(project.Desired.Delivery.Images) &&
		(project.Lock.Delivery.Profile != profile ||
			project.Lock.Delivery.InventorySHA256 != project.DeliverySHA256 ||
			project.Lock.Delivery.GraphSHA256 != graphSHA ||
			len(project.Lock.Delivery.Images) != len(project.Desired.Delivery.Images)) {
		return PublishResult{}, fmt.Errorf("partial publication requires a complete current %s image lock", profile)
	}
	if len(selectedIDs) != len(project.Desired.Delivery.Images) {
		if err := project.Validate(); err != nil {
			return PublishResult{}, fmt.Errorf("partial publication requires fully current project state: %w", err)
		}
	}
	parallelism := options.Parallelism
	if parallelism <= 0 {
		parallelism = project.Desired.Updates.Parallelism
	}
	if parallelism <= 0 {
		parallelism = defaultParallelism
	}
	username := service.env("HARBOR_USERNAME")
	password := service.env("HARBOR_PASSWORD")
	if username == "" || password == "" {
		return PublishResult{}, fmt.Errorf("HARBOR_USERNAME and HARBOR_PASSWORD are required to publish images")
	}
	credentials := atumoci.Credentials{
		Username: username,
		Password: password,
		CACert:   []byte(service.env("HARBOR_CA_CRT")),
	}
	registry, err := atumoci.NewClient(project.Desired.Delivery.Registry, credentials)
	if err != nil {
		return PublishResult{}, err
	}

	results := make(map[string]config.LockedImage, len(selected))
	current := currentEntries(project)
	var resultMu sync.Mutex
	published, reused := 0, 0
	mirrors, builds, err := partitionSelectedImages(selected)
	if err != nil {
		return PublishResult{}, err
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	var buildEntries []config.LockedImage
	var buildPublished, buildReused int
	group.Go(func() error {
		var buildErr error
		buildEntries, buildPublished, buildReused, buildErr = service.publishBuilds(
			groupContext, project, registry, builds, profile, graphSHA, options, current,
		)
		return buildErr
	})
	for _, image := range mirrors {
		image := image
		group.Go(func() error {
			locked, reusable := reusableEntry(project, profile, image, current)
			entry, wasReused, err := service.publishMirror(groupContext, registry, image, locked, reusable && !options.Force)
			if err != nil {
				return err
			}
			resultMu.Lock()
			results[entry.ID] = entry
			if wasReused {
				reused++
			} else {
				published++
			}
			resultMu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return PublishResult{}, err
	}
	for _, entry := range buildEntries {
		results[entry.ID] = entry
	}
	published += buildPublished
	reused += buildReused
	imageLock, err := assembleImageLock(project, profile, project.DeliverySHA256, graphSHA, selectedIDs, results)
	if err != nil {
		return PublishResult{}, err
	}
	bundle, err := reusableBundle(project, imageLock)
	if err != nil {
		return PublishResult{}, fmt.Errorf("identify reusable deployment bundle: %w", err)
	}
	changed, err := writeRootLock(project, imageLock, bundle)
	if err != nil {
		return PublishResult{}, err
	}
	return PublishResult{Lock: imageLock, Published: published, Reused: reused, LockChanged: changed}, nil
}

func (service *Service) publishMirror(
	ctx context.Context,
	registry *atumoci.Client,
	image selectedImage,
	locked config.LockedImage,
	reuse bool,
) (config.LockedImage, bool, error) {
	if reuse {
		if descriptor, err := registry.Resolve(ctx, image.Image.Target); err == nil && descriptor.Digest.String() == locked.Digest {
			if err := registry.ValidateLinuxAMD64(ctx, image.Image.Target, descriptor); err != nil {
				return config.LockedImage{}, false, err
			}
			service.logger.InfoContext(ctx, "reuse mirrored image", "image", image.Image.ID, "digest", descriptor.Digest)
			return locked, true, nil
		}
	}
	service.logger.InfoContext(ctx, "mirror official image", "image", image.Image.ID, "source", image.Delivery.Source)
	descriptor, err := registry.Mirror(ctx, image.Delivery.Source, image.Delivery.Digest, image.Image.Target)
	if err != nil {
		return config.LockedImage{}, false, err
	}
	if err := registry.ValidateLinuxAMD64(ctx, image.Image.Target, descriptor); err != nil {
		return config.LockedImage{}, false, err
	}
	resolved, err := registry.Resolve(ctx, image.Image.Target)
	if err != nil {
		return config.LockedImage{}, false, err
	}
	if resolved.Digest != descriptor.Digest {
		return config.LockedImage{}, false, fmt.Errorf(
			"published mirror %s resolved to %s, want %s", image.Image.ID, resolved.Digest, descriptor.Digest,
		)
	}
	return config.LockedImage{
		ID:          image.Image.ID,
		Target:      image.Image.Target,
		Digest:      descriptor.Digest.String(),
		InputSHA256: image.InputSHA,
		Delivery:    image.Delivery,
	}, false, nil
}
