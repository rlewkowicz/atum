package delivery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"atum/cli/config"
	atumoci "atum/cli/oci"
	"atum/cli/progress"
	"atum/cli/secretvalue"
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
	if err := config.ValidateSourceSnapshot(project); err != nil {
		return PublishResult{}, fmt.Errorf("validate exact source handoff: %w", err)
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
	parallelism := effectiveParallelism(
		options.Parallelism, project.Desired.Updates.Parallelism,
	)
	options.Parallelism = parallelism
	ctx = withDeliveryBudget(ctx, parallelism)
	username := service.env("HARBOR_USERNAME")
	password := service.env("HARBOR_PASSWORD")
	if username == "" || password == "" {
		return PublishResult{}, fmt.Errorf("HARBOR_USERNAME and HARBOR_PASSWORD are required to publish images")
	}
	credentials := atumoci.Credentials{
		Username: username,
		Password: secretvalue.New([]byte(password)),
		CACert:   []byte(service.env("HARBOR_CA_CRT")),
	}
	password = ""
	defer credentials.Clear()
	registry, err := atumoci.NewClient(project.Desired.Delivery.Registry, credentials)
	if err != nil {
		return PublishResult{}, err
	}
	defer registry.Clear()

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
	progress.Update(ctx, progress.Platform, "image-publication", "Image publication",
		"publishing immutable image inventory", 0, len(selected))
	var completed atomic.Int64
	report := func(id string, reused bool) {
		detail := "published image " + id
		if reused {
			detail = "reused image " + id
		}
		current := int(completed.Add(1))
		progress.Update(ctx, progress.Platform, "image-publication", "Image publication",
			detail, current, len(selected))
	}
	var buildEntries []config.LockedImage
	var buildPublished, buildReused int
	group.Go(func() error {
		var buildErr error
		buildEntries, buildPublished, buildReused, buildErr = service.publishBuilds(
			groupContext, project, registry, builds, profile, graphSHA, options, current,
			report,
		)
		return buildErr
	})
	for _, image := range mirrors {
		image := image
		group.Go(func() error {
			return runDeliveryWorker(groupContext, func() error {
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
				report(entry.ID, wasReused)
				return nil
			})
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
	project.Lock.Delivery = imageLock
	project.ExecutionBundle = bundle
	if err := persistExecutionProject(project); err != nil {
		return PublishResult{}, err
	}
	return PublishResult{Lock: imageLock, Published: published, Reused: reused}, nil
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
