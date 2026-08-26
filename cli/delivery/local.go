package delivery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"atum/cli/config"
	atumoci "atum/cli/oci"
	"atum/cli/progress"

	"golang.org/x/sync/errgroup"
)

type localDelivery struct {
	builds  map[string]buildOutput
	mirrors map[string]mirrorOutput
	lock    config.ImageLock
}

// resolveLocalDelivery creates a complete delivery lock without depending on
// the target registry. Official images are verified at their exact source
// digest and source builds remain in content-addressed local OCI layouts for
// direct publication.
func (service *Service) resolveLocalDelivery(
	ctx context.Context,
	project *config.Project,
	options PublishOptions,
) (localDelivery, error) {
	profile := options.Profile
	if profile == "" {
		profile = project.Desired.Delivery.Policy.DefaultProfile
	}
	graphSHA, err := config.DeliveryGraphSHA256(project, profile)
	if err != nil {
		return localDelivery{}, fmt.Errorf("resolve delivery graph: %w", err)
	}
	selectionOptions := options
	selectionOptions.Group = "platform"
	selectionOptions.Targets = nil
	selected, selectedIDs, err := resolveSelection(project, selectionOptions, graphSHA)
	if err != nil {
		return localDelivery{}, err
	}
	if len(selectedIDs) != len(project.Desired.Delivery.Images) {
		return localDelivery{}, fmt.Errorf("publication requires the complete runtime image inventory")
	}
	registry, err := atumoci.NewClient(project.Desired.Delivery.Registry, atumoci.Credentials{})
	if err != nil {
		return localDelivery{}, err
	}
	defer registry.Clear()
	parallelism := effectiveParallelism(
		options.Parallelism, project.Desired.Updates.Parallelism,
	)
	options.Parallelism = parallelism
	ctx = withDeliveryBudget(ctx, parallelism)
	mirrors, builds, err := partitionSelectedImages(selected)
	if err != nil {
		return localDelivery{}, err
	}
	progress.Update(ctx, progress.Platform, "publication", "Publication inputs",
		fmt.Sprintf("verifying %d upstream images; building %d compatibility images", len(mirrors), len(builds)),
		0, len(selected))
	results := make(map[string]config.LockedImage, len(selected))
	var resultMu sync.Mutex
	var resolved atomic.Int64
	var buildOutputs map[string]buildOutput
	var buildEntries map[string]config.LockedImage
	mirrorOutputs := make(map[string]mirrorOutput, len(mirrors))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	group.Go(func() error {
		var buildErr error
		buildOutputs, buildEntries, _, _, buildErr = service.buildLocally(
			groupContext, project, builds, profile, graphSHA, options,
		)
		if buildErr == nil {
			current := int(resolved.Add(int64(len(buildEntries))))
			progress.Update(groupContext, progress.Platform, "publication", "Publication inputs",
				"compatibility images ready", current, len(selected))
		}
		return buildErr
	})
	for _, image := range mirrors {
		image := image
		group.Go(func() error {
			return runDeliveryWorker(groupContext, func() error {
				output, err := service.prepareMirrorOutput(groupContext, project, registry, image)
				if err != nil {
					return err
				}
				entry := config.LockedImage{
					ID: image.Image.ID, Target: image.Image.Target,
					Digest: image.Delivery.Digest, InputSHA256: image.InputSHA,
					Delivery: image.Delivery,
				}
				resultMu.Lock()
				results[entry.ID] = entry
				mirrorOutputs[entry.ID] = output
				resultMu.Unlock()
				current := int(resolved.Add(1))
				progress.Update(groupContext, progress.Platform, "publication", "Publication inputs",
					"verified upstream image "+entry.ID, current, len(selected))
				return nil
			})
		})
	}
	if err := group.Wait(); err != nil {
		return localDelivery{}, err
	}
	progress.Update(ctx, progress.Platform, "publication", "Publication inputs",
		"all runtime images resolved", len(selected), len(selected))
	for id, entry := range buildEntries {
		results[id] = entry
	}
	imageLock, err := assembleImageLock(project, profile, project.DeliverySHA256, graphSHA, selectedIDs, results)
	if err != nil {
		return localDelivery{}, err
	}
	return localDelivery{builds: buildOutputs, mirrors: mirrorOutputs, lock: imageLock}, nil
}
