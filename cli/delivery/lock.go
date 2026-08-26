package delivery

import (
	"fmt"
	"reflect"
	"sort"

	"atum/cli/config"
)

func currentEntries(project *config.Project) map[string]config.LockedImage {
	entries := make(map[string]config.LockedImage, len(project.Lock.Delivery.Images))
	for _, entry := range project.Lock.Delivery.Images {
		entries[entry.ID] = entry
	}
	return entries
}

func reusableEntry(
	project *config.Project,
	profile string,
	selected selectedImage,
	entries map[string]config.LockedImage,
) (config.LockedImage, bool) {
	lock := project.Lock.Delivery
	if lock.Profile != profile {
		return config.LockedImage{}, false
	}
	entry, exists := entries[selected.Image.ID]
	if exists && entry.Target == selected.Image.Target &&
		entry.InputSHA256 == selected.InputSHA &&
		reflect.DeepEqual(entry.Delivery, selected.Delivery) {
		return entry, true
	}
	return config.LockedImage{}, false
}

func reusableBundle(project *config.Project, delivery config.ImageLock) (*config.Bundle, error) {
	if project.ExecutionBundle == nil || project.Lock.DesiredSHA256 != project.DesiredSHA256 ||
		!reflect.DeepEqual(delivery, project.Lock.Delivery) {
		return nil, nil
	}
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return nil, err
	}
	if sourceSHA != project.ExecutionBundle.AtumSourceSHA256 {
		return nil, nil
	}
	bundle := *project.ExecutionBundle
	return &bundle, nil
}

// matchesCommittedDelivery compares the updater-owned immutable selection
// while leaving compatibility-build output digests under execution-state
// ownership. Mirror digests remain immutable inputs and are compared exactly.
func matchesCommittedDelivery(reproduced, committed config.ImageLock) bool {
	if len(reproduced.Images) != len(committed.Images) {
		return false
	}
	immutable := reproduced
	immutable.Images = append([]config.LockedImage(nil), reproduced.Images...)
	for index := range committed.Images {
		if committed.Images[index].Delivery.Type != "build" {
			continue
		}
		if committed.Images[index].Digest != "" ||
			immutable.Images[index].Delivery.Type != "build" {
			return false
		}
		immutable.Images[index].Digest = ""
	}
	return reflect.DeepEqual(immutable, committed)
}

func assembleImageLock(
	project *config.Project,
	profile string,
	inventorySHA string,
	graphSHA string,
	selectedIDs map[string]struct{},
	results map[string]config.LockedImage,
) (config.ImageLock, error) {
	partial := len(selectedIDs) != len(project.Desired.Delivery.Images)
	if partial && (project.Lock.Delivery.Profile != profile ||
		project.Lock.Delivery.InventorySHA256 != inventorySHA ||
		project.Lock.Delivery.GraphSHA256 != graphSHA ||
		len(project.Lock.Delivery.Images) != len(project.Desired.Delivery.Images)) {
		return config.ImageLock{}, fmt.Errorf("partial publication requires a complete current %s image lock", profile)
	}
	images := make([]config.LockedImage, 0, len(project.Desired.Delivery.Images))
	old := currentEntries(project)
	for _, desired := range project.Desired.Delivery.Images {
		entry, published := results[desired.ID]
		if !published {
			if _, selected := selectedIDs[desired.ID]; selected {
				return config.ImageLock{}, fmt.Errorf("selected image %s has no publication result", desired.ID)
			}
			var exists bool
			entry, exists = old[desired.ID]
			if !exists {
				return config.ImageLock{}, fmt.Errorf("unselected image %s has no prior lock entry", desired.ID)
			}
		}
		images = append(images, entry)
	}
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
	for _, image := range images {
		switch image.Delivery.Type {
		case "mirror", "build":
		default:
			return config.ImageLock{}, fmt.Errorf("image %s has unsupported locked delivery %q", image.ID, image.Delivery.Type)
		}
	}
	return config.ImageLock{
		SchemaVersion:   "atum.dev/image-lock/v3",
		Profile:         profile,
		Platform:        project.Desired.Project.Platform,
		InventorySHA256: inventorySHA,
		GraphSHA256:     graphSHA,
		Images:          images,
	}, nil
}
