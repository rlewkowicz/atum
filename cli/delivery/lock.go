package delivery

import (
	"fmt"
	"reflect"
	"sort"

	"atum/cli/config"
)

// matchesCommittedDelivery compares the updater-owned immutable selection
// while leaving compatibility-build output digests under local publication
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
	results map[string]config.LockedImage,
) (config.ImageLock, error) {
	if len(results) != len(project.Desired.Delivery.Images) {
		return config.ImageLock{}, fmt.Errorf(
			"canonical publication resolved %d images, want %d",
			len(results),
			len(project.Desired.Delivery.Images),
		)
	}
	images := make([]config.LockedImage, 0, len(project.Desired.Delivery.Images))
	for _, desired := range project.Desired.Delivery.Images {
		entry, found := results[desired.ID]
		if !found {
			return config.ImageLock{}, fmt.Errorf(
				"canonical publication has no result for image %s",
				desired.ID,
			)
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
