package delivery

import (
	"fmt"
	"sort"

	"atum/cli/config"
)

func resolveSelection(project *config.Project, graphSHA string) ([]selectedImage, error) {
	profile := project.Desired.Delivery.Policy.DefaultProfile
	if _, exists := project.Desired.Delivery.Profiles[profile]; !exists {
		return nil, fmt.Errorf("delivery profile %q is not defined", profile)
	}
	selected := make([]selectedImage, 0, len(project.Desired.Delivery.Images))
	for _, image := range project.Desired.Delivery.Images {
		resolved, err := config.ResolveDelivery(image, profile, graphSHA)
		if err != nil {
			return nil, fmt.Errorf("resolve delivery for %s: %w", image.ID, err)
		}
		inputSHA, err := project.Desired.ImageInputSHA256(image, resolved, graphSHA)
		if err != nil {
			return nil, fmt.Errorf("resolve input for %s: %w", image.ID, err)
		}
		selected = append(selected, selectedImage{Image: image, Delivery: resolved, InputSHA: inputSHA})
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("runtime image inventory is empty")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Image.ID < selected[j].Image.ID })
	return selected, nil
}

func partitionSelectedImages(selected []selectedImage) (mirrors, builds []selectedImage, err error) {
	mirrors = make([]selectedImage, 0, len(selected))
	builds = make([]selectedImage, 0, len(selected))
	for _, image := range selected {
		switch image.Delivery.Type {
		case "mirror":
			mirrors = append(mirrors, image)
		case "build":
			builds = append(builds, image)
		default:
			return nil, nil, fmt.Errorf("image %s uses unsupported delivery %q", image.Image.ID, image.Delivery.Type)
		}
	}
	return mirrors, builds, nil
}
