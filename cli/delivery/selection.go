package delivery

import (
	"fmt"
	"sort"
	"strings"

	"atum/cli/config"
)

func resolveSelection(project *config.Project, options PublishOptions, graphSHA string) ([]selectedImage, map[string]struct{}, error) {
	profile := options.Profile
	if profile == "" {
		profile = project.Desired.Delivery.Policy.DefaultProfile
	}
	if _, exists := project.Desired.Delivery.Profiles[profile]; !exists {
		return nil, nil, fmt.Errorf("delivery profile %q is not defined", profile)
	}
	group := options.Group
	if group == "" {
		group = defaultGroup
	}
	wanted := make(map[string]struct{}, len(options.Targets))
	for _, item := range options.Targets {
		for _, id := range strings.Split(item, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				wanted[id] = struct{}{}
			}
		}
	}
	if len(wanted) == 0 && group != "all" && group != "platform" && group != "prep" && group != "bigbang" && group != "build-system" {
		return nil, nil, fmt.Errorf("unsupported image group %q", group)
	}
	selected := make([]selectedImage, 0, len(project.Desired.Delivery.Images))
	found := make(map[string]struct{}, len(wanted))
	for _, image := range project.Desired.Delivery.Images {
		if !image.Runtime {
			continue
		}
		include := len(wanted) == 0 && (group == "all" || group == "platform" || contains(image.Scopes, group))
		if _, exists := wanted[image.ID]; exists {
			include = true
			found[image.ID] = struct{}{}
		}
		if !include {
			continue
		}
		resolved, err := config.ResolveDelivery(image, profile, graphSHA)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve delivery for %s: %w", image.ID, err)
		}
		inputSHA, err := project.Desired.ImageInputSHA256(image, resolved, graphSHA)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve input for %s: %w", image.ID, err)
		}
		selected = append(selected, selectedImage{Image: image, Delivery: resolved, InputSHA: inputSHA})
	}
	for id := range wanted {
		if _, exists := found[id]; !exists {
			return nil, nil, fmt.Errorf("selected image %q is absent from the runtime inventory", id)
		}
	}
	if len(selected) == 0 {
		return nil, nil, fmt.Errorf("image selection is empty")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Image.ID < selected[j].Image.ID })
	selectedIDs := make(map[string]struct{}, len(selected))
	for _, image := range selected {
		selectedIDs[image.Image.ID] = struct{}{}
	}
	return selected, selectedIDs, nil
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

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
