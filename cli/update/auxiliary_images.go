package update

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"atum/cli/config"
)

type auxiliaryImageChange struct {
	Artifact string
	Added    []string
	Removed  []string
}

func approveAuxiliaryImages(desired *config.Document, approvals []string) error {
	for _, approval := range approvals {
		artifact, specification, found := strings.Cut(approval, "=")
		fields := strings.Split(specification, ",")
		if !found || len(fields) != 3 || !strings.HasPrefix(artifact, "chart/") {
			return fmt.Errorf(
				"auxiliary image approval %q must be chart/<id>=<image-id>,<license>,<official-reference>",
				approval,
			)
		}
		imageID := strings.TrimSpace(fields[0])
		license := strings.TrimSpace(fields[1])
		reference := strings.TrimSpace(fields[2])
		if imageID == "" || license == "" || !validImageReference(reference) {
			return fmt.Errorf("auxiliary image approval %q has an invalid identity or reference", approval)
		}
		chartID := strings.TrimPrefix(artifact, "chart/")
		chartExists := false
		for i := range desired.Platform.Charts {
			if desired.Platform.Charts[i].ID == chartID {
				chartExists = true
				break
			}
		}
		if !chartExists {
			return fmt.Errorf("auxiliary image approval %q names an untracked chart", approval)
		}
		repository := imageRepository(reference)
		if matches := mappedImageRepositories(desired.Delivery.Images, repository); len(matches) != 0 {
			return fmt.Errorf(
				"auxiliary image approval %q repository is already owned by %d delivery entries",
				approval, len(matches),
			)
		}
		for i := range desired.Delivery.Images {
			if desired.Delivery.Images[i].ID == imageID {
				return fmt.Errorf("auxiliary image approval %q duplicates delivery image ID %s", approval, imageID)
			}
		}
		tag := imageTag(reference)
		version := strings.TrimPrefix(tag, "v")
		target := desired.Delivery.Policy.RuntimeRegistryPrefix + imageID + ":" + tag
		officialReference := officialAuxiliaryImageReference(reference)
		desired.Delivery.Images = append(desired.Delivery.Images, config.Image{
			ID:          imageID,
			Family:      chartID,
			Version:     version,
			Target:      target,
			Scopes:      []string{"bigbang"},
			Runtime:     true,
			License:     license,
			Consumers:   []string{"Tracked chart " + chartID},
			BigBangRefs: []string{reference},
			Delivery: config.ImageDelivery{
				Default: config.DeliveryChoice{
					Type:   "mirror",
					Source: officialReference,
					Digest: "sha256:" + strings.Repeat("0", 64),
				},
			},
		})
	}
	return nil
}

func officialAuxiliaryImageReference(reference string) string {
	const (
		legacyKubebuilderRegistry  = "gcr.io/kubebuilder/"
		currentKubebuilderRegistry = "registry.k8s.io/kubebuilder/"
	)
	if strings.HasPrefix(reference, legacyKubebuilderRegistry) {
		return currentKubebuilderRegistry + strings.TrimPrefix(reference, legacyKubebuilderRegistry)
	}
	return reference
}

func reconcileDeliveryEvidence(desired *config.Document) {
	evidenceByID := make(map[string]string, len(desired.Delivery.RenderedBaseline.Entries))
	for i := range desired.Delivery.RenderedBaseline.Entries {
		entry := &desired.Delivery.RenderedBaseline.Entries[i]
		evidenceByID[entry.ImageID] = entry.Evidence
	}
	baseline := make([]config.RenderedBaselineEntry, len(desired.Delivery.Images))
	crosswalk := make([]config.LegacyCrosswalkEntry, len(desired.Delivery.Images))
	counts := config.ScopeCounts{Unique: len(desired.Delivery.Images)}
	deliveryCounts := config.DeliveryCounts{Total: len(desired.Delivery.Images)}
	compatibilityBuilds := make([]string, 0, len(desired.Delivery.Images))
	for i := range desired.Delivery.Images {
		image := &desired.Delivery.Images[i]
		for _, scope := range image.Scopes {
			switch scope {
			case "prep":
				counts.Prep++
			case "bigbang":
				counts.BigBang++
			}
		}
		evidence := evidenceByID[image.ID]
		if evidence == "" {
			evidence = "rendered"
		}
		baseline[i] = config.RenderedBaselineEntry{
			ImageID:  image.ID,
			Target:   image.Target,
			Scopes:   requiredStringArray(image.Scopes),
			Evidence: evidence,
		}
		entry := config.LegacyCrosswalkEntry{
			ImageID:         image.ID,
			Family:          image.Family,
			Scopes:          requiredStringArray(image.Scopes),
			Consumers:       requiredStringArray(image.Consumers),
			BigBangRefs:     requiredStringArray(image.BigBangRefs),
			Replacement:     image.Target,
			DefaultDelivery: image.Delivery.Default.Type,
		}
		switch image.Delivery.Default.Type {
		case "mirror":
			deliveryCounts.Mirrored++
			entry.OfficialSource = &config.OfficialSource{
				Reference: image.Delivery.Default.Source,
				Digest:    image.Delivery.Default.Digest,
			}
		case "build":
			deliveryCounts.Built++
			compatibilityBuilds = append(compatibilityBuilds, image.ID)
			entry.CompatibilityBuild = &config.CompatibilityBuild{
				BakeTarget: image.Delivery.Default.BakeTarget,
				Materials:  requiredStringArray(image.Delivery.Default.Materials),
			}
		}
		crosswalk[i] = entry
	}
	sort.Strings(compatibilityBuilds)
	desired.Delivery.RenderedBaseline.Counts = counts
	desired.Delivery.RenderedBaseline.Entries = baseline
	desired.Delivery.LegacyCrosswalk.DefaultCounts = deliveryCounts
	desired.Delivery.LegacyCrosswalk.CompatibilityBuilds = compatibilityBuilds
	desired.Delivery.LegacyCrosswalk.Entries = crosswalk
}

func requiredStringArray(values []string) []string {
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func projectTrackedChartAuxiliaryImages(
	currentGenerated map[string]any,
	candidateGenerated map[string]any,
	charts []resolvedTrackedChart,
	artifacts []chartArtifact,
	inspections []chartInspection,
	images []config.Image,
) ([]auxiliaryImageChange, error) {
	if len(artifacts) != len(inspections) {
		return nil, fmt.Errorf(
			"artifact count %d does not match inspection count %d",
			len(artifacts), len(inspections),
		)
	}
	inspectionByArtifact := make(map[string]chartInspection, len(artifacts))
	for i := range artifacts {
		inspectionByArtifact[artifacts[i].ID] = inspections[i]
	}
	changes := make([]auxiliaryImageChange, 0, len(charts))
	for i := range charts {
		artifact := "chart/" + charts[i].Chart.ID
		inspection, exists := inspectionByArtifact[artifact]
		if !exists {
			return nil, fmt.Errorf("selected tracked chart %s has no rendered inspection", artifact)
		}
		substitutions, err := trackedChartAuxiliarySubstitutions(artifact, inspection, images)
		if err != nil {
			return nil, err
		}
		current, err := generatedPostRendererImages(currentGenerated, charts[i].Chart.ValuesPath)
		if err != nil {
			return nil, fmt.Errorf("read current auxiliary images for %s: %w", artifact, err)
		}
		if err := setGeneratedPostRendererImages(
			candidateGenerated,
			charts[i].Chart.ValuesPath,
			substitutions,
		); err != nil {
			return nil, fmt.Errorf("project auxiliary images for %s: %w", artifact, err)
		}
		added, removed := auxiliaryImageDifference(current, substitutions)
		if len(added) != 0 || len(removed) != 0 {
			changes = append(changes, auxiliaryImageChange{
				Artifact: artifact,
				Added:    added,
				Removed:  removed,
			})
		}
	}
	return changes, nil
}

func trackedChartAuxiliarySubstitutions(
	artifact string,
	inspection chartInspection,
	images []config.Image,
) ([]map[string]any, error) {
	sourceImages := observedSourceImages(inspection)
	byRepository := make(map[string]map[string]any, len(sourceImages))
	for _, reference := range sourceImages {
		repository := imageRepository(reference)
		matches := mappedImages(images, reference)
		if len(matches) == 0 {
			matches = mappedImageRepositories(images, repository)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("%s renders unknown image repository %s", artifact, repository)
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf(
				"%s image repository %s maps ambiguously to %d delivery entries",
				artifact, repository, len(matches),
			)
		}
		image := images[matches[0]]
		if mapping := image.VersionMapping; mapping != nil && mapping.Artifact == artifact {
			continue
		}
		if reference == image.Target {
			continue
		}
		targetRepository := imageRepository(image.Target)
		targetTag := imageTag(image.Target)
		if targetRepository == "" || targetTag == "" {
			return nil, fmt.Errorf("%s delivery target %s is not tag-addressable", artifact, image.Target)
		}
		substitution := map[string]any{
			"name":    repository,
			"newName": targetRepository,
			"newTag":  targetTag,
		}
		if previous, exists := byRepository[repository]; exists &&
			!reflect.DeepEqual(previous, substitution) {
			return nil, fmt.Errorf(
				"%s renders conflicting auxiliary image identities for repository %s",
				artifact, repository,
			)
		}
		byRepository[repository] = substitution
	}
	repositories := make([]string, 0, len(byRepository))
	for repository := range byRepository {
		repositories = append(repositories, repository)
	}
	sort.Strings(repositories)
	result := make([]map[string]any, len(repositories))
	for i := range repositories {
		result[i] = byRepository[repositories[i]]
	}
	return result, nil
}

func generatedPostRendererImages(root map[string]any, valuesPath string) ([]map[string]any, error) {
	values, err := valuesAt(root, valuesPath)
	if err != nil {
		return nil, err
	}
	renderers, _ := values["postRenderers"].([]any)
	if len(renderers) == 0 {
		return nil, nil
	}
	renderer, _ := renderers[0].(map[string]any)
	kustomize, _ := renderer["kustomize"].(map[string]any)
	raw, _ := kustomize["images"].([]any)
	result := make([]map[string]any, 0, len(raw))
	for i := range raw {
		image, ok := raw[i].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("postRenderer image %d is not a map", i)
		}
		result = append(result, cloneMap(image))
	}
	return result, nil
}

func setGeneratedPostRendererImages(
	root map[string]any,
	valuesPath string,
	images []map[string]any,
) error {
	values, err := valuesAt(root, valuesPath)
	if err != nil {
		return err
	}
	renderers, _ := values["postRenderers"].([]any)
	if len(renderers) == 0 {
		renderers = []any{map[string]any{"kustomize": map[string]any{}}}
		values["postRenderers"] = renderers
	}
	renderer, ok := renderers[0].(map[string]any)
	if !ok {
		return fmt.Errorf("postRenderer 0 is not a map")
	}
	kustomize, ok := renderer["kustomize"].(map[string]any)
	if !ok {
		return fmt.Errorf("postRenderer 0 has no kustomize configuration")
	}
	if len(images) == 0 {
		delete(kustomize, "images")
		return nil
	}
	raw := make([]any, len(images))
	for i := range images {
		raw[i] = cloneMap(images[i])
	}
	kustomize["images"] = raw
	return nil
}

func auxiliaryImageDifference(
	current []map[string]any,
	candidate []map[string]any,
) ([]string, []string) {
	currentSet := auxiliaryImageSet(current)
	candidateSet := auxiliaryImageSet(candidate)
	added := make([]string, 0, len(candidateSet))
	removed := make([]string, 0, len(currentSet))
	for value := range candidateSet {
		if _, exists := currentSet[value]; !exists {
			added = append(added, value)
		}
	}
	for value := range currentSet {
		if _, exists := candidateSet[value]; !exists {
			removed = append(removed, value)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func auxiliaryImageSet(images []map[string]any) map[string]struct{} {
	result := make(map[string]struct{}, len(images))
	for i := range images {
		name, _ := images[i]["name"].(string)
		newName, _ := images[i]["newName"].(string)
		newTag, _ := images[i]["newTag"].(string)
		result[name+" -> "+strings.TrimSuffix(newName, ":")+":"+newTag] = struct{}{}
	}
	return result
}
