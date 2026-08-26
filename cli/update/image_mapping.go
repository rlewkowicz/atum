package update

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"atum/cli/config"

	"golang.org/x/sync/errgroup"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
)

type imageReplacement struct {
	Old string
	New string
}

func imageTargetsByID(images []config.Image) map[string]string {
	targets := make(map[string]string, len(images))
	for _, image := range images {
		targets[image.ID] = image.Target
	}
	return targets
}

func projectOperatorImage(tree *candidateTree, images []config.Image) error {
	target := ""
	for _, image := range images {
		if image.ID == "atum-operator" {
			target = image.Target
			break
		}
	}
	if target == "" {
		return errors.New("delivery inventory has no atum-operator image")
	}
	const relative = "platform/apps/atum-operator/deployment.yaml"
	current, err := tree.YAML(relative)
	if err != nil {
		return fmt.Errorf("read Atum operator deployment: %w", err)
	}
	candidate := cloneMap(current)
	spec, ok := candidate["spec"].(map[string]any)
	if !ok { return errors.New("Atum operator deployment has no spec") }
	template, ok := spec["template"].(map[string]any)
	if !ok { return errors.New("Atum operator deployment has no pod template") }
	pod, ok := template["spec"].(map[string]any)
	if !ok { return errors.New("Atum operator deployment has no pod spec") }
	containers, ok := pod["containers"].([]any)
	if !ok || len(containers) != 1 { return errors.New("Atum operator deployment must have exactly one container") }
	container, ok := containers[0].(map[string]any)
	if !ok || container["name"] != "manager" { return errors.New("Atum operator manager container is invalid") }
	container["image"] = target
	return setCandidateYAML(tree, relative, current, candidate)
}

func imageTargetReplacements(
	previous map[string]string,
	images []config.Image,
) ([]imageReplacement, error) {
	replacements := make([]imageReplacement, 0, len(images))
	for _, image := range images {
		oldTarget, existed := previous[image.ID]
		if !existed || oldTarget == image.Target {
			continue
		}
		replacements = append(replacements, imageReplacement{
			Old: oldTarget,
			New: image.Target,
		})
	}
	return compactReplacements(replacements)
}

func renderedImageTargetReplacements(
	images []config.Image,
) ([]imageReplacement, error) {
	replacements := make([]imageReplacement, 0, len(images))
	for _, image := range images {
		for _, reference := range image.BigBangRefs {
			if reference == image.Target {
				continue
			}
			replacements = append(replacements, imageReplacement{
				Old: reference,
				New: image.Target,
			})
		}
	}
	return compactReplacements(replacements)
}

func reconcileBootstrapImageVersions(
	desired *config.Document,
	lock *config.Lock,
	charts []resolvedBootstrapChart,
) ([]imageReplacement, error) {
	indices := make(map[string]int, len(desired.Delivery.Images))
	for i := range desired.Delivery.Images {
		indices[desired.Delivery.Images[i].ID] = i
	}
	lockedIndices := lockedImageIndices(lock)
	var replacements []imageReplacement
	for i := range charts {
		chart := &charts[i]
		loaded, err := loader.Load(chart.ArchivePath)
		if err != nil {
			return nil, fmt.Errorf("load bootstrap chart %s image bindings: %w", chart.Chart.ID, err)
		}
		if loaded.Metadata == nil {
			return nil, fmt.Errorf("bootstrap chart %s has no metadata", chart.Chart.ID)
		}
		for _, binding := range chart.Chart.ImageBindings {
			index, exists := indices[binding.ID]
			if !exists {
				return nil, fmt.Errorf("bootstrap chart %s references missing bound image %s", chart.Chart.ID, binding.ID)
			}
			image := &desired.Delivery.Images[index]
			if image.Delivery.Default.Type != "mirror" {
				return nil, fmt.Errorf("bootstrap image %s must use only its official mirror", image.ID)
			}
			newSource, tag, version, err := bootstrapImageSource(loaded.Values, loaded.Metadata.AppVersion, binding)
			if err != nil {
				return nil, fmt.Errorf("resolve bootstrap image %s: %w", image.ID, err)
			}
			oldTarget := image.Target
			newTarget, err := replaceImageTag(oldTarget, tag)
			if err != nil {
				return nil, fmt.Errorf("update bootstrap target %s: %w", image.ID, err)
			}
			image.Version = version
			image.Target = newTarget
			image.Delivery.Default.Source = newSource
			updateLockedTarget(
				lock,
				lockedIndices,
				image.ID,
				oldTarget,
				newTarget,
				newSource,
				"",
			)
			if oldTarget != newTarget {
				replacements = append(replacements, imageReplacement{Old: oldTarget, New: newTarget})
			}
		}
	}
	return replacements, nil
}

func bootstrapImageSource(values map[string]any, appVersion string, binding config.ChartImageBinding) (string, string, string, error) {
	image, err := valuesAt(values, binding.ValuesPath)
	if err != nil {
		return "", "", "", err
	}
	repository, _ := image["repository"].(string)
	registry, _ := image["registry"].(string)
	if binding.ImageRepository != "" {
		repository = binding.ImageRepository
		registry = ""
	} else if repository == "" {
		name, _ := image["name"].(string)
		imageRegistry, _ := values["imageRegistry"].(string)
		imageNamespace, _ := values["imageNamespace"].(string)
		if name == "" || imageRegistry == "" || imageNamespace == "" {
			return "", "", "", fmt.Errorf("values path %s has no complete image repository", binding.ValuesPath)
		}
		repository = strings.TrimSuffix(imageRegistry, "/") + "/" + strings.Trim(imageNamespace, "/") + "/" + strings.TrimPrefix(name, "/")
	} else if registry != "" {
		repository = strings.TrimSuffix(registry, "/") + "/" + strings.TrimPrefix(repository, "/")
	}
	tag, _ := image["tag"].(string)
	if tag == "" {
		tag = appVersion
	}
	if binding.TagSuffix != "" && !strings.HasSuffix(tag, binding.TagSuffix) {
		tag += binding.TagSuffix
	}
	reference := repository + ":" + tag
	if !validImageReference(reference) {
		return "", "", "", fmt.Errorf("values path %s resolves invalid image %q", binding.ValuesPath, reference)
	}
	version := strings.TrimPrefix(strings.TrimSuffix(tag, binding.TagSuffix), "v")
	if version == "" {
		return "", "", "", fmt.Errorf("values path %s resolves an empty version", binding.ValuesPath)
	}
	return imageRepository(reference) + ":" + tag, tag, version, nil
}

func refreshMirrorDigests(
	ctx context.Context,
	parallelism int,
	current *config.Document,
	desired *config.Document,
	lock *config.Lock,
) (bool, error) {
	type request struct {
		source string
		pinned string
	}
	type result struct {
		request request
		digests resolvedImageDigests
	}
	currentSources := make(map[string]config.DeliveryChoice, len(current.Delivery.Images))
	for i := range current.Delivery.Images {
		currentSources[current.Delivery.Images[i].ID] = current.Delivery.Images[i].Delivery.Default
	}
	byRequest := make(map[request][]int, len(desired.Delivery.Images))
	lockedIndices := lockedImageIndices(lock)
	changed := false
	for i := range desired.Delivery.Images {
		image := &desired.Delivery.Images[i]
		if image.Delivery.Default.Type != "mirror" {
			continue
		}
		for _, prefix := range desired.Delivery.Policy.ForbiddenArtifactPrefixes {
			if strings.HasPrefix(image.Delivery.Default.Source, prefix) {
				return false, fmt.Errorf("mirror %s uses forbidden source %s", image.ID, image.Delivery.Default.Source)
			}
		}
		if image.Delivery.Default.Digest != "" {
			previous := currentSources[image.ID]
			if previous.Source != image.Delivery.Default.Source ||
				previous.Digest != image.Delivery.Default.Digest {
				changed = true
			}
			updateLockedTarget(
				lock,
				lockedIndices,
				image.ID,
				image.Target,
				image.Target,
				image.Delivery.Default.Source,
				image.Delivery.Default.Digest,
			)
			continue
		}
		pinned := ""
		if previous, exists := currentSources[image.ID]; exists &&
			previous.Source == image.Delivery.Default.Source {
			pinned = previous.Digest
		}
		key := request{source: image.Delivery.Default.Source, pinned: pinned}
		byRequest[key] = append(byRequest[key], i)
	}
	requests := make([]request, 0, len(byRequest))
	for key := range byRequest {
		requests = append(requests, key)
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].source == requests[j].source {
			return requests[i].pinned < requests[j].pinned
		}
		return requests[i].source < requests[j].source
	})
	results := make([]result, len(requests))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for resultIndex, key := range requests {
		resultIndex, key := resultIndex, key
		group.Go(func() error {
			var digests resolvedImageDigests
			var err error
			if key.pinned == "" {
				digests, err = resolveImageDigests(groupContext, key.source)
			} else {
				digests, err = resolvePinnedImageDigests(
					groupContext, key.source, key.pinned)
			}
			if err != nil {
				return err
			}
			results[resultIndex] = result{request: key, digests: digests}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return false, err
	}
	for _, resolved := range results {
		digest, err := normalizedMirrorDigest(
			resolved.request.pinned, resolved.digests)
		if err != nil {
			return false, fmt.Errorf(
				"resolve pinned mirror %s: %w", resolved.request.source, err)
		}
		for _, index := range byRequest[resolved.request] {
			image := &desired.Delivery.Images[index]
			if image.Delivery.Default.Digest == digest {
				continue
			}
			changed = true
			image.Delivery.Default.Digest = digest
			updateLockedTarget(
				lock, lockedIndices, image.ID, image.Target, image.Target,
				image.Delivery.Default.Source, digest)
		}
	}
	return changed, nil
}

func normalizedMirrorDigest(
	pinned string,
	resolved resolvedImageDigests,
) (string, error) {
	if pinned != "" && resolved.tag != pinned {
		return "", fmt.Errorf(
			"resolved root %s does not match requested digest %s",
			resolved.tag, pinned)
	}
	return resolved.manifest, nil
}

func lockedImageIndices(lock *config.Lock) map[string]int {
	indices := make(map[string]int, len(lock.Delivery.Images))
	for index := range lock.Delivery.Images {
		indices[lock.Delivery.Images[index].ID] = index
	}
	return indices
}

func updateLockedTarget(
	lock *config.Lock,
	indices map[string]int,
	imageID,
	oldTarget,
	newTarget,
	source,
	digest string,
) {
	index, found := indices[imageID]
	if !found {
		return
	}
	image := &lock.Delivery.Images[index]
	if image.Target == oldTarget {
		image.Target = newTarget
	}
	if image.Delivery.Type == "mirror" {
		image.Delivery.Source = source
		if digest != "" {
			image.Delivery.Digest = digest
			image.Digest = digest
		}
	}
}

func resolveImageLock(desired *config.Document, lock *config.Lock) error {
	resolved := make([]config.LockedImage, 0, len(desired.Delivery.Images))
	for _, image := range desired.Delivery.Images {
		delivery, err := config.ResolveDelivery(
			image,
			lock.Delivery.Profile,
			lock.Delivery.GraphSHA256,
		)
		if err != nil {
			return fmt.Errorf("resolve image delivery %s: %w", image.ID, err)
		}
		inputSHA, err := desired.ImageInputSHA256(
			image,
			delivery,
			lock.Delivery.GraphSHA256,
		)
		if err != nil {
			return fmt.Errorf("resolve image input %s: %w", image.ID, err)
		}
		digest := ""
		if delivery.Type == "mirror" {
			digest = delivery.Digest
		}
		resolved = append(resolved, config.LockedImage{
			ID:          image.ID,
			Target:      image.Target,
			Digest:      digest,
			InputSHA256: inputSHA,
			Delivery:    delivery,
		})
	}
	lock.Delivery.Images = resolved
	return nil
}

func equivalentTag(left, right string) bool {
	return strings.TrimPrefix(left, "v") == strings.TrimPrefix(right, "v")
}

func matchTagStyle(template, value string) string {
	wantsPrefix := strings.HasPrefix(template, "v")
	value = strings.TrimPrefix(value, "v")
	if wantsPrefix {
		return "v" + value
	}
	return value
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func replaceImageReferences(value any, replacements []imageReplacement) error {
	if len(replacements) == 0 {
		return nil
	}
	byReference := make(map[string]string, len(replacements))
	byRepository := make(map[string][]imageReplacement, len(replacements))
	byHub := make(map[string][]imageReplacement, len(replacements))
	for _, replacement := range replacements {
		byReference[replacement.Old] = replacement.New
		repository := imageRepository(replacement.Old)
		byRepository[repository] = append(byRepository[repository], replacement)
		if separator := strings.LastIndexByte(repository, '/'); separator > 0 {
			hub := repository[:separator]
			byHub[hub] = append(byHub[hub], replacement)
		}
	}
	var replacementErr error
	var walk func(any)
	walk = func(current any) {
		if replacementErr != nil {
			return
		}
		switch typed := current.(type) {
		case map[string]any:
			for key, item := range typed {
				if text, ok := item.(string); ok {
					if replacement, exists := byReference[text]; exists {
						typed[key] = replacement
					} else if prefix, reference, embedded := embeddedImageReference(text); embedded {
						if replacement, exists := byReference[reference]; exists {
							typed[key] = prefix + replacement
						}
					}
				}
				walk(typed[key])
			}
			for _, repositoryKey := range [...]string{"repository", "repo", "image", "image_name", "newName"} {
				repository, ok := typed[repositoryKey].(string)
				if !ok {
					continue
				}
				candidates := byRepository[imageRepository(repository)]
				for _, registryKey := range [...]string{"registry", "defaultRegistry"} {
					registry, ok := typed[registryKey].(string)
					if !ok || registry == "" {
						continue
					}
					qualified := strings.TrimSuffix(registry, "/") + "/" + strings.TrimPrefix(repository, "/")
					qualifiedCandidates := byRepository[imageRepository(qualified)]
					if len(qualifiedCandidates) == 0 {
						continue
					}
					if len(candidates) == 0 {
						candidates = qualifiedCandidates
						continue
					}
					combined := make(
						[]imageReplacement,
						0,
						len(candidates)+len(qualifiedCandidates),
					)
					combined = append(combined, candidates...)
					candidates = append(combined, qualifiedCandidates...)
				}
				if len(candidates) == 0 {
					continue
				}
				for _, tagKey := range [...]string{"tag", "imageTag", "image_version", "newTag"} {
					tag, ok := typed[tagKey].(string)
					if !ok {
						continue
					}
					matched, err := matchingReplacementTag(tag, candidates)
					if err != nil {
						replacementErr = fmt.Errorf("image %s:%s: %w", repository, tag, err)
						return
					}
					if matched != "" {
						typed[tagKey] = matched
					}
				}
			}
			hub, hasHub := typed["hub"].(string)
			tag, hasTag := typed["tag"].(string)
			if hasHub && hasTag {
				matched, err := matchingReplacementTag(tag, byHub[imageRepository(hub)])
				if err != nil {
					replacementErr = fmt.Errorf("image hub %s:%s: %w", hub, tag, err)
					return
				}
				if matched != "" {
					typed["tag"] = matched
				}
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(value)
	return replacementErr
}

func matchingReplacementTag(tag string, candidates []imageReplacement) (string, error) {
	matched := ""
	for _, replacement := range candidates {
		if !equivalentTag(tag, imageTag(replacement.Old)) {
			continue
		}
		candidate := matchTagStyle(tag, imageTag(replacement.New))
		if matched != "" && matched != candidate {
			return "", errors.New("conflicting replacement tags")
		}
		matched = candidate
	}
	return matched, nil
}
