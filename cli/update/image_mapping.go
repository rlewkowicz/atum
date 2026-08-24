package update

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/gitcache"

	"golang.org/x/sync/errgroup"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
)

type imageReplacement struct {
	Old string
	New string
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
			if image.Delivery.Default.Type != "mirror" || image.Delivery.FullBuildTarget != "" {
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
			updateEvidenceTargets(
				desired, image.ID,
				oldTarget, newTarget, newSource, "",
			)
			updateLockedTarget(lock, image.ID, oldTarget, newTarget, newSource, "")
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

func validateImageContract(
	desired *config.Document,
	artifact string,
	current chartInspection,
	candidate chartInspection,
	renderedImages map[string]struct{},
	allowContractChange bool,
) error {
	_, err := reconcileImageContract(nil, nil, nil, desired, nil, artifact, current, candidate, renderedImages, false, allowContractChange)
	return err
}

func reconcileImageContract(
	ctx context.Context,
	cache *gitcache.Manager,
	tree *candidateTree,
	desired *config.Document,
	lock *config.Lock,
	artifact string,
	current chartInspection,
	candidate chartInspection,
	renderedImages map[string]struct{},
	mutate bool,
	allowContractChange bool,
) ([]imageReplacement, error) {
	if reflect.DeepEqual(current, candidate) && !hasDirectChartAppVersionMapping(desired, artifact) {
		return nil, nil
	}
	currentImages, err := imagesByRepository(observedSourceImages(current))
	if err != nil {
		return nil, fmt.Errorf("inspect current images for %s: %w", artifact, err)
	}
	candidateImages, err := imagesByRepository(observedSourceImages(candidate))
	if err != nil {
		return nil, fmt.Errorf("inspect candidate images for %s: %w", artifact, err)
	}
	for repository, candidateReference := range candidateImages {
		if _, existed := currentImages[repository]; existed {
			continue
		}
		mapped := mappedImages(desired.Delivery.Images, candidateReference)
		if len(mapped) == 0 {
			return nil, fmt.Errorf("%s introduced unknown image repository %s", artifact, repository)
		}
		if len(mapped) > 1 {
			return nil, fmt.Errorf("%s introduced image %s with %d delivery mappings", artifact, candidateReference, len(mapped))
		}
		// An image may be absent from one package release while retaining an
		// exact, declared delivery mapping for releases on the other side of an
		// upgrade. Treat that known reference as an unchanged contract; unknown
		// repositories and tags still fail closed above.
		currentImages[repository] = candidateReference
	}
	if err := addMappedDeclaredImages(
		desired.Delivery.Images,
		artifact,
		current.Declared,
		candidate.Declared,
		renderedImages,
		currentImages,
		candidateImages,
	); err != nil {
		return nil, fmt.Errorf("inspect declared images for %s: %w", artifact, err)
	}

	var replacements []imageReplacement
	repositories := make([]string, 0, len(candidateImages))
	for repository := range candidateImages {
		repositories = append(repositories, repository)
	}
	sort.Strings(repositories)
	for _, repository := range repositories {
		oldReference := currentImages[repository]
		newReference := candidateImages[repository]
		if (strings.Contains(oldReference, "@") || strings.Contains(newReference, "@")) && oldReference != newReference {
			return nil, fmt.Errorf("%s changes digest-pinned image %s to %s; update requires explicit review", artifact, oldReference, newReference)
		}
		indices := mappedImages(desired.Delivery.Images, oldReference)
		if len(indices) == 0 {
			indices = mappedImages(desired.Delivery.Images, newReference)
		}
		if len(indices) == 0 {
			indices = mappedImageRepositories(desired.Delivery.Images, repository)
		}
		if len(indices) == 0 {
			return nil, fmt.Errorf("%s uses image %s without an explicit delivery mapping", artifact, oldReference)
		}
		if len(indices) > 1 {
			return nil, fmt.Errorf("%s image %s maps ambiguously to %d delivery entries", artifact, oldReference, len(indices))
		}
		index := indices[0]
		image := &desired.Delivery.Images[index]
		if image.VersionMapping != nil && image.VersionMapping.Artifact == artifact {
			replacement, changed, err := reconcileVersionMappedImage(
				ctx, cache, tree, desired, lock, image, current, candidate, oldReference, newReference, mutate,
			)
			if err != nil {
				return nil, fmt.Errorf("%s image %s: %w", artifact, image.ID, err)
			}
			if changed {
				replacements = append(replacements, replacement)
			}
			continue
		}
		oldTag := imageTag(oldReference)
		newTag := imageTag(newReference)
		officialTag := imageTag(image.Delivery.Default.Source)
		if equivalentTag(officialTag, newTag) {
			if mutate {
				recordBigBangReference(desired, image, oldReference, newReference)
			}
			continue
		}
		if !equivalentTag(officialTag, oldTag) && !mappedReferenceMatches(image.BigBangRefs, repository, officialTag) {
			if containsString(image.BigBangRefs, newReference) {
				continue
			}
			if allowContractChange {
				if mutate {
					recordBigBangReference(desired, image, oldReference, newReference)
				}
				continue
			}
			return nil, fmt.Errorf("%s image %s upstream tag %s does not map mechanically to official tag %s",
				artifact, image.ID, oldTag, officialTag)
		}
		if image.Delivery.FullBuildTarget != "" {
			return nil, fmt.Errorf("%s changes full-build image %s from %s to %s; publish the updated build graph before advancing its lock",
				artifact, image.ID, oldTag, newTag)
		}
		if image.Delivery.Default.Type != "mirror" {
			return nil, fmt.Errorf("%s changes compatibility-build image %s from %s to %s; update the build recipe explicitly",
				artifact, image.ID, oldTag, newTag)
		}
		newOfficialTag := matchTagStyle(officialTag, newTag)
		newSource, err := replaceImageTag(image.Delivery.Default.Source, newOfficialTag)
		if err != nil {
			return nil, err
		}
		oldTarget := image.Target
		newTarget, err := replaceImageTag(oldTarget, newOfficialTag)
		if err != nil {
			return nil, err
		}
		if mutate {
			evidenceReference := renderedEvidenceReferenceForTag(*image, repository, officialTag)
			if evidenceReference == "" {
				evidenceReference = oldReference
			}
			image.Version = newOfficialTag
			image.Target = newTarget
			image.Delivery.Default.Source = newSource
			recordRenderedEvidence(
				desired,
				image,
				renderedEvidenceTransition{prior: evidenceReference, candidate: newReference},
			)
			updateEvidenceTargets(desired, image.ID, oldTarget, newTarget, newSource, "")
			updateLockedTarget(lock, image.ID, oldTarget, newTarget, newSource, "")
		}
		replacements = append(replacements, imageReplacement{Old: oldTarget, New: newTarget})
	}
	return replacements, nil
}

func hasDirectChartAppVersionMapping(
	desired *config.Document,
	artifact string,
) bool {
	if desired == nil {
		return false
	}
	for i := range desired.Delivery.Images {
		image := &desired.Delivery.Images[i]
		if directChartAppVersionMapping(image.VersionMapping, artifact) {
			return true
		}
	}
	return false
}

func directChartApplicationRepositories(desired *config.Document) map[string][]string {
	repositories := make(map[string][]string)
	if desired == nil {
		return repositories
	}
	for i := range desired.Delivery.Images {
		image := &desired.Delivery.Images[i]
		mapping := image.VersionMapping
		if mapping == nil || !directChartAppVersionMapping(mapping, mapping.Artifact) {
			continue
		}
		chartID := strings.TrimPrefix(mapping.Artifact, "chart/")
		candidates := [...]string{
			imageRepository(image.Delivery.Default.Source),
			imageRepository(image.Target),
		}
		for _, repository := range candidates {
			if repository != "" && !containsString(repositories[chartID], repository) {
				repositories[chartID] = append(repositories[chartID], repository)
			}
		}
		if mapping.Build != nil && mapping.Build.ImageRepository != "" &&
			!containsString(repositories[chartID], mapping.Build.ImageRepository) {
			repositories[chartID] = append(repositories[chartID], mapping.Build.ImageRepository)
		}
	}
	return repositories
}

func directChartAppVersionMapping(mapping *config.ImageVersionMapping, artifact string) bool {
	return strings.HasPrefix(artifact, "chart/") &&
		mapping != nil &&
		mapping.Artifact == artifact &&
		mapping.Source == "chartAppVersion"
}

func reconcileVersionMappedImage(
	ctx context.Context,
	cache *gitcache.Manager,
	tree *candidateTree,
	desired *config.Document,
	lock *config.Lock,
	image *config.Image,
	current, candidate chartInspection,
	oldReference, newReference string,
	mutate bool,
) (imageReplacement, bool, error) {
	var resolveTag exactTagResolver
	if cache != nil {
		resolveTag = cache.ResolveTag
	}
	return reconcileVersionMappedImageWithResolver(
		ctx, cache, resolveTag, tree, desired, lock, image,
		current, candidate, oldReference, newReference, mutate,
	)
}

func reconcileVersionMappedImageWithResolver(
	ctx context.Context,
	cache *gitcache.Manager,
	resolveTag exactTagResolver,
	tree *candidateTree,
	desired *config.Document,
	lock *config.Lock,
	image *config.Image,
	current, candidate chartInspection,
	oldReference, newReference string,
	mutate bool,
) (imageReplacement, bool, error) {
	mapping := image.VersionMapping
	if mapping.Source == "upstreamImageTag" {
		return reconcileMappedBuildImage(
			ctx, cache, tree, desired, lock, image, oldReference, newReference, mutate,
		)
	}
	if mapping.Source != "chartAppVersion" {
		return imageReplacement{}, false, fmt.Errorf("unsupported version source %q", mapping.Source)
	}
	directMapping := directChartAppVersionMapping(mapping, mapping.Artifact)
	currentRenderedOwned := false
	if directMapping {
		if image.Delivery.Default.Type != "mirror" {
			return imageReplacement{}, false, errors.New("direct chart application mapping requires an official mirror")
		}
		currentRenderedOwned = directRenderedReferenceOwned(*image, oldReference)
		if !currentRenderedOwned {
			return imageReplacement{}, false, fmt.Errorf(
				"current chart repository %s does not match official mirror repository %s",
				imageRepository(oldReference), imageRepository(image.Delivery.Default.Source),
			)
		}
		if mapping.Build != nil &&
			imageRepository(image.Delivery.Default.Source) != mapping.Build.ImageRepository {
			return imageReplacement{}, false, fmt.Errorf(
				"official mirror repository %s does not match mapped build repository %s",
				imageRepository(image.Delivery.Default.Source), mapping.Build.ImageRepository,
			)
		}
	}
	currentVersion, currentTag, err := mappedChartVersion(current.AppVersion, mapping.TagPrefix)
	if err != nil {
		return imageReplacement{}, false, fmt.Errorf("current chart: %w", err)
	}
	candidateVersion, candidateTag, err := mappedChartVersion(candidate.AppVersion, mapping.TagPrefix)
	if err != nil {
		return imageReplacement{}, false, fmt.Errorf("candidate chart: %w", err)
	}
	inventoryVersion, inventoryTag, err := mappedChartVersion(image.Version, mapping.TagPrefix)
	if err != nil {
		return imageReplacement{}, false, fmt.Errorf("delivery inventory: %w", err)
	}
	inventorySourceTag := mappedOfficialSourceTag(mapping, inventoryVersion)
	inventoryCurrent := inventoryVersion == currentVersion &&
		imageTag(image.Target) == currentTag &&
		imageTag(image.Delivery.Default.Source) == inventorySourceTag
	repairPrerelease := false
	if !inventoryCurrent {
		currentStable, _ := eligibleChartAppVersion(current.AppVersion)
		candidateStable, _ := eligibleChartAppVersion(candidate.AppVersion)
		inventoryStable, _ := eligibleChartAppVersion(image.Version)
		repairPrerelease = directMapping &&
			currentStable && candidateStable && !inventoryStable &&
			imageTag(image.Target) == inventoryTag &&
			currentRenderedOwned &&
			imageTag(image.Delivery.Default.Source) == inventorySourceTag
		if !repairPrerelease {
			return imageReplacement{}, false, fmt.Errorf(
				"version mapping is stale: inventory %s/%s does not match chart appVersion %s",
				image.Version, imageTag(image.Target), current.AppVersion,
			)
		}
	}
	renderedEvidence := renderedEvidenceTransition{
		prior:     oldReference,
		candidate: newReference,
	}
	if directMapping {
		renderedEvidence.candidate, err = directRenderedEvidenceReference(
			*image, newReference, candidateTag,
		)
		if err != nil {
			return imageReplacement{}, false, fmt.Errorf("candidate chart evidence: %w", err)
		}
		if repairPrerelease {
			renderedEvidence.prior = ""
		} else {
			renderedEvidence.prior, err = directRenderedEvidenceReference(
				*image, oldReference, currentTag,
			)
			if err != nil {
				return imageReplacement{}, false, fmt.Errorf("current chart evidence: %w", err)
			}
		}
	}
	candidateEvidenceTag := mappedOfficialSourceTag(mapping, candidateVersion)
	if mapping.Build != nil {
		return reconcileMappedBuildVersionWithResolver(
			ctx, resolveTag, tree, desired, lock, image,
			inventoryVersion, candidateVersion,
			renderedEvidence, mutate,
		)
	}
	if err := validateRenderedEvidenceTransition(*image, mapping, renderedEvidence); err != nil {
		return imageReplacement{}, false, err
	}
	if inventoryVersion == candidateVersion {
		if mutate && renderedEvidence.prior != renderedEvidence.candidate {
			recordRenderedEvidence(desired, image, renderedEvidence)
		}
		return imageReplacement{}, false, nil
	}
	newSource, err := replaceImageTag(image.Delivery.Default.Source, candidateEvidenceTag)
	if err != nil {
		return imageReplacement{}, false, err
	}
	oldTarget := image.Target
	newTarget, err := replaceImageTag(oldTarget, candidateTag)
	if err != nil {
		return imageReplacement{}, false, err
	}
	if mutate {
		image.Version = candidateVersion
		image.Target = newTarget
		image.Delivery.Default.Source = newSource
		recordRenderedEvidence(desired, image, renderedEvidence)
		updateEvidenceTargets(desired, image.ID, oldTarget, newTarget, newSource, "")
		updateLockedTarget(lock, image.ID, oldTarget, newTarget, newSource, "")
	}
	return imageReplacement{Old: oldTarget, New: newTarget}, true, nil
}

func directRenderedReferenceOwned(image config.Image, reference string) bool {
	repository := imageRepository(reference)
	if repository == imageRepository(image.Delivery.Default.Source) {
		return true
	}
	return repository == imageRepository(image.Target) &&
		equivalentTag(imageTag(reference), imageTag(image.Target))
}

func directRenderedEvidenceReference(
	image config.Image,
	reference, chartTag string,
) (string, error) {
	repository := imageRepository(reference)
	sourceRepository := imageRepository(image.Delivery.Default.Source)
	if repository == sourceRepository {
		if !equivalentTag(imageTag(reference), chartTag) {
			return "", fmt.Errorf(
				"official reference %s does not match chart application tag %s",
				reference, chartTag,
			)
		}
		return reference, nil
	}
	if repository != imageRepository(image.Target) ||
		!equivalentTag(imageTag(reference), imageTag(image.Target)) {
		return "", fmt.Errorf(
			"rendered reference %s is not owned by target %s or official source %s",
			reference, image.Target, image.Delivery.Default.Source,
		)
	}
	projected, err := replaceImageTag(image.Delivery.Default.Source, chartTag)
	if err != nil {
		return "", err
	}
	return projected, nil
}

func mappedOfficialSourceTag(mapping *config.ImageVersionMapping, normalizedVersion string) string {
	if mapping.Build != nil {
		return mapping.Build.ImageTagPrefix + normalizedVersion
	}
	return mapping.TagPrefix + normalizedVersion
}

func mappedChartVersion(appVersion, prefix string) (string, string, error) {
	version := strings.TrimPrefix(strings.TrimSpace(appVersion), "v")
	if version == "" {
		return "", "", errors.New("appVersion is empty")
	}
	return version, prefix + version, nil
}

func recordBigBangReference(desired *config.Document, image *config.Image, oldReference, newReference string) {
	recordRenderedEvidence(
		desired,
		image,
		renderedEvidenceTransition{prior: oldReference, candidate: newReference},
	)
	updateEvidenceTargets(
		desired,
		image.ID,
		image.Target,
		image.Target,
		image.Delivery.Default.Source,
		"",
	)
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
		pinned := ""
		if previous, exists := currentSources[image.ID]; exists &&
			previous.Source == image.Delivery.Default.Source {
			if previous.Digest != image.Delivery.Default.Digest {
				return false, fmt.Errorf("mirror %s digest changed without changing source %s", image.ID, image.Delivery.Default.Source)
			}
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
	changed := false
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
			updateEvidenceTargets(
				desired, image.ID, image.Target, image.Target,
				image.Delivery.Default.Source, digest)
			updateLockedTarget(
				lock, image.ID, image.Target, image.Target,
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

func reconcileKubernetesImages(desired *config.Document, lock *config.Lock, kubernetesVersion string) ([]imageReplacement, error) {
	components := strings.Split(kubernetesVersion, ".")
	if len(components) != 3 {
		return nil, fmt.Errorf("Kubernetes version %q is not major.minor.patch", kubernetesVersion)
	}
	version := components[0] + "." + components[1] + ".0"
	for i := range desired.Delivery.Images {
		image := &desired.Delivery.Images[i]
		if image.ID != "kubectl" {
			continue
		}
		if image.Delivery.Default.Type != "mirror" || imageRepository(image.Delivery.Default.Source) != "docker.io/alpine/k8s" {
			return nil, errors.New("kubectl delivery must mirror docker.io/alpine/k8s")
		}
		if image.Version == version {
			return nil, nil
		}
		oldTarget := image.Target
		newTarget, err := replaceImageTag(oldTarget, version)
		if err != nil {
			return nil, err
		}
		newSource, err := replaceImageTag(image.Delivery.Default.Source, version)
		if err != nil {
			return nil, err
		}
		image.Version = version
		image.Target = newTarget
		image.Delivery.Default.Source = newSource
		updateEvidenceTargets(
			desired, image.ID,
			oldTarget, newTarget, newSource, "",
		)
		updateLockedTarget(lock, image.ID, oldTarget, newTarget, newSource, "")
		return []imageReplacement{{Old: oldTarget, New: newTarget}}, nil
	}
	return nil, errors.New("delivery inventory has no kubectl image")
}

func imagesByRepository(images []string) (map[string]string, error) {
	result := make(map[string]string, len(images))
	for _, image := range images {
		repository := imageRepository(image)
		if repository == "" {
			continue
		}
		if previous, exists := result[repository]; exists && imageTag(previous) != imageTag(image) {
			return nil, fmt.Errorf("repository %s has multiple tags %s and %s", repository, imageTag(previous), imageTag(image))
		}
		result[repository] = image
	}
	return result, nil
}

func mappedImages(images []config.Image, currentReference string) []int {
	repository := imageRepository(currentReference)
	tag := imageTag(currentReference)
	var exact []int
	for i := range images {
		if imageRepository(images[i].Target) == repository && equivalentTag(imageTag(images[i].Target), tag) {
			exact = append(exact, i)
			continue
		}
		for _, reference := range images[i].BigBangRefs {
			if imageRepository(reference) == repository && equivalentTag(imageTag(reference), tag) {
				exact = append(exact, i)
				break
			}
		}
	}
	if len(exact) != 0 {
		return exact
	}
	for i := range images {
		choice := images[i].Delivery.Default
		if choice.Type == "mirror" && imageRepository(choice.Source) == repository && equivalentTag(imageTag(choice.Source), tag) {
			exact = append(exact, i)
		}
	}
	return exact
}

func addMappedDeclaredImages(
	images []config.Image,
	artifact string,
	current, candidate []string,
	renderedImages map[string]struct{},
	currentImages, candidateImages map[string]string,
) error {
	currentDeclared := uniqueDeclaredImages(current)
	candidateDeclared := uniqueDeclaredImages(candidate)
	for repository, candidateReference := range candidateDeclared {
		if _, rendered := candidateImages[repository]; rendered {
			continue
		}
		matches := mappedImages(images, candidateReference)
		if len(matches) == 0 {
			matches = mappedImageRepositories(images, repository)
		}
		if len(matches) == 0 {
			// Package annotations often include test-only images. Only declared
			// repositories with an explicit delivery mapping can become runtime
			// images through a controller or admission webhook.
			continue
		}
		if len(matches) > 1 {
			return fmt.Errorf("declared image repository %s maps ambiguously to %d delivery entries", repository, len(matches))
		}
		if mapping := images[matches[0]].VersionMapping; mapping != nil && mapping.Artifact != artifact {
			continue
		}
		if _, rendered := renderedImages[images[matches[0]].ID]; rendered {
			continue
		}
		currentReference, existed := currentDeclared[repository]
		if !existed {
			currentReference = mappedReferenceForRepository(images[matches[0]], repository)
			if currentReference == "" {
				return fmt.Errorf("declared image repository %s has no prior mapped reference", repository)
			}
		}
		currentImages[repository] = currentReference
		candidateImages[repository] = candidateReference
	}
	return nil
}

func renderedImageIDs(images []config.Image, inspections []chartInspection) map[string]struct{} {
	result := make(map[string]struct{}, len(images))
	for i := range inspections {
		for _, reference := range observedSourceImages(inspections[i]) {
			repository := imageRepository(reference)
			matches := mappedImages(images, reference)
			if len(matches) == 0 {
				matches = mappedImageRepositories(images, repository)
			}
			if len(matches) == 1 {
				result[images[matches[0]].ID] = struct{}{}
			}
		}
	}
	return result
}

func uniqueDeclaredImages(images []string) map[string]string {
	result := make(map[string]string, len(images))
	ambiguous := make(map[string]struct{})
	for _, image := range images {
		repository := imageRepository(image)
		if repository == "" {
			continue
		}
		if _, excluded := ambiguous[repository]; excluded {
			continue
		}
		if previous, exists := result[repository]; exists && imageTag(previous) != imageTag(image) {
			delete(result, repository)
			ambiguous[repository] = struct{}{}
			continue
		}
		result[repository] = image
	}
	return result
}

func mappedReferenceForRepository(image config.Image, repository string) string {
	for _, reference := range image.BigBangRefs {
		if imageRepository(reference) == repository {
			return reference
		}
	}
	if imageRepository(image.Delivery.Default.Source) == repository {
		return image.Delivery.Default.Source
	}
	if imageRepository(image.Target) == repository {
		return image.Target
	}
	return ""
}

func renderedEvidenceReferenceForTag(image config.Image, repository, tag string) string {
	for _, reference := range image.BigBangRefs {
		if imageRepository(reference) == repository && equivalentTag(imageTag(reference), tag) {
			return reference
		}
	}
	return ""
}

func validateRenderedEvidenceTransition(
	image config.Image,
	mapping *config.ImageVersionMapping,
	transition renderedEvidenceTransition,
) error {
	if transition.candidate == "" {
		return errors.New("candidate rendered evidence is missing")
	}
	artifact := ""
	if mapping != nil {
		artifact = mapping.Artifact
	}
	if transition.prior == "" || !directChartAppVersionMapping(mapping, artifact) {
		return nil
	}
	recorded := renderedEvidenceReferenceForTag(
		image, imageRepository(transition.prior), imageTag(transition.prior),
	)
	if recorded == "" {
		return fmt.Errorf(
			"prior rendered reference %s does not match recorded Big Bang evidence",
			transition.prior,
		)
	}
	return nil
}

func mappedImageRepositories(images []config.Image, repository string) []int {
	var matches []int
	for i := range images {
		if imageMapsRepository(images[i], repository) {
			matches = append(matches, i)
		}
	}
	return matches
}

func imageMapsRepository(image config.Image, repository string) bool {
	if imageRepository(image.Target) == repository ||
		imageRepository(image.Delivery.Default.Source) == repository {
		return true
	}
	for _, reference := range image.BigBangRefs {
		if imageRepository(reference) == repository {
			return true
		}
	}
	return false
}

func mappedReferenceMatches(references []string, repository, tag string) bool {
	for _, reference := range references {
		if imageRepository(reference) == repository && equivalentTag(imageTag(reference), tag) {
			return true
		}
	}
	return false
}

func updateEvidenceTargets(
	desired *config.Document,
	imageID string,
	oldTarget, newTarget, source, digest string,
) {
	for i := range desired.Delivery.RenderedBaseline.Entries {
		entry := &desired.Delivery.RenderedBaseline.Entries[i]
		if entry.ImageID == imageID && entry.Target == oldTarget {
			entry.Target = newTarget
		}
	}
	for i := range desired.Delivery.LegacyCrosswalk.Entries {
		entry := &desired.Delivery.LegacyCrosswalk.Entries[i]
		if entry.ImageID != imageID {
			continue
		}
		entry.Replacement = newTarget
		if entry.OfficialSource != nil {
			entry.OfficialSource.Reference = source
			if digest != "" {
				entry.OfficialSource.Digest = digest
			}
		}
	}
}

func recordRenderedEvidence(
	desired *config.Document,
	image *config.Image,
	transition renderedEvidenceTransition,
) {
	image.BigBangRefs = appendRenderedEvidence(image.BigBangRefs, transition)
	for i := range desired.Delivery.LegacyCrosswalk.Entries {
		entry := &desired.Delivery.LegacyCrosswalk.Entries[i]
		if entry.ImageID == image.ID {
			entry.BigBangRefs = appendRenderedEvidence(entry.BigBangRefs, transition)
		}
	}
}

func updateLockedTarget(lock *config.Lock, imageID, oldTarget, newTarget, source, digest string) {
	for i := range lock.Delivery.Images {
		image := &lock.Delivery.Images[i]
		if image.ID != imageID {
			continue
		}
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
		return
	}
}

func refreshImageInputHashes(desired *config.Document, lock *config.Lock) (bool, error) {
	byID := make(map[string]config.Image, len(desired.Delivery.Images))
	for _, image := range desired.Delivery.Images {
		byID[image.ID] = image
	}
	current := len(lock.Delivery.Images) == len(desired.Delivery.Images)
	seen := make(map[string]struct{}, len(lock.Delivery.Images))
	for i := range lock.Delivery.Images {
		locked := &lock.Delivery.Images[i]
		image, exists := byID[locked.ID]
		if !exists {
			current = false
			continue
		}
		if _, duplicate := seen[locked.ID]; duplicate {
			current = false
		}
		seen[locked.ID] = struct{}{}
		expectedDelivery, err := config.ResolveDelivery(image, lock.Delivery.Profile, lock.Delivery.GraphSHA256)
		if err != nil {
			return false, fmt.Errorf("resolve image delivery %s: %w", locked.ID, err)
		}
		if locked.Target != image.Target || !reflect.DeepEqual(locked.Delivery, expectedDelivery) {
			current = false
		}
		inputSHA, err := desired.ImageInputSHA256(image, expectedDelivery, lock.Delivery.GraphSHA256)
		if err != nil {
			return false, fmt.Errorf("resolve image input %s: %w", locked.ID, err)
		}
		if expectedDelivery.Type == "build" && locked.InputSHA256 != inputSHA {
			current = false
		}
		if expectedDelivery.Type == "mirror" && reflect.DeepEqual(locked.Delivery, expectedDelivery) {
			locked.InputSHA256 = inputSHA
		}
	}
	return current, nil
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

func appendRenderedEvidence(
	values []string,
	transition renderedEvidenceTransition,
) []string {
	if transition.candidate == "" || containsString(values, transition.candidate) {
		return values
	}
	if transition.prior != "" &&
		!mappedReferenceMatches(
			values, imageRepository(transition.prior), imageTag(transition.prior),
		) {
		return values
	}
	return append(values, transition.candidate)
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
				candidates := append([]imageReplacement(nil), byRepository[imageRepository(repository)]...)
				for _, registryKey := range [...]string{"registry", "defaultRegistry"} {
					registry, ok := typed[registryKey].(string)
					if !ok || registry == "" {
						continue
					}
					qualified := strings.TrimSuffix(registry, "/") + "/" + strings.TrimPrefix(repository, "/")
					candidates = append(candidates, byRepository[imageRepository(qualified)]...)
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
