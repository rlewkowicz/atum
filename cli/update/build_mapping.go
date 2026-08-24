package update

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"atum/cli/config"
	"atum/cli/gitcache"

	"github.com/Masterminds/semver/v3"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/sync/errgroup"
)

const buildGraphFile = "platform/build/docker-bake.hcl"

type staticBakeTarget struct {
	tags     []string
	contexts map[string]string
	args     map[string]string
}

type inferredVersionMapping struct {
	imageIndex        int
	mapping           config.ImageVersionMapping
	renderedReference string
}

type exactTagResolver func(context.Context, string, string) (gitcache.Release, error)

type renderedEvidenceTransition struct {
	prior     string
	candidate string
}

func inferTrackedChartVersionMappings(
	ctx context.Context,
	parallelism int,
	cache *gitcache.Manager,
	tree *candidateTree,
	desired *config.Document,
	currentInputs map[string]artifactInput,
	kubernetesVersion string,
) (int, error) {
	if cache == nil {
		return 0, errors.New("infer tracked chart version mappings: Git resolver is missing")
	}
	return inferTrackedChartVersionMappingsWithResolver(
		ctx, parallelism, cache.ResolveTag, tree, desired, currentInputs, kubernetesVersion,
	)
}

func inferTrackedChartVersionMappingsWithResolver(
	ctx context.Context,
	parallelism int,
	resolveTag exactTagResolver,
	tree *candidateTree,
	desired *config.Document,
	currentInputs map[string]artifactInput,
	kubernetesVersion string,
) (int, error) {
	if len(desired.Platform.Charts) == 0 {
		return 0, nil
	}
	if resolveTag == nil {
		return 0, errors.New("infer tracked chart version mappings: exact Git tag resolver is missing")
	}
	graph, err := tree.CandidateData(buildGraphFile)
	if err != nil {
		return 0, err
	}
	inferred := make([][]inferredVersionMapping, len(desired.Platform.Charts))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for chartIndex := range desired.Platform.Charts {
		chartIndex := chartIndex
		group.Go(func() error {
			chart := desired.Platform.Charts[chartIndex]
			artifact := "chart/" + chart.ID
			input, exists := currentInputs[artifact]
			if !exists {
				return fmt.Errorf("infer %s image versions: current artifact is missing", artifact)
			}
			inspection, err := inspectChart(input.Path, kubernetesVersion, nil)
			if err != nil {
				return fmt.Errorf("infer %s image versions: %w", artifact, err)
			}
			mappings, err := inferChartInspectionVersionMappings(
				groupContext, resolveTag, graph, artifact, inspection, desired.Delivery.Images,
			)
			if err != nil {
				return err
			}
			inferred[chartIndex] = mappings
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return 0, err
	}
	return applyInferredVersionMappings(desired, inferred)
}

func applyInferredVersionMappings(
	desired *config.Document,
	inferred [][]inferredVersionMapping,
) (int, error) {
	owners := make(map[int]string)
	count := 0
	for chartIndex := range inferred {
		for mappingIndex := range inferred[chartIndex] {
			candidate := &inferred[chartIndex][mappingIndex]
			artifact := candidate.mapping.Artifact
			if previous, exists := owners[candidate.imageIndex]; exists {
				return 0, fmt.Errorf("delivery image %s derives versions from both %s and %s",
					desired.Delivery.Images[candidate.imageIndex].ID, previous, artifact)
			}
			owners[candidate.imageIndex] = artifact
			mapping := candidate.mapping
			image := &desired.Delivery.Images[candidate.imageIndex]
			image.VersionMapping = &mapping
			if candidate.renderedReference != "" {
				recordRenderedEvidence(
					desired,
					image,
					renderedEvidenceTransition{candidate: candidate.renderedReference},
				)
			}
			count++
		}
	}
	return count, nil
}

func inferChartInspectionVersionMappings(
	ctx context.Context,
	resolveTag exactTagResolver,
	graph []byte,
	artifact string,
	inspection chartInspection,
	images []config.Image,
) ([]inferredVersionMapping, error) {
	eligible := make([]bool, len(images))
	for i := range images {
		image := &images[i]
		eligible[i] = image.VersionMapping == nil &&
			image.Delivery.Default.Type == "mirror" &&
			image.Delivery.FullBuildTarget != ""
	}
	appVersion, _, err := mappedChartVersion(inspection.AppVersion, "")
	if err != nil {
		return nil, fmt.Errorf("infer %s image versions: %w", artifact, err)
	}
	seen := make(map[int]string, len(inspection.Images))
	var inferred []inferredVersionMapping
	for _, reference := range inspection.Images {
		if !equivalentTag(imageTag(reference), appVersion) {
			continue
		}
		repository := imageRepository(reference)
		knownMatches := mappedInferenceRepositories(images, eligible, repository, appVersion)
		matches := mappedInferenceMirrors(images, eligible, repository, appVersion)
		if len(matches) == 0 {
			if len(knownMatches) != 0 {
				return nil, fmt.Errorf(
					"%s default image %s matches delivery only through a runtime target or historical reference",
					artifact, reference,
				)
			}
			continue
		}
		if len(matches) > 1 {
			return nil, fmt.Errorf("%s default image %s maps ambiguously to %d delivery entries",
				artifact, reference, len(matches))
		}
		imageIndex := matches[0]
		if previous, duplicate := seen[imageIndex]; duplicate {
			if previous != reference {
				return nil, fmt.Errorf(
					"%s delivery image %s is rendered from multiple current chart references: %s and %s",
					artifact, images[imageIndex].ID, previous, reference,
				)
			}
			continue
		}
		seen[imageIndex] = reference
		image := images[imageIndex]
		mapping, err := inferChartAppBuildMapping(
			ctx, resolveTag, graph, artifact, reference, image,
		)
		if err != nil {
			return nil, fmt.Errorf("infer %s image %s version mapping: %w", artifact, image.ID, err)
		}
		inventoryVersion, _, err := mappedChartVersion(image.Version, "")
		if err != nil {
			return nil, fmt.Errorf("infer %s image %s inventory version: %w", artifact, image.ID, err)
		}
		renderedReference := ""
		if inventoryVersion == appVersion {
			renderedReference = reference
		}
		inferred = append(inferred, inferredVersionMapping{
			imageIndex:        imageIndex,
			mapping:           mapping,
			renderedReference: renderedReference,
		})
	}
	return inferred, nil
}

func mappedInferenceMirrors(
	images []config.Image,
	eligible []bool,
	repository, appVersion string,
) []int {
	var matches []int
	for i := range images {
		image := &images[i]
		if eligible[i] &&
			inferenceRepositoryVersionMatches(*image, repository, appVersion, true) {
			matches = append(matches, i)
		}
	}
	return matches
}

func mappedInferenceRepositories(
	images []config.Image,
	eligible []bool,
	repository, appVersion string,
) []int {
	var matches []int
	for i := range images {
		if !eligible[i] {
			continue
		}
		if inferenceRepositoryVersionMatches(images[i], repository, appVersion, false) {
			matches = append(matches, i)
		}
	}
	return matches
}

func inferenceRepositoryVersionMatches(
	image config.Image,
	repository, appVersion string,
	officialOnly bool,
) bool {
	inventoryVersion, _, err := mappedChartVersion(image.Version, "")
	if err != nil {
		return false
	}
	versionMatches := inventoryVersion == appVersion
	if !versionMatches {
		inventoryStable, _ := eligibleChartAppVersion(inventoryVersion)
		appStable, _ := eligibleChartAppVersion(appVersion)
		versionMatches = !inventoryStable && appStable
	}
	if !versionMatches {
		return false
	}
	referenceMatches := func(reference string) bool {
		return imageRepository(reference) == repository &&
			equivalentTag(imageTag(reference), inventoryVersion)
	}
	if officialOnly {
		return referenceMatches(image.Delivery.Default.Source)
	}
	if referenceMatches(image.Target) || referenceMatches(image.Delivery.Default.Source) {
		return true
	}
	for _, reference := range image.BigBangRefs {
		if referenceMatches(reference) {
			return true
		}
	}
	return false
}

func inferChartAppBuildMapping(
	ctx context.Context,
	resolveTag exactTagResolver,
	graph []byte,
	artifact, defaultReference string,
	image config.Image,
) (config.ImageVersionMapping, error) {
	if resolveTag == nil {
		return config.ImageVersionMapping{}, errors.New("exact Git tag resolver is missing")
	}
	if image.Delivery.Default.Type != "mirror" {
		return config.ImageVersionMapping{}, errors.New("delivery default is not an official mirror")
	}
	repository := imageRepository(defaultReference)
	if repository == "" || repository != imageRepository(image.Delivery.Default.Source) {
		return config.ImageVersionMapping{}, fmt.Errorf(
			"current chart repository %s does not match official mirror repository %s",
			repository, imageRepository(image.Delivery.Default.Source),
		)
	}
	currentVersion := strings.TrimPrefix(strings.TrimSpace(image.Version), "v")
	if currentVersion == "" {
		return config.ImageVersionMapping{}, errors.New("current image version is empty")
	}
	targetTag := imageTag(image.Target)
	if !strings.HasSuffix(targetTag, currentVersion) {
		return config.ImageVersionMapping{}, fmt.Errorf("runtime target tag %s does not end in version %s", targetTag, currentVersion)
	}
	tagPrefix := strings.TrimSuffix(targetTag, currentVersion)
	sourceTag := imageTag(image.Delivery.Default.Source)
	if !strings.HasSuffix(sourceTag, currentVersion) {
		return config.ImageVersionMapping{}, fmt.Errorf("mirror tag %s does not end in version %s", sourceTag, currentVersion)
	}
	imageTagPrefix := strings.TrimSuffix(sourceTag, currentVersion)
	appVersion, _, err := mappedChartVersion(imageTag(defaultReference), imageTagPrefix)
	if err != nil {
		return config.ImageVersionMapping{}, err
	}
	if appVersion != currentVersion {
		inventoryStable, _ := eligibleChartAppVersion(currentVersion)
		chartStable, _ := eligibleChartAppVersion(appVersion)
		if inventoryStable || !chartStable {
			return config.ImageVersionMapping{}, fmt.Errorf(
				"chart application version %s does not match delivery version %s",
				appVersion, currentVersion,
			)
		}
	}

	target, err := loadStaticBakeTarget(graph, image.Delivery.FullBuildTarget)
	if err != nil {
		return config.ImageVersionMapping{}, err
	}
	if len(target.tags) != 1 || imageRepository(target.tags[0]) != imageRepository(image.Target) {
		return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s does not own runtime repository %s",
			image.Delivery.FullBuildTarget, imageRepository(image.Target))
	}
	fullTagPrefix := tagPrefix + currentVersion
	fullTag := imageTag(target.tags[0])
	if !strings.HasPrefix(fullTag, fullTagPrefix) {
		return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s tag %s does not begin with %s",
			image.Delivery.FullBuildTarget, fullTag, fullTagPrefix)
	}
	fullTagSuffix := strings.TrimPrefix(fullTag, fullTagPrefix)
	if fullTagSuffix == "" {
		return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s has no full-build tag suffix",
			image.Delivery.FullBuildTarget)
	}
	if target.args["ATUM_IMAGE_VERSION"] != currentVersion {
		return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s version %q does not match %s",
			image.Delivery.FullBuildTarget, target.args["ATUM_IMAGE_VERSION"], currentVersion)
	}
	revision := target.args["ATUM_IMAGE_REVISION"]
	if err := validateGitCommit(revision); err != nil {
		return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s revision: %w",
			image.Delivery.FullBuildTarget, err)
	}
	type gitInput struct {
		context string
		url     string
		prefix  string
	}
	var matched *gitInput
	for contextName, value := range target.contexts {
		gitURL, tag, commit, ok := pinnedGitContext(value)
		if !ok || commit != revision || !strings.HasSuffix(tag, currentVersion) {
			continue
		}
		candidate := gitInput{
			context: contextName,
			url:     gitURL,
			prefix:  strings.TrimSuffix(tag, currentVersion),
		}
		if matched != nil {
			return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s has multiple versioned Git inputs",
				image.Delivery.FullBuildTarget)
		}
		matched = &candidate
	}
	if matched == nil {
		return config.ImageVersionMapping{}, fmt.Errorf("Bake target %s has no Git input for version %s",
			image.Delivery.FullBuildTarget, currentVersion)
	}
	gitTag := matched.prefix + currentVersion
	if err := admitMappedBuildGitTag(gitTag, currentVersion); err != nil {
		return config.ImageVersionMapping{}, fmt.Errorf(
			"admit Bake target %s Git tag: %w", image.Delivery.FullBuildTarget, err,
		)
	}
	release, err := resolveTag(ctx, matched.url, gitTag)
	if err != nil {
		return config.ImageVersionMapping{}, fmt.Errorf(
			"resolve Bake target %s Git tag %s: %w",
			image.Delivery.FullBuildTarget, gitTag, err,
		)
	}
	if release.Version != gitTag || release.Commit != revision {
		return config.ImageVersionMapping{}, fmt.Errorf(
			"Bake target %s Git tag %s resolves as %s at %s, want exact tag at provenance revision %s",
			image.Delivery.FullBuildTarget, gitTag, release.Version, release.Commit, revision,
		)
	}
	return config.ImageVersionMapping{
		Artifact:  artifact,
		Source:    "chartAppVersion",
		TagPrefix: tagPrefix,
		Build: &config.ImageBuildVersionMapping{
			ImageRepository: repository,
			ImageTagPrefix:  imageTagPrefix,
			GitURL:          matched.url,
			GitTagPrefix:    matched.prefix,
			GitContext:      matched.context,
			FullTagSuffix:   fullTagSuffix,
		},
	}, nil
}

func pinnedGitContext(value string) (string, string, string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" {
		return "", "", "", false
	}
	query := parsed.Query()
	tag := query.Get("tag")
	commit := query.Get("checksum")
	if len(query) != 2 || tag == "" || validateGitCommit(commit) != nil {
		return "", "", "", false
	}
	parsed.RawQuery = ""
	return parsed.String(), tag, commit, true
}

func reconcileMappedBuildImage(
	ctx context.Context,
	cache *gitcache.Manager,
	tree *candidateTree,
	desired *config.Document,
	lock *config.Lock,
	image *config.Image,
	oldReference, newReference string,
	mutate bool,
) (imageReplacement, bool, error) {
	mapping := image.VersionMapping
	oldVersion, _, err := mappedUpstreamVersion(oldReference, mapping.UpstreamTagPrefix)
	if err != nil {
		return imageReplacement{}, false, fmt.Errorf("current reference: %w", err)
	}
	newVersion, _, err := mappedUpstreamVersion(newReference, mapping.UpstreamTagPrefix)
	if err != nil {
		return imageReplacement{}, false, fmt.Errorf("candidate reference: %w", err)
	}
	return reconcileMappedBuildVersion(
		ctx, cache, tree, desired, lock, image,
		oldVersion, newVersion,
		renderedEvidenceTransition{prior: oldReference, candidate: newReference},
		mutate,
	)
}

func reconcileMappedBuildVersion(
	ctx context.Context,
	cache *gitcache.Manager,
	tree *candidateTree,
	desired *config.Document,
	lock *config.Lock,
	image *config.Image,
	oldVersion, newVersion string,
	evidence renderedEvidenceTransition,
	mutate bool,
) (imageReplacement, bool, error) {
	var resolveTag exactTagResolver
	if cache != nil {
		resolveTag = cache.ResolveTag
	}
	return reconcileMappedBuildVersionWithResolver(
		ctx, resolveTag, tree, desired, lock, image,
		oldVersion, newVersion, evidence, mutate,
	)
}

func reconcileMappedBuildVersionWithResolver(
	ctx context.Context,
	resolveTag exactTagResolver,
	tree *candidateTree,
	desired *config.Document,
	lock *config.Lock,
	image *config.Image,
	oldVersion, newVersion string,
	evidence renderedEvidenceTransition,
	mutate bool,
) (imageReplacement, bool, error) {
	mapping := image.VersionMapping
	build := mapping.Build
	if build == nil {
		return imageReplacement{}, false, errors.New("build mapping is missing")
	}
	oldTargetTag := mapping.TagPrefix + oldVersion + mapping.TagSuffix
	newTargetTag := mapping.TagPrefix + newVersion + mapping.TagSuffix
	if image.Version != oldVersion || imageTag(image.Target) != oldTargetTag {
		return imageReplacement{}, false, fmt.Errorf(
			"version mapping is stale: inventory %s/%s does not match source version %s",
			image.Version, imageTag(image.Target), oldVersion,
		)
	}
	if err := validateRenderedEvidenceTransition(*image, mapping, evidence); err != nil {
		return imageReplacement{}, false, err
	}
	compatibilityBuild := image.Delivery.Default.Type == "build"
	materialIndex := -1
	oldMaterial := ""
	publicSource := ""
	var err error
	if compatibilityBuild {
		materialIndex, oldMaterial, err = mappedBuildMaterial(image.Delivery.Default.Materials, build.ImageRepository)
		if err != nil {
			return imageReplacement{}, false, err
		}
	} else {
		publicSource = image.Delivery.Default.Source
		if imageTag(publicSource) != build.ImageTagPrefix+oldVersion {
			return imageReplacement{}, false, fmt.Errorf("mirror source %s does not match mapped version %s", publicSource, oldVersion)
		}
	}
	gitTags := [2]string{build.GitTagPrefix + oldVersion, build.GitTagPrefix + newVersion}
	versions := [2]string{oldVersion, newVersion}
	for i := range gitTags {
		if err := admitMappedBuildGitTag(gitTags[i], versions[i]); err != nil {
			return imageReplacement{}, false, err
		}
	}
	if oldVersion == newVersion {
		if mutate && evidence.prior != evidence.candidate {
			recordRenderedEvidence(desired, image, evidence)
		}
		return imageReplacement{}, false, nil
	}
	oldTarget := image.Target
	newTarget, err := replaceImageTag(oldTarget, newTargetTag)
	if err != nil {
		return imageReplacement{}, false, err
	}
	if !mutate {
		return imageReplacement{Old: oldTarget, New: newTarget}, true, nil
	}
	if ctx == nil || resolveTag == nil || tree == nil {
		return imageReplacement{}, false, errors.New("build update has no resolver context")
	}
	publicTag := build.ImageTagPrefix + newVersion
	if compatibilityBuild {
		publicSource = build.ImageRepository + ":" + publicTag
	} else {
		publicSource, err = replaceImageTag(publicSource, publicTag)
		if err != nil {
			return imageReplacement{}, false, err
		}
	}
	var digest string
	var releases [2]gitcache.Release
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(2)
	if compatibilityBuild {
		group.Go(func() error {
			var resolveErr error
			digest, resolveErr = resolveImageDigest(groupContext, publicSource)
			return resolveErr
		})
	}
	for i := range gitTags {
		i := i
		group.Go(func() error {
			var resolveErr error
			releases[i], resolveErr = resolveTag(groupContext, build.GitURL, gitTags[i])
			return resolveErr
		})
	}
	if err := group.Wait(); err != nil {
		return imageReplacement{}, false, err
	}
	graph, err := tree.CandidateData(buildGraphFile)
	if err != nil {
		return imageReplacement{}, false, err
	}
	newMaterial := ""
	if compatibilityBuild {
		newMaterial = build.ImageRepository + "@" + digest
		graph, err = updateCompatibilityBakeTarget(
			graph, image.Delivery.Default.BakeTarget, build.BakeContext,
			oldTarget, newTarget, oldTargetTag, newTargetTag, oldMaterial, newMaterial,
		)
		if err != nil {
			return imageReplacement{}, false, err
		}
	}
	graph, err = updateSourceBakeTarget(
		graph, image.Delivery.FullBuildTarget, build,
		imageRepository(oldTarget), mapping.TagPrefix, oldVersion, newVersion,
		releases[0].Commit, releases[1].Commit,
	)
	if err != nil {
		return imageReplacement{}, false, err
	}
	if err := tree.Set(buildGraphFile, graph); err != nil {
		return imageReplacement{}, false, err
	}
	image.Version = newVersion
	image.Target = newTarget
	if compatibilityBuild {
		image.Delivery.Default.Materials[materialIndex] = newMaterial
	} else {
		image.Delivery.Default.Source = publicSource
	}
	recordRenderedEvidence(desired, image, evidence)
	updateEvidenceTargets(
		desired, image.ID,
		oldTarget, newTarget, publicSource, "",
	)
	if compatibilityBuild {
		updateCrosswalkBuild(desired, *image)
	}
	updateLockedTarget(lock, image.ID, oldTarget, newTarget, publicSource, "")
	return imageReplacement{Old: oldTarget, New: newTarget}, true, nil
}

func admitMappedBuildGitTag(exactTag, artifactVersion string) error {
	tagVersion, err := semver.NewVersion(exactTag)
	if err != nil || tagVersion.Prerelease() == "" {
		return nil
	}
	artifact, err := semver.NewVersion(artifactVersion)
	if err != nil || artifact.Prerelease() == "" {
		return fmt.Errorf(
			"Git tag %s is a semantic prerelease but authoritative artifact version %s is not",
			exactTag, artifactVersion,
		)
	}
	return nil
}

func mappedUpstreamVersion(reference, prefix string) (string, string, error) {
	tag := imageTag(reference)
	if tag == "" {
		return "", "", errors.New("image tag is empty")
	}
	version := strings.TrimPrefix(tag, prefix)
	if version == "" || prefix+version != tag {
		return "", "", fmt.Errorf("tag %q does not use prefix %q", tag, prefix)
	}
	return version, tag, nil
}

func mappedBuildMaterial(materials []string, repository string) (int, string, error) {
	prefix := repository + "@sha256:"
	index := -1
	for i, material := range materials {
		if !strings.HasPrefix(material, prefix) {
			continue
		}
		if index >= 0 {
			return -1, "", fmt.Errorf("build mapping repeats image material %s", repository)
		}
		index = i
	}
	if index < 0 {
		return -1, "", fmt.Errorf("build mapping has no digest-pinned image material %s", repository)
	}
	return index, materials[index], nil
}

func updateCrosswalkBuild(desired *config.Document, image config.Image) {
	for i := range desired.Delivery.LegacyCrosswalk.Entries {
		entry := &desired.Delivery.LegacyCrosswalk.Entries[i]
		if entry.ImageID == image.ID && entry.CompatibilityBuild != nil {
			entry.CompatibilityBuild.Materials = append(entry.CompatibilityBuild.Materials[:0], image.Delivery.Default.Materials...)
			return
		}
	}
}

func updateCompatibilityBakeTarget(
	data []byte,
	name, contextName, oldTarget, newTarget, oldTag, newTag, oldMaterial, newMaterial string,
) ([]byte, error) {
	return updateStaticBakeTarget(data, name, func(target *staticBakeTarget) error {
		if len(target.tags) != 1 || target.tags[0] != oldTarget {
			return fmt.Errorf("Bake target %s tags do not match %s", name, oldTarget)
		}
		if target.contexts[contextName] != "docker-image://"+oldMaterial {
			return fmt.Errorf("Bake target %s context %s does not match %s", name, contextName, oldMaterial)
		}
		if target.args["ATUM_IMAGE_VERSION"] != oldTag {
			return fmt.Errorf("Bake target %s version does not match %s", name, oldTag)
		}
		target.tags[0] = newTarget
		target.contexts[contextName] = "docker-image://" + newMaterial
		target.args["ATUM_IMAGE_VERSION"] = newTag
		return nil
	})
}

func updateSourceBakeTarget(
	data []byte,
	name string,
	build *config.ImageBuildVersionMapping,
	repository, tagPrefix, oldVersion, newVersion, oldCommit, newCommit string,
) ([]byte, error) {
	oldTag := tagPrefix + oldVersion + build.FullTagSuffix
	newTag := tagPrefix + newVersion + build.FullTagSuffix
	oldSourceTag := build.GitTagPrefix + oldVersion
	newSourceTag := build.GitTagPrefix + newVersion
	oldSource := build.GitURL + "?tag=" + oldSourceTag + "&checksum=" + oldCommit
	newSource := build.GitURL + "?tag=" + newSourceTag + "&checksum=" + newCommit
	return updateStaticBakeTarget(data, name, func(target *staticBakeTarget) error {
		if len(target.tags) != 1 || target.tags[0] != repository+":"+oldTag {
			return fmt.Errorf("Bake target %s tags do not match source build version %s", name, oldVersion)
		}
		if target.contexts[build.GitContext] != oldSource {
			return fmt.Errorf("Bake target %s context %s does not match Git tag %s", name, build.GitContext, oldSourceTag)
		}
		if target.args["ATUM_IMAGE_VERSION"] != oldVersion || target.args["ATUM_IMAGE_REVISION"] != oldCommit {
			return fmt.Errorf("Bake target %s provenance does not match Git tag %s", name, oldSourceTag)
		}
		target.tags[0] = repository + ":" + newTag
		target.contexts[build.GitContext] = newSource
		target.args["ATUM_IMAGE_VERSION"] = newVersion
		target.args["ATUM_IMAGE_REVISION"] = newCommit
		return nil
	})
}

func updateStaticBakeTarget(
	data []byte,
	name string,
	update func(*staticBakeTarget) error,
) ([]byte, error) {
	target, err := loadStaticBakeTarget(data, name)
	if err != nil {
		return nil, err
	}
	if err := update(&target); err != nil {
		return nil, err
	}
	written, diagnostics := hclwrite.ParseConfig(data, buildGraphFile, hcl.Pos{Line: 1, Column: 1})
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("parse writable build graph: %s", diagnostics.Error())
	}
	var writeBlock *hclwrite.Block
	for _, block := range written.Body().Blocks() {
		labels := block.Labels()
		if block.Type() == "target" && len(labels) == 1 && labels[0] == name {
			writeBlock = block
			break
		}
	}
	if writeBlock == nil {
		return nil, fmt.Errorf("writable Bake target %s is missing", name)
	}
	writeBlock.Body().SetAttributeValue("tags", stringListValue(target.tags))
	writeBlock.Body().SetAttributeValue("contexts", stringMapValue(target.contexts))
	writeBlock.Body().SetAttributeValue("args", stringMapValue(target.args))
	result := written.Bytes()
	if _, diagnostics := hclparse.NewParser().ParseHCL(result, buildGraphFile); diagnostics.HasErrors() {
		return nil, fmt.Errorf("updated build graph is invalid: %s", diagnostics.Error())
	}
	return result, nil
}

func loadStaticBakeTarget(data []byte, name string) (staticBakeTarget, error) {
	parsed, diagnostics := hclparse.NewParser().ParseHCL(data, buildGraphFile)
	if diagnostics.HasErrors() {
		return staticBakeTarget{}, fmt.Errorf("parse build graph: %s", diagnostics.Error())
	}
	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		return staticBakeTarget{}, fmt.Errorf("build graph has unsupported body %T", parsed.Body)
	}
	var syntaxBlock *hclsyntax.Block
	for _, block := range body.Blocks {
		if block.Type == "target" && len(block.Labels) == 1 && block.Labels[0] == name {
			if syntaxBlock != nil {
				return staticBakeTarget{}, fmt.Errorf("Bake target %s is repeated", name)
			}
			syntaxBlock = block
		}
	}
	if syntaxBlock == nil {
		return staticBakeTarget{}, fmt.Errorf("Bake target %s is missing", name)
	}
	if _, matrix := syntaxBlock.Body.Attributes["matrix"]; matrix {
		return staticBakeTarget{}, fmt.Errorf("Bake target %s is a matrix template, not a concrete target", name)
	}
	if _, dynamicName := syntaxBlock.Body.Attributes["name"]; dynamicName {
		return staticBakeTarget{}, fmt.Errorf("Bake target %s overrides its concrete target name", name)
	}
	target, err := readStaticBakeTarget(name, syntaxBlock)
	if err != nil {
		return staticBakeTarget{}, err
	}
	return target, nil
}

func readStaticBakeTarget(name string, block *hclsyntax.Block) (staticBakeTarget, error) {
	tags, err := staticStringList(block.Body.Attributes["tags"])
	if err != nil {
		return staticBakeTarget{}, fmt.Errorf("Bake target %s tags: %w", name, err)
	}
	contexts, err := staticStringMap(block.Body.Attributes["contexts"])
	if err != nil {
		return staticBakeTarget{}, fmt.Errorf("Bake target %s contexts: %w", name, err)
	}
	args, err := staticStringMap(block.Body.Attributes["args"])
	if err != nil {
		return staticBakeTarget{}, fmt.Errorf("Bake target %s args: %w", name, err)
	}
	return staticBakeTarget{tags: tags, contexts: contexts, args: args}, nil
}

func staticStringList(attribute *hclsyntax.Attribute) ([]string, error) {
	if attribute == nil {
		return nil, errors.New("attribute is missing")
	}
	value, diagnostics := attribute.Expr.Value(nil)
	if diagnostics.HasErrors() || !value.IsKnown() || !value.CanIterateElements() {
		return nil, errors.New("attribute is not a static string list")
	}
	result := make([]string, 0, value.LengthInt())
	iterator := value.ElementIterator()
	for iterator.Next() {
		_, item := iterator.Element()
		if !item.IsKnown() || item.Type() != cty.String {
			return nil, errors.New("attribute contains a non-string value")
		}
		result = append(result, item.AsString())
	}
	return result, nil
}

func staticStringMap(attribute *hclsyntax.Attribute) (map[string]string, error) {
	if attribute == nil {
		return nil, errors.New("attribute is missing")
	}
	value, diagnostics := attribute.Expr.Value(nil)
	if diagnostics.HasErrors() || !value.IsKnown() || !value.CanIterateElements() {
		return nil, errors.New("attribute is not a static string object")
	}
	result := make(map[string]string, value.LengthInt())
	iterator := value.ElementIterator()
	for iterator.Next() {
		key, item := iterator.Element()
		if !key.IsKnown() || key.Type() != cty.String || !item.IsKnown() || item.Type() != cty.String {
			return nil, errors.New("attribute contains a non-string key or value")
		}
		result[key.AsString()] = item.AsString()
	}
	return result, nil
}

func stringListValue(values []string) cty.Value {
	items := make([]cty.Value, len(values))
	for i := range values {
		items[i] = cty.StringVal(values[i])
	}
	return cty.ListVal(items)
}

func stringMapValue(values map[string]string) cty.Value {
	items := make(map[string]cty.Value, len(values))
	for key, value := range values {
		items[key] = cty.StringVal(value)
	}
	return cty.ObjectVal(items)
}
