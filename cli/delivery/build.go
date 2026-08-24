package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"
	"atum/cli/process"
	"atum/cli/progress"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	ocistore "oras.land/oras-go/v2/content/oci"
)

const (
	indexLimit       = 4 << 20
	layoutEntryLimit = 10_000
)

type buildOutput struct {
	image      selectedImage
	relative   string
	absolute   string
	store      *ocistore.Store
	descriptor ocispec.Descriptor
}

func (service *Service) publishBuilds(
	ctx context.Context,
	project *config.Project,
	registry *atumoci.Client,
	builds []selectedImage,
	profile string,
	graphSHA string,
	options PublishOptions,
	current map[string]config.LockedImage,
) ([]config.LockedImage, int, int, error) {
	if len(builds) == 0 {
		return nil, 0, 0, nil
	}
	entries := make([]config.LockedImage, 0, len(builds))
	remaining := make([]selectedImage, 0, len(builds))
	registryReused := 0
	for _, image := range builds {
		if !options.Force {
			if locked, exists := reusableEntry(project, profile, image, current); exists {
				if descriptor, err := registry.Resolve(ctx, image.Image.Target); err == nil && descriptor.Digest.String() == locked.Digest {
					if err := registry.ValidateLinuxAMD64(ctx, image.Image.Target, descriptor); err != nil {
						return nil, 0, 0, err
					}
					entries = append(entries, locked)
					registryReused++
					service.logger.InfoContext(ctx, "reuse built image", "image", image.Image.ID, "digest", locked.Digest)
					continue
				}
			}
		}
		remaining = append(remaining, image)
	}
	outputs, built, localReused, err := service.prepareBuildSet(ctx, project, remaining, profile, graphSHA, options, false)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(outputs) == 0 {
		return entries, 0, registryReused, nil
	}
	publishedEntries := make([]config.LockedImage, len(outputs))
	parallelism := options.Parallelism
	if parallelism <= 0 {
		parallelism = project.Desired.Updates.Parallelism
	}
	if parallelism <= 0 {
		parallelism = defaultParallelism
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for index := range outputs {
		index := index
		group.Go(func() error {
			entry, err := service.publishBuildOutput(groupContext, registry, outputs[index])
			if err != nil {
				return err
			}
			publishedEntries[index] = entry
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, 0, 0, err
	}
	entries = append(entries, publishedEntries...)
	return entries, built, registryReused + localReused, nil
}

func (service *Service) buildLocally(
	ctx context.Context,
	project *config.Project,
	builds []selectedImage,
	profile, graphSHA string,
	options PublishOptions,
) (map[string]buildOutput, map[string]config.LockedImage, int, int, error) {
	progress.Start(ctx, progress.Platform, "compatibility-builds", "Compatibility builds",
		fmt.Sprintf("resolving %d build outputs", len(builds)))
	prepared, built, reused, err := service.prepareBuildSet(ctx, project, builds, profile, graphSHA, options, true)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "compatibility-builds", "Compatibility builds", err)
		return nil, nil, 0, 0, err
	}
	outputs := make(map[string]buildOutput, len(prepared))
	entries := make(map[string]config.LockedImage, len(prepared))
	for _, output := range prepared {
		entry, err := lockedBuildOutput(ctx, output)
		if err != nil {
			progress.Fail(ctx, progress.Platform, "compatibility-builds", "Compatibility builds", err)
			return nil, nil, 0, 0, err
		}
		outputs[entry.ID] = output
		entries[entry.ID] = entry
	}
	progress.Done(ctx, progress.Platform, "compatibility-builds", "Compatibility builds",
		fmt.Sprintf("%d built, %d reused", built, reused))
	return outputs, entries, built, reused, nil
}

func (service *Service) prepareBuildSet(
	ctx context.Context,
	project *config.Project,
	builds []selectedImage,
	profile, graphSHA string,
	options PublishOptions,
	localCache bool,
) ([]buildOutput, int, int, error) {
	if len(builds) == 0 {
		return nil, 0, 0, nil
	}
	outputs := make([]buildOutput, len(builds))
	pending := make([]buildOutput, 0, len(builds))
	pendingIndexes := make([]int, 0, len(builds))
	reused := 0
	for index, image := range builds {
		output, cached, err := service.prepareBuildOutput(ctx, project, image, graphSHA, options.Force)
		if err != nil {
			return nil, 0, 0, err
		}
		outputs[index] = output
		if cached {
			reused++
			continue
		}
		pending = append(pending, output)
		pendingIndexes = append(pendingIndexes, index)
	}
	if len(pending) == 0 {
		return outputs, 0, reused, nil
	}
	workspace, cleanup, err := materializeBuildWorkspace(project.Root)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("materialize immutable build source: %w", err)
	}
	defer cleanup()
	snapshotProject := *project
	snapshotProject.Root = workspace
	snapshotGraph, err := config.DeliveryGraphSHA256(&snapshotProject, profile)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("verify immutable build source: %w", err)
	}
	if snapshotGraph != graphSHA {
		return nil, 0, 0, fmt.Errorf("immutable build source graph is %s, want %s", snapshotGraph, graphSHA)
	}
	if err := service.runBake(ctx, project, workspace, pending, options, localCache); err != nil {
		return nil, 0, 0, err
	}
	currentGraph, err := config.DeliveryGraphSHA256(project, profile)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("recheck delivery graph after build: %w", err)
	}
	if currentGraph != graphSHA {
		return nil, 0, 0, fmt.Errorf("delivery graph changed during build: found %s, want %s", currentGraph, graphSHA)
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(max(1, project.Desired.Delivery.Policy.BuildParallelism))
	for position, outputIndex := range pendingIndexes {
		position, outputIndex := position, outputIndex
		group.Go(func() error {
			store, descriptor, err := openBuildLayout(groupContext, pending[position].absolute)
			if err != nil {
				return fmt.Errorf("read build output for %s: %w", pending[position].image.Image.ID, err)
			}
			outputs[outputIndex].store = store
			outputs[outputIndex].descriptor = descriptor
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, 0, 0, err
	}
	return outputs, len(pending), reused, nil
}

func (service *Service) prepareBuildOutput(
	ctx context.Context,
	project *config.Project,
	image selectedImage,
	graphSHA string,
	force bool,
) (buildOutput, bool, error) {
	if !fssecure.ValidName(image.Delivery.BakeTarget) {
		return buildOutput{}, false, fmt.Errorf("image %s has unsafe Bake target %q", image.Image.ID, image.Delivery.BakeTarget)
	}
	parentRelative := filepath.Join(".atum", "cache", "builds", graphSHA)
	if _, err := fssecure.EnsureDirectory(project.Root, parentRelative, 0o700); err != nil {
		return buildOutput{}, false, fmt.Errorf("create build cache: %w", err)
	}
	relative := filepath.Join(parentRelative, image.InputSHA+"-"+image.Delivery.BakeTarget)
	absolute, err := fssecure.Resolve(project.Root, relative, true)
	if err != nil {
		return buildOutput{}, false, err
	}
	output := buildOutput{image: image, relative: relative, absolute: absolute}
	if !force {
		store, descriptor, openErr := openBuildLayout(ctx, absolute)
		if openErr == nil {
			output.store = store
			output.descriptor = descriptor
			service.logger.InfoContext(ctx, "reuse local build output", "image", image.Image.ID, "digest", descriptor.Digest)
			return output, true, nil
		}
		if !errors.Is(openErr, os.ErrNotExist) {
			service.logger.WarnContext(ctx, "discard invalid local build output", "image", image.Image.ID, "error", openErr)
		}
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if !info.IsDir() {
			return buildOutput{}, false, fmt.Errorf("build cache path %s is not a directory", relative)
		}
		if err := fssecure.RemoveTree(project.Root, relative); err != nil {
			return buildOutput{}, false, fmt.Errorf("remove stale build cache %s: %w", relative, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return buildOutput{}, false, fmt.Errorf("inspect build cache %s: %w", relative, statErr)
	}
	return output, false, nil
}

func (service *Service) runBake(
	ctx context.Context,
	project *config.Project,
	workspace string,
	outputs []buildOutput,
	options PublishOptions,
	localCache bool,
) error {
	session, cleanup, err := service.dockerConfig(project, !localCache)
	if err != nil {
		return err
	}
	defer cleanup()
	builder, err := service.prepareBuilder(ctx, project, session)
	if err != nil {
		return err
	}
	cacheRoot, err := fssecure.EnsureDirectory(project.Root, filepath.Join(".atum", "cache"), 0o700)
	if err != nil {
		return fmt.Errorf("create Buildx output root: %w", err)
	}
	baseArguments := []string{
		"buildx", "bake",
		"--allow=fs.read=" + workspace,
		"--allow=fs.write=" + cacheRoot,
		"--file", bakeFilename,
		"--builder", builder,
	}
	arguments := append([]string(nil), baseArguments...)
	targets := make([]string, 0, len(outputs))
	targetTags := make(map[string]string, len(outputs))
	cacheOverrides := make([]string, 0)
	seen := make(map[string]string, len(outputs))
	for _, output := range outputs {
		target := output.image.Delivery.BakeTarget
		if previous, exists := seen[target]; exists {
			return fmt.Errorf("images %s and %s share Bake target %s", previous, output.image.Image.ID, target)
		}
		seen[target] = output.image.Image.ID
		targets = append(targets, target)
		targetTags[target] = output.image.Image.Target
		arguments = append(arguments,
			"--set", target+".tags="+output.image.Image.Target,
			"--set", target+".output=type=oci,dest="+output.absolute+",tar=false,oci-mediatypes=true,rewrite-timestamp=true",
		)
	}
	cachePaths := make(map[string]string)
	if localCache {
		reachable, err := config.ReachableBakeTargets(project, targets)
		if err != nil {
			return fmt.Errorf("resolve local cache graph: %w", err)
		}
		cacheRootRelative := filepath.Join(".atum", "cache", "buildkit")
		if _, err := fssecure.EnsureDirectory(project.Root, cacheRootRelative, 0o700); err != nil {
			return fmt.Errorf("create local BuildKit cache: %w", err)
		}
		cachePaths = make(map[string]string, len(reachable))
		cacheOverrides = make([]string, 0, len(reachable)*4)
		for _, target := range reachable {
			cacheRelative := filepath.Join(cacheRootRelative, target)
			cachePath, err := fssecure.EnsureDirectory(project.Root, cacheRelative, 0o700)
			if err != nil {
				return fmt.Errorf("create local cache for %s: %w", target, err)
			}
			cachePaths[target] = cachePath
			cacheOverrides = append(cacheOverrides,
				"--set", target+".cache-from=type=local,src="+cachePath,
				"--set", target+".cache-to=",
			)
		}
		arguments = append(arguments, cacheOverrides...)
	}
	arguments = append(arguments, targets...)
	sbom, err := bootstrapMirrorReference(project, "sbom-scanner")
	if err != nil {
		return err
	}
	command := process.Command{
		Name: service.docker,
		Dir:  filepath.Join(workspace, buildDirectory),
		Env: []string{
			"ATUM_BOOTSTRAP_OUTPUT=type=registry,oci-mediatypes=true,rewrite-timestamp=true",
			"ATUM_CACHE_REGISTRY=" + project.Desired.Delivery.Registry.Host + "/buildkit",
			"ATUM_DEBIAN_IMAGE=" + project.Desired.Delivery.Policy.BuildBase,
			"ATUM_PLATFORM=" + project.Desired.Project.Platform,
			"ATUM_SBOM_GENERATOR_IMAGE=" + sbom,
			"BUILDX_CONFIG=" + session.buildxConfig,
			"DOCKER_CONFIG=" + session.dockerConfig,
			"SOURCE_DATE_EPOCH=0",
		},
	}
	service.logger.InfoContext(ctx, "build image graph", "targets", strings.Join(targets, ","))
	progress.Update(ctx, progress.Platform, "compatibility-builds", "Compatibility builds",
		fmt.Sprintf("BuildKit solving %d targets in parallel", len(targets)), 0, len(targets))
	command.Args = arguments
	if err := service.runner.Run(ctx, command); err != nil {
		return err
	}
	// BuildKit's local exporter cannot safely write shared layer references
	// from multiple Bake targets concurrently. Preserve the parallel image
	// solve above, then export each target's complete cache graph serially.
	persisted := 0
	for _, target := range targets {
		cachePath, enabled := cachePaths[target]
		if !enabled {
			continue
		}
		cacheArguments := append([]string(nil), baseArguments...)
		cacheArguments = append(cacheArguments, cacheOverrides...)
		cacheArguments = append(cacheArguments,
			"--set", target+".tags="+targetTags[target],
			"--set", target+".output=type=cacheonly",
			"--set", target+".cache-from=type=local,src="+cachePath,
			"--set", target+".cache-to=type=local,dest="+cachePath+",mode=max",
			target,
		)
		service.logger.InfoContext(ctx, "persist BuildKit cache", "target", target)
		command.Args = cacheArguments
		if err := service.runner.Run(ctx, command); err != nil {
			return fmt.Errorf("persist BuildKit cache for %s: %w", target, err)
		}
		persisted++
		progress.Update(ctx, progress.Platform, "compatibility-builds", "Compatibility builds",
			"persisted BuildKit cache "+target, persisted, len(targets))
	}
	return nil
}

func lockedBuildOutput(ctx context.Context, output buildOutput) (config.LockedImage, error) {
	if output.store == nil || output.descriptor.Digest == "" {
		return config.LockedImage{}, fmt.Errorf("build output for %s is incomplete", output.image.Image.ID)
	}
	if err := atumoci.ValidateLinuxAMD64(ctx, output.store, output.descriptor); err != nil {
		return config.LockedImage{}, fmt.Errorf("validate build output %s: %w", output.image.Image.ID, err)
	}
	return config.LockedImage{
		ID:          output.image.Image.ID,
		Target:      output.image.Image.Target,
		Digest:      output.descriptor.Digest.String(),
		InputSHA256: output.image.InputSHA,
		Delivery:    output.image.Delivery,
	}, nil
}

func (service *Service) publishBuildOutput(
	ctx context.Context,
	registry *atumoci.Client,
	output buildOutput,
) (config.LockedImage, error) {
	entry, err := lockedBuildOutput(ctx, output)
	if err != nil {
		return config.LockedImage{}, err
	}
	service.logger.InfoContext(ctx, "publish built image", "image", output.image.Image.ID, "digest", entry.Digest)
	if _, err := registry.CopyFromStore(ctx, output.store, entry.Digest, output.image.Image.Target); err != nil {
		return config.LockedImage{}, err
	}
	resolved, err := registry.Resolve(ctx, output.image.Image.Target)
	if err != nil {
		return config.LockedImage{}, err
	}
	if resolved.Digest != output.descriptor.Digest {
		return config.LockedImage{}, fmt.Errorf("published image %s resolved to %s, want %s", output.image.Image.ID, resolved.Digest, output.descriptor.Digest)
	}
	return entry, nil
}

func openBuildLayout(ctx context.Context, directory string) (*ocistore.Store, ocispec.Descriptor, error) {
	if err := verifyOCILayoutTree(directory); err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	indexPath := filepath.Join(directory, ocispec.ImageIndexFile)
	info, err := os.Lstat(indexPath)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > indexLimit {
		return nil, ocispec.Descriptor{}, fmt.Errorf("OCI index is not a bounded regular file")
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if len(index.Manifests) != 1 {
		return nil, ocispec.Descriptor{}, fmt.Errorf("OCI output has %d roots, want one", len(index.Manifests))
	}
	store, err := ocistore.NewWithContext(ctx, directory)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	descriptor, err := store.Resolve(ctx, index.Manifests[0].Digest.String())
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if descriptor.Digest != index.Manifests[0].Digest || descriptor.Size != index.Manifests[0].Size ||
		descriptor.MediaType != index.Manifests[0].MediaType {
		return nil, ocispec.Descriptor{}, fmt.Errorf("OCI root descriptor changed while opening output")
	}
	if err := atumoci.ValidateLinuxAMD64(ctx, store, descriptor); err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	return store, descriptor, nil
}

func verifyOCILayoutTree(directory string) error {
	root, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if root.Mode()&os.ModeSymlink != 0 || !root.IsDir() {
		return fmt.Errorf("OCI output is not a real directory")
	}
	entries := 0
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > layoutEntryLimit {
			return fmt.Errorf("OCI output exceeds %d filesystem entries", layoutEntryLimit)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("OCI output contains unsupported path %s", path)
		}
		return nil
	})
}
