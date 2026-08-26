package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"

	"atum/cli/config"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"
	"atum/cli/progress"
	"atum/cli/secretvalue"
	"atum/cli/update"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	ocistore "oras.land/oras-go/v2/content/oci"
)

const (
	bundleSchema     = "atum.dev/bundle/v3"
	bundleLockSchema = "atum.dev/bundle-lock/v3"
)

type bundleManifest struct {
	SchemaVersion   string            `json:"schemaVersion"`
	Platform        string            `json:"platform"`
	DesiredSHA256   string            `json:"desiredSha256"`
	InventorySHA256 string            `json:"inventorySha256"`
	GraphSHA256     string            `json:"graphSha256"`
	LockSHA256      string            `json:"lockSha256"`
	ImagesOCISHA256 string            `json:"imagesOciSha256"`
	Source          sourceManifest    `json:"source"`
	Images          []bundleImage     `json:"images"`
	Charts          []bundleChart     `json:"charts"`
	Seed            bundleSeed        `json:"seed"`
}

type sourceManifest struct {
	Atum           atumSnapshot         `json:"atum"`
	SnapshotSHA256 string               `json:"snapshotSha256"`
}

type atumSnapshot struct {
	archiveIdentity
	Commit string `json:"commit"`
}

type bundleImage struct {
	config.LockedImage
	SeedReference string `json:"seedReference"`
}

type bundleChart struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Target        string `json:"target"`
	ArchiveSHA256 string `json:"archiveSha256"`
	Size          int64  `json:"size"`
	File          string `json:"file"`
}

type bundleSidecar struct {
	SchemaVersion string          `json:"schemaVersion"`
	Artifact      archiveIdentity `json:"artifact"`
	Bundle        bundleManifest  `json:"bundle"`
}

func (service *Service) Bundle(ctx context.Context, options BundleOptions) (BundleResult, error) {
	if options.Reproduce && (options.Locked || options.Push || options.Publish.Force) {
		return BundleResult{}, errors.New("locked reproduction cannot be combined with registry or force options")
	}
	if options.Locked && options.Publish.Force {
		return BundleResult{}, errors.New("--force cannot be combined with --locked")
	}
	if (options.Push || options.Locked) &&
		(service.env("HARBOR_USERNAME") == "" || service.env("HARBOR_PASSWORD") == "") {
		return BundleResult{}, errors.New("HARBOR_USERNAME and HARBOR_PASSWORD are required for a registry-backed deployment bundle")
	}
	unlock, err := update.LockProject(ctx, service.root)
	if err != nil {
		return BundleResult{}, fmt.Errorf("lock project state: %w", err)
	}
	defer unlock()
	if err := update.RecoverLocked(service.root); err != nil {
		return BundleResult{}, fmt.Errorf("recover interrupted update: %w", err)
	}
	project, err := config.LoadWithOptions(service.root, config.LoadOptions{AllowStale: !options.Locked && !options.Reproduce})
	if err != nil {
		return BundleResult{}, err
	}
	executionProject, executionCurrent, err := loadExecutionProject(project)
	if err != nil {
		return BundleResult{}, err
	}
	if executionCurrent {
		project = executionProject
	}
	if err := config.ValidateSourceSnapshot(project); err != nil {
		return BundleResult{}, fmt.Errorf("validate exact source handoff: %w", err)
	}
	if project.Lock.Delivery.Pending() && (options.Locked || options.Reproduce) {
		return BundleResult{}, errors.New("pending image delivery must be resolved before locked bundle reproduction")
	}
	if (options.Locked || options.Reproduce) && !executionCurrent {
		return BundleResult{}, errors.New("local image publication receipt is absent or stale; rerun image publication")
	}
	requestedProfile := options.Publish.Profile
	if options.Reproduce {
		if requestedProfile != "" && requestedProfile != project.Lock.Delivery.Profile {
			return BundleResult{}, fmt.Errorf(
				"reproduction profile is %s, not committed profile %s",
				requestedProfile,
				project.Lock.Delivery.Profile,
			)
		}
		requestedProfile = project.Lock.Delivery.Profile
		options.Publish.Profile = requestedProfile
	}
	if requestedProfile == "" {
		requestedProfile = project.Desired.Delivery.Policy.DefaultProfile
	}
	if !options.Push && !options.Publish.Force && requestedProfile == project.Lock.Delivery.Profile {
		if validationErr := project.Validate(); validationErr == nil {
			result, reused, err := service.reuseCurrentBundle(ctx, project)
			if err != nil {
				return BundleResult{}, err
			}
			if reused {
				return result, nil
			}
		}
	}
	var local *localDelivery
	if !options.Locked {
		if len(options.Publish.Targets) != 0 ||
			(options.Publish.Group != "" && options.Publish.Group != "platform" && options.Publish.Group != "all") {
			return BundleResult{}, errors.New("deployment bundle always resolves the complete platform image inventory")
		}
		resolved, err := service.resolveLocalDelivery(ctx, project, options.Publish)
		if err != nil {
			return BundleResult{}, err
		}
		if options.Reproduce {
			if !reflect.DeepEqual(resolved.lock, project.Lock.Delivery) {
				return BundleResult{}, errors.New("locally reproduced image graph differs from the committed delivery lock")
			}
		} else {
			bundle, err := reusableBundle(project, resolved.lock)
			if err != nil {
				return BundleResult{}, fmt.Errorf("identify reusable deployment bundle: %w", err)
			}
			project.Lock.Delivery = resolved.lock
			project.ExecutionBundle = bundle
		}
		local = &resolved
	} else if options.Publish.Profile != "" && options.Publish.Profile != project.Lock.Delivery.Profile {
		return BundleResult{}, fmt.Errorf("locked delivery profile is %s, not %s", project.Lock.Delivery.Profile, options.Publish.Profile)
	}
	if !options.Push && !options.Publish.Force {
		result, reused, err := service.reuseCurrentBundle(ctx, project)
		if err != nil {
			return BundleResult{}, err
		}
		if reused {
			return result, nil
		}
	}
	result, err := service.bundleLocked(ctx, project, options, local)
	if err != nil {
		return BundleResult{}, err
	}
	if err := persistExecutionProject(project); err != nil {
		return BundleResult{}, err
	}
	if err := pruneBundleArtifacts(project, project.ExecutionBundle); err != nil {
		return BundleResult{}, err
	}
	return result, nil
}

func (service *Service) reuseCurrentBundle(
	ctx context.Context,
	project *config.Project,
) (BundleResult, bool, error) {
	result, reused, err := reuseExistingBundle(project)
	if err != nil || !reused {
		return result, reused, err
	}
	if err := pruneBundleArtifacts(project, project.ExecutionBundle); err != nil {
		return BundleResult{}, false, err
	}
	service.logger.InfoContext(ctx, "reuse deployment bundle", "sha256", result.Bundle.SHA256)
	return result, true, nil
}

func (service *Service) bundleLocked(
	ctx context.Context,
	project *config.Project,
	options BundleOptions,
	local *localDelivery,
) (BundleResult, error) {
	snapshotLock := project.Lock
	snapshotLockData, err := json.MarshalIndent(snapshotLock, "", "  ")
	if err != nil {
		return BundleResult{}, fmt.Errorf("encode bundle lock snapshot: %w", err)
	}
	snapshotLockData = append(snapshotLockData, '\n')
	sourceLockData, err := config.SourceLockData(project)
	if err != nil {
		return BundleResult{}, err
	}
	lockSHA := config.SHA256(snapshotLockData)
	artifactRelative := filepath.Join(".atum", "artifacts", lockSHA)
	artifactRoot, err := fssecure.EnsureDirectory(project.Root, artifactRelative, 0o700)
	if err != nil {
		return BundleResult{}, fmt.Errorf("create artifact directory: %w", err)
	}
	stage, err := os.MkdirTemp(artifactRoot, ".bundle-stage-")
	if err != nil {
		return BundleResult{}, fmt.Errorf("create bundle stage: %w", err)
	}
	stageRelative := filepath.Join(artifactRelative, filepath.Base(stage))
	defer func() { _ = fssecure.RemoveTree(project.Root, stageRelative) }()

	password := service.env("HARBOR_PASSWORD")
	credentials := atumoci.Credentials{
		Username: service.env("HARBOR_USERNAME"),
		Password: secretvalue.New([]byte(password)),
		CACert:   []byte(service.env("HARBOR_CA_CRT")),
	}
	password = ""
	defer credentials.Clear()
	registry, err := atumoci.NewClient(project.Desired.Delivery.Registry, credentials)
	if err != nil {
		return BundleResult{}, err
	}
	defer registry.Clear()
	parallelism := effectiveParallelism(0, project.Desired.Updates.Parallelism)
	ctx = withDeliveryBudget(ctx, parallelism)
	manifest := bundleManifest{
		SchemaVersion:   bundleSchema,
		Platform:        project.Lock.Delivery.Platform,
		DesiredSHA256:   project.DesiredSHA256,
		InventorySHA256: project.Lock.Delivery.InventorySHA256,
		GraphSHA256:     project.Lock.Delivery.GraphSHA256,
		LockSHA256:      lockSHA,
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error {
		identity, images, err := service.bundleImages(
			groupContext, project, registry, stage, parallelism, local, options.Push && local != nil,
		)
		if err == nil {
			manifest.ImagesOCISHA256 = identity.SHA256
			manifest.Images = images
		}
		return err
	})
	group.Go(func() error {
		source, err := service.bundleSources(project, stage, sourceLockData)
		if err == nil {
			manifest.Source = source
		}
		return err
	})
	group.Go(func() error {
		charts, err := service.bundleCharts(groupContext, project, stage, parallelism)
		if err == nil {
			manifest.Charts = charts
		}
		return err
	})
	group.Go(func() error {
		seed, err := service.bundleSeed(groupContext, project, registry, stage, parallelism, local)
		if err == nil {
			manifest.Seed = seed
		}
		return err
	})
	if err := group.Wait(); err != nil {
		return BundleResult{}, err
	}
	progress.Update(ctx, progress.Platform, "bundle", "Deployment bundle",
		"runtime images, sources, charts, and seed services assembled", len(manifest.Images), len(manifest.Images))
	if err := validateBundleManifest(project, manifest); err != nil {
		return BundleResult{}, fmt.Errorf("validate deployment bundle manifest: %w", err)
	}
	if err := writeRegular(filepath.Join(stage, config.DesiredFilename), project.DesiredData, 0o644); err != nil {
		return BundleResult{}, err
	}
	if err := writeRegular(filepath.Join(stage, config.LockFilename), snapshotLockData, 0o644); err != nil {
		return BundleResult{}, err
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BundleResult{}, err
	}
	manifestData = append(manifestData, '\n')
	if err := writeRegular(filepath.Join(stage, "bundle.json"), manifestData, 0o644); err != nil {
		return BundleResult{}, err
	}
	pendingRelative := filepath.Join(artifactRelative, ".atum-bundle.tar")
	pending := filepath.Join(project.Root, pendingRelative)
	progress.Update(ctx, progress.Platform, "bundle", "Deployment bundle",
		"writing deterministic deployment archive", 0, 0)
	identity, err := writeDirectoryArchive(pending, stage, "")
	if err != nil {
		return BundleResult{}, fmt.Errorf("write deterministic bundle: %w", err)
	}
	filename := "atum-bundle-" + identity.SHA256 + ".tar"
	finalRelative := filepath.Join(artifactRelative, filename)
	finalPath := filepath.Join(project.Root, finalRelative)
	if err := publishBundleArchive(project.Root, pendingRelative, finalRelative, identity); err != nil {
		return BundleResult{}, fmt.Errorf("publish bundle artifact: %w", err)
	}
	identity.File = filepath.ToSlash(finalRelative)
	sidecar := bundleSidecar{SchemaVersion: bundleLockSchema, Artifact: identity, Bundle: manifest}
	sidecarData, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return BundleResult{}, err
	}
	sidecarData = append(sidecarData, '\n')
	sidecarRelative := filepath.Join(artifactRelative, "atum-bundle-"+identity.SHA256+".lock.json")
	if err := fssecure.WriteRegular(project.Root, sidecarRelative, sidecarData, 0o644); err != nil {
		return BundleResult{}, err
	}
	bundle := config.Bundle{
		File:             identity.File,
		SHA256:           identity.SHA256,
		Size:             identity.Size,
		AtumSourceSHA256: manifest.Source.SnapshotSHA256,
	}
	if options.Push {
		target := project.Desired.Delivery.Registry.Host + "/seed-artifacts/atum-bundle:sha256-" + identity.SHA256
		published, err := registry.PushArtifact(ctx, finalPath, identity.SHA256, identity.Size, target)
		if err != nil {
			return BundleResult{}, err
		}
		bundle.OCIReference = target
		bundle.OCIDigest = published.Digest.String()
	} else if current := project.ExecutionBundle; current != nil &&
		current.File == bundle.File && current.SHA256 == bundle.SHA256 && current.Size == bundle.Size {
		bundle.OCIReference = current.OCIReference
		bundle.OCIDigest = current.OCIDigest
	}
	project.ExecutionBundle = &bundle
	return BundleResult{Bundle: bundle, Path: finalPath}, nil
}

func publishBundleArchive(root, pendingRelative, destinationRelative string, identity archiveIdentity) error {
	destination, err := fssecure.Resolve(root, destinationRelative, true)
	if err != nil {
		return err
	}
	pending, err := fssecure.Resolve(root, pendingRelative, false)
	if err != nil {
		return err
	}
	for {
		file, openErr := fssecure.OpenRegular(root, destinationRelative)
		if openErr == nil {
			digest, size, err := readerSHA256(file)
			closeErr := file.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if digest != identity.SHA256 || size != identity.Size {
				return fmt.Errorf("content-addressed destination %s is %s/%d, want %s/%d",
					destination, digest, size, identity.SHA256, identity.Size)
			}
			if err := os.Remove(pending); err != nil {
				return err
			}
			break
		}
		if !errors.Is(openErr, os.ErrNotExist) {
			return openErr
		}
		published, err := fssecure.RenameRegularNoReplace(root, pendingRelative, destinationRelative)
		if err != nil {
			return err
		}
		if published {
			break
		}
	}
	return syncDirectory(filepath.Dir(destination))
}

func (service *Service) bundleImages(
	ctx context.Context,
	project *config.Project,
	registry *atumoci.Client,
	stage string,
	parallelism int,
	local *localDelivery,
	publishLocal bool,
) (archiveIdentity, []bundleImage, error) {
	layoutRoot := filepath.Join(stage, ".images-oci")
	store, err := ocistore.NewWithContext(ctx, layoutRoot)
	if err != nil {
		return archiveIdentity{}, nil, fmt.Errorf("create bundle OCI layout: %w", err)
	}
	images := make([]bundleImage, len(project.Lock.Delivery.Images))
	descriptors := make([]ocispec.Descriptor, len(project.Lock.Delivery.Images))
	progress.Update(ctx, progress.Platform, "bundle", "Deployment bundle",
		"packing runtime images into OCI layout", 0, len(images))
	var packed atomic.Int64
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for index, image := range project.Lock.Delivery.Images {
		index, image := index, image
		group.Go(func() error {
			return runDeliveryWorker(groupContext, func() error {
				seedReference := atumoci.SeedReference(image.ID)
			var descriptor ocispec.Descriptor
			var err error
			if local == nil {
				descriptor, err = registry.CopyToStore(groupContext, image.Target, image.Digest, store, seedReference)
			} else if image.Delivery.Type == "mirror" {
				output, exists := local.mirrors[image.ID]
				if !exists {
					return fmt.Errorf("local mirror output for %s is missing", image.ID)
				}
				if output.descriptor.Digest.String() != image.Digest {
					return fmt.Errorf("local mirror output for %s is %s, want %s", image.ID, output.descriptor.Digest, image.Digest)
				}
				descriptor, err = atumoci.CopyTargetToStore(
					groupContext, output.store, image.Digest, store, seedReference,
				)
			} else if output, exists := local.builds[image.ID]; exists {
				descriptor, err = atumoci.CopyTargetToStore(groupContext, output.store, image.Digest, store, seedReference)
			} else {
				return fmt.Errorf("local build output for %s is missing", image.ID)
			}
			if err != nil {
				return err
			}
			var validateErr error
			if image.Delivery.Type == "mirror" {
				validateErr = atumoci.ValidateLinuxAMD64Manifest(groupContext, store, descriptor)
			} else {
				validateErr = atumoci.ValidateLinuxAMD64(groupContext, store, descriptor)
			}
			if validateErr != nil {
				return fmt.Errorf("validate bundled image %s: %w", image.ID, validateErr)
			}
			if publishLocal {
				published, err := registry.CopyFromStore(groupContext, store, image.Digest, image.Target)
				if err != nil {
					return err
				}
				if err := registry.ValidateLinuxAMD64(groupContext, image.Target, published); err != nil {
					return err
				}
				resolved, err := registry.Resolve(groupContext, image.Target)
				if err != nil {
					return err
				}
				if resolved.Digest != published.Digest {
					return fmt.Errorf("published image %s resolved to %s, want %s", image.ID, resolved.Digest, published.Digest)
				}
			}
			images[index] = bundleImage{LockedImage: image, SeedReference: seedReference}
			descriptors[index] = descriptor
			current := int(packed.Add(1))
			progress.Update(groupContext, progress.Platform, "bundle", "Deployment bundle",
				"packed runtime image "+image.ID, current, len(images))
				return nil
			})
		})
	}
	if err := group.Wait(); err != nil {
		return archiveIdentity{}, nil, err
	}
	progress.Update(ctx, progress.Platform, "bundle", "Deployment bundle",
		"writing deterministic OCI image archive", len(images), len(images))
	index := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Manifests: make([]ocispec.Descriptor, len(descriptors)),
	}
	for position, descriptor := range descriptors {
		descriptor.Annotations = map[string]string{ocispec.AnnotationRefName: images[position].SeedReference}
		descriptor.Data = nil
		descriptor.URLs = nil
		index.Manifests[position] = descriptor
	}
	indexData, err := json.Marshal(index)
	if err != nil {
		return archiveIdentity{}, nil, fmt.Errorf("encode deterministic OCI index: %w", err)
	}
	if err := writeRegular(filepath.Join(layoutRoot, ocispec.ImageIndexFile), append(indexData, '\n'), 0o644); err != nil {
		return archiveIdentity{}, nil, fmt.Errorf("write deterministic OCI index: %w", err)
	}
	identity, err := writeDirectoryArchive(filepath.Join(stage, "images.oci.tar"), layoutRoot, "images.oci.tar")
	if err != nil {
		return archiveIdentity{}, nil, err
	}
	layoutRelative, err := filepath.Rel(project.Root, layoutRoot)
	if err != nil {
		return archiveIdentity{}, nil, fmt.Errorf("resolve temporary OCI layout: %w", err)
	}
	if err := fssecure.RemoveTree(project.Root, layoutRelative); err != nil {
		return archiveIdentity{}, nil, fmt.Errorf("remove temporary OCI layout: %w", err)
	}
	return identity, images, nil
}

func (service *Service) bundleSources(
	project *config.Project,
	stage string,
	snapshotLock []byte,
) (sourceManifest, error) {
	sourceRoot := filepath.Join(stage, "sources")
	if err := os.MkdirAll(sourceRoot, 0o700); err != nil {
		return sourceManifest{}, err
	}
	atumIdentity, snapshotIdentity, err := writeGitArchive(
		filepath.Join(sourceRoot, "atum.tar"),
		project.Root,
		"sources/atum.tar",
		map[string][]byte{config.LockFilename: snapshotLock},
	)
	if err != nil {
		return sourceManifest{}, fmt.Errorf("archive Atum handoff: %w", err)
	}
	return sourceManifest{
		Atum: atumSnapshot{
			archiveIdentity: atumIdentity,
			Commit:          snapshotIdentity.Commit,
		},
		SnapshotSHA256: snapshotIdentity.SHA256,
	}, nil
}

func (service *Service) bundleCharts(
	ctx context.Context,
	project *config.Project,
	stage string,
	parallelism int,
) ([]bundleChart, error) {
	charts := make([]bundleChart, len(project.Lock.Resolved.Artifacts))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(min(parallelism, 8))
	for index, chart := range project.Lock.Resolved.Artifacts {
		index, chart := index, chart
		group.Go(func() error {
			return runDeliveryWorker(groupContext, func() error {
				identity, err := copyVerified(
				project.Root,
				chart.File,
				filepath.Join(stage, "charts", filepath.Base(chart.File)),
				"charts/"+filepath.Base(chart.File),
				chart.ArchiveSHA256,
				config.ChartArchiveLimit,
			)
			if err != nil {
				return err
			}
			charts[index] = bundleChart{
				ID:            chart.ID,
				Name:          chart.Name,
				Version:       chart.Version,
				Target:        chart.Target,
				ArchiveSHA256: chart.ArchiveSHA256,
				Size:          identity.Size,
				File:          "charts/" + filepath.Base(chart.File),
			}
				return nil
			})
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return charts, nil
}

func copyVerified(
	root, sourceRelative, destination, bundlePath, expectedSHA string,
	maxSize int64,
) (archiveIdentity, error) {
	input, err := fssecure.OpenRegular(root, sourceRelative)
	if err != nil {
		return archiveIdentity{}, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return archiveIdentity{}, err
	}
	if info.Size() <= 0 || (maxSize >= 0 && info.Size() > maxSize) {
		return archiveIdentity{}, fmt.Errorf("%s has invalid size %d", sourceRelative, info.Size())
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return archiveIdentity{}, err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return archiveIdentity{}, err
	}
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	hash := sha256.New()
	size, copyErr := io.CopyBuffer(io.MultiWriter(output, hash), input, *buffer)
	closeErr := output.Close()
	if copyErr != nil {
		return archiveIdentity{}, copyErr
	}
	if closeErr != nil {
		return archiveIdentity{}, closeErr
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if size != info.Size() || actual != expectedSHA {
		_ = os.Remove(destination)
		return archiveIdentity{}, fmt.Errorf("%s copied as %s/%d, want %s/%d", sourceRelative, actual, size, expectedSHA, info.Size())
	}
	return archiveIdentity{File: bundlePath, SHA256: actual, Size: size}, nil
}

func writeRegular(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
