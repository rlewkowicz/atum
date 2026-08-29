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
	"sort"
	"strings"
	"sync/atomic"

	"atum/cli/config"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"
	"atum/cli/progress"
	"atum/cli/update"

	"golang.org/x/sync/errgroup"
	ocistore "oras.land/oras-go/v2/content/oci"
)

const seedPayloadSchema = "atum.dev/seed-payload/v1"

func (service *Service) prepareSeed(
	ctx context.Context,
	project *config.Project,
	local localDelivery,
) (ArtifactIdentity, error) {
	stageRoot, err := fssecure.EnsureDirectory(
		project.Root,
		filepath.Join(".atum", "state", "seed-stage"),
		0o700,
	)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	stage, err := os.MkdirTemp(stageRoot, ".seed-")
	if err != nil {
		return ArtifactIdentity{}, err
	}
	stageRelative, err := filepath.Rel(project.Root, stage)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	defer func() { _ = fssecure.RemoveTree(project.Root, stageRelative) }()
	registry, err := atumoci.NewClient(
		project.Desired.Delivery.Registry,
		atumoci.Credentials{},
	)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	defer registry.Clear()
	seed, err := service.prepareSeedArchive(
		ctx,
		project,
		registry,
		stage,
		effectiveParallelism(0, project.Desired.Updates.Parallelism),
		&local,
	)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	if err := validateSeedArchive(project, seed); err != nil {
		return ArtifactIdentity{}, err
	}
	destinationRelative := filepath.Join(
		".atum",
		"artifacts",
		"seed",
		"atum-seed-"+seed.Artifact.SHA256+".tar",
	)
	sourceRelative, err := filepath.Rel(
		project.Root,
		filepath.Join(stage, seed.Artifact.File),
	)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	if err := publishSeedArchive(
		project.Root,
		sourceRelative,
		destinationRelative,
		seed.Artifact,
	); err != nil {
		return ArtifactIdentity{}, err
	}
	return ArtifactIdentity{
		File:   filepath.ToSlash(destinationRelative),
		SHA256: seed.Artifact.SHA256,
		Size:   seed.Artifact.Size,
	}, nil
}

func publishSeedArchive(
	root, sourceRelative, destinationRelative string,
	identity archiveIdentity,
) error {
	destination, err := fssecure.Resolve(root, destinationRelative, true)
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
				return fmt.Errorf(
					"content-addressed seed %s is %s/%d, want %s/%d",
					destination,
					digest,
					size,
					identity.SHA256,
					identity.Size,
				)
			}
			return nil
		}
		if !errors.Is(openErr, os.ErrNotExist) {
			return openErr
		}
		published, err := fssecure.RenameRegularNoReplace(
			root,
			sourceRelative,
			destinationRelative,
		)
		if err != nil {
			return err
		}
		if published {
			return syncDirectory(filepath.Dir(destination))
		}
	}
}

type seedArchive struct {
	Artifact  archiveIdentity     `json:"artifact"`
	Manifest  archiveIdentity     `json:"manifest"`
	Checksums archiveIdentity     `json:"checksums"`
	Payload   seedPayloadManifest `json:"payload"`
}

type seedPayloadManifest struct {
	SchemaVersion   string             `json:"schemaVersion"`
	ForgejoURL      string             `json:"forgejoUrl"`
	HarborURL       string             `json:"harborUrl"`
	HarborVersion   string             `json:"harborVersion"`
	DockerArchive   archiveIdentity    `json:"dockerArchive"`
	HarborInstaller archiveIdentity    `json:"harborInstaller"`
	Images          []config.SeedImage `json:"images"`
}

func (service *Service) prepareSeedArchive(
	ctx context.Context,
	project *config.Project,
	registry *atumoci.Client,
	stage string,
	parallelism int,
	local *localDelivery,
) (seedArchive, error) {
	seedRoot := filepath.Join(stage, ".seed-payload")
	if err := os.MkdirAll(seedRoot, 0o700); err != nil {
		return seedArchive{}, fmt.Errorf("create seed payload stage: %w", err)
	}
	seedRelative, err := filepath.Rel(project.Root, seedRoot)
	if err != nil {
		return seedArchive{}, err
	}
	defer func() { _ = fssecure.RemoveTree(project.Root, seedRelative) }()

	images := make(
		[]config.SeedImage,
		0,
		2+len(project.Desired.Delivery.Seed.Harbor.Images),
	)
	images = append(images, project.Desired.Delivery.Seed.Forgejo.Image)
	images = append(images, project.Desired.Delivery.Seed.Harbor.Images...)
	images = append(images, project.Desired.Delivery.Seed.KubesprayFiles.Image)
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })

	var dockerArchive, installer archiveIdentity
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error {
		var imageErr error
		dockerArchive, imageErr = service.prepareSeedImages(
			groupContext, project, registry, seedRoot, images, parallelism, local,
		)
		return imageErr
	})
	group.Go(func() error {
		return runDeliveryWorker(groupContext, func() error {
			asset := project.Desired.Delivery.Seed.Harbor.Installer
			cached, fetchErr := update.FetchSeedAsset(groupContext, project.Root, asset)
			if fetchErr != nil {
				return fetchErr
			}
			relative, relativeErr := filepath.Rel(project.Root, cached)
			if relativeErr != nil {
				return relativeErr
			}
			installer, fetchErr = copyVerified(
				project.Root,
				relative,
				filepath.Join(seedRoot, asset.File),
				asset.File,
				asset.SHA256,
				config.SeedAssetLimit,
			)
			return fetchErr
		})
	})
	if err := group.Wait(); err != nil {
		return seedArchive{}, err
	}

	payload := seedPayloadManifest{
		SchemaVersion:   seedPayloadSchema,
		ForgejoURL:      project.Desired.Delivery.Seed.Forgejo.URL,
		HarborURL:       project.Desired.Delivery.Seed.Harbor.URL,
		HarborVersion:   project.Desired.Delivery.Seed.Harbor.Version,
		DockerArchive:   dockerArchive,
		HarborInstaller: installer,
		Images:          images,
	}
	manifestData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return seedArchive{}, fmt.Errorf("encode seed payload manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	manifest := archiveIdentity{File: "seed.json", SHA256: config.SHA256(manifestData), Size: int64(len(manifestData))}
	if err := writeRegular(filepath.Join(seedRoot, manifest.File), manifestData, 0o644); err != nil {
		return seedArchive{}, err
	}
	checksumData := []byte(fmt.Sprintf(
		"%s  %s\n%s  %s\n%s  %s\n",
		dockerArchive.SHA256, dockerArchive.File,
		installer.SHA256, installer.File,
		manifest.SHA256, manifest.File,
	))
	checksums := archiveIdentity{File: "SHA256SUMS", SHA256: config.SHA256(checksumData), Size: int64(len(checksumData))}
	if err := writeRegular(filepath.Join(seedRoot, checksums.File), checksumData, 0o644); err != nil {
		return seedArchive{}, err
	}
	artifact, err := writeDirectoryArchive(filepath.Join(stage, "seed", "atum-seed.tar"), seedRoot, "seed/atum-seed.tar")
	if err != nil {
		return seedArchive{}, fmt.Errorf("write deterministic seed payload: %w", err)
	}
	return seedArchive{Artifact: artifact, Manifest: manifest, Checksums: checksums, Payload: payload}, nil
}

func (service *Service) prepareSeedImages(
	ctx context.Context,
	project *config.Project,
	registry *atumoci.Client,
	seedRoot string,
	images []config.SeedImage,
	parallelism int,
	local *localDelivery,
) (archiveIdentity, error) {
	extraRoot := filepath.Join(seedRoot, ".oci")
	extraStore, err := ocistore.NewWithContext(ctx, extraRoot)
	if err != nil {
		return archiveIdentity{}, fmt.Errorf("create seed OCI stage: %w", err)
	}
	inputs := make([]dockerArchiveImage, len(images))
	progress.Start(
		ctx,
		progress.Platform,
		"seed-artifacts",
		"Seed artifacts",
		fmt.Sprintf("preparing %d bastion-only images", len(images)),
	)
	var completed atomic.Int64
	var copiedBytes atomic.Int64
	reportComplete := func(id string) {
		progress.UpdateBytes(
			ctx,
			progress.Platform,
			"seed-artifacts",
			"Seed artifacts",
			"prepared seed image "+id,
			int(completed.Add(1)),
			len(images),
			copiedBytes.Load(),
			0,
		)
	}
	lockedByID := make(map[string]config.LockedImage, len(project.Lock.Delivery.Images))
	for _, image := range project.Lock.Delivery.Images {
		lockedByID[image.ID] = image
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(effectiveParallelism(parallelism, 0))
	for index, image := range images {
		index, image := index, image
		group.Go(func() error {
			return runDeliveryWorker(groupContext, func() error {
				if local != nil {
					locked, lockedFound := lockedByID[image.ID]
					output, outputFound := local.mirrors[image.ID]
					if lockedFound && outputFound && locked.Digest == image.Digest && locked.Delivery.Type == "mirror" &&
						locked.Delivery.Source == image.Source && locked.Delivery.Digest == image.Digest {
						manifest, err := atumoci.LinuxAMD64Manifest(
							groupContext,
							output.store,
							output.descriptor,
						)
						if err != nil {
							return fmt.Errorf("select seed image %s: %w", image.ID, err)
						}
						inputs[index] = dockerArchiveImage{
							Reference: image.Source, Descriptor: manifest, Store: output.store,
						}
						reportComplete(image.ID)
						return nil
					}
				}
				descriptor, err := registry.CopyToStore(
					groupContext,
					image.Source,
					image.Digest,
					extraStore,
					"atum-seed.local/"+image.ID+":seed",
					func(delta int64) {
						progress.UpdateBytes(
							groupContext,
							progress.Platform,
							"seed-artifacts",
							"Seed artifacts",
							"caching seed image "+image.ID,
							int(completed.Load()),
							len(images),
							copiedBytes.Add(delta),
							0,
						)
					},
				)
				if err != nil {
					return err
				}
				manifest, err := atumoci.LinuxAMD64Manifest(
					groupContext,
					extraStore,
					descriptor,
				)
				if err != nil {
					return fmt.Errorf("select seed image %s: %w", image.ID, err)
				}
				inputs[index] = dockerArchiveImage{
					Reference:  image.Source,
					Descriptor: manifest,
					Store:      extraStore,
				}
				reportComplete(image.ID)
				return nil
			})
		})
	}
	if err := group.Wait(); err != nil {
		return archiveIdentity{}, err
	}
	identity, err := writeDockerArchive(ctx, filepath.Join(seedRoot, "images.tar"), "images.tar", inputs)
	if err != nil {
		return archiveIdentity{}, err
	}
	extraRelative, err := filepath.Rel(project.Root, extraRoot)
	if err != nil {
		return archiveIdentity{}, err
	}
	if err := fssecure.RemoveTree(project.Root, extraRelative); err != nil {
		return archiveIdentity{}, fmt.Errorf("remove seed OCI stage: %w", err)
	}
	progress.Done(
		ctx,
		progress.Platform,
		"seed-artifacts",
		"Seed artifacts",
		fmt.Sprintf("%d images archived in %d bytes", len(images), identity.Size),
	)
	return identity, nil
}

func validateSeedArchive(project *config.Project, seed seedArchive) error {
	desired := project.Desired.Delivery.Seed
	if !validArchive(seed.Artifact, "seed/atum-seed.tar") || !validArchive(seed.Manifest, "seed.json") ||
		!validArchive(seed.Checksums, "SHA256SUMS") || seed.Payload.SchemaVersion != seedPayloadSchema ||
		seed.Payload.ForgejoURL != desired.Forgejo.URL || seed.Payload.HarborURL != desired.Harbor.URL ||
		seed.Payload.HarborVersion != desired.Harbor.Version ||
		seed.Payload.DockerArchive.File != "images.tar" || !validArchive(seed.Payload.DockerArchive, "images.tar") ||
		seed.Payload.HarborInstaller.File != desired.Harbor.Installer.File ||
		seed.Payload.HarborInstaller.SHA256 != desired.Harbor.Installer.SHA256 ||
		seed.Payload.HarborInstaller.Size != desired.Harbor.Installer.Size {
		return fmt.Errorf("minimal seed payload does not match desired state")
	}
	wanted := make([]config.SeedImage, 0, 2+len(desired.Harbor.Images))
	wanted = append(wanted, desired.Forgejo.Image)
	wanted = append(wanted, desired.Harbor.Images...)
	wanted = append(wanted, desired.KubesprayFiles.Image)
	sort.Slice(wanted, func(i, j int) bool { return wanted[i].ID < wanted[j].ID })
	if len(seed.Payload.Images) != len(wanted) {
		return fmt.Errorf("minimal seed image inventory is incomplete")
	}
	for index := range wanted {
		if seed.Payload.Images[index] != wanted[index] {
			return fmt.Errorf("minimal seed image %d does not match desired state", index)
		}
	}
	if strings.Contains(seed.Artifact.File, "\\") {
		return fmt.Errorf("minimal seed artifact path is not portable")
	}
	return nil
}

func validArchive(identity archiveIdentity, expectedFile string) bool {
	if identity.File != expectedFile || identity.Size <= 0 ||
		len(identity.SHA256) != sha256.Size*2 ||
		strings.ToLower(identity.SHA256) != identity.SHA256 {
		return false
	}
	decoded, err := hex.DecodeString(identity.SHA256)
	return err == nil && len(decoded) == sha256.Size
}

func copyVerified(
	root, sourceRelative, destination, artifactPath, expectedSHA string,
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
	if info.Size() <= 0 || maxSize >= 0 && info.Size() > maxSize {
		return archiveIdentity{}, fmt.Errorf(
			"%s has invalid size %d",
			sourceRelative,
			info.Size(),
		)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return archiveIdentity{}, err
	}
	output, err := os.OpenFile(
		destination,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return archiveIdentity{}, err
	}
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	hash := sha256.New()
	size, copyErr := io.CopyBuffer(
		io.MultiWriter(output, hash),
		input,
		*buffer,
	)
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
		return archiveIdentity{}, fmt.Errorf(
			"%s copied as %s/%d, want %s/%d",
			sourceRelative,
			actual,
			size,
			expectedSHA,
			info.Size(),
		)
	}
	return archiveIdentity{
		File:   artifactPath,
		SHA256: actual,
		Size:   size,
	}, nil
}
