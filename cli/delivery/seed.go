package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"
	"atum/cli/update"

	"golang.org/x/sync/errgroup"
	ocistore "oras.land/oras-go/v2/content/oci"
)

const seedPayloadSchema = "atum.dev/seed-payload/v1"

type bundleSeed struct {
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

func (service *Service) bundleSeed(
	ctx context.Context,
	project *config.Project,
	registry *atumoci.Client,
	stage string,
	parallelism int,
	local *localDelivery,
) (bundleSeed, error) {
	seedRoot := filepath.Join(stage, ".seed-payload")
	if err := os.MkdirAll(seedRoot, 0o700); err != nil {
		return bundleSeed{}, fmt.Errorf("create seed payload stage: %w", err)
	}
	seedRelative, err := filepath.Rel(project.Root, seedRoot)
	if err != nil {
		return bundleSeed{}, err
	}
	defer func() { _ = fssecure.RemoveTree(project.Root, seedRelative) }()

	images := make([]config.SeedImage, 0, 1+len(project.Desired.Delivery.Seed.Harbor.Images))
	images = append(images, project.Desired.Delivery.Seed.Forgejo.Image)
	images = append(images, project.Desired.Delivery.Seed.Harbor.Images...)
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })

	var dockerArchive, installer archiveIdentity
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error {
		var imageErr error
		dockerArchive, imageErr = service.bundleSeedImages(
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
		return bundleSeed{}, err
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
		return bundleSeed{}, fmt.Errorf("encode seed payload manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	manifest := archiveIdentity{File: "seed.json", SHA256: config.SHA256(manifestData), Size: int64(len(manifestData))}
	if err := writeRegular(filepath.Join(seedRoot, manifest.File), manifestData, 0o644); err != nil {
		return bundleSeed{}, err
	}
	checksumData := []byte(fmt.Sprintf(
		"%s  %s\n%s  %s\n%s  %s\n",
		dockerArchive.SHA256, dockerArchive.File,
		installer.SHA256, installer.File,
		manifest.SHA256, manifest.File,
	))
	checksums := archiveIdentity{File: "SHA256SUMS", SHA256: config.SHA256(checksumData), Size: int64(len(checksumData))}
	if err := writeRegular(filepath.Join(seedRoot, checksums.File), checksumData, 0o644); err != nil {
		return bundleSeed{}, err
	}
	artifact, err := writeDirectoryArchive(filepath.Join(stage, "seed", "atum-seed.tar"), seedRoot, "seed/atum-seed.tar")
	if err != nil {
		return bundleSeed{}, fmt.Errorf("write deterministic seed payload: %w", err)
	}
	return bundleSeed{Artifact: artifact, Manifest: manifest, Checksums: checksums, Payload: payload}, nil
}

func (service *Service) bundleSeedImages(
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
					inputs[index] = dockerArchiveImage{
						Reference: image.Source, Descriptor: output.descriptor, Store: output.store,
					}
					return nil
				}
			}
			descriptor, err := registry.CopyToStore(
				groupContext,
				image.Source,
				image.Digest,
				extraStore,
				"atum-seed.local/"+image.ID+":seed",
			)
			if err != nil {
				return err
			}
			if err := atumoci.ValidateLinuxAMD64Manifest(groupContext, extraStore, descriptor); err != nil {
				return fmt.Errorf("validate seed image %s: %w", image.ID, err)
			}
			inputs[index] = dockerArchiveImage{Reference: image.Source, Descriptor: descriptor, Store: extraStore}
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
	return identity, nil
}

func validateBundleSeed(project *config.Project, seed bundleSeed) error {
	desired := project.Desired.Delivery.Seed
	if !validArchive(seed.Artifact, "seed/atum-seed.tar") || !validArchive(seed.Manifest, "seed.json") ||
		!validArchive(seed.Checksums, "SHA256SUMS") || seed.Payload.SchemaVersion != seedPayloadSchema ||
		seed.Payload.ForgejoURL != desired.Forgejo.URL || seed.Payload.HarborURL != desired.Harbor.URL ||
		seed.Payload.HarborVersion != desired.Harbor.Version ||
		seed.Payload.DockerArchive.File != "images.tar" || !validArchive(seed.Payload.DockerArchive, "images.tar") ||
		seed.Payload.HarborInstaller.File != desired.Harbor.Installer.File ||
		seed.Payload.HarborInstaller.SHA256 != desired.Harbor.Installer.SHA256 ||
		seed.Payload.HarborInstaller.Size != desired.Harbor.Installer.Size {
		return fmt.Errorf("deployment bundle seed payload does not match desired state")
	}
	wanted := make([]config.SeedImage, 0, 1+len(desired.Harbor.Images))
	wanted = append(wanted, desired.Forgejo.Image)
	wanted = append(wanted, desired.Harbor.Images...)
	sort.Slice(wanted, func(i, j int) bool { return wanted[i].ID < wanted[j].ID })
	if len(seed.Payload.Images) != len(wanted) {
		return fmt.Errorf("deployment bundle seed image inventory is incomplete")
	}
	for index := range wanted {
		if seed.Payload.Images[index] != wanted[index] {
			return fmt.Errorf("deployment bundle seed image %d does not match desired state", index)
		}
	}
	if strings.Contains(seed.Artifact.File, "\\") {
		return fmt.Errorf("deployment bundle seed artifact path is not portable")
	}
	return nil
}
