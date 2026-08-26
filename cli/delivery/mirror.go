package delivery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	ocistore "oras.land/oras-go/v2/content/oci"
)

type mirrorOutput struct {
	store      *ocistore.Store
	descriptor ocispec.Descriptor
}

func (service *Service) prepareMirrorOutput(
	ctx context.Context,
	project *config.Project,
	registry *atumoci.Client,
	image selectedImage,
	report func(int64),
) (mirrorOutput, error) {
	digest, found := strings.CutPrefix(image.Delivery.Digest, "sha256:")
	decoded, decodeErr := hex.DecodeString(digest)
	if !found || decodeErr != nil || !fssecure.ValidName(image.Image.ID) || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
		return mirrorOutput{}, fmt.Errorf("official image %s has an invalid cache identity", image.Image.ID)
	}
	parentRelative := filepath.Join(".atum", "cache", "oci", "mirrors")
	if _, err := fssecure.EnsureDirectory(project.Root, parentRelative, 0o700); err != nil {
		return mirrorOutput{}, fmt.Errorf("create OCI mirror cache: %w", err)
	}
	relative := filepath.Join(parentRelative, image.Image.ID+"-"+digest)
	absolute, err := fssecure.Resolve(project.Root, relative, true)
	if err != nil {
		return mirrorOutput{}, err
	}
	if output, err := openMirrorOutput(ctx, absolute, image.Delivery.Digest); err == nil {
		service.logger.InfoContext(ctx, "reuse official image cache", "image", image.Image.ID, "digest", image.Delivery.Digest)
		return output, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		service.logger.WarnContext(ctx, "discard invalid official image cache", "image", image.Image.ID, "error", err)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if !info.IsDir() {
			return mirrorOutput{}, fmt.Errorf("OCI mirror cache path %s is not a directory", relative)
		}
		if err := fssecure.RemoveTree(project.Root, relative); err != nil {
			return mirrorOutput{}, fmt.Errorf("remove stale OCI mirror cache %s: %w", relative, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return mirrorOutput{}, fmt.Errorf("inspect OCI mirror cache %s: %w", relative, statErr)
	}
	absolute, err = fssecure.EnsureDirectory(project.Root, relative, 0o700)
	if err != nil {
		return mirrorOutput{}, err
	}
	store, err := ocistore.NewWithContext(ctx, absolute)
	if err != nil {
		return mirrorOutput{}, fmt.Errorf("create OCI mirror cache for %s: %w", image.Image.ID, err)
	}
	service.logger.InfoContext(ctx, "cache official image", "image", image.Image.ID, "source", image.Delivery.Source)
	descriptor, err := registry.CopyToStore(
		ctx,
		image.Delivery.Source,
		image.Delivery.Digest,
		store,
		atumoci.SeedReference(image.Image.ID),
		report,
	)
	if err != nil {
		return mirrorOutput{}, err
	}
	if err := atumoci.ValidateLinuxAMD64Manifest(ctx, store, descriptor); err != nil {
		return mirrorOutput{}, fmt.Errorf("validate cached official image %s: %w", image.Image.ID, err)
	}
	return mirrorOutput{store: store, descriptor: descriptor}, nil
}

func openMirrorOutput(ctx context.Context, directory, digest string) (mirrorOutput, error) {
	if err := verifyOCILayoutTree(directory); err != nil {
		return mirrorOutput{}, err
	}
	store, err := ocistore.NewWithContext(ctx, directory)
	if err != nil {
		return mirrorOutput{}, err
	}
	descriptor, err := store.Resolve(ctx, digest)
	if err != nil {
		return mirrorOutput{}, err
	}
	if descriptor.Digest.String() != digest {
		return mirrorOutput{}, fmt.Errorf("cached OCI image resolves to %s, want %s", descriptor.Digest, digest)
	}
	if err := atumoci.ValidateLinuxAMD64Manifest(ctx, store, descriptor); err != nil {
		return mirrorOutput{}, err
	}
	return mirrorOutput{store: store, descriptor: descriptor}, nil
}
