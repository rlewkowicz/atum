package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"atum/cli/fssecure"
	atumoci "atum/cli/oci"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
)

const bundleOCIMetadataLimit = 4 << 20

// bundleImageStore opens every blob beneath the fssecure project boundary.
// Its reference map is immutable after construction and safe for concurrent
// registry publication.
type bundleImageStore struct {
	root       string
	blobRoot   string
	references map[string]ocispec.Descriptor
}

func (store *bundleImageStore) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return ocispec.Descriptor{}, err
	}
	descriptor, exists := store.references[reference]
	if !exists {
		return ocispec.Descriptor{}, fmt.Errorf("resolve bundled OCI reference %s: %w", reference, errdef.ErrNotFound)
	}
	return descriptor, nil
}

func (store *bundleImageStore) Fetch(
	ctx context.Context,
	descriptor ocispec.Descriptor,
) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relative, err := store.blobPath(descriptor)
	if err != nil {
		return nil, err
	}
	file, err := fssecure.OpenRegular(store.root, relative)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Size() != descriptor.Size {
		_ = file.Close()
		return nil, fmt.Errorf("bundled OCI blob %s is %d bytes, want %d", descriptor.Digest, info.Size(), descriptor.Size)
	}
	return file, nil
}

func (store *bundleImageStore) Exists(ctx context.Context, descriptor ocispec.Descriptor) (bool, error) {
	file, err := store.Fetch(ctx, descriptor)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, file.Close()
}

func (store *bundleImageStore) blobPath(descriptor ocispec.Descriptor) (string, error) {
	if err := descriptor.Digest.Validate(); err != nil || descriptor.Size <= 0 {
		return "", fmt.Errorf("bundled OCI descriptor %s/%d is invalid", descriptor.Digest, descriptor.Size)
	}
	return filepath.Join(
		store.blobRoot,
		descriptor.Digest.Algorithm().String(),
		descriptor.Digest.Encoded(),
	), nil
}

func validateMaterializedImages(
	ctx context.Context,
	root, cacheRelative string,
	manifest bundleManifest,
) (*bundleImageStore, map[string]map[string]struct{}, error) {
	imageRelative := filepath.Join(cacheRelative, "images")
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err := readBundleOCIJSON(root, filepath.Join(imageRelative, ocispec.ImageLayoutFile), &layout); err != nil {
		return nil, nil, fmt.Errorf("read bundled OCI layout identity: %w", err)
	}
	if layout.ImageLayoutVersion != ocispec.ImageLayoutVersion {
		return nil, nil, fmt.Errorf("bundled OCI layout version is %q", layout.ImageLayoutVersion)
	}
	var index ocispec.Index
	if err := readBundleOCIJSON(root, filepath.Join(imageRelative, ocispec.ImageIndexFile), &index); err != nil {
		return nil, nil, fmt.Errorf("read bundled OCI index: %w", err)
	}
	if index.SchemaVersion != 2 || index.MediaType != "" || index.ArtifactType != "" ||
		index.Subject != nil || len(index.Annotations) != 0 || len(index.Manifests) != len(manifest.Images) {
		return nil, nil, errors.New("bundled OCI index has an unexpected structure or image count")
	}
	store := &bundleImageStore{
		root:       root,
		blobRoot:   filepath.Join(imageRelative, "blobs"),
		references: make(map[string]ocispec.Descriptor, len(manifest.Images)*2),
	}
	runtimeDigests := make(map[string]map[string]struct{}, len(manifest.Images))
	verifier := atumoci.NewBlobVerifier()
	for position, image := range manifest.Images {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		descriptor := index.Manifests[position]
		if descriptor.Digest.String() != image.Digest || descriptor.Size <= 0 ||
			len(descriptor.Annotations) != 1 ||
			descriptor.Annotations[ocispec.AnnotationRefName] != image.SeedReference ||
			len(descriptor.URLs) != 0 || len(descriptor.Data) != 0 {
			return nil, nil, fmt.Errorf("bundled OCI index entry %d does not match image %s", position, image.ID)
		}
		for _, reference := range []string{image.Digest, image.SeedReference} {
			if prior, duplicate := store.references[reference]; duplicate &&
				(prior.Digest != descriptor.Digest || prior.Size != descriptor.Size || prior.MediaType != descriptor.MediaType) {
				return nil, nil, fmt.Errorf("bundled OCI reference %s resolves with conflicting descriptors", reference)
			}
			store.references[reference] = descriptor
		}
		if _, duplicate := runtimeDigests[image.Target]; duplicate {
			return nil, nil, fmt.Errorf("bundled OCI target %s is duplicated", image.Target)
		}
		var (
			digests map[string]struct{}
			err     error
		)
		if image.Delivery.Type == "mirror" {
			digests, err = verifier.RuntimeManifestDigestsWithContent(ctx, store, descriptor)
		} else {
			digests, err = verifier.RuntimeDigestsWithContent(ctx, store, descriptor)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("validate bundled OCI image %s: %w", image.ID, err)
		}
		runtimeDigests[image.Target] = digests
	}
	return store, runtimeDigests, nil
}

func readBundleOCIJSON(root, relative string, target any) error {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, bundleOCIMetadataLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(data) == 0 || len(data) > bundleOCIMetadataLimit {
		return fmt.Errorf("OCI metadata %s has invalid size %d", relative, len(data))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("OCI metadata contains multiple JSON values")
	}
	return nil
}
