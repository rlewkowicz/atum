package delivery

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	atumoci "atum/cli/oci"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

const dockerArchiveMetadataLimit = 4 << 20

type dockerArchiveImage struct {
	Reference  string
	Descriptor ocispec.Descriptor
	Store      content.ReadOnlyStorage
}

type dockerArchiveEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type dockerArchiveBlob struct {
	name       string
	descriptor ocispec.Descriptor
	store      content.ReadOnlyStorage
}

// writeDockerArchive emits Docker's loadable image archive deterministically.
// Metadata remains bounded, image bodies are streamed, and common layers are
// written once even when multiple seed services share them.
func writeDockerArchive(
	ctx context.Context,
	destination, artifactPath string,
	input []dockerArchiveImage,
) (archiveIdentity, error) {
	if len(input) == 0 {
		return archiveIdentity{}, fmt.Errorf("seed Docker image inventory is empty")
	}
	images := append([]dockerArchiveImage(nil), input...)
	sort.Slice(images, func(i, j int) bool { return images[i].Reference < images[j].Reference })
	entries := make([]dockerArchiveEntry, len(images))
	blobs := make(map[string]dockerArchiveBlob, len(images)*8)
	for index, image := range images {
		if image.Store == nil || image.Reference == "" {
			return archiveIdentity{}, fmt.Errorf("seed Docker image %d has an incomplete source", index)
		}
		if err := atumoci.ValidateLinuxAMD64Manifest(ctx, image.Store, image.Descriptor); err != nil {
			return archiveIdentity{}, fmt.Errorf("validate seed Docker image %s: %w", image.Reference, err)
		}
		manifestData, err := readDockerMetadata(ctx, image.Store, image.Descriptor)
		if err != nil {
			return archiveIdentity{}, fmt.Errorf("read seed Docker manifest %s: %w", image.Reference, err)
		}
		var manifest ocispec.Manifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return archiveIdentity{}, fmt.Errorf("decode seed Docker manifest %s: %w", image.Reference, err)
		}
		configName := manifest.Config.Digest.Encoded() + ".json"
		if err := addDockerBlob(blobs, dockerArchiveBlob{name: configName, descriptor: manifest.Config, store: image.Store}); err != nil {
			return archiveIdentity{}, err
		}
		layers := make([]string, len(manifest.Layers))
		for layerIndex, layer := range manifest.Layers {
			name, err := dockerLayerName(layer)
			if err != nil {
				return archiveIdentity{}, fmt.Errorf("seed Docker image %s: %w", image.Reference, err)
			}
			layers[layerIndex] = name
			if err := addDockerBlob(blobs, dockerArchiveBlob{name: name, descriptor: layer, store: image.Store}); err != nil {
				return archiveIdentity{}, err
			}
		}
		entries[index] = dockerArchiveEntry{Config: configName, RepoTags: []string{image.Reference}, Layers: layers}
	}
	manifestData, err := json.Marshal(entries)
	if err != nil {
		return archiveIdentity{}, fmt.Errorf("encode seed Docker archive manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	names := make([]string, 0, len(blobs))
	for name := range blobs {
		names = append(names, name)
	}
	sort.Strings(names)
	return writeArchive(destination, artifactPath, func(writer *tar.Writer, buffer []byte) error {
		for _, name := range names {
			if err := writeDockerBlob(ctx, writer, buffer, blobs[name]); err != nil {
				return err
			}
		}
		return writeBytesEntry(writer, "manifest.json", manifestData, 0o644)
	})
}

func addDockerBlob(blobs map[string]dockerArchiveBlob, blob dockerArchiveBlob) error {
	if blob.descriptor.Size <= 0 || blob.descriptor.Digest.Validate() != nil {
		return fmt.Errorf("Docker archive blob %s has an invalid descriptor", blob.name)
	}
	if existing, found := blobs[blob.name]; found {
		if existing.descriptor.Digest != blob.descriptor.Digest || existing.descriptor.Size != blob.descriptor.Size {
			return fmt.Errorf("Docker archive blob %s has conflicting descriptors", blob.name)
		}
		return nil
	}
	blobs[blob.name] = blob
	return nil
}

func dockerLayerName(layer ocispec.Descriptor) (string, error) {
	extension := ""
	switch layer.MediaType {
	case ocispec.MediaTypeImageLayer, "application/vnd.docker.image.rootfs.diff.tar":
		extension = ".tar"
	case ocispec.MediaTypeImageLayerGzip, "application/vnd.docker.image.rootfs.diff.tar.gzip":
		extension = ".tar.gz"
	case ocispec.MediaTypeImageLayerZstd:
		extension = ".tar.zst"
	default:
		return "", fmt.Errorf("layer %s uses unsupported media type %s", layer.Digest, layer.MediaType)
	}
	return layer.Digest.Encoded() + extension, nil
}

func readDockerMetadata(
	ctx context.Context,
	store content.ReadOnlyStorage,
	descriptor ocispec.Descriptor,
) ([]byte, error) {
	if descriptor.Size <= 0 || descriptor.Size > dockerArchiveMetadataLimit {
		return nil, fmt.Errorf("descriptor %s has invalid metadata size %d", descriptor.Digest, descriptor.Size)
	}
	reader, err := store.Fetch(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, descriptor.Size+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("read descriptor %s: %w", descriptor.Digest, errors.Join(readErr, closeErr))
	}
	verifier := descriptor.Digest.Verifier()
	_, _ = verifier.Write(data)
	if int64(len(data)) != descriptor.Size || !verifier.Verified() {
		return nil, fmt.Errorf("descriptor %s content does not match %d bytes", descriptor.Digest, descriptor.Size)
	}
	return data, nil
}

func writeDockerBlob(ctx context.Context, writer *tar.Writer, buffer []byte, blob dockerArchiveBlob) error {
	if err := writer.WriteHeader(normalizedHeader(blob.name, 0o644, blob.descriptor.Size, tar.TypeReg, "")); err != nil {
		return err
	}
	reader, err := blob.store.Fetch(ctx, blob.descriptor)
	if err != nil {
		return fmt.Errorf("fetch Docker archive blob %s: %w", blob.descriptor.Digest, err)
	}
	verifier := blob.descriptor.Digest.Verifier()
	limited := &io.LimitedReader{R: reader, N: blob.descriptor.Size + 1}
	written, copyErr := io.CopyBuffer(io.MultiWriter(writer, verifier), limited, buffer)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return fmt.Errorf("write Docker archive blob %s: %w", blob.descriptor.Digest, errors.Join(copyErr, closeErr))
	}
	if written != blob.descriptor.Size || limited.N != 1 || !verifier.Verified() {
		return fmt.Errorf("Docker archive blob %s yielded %d bytes, want %d", blob.descriptor.Digest, written, blob.descriptor.Size)
	}
	return nil
}
