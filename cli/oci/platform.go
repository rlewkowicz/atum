package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

const manifestLimit = 4 << 20

const graphDescriptorLimit = 100_000

type descriptorIdentity struct {
	size int64
}

type descriptorExpansion struct {
	digest    digest.Digest
	mediaType string
}

// BlobVerifier streams every unique image layer through its descriptor digest
// once. A verifier is intentionally reusable across a complete OCI inventory
// and is not safe for concurrent use.
type BlobVerifier struct {
	verified map[digest.Digest]descriptorIdentity
	expanded map[descriptorExpansion]struct{}
	buffer   []byte
}

func NewBlobVerifier() *BlobVerifier {
	return &BlobVerifier{
		verified: make(map[digest.Digest]descriptorIdentity, 512),
		expanded: make(map[descriptorExpansion]struct{}, 128),
		buffer:   make([]byte, 128<<10),
	}
}

// ValidateLinuxAMD64Manifest requires one exact runnable manifest. Official
// mirror pins use this stricter contract so a bundle never retains unrelated
// architectures from a multi-platform source index.
func ValidateLinuxAMD64Manifest(ctx context.Context, source content.ReadOnlyStorage, root ocispec.Descriptor) error {
	switch root.MediaType {
	case ocispec.MediaTypeImageManifest, "application/vnd.docker.distribution.manifest.v2+json":
		return ValidateLinuxAMD64(ctx, source, root)
	default:
		return fmt.Errorf("OCI mirror root %s has media type %s, want an exact image manifest", root.Digest, root.MediaType)
	}
}

// ValidateLinuxAMD64 proves that a root is either one linux/amd64 manifest or
// an attested index containing exactly one runnable linux/amd64 manifest.
func ValidateLinuxAMD64(ctx context.Context, source content.ReadOnlyStorage, root ocispec.Descriptor) error {
	_, err := runtimeDigests(ctx, source, root, nil)
	return err
}

// RuntimeDigestsWithContent validates the complete local image graph while
// returning the same runtime identities as RuntimeDigests. Shared layers are
// hashed once across calls made through the same verifier.
func (verifier *BlobVerifier) RuntimeDigestsWithContent(
	ctx context.Context,
	source content.ReadOnlyStorage,
	root ocispec.Descriptor,
) (map[string]struct{}, error) {
	if verifier == nil {
		return nil, fmt.Errorf("OCI blob verifier is nil")
	}
	if err := verifier.VerifyGraph(ctx, source, root); err != nil {
		return nil, err
	}
	return runtimeDigests(ctx, source, root, verifier)
}

func (verifier *BlobVerifier) RuntimeManifestDigestsWithContent(
	ctx context.Context,
	source content.ReadOnlyStorage,
	root ocispec.Descriptor,
) (map[string]struct{}, error) {
	if root.MediaType != ocispec.MediaTypeImageManifest &&
		root.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return nil, fmt.Errorf("OCI mirror root %s has media type %s, want an exact image manifest", root.Digest, root.MediaType)
	}
	return verifier.RuntimeDigestsWithContent(ctx, source, root)
}

// RuntimeDigests validates one runnable linux/amd64 graph and returns the
// exact root, selected manifest, and image-config digests a CRI implementation
// may expose as ContainerStatus.imageID. Layer digests are intentionally not
// accepted as runtime identities.
func RuntimeDigests(
	ctx context.Context,
	source content.ReadOnlyStorage,
	root ocispec.Descriptor,
) (map[string]struct{}, error) {
	return runtimeDigests(ctx, source, root, nil)
}

func runtimeDigests(
	ctx context.Context,
	source content.ReadOnlyStorage,
	root ocispec.Descriptor,
	verifier *BlobVerifier,
) (map[string]struct{}, error) {
	if err := root.Digest.Validate(); err != nil || root.Size <= 0 || root.Size > manifestLimit {
		return nil, fmt.Errorf("OCI root descriptor %s/%d is invalid", root.Digest, root.Size)
	}
	descriptor := root
	accepted := map[string]struct{}{root.Digest.String(): {}}
	switch root.MediaType {
	case ocispec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.list.v2+json":
		data, err := fetchBounded(ctx, source, root)
		if err != nil {
			return nil, fmt.Errorf("read OCI index %s: %w", root.Digest, err)
		}
		var index ocispec.Index
		if err := json.Unmarshal(data, &index); err != nil {
			return nil, fmt.Errorf("decode OCI index %s: %w", root.Digest, err)
		}
		if index.SchemaVersion != 2 {
			return nil, fmt.Errorf("OCI index %s has schema version %d, want 2", root.Digest, index.SchemaVersion)
		}
		matches := 0
		for _, candidate := range index.Manifests {
			if candidate.Platform != nil && candidate.Platform.OS == "linux" && candidate.Platform.Architecture == "amd64" {
				descriptor = candidate
				matches++
			}
		}
		if matches != 1 {
			return nil, fmt.Errorf("OCI index %s contains %d linux/amd64 manifests, want one", root.Digest, matches)
		}
		if descriptor.MediaType != ocispec.MediaTypeImageManifest &&
			descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
			return nil, fmt.Errorf("OCI index %s selects unsupported manifest media type %s", root.Digest, descriptor.MediaType)
		}
		accepted[descriptor.Digest.String()] = struct{}{}
	case ocispec.MediaTypeImageManifest, "application/vnd.docker.distribution.manifest.v2+json":
	default:
		return nil, fmt.Errorf("OCI root %s has unsupported media type %s", root.Digest, root.MediaType)
	}
	manifestData, err := fetchBounded(ctx, source, descriptor)
	if err != nil {
		return nil, fmt.Errorf("read OCI manifest %s: %w", descriptor.Digest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode OCI manifest %s: %w", descriptor.Digest, err)
	}
	if manifest.SchemaVersion != 2 {
		return nil, fmt.Errorf("OCI manifest %s has schema version %d, want 2", descriptor.Digest, manifest.SchemaVersion)
	}
	if manifest.Config.MediaType != ocispec.MediaTypeImageConfig &&
		manifest.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
		return nil, fmt.Errorf("OCI manifest %s has unsupported image config media type %s", descriptor.Digest, manifest.Config.MediaType)
	}
	configData, err := fetchBounded(ctx, source, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("read OCI config %s: %w", manifest.Config.Digest, err)
	}
	var image ocispec.Image
	if err := json.Unmarshal(configData, &image); err != nil {
		return nil, fmt.Errorf("decode OCI config %s: %w", manifest.Config.Digest, err)
	}
	if image.OS != "linux" || image.Architecture != "amd64" {
		return nil, fmt.Errorf("OCI root %s is %s/%s, want linux/amd64", root.Digest, image.OS, image.Architecture)
	}
	for _, layer := range manifest.Layers {
		if err := layer.Digest.Validate(); err != nil || layer.Size <= 0 {
			return nil, fmt.Errorf("OCI manifest %s contains invalid layer %s/%d", descriptor.Digest, layer.Digest, layer.Size)
		}
		if verifier != nil {
			if err := verifier.verify(ctx, source, layer); err != nil {
				return nil, fmt.Errorf("verify OCI layer %s: %w", layer.Digest, err)
			}
		} else {
			exists, err := source.Exists(ctx, layer)
			if err != nil {
				return nil, fmt.Errorf("inspect OCI layer %s: %w", layer.Digest, err)
			}
			if !exists {
				return nil, fmt.Errorf("OCI manifest %s is missing layer %s", descriptor.Digest, layer.Digest)
			}
		}
	}
	accepted[manifest.Config.Digest.String()] = struct{}{}
	return accepted, nil
}

func (verifier *BlobVerifier) verify(
	ctx context.Context,
	source content.Fetcher,
	descriptor ocispec.Descriptor,
) error {
	identity := descriptorIdentity{size: descriptor.Size}
	if prior, exists := verifier.verified[descriptor.Digest]; exists {
		if prior != identity {
			return fmt.Errorf("descriptor %s repeats with identities %+v and %+v", descriptor.Digest, prior, identity)
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if descriptor.Size == math.MaxInt64 {
		return fmt.Errorf("descriptor %s size cannot be safely bounded", descriptor.Digest)
	}
	reader, err := source.Fetch(ctx, descriptor)
	if err != nil {
		return err
	}
	digestVerifier := descriptor.Digest.Verifier()
	written, copyErr := io.CopyBuffer(
		digestVerifier,
		io.LimitReader(&contextReader{ctx: ctx, reader: reader}, descriptor.Size+1),
		verifier.buffer,
	)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if written != descriptor.Size || !digestVerifier.Verified() {
		return fmt.Errorf("descriptor %s content is %d bytes or has a mismatched digest, want %d", descriptor.Digest, written, descriptor.Size)
	}
	verifier.verified[descriptor.Digest] = identity
	return nil
}

// VerifyGraph proves every descriptor reachable from root, including
// attestations and their subjects. Metadata remains bounded in memory while
// configs, layers, and arbitrary artifact blobs are streamed.
func (verifier *BlobVerifier) VerifyGraph(
	ctx context.Context,
	source content.ReadOnlyStorage,
	root ocispec.Descriptor,
) error {
	if verifier == nil {
		return errors.New("OCI blob verifier is nil")
	}
	stack := []ocispec.Descriptor{root}
	for len(stack) != 0 {
		if len(verifier.expanded) >= graphDescriptorLimit {
			return fmt.Errorf("OCI graph exceeds %d descriptors", graphDescriptorLimit)
		}
		last := len(stack) - 1
		descriptor := stack[last]
		stack = stack[:last]
		if err := descriptor.Digest.Validate(); err != nil || descriptor.Size <= 0 {
			return fmt.Errorf("OCI graph descriptor %s/%d is invalid", descriptor.Digest, descriptor.Size)
		}
		identity := descriptorIdentity{size: descriptor.Size}
		if prior, exists := verifier.verified[descriptor.Digest]; exists && prior != identity {
			return fmt.Errorf("descriptor %s repeats with identities %+v and %+v", descriptor.Digest, prior, identity)
		}
		expansion := descriptorExpansion{digest: descriptor.Digest, mediaType: descriptor.MediaType}
		if _, expanded := verifier.expanded[expansion]; expanded {
			continue
		}
		var successors []ocispec.Descriptor
		switch descriptor.MediaType {
		case ocispec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.list.v2+json":
			data, err := fetchBounded(ctx, source, descriptor)
			if err != nil {
				return err
			}
			var index ocispec.Index
			if err := json.Unmarshal(data, &index); err != nil {
				return fmt.Errorf("decode OCI graph index %s: %w", descriptor.Digest, err)
			}
			if index.SchemaVersion != 2 {
				return fmt.Errorf("OCI graph index %s has schema version %d", descriptor.Digest, index.SchemaVersion)
			}
			if index.Subject != nil {
				successors = append(successors, *index.Subject)
			}
			successors = append(successors, index.Manifests...)
			verifier.verified[descriptor.Digest] = identity
		case ocispec.MediaTypeImageManifest, "application/vnd.docker.distribution.manifest.v2+json":
			data, err := fetchBounded(ctx, source, descriptor)
			if err != nil {
				return err
			}
			var manifest ocispec.Manifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				return fmt.Errorf("decode OCI graph manifest %s: %w", descriptor.Digest, err)
			}
			if manifest.SchemaVersion != 2 {
				return fmt.Errorf("OCI graph manifest %s has schema version %d", descriptor.Digest, manifest.SchemaVersion)
			}
			if manifest.Subject != nil {
				successors = append(successors, *manifest.Subject)
			}
			successors = append(successors, manifest.Config)
			successors = append(successors, manifest.Layers...)
			verifier.verified[descriptor.Digest] = identity
		case "application/vnd.oci.artifact.manifest.v1+json":
			data, err := fetchBounded(ctx, source, descriptor)
			if err != nil {
				return err
			}
			var artifact struct {
				MediaType    string               `json:"mediaType"`
				ArtifactType string               `json:"artifactType"`
				Blobs        []ocispec.Descriptor `json:"blobs"`
				Subject      *ocispec.Descriptor  `json:"subject,omitempty"`
				Annotations  map[string]string    `json:"annotations,omitempty"`
			}
			if err := json.Unmarshal(data, &artifact); err != nil {
				return fmt.Errorf("decode OCI artifact manifest %s: %w", descriptor.Digest, err)
			}
			if artifact.MediaType != descriptor.MediaType {
				return fmt.Errorf("OCI artifact manifest %s has media type %s", descriptor.Digest, artifact.MediaType)
			}
			if artifact.Subject != nil {
				successors = append(successors, *artifact.Subject)
			}
			successors = append(successors, artifact.Blobs...)
			verifier.verified[descriptor.Digest] = identity
		default:
			if err := verifier.verify(ctx, source, descriptor); err != nil {
				return err
			}
		}
		verifier.expanded[expansion] = struct{}{}
		if len(stack) > graphDescriptorLimit-len(successors) {
			return fmt.Errorf("OCI graph exceeds %d pending descriptors", graphDescriptorLimit)
		}
		stack = append(stack, successors...)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func fetchBounded(ctx context.Context, source content.Fetcher, descriptor ocispec.Descriptor) ([]byte, error) {
	if err := descriptor.Digest.Validate(); err != nil {
		return nil, fmt.Errorf("descriptor digest %q is invalid: %w", descriptor.Digest, err)
	}
	if descriptor.Size < 0 || descriptor.Size > manifestLimit {
		return nil, fmt.Errorf("descriptor %s size %d exceeds %d bytes", descriptor.Digest, descriptor.Size, manifestLimit)
	}
	reader, err := source.Fetch(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	verifier := descriptor.Digest.Verifier()
	data, err := io.ReadAll(io.LimitReader(io.TeeReader(reader, verifier), manifestLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > manifestLimit {
		return nil, fmt.Errorf("descriptor %s exceeds %d bytes", descriptor.Digest, manifestLimit)
	}
	if int64(len(data)) != descriptor.Size || !verifier.Verified() {
		return nil, fmt.Errorf("descriptor %s content does not match its size and digest", descriptor.Digest)
	}
	return data, nil
}
