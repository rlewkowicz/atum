package update

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var linuxAMD64 = v1.Platform{OS: "linux", Architecture: "amd64"}

type resolvedImageDigests struct {
	manifest string
	tag      string
}

func resolveImageDigest(ctx context.Context, source string) (string, error) {
	resolved, err := resolveImageDigests(ctx, source)
	if err != nil {
		return "", err
	}
	return resolved.manifest, nil
}

func resolveImageDigests(ctx context.Context, source string) (resolvedImageDigests, error) {
	if strings.Contains(source, "@") {
		return resolvedImageDigests{}, fmt.Errorf(
			"image source %s must retain a tag separate from its resolved digest", source)
	}
	reference, err := name.ParseReference(source)
	if err != nil {
		return resolvedImageDigests{}, fmt.Errorf("parse image source %s: %w", source, err)
	}
	return resolveImageReference(ctx, reference, source)
}

func resolvePinnedImageDigests(
	ctx context.Context,
	source string,
	digest string,
) (resolvedImageDigests, error) {
	if strings.Contains(source, "@") {
		return resolvedImageDigests{}, fmt.Errorf(
			"image source %s must retain a tag separate from its resolved digest", source)
	}
	reference, err := name.ParseReference(source)
	if err != nil {
		return resolvedImageDigests{}, fmt.Errorf("parse image source %s: %w", source, err)
	}
	pinned := reference.Context().Digest(digest)
	return resolveImageReference(ctx, pinned, pinned.Name())
}

func resolveImageReference(
	ctx context.Context,
	reference name.Reference,
	label string,
) (resolvedImageDigests, error) {
	descriptor, err := remote.Get(
		reference,
		remote.WithContext(ctx),
		remote.WithPlatform(linuxAMD64),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return resolvedImageDigests{}, fmt.Errorf(
			"resolve image descriptor %s: %w", label, err)
	}
	image, err := descriptor.Image()
	if err != nil {
		return resolvedImageDigests{}, fmt.Errorf(
			"resolve linux/amd64 image %s: %w", label, err)
	}
	configuration, err := image.ConfigFile()
	if err != nil {
		return resolvedImageDigests{}, fmt.Errorf("inspect image platform %s: %w", label, err)
	}
	if configuration.OS != linuxAMD64.OS || configuration.Architecture != linuxAMD64.Architecture {
		return resolvedImageDigests{}, fmt.Errorf(
			"image %s resolved to %s/%s, want linux/amd64",
			label, configuration.OS, configuration.Architecture)
	}
	digest, err := image.Digest()
	if err != nil {
		return resolvedImageDigests{}, fmt.Errorf("resolve image digest %s: %w", label, err)
	}
	return resolvedImageDigests{
		manifest: digest.String(),
		tag:      descriptor.Digest.String(),
	}, nil
}
