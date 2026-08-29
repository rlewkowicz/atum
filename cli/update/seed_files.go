package update

import (
	"context"
	"fmt"

	"atum/cli/config"
)

type imageDigestResolver func(context.Context, string) (string, error)

// projectSeedKubesprayFiles is the sole writer of the bastion-only files
// service identity. It deliberately does not add the image to delivery.Images:
// the image is Terraform's minimal pre-Harbor seed input, not cluster state.
func projectSeedKubesprayFiles(
	ctx context.Context,
	desired *config.Document,
	resolve imageDigestResolver,
) error {
	if desired == nil || resolve == nil {
		return fmt.Errorf("seed Kubespray files projection requires desired state and an image resolver")
	}
	digest, err := resolve(ctx, config.SeedKubesprayFilesImageSource)
	if err != nil {
		return fmt.Errorf("resolve seed Kubespray files image: %w", err)
	}
	if !isResolvedImageDigest(digest) {
		return fmt.Errorf("seed Kubespray files image resolved invalid digest %q", digest)
	}
	desired.Delivery.Seed.KubesprayFiles = config.SeedKubesprayFiles{
		URL: config.SeedKubesprayFilesURL,
		Image: config.SeedImage{
			ID:     config.SeedKubesprayFilesImageID,
			Source: config.SeedKubesprayFilesImageSource,
			Digest: digest,
		},
	}
	return nil
}
