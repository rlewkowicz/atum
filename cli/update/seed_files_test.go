package update

import (
	"context"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestProjectSeedKubesprayFilesOwnsExactBastionIdentity(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("a", 64)
	desired := config.Document{
		Delivery: config.Delivery{
			Seed: config.SeedPlane{
				KubesprayFiles: config.SeedKubesprayFiles{
					URL: "http://stale.invalid",
					Image: config.SeedImage{
						ID: "stale", Source: "example.invalid/stale:latest",
						Digest: "sha256:" + strings.Repeat("b", 64),
					},
				},
			},
		},
	}
	resolveCalls := 0
	resolve := func(_ context.Context, source string) (string, error) {
		resolveCalls++
		if source != config.SeedKubesprayFilesImageSource {
			t.Fatalf("resolver source = %q", source)
		}
		return digest, nil
	}
	if err := projectSeedKubesprayFiles(t.Context(), &desired, resolve); err != nil {
		t.Fatal(err)
	}
	want := config.SeedKubesprayFiles{
		URL: config.SeedKubesprayFilesURL,
		Image: config.SeedImage{
			ID:     config.SeedKubesprayFilesImageID,
			Source: config.SeedKubesprayFilesImageSource,
			Digest: digest,
		},
	}
	if desired.Delivery.Seed.KubesprayFiles != want {
		t.Fatalf("seed files = %#v, want %#v", desired.Delivery.Seed.KubesprayFiles, want)
	}
	if len(desired.Delivery.Images) != 0 {
		t.Fatal("bastion-only Nginx entered the runtime image inventory")
	}
	if err := projectSeedKubesprayFiles(t.Context(), &desired, resolve); err != nil {
		t.Fatal(err)
	}
	if desired.Delivery.Seed.KubesprayFiles != want || resolveCalls != 2 {
		t.Fatalf("stable rerun = %#v, calls = %d", desired.Delivery.Seed.KubesprayFiles, resolveCalls)
	}
}

func TestProjectSeedFilesSchemaIsDeterministicAndRejectsUnknownShape(t *testing.T) {
	t.Parallel()

	input := []byte(`{
    "seedPlane": {
      "required": ["forgejo", "harbor"],
        }
      }
    },
    "seedAsset": {
}`)
	first, err := projectSeedFilesSchemaData(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := projectSeedFilesSchemaData(first)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) ||
		!strings.Contains(string(first), `"url": {"const": "http://10.77.0.9:8080"}`) {
		t.Fatalf("seed-files schema projection is unstable:\n%s", first)
	}
	if _, err := projectSeedFilesSchemaData([]byte(`{"seedPlane":{}}`)); err == nil {
		t.Fatal("unsupported seed schema shape was accepted")
	}
}
