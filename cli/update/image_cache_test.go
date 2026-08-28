package update

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"atum/cli/config"
	atumoci "atum/cli/oci"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func TestOfficialAdmissionReusesExactLocalOCICache(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: "amd64",
		OS:           "linux",
		RootFS:       v1.RootFS{Type: "layers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := atumoci.OfficialMirrorCacheRelative(
		"example",
		digest.String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image})
	if _, err := layout.Write(absolute, index); err != nil {
		t.Fatal(err)
	}

	const source = "docker.io/example/tool:1.0.0"
	record := config.Image{
		ID:     "example",
		Target: "registry.atum.test/atum/example:1.0.0",
		Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
			Type:   "mirror",
			Source: source,
		}},
	}
	receipt := config.ImageMirrorReceipt{
		ID:     record.ID,
		Source: source,
		Digest: digest.String(),
	}
	inspection, err := inspectOfficialCandidateWithCache(
		context.Background(),
		root,
		source,
		record,
		receipt,
		true,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "docker.io/example/tool@" + digest.String()
	if inspection.material != want {
		t.Fatalf("cached official material = %q, want %q", inspection.material, want)
	}
}

func TestOfficialAdmissionSelectsLinuxAMD64FromCachedIndex(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	amd64, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: "amd64",
		OS:           "linux",
		RootFS:       v1.RootFS{Type: "layers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	arm64, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: "arm64",
		OS:           "linux",
		RootFS:       v1.RootFS{Type: "layers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(
		empty.Index,
		mutate.IndexAddendum{
			Add: amd64,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			}},
		},
		mutate.IndexAddendum{
			Add: arm64,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{
				Architecture: "arm64",
				OS:           "linux",
			}},
		},
	)
	digest, err := index.Digest()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := atumoci.OfficialMirrorCacheRelative(
		"example-index",
		digest.String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatal(err)
	}
	layoutPath, err := layout.Write(absolute, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := layoutPath.AppendIndex(index); err != nil {
		t.Fatal(err)
	}

	const source = "quay.io/example/tool:1.0.0"
	record := config.Image{
		ID:     "example-index",
		Target: "registry.atum.test/atum/example-index:1.0.0",
		Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
			Type:   "mirror",
			Source: source,
		}},
	}
	receipt := config.ImageMirrorReceipt{
		ID:     record.ID,
		Source: source,
		Digest: digest.String(),
	}
	inspection, err := inspectOfficialCandidateWithCache(
		context.Background(),
		root,
		source,
		record,
		receipt,
		true,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "quay.io/example/tool@" + digest.String()
	if inspection.material != want {
		t.Fatalf("cached official material = %q, want %q", inspection.material, want)
	}
}

func TestMissingOfficialOCICacheIsNotReportedAsReusable(t *testing.T) {
	t.Parallel()
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	image, found, err := openCachedOfficialImage(
		context.Background(),
		t.TempDir(),
		"example",
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if found || image != nil {
		t.Fatalf("missing cache image = %v, found = %t", image, found)
	}
}
