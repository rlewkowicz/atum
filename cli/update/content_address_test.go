package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestProjectContentAddressedTargets(t *testing.T) {
	graphSHA256 := strings.Repeat("a", 64)
	desired := config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{
				{
					ID:      "built",
					Version: "1.2.3",
					Target:  "registry.example/atum/built:1.2.3",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type:       "build",
						BakeTarget: "built",
						Materials:  []string{"platform/build/docker/Dockerfile.delivery"},
					}},
				},
				{
					ID:      "mirrored",
					Version: "4.5.6",
					Target:  "registry.example/atum/mirrored:4.5.6",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "registry.example/vendor/mirrored:4.5.6",
						Digest: "sha256:" + strings.Repeat("b", 64),
					}},
				},
			},
		},
	}
	delivery, err := config.ResolveDelivery(desired.Delivery.Images[0], "platform", graphSHA256)
	if err != nil {
		t.Fatalf("resolve delivery: %v", err)
	}
	inputSHA256, err := desired.ImageInputSHA256(
		desired.Delivery.Images[0],
		delivery,
		graphSHA256,
	)
	if err != nil {
		t.Fatalf("resolve input: %v", err)
	}
	replacements, err := projectContentAddressedMirrorTargets(&desired)
	if err != nil {
		t.Fatalf("project content-addressed mirror targets: %v", err)
	}
	wantMirror := "registry.example/atum/mirrored:4.5.6-mirror-" +
		strings.Repeat("b", 48)
	if desired.Delivery.Images[1].Target != wantMirror {
		t.Fatalf(
			"mirror target = %q, want %q",
			desired.Delivery.Images[1].Target,
			wantMirror,
		)
	}
	if len(replacements) != 1 ||
		replacements[0].Old != "registry.example/atum/mirrored:4.5.6" ||
		replacements[0].New != wantMirror {
		t.Fatalf("mirror replacements = %#v", replacements)
	}
	replacements, err = projectContentAddressedMirrorTargets(&desired)
	if err != nil {
		t.Fatalf("repeat content-addressed mirror projection: %v", err)
	}
	if len(replacements) != 0 {
		t.Fatalf("repeat mirror projection returned replacements: %#v", replacements)
	}

	replacements, err = projectContentAddressedBuildTargets(
		&desired,
		"platform",
		graphSHA256,
	)
	if err != nil {
		t.Fatalf("project content-addressed targets: %v", err)
	}
	want := "registry.example/atum/built:build-" + inputSHA256
	if desired.Delivery.Images[0].Target != want {
		t.Fatalf("build target = %q, want %q", desired.Delivery.Images[0].Target, want)
	}
	if desired.Delivery.Images[1].Target != wantMirror {
		t.Fatalf("build projection changed mirror target to %q", desired.Delivery.Images[1].Target)
	}
	if len(replacements) != 1 ||
		replacements[0].Old != "registry.example/atum/built:1.2.3" ||
		replacements[0].New != want {
		t.Fatalf("replacements = %#v", replacements)
	}
	replacements, err = projectContentAddressedBuildTargets(
		&desired,
		"platform",
		graphSHA256,
	)
	if err != nil {
		t.Fatalf("repeat content-addressed projection: %v", err)
	}
	if len(replacements) != 0 {
		t.Fatalf("repeat projection returned replacements: %#v", replacements)
	}
}

func TestBootstrapSourceRenderFilesRestoreExactMirrorProjection(t *testing.T) {
	const (
		valuesPath = "platform/apps/prep/example/values.yaml"
		target     = "registry.example/atum/example:1.2.3-mirror-" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		source = "docker.io/example/tool:1.2.3"
	)
	files := map[string][]byte{
		valuesPath: []byte(
			"image:\n" +
				"  repository: registry.example/atum/example\n" +
				"  tag: 1.2.3-mirror-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
		),
	}
	projected, err := bootstrapSourceRenderFiles(
		".",
		files,
		[]config.Chart{{
			ID:     "example",
			Values: valuesPath,
		}},
		map[string]config.ImageMirrorReceipt{
			"example": {
				ID:     "example",
				Target: target,
				Source: source,
				Digest: "sha256:" + strings.Repeat("a", 64),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	values, err := readManagedYAML(".", projected, valuesPath)
	if err != nil {
		t.Fatal(err)
	}
	image, err := valuesAt(values, "image")
	if err != nil {
		t.Fatal(err)
	}
	if image["repository"] != "docker.io/example/tool" ||
		image["tag"] != "1.2.3" {
		t.Fatalf("source-render image = %#v", image)
	}
	if err := replaceBootstrapImageReferences(
		values,
		[]imageReplacement{{
			Old: source,
			New: target,
		}},
	); err != nil {
		t.Fatal(err)
	}
	if image["repository"] != "registry.example/atum/example" ||
		image["tag"] !=
			"1.2.3-mirror-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("reprojected bootstrap image = %#v", image)
	}
	original, err := readManagedYAML(".", files, valuesPath)
	if err != nil {
		t.Fatal(err)
	}
	originalImage, err := valuesAt(original, "image")
	if err != nil {
		t.Fatal(err)
	}
	if originalImage["repository"] !=
		"registry.example/atum/example" {
		t.Fatalf("managed input was mutated: %#v", originalImage)
	}
}
