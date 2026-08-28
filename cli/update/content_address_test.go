package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestProjectContentAddressedBuildTargets(t *testing.T) {
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
	replacements, err := projectContentAddressedBuildTargets(
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
	if desired.Delivery.Images[1].Target != "registry.example/atum/mirrored:4.5.6" {
		t.Fatalf("mirror target changed to %q", desired.Delivery.Images[1].Target)
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
