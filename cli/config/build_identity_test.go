package config

import (
	"strings"
	"testing"
)

func TestBuildImageInputExcludesDerivedTarget(t *testing.T) {
	graphSHA256 := strings.Repeat("a", 64)
	delivery := LockedDelivery{
		Type:          "build",
		BakeTarget:    "example",
		Materials:     []string{"platform/build/docker/Dockerfile.delivery"},
		SourceProfile: "platform",
	}
	image := Image{
		ID:      "example",
		Version: "1.2.3",
		Target:  "registry.example/atum/example:1.2.3",
	}
	first, err := (Document{}).ImageInputSHA256(image, delivery, graphSHA256)
	if err != nil {
		t.Fatalf("resolve first build input: %v", err)
	}
	image.Target = "registry.example/atum/example:build-" + strings.Repeat("b", 64)
	second, err := (Document{}).ImageInputSHA256(image, delivery, graphSHA256)
	if err != nil {
		t.Fatalf("resolve second build input: %v", err)
	}
	if first != second {
		t.Fatalf("derived target changed build input from %s to %s", first, second)
	}
	tag, err := ContentAddressedBuildTag(first)
	if err != nil {
		t.Fatalf("resolve content-addressed tag: %v", err)
	}
	if tag != "build-"+first {
		t.Fatalf("content-addressed tag = %q, want build-%s", tag, first)
	}
}

func TestMirrorImageInputIncludesPublicationTarget(t *testing.T) {
	delivery := LockedDelivery{
		Type:          "mirror",
		Source:        "registry.example/vendor/example:1.2.3",
		Digest:        "sha256:" + strings.Repeat("a", 64),
		SourceProfile: "platform",
	}
	image := Image{
		ID:      "example",
		Version: "1.2.3",
		Target:  "registry.example/atum/example:1.2.3",
	}
	first, err := (Document{}).ImageInputSHA256(image, delivery, "")
	if err != nil {
		t.Fatalf("resolve first mirror input: %v", err)
	}
	image.Target = "registry.example/atum/example:1.2.4"
	second, err := (Document{}).ImageInputSHA256(image, delivery, "")
	if err != nil {
		t.Fatalf("resolve second mirror input: %v", err)
	}
	if first == second {
		t.Fatal("mirror publication target did not change its input identity")
	}
	tag, err := ContentAddressedMirrorTag("v"+image.Version, delivery.Digest)
	if err != nil {
		t.Fatalf("resolve content-addressed mirror tag: %v", err)
	}
	if tag != "v1.2.3-mirror-"+strings.Repeat("a", mirrorTagIdentityLength) {
		t.Fatalf("content-addressed mirror tag = %q", tag)
	}
}

func TestMirrorTargetTagsPreserveSharedHubVersion(t *testing.T) {
	images := []Image{
		{
			ID:      "pilot",
			Version: "1.30.3",
			Target:  "registry.example/atum/pilot:1.30.3",
			Delivery: ImageDelivery{Default: DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/istio/pilot:1.30.3",
				Digest: "sha256:" + strings.Repeat("a", 64),
			}},
		},
		{
			ID:      "proxyv2",
			Version: "1.30.3",
			Target:  "registry.example/atum/proxyv2:1.30.3",
			Delivery: ImageDelivery{Default: DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/istio/proxyv2:1.30.3",
				Digest: "sha256:" + strings.Repeat("b", 64),
			}},
		},
	}
	first, err := MirrorTargetTags(images)
	if err != nil {
		t.Fatal(err)
	}
	if first["pilot"] != first["proxyv2"] ||
		!strings.HasPrefix(first["pilot"], "1.30.3-mirror-set-") {
		t.Fatalf("shared hub/version tags = %#v", first)
	}
	for index := range images {
		images[index].Target = "registry.example/atum/" +
			images[index].ID + ":" + first[images[index].ID]
	}
	second, err := MirrorTargetTags(images)
	if err != nil {
		t.Fatal(err)
	}
	if first["pilot"] != second["pilot"] ||
		first["proxyv2"] != second["proxyv2"] {
		t.Fatalf("repeat shared tags changed from %#v to %#v", first, second)
	}
	images[1].Delivery.Default.Digest =
		"sha256:" + strings.Repeat("c", 64)
	changed, err := MirrorTargetTags(images)
	if err != nil {
		t.Fatal(err)
	}
	if changed["pilot"] == first["pilot"] ||
		changed["pilot"] != changed["proxyv2"] {
		t.Fatalf("changed shared tags = %#v, original %#v", changed, first)
	}
}

func TestMirrorTargetTagsPreserveFluxBootstrapNames(t *testing.T) {
	ids := []string{
		FluxSourceController,
		FluxKustomizeController,
		FluxHelmController,
		FluxNotificationController,
	}
	images := make([]Image, 0, len(ids))
	for index, id := range ids {
		tag := "v1." + string(rune('1'+index)) + ".0"
		images = append(images, Image{
			ID:        id,
			Family:    "flux",
			Version:   strings.TrimPrefix(tag, "v"),
			Target:    "registry.example/atum/" + id + ":" + tag,
			Consumers: []string{"flux"},
			Delivery: ImageDelivery{Default: DeliveryChoice{
				Type:   "mirror",
				Source: "ghcr.io/fluxcd/" + id + ":" + tag,
				Digest: "sha256:" + strings.Repeat(string(rune('a'+index)), 64),
			}},
		})
	}
	tags, err := MirrorTargetTags(images)
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range images {
		want := imageReferenceTag(image.Delivery.Default.Source)
		if tags[image.ID] != want {
			t.Fatalf("%s target tag = %q, want %q", image.ID, tags[image.ID], want)
		}
	}
}

func TestMirrorTargetTagsPreserveKubesprayNames(t *testing.T) {
	const tag = "v3.31.5"
	image := Image{
		ID:        "kubespray-node-77c1a7981006",
		Family:    "kubernetes",
		Version:   "3.31.5",
		Target:    "registry.example/atum/kubespray/quay.io/calico/node:" + tag,
		Scopes:    []string{"kubespray"},
		Runtime:   true,
		Consumers: []string{"kubespray"},
		Discovery: "kubespray",
		Delivery: ImageDelivery{Default: DeliveryChoice{
			Type:   "mirror",
			Source: "quay.io/calico/node:" + tag,
			Digest: "sha256:" + strings.Repeat("a", 64),
		}},
	}
	tags, err := MirrorTargetTags([]Image{image})
	if err != nil {
		t.Fatal(err)
	}
	if tags[image.ID] != tag {
		t.Fatalf("%s target tag = %q, want %q", image.ID, tags[image.ID], tag)
	}
}

func TestBuildGraphIdentityNormalizesOnlyCanonicalTargetTags(t *testing.T) {
	left := []byte(`target "one" {
  tags       = ["registry.example/atum/one:1"]
  args = {
    VERSION = "1"
  }
}

target "two" {
  tags       = ["registry.example/atum/two:2"]
}
`)
	right := []byte(strings.ReplaceAll(
		string(left),
		":1\"]",
		":build-"+strings.Repeat("a", 64)+"\"]",
	))
	right = []byte(strings.ReplaceAll(
		string(right),
		":2\"]",
		":build-"+strings.Repeat("b", 64)+"\"]",
	))
	normalizedLeft, leftTargets, err := normalizeBuildGraphTargetTags(left)
	if err != nil {
		t.Fatalf("normalize first graph: %v", err)
	}
	normalizedRight, rightTargets, err := normalizeBuildGraphTargetTags(right)
	if err != nil {
		t.Fatalf("normalize second graph: %v", err)
	}
	if leftTargets != 2 || rightTargets != 2 {
		t.Fatalf("normalized target counts = %d and %d, want 2", leftTargets, rightTargets)
	}
	if string(normalizedLeft) != string(normalizedRight) {
		t.Fatalf("target-only graph change altered identity input:\n%s\n%s", normalizedLeft, normalizedRight)
	}
	changedArgument := []byte(strings.Replace(string(right), `VERSION = "1"`, `VERSION = "2"`, 1))
	normalizedArgument, _, err := normalizeBuildGraphTargetTags(changedArgument)
	if err != nil {
		t.Fatalf("normalize changed graph: %v", err)
	}
	if string(normalizedLeft) == string(normalizedArgument) {
		t.Fatal("non-target graph change was normalized away")
	}
}
