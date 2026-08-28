package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestOfficialImageEvidenceRequiresOnePermittedImmutableRepository(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := DeliveryPolicy{
		ForbiddenArtifactPrefixes: []string{"registry1.dso.mil/ironbank"},
		MutableTagsForbidden:      true,
	}
	tests := []struct {
		name     string
		source   string
		material string
		wantErr  bool
	}{
		{
			name:     "same official repository",
			source:   "docker.io/hashicorp/vault:1.21.4",
			material: "index.docker.io/hashicorp/vault@" + digest,
		},
		{
			name:     "unrelated source",
			source:   "docker.io/library/alpine:3.23",
			material: "index.docker.io/hashicorp/vault@" + digest,
			wantErr:  true,
		},
		{
			name:     "Registry1 source",
			source:   "registry1.dso.mil/ironbank/hashicorp/vault:1.21.4",
			material: "registry1.dso.mil/ironbank/hashicorp/vault@" + digest,
			wantErr:  true,
		},
		{
			name:     "non-immutable material",
			source:   "docker.io/hashicorp/vault:1.21.4",
			material: "docker.io/hashicorp/vault:1.21.4",
			wantErr:  true,
		},
		{
			name:     "immutable source",
			source:   "docker.io/hashicorp/vault@" + digest,
			material: "docker.io/hashicorp/vault@" + digest,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateOfficialImageEvidence(
				policy,
				test.source,
				test.material,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("evidence error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestKubesprayOfficialImagesExactlyJoinHarborProjection(t *testing.T) {
	t.Parallel()
	official := []string{
		"quay.io/calico/node:v3.31.4",
		"docker.io/flannel/flannel:v0.27.4",
		"quay.io/metallb/controller:v0.15.3",
		"quay.io/cilium/hubble-relay:v1.19.1",
		"quay.io/cilium/operator:v1.19.1",
	}
	wantOfficial := append([]string(nil), official...)
	sources := append(
		append([]string(nil), official...),
		"quay.io/cilium/operator-generic:v1.19.1",
	)
	inventory := KubesprayArtifactInventory{
		KubernetesVersion: "1.35.2",
		OfficialImages:    official,
		RuntimeImages: []string{
			"quay.io/cilium/operator-generic:v1.19.1",
		},
		Images: make([]string, len(sources)),
	}
	projected := make(map[string]Image, len(sources))
	projectedList := make([]Image, 0, len(sources))
	const targetPrefix = "harbor.internal/atum/"
	for index, source := range sources {
		id := "image-" + string(rune('a'+index))
		inventory.Images[index] = id
		image := Image{
			ID:        id,
			Discovery: "kubespray",
			Target: targetPrefix + "kubespray/" +
				imageReferenceRepository(source) + ":" +
				imageReferenceTag(source),
			Scopes:  []string{"kubespray"},
			Runtime: true,
			Delivery: ImageDelivery{Default: DeliveryChoice{
				Type:   "mirror",
				Source: source,
				Digest: "sha256:" + strings.Repeat("b", 64),
			}},
		}
		projected[id] = image
		projectedList = append(projectedList, image)
	}
	var problems []string
	validateKubesprayImageProjection(
		&problems,
		[]KubesprayArtifactInventory{inventory},
		projectedList,
		targetPrefix,
		false,
	)
	if len(problems) != 0 {
		t.Fatalf("persisted full upstream projection was rejected: %v", problems)
	}
	if err := validateKubesprayOfficialImageProjection(
		inventory,
		projected,
	); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inventory.OfficialImages, wantOfficial) {
		t.Fatalf(
			"official script order changed: got %#v want %#v",
			inventory.OfficialImages,
			wantOfficial,
		)
	}

	missingGeneric := inventory
	missingGeneric.Images = append(
		[]string(nil),
		inventory.Images[:len(inventory.Images)-1]...,
	)
	if err := validateKubesprayOfficialImageProjection(
		missingGeneric,
		projected,
	); err == nil {
		t.Fatal("missing source-derived Cilium generic mirror passed projection validation")
	}

	futureOfficialGeneric := inventory
	futureOfficialGeneric.OfficialImages = append(
		append([]string(nil), inventory.OfficialImages...),
		"quay.io/cilium/operator-generic:v1.19.1",
	)
	if err := validateKubesprayOfficialImageProjection(
		futureOfficialGeneric,
		projected,
	); err != nil {
		t.Fatalf(
			"one generic projection did not satisfy a future official generic entry: %v",
			err,
		)
	}

	missing := inventory
	missing.Images = append([]string(nil), inventory.Images[1:]...)
	if err := validateKubesprayOfficialImageProjection(
		missing,
		projected,
	); err == nil {
		t.Fatal("missing official mirror passed projection validation")
	}

	substitutedImages := cloneProjectedImages(projected)
	substitutedImages[inventory.Images[0]] = Image{
		ID:        inventory.Images[0],
		Discovery: "kubespray",
		Delivery: ImageDelivery{Default: DeliveryChoice{
			Type:   "mirror",
			Source: "quay.io/example/substitute:v1",
			Digest: "sha256:" + strings.Repeat("c", 64),
		}},
	}
	if err := validateKubesprayOfficialImageProjection(
		inventory,
		substitutedImages,
	); err == nil {
		t.Fatal("substituted official mirror passed projection validation")
	}

	extra := inventory
	extra.Images = append(append([]string(nil), inventory.Images...), "decoy")
	extraImages := cloneProjectedImages(projected)
	extraImages["decoy"] = Image{
		ID:        "decoy",
		Discovery: "kubespray",
		Delivery: ImageDelivery{Default: DeliveryChoice{
			Type:   "mirror",
			Source: "quay.io/example/decoy:v1",
			Digest: "sha256:" + strings.Repeat("d", 64),
		}},
	}
	if err := validateKubesprayOfficialImageProjection(
		extra,
		extraImages,
	); err == nil {
		t.Fatal("unrelated non-script mirror passed projection validation")
	}

	duplicated := inventory
	duplicated.Images = append(
		append([]string(nil), inventory.Images...),
		"duplicate",
	)
	duplicatedImages := cloneProjectedImages(projected)
	duplicatedImages["duplicate"] = projected[inventory.Images[0]]
	if err := validateKubesprayOfficialImageProjection(
		duplicated,
		duplicatedImages,
	); err == nil {
		t.Fatal("duplicated projected source passed projection validation")
	}
}

func cloneProjectedImages(images map[string]Image) map[string]Image {
	cloned := make(map[string]Image, len(images))
	for id, image := range images {
		cloned[id] = image
	}
	return cloned
}
