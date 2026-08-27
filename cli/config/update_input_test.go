package config

import (
	"strings"
	"testing"
)

func TestUpdateInputDiscardsEveryNonCanonicalDerivedImage(t *testing.T) {
	t.Parallel()
	images := []Image{
		{ID: "configured", Discovery: "configuration"},
		{ID: "operator", Discovery: "first-party"},
		{ID: "controller", Discovery: "controller-generated"},
		{ID: "rendered", Discovery: "rendered"},
		{ID: "kubespray-image", Discovery: "kubespray"},
		{ID: "arbitrary", Discovery: "not-a-supported-discovery"},
	}
	v5Inventory := KubesprayArtifactInventory{
		SchemaVersion:     "atum.dev/kubespray-artifacts/v5",
		KubernetesVersion: "1.35.2",
		KubesprayCommit:   strings.Repeat("a", 40),
		InventorySHA256:   strings.Repeat("b", 64),
		Files: []KubesprayFile{{
			Variable:  "kubeadm_download_url",
			Source:    "https://dl.k8s.io/release/v1.35.2/bin/linux/amd64/kubeadm",
			LocalPath: "kubeadm",
			CacheFile: ".atum/cache/kubespray-offline/sha256/" +
				strings.Repeat("c", 64),
			SHA256: strings.Repeat("c", 64),
			Size:   1,
		}},
		Images: []string{"kubespray-image"},
	}
	desired := Document{Delivery: Delivery{
		Kubespray: []KubesprayArtifactInventory{v5Inventory},
		Images:    images,
	}}
	lock := Lock{
		Resolved: Resolved{
			Kubespray: []KubesprayArtifactInventory{v5Inventory},
		},
		Delivery: ImageLock{Images: []LockedImage{
			{ID: "kubespray-image"},
			{ID: "rendered"},
			{ID: "arbitrary"},
		}},
	}
	discardUpdateImageProjections(&desired, &lock)
	retained := desired.Delivery.Images
	if len(retained) != 3 {
		t.Fatalf("retained update inputs = %#v, want only three canonical inputs", retained)
	}
	for index, id := range []string{"configured", "operator", "controller"} {
		if retained[index].ID != id {
			t.Fatalf("retained update input %d = %q, want %q", index, retained[index].ID, id)
		}
	}
	if validImageDiscovery(images[len(images)-1].Discovery) {
		t.Fatal("strict discovery validation accepted arbitrary derived input")
	}
	if len(lock.Delivery.Images) != 0 {
		t.Fatalf("replaceable locked images survived update acquisition: %#v", lock.Delivery.Images)
	}
	if len(desired.Delivery.Kubespray) != 0 ||
		len(lock.Resolved.Kubespray) != 0 {
		t.Fatalf(
			"replaceable Kubespray inventories survived update acquisition: desired=%#v locked=%#v",
			desired.Delivery.Kubespray,
			lock.Resolved.Kubespray,
		)
	}

	var strictProblems []string
	validateKubesprayImageProjection(
		&strictProblems,
		[]KubesprayArtifactInventory{v5Inventory},
		nil,
		"harbor.internal/atum/",
		false,
	)
	if len(strictProblems) == 0 ||
		strictProblems[0] != "Kubespray image projection is incomplete" {
		t.Fatalf(
			"strict projection validation problems = %#v, want incomplete projection",
			strictProblems,
		)
	}
}

func TestCompatibilityReceiptsAreDeepCopiedAndFiltered(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("d", 64)
	contractDigest := strings.Repeat("e", 64)
	source := "docker.io/hashicorp/vault:1.21.4"
	material := "index.docker.io/hashicorp/vault@" + digest
	canonical := Image{
		ID:        "vault",
		Discovery: "rendered",
		Delivery: ImageDelivery{Default: DeliveryChoice{
			Type:       "build",
			BakeTarget: "vault-curl-compat",
			Materials:  []string{material},
		}},
		Compatibility: &ImageCompatibility{
			Contract:         ImageAdmissionContract,
			Incompatibility:  "official executable curl is absent",
			OfficialSource:   source,
			OfficialMaterial: material,
			RemovalCondition: "remove when the official image supplies curl",
			OfficialConfig: ImageOfficialConfig{
				SHA256: digest,
			},
			Observations: []ImageRuntimeEvidence{{
				Artifact:              "package/vault",
				RenderedLocation:      "statefulset/vault/init/prepare",
				RuntimeContractSHA256: contractDigest,
			}},
		},
	}
	invalidSchema := canonical
	invalidSchema.ID = "invalid-schema"
	invalidSchema.Compatibility = cloneCompatibility(canonical.Compatibility)
	invalidSchema.Compatibility.Contract = "atum.dev/image-admission/v2"
	registry1 := canonical
	registry1.ID = "registry1"
	registry1.Compatibility = cloneCompatibility(canonical.Compatibility)
	registry1.Compatibility.OfficialSource =
		"registry1.dso.mil/ironbank/hashicorp/vault:1.21.4"
	invalidObservation := canonical
	invalidObservation.ID = "invalid-observation"
	invalidObservation.Compatibility = cloneCompatibility(canonical.Compatibility)
	invalidObservation.Compatibility.Observations[0].RuntimeContractSHA256 = ""

	receipts, err := compatibilityReceipts(
		DeliveryPolicy{
			MutableTagsForbidden: true,
			ForbiddenArtifactPrefixes: []string{
				"registry1.dso.mil/ironbank",
			},
		},
		[]Image{
			canonical,
			invalidSchema,
			registry1,
			invalidObservation,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[canonical.ID].Compatibility == nil {
		t.Fatalf("compatibility receipts = %#v, want only canonical receipt", receipts)
	}
	sanitizedDesired := Document{Delivery: Delivery{
		Images: []Image{canonical},
	}}
	sanitizedLock := Lock{Delivery: ImageLock{Images: []LockedImage{{
		ID: canonical.ID,
	}}}}
	discardUpdateImageProjections(&sanitizedDesired, &sanitizedLock)
	if len(sanitizedDesired.Delivery.Images) != 0 ||
		len(sanitizedLock.Delivery.Images) != 0 {
		t.Fatalf(
			"receipt populated sanitized state: desired=%#v locked=%#v",
			sanitizedDesired.Delivery.Images,
			sanitizedLock.Delivery.Images,
		)
	}
	canonical.Compatibility.Observations[0].Artifact = "mutated"
	if receipts[canonical.ID].Compatibility.Observations[0].Artifact !=
		"package/vault" {
		t.Fatal("compatibility receipt shares mutable observation storage")
	}

	duplicate := canonical
	receipts, err = compatibilityReceipts(
		DeliveryPolicy{},
		[]Image{canonical, duplicate},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatalf("duplicate compatibility record produced receipts: %#v", receipts)
	}

	registry1Sibling := registry1
	registry1Sibling.ID = canonical.ID
	receipts, err = compatibilityReceipts(
		DeliveryPolicy{},
		[]Image{canonical, registry1Sibling},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatalf(
			"Registry1 duplicate sibling produced receipts: %#v",
			receipts,
		)
	}

	malformedSibling := invalidObservation
	malformedSibling.ID = canonical.ID
	receipts, err = compatibilityReceipts(
		DeliveryPolicy{},
		[]Image{malformedSibling, canonical},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatalf(
			"malformed duplicate sibling produced receipts: %#v",
			receipts,
		)
	}
}

func cloneCompatibility(
	evidence *ImageCompatibility,
) *ImageCompatibility {
	cloned := *evidence
	cloned.Observations = append(
		[]ImageRuntimeEvidence(nil),
		evidence.Observations...,
	)
	return &cloned
}
