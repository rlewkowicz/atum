package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestRetainedCompatibilityBuildRowsExposeEveryRemovalCondition(t *testing.T) {
	t.Parallel()
	images := []config.Image{
		{
			ID:        "atum-operator",
			Discovery: "first-party",
			Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type: "build",
			}},
		},
		{
			ID:        "vault",
			Discovery: "rendered",
			Consumers: []string{"package/vault"},
			BigBangRefs: []string{
				"registry1.dso.mil/ironbank/hashicorp/vault:1.21.4",
			},
			Compatibility: &config.ImageCompatibility{
				Incompatibility:  "official image lacks curl",
				RemovalCondition: "remove when the immutable official image supplies curl",
				Observations: []config.ImageRuntimeEvidence{{
					Artifact:              "package/vault",
					RenderedLocation:      "statefulset/vault/init/prepare",
					RuntimeContractSHA256: strings.Repeat("a", 64),
				}},
			},
			Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type:       "build",
				BakeTarget: "vault-curl-compat",
				Materials:  []string{"docker.io/hashicorp/vault@sha256:" + strings.Repeat("b", 64)},
			}},
		},
	}
	rows, err := renderRetainedCompatibilityBuildRows(images)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rows)
	if !strings.Contains(text, images[1].Compatibility.RemovalCondition) {
		t.Fatalf("retained-build report omits the removal condition:\n%s", text)
	}
	if strings.Contains(text, "atum-operator") {
		t.Fatalf("first-party build was reported as compatibility evidence:\n%s", text)
	}

	images[1].Compatibility.RemovalCondition = ""
	if _, err := renderRetainedCompatibilityBuildRows(images); err == nil {
		t.Fatal("retained-build report accepted missing removal evidence")
	}
}

func TestKubesprayInventoryRowsExposeExactSelectedRuntimeProvenance(t *testing.T) {
	t.Parallel()
	selectionSHA := strings.Repeat("c", 64)
	inventorySHA := strings.Repeat("e", 64)
	inventory := config.KubesprayArtifactInventory{
		KubernetesVersion:       "1.35.4",
		KubesprayCommit:         strings.Repeat("d", 40),
		InventoryScope:          config.KubespraySelectedRuntimeInventory,
		SelectionInputSHA256:    selectionSHA,
		SelectedInventorySHA256: inventorySHA,
		Files:                   make([]config.KubesprayFile, 11),
		Images:                  make([]string, 10),
	}
	rows, err := renderKubesprayInventoryRows(
		[]config.KubesprayArtifactInventory{inventory},
	)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rows)
	for _, evidence := range []string{
		inventory.KubernetesVersion,
		inventory.KubesprayCommit,
		selectionSHA,
		inventorySHA,
		"11",
		"10",
		config.KubespraySelectedRuntimeInventory,
	} {
		if !strings.Contains(text, evidence) {
			t.Errorf("Kubespray report row lacks %q:\n%s", evidence, text)
		}
	}
}
