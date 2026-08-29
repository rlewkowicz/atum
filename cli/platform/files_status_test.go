package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/delivery"
)

func TestFileProjectionObserverRejectsNonBastionEndpoint(t *testing.T) {
	t.Parallel()

	project := &config.Project{
		Root: t.TempDir(),
		Desired: config.Document{
			Delivery: config.Delivery{
				Seed: config.SeedPlane{
					KubesprayFiles: config.SeedKubesprayFiles{
						URL: "http://proxy.invalid",
					},
				},
				Kubespray: []config.KubesprayArtifactInventory{{
					Files: []config.KubesprayFile{{
						RepositoryPath: "dl.k8s.io/release",
						SHA256: config.SHA256([]byte("blob")),
						Size: 4,
					}},
				}},
			},
		},
	}
	project.Desired.Delivery.Kubespray[0].Files[0].CacheFile = filepath.Join(
		".atum",
		"cache",
		"kubespray-offline",
		"sha256",
		project.Desired.Delivery.Kubespray[0].Files[0].SHA256,
	)
	cache := filepath.Join(
		project.Root,
		project.Desired.Delivery.Kubespray[0].Files[0].CacheFile,
	)
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := delivery.MaterializeFileManifest(project)
	if err != nil {
		t.Fatal(err)
	}
	service := Service{Project: project}
	receipt := delivery.Receipt{KubesprayFiles: manifest.Identity}
	err = service.observeKubesprayFiles(t.Context(), receipt)
	if err == nil {
		t.Fatal("non-bastion files endpoint was accepted")
	}
}

func TestFileProjectionFailureRemainsAttributedAndNoncompliant(t *testing.T) {
	t.Parallel()

	compliance := DeliveryComplianceStatus{KubesprayFilesExact: true}
	recordKubesprayFilesObservation(
		&compliance,
		fmt.Errorf("dl.k8s.io/release content identity differs"),
	)
	if compliance.KubesprayFilesExact ||
		len(compliance.Issues) != 1 ||
		!strings.Contains(compliance.Issues[0], "dl.k8s.io/release") {
		t.Fatalf("file compliance failure = %#v", compliance)
	}
}
