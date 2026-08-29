package config

import (
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

func TestSelectedKubesprayImagesExactlyJoinHarborProjection(t *testing.T) {
	t.Parallel()
	sources := []string{
		"quay.io/calico/node:v3.31.4",
		"registry.k8s.io/kube-apiserver:v1.35.4",
	}
	inventory := KubesprayArtifactInventory{
		KubernetesVersion: "1.35.4",
		Images:            make([]string, len(sources)),
	}
	projected := make(map[string]Image, len(sources))
	projectedList := make([]Image, 0, len(sources))
	const targetPrefix = "harbor.internal/atum/"
	for index, source := range sources {
		id, err := KubesprayImageID(source)
		if err != nil {
			t.Fatal(err)
		}
		inventory.Images[index] = id
		image := Image{
			ID: id, Version: strings.TrimPrefix(imageReferenceTag(source), "v"),
			Discovery: "kubespray",
			Scopes:    []string{"kubespray"},
			Runtime:   true,
			Delivery: ImageDelivery{Default: DeliveryChoice{
				Type: "mirror", Source: source,
				Digest: "sha256:" + strings.Repeat("b", 64),
			}},
		}
		projectedList = append(projectedList, image)
	}
	targetTags, err := MirrorTargetTags(projectedList)
	if err != nil {
		t.Fatal(err)
	}
	for index := range projectedList {
		image := &projectedList[index]
		image.Target = targetPrefix + "kubespray/" +
			imageReferenceRepository(image.Delivery.Default.Source) + ":" +
			targetTags[image.ID]
		projected[image.ID] = *image
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
		t.Fatalf("selected projection was rejected: %v", problems)
	}
	if err := validateKubespraySelectedImageProjection(
		inventory, projected,
	); err != nil {
		t.Fatal(err)
	}
	delete(projected, inventory.Images[0])
	if err := validateKubespraySelectedImageProjection(
		inventory, projected,
	); err == nil {
		t.Fatal("missing selected image passed projection validation")
	}
}

func TestKubesprayFileContractRejectsUnsupportedAndMismatchedPaths(t *testing.T) {
	t.Parallel()
	const (
		kubernetesVersion = "1.35.4"
		kubesprayCommit   = "1c9add48975060f45396b34d8e022c30d7f80dab"
	)
	sha256 := strings.Repeat("a", 64)
	inventory := KubesprayArtifactInventory{
		SchemaVersion:           KubesprayArtifactSchema,
		KubernetesVersion:       kubernetesVersion,
		KubesprayCommit:         kubesprayCommit,
		InventoryScope:          KubespraySelectedRuntimeInventory,
		SelectionInputSHA256:    strings.Repeat("b", 64),
		SelectedInventorySHA256: "",
		Files: []KubesprayFile{{
			ID:             "kubeadm",
			Source:         "https://dl.k8s.io/release/v1.35.4/bin/linux/amd64/kubeadm",
			RepositoryPath: "dl.k8s.io/release/v1.35.4/bin/linux/amd64/kubeadm",
			CacheFile:      ".atum/cache/kubespray-offline/sha256/" + sha256,
			SHA256:         sha256,
			Size:           1,
		}},
		Images: []string{"kubespray-kube-apiserver-aabbccddeeff"},
	}
	release := ClusterRelease{
		Kubernetes: kubernetesVersion,
		Kubespray:  GitSource{Commit: kubesprayCommit},
	}
	assertRejected := func(candidate KubesprayArtifactInventory) {
		t.Helper()
		digest, err := KubesprayInventorySHA256(candidate)
		if err != nil {
			t.Fatal(err)
		}
		candidate.SelectedInventorySHA256 = digest
		var problems []string
		validateKubesprayArtifactInventory(
			&problems,
			candidate,
			release,
			false,
		)
		if len(problems) == 0 ||
			problems[0] != "Kubespray file inventory has an invalid artifact record" {
			t.Fatalf("invalid persisted file problems = %#v", problems)
		}
	}

	unsupported := inventory
	unsupported.Files = append([]KubesprayFile(nil), inventory.Files...)
	unsupported.Files[0].Source = "https://artifacts.example.test/kubeadm"
	assertRejected(unsupported)

	mismatched := inventory
	mismatched.Files = append([]KubesprayFile(nil), inventory.Files...)
	mismatched.Files[0].RepositoryPath = "dl.k8s.io/release/v1.35.4/bin/linux/amd64/kubectl"
	assertRejected(mismatched)

	nonCanonical := inventory
	nonCanonical.Files = append([]KubesprayFile(nil), inventory.Files...)
	nonCanonical.Files[0].Source =
		"https://dl.k8s.io/release/../release/v1.35.4/bin/linux/amd64/kubeadm"
	assertRejected(nonCanonical)

	for _, source := range []string{
		"https://user@dl.k8s.io/release/kubeadm",
		"https://dl.k8s.io/release/kubeadm?mutable=true",
		"https://dl.k8s.io/release/kubeadm#fragment",
		"https://dl.k8s.io/release/../release/kubeadm",
		"https://dl.k8s.io/release//kubeadm",
		"https://dl.k8s.io/release/kubeadm/",
		"https://raw.githubusercontent.com/example/project/main/install.yaml",
	} {
		if _, err := KubesprayFileRepositoryPath(source); err == nil {
			t.Fatalf("ambiguous source %q passed the file contract", source)
		}
	}
}
