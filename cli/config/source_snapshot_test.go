package config

import "testing"

func TestKubesprayGroupVarOwnershipProjections(t *testing.T) {
	t.Parallel()
	desired := Document{Orchestration: Orchestration{
		Inventory: "orchestration/inventory/atum",
	}}
	runtimeWant := []string{
		"orchestration/inventory/atum/group_vars/all/all.yml",
		"orchestration/inventory/atum/group_vars/all/containerd.yml",
		"orchestration/inventory/atum/group_vars/k8s_cluster/addons.yml",
		"orchestration/inventory/atum/group_vars/k8s_cluster/k8s-cluster.yml",
	}
	selectionWant := []string{
		runtimeWant[0],
		runtimeWant[2],
		runtimeWant[3],
	}
	runtimePaths := KubesprayRuntimeGroupVarPaths(desired)
	selectionPaths := KubespraySelectionGroupVarPaths(desired)
	if len(runtimePaths) != len(runtimeWant) {
		t.Fatalf("runtime group-var paths = %#v, want %#v", runtimePaths, runtimeWant)
	}
	if len(selectionPaths) != len(selectionWant) {
		t.Fatalf(
			"selection group-var paths = %#v, want %#v",
			selectionPaths,
			selectionWant,
		)
	}
	members := RequiredSourceSnapshotMembers(desired)
	for index := range runtimeWant {
		if runtimePaths[index] != runtimeWant[index] {
			t.Fatalf(
				"runtime group-var path %d = %q, want %q",
				index,
				runtimePaths[index],
				runtimeWant[index],
			)
		}
		if !containsSortedMember(members, runtimeWant[index]) {
			t.Errorf("source snapshot does not contain %q", runtimeWant[index])
		}
	}
	for index := range selectionWant {
		if selectionPaths[index] != selectionWant[index] {
			t.Fatalf(
				"selection group-var path %d = %q, want %q",
				index,
				selectionPaths[index],
				selectionWant[index],
			)
		}
	}
	if containsSortedMember(selectionPaths, runtimeWant[1]) {
		t.Fatalf(
			"generated containerd variables became a selection input: %#v",
			selectionPaths,
		)
	}
}

func TestOperatorSourceSnapshotMembership(t *testing.T) {
	desired := Document{
		Project: ProjectConfig{Cluster: "atum"},
		Orchestration: Orchestration{
			Directory: "kubespray",
			Inventory: "kubespray/inventory/atum",
		},
		Platform: Platform{
			Directory: "platform",
			Values:    PlatformValues{Profiles: map[string]string{}},
		},
		Delivery: Delivery{Images: []Image{{
			ID:        "atum-operator",
			Discovery: "first-party",
			Delivery: ImageDelivery{Default: DeliveryChoice{
				Type: "build",
				Materials: []string{
					"platform/build/docker/Dockerfile.operator",
					"cmd/atum-operator",
					"operator",
					"go.mod",
					"go.sum",
				},
			}},
		}}},
	}
	members := RequiredSourceSnapshotMembers(desired)
	for _, wanted := range []string{
		"cmd/atum-operator/",
		"operator/",
		"platform/apps/atum-operator/",
		"platform/build/docker/Dockerfile.operator",
		"go.mod",
		"go.sum",
	} {
		if !containsSortedMember(members, wanted) {
			t.Errorf("source snapshot does not contain %q", wanted)
		}
	}
}

func TestCertificateSourceSnapshotKeepsDisjointFluxOwners(t *testing.T) {
	t.Parallel()
	desired := Document{
		Project: ProjectConfig{Cluster: "atum"},
		Orchestration: Orchestration{
			Directory: "kubespray",
			Inventory: "kubespray/inventory/atum",
		},
		Platform: Platform{
			Directory: "platform",
			Values: PlatformValues{
				Profiles: map[string]string{"local": "platform/profiles/local/prep/values.yaml"},
			},
		},
	}
	members := RequiredSourceSnapshotMembers(desired)
	for _, wanted := range []string{
		"platform/clusters/atum/platform-certificates.yaml",
		"platform/clusters/atum/platform-profile-access.yaml",
		"platform/profiles/local/prep/certificates/kustomization.yaml",
		"platform/profiles/local/access/kustomization.yaml",
		"platform/secrets/atum/pki/kustomization.yaml",
	} {
		if !containsSortedMember(members, wanted) {
			t.Errorf("certificate source snapshot does not contain %q", wanted)
		}
	}
}

func containsSortedMember(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
