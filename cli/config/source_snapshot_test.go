package config

import "testing"

func TestOperatorSourceSnapshotMembership(t *testing.T) {
	desired := Document{
		Project: ProjectConfig{Cluster: "atum"},
		Orchestration: Orchestration{
			Directory: "kubespray",
			Inventory: "kubespray/inventory/atum",
		},
		Platform: Platform{
			Directory: "platform",
			Values: PlatformValues{Profiles: map[string]string{}},
		},
		Delivery: Delivery{Images: []Image{{
			ID: "atum-operator",
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

func containsSortedMember(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
