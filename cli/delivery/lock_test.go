package delivery

import (
	"testing"

	"atum/cli/config"
)

func TestMatchesCommittedDeliverySeparatesBuildExecutionDigest(t *testing.T) {
	t.Parallel()

	committed := config.ImageLock{
		SchemaVersion:   "atum.dev/image-lock/v3",
		Profile:         "platform",
		Platform:        "linux/amd64",
		InventorySHA256: "inventory",
		GraphSHA256:     "graph",
		Images: []config.LockedImage{
			{
				ID: "built", Target: "registry.example/built:v1",
				InputSHA256: "build-input",
				Delivery: config.LockedDelivery{
					Type: "build", BakeTarget: "built",
					Materials:     []string{"Dockerfile"},
					SourceProfile: "platform",
				},
			},
			{
				ID: "mirrored", Target: "registry.example/mirrored:v1",
				Digest: "sha256:mirror", InputSHA256: "mirror-input",
				Delivery: config.LockedDelivery{
					Type: "mirror", Source: "registry.example/upstream:v1",
					Digest: "sha256:mirror", SourceProfile: "platform",
				},
			},
		},
	}
	reproduced := committed
	reproduced.Images = append([]config.LockedImage(nil), committed.Images...)
	reproduced.Images[0].Digest = "sha256:build-output"
	if !matchesCommittedDelivery(reproduced, committed) {
		t.Fatal("execution-owned build digest changed immutable delivery comparison")
	}

	reproduced.Images[1].Digest = "sha256:other-mirror"
	if matchesCommittedDelivery(reproduced, committed) {
		t.Fatal("immutable mirror digest mismatch was accepted")
	}
}

func TestMatchesCommittedDeliveryRejectsBuildDigestInRootLock(t *testing.T) {
	t.Parallel()

	committed := config.ImageLock{Images: []config.LockedImage{{
		ID: "built", Digest: "sha256:legacy",
		Delivery: config.LockedDelivery{Type: "build"},
	}}}
	if matchesCommittedDelivery(committed, committed) {
		t.Fatal("execution-owned build digest was accepted in the committed lock")
	}
}
