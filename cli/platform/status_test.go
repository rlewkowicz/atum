package platform

import (
	"strings"
	"testing"

	"atum/cli/kube"
)

func TestStatusDimensionsRemainIndependent(t *testing.T) {
	t.Parallel()
	reconciliation := ReconciliationStatus{
		GitRepositories: []ResourceStatus{{Name: "source", Ready: true}},
		Kustomizations: []ResourceStatus{{Name: "flux-system/sink", Ready: true}},
		OCIRepositories: []ResourceStatus{{Name: "oci", Ready: true}},
		HelmReleases: []ResourceStatus{{Name: "release", Ready: true}},
		Certificates: []ResourceStatus{{Name: "certificate", Ready: true}},
		PlatformConfigurations: []ResourceStatus{{Name: "configuration", Ready: true}},
	}
	if !reconciliation.Complete() {
		t.Fatal("native Ready condition should complete only reconciliation")
	}
	delivery := DeliveryComplianceStatus{
		PublicationExact: true,
		ForgejoExact: true,
		HarborImagesExact: true,
		HarborChartsExact: true,
	}
	if !delivery.Compliant() {
		t.Fatal("exact Atum delivery receipts should be compliant")
	}
	local := LocalIntegrationStatus{
		Required:            true,
		LoadBalancerReady:   true,
		HostAccessObserved:  true,
		LocalDNSReady:       true,
		CATrustReady:        true,
		RootCAFingerprint:   "root",
		CAFingerprint:       "root",
	}
	if !local.Exact() {
		t.Fatal("exact local connection receipts should be exact")
	}

	delivery.HarborImagesExact = false
	if delivery.Compliant() {
		t.Fatal("image drift must affect delivery compliance")
	}
	if !reconciliation.Complete() {
		t.Fatal("delivery drift must not redefine native reconciliation")
	}
	if !local.Exact() {
		t.Fatal("delivery drift must not redefine local integration")
	}
}

func TestResourceStatusRejectsStaleNativeGeneration(t *testing.T) {
	t.Parallel()

	object := &kube.Object{
		Name: "atum",
		Namespace: "atum-system",
		Generation: 3,
		Object: map[string]any{
			"status": map[string]any{
				"observedGeneration": int64(2),
				"conditions": []any{
					map[string]any{"type": "Ready", "status": "True"},
				},
			},
		},
	}
	status := resourceStatus(object)
	if status.Ready || !strings.Contains(status.Message, "stale") {
		t.Fatalf("stale native generation was reported as current: %#v", status)
	}
}
