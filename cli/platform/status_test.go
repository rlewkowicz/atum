package platform

import "testing"

func TestStatusDimensionsRemainIndependent(t *testing.T) {
	t.Parallel()
	reconciliation := ReconciliationStatus{
		Kustomizations: []ResourceStatus{{Name: "flux-system/sink", Ready: true}},
		BigBangSource:  ResourceStatus{Name: "source", Ready: true},
		BigBangRelease: ResourceStatus{Name: "release", Ready: true},
	}
	if !reconciliation.Complete() {
		t.Fatal("native Ready condition should complete only reconciliation")
	}
	delivery := DeliveryComplianceStatus{
		SourcesInternal:    true,
		RuntimeImagesExact: true,
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

	delivery.RuntimeImagesExact = false
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
