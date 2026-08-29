package platform

import (
	"context"
	"strings"
	"testing"

	"atum/cli/kube"
)

type recordingResourceGetter struct {
	object    *kube.Object
	found     bool
	resource  kube.Resource
	namespace string
	name      string
}

func (getter *recordingResourceGetter) GetResource(
	_ context.Context,
	resource kube.Resource,
	namespace string,
	name string,
) (*kube.Object, bool, error) {
	getter.resource = resource
	getter.namespace = namespace
	getter.name = name
	return getter.object, getter.found, nil
}

func TestIdentityStatusFetchesOnlyExactSingleton(t *testing.T) {
	t.Parallel()

	getter := &recordingResourceGetter{object: &kube.Object{
		Name: "atum", Namespace: "atum-system", Ready: true,
	}, found: true}
	statuses, err := observeExactResourceStatus(
		context.Background(), getter, kube.PlatformIdentityConfiguration,
		"atum-system", "atum",
	)
	if err != nil {
		t.Fatal(err)
	}
	if getter.resource != kube.PlatformIdentityConfiguration ||
		getter.namespace != "atum-system" || getter.name != "atum" {
		t.Fatalf("exact lookup = %d %s/%s", getter.resource, getter.namespace, getter.name)
	}
	if len(statuses) != 1 || statuses[0].Name != "atum-system/atum" || !statuses[0].Ready {
		t.Fatalf("identity status = %#v", statuses)
	}
}

func TestStatusDimensionsRemainIndependent(t *testing.T) {
	t.Parallel()
	reconciliation := ReconciliationStatus{
		GitRepositories:                []ResourceStatus{{Name: "source", Ready: true}},
		Kustomizations:                 []ResourceStatus{{Name: "flux-system/sink", Ready: true}},
		OCIRepositories:                []ResourceStatus{{Name: "oci", Ready: true}},
		HelmReleases:                   []ResourceStatus{{Name: "release", Ready: true}},
		Certificates:                   []ResourceStatus{{Name: "certificate", Ready: true}},
		PlatformIdentityConfigurations: []ResourceStatus{{Name: "configuration", Ready: true}},
	}
	if !reconciliation.Complete() {
		t.Fatal("native Ready condition should complete only reconciliation")
	}
	delivery := DeliveryComplianceStatus{
		PublicationExact:  true,
		ForgejoExact:      true,
		HarborImagesExact: true,
		HarborChartsExact: true,
		KubesprayFilesExact: true,
	}
	if !delivery.Compliant() {
		t.Fatal("exact Atum delivery receipts should be compliant")
	}
	local := LocalIntegrationStatus{
		Required:           true,
		LoadBalancerReady:  true,
		HostAccessObserved: true,
		LocalDNSReady:      true,
		CATrustReady:       true,
		RootCAFingerprint:  "root",
		CAFingerprint:      "root",
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
		Name:       "atum",
		Namespace:  "atum-system",
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
