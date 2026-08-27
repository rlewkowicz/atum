package kube

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestPlatformIdentityConfigurationResource(t *testing.T) {
	t.Parallel()

	got, err := resourceGVR(PlatformIdentityConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	want := schema.GroupVersionResource{
		Group: "platform.atum.dev", Version: "v1alpha1",
		Resource: "platformidentityconfigurations",
	}
	if got != want {
		t.Fatalf("resource = %#v, want %#v", got, want)
	}
}

func TestNodeControlPlaneRoleUsesCanonicalLabels(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{name: "control-plane", labels: map[string]string{
			"node-role.kubernetes.io/control-plane": "",
		}, want: true},
		{name: "legacy master", labels: map[string]string{
			"node-role.kubernetes.io/master": "",
		}, want: true},
		{name: "worker", labels: map[string]string{
			"node-role.kubernetes.io/worker": "",
		}},
		{name: "unlabeled"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := nodeHasControlPlaneRole(test.labels); got != test.want {
				t.Fatalf("control-plane role = %t, want %t", got, test.want)
			}
		})
	}
}
