package kube

import "testing"

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
