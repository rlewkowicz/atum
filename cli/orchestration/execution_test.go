package orchestration

import (
	"reflect"
	"testing"
)

func TestManagedKubesprayArgumentsPreserveRawTokens(t *testing.T) {
	t.Parallel()
	raw := []string{
		"--limit", "control-plane",
		"--extra-vars", "@operator-values.json",
		"--", "--native-positional",
	}
	got := managedKubesprayArguments(
		"inventory/atum/hosts.yaml",
		12,
		`{"kube_version":"1.35.4","serial":1}`,
		".atum/cache/kubespray/upgrade-cluster.yml",
		raw,
	)
	want := []string{
		"--inventory", "inventory/atum/hosts.yaml",
		"--forks", "12",
		"--extra-vars", `{"kube_version":"1.35.4","serial":1}`,
		".atum/cache/kubespray/upgrade-cluster.yml",
		"--limit", "control-plane",
		"--extra-vars", "@operator-values.json",
		"--", "--native-positional",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("managed Kubespray arguments:\n got: %#v\nwant: %#v", got, want)
	}
	if !reflect.DeepEqual(raw, want[len(want)-len(raw):]) {
		t.Fatalf("raw Kubespray tokens were mutated: %#v", raw)
	}
}
