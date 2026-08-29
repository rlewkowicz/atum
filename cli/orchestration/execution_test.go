package orchestration

import (
	"reflect"
	"testing"
)

func TestManagedKubesprayArgumentsGiveHandoffFinalOptionPrecedence(t *testing.T) {
	t.Parallel()
	const managed = `{"files_repo":"http://10.77.0.9:8080","serial":1}`
	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{
			name: "raw extra vars",
			raw: []string{
				"--limit", "control-plane",
				"--extra-vars", `{"files_repo":"https://unverified.invalid"}`,
			},
			want: []string{
				"--inventory", "inventory/atum/hosts.yaml",
				"--forks", "12",
				".atum/cache/kubespray/upgrade-cluster.yml",
				"--limit", "control-plane",
				"--extra-vars", `{"files_repo":"https://unverified.invalid"}`,
				"--extra-vars", managed,
			},
		},
		{
			name: "literal terminator",
			raw: []string{
				"--extra-vars", "@operator-values.json",
				"--", "--native-positional", "@tail",
			},
			want: []string{
				"--inventory", "inventory/atum/hosts.yaml",
				"--forks", "12",
				".atum/cache/kubespray/upgrade-cluster.yml",
				"--extra-vars", "@operator-values.json",
				"--extra-vars", managed,
				"--", "--native-positional", "@tail",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			raw := append([]string(nil), test.raw...)
			got := managedKubesprayArguments(
				"inventory/atum/hosts.yaml",
				12,
				managed,
				".atum/cache/kubespray/upgrade-cluster.yml",
				raw,
			)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("managed Kubespray arguments:\n got: %#v\nwant: %#v", got, test.want)
			}
			if !reflect.DeepEqual(raw, test.raw) {
				t.Fatalf("raw Kubespray tokens were mutated: %#v", raw)
			}
		})
	}
}
