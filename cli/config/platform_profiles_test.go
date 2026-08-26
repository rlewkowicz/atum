package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestPlatformProfileSelection(t *testing.T) {
	t.Parallel()

	document := Document{
		Infrastructure: Infrastructure{
			Active: "local",
			Targets: map[string]InfrastructureTarget{
				"local": {PlatformProfile: "local"},
			},
		},
		Platform: Platform{
			Directory: "platform",
			Values: PlatformValues{
				Profiles: map[string]string{
					"local": "platform/profiles/local/prep/values.yaml",
				},
			},
			Bootstrap: BootstrapCharts{Charts: []Chart{
				{ID: "global"},
				{ID: "local-only", Profiles: []string{"local"}},
			}},
		},
	}

	if got, want := document.Platform.Values.SortedProfileNames(), []string{"local"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sorted profiles = %v, want %v", got, want)
	}
	if got, want := chartIDs(document.ActiveBootstrapCharts()), []string{"global", "local-only"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("local bootstrap charts = %v, want %v", got, want)
	}
	if got, ok := document.ActiveProfileValuesPath(); !ok || got != "platform/profiles/local/prep/values.yaml" {
		t.Fatalf("local profile values = %q, %t", got, ok)
	}
	if got, ok := document.ActiveIdentityContractPath(); !ok ||
		got != "platform/profiles/local/identity/contract.yaml" {
		t.Fatalf("local identity contract = %q, %t", got, ok)
	}

}

func TestValidateLocalAccess(t *testing.T) {
	t.Parallel()

	valid := LocalAccess{
		Domain:                "atum.test",
		DNSServer:             "10.77.0.1",
		PublicIngressVIP:      "10.77.0.20",
		PassthroughIngressVIP: "10.77.0.21",
		LoadBalancerRange:     "10.77.0.22-10.77.0.39",
		PassthroughHosts:      []string{"keycloak"},
	}
	var problems []string
	validateLocalAccess(&problems, "local", valid)
	if len(problems) != 0 {
		t.Fatalf("valid local access problems = %v", problems)
	}

	invalid := valid
	invalid.Domain = "../atum.test"
	invalid.PassthroughIngressVIP = invalid.PublicIngressVIP
	invalid.PassthroughHosts = []string{"keycloak", "keycloak"}
	invalid.LoadBalancerRange = "10.77.0.39-10.77.0.22"
	validateLocalAccess(&problems, "local", invalid)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		"domain must be a lowercase DNS domain",
		"passthrough host \"keycloak\" is duplicated",
		"must contain passthrough host \"keycloak\" exactly once",
		"passthrough ingress VIP duplicates public ingress VIP",
		"load-balancer range \"10.77.0.39-10.77.0.22\" must be ascending",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems %q do not contain %q", joined, want)
		}
	}
}

func TestMergePlatformValuesOrderAndOwnership(t *testing.T) {
	t.Parallel()

	operational := map[string]any{
		"app": map[string]any{
			"replicas": 1,
			"image":    "operational",
		},
	}
	generated := map[string]any{
		"app": map[string]any{"image": "pinned"},
	}
	profile := map[string]any{
		"app": map[string]any{"replicas": 3},
		"dns": map[string]any{"domain": "atum.test"},
	}

	merged, err := MergePlatformValues(operational, generated, profile)
	if err != nil {
		t.Fatalf("merge platform values: %v", err)
	}
	want := map[string]any{
		"app": map[string]any{
			"replicas": 3,
			"image":    "pinned",
		},
		"dns": map[string]any{"domain": "atum.test"},
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("merged values = %#v, want %#v", merged, want)
	}
	merged["app"].(map[string]any)["image"] = "mutated"
	if generated["app"].(map[string]any)["image"] != "pinned" {
		t.Fatal("merged values alias generated input")
	}

	_, err = MergePlatformValues(operational, generated, map[string]any{
		"app": map[string]any{"image": "profile"},
	})
	if err == nil || !strings.Contains(err.Error(), "app.image") {
		t.Fatalf("generated/profile collision error = %v", err)
	}
}

func chartIDs(charts []Chart) []string {
	ids := make([]string, len(charts))
	for index := range charts {
		ids[index] = charts[index].ID
	}
	return ids
}
