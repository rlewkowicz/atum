package update

import (
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"

	chart "helm.sh/helm/v4/pkg/chart/v2"
)

func TestNormalizePlaceholderValueMapPreservesHelmOverrideSemantics(t *testing.T) {
	t.Parallel()

	defaults := map[string]any{
		"gitlab": map[string]any{
			"sso": map[string]any{
				"groups": []any{},
				"scopes": []any{"Gitlab"},
			},
		},
		"garage": map[string]any{
			"environment": map[string]any{},
		},
		"policy":    false,
		"preserved": map[string]any{"enabled": true},
		"nullified": map[string]any{"enabled": true},
	}
	overrides := map[string]any{
		"gitlab": map[string]any{
			"sso": map[string]any{
				"groups": map[string]any{"adminGroups": []any{"atum-admins"}},
			},
		},
		"garage": map[string]any{
			"environment": []any{},
		},
		"policy":    map[string]any{"enabled": true},
		"nullified": nil,
	}

	var receipts []config.ChartNormalization
	if err := normalizePlaceholderValueMap(defaults, overrides, "root", &receipts); err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"gitlab": map[string]any{
			"sso": map[string]any{
				"groups": map[string]any{},
				"scopes": []any{"Gitlab"},
			},
		},
		"garage": map[string]any{
			"environment": []any{},
		},
		"policy":    map[string]any{},
		"preserved": map[string]any{"enabled": true},
		"nullified": map[string]any{"enabled": true},
	}
	if !reflect.DeepEqual(defaults, want) {
		t.Fatalf("normalized defaults = %#v, want %#v", defaults, want)
	}
	wantReceipts := []config.ChartNormalization{
		{Path: "root.garage.environment", From: "map", To: "list"},
		{Path: "root.gitlab.sso.groups", From: "list", To: "map"},
		{Path: "root.policy", From: "boolean", To: "map"},
	}
	if !reflect.DeepEqual(receipts, wantReceipts) {
		t.Fatalf("normalization receipts = %#v, want %#v", receipts, wantReceipts)
	}
}

func TestNormalizePlaceholderValueMapRejectsNonEmptyCollectionMismatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		defaults map[string]any
		override any
	}{
		{name: "true", defaults: map[string]any{"value": true}, override: []any{"selected"}},
		{name: "string", defaults: map[string]any{"value": "configured"}, override: map[string]any{"selected": true}},
		{name: "list", defaults: map[string]any{"value": []any{"configured"}}, override: map[string]any{"selected": true}},
		{name: "map", defaults: map[string]any{"value": map[string]any{"configured": true}}, override: []any{"selected"}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var receipts []config.ChartNormalization
			err := normalizePlaceholderValueMap(
				test.defaults,
				map[string]any{"value": test.override},
				"root.alias",
				&receipts,
			)
			if err == nil || !strings.Contains(err.Error(), "root.alias.value") {
				t.Fatalf("normalization error = %v, want full value path", err)
			}
			if len(receipts) != 0 {
				t.Fatalf("normalization receipts = %#v, want none", receipts)
			}
		})
	}
}

func TestNormalizePlaceholderDefaultsMatchesAliasedDependencyByIdentity(t *testing.T) {
	t.Parallel()

	garage := &chart.Chart{
		Metadata: &chart.Metadata{Name: "garage", Version: "0.9.3"},
		Values: map[string]any{
			"environment": map[string]any{},
		},
	}
	common := &chart.Chart{
		Metadata: &chart.Metadata{Name: "bb-common", Version: "1.4.0"},
		Values:   map[string]any{},
	}
	root := &chart.Chart{
		Metadata: &chart.Metadata{
			Name:    "garage",
			Version: "0.9.3-bb.2",
			Dependencies: []*chart.Dependency{
				{Name: "garage", Alias: "upstream", Version: "0.9.3"},
				{Name: "bb-common", Version: "1.4.0"},
			},
		},
		Values: map[string]any{"upstream": map[string]any{}},
	}
	root.SetDependencies(common, garage)
	environment := []any{map[string]any{"name": "GARAGE_ADMIN_TOKEN"}}

	receipts, err := normalizePlaceholderDefaults(root, map[string]any{
		"upstream": map[string]any{"environment": environment},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(garage.Values["environment"], []any{}) {
		t.Fatalf(
			"aliased dependency environment = %#v, want an empty list placeholder for %#v",
			garage.Values["environment"],
			environment,
		)
	}
	wantReceipts := []config.ChartNormalization{{
		Path: "garage.upstream.environment", From: "map", To: "list",
	}}
	if !reflect.DeepEqual(receipts, wantReceipts) {
		t.Fatalf("normalization receipts = %#v, want %#v", receipts, wantReceipts)
	}
}
