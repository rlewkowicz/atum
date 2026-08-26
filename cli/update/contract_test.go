package update

import (
	"reflect"
	"testing"
)

func TestNormalizeIgnoredChartDefaultsPreservesHelmOverrideSemantics(t *testing.T) {
	t.Parallel()

	defaults := map[string]any{
		"gitlab": map[string]any{
			"sso": map[string]any{
				"groups": []any{},
				"scopes": []any{"Gitlab"},
			},
		},
		"garage": map[string]any{
			"environment": map[string]any{"LOG_LEVEL": "info"},
		},
		"preserved": map[string]any{"enabled": true},
		"nullified": map[string]any{"enabled": true},
	}
	overrides := map[string]any{
		"gitlab": map[string]any{
			"sso": map[string]any{
				"groups": map[string]any{"adminGroups": []any{"atum-admins"}},
			},
		},
		"garage":    map[string]any{"environment": "production"},
		"nullified": nil,
	}

	normalizeIgnoredChartDefaults(defaults, overrides)

	want := map[string]any{
		"gitlab": map[string]any{
			"sso": map[string]any{
				"groups": map[string]any{},
				"scopes": []any{"Gitlab"},
			},
		},
		"garage":    map[string]any{},
		"preserved": map[string]any{"enabled": true},
		"nullified": map[string]any{"enabled": true},
	}
	if !reflect.DeepEqual(defaults, want) {
		t.Fatalf("normalized defaults = %#v, want %#v", defaults, want)
	}
}
