package update

import "testing"

func TestRenderStatefulValuesOverlayPreservesAdditionalGarageTopology(t *testing.T) {
	t.Parallel()

	projection := statefulValuesProjection{
		values: map[string]any{},
		targetValues: map[string]string{
			"garage-admin-token":       "render-admin-token",
			"garage-access-key-id":     "render-access-key",
			"garage-secret-access-key": "render-secret-key",
		},
	}
	operational := map[string]any{
		"packages": map[string]any{
			"garage": map[string]any{
				"values": map[string]any{
					"garageInit": map[string]any{
						"consumers": []any{
							map[string]any{
								"name":        "gitlab",
								"credentials": map[string]any{},
							},
							map[string]any{"name": "loki"},
						},
					},
					"upstream": map[string]any{
						"environment": []any{
							map[string]any{"name": "GARAGE_ADMIN_TOKEN"},
							map[string]any{"name": "GARAGE_REGION", "value": "local"},
						},
					},
				},
			},
		},
	}

	rendered, err := renderStatefulValuesOverlay(projection, operational)
	if err != nil {
		t.Fatalf("render stateful values: %v", err)
	}
	garage := mapAt(rendered, "packages", "garage", "values")
	consumers := mapSlice(mapAt(garage, "garageInit")["consumers"])
	if len(consumers) != 2 {
		t.Fatalf("consumer count = %d, want 2", len(consumers))
	}
	credentials := mapAt(consumers[0], "credentials")
	if stringAt(credentials, "accessKeyId") != "render-access-key" ||
		stringAt(credentials, "secretAccessKey") != "render-secret-key" {
		t.Fatalf("first consumer credentials were not projected")
	}
	if stringAt(consumers[1], "name") != "loki" {
		t.Fatalf("additional consumer was changed")
	}
	environment := mapSlice(mapAt(garage, "upstream")["environment"])
	if len(environment) != 2 ||
		stringAt(environment[0], "value") != "render-admin-token" ||
		stringAt(environment[1], "value") != "local" {
		t.Fatalf("operational environment topology was not preserved: %#v", environment)
	}
}
