package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestRenderBakeContextPreservesContextAuthority(t *testing.T) {
	tests := []struct {
		name    string
		context bakeContext
		want    string
		wantErr bool
	}{
		{
			name: "local source",
			context: bakeContext{kind: bakeLocalContext, source: "../.."},
			want: "../..",
		},
		{
			name: "image source",
			context: bakeContext{
				kind: bakeImageContext,
				source: "10.77.0.9:32443/atum/golang@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			want: "docker-image://10.77.0.9:32443/atum/golang@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "duplicate image qualifier",
			context: bakeContext{
				kind: bakeImageContext,
				source: "docker-image://10.77.0.9:32443/atum/golang@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := renderBakeContext(test.context)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v", err)
			}
			if got != test.want {
				t.Fatalf("context = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOperatorBuildGraphUsesOneLocalAndOnePinnedHarborContext(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	desired := config.Document{
		Project: config.ProjectConfig{Platform: "linux/amd64"},
		Delivery: config.Delivery{
			Registry: config.Registry{Host: "10.77.0.9:32443"},
			Policy: config.DeliveryPolicy{BuildBase: "10.77.0.9:32443/atum/debian@sha256:" + strings.Repeat("b", 64)},
			Images: []config.Image{
				{ID: "sbom-scanner", Target: "10.77.0.9:32443/atum/sbom-scanner:1"},
				{
					ID: "operator-builder",
					Target: "10.77.0.9:32443/atum/operator-builder:1.26.0",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type: "mirror", Digest: digest,
					}},
				},
				{
					ID: "atum-operator",
					Discovery: "first-party",
					Target: "10.77.0.9:32443/atum/atum-operator:0.1.0",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type: "build", BakeTarget: "atum-operator",
					}},
				},
			},
		},
	}
	graph, err := renderBuildGraph(desired)
	if err != nil {
		t.Fatalf("render graph: %v", err)
	}
	text := string(graph)
	for _, wanted := range []string{
		`atum_source = "../.."`,
		`atum_go_upstream = "docker-image://10.77.0.9:32443/atum/operator-builder:1.26.0@` + digest + `"`,
	} {
		if !strings.Contains(text, wanted) {
			t.Errorf("graph does not contain %q", wanted)
		}
	}
	if strings.Contains(text, "docker-image://../..") ||
		strings.Contains(text, "docker-image://docker-image://") {
		t.Fatalf("graph contains a malformed context:\n%s", text)
	}
}
