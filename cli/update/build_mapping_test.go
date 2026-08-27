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
			name:    "local source",
			context: bakeContext{kind: bakeLocalContext, source: "../.."},
			want:    "../..",
		},
		{
			name: "image source",
			context: bakeContext{
				kind:   bakeImageContext,
				source: "10.77.0.9:32443/atum/golang@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			want: "docker-image://10.77.0.9:32443/atum/golang@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "duplicate image qualifier",
			context: bakeContext{
				kind:   bakeImageContext,
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

func TestOperatorBuildGraphUsesOneLocalAndOnePinnedOfficialContext(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	desired := config.Document{
		Project: config.ProjectConfig{Platform: "linux/amd64"},
		Delivery: config.Delivery{
			Registry: config.Registry{Host: "10.77.0.9:32443"},
			Policy:   config.DeliveryPolicy{BuildBase: "10.77.0.9:32443/atum/debian@sha256:" + strings.Repeat("b", 64)},
			Images: []config.Image{
				{ID: "sbom-scanner", Target: "10.77.0.9:32443/atum/sbom-scanner:1"},
				{
					ID:     "operator-builder",
					Target: "10.77.0.9:32443/atum/operator-builder:1.26.0",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/library/golang:1.26.0-alpine",
						Digest: digest,
					}},
				},
				{
					ID:        "atum-operator",
					Discovery: "first-party",
					Target:    "10.77.0.9:32443/atum/atum-operator:0.1.0",
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
		`atum_go_upstream = "docker-image://docker.io/library/golang:1.26.0-alpine@` + digest + `"`,
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

func TestOperatorBuilderDigestMustBeResolved(t *testing.T) {
	t.Parallel()
	desired := config.Document{
		Delivery: config.Delivery{
			Policy: config.DeliveryPolicy{
				RuntimeRegistryPrefix: "10.77.0.9:32443/atum/",
			},
			Images: []config.Image{
				{
					ID: "operator-builder",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/library/golang:old",
						Digest: "sha256:" + strings.Repeat("a", 64),
					}},
				},
			},
		},
	}
	ensureOperatorImages(&desired)
	var builder config.Image
	for _, image := range desired.Delivery.Images {
		if image.ID == "operator-builder" {
			builder = image
			break
		}
	}
	if builder.Delivery.Default.Digest != "" {
		t.Fatalf(
			"canonical operator builder digest = %q, want unresolved",
			builder.Delivery.Default.Digest,
		)
	}
	for _, digest := range []string{
		"",
		"sha256:" + strings.Repeat("0", 64),
		"sha256:" + strings.Repeat("g", 64),
		"sha512:" + strings.Repeat("a", 64),
	} {
		if isResolvedImageDigest(digest) {
			t.Errorf("unresolved digest %q was accepted", digest)
		}
	}
	if !isResolvedImageDigest("sha256:" + strings.Repeat("a", 64)) {
		t.Error("valid resolved digest was rejected")
	}
}

func TestOperatorBuildGraphRejectsUnresolvedBuilder(t *testing.T) {
	t.Parallel()
	desired := config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{
				{
					ID: "operator-builder",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/library/golang:1.26.0-alpine",
						Digest: "sha256:" + strings.Repeat("0", 64),
					}},
				},
				{
					ID:        "atum-operator",
					Discovery: "first-party",
					Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
						Type:       "build",
						BakeTarget: "atum-operator",
					}},
				},
			},
		},
	}
	if _, err := renderBuildGraph(desired); err == nil ||
		!strings.Contains(err.Error(), "no immutable official builder image") {
		t.Fatalf("render graph error = %v", err)
	}
}
