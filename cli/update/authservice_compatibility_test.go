package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestAuthserviceCABundleCompatibilityUsesExactUtilityInitContainer(t *testing.T) {
	t.Parallel()
	const utilityTarget = "registry.test/atum/ubi9:9.8-mirror-digest"
	desired := config.Document{
		Platform: config.Platform{Packages: []config.Package{{
			ID: "authservice",
			Source: config.GitSource{
				Version: authserviceCABundlePackageVersion,
			},
		}}},
		Delivery: config.Delivery{Images: []config.Image{
			{
				ID:        "authservice",
				Version:   authserviceCABundleApplicationVersion,
				Consumers: []string{"package/authservice"},
				BigBangRefs: []string{
					"registry1.dso.mil/ironbank/istio-ecosystem/authservice:1.1.5",
				},
				Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
					Type:   "mirror",
					Source: "ghcr.io/istio-ecosystem/authservice/authservice:1.1.5",
				}},
			},
			{
				ID:      "ubi9",
				Version: authserviceCABundleUtilityVersion,
				Target:  utilityTarget,
				Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
					Type:   "mirror",
					Source: "registry.access.redhat.com/ubi9/ubi:9.8",
				}},
			},
		}},
	}
	generated := make(map[string]any)
	if err := projectAuthserviceCABundleCompatibility(
		generated,
		desired,
		indexSelectedImages(desired.Delivery.Images),
	); err != nil {
		t.Fatal(err)
	}
	renderers, _ := mapAt(
		generated,
		"addons",
		"authservice",
	)["postRenderers"].([]any)
	if len(renderers) != 1 {
		t.Fatalf("Authservice postRenderers = %#v", renderers)
	}
	kustomize, _ := renderers[0].(map[string]any)["kustomize"].(map[string]any)
	patches, _ := kustomize["patches"].([]any)
	if len(patches) != 1 {
		t.Fatalf("Authservice post-render patches = %#v", patches)
	}
	patch, _ := patches[0].(map[string]any)
	target, _ := patch["target"].(map[string]any)
	if target["group"] != "apps" || target["version"] != "v1" ||
		target["kind"] != "Deployment" || target["name"] != "authservice" {
		t.Fatalf("Authservice post-render target = %#v", target)
	}
	content, _ := patch["patch"].(string)
	if !strings.Contains(content, "name: update-ca-bundle") ||
		!strings.Contains(content, utilityTarget) ||
		strings.Contains(content, "\n      containers:") {
		t.Fatalf("Authservice compatibility patch = %q", content)
	}

	desired.Platform.Packages[0].Source.Version = "1.1.6-bb.0"
	if err := projectAuthserviceCABundleCompatibility(
		make(map[string]any),
		desired,
		indexSelectedImages(desired.Delivery.Images),
	); err == nil || !strings.Contains(err.Error(), "requires review") {
		t.Fatalf("unaudited Authservice package error = %v", err)
	}
}
