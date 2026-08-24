package update

import (
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestRenderFluxSyncOwnsPostAdmissionRoot(t *testing.T) {
	t.Parallel()
	desired := config.Document{
		Project: config.ProjectConfig{Cluster: "atum"},
		Platform: config.Platform{
			Directory: "platform",
			Sources: config.SourceRegistry{
				ClusterURL:   "http://forgejo:3000",
				Organization: "atum",
				Repository:   "atum",
			},
		},
	}
	data, err := renderFluxSync(desired)
	if err != nil {
		t.Fatal(err)
	}
	sync := string(data)
	for _, required := range []string{
		"branch: deployed",
		"path: ./platform/clusters/atum",
		"url: http://forgejo:3000/atum/atum.git",
	} {
		if !strings.Contains(sync, required) {
			t.Fatalf("rendered Flux sync does not contain %q:\n%s", required, sync)
		}
	}
}

func TestFluxProfilePatch(t *testing.T) {
	t.Parallel()

	current := map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		"kind":       "Kustomization",
		"metadata": map[string]any{
			"name":      "flux-system",
			"namespace": "flux-system",
		},
	}
	local, err := fluxProfilePatch(current, config.InfrastructureTarget{
		PlatformProfile: "local",
		LocalAccess:     &config.LocalAccess{Domain: "atum.test"},
	})
	if err != nil {
		t.Fatalf("local patch: %v", err)
	}
	if !reflect.DeepEqual(local["metadata"], current["metadata"]) ||
		local["apiVersion"] != current["apiVersion"] || local["kind"] != current["kind"] {
		t.Fatalf("local patch identity = %#v", local)
	}
	localSubstitute := local["spec"].(map[string]any)["postBuild"].(map[string]any)["substitute"].(map[string]any)
	if localSubstitute["ATUM_PLATFORM_PROFILE"] != "local" ||
		localSubstitute["ATUM_PLATFORM_DOMAIN"] != "atum.test" {
		t.Fatalf("local substitutions = %#v", localSubstitute)
	}

	cloud, err := fluxProfilePatch(current, config.InfrastructureTarget{
		PlatformProfile: "cloud",
	})
	if err != nil {
		t.Fatalf("cloud patch: %v", err)
	}
	substitute := cloud["spec"].(map[string]any)["postBuild"].(map[string]any)["substitute"].(map[string]any)
	if substitute["ATUM_PLATFORM_PROFILE"] != "cloud" ||
		substitute["ATUM_PLATFORM_DOMAIN"] != "" {
		t.Fatalf("cloud substitutions = %#v", substitute)
	}

	current["metadata"].(map[string]any)["name"] = "other"
	if _, err := fluxProfilePatch(current, config.InfrastructureTarget{}); err == nil {
		t.Fatal("patch accepted the wrong Flux Kustomization")
	}
}
