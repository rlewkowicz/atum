package update

import (
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/gitcache"
)

func TestLatestOnlyBigBangCandidateDiscardsOlderReleaseCatalog(t *testing.T) {
	t.Parallel()

	latest := resolvedGit{
		Source: config.GitSource{
			Version: "3.31.0",
			Commit:  strings.Repeat("a", 40),
		},
		Checkout: ".atum/cache/bigbang/latest",
		Releases: []gitcache.Release{
			{Version: "3.31.0", Commit: strings.Repeat("a", 40)},
			{Version: "3.30.0", Commit: strings.Repeat("b", 40)},
		},
	}

	candidate := latestOnlyBigBangCandidate(latest)
	if !reflect.DeepEqual(candidate.Source, latest.Source) || candidate.Checkout != latest.Checkout {
		t.Fatalf("latest candidate changed resolved source: %#v", candidate)
	}
	if candidate.Releases != nil {
		t.Fatalf("latest candidate retained fallback releases: %#v", candidate.Releases)
	}
	if len(latest.Releases) != 2 {
		t.Fatal("latest-only projection mutated the resolved release catalog")
	}
}

func TestBigBangPackageAdmissionPrecedesHistoricalArtifactBaseline(t *testing.T) {
	t.Parallel()

	resolved := resolvedGit{Source: config.GitSource{Version: "3.31.0"}}
	malformed := map[string]any{"packages": map[string]any{
		"new": map[string]any{"enabled": true, "sourceType": "git"},
	}}
	if _, err := admitBigBangPackageSelection(
		resolved, map[string]any{}, malformed, malformed, config.Platform{},
	); err == nil {
		t.Fatal("undeclared enabled package passed the pre-artifact admission handoff")
	}
	untrackedChart := map[string]any{"packages": map[string]any{
		"untracked": map[string]any{"enabled": true, "sourceType": "helmRepo"},
	}}
	if _, err := admitBigBangPackageSelection(
		resolved, map[string]any{}, untrackedChart, untrackedChart, config.Platform{},
	); err == nil {
		t.Fatal("untracked HelmRepository declaration passed the pre-artifact admission handoff")
	}

	operational := map[string]any{"packages": map[string]any{
		"new": map[string]any{
			"enabled": true, "sourceType": "git",
			"wrapper": map[string]any{"enabled": true},
			"atum": map[string]any{
				"id": "new", "fluxName": "new", "license": "MIT",
				"integration": "generic",
				"source": map[string]any{
					"repo": "https://example.test/new.git",
					"tag": "1.0.0", "path": "chart",
				},
			},
		},
	}}
	defaults := map[string]any{"wrapper": map[string]any{
		"sourceType": "git",
		"git": map[string]any{
			"repo": "https://example.test/wrapper.git",
			"tag": "0.4.15", "path": "chart",
		},
	}}
	configured, err := config.StripPackageSelectionMetadata(operational, defaults)
	if err != nil {
		t.Fatalf("project package values: %v", err)
	}
	admitted, err := admitBigBangPackageSelection(
		resolved, defaults, operational, configured, config.Platform{},
	)
	if err != nil || len(admitted.packages) != 1 || admitted.packages[0].ID != "new" ||
		len(admitted.wrapperConsumers) != 1 ||
		!admitted.wrapperRequirement.Required ||
		admitted.wrapperRequirement.Declaration.Tag != "0.4.15" {
		t.Fatalf("admitted package handoff = %#v, error %v", admitted, err)
	}
	collision := map[string]any{"packages": map[string]any{
		"bigbang-wrapper": map[string]any{
			"enabled": true, "sourceType": "git",
			"helmRelease": map[string]any{"namespace": "bigbang"},
			"atum": map[string]any{
				"id": "generic-wrapper", "fluxName": "bigbang-wrapper",
				"license": "MIT", "integration": "generic",
				"source": map[string]any{
					"repo": "https://example.test/generic-wrapper.git",
					"tag": "1.0.0", "path": "chart",
				},
			},
		},
	}}
	collisionConfigured, err := config.StripPackageSelectionMetadata(collision, defaults)
	if err != nil {
		t.Fatalf("project collision package values: %v", err)
	}
	if _, err := admitBigBangPackageSelection(
		resolved, defaults, collision, collisionConfigured, config.Platform{},
	); err == nil {
		t.Fatal("generic package overwrote the consumer-independent shared-wrapper source obligation")
	}
	paired, err := pairArtifacts(nil, []artifactInput{{
		ID: "package/new", Path: "new/chart",
	}})
	if err != nil || len(paired) != 1 || !paired[0].IntroductionBaseline {
		t.Fatalf("new package introduction baseline = %#v, error %v", paired, err)
	}
}

func TestBigBangIncompatibilityIsTerminalForLatestAndHistoricalSelections(t *testing.T) {
	t.Parallel()

	failures := []string{
		"3.31.0/Kubernetes 1.34.1: chart/gitlab render failed",
		"3.31.0/Kubernetes 1.33.5: platform identity contract changed",
	}
	latestErr := incompatibleBigBangError("3.31.0", false, failures)
	if !strings.Contains(latestErr.Error(), "newest Big Bang 3.31.0 is incompatible") {
		t.Fatalf("latest incompatibility = %v", latestErr)
	}
	for _, failure := range failures {
		if !strings.Contains(latestErr.Error(), failure) {
			t.Fatalf("latest incompatibility omitted %q: %v", failure, latestErr)
		}
	}
	if strings.Contains(latestErr.Error(), "3.30.0") {
		t.Fatalf("latest incompatibility implied release fallback: %v", latestErr)
	}

	historicalFailure := "3.29.1/Kubernetes 1.32.7: " +
		"platform identity contract: client identity changed"
	historicalErr := incompatibleBigBangError(
		"3.29.1",
		true,
		[]string{historicalFailure},
	)
	for _, expected := range []string{
		"pinned Big Bang 3.29.1 is incompatible",
		"3.29.1/Kubernetes 1.32.7",
		"platform identity contract: client identity changed",
	} {
		if !strings.Contains(historicalErr.Error(), expected) {
			t.Fatalf("historical incompatibility omitted %q: %v", expected, historicalErr)
		}
	}
	if strings.Contains(historicalErr.Error(), "3.28.0") {
		t.Fatalf("historical incompatibility implied release fallback: %v", historicalErr)
	}
}

func TestReleaseLadderAcceptsCompatibleNonLeadingKubernetesCandidate(t *testing.T) {
	t.Parallel()

	candidates := []kubernetesCandidate{
		{
			kubespray: resolvedGit{Source: config.GitSource{Version: "v2.30.0"}},
			kubernetes: kubernetesRelease{Version: "1.34.2"},
		},
		{
			kubespray: resolvedGit{Source: config.GitSource{Version: "v2.29.0"}},
			kubernetes: kubernetesRelease{Version: "1.33.6"},
		},
	}
	current := []config.ClusterRelease{{
		Kubernetes: "1.32.9",
		Kubespray:  config.GitSource{Version: "v2.28.0"},
	}}

	ladder, err := buildReleaseLadder(current, candidates, candidates[1])
	if err != nil {
		t.Fatalf("build release ladder from fallback Kubernetes candidate: %v", err)
	}
	if len(ladder) != 2 || ladder[1].Kubernetes != "1.33.6" ||
		ladder[1].Kubespray.Version != "v2.29.0" {
		t.Fatalf("release ladder = %#v", ladder)
	}
}
