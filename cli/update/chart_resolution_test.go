package update

import (
	"testing"

	"atum/cli/config"
)

func TestStableChartSelectionUsesChartStabilityNotVersionEquality(t *testing.T) {
	t.Parallel()

	release := chartRelease{Version: "2.8.2", AppVersion: "2.8.0"}
	if eligible, reason := eligibleChartAppVersion(release.AppVersion); !eligible {
		t.Fatalf("stable application version was rejected because it differs from the chart: %s", reason)
	}
	if release.Version == release.AppVersion {
		t.Fatal("test fixture does not exercise distinct chart and application versions")
	}
	if eligible, _ := eligibleChartAppVersion("3.9.0-beta.1"); eligible {
		t.Fatal("stable channel admitted a semantic prerelease application")
	}
	if eligible, reason := eligibleChartAppVersion("vendor-stable"); !eligible {
		t.Fatalf("opaque application version was rejected despite a stable chart: %s", reason)
	}
}

func TestChartReleaseCandidatesRepairPrereleaseWithoutChangingStableWindow(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "3.8.0", AppVersion: "3.8.0"},
		{Version: "3.7.0", AppVersion: "3.7.0"},
		{Version: "3.9.0", AppVersion: "3.9.0-beta.1"},
	}
	stable := chartReleaseCandidates(releases, 0, "3.8.0")
	if len(stable) != 1 || stable[0].Version != "3.8.0" {
		t.Fatalf("stable current release changed its no-downgrade window: %#v", stable)
	}
	repair := chartReleaseCandidates(releases, 2, "3.9.0-beta.1")
	if len(repair) != len(releases) {
		t.Fatalf("prerelease repair did not inspect older stable releases: %#v", repair)
	}
}

func TestCanonicalGenericChartInventoryRetainsOnlyOwnedDirectCharts(t *testing.T) {
	t.Parallel()

	desired := config.Document{
		Platform: config.Platform{
			Charts: []config.TrackedChart{
				{ID: "retired-chart"},
				{ID: "opensearch", ValuesPath: "packages.opensearch"},
				{ID: "opensearch-dashboards", ValuesPath: "packages.opensearch-dashboards"},
				{ID: "cert-manager", ValuesPath: "packages.cert-manager"},
			},
		},
	}
	operational := map[string]any{
		"packages": map[string]any{
			"opensearch":            map[string]any{"enabled": true},
			"opensearch-dashboards": map[string]any{"enabled": true},
		},
	}
	obsolete, err := canonicalizeGenericChartInventory(&desired, operational)
	if err != nil {
		t.Fatalf("canonicalize generic charts: %v", err)
	}
	if len(obsolete) != 0 {
		t.Fatalf("direct generic charts produced migration files: %#v", obsolete)
	}
	for _, chart := range desired.Platform.Charts {
		if chart.ID == "retired-chart" {
			t.Fatal("unsupported chart survived generic chart canonicalization")
		}
	}
	if len(desired.Platform.Charts) != 3 {
		t.Fatalf("generic chart count = %d, want 3", len(desired.Platform.Charts))
	}
}
