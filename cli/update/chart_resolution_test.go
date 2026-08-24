package update

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestApplicationPairedCandidatesRankApplicationBeforeChart(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "3.0.2", AppVersion: "3.0.0", ArchivePath: "3.0.2"},
		{Version: "3.0.1", AppVersion: "3.0.0-rc.1", ArchivePath: "3.0.1"},
		{Version: "3.0.0", AppVersion: "3.0.0", ArchivePath: "3.0.0"},
		{Version: "2.8.2", AppVersion: "2.8.0", ArchivePath: "2.8.2"},
		{Version: "2.8.1", AppVersion: "2.8.0", ArchivePath: "2.8.1"},
		{Version: "2.8.0", AppVersion: "2.8.0", ArchivePath: "2.8.0"},
		{Version: "2.7.0", AppVersion: "2.7.0", ArchivePath: "2.7.0"},
	}
	fetched := make(map[string]chartRelease, len(releases))
	for _, release := range releases {
		fetched[release.Version] = release
	}
	catalog := &chartCatalog{ID: "operator", Name: "operator", fetched: fetched}
	got, err := catalog.applicationPairedCandidates(
		context.Background(), nil, releases, 3, releases[3],
	)
	if err != nil {
		t.Fatalf("applicationPairedCandidates: %v", err)
	}
	versions := make([]string, len(got))
	for i := range got {
		versions[i] = got[i].Version
	}
	want := []string{"3.0.2", "3.0.0", "2.8.2", "2.8.1", "2.8.0"}
	if !reflect.DeepEqual(versions, want) {
		t.Fatalf("candidate order = %v, want %v", versions, want)
	}
}

func TestOpenSearchApplicationCandidatesRejectPrereleasesAndRetainRepairWindow(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "3.0.2", AppVersion: "3.0.0-alpha"},
		{Version: "3.0.1", AppVersion: "3.0.0-alpha"},
		{Version: "3.0.0", AppVersion: "3.0.0-alpha"},
		{Version: "2.8.4", AppVersion: "3.0.0-alpha"},
		{Version: "2.8.3", AppVersion: "3.0.0-alpha"},
		{Version: "2.8.2", AppVersion: "2.8.0"},
		{Version: "2.8.1", AppVersion: "2.8.0"},
		{Version: "2.8.0", AppVersion: "2.8.0"},
		{Version: "2.7.0", AppVersion: "2.7.0"},
	}
	fetched := make(map[string]chartRelease, len(releases))
	for _, release := range releases {
		fetched[release.Version] = release
	}
	catalog := &chartCatalog{ID: "operator", Name: "operator", fetched: fetched}
	for _, currentIndex := range []int{5, 7} {
		got, err := catalog.applicationPairedCandidates(
			context.Background(), nil, releases, currentIndex, releases[currentIndex],
		)
		if err != nil {
			t.Fatalf("applicationPairedCandidates at %d: %v", currentIndex, err)
		}
		versions := make([]string, len(got))
		for i := range got {
			versions[i] = got[i].Version
		}
		want := []string{"2.8.2", "2.8.1", "2.8.0"}
		if !reflect.DeepEqual(versions, want) {
			t.Fatalf("candidate order at %d = %v, want %v", currentIndex, versions, want)
		}
	}
}

func TestApplicationPairedCompatibleReleaseUsesOldestCompatibleSameApplicationBaseline(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "2.8.2", AppVersion: "2.8.0", KubeVersion: ">= 1.30.0", ArchivePath: "2.8.2", ArchiveSHA: "sha"},
		{Version: "2.8.1", AppVersion: "2.8.0", KubeVersion: ">= 1.31.0", ArchivePath: "2.8.1", ArchiveSHA: "sha"},
		{Version: "2.8.0", AppVersion: "2.8.0", KubeVersion: ">= 1.30.0", ArchivePath: "2.8.0", ArchiveSHA: "sha"},
	}
	fetched := make(map[string]chartRelease, len(releases))
	for _, release := range releases {
		fetched[release.Version] = release
	}
	catalog := &chartCatalog{
		ID:                "operator",
		Name:              "operator",
		Current:           "2.8.2",
		CurrentArchiveSHA: "sha",
		Releases:          releases,
		ApplicationPaired: true,
		fetched:           fetched,
	}
	selected, err := catalog.compatibleAt(context.Background(), nil, "1.30.0", 0)
	if err != nil {
		t.Fatalf("compatibleAt: %v", err)
	}
	if selected.Version != "2.8.2" || selected.BaselinePath != "2.8.0" {
		t.Fatalf("selected release = %#v", selected)
	}
}

func TestApplicationPairedChartsBacktrackWithinNewestSemanticApplication(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{
			Version: "2.8.2", AppVersion: "v2.8.0+chart.2",
			ArchivePath: "2.8.2", ArchiveSHA: "sha",
		},
		{
			Version: "2.8.1", AppVersion: "2.8.0+chart.1",
			ArchivePath: "2.8.1", ArchiveSHA: "sha",
		},
		{
			Version: "2.8.0", AppVersion: "2.8.0",
			ArchivePath: "2.8.0", ArchiveSHA: "sha",
		},
	}
	fetched := make(map[string]chartRelease, len(releases))
	for _, release := range releases {
		fetched[release.Version] = release
	}
	catalog := &chartCatalog{
		ID:                "operator",
		Name:              "operator",
		Current:           "2.8.2",
		CurrentArchiveSHA: "sha",
		Releases:          releases,
		ApplicationPaired: true,
		fetched:           fetched,
	}
	for offset, version := range []string{"2.8.2", "2.8.1", "2.8.0"} {
		selected, err := catalog.compatibleAt(context.Background(), nil, "1.30.0", offset)
		if err != nil {
			t.Fatalf("compatibleAt offset %d: %v", offset, err)
		}
		if selected.Version != version || selected.BaselinePath != "2.8.0" {
			t.Fatalf("selected release at offset %d = %#v", offset, selected)
		}
	}
	selected, err := catalog.compatibleAt(context.Background(), nil, "1.30.0", 0)
	if err != nil {
		t.Fatalf("compatibleAt archive spelling: %v", err)
	}
	if selected.AppVersion != "v2.8.0+chart.2" {
		t.Fatalf("selected appVersion = %q, want archive spelling", selected.AppVersion)
	}
}

func TestApplicationPairedCompatibilityDoesNotFallBackFromNewestStableApplication(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "3.0.1", AppVersion: "3.0.0", ArchivePath: "3.0.1", ArchiveSHA: "new"},
		{Version: "3.0.0", AppVersion: "3.0.0", ArchivePath: "3.0.0", ArchiveSHA: "new"},
		{Version: "2.8.0", AppVersion: "2.8.0", ArchivePath: "2.8.0", ArchiveSHA: "old"},
	}
	fetched := make(map[string]chartRelease, len(releases))
	for _, release := range releases {
		fetched[release.Version] = release
	}
	catalog := &chartCatalog{
		ID:                "operator",
		Name:              "operator",
		Current:           "2.8.0",
		CurrentArchiveSHA: "old",
		Releases:          releases,
		ApplicationPaired: true,
		fetched:           fetched,
	}
	_, err := catalog.compatibleAt(context.Background(), nil, "1.30.0", 2)
	if err == nil || !strings.Contains(err.Error(), "newest stable application 3.0.0 has no remaining chart") {
		t.Fatalf("error = %v", err)
	}
}

func TestOpaqueApplicationVersionRetainsChartOrdering(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "2.0.0"},
		{Version: "1.1.0"},
		{Version: "1.0.0"},
	}
	catalog := &chartCatalog{ID: "operator"}
	got, err := catalog.applicationPairedCandidates(
		context.Background(),
		nil,
		releases,
		1,
		chartRelease{AppVersion: "RELEASE.2026-08-22"},
	)
	if err != nil {
		t.Fatalf("applicationPairedCandidates: %v", err)
	}
	if !reflect.DeepEqual(got, releases[:2]) {
		t.Fatalf("opaque application candidates = %#v, want chart-ordered candidates %#v", got, releases[:2])
	}
}

func TestEligibleChartAppVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		appVersion string
		want       bool
	}{
		{name: "stable", appVersion: "3.0.0", want: true},
		{name: "stable with prefix", appVersion: "v3.0.0", want: true},
		{name: "build metadata", appVersion: "3.0.0+build.1", want: true},
		{name: "alpha", appVersion: "3.0.0-alpha", want: false},
		{name: "release candidate", appVersion: "v3.0.0-rc.1", want: false},
		{name: "opaque", appVersion: "RELEASE.2026-08-22", want: true},
		{name: "empty", appVersion: "", want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _ := eligibleChartAppVersion(test.appVersion)
			if got != test.want {
				t.Fatalf("eligibleChartAppVersion(%q) = %t, want %t", test.appVersion, got, test.want)
			}
		})
	}
}

func TestChartReleaseCandidates(t *testing.T) {
	t.Parallel()

	releases := []chartRelease{
		{Version: "3.1.0"},
		{Version: "3.0.2"},
		{Version: "2.8.2"},
	}
	tests := []struct {
		name       string
		appVersion string
		want       int
	}{
		{name: "stable semantic", appVersion: "3.0.0", want: 2},
		{name: "semantic prerelease", appVersion: "3.0.0-alpha", want: 3},
		{name: "opaque", appVersion: "RELEASE.2026-08-22", want: 2},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := chartReleaseCandidates(releases, 1, test.appVersion); len(got) != test.want {
				t.Fatalf("chartReleaseCandidates produced %d candidates, want %d", len(got), test.want)
			}
		})
	}
}

func TestChartArchiveMetadataOwnsApplicationEligibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		indexAppVersion string
		archiveVersion  string
		wantError       bool
	}{
		{
			name:            "index prerelease archive stable",
			indexAppVersion: "2.8.0-alpha",
			archiveVersion:  "2.8.0",
		},
		{
			name:            "index stable archive prerelease",
			indexAppVersion: "2.8.0",
			archiveVersion:  "2.8.0-alpha",
			wantError:       true,
		},
	}
	for _, kind := range []string{"tracked", "bootstrap"} {
		kind := kind
		for _, test := range tests {
			test := test
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				indexRelease := chartRelease{
					Version:    "1.0.0",
					AppVersion: test.indexAppVersion,
					URL:        "https://example.test/operator-1.0.0.tgz",
					ArchiveSHA: strings.Repeat("a", 64),
				}
				archiveRelease := indexRelease
				archiveRelease.AppVersion = test.archiveVersion
				catalog := &chartCatalog{
					ID:       "operator",
					Name:     "operator",
					Releases: []chartRelease{indexRelease},
					fetched: map[string]chartRelease{
						indexRelease.Version: archiveRelease,
					},
				}
				var (
					resolvedApp string
					err         error
				)
				switch kind {
				case "tracked":
					var resolved []resolvedTrackedChart
					resolved, err = resolveTrackedChartsForKubernetes(
						context.Background(),
						nil,
						1,
						[]config.TrackedChart{{ID: "operator", Name: "operator"}},
						[]*chartCatalog{catalog},
						"1.34.0",
						map[string]int{"operator": 0},
						nil,
					)
					if err == nil {
						resolvedApp = resolved[0].Chart.AppVersion
					}
				case "bootstrap":
					var resolved []resolvedBootstrapChart
					resolved, err = resolveBootstrapChartsForKubernetes(
						context.Background(),
						nil,
						1,
						[]config.Chart{{
							ID:     "operator",
							Name:   "operator",
							Target: "registry.test/charts/operator:1.0.0",
						}},
						[]*chartCatalog{catalog},
						"1.34.0",
						map[string]int{"operator": 0},
					)
					if err == nil {
						resolvedApp = resolved[0].Chart.AppVersion
					}
				}
				if test.wantError {
					if err == nil || !strings.Contains(err.Error(), "deploys prerelease appVersion") {
						t.Fatalf("error = %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("resolve chart: %v", err)
				}
				if resolvedApp != test.archiveVersion {
					t.Fatalf("resolved appVersion = %q, want archive value %q", resolvedApp, test.archiveVersion)
				}
			})
		}
	}
}
