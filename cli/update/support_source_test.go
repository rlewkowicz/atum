package update

import (
	"testing"

	"atum/cli/config"
)

func TestWrapperSupportConsumerAndChartPathContract(t *testing.T) {
	t.Parallel()

	values := map[string]any{"packages": map[string]any{
		"opensearch": map[string]any{"wrapper": map[string]any{"enabled": true}},
	}}
	platform := config.Platform{Charts: []config.TrackedChart{{
		ID: "opensearch", ValuesPath: "packages.opensearch",
	}}}
	if consumers, err := config.ActiveWrapperConsumers(platform, values); err != nil || len(consumers) != 1 {
		t.Fatalf("enabled wrapper consumer projection = %#v, error %v", consumers, err)
	}
	for _, path := range []string{"chart", "charts/wrapper"} {
		if !config.SafeRepositoryChartPath(path) {
			t.Fatalf("safe wrapper path %q was rejected", path)
		}
	}
	for _, path := range []string{"", ".", "..", "../chart", "/chart", `chart\wrapper`} {
		if config.SafeRepositoryChartPath(path) {
			t.Fatalf("unsafe wrapper path %q was accepted", path)
		}
	}
}

func TestWrapperSourceDerivesOnlyFromActiveBigBangDeclaration(t *testing.T) {
	t.Parallel()

	defaults := map[string]any{"wrapper": map[string]any{"git": map[string]any{
		"repo": "https://repo.example/wrapper.git", "tag": "0.4.15", "path": "chart",
	}}}
	platform := config.Platform{Charts: []config.TrackedChart{{
		ID: "opensearch", ValuesPath: "packages.OpenSearch",
	}}}
	inactive, consumers, err := wrapperSourceFromBigBang(platform, defaults, map[string]any{})
	if err != nil || len(consumers) != 0 || inactive != (wrapperSourceDeclaration{}) {
		t.Fatalf("inactive wrapper source = %#v, consumers %#v, error %v", inactive, consumers, err)
	}
	effective := map[string]any{"packages": map[string]any{
		"OpenSearch": map[string]any{"wrapper": map[string]any{"enabled": true}},
	}}
	declaration, consumers, err := wrapperSourceFromBigBang(platform, defaults, effective)
	if err != nil || len(consumers) != 1 {
		t.Fatalf("derive active wrapper source: consumers %#v, error %v", consumers, err)
	}
	if declaration.URL != "https://repo.example/wrapper.git" ||
		declaration.Tag != "0.4.15" || declaration.ChartPath != "chart" {
		t.Fatalf("wrapper declaration = %#v", declaration)
	}
	if consumers[0].ReleaseName != "open-search-wrapper" ||
		consumers[0].PackageKey != "open-search" ||
		consumers[0].Namespace != "open-search" ||
		consumers[0].OwnerID != "opensearch" {
		t.Fatalf("normalized source consumer = %#v", consumers[0])
	}
}

func TestWrapperSourceRejectsInvalidDeclarationBeforeResolution(t *testing.T) {
	t.Parallel()

	platform := config.Platform{Charts: []config.TrackedChart{{
		ID: "opensearch", ValuesPath: "packages.opensearch",
	}}}
	effective := map[string]any{"packages": map[string]any{
		"opensearch": map[string]any{"wrapper": map[string]any{"enabled": true}},
	}}
	defaults := map[string]any{"wrapper": map[string]any{"git": map[string]any{
		"repo": "ssh://repo.example/wrapper.git", "tag": "0.4.15", "path": "chart",
	}}}
	if _, _, err := wrapperSourceFromBigBang(platform, defaults, effective); err == nil {
		t.Fatal("unsupported wrapper URL reached resolution")
	}
}

func TestWrapperSourceRejectsMovedTagAndSameBigBangDeclarationChange(t *testing.T) {
	t.Parallel()

	const (
		oldCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		bbCommit  = "cccccccccccccccccccccccccccccccccccccccc"
	)
	previous := config.Resolved{
		BigBang: config.GitSource{Commit: bbCommit},
		SupportSources: []config.SupportSource{{
			ID: "wrapper", ChartPath: "chart",
			Source: config.GitSource{
				URL: "https://repo.example/wrapper.git", Version: "0.4.15", Commit: oldCommit,
			},
		}},
	}
	exact := wrapperSourceDeclaration{
		URL: "https://repo.example/wrapper.git", Tag: "0.4.15", ChartPath: "chart",
	}
	if err := validateWrapperSourceContinuity(previous, previous.BigBang, exact, newCommit); err == nil {
		t.Fatal("moved wrapper tag was accepted")
	}
	changed := exact
	changed.ChartPath = "charts/wrapper"
	if err := validateWrapperSourceContinuity(previous, previous.BigBang, changed, oldCommit); err == nil {
		t.Fatal("changed declaration for an identical Big Bang commit was accepted")
	}
	historical := config.GitSource{Commit: "dddddddddddddddddddddddddddddddddddddddd"}
	downgrade := wrapperSourceDeclaration{
		URL: exact.URL, Tag: "0.3.0", ChartPath: exact.ChartPath,
	}
	if err := validateWrapperSourceContinuity(previous, historical, downgrade, newCommit); err != nil {
		t.Fatalf("historical Big Bang wrapper downgrade was rejected: %v", err)
	}
}

func TestResolvedWrapperChangeInvalidatesMaterialState(t *testing.T) {
	t.Parallel()

	project := &config.Project{
		Desired: config.Document{},
		Lock: config.Lock{Resolved: config.Resolved{SupportSources: []config.SupportSource{{
			ID: "wrapper", Source: config.GitSource{
				Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		}}}},
	}
	desired := project.Desired
	lock := project.Lock
	lock.Resolved.SupportSources = append([]config.SupportSource(nil), project.Lock.Resolved.SupportSources...)
	lock.Resolved.SupportSources[0].Source.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if !materialStateChanged(project, &desired, &lock) {
		t.Fatal("resolved wrapper source change did not invalidate material state")
	}
}
