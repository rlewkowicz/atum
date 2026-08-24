package config

import (
	"strings"
	"testing"
)

func TestRepositoryInventoryIncludesResolvedSupportInStableOrder(t *testing.T) {
	t.Parallel()

	source := func(version, commit string) GitSource {
		return GitSource{
			URL: "https://example.test/source.git", Version: version,
			Branch: "main", Commit: commit,
		}
	}
	desired := Document{Platform: Platform{
		BigBang: source("3.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Flux:    source("2.0.0", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Packages: []Package{{
			ID: "z-package", Source: source("1.0.0", "cccccccccccccccccccccccccccccccccccccccc"),
		}},
	}}
	resolved := Resolved{SupportSources: []SupportSource{{
		ID: "wrapper", Source: source("0.4.15", "dddddddddddddddddddddddddddddddddddddddd"),
	}}}
	inventory, err := RepositoryInventory(desired, resolved)
	if err != nil {
		t.Fatalf("repository inventory: %v", err)
	}
	want := []string{"bigbang", "flux", "wrapper", "z-package"}
	if len(inventory) != len(want) {
		t.Fatalf("repository count = %d, want %d", len(inventory), len(want))
	}
	for i := range want {
		if inventory[i].ID != want[i] {
			t.Fatalf("repository %d = %q, want %q", i, inventory[i].ID, want[i])
		}
	}
	if inventory[2].CacheKey != "support-wrapper" {
		t.Fatalf("wrapper cache key = %q", inventory[2].CacheKey)
	}
}

func TestRepositoryInventoryRejectsSupportCollision(t *testing.T) {
	t.Parallel()

	desired := Document{Platform: Platform{
		BigBang: GitSource{}, Flux: GitSource{},
		Packages: []Package{{ID: "wrapper"}},
	}}
	_, err := RepositoryInventory(desired, Resolved{
		SupportSources: []SupportSource{{ID: "wrapper"}},
	})
	if err == nil {
		t.Fatal("duplicate package and support source ID was accepted")
	}
}

func TestActiveWrapperConsumersUnifiesPackagesAndTrackedCharts(t *testing.T) {
	t.Parallel()

	platform := Platform{
		Packages: []Package{
			{ID: "git-package", ValuesPath: "packages.GitPackage"},
			{ID: "ignored", ValuesPath: "addons.ignored"},
		},
		Charts: []TrackedChart{
			{ID: "opensearch", ValuesPath: "packages.opensearch"},
			{ID: "disabled", ValuesPath: "packages.disabled"},
		},
	}
	values := map[string]any{"packages": map[string]any{
		"opensearch": map[string]any{
			"namespace": map[string]any{"name": "search"},
			"wrapper":   map[string]any{"enabled": true},
		},
		"disabled": map[string]any{
			"enabled": false, "wrapper": map[string]any{"enabled": true},
		},
		"GitPackage": map[string]any{
			"helmRelease": map[string]any{"namespace": "addons-system"},
			"wrapper":     map[string]any{"enabled": true},
		},
	}, "addons": map[string]any{
		"ignored": map[string]any{
			"wrapper": map[string]any{"enabled": true},
		},
	}}
	consumers, err := ActiveWrapperConsumers(platform, values)
	if err != nil {
		t.Fatalf("active wrapper consumers: %v", err)
	}
	if len(consumers) != 2 {
		t.Fatalf("active consumer count = %d, want 2", len(consumers))
	}
	byOwner := make(map[string]WrapperConsumer, len(consumers))
	for _, consumer := range consumers {
		byOwner[consumer.OwnerID] = consumer
	}
	if got := byOwner["opensearch"]; got.PackageKey != "opensearch" ||
		got.ReleaseName != "opensearch-wrapper" || got.Namespace != "search" {
		t.Fatalf("tracked chart wrapper consumer = %#v", got)
	}
	if got := byOwner["git-package"]; got.ReleaseName != "git-package-wrapper" ||
		got.PackageKey != "git-package" || got.Namespace != "addons-system" {
		t.Fatalf("Git package wrapper consumer = %#v", got)
	}
	if _, exists := byOwner["ignored"]; exists {
		t.Fatal("wrapper-shaped values outside .Values.packages created a consumer")
	}
}

func TestActiveWrapperConsumersRejectsUndeclaredAndAmbiguousReleases(t *testing.T) {
	t.Parallel()

	outside := map[string]any{
		"TopLevel": map[string]any{"wrapper": map[string]any{"enabled": true}},
		"addons": map[string]any{"ignored": map[string]any{
			"wrapper": map[string]any{"enabled": true},
		}},
	}
	consumers, err := ActiveWrapperConsumers(
		Platform{Packages: []Package{{ID: "ignored", ValuesPath: "addons.ignored"}}},
		outside,
	)
	if err != nil || len(consumers) != 0 {
		t.Fatalf("wrapper-shaped values outside packages projected %#v, error %v", consumers, err)
	}

	undeclared := map[string]any{"packages": map[string]any{
		"unknown": map[string]any{"wrapper": map[string]any{"enabled": true}},
	}}
	if _, err := ActiveWrapperConsumers(Platform{}, undeclared); err == nil {
		t.Fatal("undeclared wrapper consumer was accepted")
	}

	platform := Platform{
		Packages: []Package{{ID: "first", ValuesPath: "packages.MyApp"}},
		Charts:   []TrackedChart{{ID: "second", ValuesPath: "packages.my-app"}},
	}
	ambiguous := map[string]any{"packages": map[string]any{
		"MyApp": map[string]any{
			"wrapper": map[string]any{"enabled": true},
		},
		"my-app": map[string]any{
			"namespace": map[string]any{"name": "different"},
			"wrapper":   map[string]any{"enabled": true},
		},
	}}
	if _, err := ActiveWrapperConsumers(platform, ambiguous); err == nil {
		t.Fatal("ambiguous wrapper release identity was accepted")
	}
}

func TestBigBangPackageIdentityMatchesResourceNameContract(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"OpenSearch":  "open-search",
		"HTTPServer":  "http-server",
		"GO_PATH":     "go-path",
		"-Leading":    "leading",
		"punct.value": "punct-value",
	}
	for input, expected := range tests {
		actual, err := bigBangPackageIdentity(input)
		if err != nil {
			t.Fatalf("render package identity %q: %v", input, err)
		}
		if actual != expected {
			t.Fatalf("package identity %q = %q, want %q", input, actual, expected)
		}
	}
	long, err := bigBangPackageIdentity(strings.Repeat("A", 70))
	if err != nil || long != strings.Repeat("a", 63) {
		t.Fatalf("truncated package identity = %q, error %v", long, err)
	}
	longKey := strings.Repeat("A", 70)
	if _, err := ActiveWrapperConsumers(
		Platform{Charts: []TrackedChart{{ID: "long", ValuesPath: "packages." + longKey}}},
		map[string]any{"packages": map[string]any{
			longKey: map[string]any{"wrapper": map[string]any{"enabled": true}},
		}},
	); err == nil {
		t.Fatal("Big Bang identity producing an invalid wrapper release name was accepted")
	}
}

func TestValidateWrapperSupportSourceRequiresImmutableHTTPSIdentity(t *testing.T) {
	t.Parallel()

	valid := SupportSource{
		ID: "wrapper", ValuesPath: "wrapper", ChartPath: "chart",
		Source: GitSource{
			URL: "https://repo.example/wrapper.git", Version: "0.4.15",
			Branch: "main", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	if err := ValidateWrapperSupportSource(valid); err != nil {
		t.Fatalf("valid wrapper support source: %v", err)
	}
	cases := []SupportSource{valid, valid, valid, valid}
	cases[0].Source.URL = "ssh://repo.example/wrapper.git"
	cases[1].Source.Branch = ""
	cases[2].Source.Commit = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases[3].Source.Patches = []string{"patch.diff"}
	for index, source := range cases {
		if err := ValidateWrapperSupportSource(source); err == nil {
			t.Fatalf("invalid wrapper support source %d was accepted", index)
		}
	}
}

func TestStaleLockAllowsMissingSupportProjection(t *testing.T) {
	t.Parallel()

	var problems []string
	validateSupportSources(&problems, &Project{}, true, nil)
	if len(problems) != 0 {
		t.Fatalf("stale support projection problems = %#v", problems)
	}
}

func TestCurrentStateValidatesExactWrapperProjection(t *testing.T) {
	t.Parallel()

	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	project := &Project{
		Root: ".",
		Desired: Document{
			Infrastructure: Infrastructure{
				Active: "local",
				Targets: map[string]InfrastructureTarget{
					"local": {PlatformProfile: "local"},
				},
			},
			Platform: Platform{
				Sources: SourceRegistry{
					ClusterURL: "http://forgejo", UpstreamOrganization: "atum-upstreams",
				},
				Charts: []TrackedChart{{ID: "opensearch", ValuesPath: "packages.opensearch"}},
				Values: PlatformValues{
					Operational: "operational.yaml", Generated: "generated.yaml",
					Profiles: map[string]string{"local": "profile.yaml"},
				},
			},
		},
		Lock: Lock{Resolved: Resolved{SupportSources: []SupportSource{{
			ID: "wrapper", ValuesPath: "wrapper", ChartPath: "chart",
			Source: GitSource{
				URL: "https://repo.example/wrapper.git", Version: "0.4.15",
				Branch: "main", Commit: commit,
			},
		}}}},
	}
	files := map[string][]byte{
		"operational.yaml": []byte(`
wrapper:
  sourceType: git
packages:
  opensearch:
    wrapper:
      enabled: true
`),
		"generated.yaml": []byte(`
wrapper:
  git:
    repo: http://forgejo/atum-upstreams/wrapper.git
    tag: ""
    semver: 0.4.15
    branch: main
    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    path: chart
`),
		"profile.yaml": []byte("{}\n"),
	}
	var problems []string
	validateSupportSources(&problems, project, false, files)
	if len(problems) != 0 {
		t.Fatalf("valid current wrapper projection problems = %#v", problems)
	}
	files["generated.yaml"] = []byte(`
wrapper:
  git:
    repo: http://forgejo/atum-upstreams/wrapper.git
    tag: ""
    semver: 0.4.15
    branch: main
    commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    path: chart
`)
	problems = nil
	validateSupportSources(&problems, project, false, files)
	if len(problems) == 0 {
		t.Fatal("mismatched generated wrapper projection was accepted")
	}
}
