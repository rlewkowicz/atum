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

func TestWrapperSourceRequirementFollowsRenderedSourceIndependently(t *testing.T) {
	t.Parallel()

	defaults := map[string]any{"wrapper": map[string]any{
		"sourceType": "git",
		"git": map[string]any{
			"repo": "https://repo.example/wrapper.git", "tag": "0.4.15", "path": "chart",
		},
	}}
	platform := config.Platform{Charts: []config.TrackedChart{{
		ID: "opensearch", ValuesPath: "packages.OpenSearch",
	}}}
	inactive, err := config.BigBangWrapperSourceRequirement(defaults, defaults, nil)
	if err != nil || inactive.Required {
		t.Fatalf("inactive wrapper source = %#v, error %v", inactive, err)
	}
	effective := mergeValues(defaults, map[string]any{"packages": map[string]any{
		"OpenSearch": map[string]any{"wrapper": map[string]any{"enabled": false}},
	}})
	consumers, err := config.ActiveWrapperConsumers(platform, effective)
	if err != nil || len(consumers) != 0 {
		t.Fatalf("inactive wrapper consumer projection = %#v, error %v", consumers, err)
	}
	requirement, err := config.BigBangWrapperSourceRequirement(defaults, effective, consumers)
	declaration := requirement.Declaration
	if err != nil || !requirement.Required || len(consumers) != 0 {
		t.Fatalf("derive rendered wrapper source: requirement %#v, consumers %#v, error %v",
			requirement, consumers, err)
	}
	if declaration.URL != "https://repo.example/wrapper.git" ||
		declaration.Tag != "0.4.15" || declaration.ChartPath != "chart" {
		t.Fatalf("wrapper declaration = %#v", declaration)
	}
}

func TestWrapperSourceAcceptsFirstIntroductionSelectedPackage(t *testing.T) {
	t.Parallel()

	selectedPlatform := config.Platform{Packages: []config.Package{{
		ID: "garage", ValuesPath: "packages.Garage",
	}}}
	effective := map[string]any{"packages": map[string]any{
		"Garage": map[string]any{
			"enabled": true,
			"wrapper": map[string]any{"enabled": true},
			"namespace": map[string]any{"name": "storage"},
		},
	}}
	defaults := map[string]any{"wrapper": map[string]any{
		"sourceType": "git",
		"git": map[string]any{
			"repo": "https://repo.example/wrapper.git", "tag": "0.4.15", "path": "chart",
		},
	}}
	effective = mergeValues(defaults, effective)
	consumers, err := config.ActiveWrapperConsumers(selectedPlatform, effective)
	if err != nil {
		t.Fatalf("derive first-introduction consumers: %v", err)
	}
	requirement, err := config.BigBangWrapperSourceRequirement(defaults, effective, consumers)
	if err != nil || requirement.Declaration.Tag != "0.4.15" || len(consumers) != 1 ||
		consumers[0].OwnerID != "garage" ||
		consumers[0].ReleaseKey() != "storage/garage-wrapper" {
		t.Fatalf("first-introduction wrapper source = %#v, consumers %#v, error %v",
			requirement, consumers, err)
	}
}

func TestPostgreSQLAndWrapperSharedUpstreamKeepDistinctRenderedSources(t *testing.T) {
	t.Parallel()

	values := map[string]any{"packages": map[string]any{
		"PostgreSQL": map[string]any{
			"namespace": map[string]any{"name": "postgresql"},
		},
	}}
	pkg := config.Package{
		ID: "postgresql", ValuesPath: "packages.PostgreSQL",
		Integration: "generic", FluxName: "postgre-sql",
		Source: config.GitSource{
			URL: "https://repo.example/wrapper.git",
		},
	}
	err := config.ValidateRenderedSourceReferences(
		values,
		[]config.Package{pkg},
		[]config.RenderedSourceObligation{{
			Owner: "Big Bang shared wrapper source",
			Reference: config.BigBangWrapperSourceReference(),
		}},
	)
	if err != nil {
		t.Fatalf("shared upstream URL conflated rendered source identities: %v", err)
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
	defaults := map[string]any{"wrapper": map[string]any{
		"sourceType": "git",
		"git": map[string]any{
			"repo": "ssh://repo.example/wrapper.git", "tag": "0.4.15", "path": "chart",
		},
	}}
	effective = mergeValues(defaults, effective)
	consumers, err := config.ActiveWrapperConsumers(platform, effective)
	if err != nil {
		t.Fatalf("derive active consumers: %v", err)
	}
	if _, err := config.BigBangWrapperSourceRequirement(defaults, effective, consumers); err == nil {
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
	exact := config.WrapperSourceDeclaration{
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
	downgrade := config.WrapperSourceDeclaration{
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

func TestNewPackageUsesDeclaredCandidateAsIntroductionBaseline(t *testing.T) {
	t.Parallel()

	candidate := artifactInput{
		ID: "package/garage", Path: "declared/garage/chart",
		Values: map[string]any{"persistence": map[string]any{"enabled": true}},
	}
	paired, err := pairArtifacts(map[string]artifactInput{}, []artifactInput{candidate})
	if err != nil {
		t.Fatalf("pair newly declared package: %v", err)
	}
	if len(paired) != 1 || paired[0].CurrentPath != candidate.Path ||
		paired[0].CandidatePath != candidate.Path || !paired[0].IntroductionBaseline {
		t.Fatalf("introduction baseline = %#v", paired)
	}

	if _, err := pairArtifacts(map[string]artifactInput{}, []artifactInput{{
		ID: "chart/undeclared", Path: "chart",
	}}); err == nil {
		t.Fatal("non-package artifact without a historical contract was accepted")
	}
	if _, err := pairArtifacts(map[string]artifactInput{
		"package/retired": {ID: "package/retired", Path: "old/chart"},
	}, nil); err == nil {
		t.Fatal("removal of a previously materialized package contract was accepted")
	}
}

func TestPackageArtifactBindingsPreserveIntegratedFanOutAndGenericIdentity(t *testing.T) {
	t.Parallel()

	collector := newReleaseValueCollector("bigbang")
	integratedSource := resourceKey{
		namespace: "bigbang", name: "istio-gateway", kind: "GitRepository",
	}
	genericSource := resourceKey{
		namespace: "redis", name: "redis", kind: "GitRepository",
	}
	collector.repositories[integratedSource] = repositoryResource{
		key: integratedSource, url: "https://registry.test/upstream/istio-gateway.git",
		refTag: "1.0.0",
	}
	collector.repositories[genericSource] = repositoryResource{
		key: genericSource, url: "https://registry.test/upstream/redis.git",
		refTag: "2.0.0",
	}
	for _, name := range []string{"public-ingressgateway", "passthrough-ingressgateway"} {
		collector.releases[name] = []releaseValues{{
			key: resourceKey{namespace: "bigbang", name: name},
			source: integratedSource, chart: "chart",
		}}
	}
	collector.releases["redis"] = []releaseValues{{
		key: resourceKey{namespace: "redis", name: "redis"},
		source: genericSource, chart: "./chart", reconcile: "Revision",
	}}
	collector.releases["redis-observer"] = []releaseValues{{
		key: resourceKey{namespace: "redis", name: "redis-observer"},
		source: genericSource, chart: "./chart", reconcile: "Revision",
	}}

	instances, err := collector.valuesForArtifacts([]artifactBinding{
		{
			id: "istio-gateway", sourceKind: "GitRepository",
			sourceName: "istio-gateway", sourceNamespace: "bigbang",
			sourceURL: "https://registry.test/upstream/istio-gateway.git",
			sourceTag: "1.0.0", chart: "chart",
			reconcileStrategy: "ChartVersion", defaultReconcile: true,
		},
		{
			id: "redis", sourceKind: "GitRepository",
			sourceName: "redis", sourceNamespace: "redis",
			sourceURL: "https://registry.test/upstream/redis.git",
			sourceTag: "2.0.0", chart: "./chart",
			reconcileStrategy: "Revision",
			releaseName: "redis", releaseNamespace: "redis",
		},
	})
	if err != nil {
		t.Fatalf("collect package artifact bindings: %v", err)
	}
	if len(instances["istio-gateway"]) != 2 {
		t.Fatalf("integrated source consumers = %#v", instances["istio-gateway"])
	}
	if len(instances["redis"]) != 1 || instances["redis"][0].identity != "redis/redis" {
		t.Fatalf("generic source consumers = %#v", instances["redis"])
	}
}
