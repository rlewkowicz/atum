package update

import (
	"context"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestApplicationInvocationPreservesTaggedImageArguments(t *testing.T) {
	t.Parallel()

	render := func(tag string) chartInspection {
		rendered := map[string]string{
			"templates/deployment.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: operator
spec:
  template:
    spec:
      containers:
        - name: operator
          image: docker.io/example/operator:2.8.0
          command: [manager]
          args:
            - --delegate=docker.io/example/helper:` + tag + `
`,
		}
		_, invocations, contractSHA, err := inspectRenderedResources(rendered, nil, nil, nil)
		if err != nil {
			t.Fatalf("inspect rendered invocation %s: %v", tag, err)
		}
		return chartInspection{
			Version:     "2.8." + tag,
			AppVersion:  "2.8.0",
			Invocations: invocations,
			ContractSHA: contractSHA,
		}
	}

	baseline := render("1")
	candidate := render("2")
	if baseline.ContractSHA != candidate.ContractSHA {
		t.Fatalf("normalized runtime hash changed from %s to %s", baseline.ContractSHA, candidate.ContractSHA)
	}
	err := validateApplicationInvocation(
		"chart/operator",
		"2.8.0",
		[]string{"docker.io/example/operator"},
		baseline,
		candidate,
	)
	if err == nil || !strings.Contains(err.Error(), "changes the mapped application 2.8.0 container command or arguments") {
		t.Fatalf("error = %v", err)
	}
}

func TestApplicationInvocationAcceptsCompatibleChartOnlyRevision(t *testing.T) {
	t.Parallel()

	repositories := []string{"docker.io/example/operator"}
	baseline := invocationInspection("2.8.0", "2.8.0", repositories[0], []any{"manager"}, []any{"--health-probe-bind-address=:8081"})
	candidate := invocationInspection("2.8.1", "2.8.0", repositories[0], []any{"manager"}, []any{"--health-probe-bind-address=:8081"})
	candidate.Invocations[0].Location = "release/templates/controller.yaml#0/spec/template/spec/containers/operator"
	candidate.Invocations[0].Name = "operator"

	if err := validateApplicationInvocation("chart/operator", "2.8.0", repositories, baseline, candidate); err != nil {
		t.Fatalf("compatible chart-only revision: %v", err)
	}
}

func TestApplicationInvocationRejectsLaterChartsRequiringUnversionedFlags(t *testing.T) {
	t.Parallel()

	repositories := []string{"docker.io/example/operator"}
	baseline := invocationInspection("2.8.0", "2.8.0", repositories[0], []any{"manager"}, nil)
	for _, chartVersion := range []string{"2.8.2", "2.8.1"} {
		chartVersion := chartVersion
		t.Run(chartVersion, func(t *testing.T) {
			t.Parallel()
			candidate := invocationInspection(
				chartVersion,
				"2.8.0",
				repositories[0],
				[]any{"manager"},
				[]any{"--webhook-cert-path=/tmp/k8s-webhook-server/serving-certs"},
			)
			err := validateApplicationInvocation("chart/operator", "2.8.0", repositories, baseline, candidate)
			if err == nil || !strings.Contains(err.Error(), "changes the mapped application 2.8.0 container command or arguments") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestApplicationInvocationRequiresMappedContainerEvidence(t *testing.T) {
	t.Parallel()

	baseline := invocationInspection("2.8.0", "2.8.0", "docker.io/example/sidecar", nil, nil)
	err := validateApplicationInvocation(
		"chart/operator",
		"2.8.0",
		[]string{"docker.io/example/operator"},
		baseline,
		baseline,
	)
	if err == nil || !strings.Contains(err.Error(), "invocation baseline has no container mapped") {
		t.Fatalf("error = %v", err)
	}
}

func TestDirectChartApplicationRepositoriesDeriveFromDeliveryMapping(t *testing.T) {
	t.Parallel()

	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{
				{
					ID:     "operator",
					Target: "registry.example/atum/operator:2.8.0",
					VersionMapping: &config.ImageVersionMapping{
						Artifact: "chart/operator",
						Source:   "chartAppVersion",
						Build: &config.ImageBuildVersionMapping{
							ImageRepository: "docker.io/example/operator",
						},
					},
					Delivery: config.ImageDelivery{
						Default: config.DeliveryChoice{
							Type:   "mirror",
							Source: "docker.io/example/operator:2.8.0",
						},
					},
				},
				{
					ID:     "independent",
					Target: "registry.example/atum/independent:4.0.0",
					VersionMapping: &config.ImageVersionMapping{
						Artifact: "chart/independent",
						Source:   "upstreamImageTag",
					},
					Delivery: config.ImageDelivery{
						Default: config.DeliveryChoice{
							Type:   "mirror",
							Source: "docker.io/example/independent:4.0.0",
						},
					},
				},
			},
		},
	}

	repositories := directChartApplicationRepositories(desired)
	if len(repositories) != 1 || len(repositories["operator"]) != 2 ||
		repositories["operator"][0] != "docker.io/example/operator" ||
		repositories["operator"][1] != "registry.example/atum/operator" {
		t.Fatalf("repositories = %#v", repositories)
	}
}

func TestOpenSearchApplicationSelectionRepairsAndRemainsStable(t *testing.T) {
	t.Parallel()

	allReleases := []chartRelease{
		{Version: "3.0.2", AppVersion: "3.0.0-alpha", ArchivePath: "3.0.2", ArchiveSHA: "alpha"},
		{Version: "3.0.1", AppVersion: "3.0.0-alpha", ArchivePath: "3.0.1", ArchiveSHA: "alpha"},
		{Version: "3.0.0", AppVersion: "3.0.0-alpha", ArchivePath: "3.0.0", ArchiveSHA: "alpha"},
		{Version: "2.8.4", AppVersion: "3.0.0-alpha", ArchivePath: "2.8.4", ArchiveSHA: "alpha"},
		{Version: "2.8.3", AppVersion: "3.0.0-alpha", ArchivePath: "2.8.3", ArchiveSHA: "alpha"},
		{Version: "2.8.2", AppVersion: "2.8.0", ArchivePath: "2.8.2", ArchiveSHA: "2.8.2"},
		{Version: "2.8.1", AppVersion: "2.8.0", ArchivePath: "2.8.1", ArchiveSHA: "2.8.1"},
		{Version: "2.8.0", AppVersion: "2.8.0", ArchivePath: "2.8.0", ArchiveSHA: "2.8.0"},
	}
	stableInvocation := invocationInspection(
		"2.8.0",
		"2.8.0",
		"docker.io/example/operator",
		[]any{"manager"},
		nil,
	)
	webhookInvocation := func(version string) chartInspection {
		return invocationInspection(
			version,
			"2.8.0",
			"docker.io/example/operator",
			[]any{"manager"},
			[]any{"--webhook-port=9443", "--webhook-cert-dir=/tmp/k8s-webhook-server/serving-certs"},
		)
	}

	compatible := map[string]chartInspection{
		"2.8.2": invocationInspection("2.8.2", "2.8.0", "docker.io/example/operator", []any{"manager"}, nil),
		"2.8.1": invocationInspection("2.8.1", "2.8.0", "docker.io/example/operator", []any{"manager"}, nil),
		"2.8.0": stableInvocation,
	}
	if got := selectFixtureApplicationChart(t, allReleases, "2.8.2", compatible); got != "2.8.2" {
		t.Fatalf("newest compatible chart = %s, want 2.8.2", got)
	}

	repair := map[string]chartInspection{
		"2.8.2": webhookInvocation("2.8.2"),
		"2.8.1": webhookInvocation("2.8.1"),
		"2.8.0": stableInvocation,
	}
	if got := selectFixtureApplicationChart(t, allReleases, "2.8.2", repair); got != "2.8.0" {
		t.Fatalf("repaired chart = %s, want 2.8.0", got)
	}
	if got := selectFixtureApplicationChart(t, allReleases, "2.8.0", repair); got != "2.8.0" {
		t.Fatalf("second-pass chart = %s, want unchanged 2.8.0", got)
	}
}

func selectFixtureApplicationChart(
	t *testing.T,
	allReleases []chartRelease,
	current string,
	inspections map[string]chartInspection,
) string {
	t.Helper()

	fetched := make(map[string]chartRelease, len(allReleases))
	currentIndex := -1
	for i := range allReleases {
		fetched[allReleases[i].Version] = allReleases[i]
		if allReleases[i].Version == current {
			currentIndex = i
		}
	}
	if currentIndex < 0 {
		t.Fatalf("fixture current chart %s is absent", current)
	}
	catalog := &chartCatalog{
		ID:                "operator",
		Name:              "operator",
		Current:           current,
		CurrentArchiveSHA: fetched[current].ArchiveSHA,
		ApplicationPaired: true,
		fetched:           fetched,
	}
	candidates, err := catalog.applicationPairedCandidates(
		context.Background(),
		nil,
		allReleases,
		currentIndex,
		fetched[current],
	)
	if err != nil {
		t.Fatalf("resolve fixture candidates: %v", err)
	}
	catalog.Releases = candidates
	configured := []config.TrackedChart{{ID: "operator", Name: "operator", Version: current}}
	offsets := map[string]int{"operator": 0}
	repositories := map[string][]string{"operator": []string{"docker.io/example/operator"}}
	for {
		resolved, err := resolveTrackedChartsForKubernetes(
			context.Background(),
			nil,
			1,
			configured,
			[]*chartCatalog{catalog},
			"1.30.0",
			offsets,
			repositories,
		)
		if err != nil {
			t.Fatalf("resolve fixture chart: %v", err)
		}
		selected := resolved[0]
		candidate, exists := inspections[selected.ArchivePath]
		if !exists {
			t.Fatalf("fixture inspection %s is absent", selected.ArchivePath)
		}
		baseline, exists := inspections[selected.InvocationBaselinePath]
		if !exists {
			t.Fatalf("fixture baseline inspection %s is absent", selected.InvocationBaselinePath)
		}
		if err := validateApplicationInvocation(
			"chart/operator",
			selected.Chart.AppVersion,
			selected.InvocationRepositories,
			baseline,
			candidate,
		); err == nil {
			return selected.Chart.Version
		}
		if !backtrackChart("chart/operator", offsets, map[string]int{}) {
			t.Fatal("fixture chart could not backtrack")
		}
	}
}

func invocationInspection(
	chartVersion string,
	appVersion string,
	repository string,
	command any,
	args any,
) chartInspection {
	return chartInspection{
		Version:    chartVersion,
		AppVersion: appVersion,
		Invocations: []containerInvocation{
			{
				Location:   "release/templates/deployment.yaml#0/spec/template/spec/containers/manager",
				Name:       "manager",
				Repository: repository,
				Command:    command,
				Args:       args,
			},
		},
	}
}
