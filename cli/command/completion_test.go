package command

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/platform"
)

func TestPlatformCompletionUsesCanonicalCategoriesAndPreservesUnknownRoutes(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	a := &app{project: &config.Project{
		Root: root,
		Desired: config.Document{
			Infrastructure: config.Infrastructure{
				Active: "local",
				Targets: map[string]config.InfrastructureTarget{
					"local": {PlatformProfile: "local"},
				},
			},
			Platform: config.Platform{Directory: "platform"},
		},
	}}
	status := exactCompletionStatus()
	completion, err := a.platformCompletion(status)
	if err != nil {
		t.Fatalf("construct platform completion: %v", err)
	}
	if !completion.Valid() {
		t.Fatal("platform completion is invalid")
	}
	groups := completion.BrowserGroups()
	if len(groups) != 3 ||
		groups[0].Name != "Identity services" ||
		groups[1].Name != "Development services" ||
		groups[2].Name != "Observability services" {
		t.Fatalf("completion groups = %#v", groups)
	}
	for index, wanted := range []string{"OpenBao", "Headlamp", "OpenSearch Dashboards"} {
		found := false
		for _, endpoint := range groups[index].Endpoints {
			found = found || endpoint.Name == wanted
		}
		if !found {
			t.Errorf("%s omits %s: %#v", groups[index].Name, wanted, groups[index].Endpoints)
		}
	}
	if got := completion.ProtocolEndpoints(); len(got) != 2 {
		t.Fatalf("protocol endpoints = %#v, want KAS and registry", got)
	}
	unknown := completion.UncategorizedWebApps()
	if len(unknown) != 1 || unknown[0].URL != "https://unknown.atum.test" {
		t.Fatalf("unknown routes = %#v", unknown)
	}
}

func exactCompletionStatus() platform.Status {
	urls := []string{
		"https://keycloak.atum.test",
		"https://headlamp.atum.test",
		"https://kiali.atum.test",
		"https://grafana.atum.test",
		"https://gitlab.atum.test",
		"https://policy.atum.test",
		"https://harbor.atum.test",
		"https://vault.atum.test",
		"https://prometheus.atum.test",
		"https://alertmanager.atum.test",
		"https://opensearch.atum.test",
		"https://kas.atum.test",
		"https://registry.atum.test",
		"https://unknown.atum.test",
	}
	slices.Sort(urls)
	return platform.Status{
		BundleReady: true, FluxReady: true, PrepReady: true,
		ProfilePrepReady: true, BigBangReady: true, ProfileAccessReady: true,
		ProfileIdentityRequired: true, ProfileIdentityReady: true,
		ClusterOIDCRequired: true, ClusterOIDCReady: true,
		LoadBalancerRequired: true, LoadBalancerReady: true,
		CertificatesRequired: true, CertificatesReady: true, RoutesReady: true,
		HostAccessObserved: true, LocalDNSReady: true, CATrustReady: true,
		RootCAFingerprint: strings.Repeat("a", 64),
		CAFingerprint:     strings.Repeat("a", 64),
		ResolverPath:      "/resolver", CAPath: "/ca",
		PublicIngressVIP: "10.77.0.20", PassthroughIngressVIP: "10.77.0.21",
		AccessURLs:         urls,
		ActiveHelmReleases: 1, ReadyHelmReleases: 1,
		ActiveWorkloads: 1, ReadyWorkloads: 1,
		InternalImageOnly: true, InternalSourcesOnly: true,
	}
}
