package command

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/platform"
	atumsecrets "atum/cli/secrets"
	"atum/cli/secretvalue"
)

func TestPlatformCompletionUsesCanonicalCategoriesAndPreservesUnknownRoutes(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	a := &app{
		project: &config.Project{
			Root: root,
			Desired: config.Document{
				Project: config.ProjectConfig{Cluster: "atum"},
				Infrastructure: config.Infrastructure{
					Active: "local",
					Targets: map[string]config.InfrastructureTarget{
						"local": {
							PlatformProfile: "local",
							LocalAccess:     &config.LocalAccess{Domain: "atum.test"},
						},
					},
				},
				Platform: config.Platform{Directory: "platform"},
			},
		},
		secretLoader: func(
			context.Context,
			*config.Project,
			atumsecrets.SOPSAdapter,
		) (atumsecrets.Document, error) {
			return atumsecrets.Document{Identity: atumsecrets.IdentitySecrets{
				Seed: secretvalue.New([]byte(base64.RawStdEncoding.EncodeToString(
					bytes.Repeat([]byte{0x5a}, 32),
				))),
			}}, nil
		},
	}
	status := exactCompletionStatus()
	completion, err := a.platformCompletion(t.Context(), status)
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
	for index, wanted := range []string{"Vault", "Headlamp", "OpenSearch Dashboards"} {
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
	kustomizations := make([]platform.ResourceStatus, 6)
	for index := range kustomizations {
		kustomizations[index] = platform.ResourceStatus{Name: "ready", Ready: true}
	}
	return platform.Status{
		Reconciliation: platform.ReconciliationStatus{
			GitRepositories: []platform.ResourceStatus{{Name: "source", Ready: true}},
			Kustomizations: kustomizations,
			OCIRepositories: []platform.ResourceStatus{{Name: "oci", Ready: true}},
			HelmReleases: []platform.ResourceStatus{{Name: "release", Ready: true}},
			Certificates: []platform.ResourceStatus{{Name: "certificate", Ready: true}},
			PlatformConfigurations: []platform.ResourceStatus{{Name: "configuration", Ready: true}},
		},
		Delivery: platform.DeliveryComplianceStatus{
			PublicationExact: true, ForgejoExact: true,
			HarborImagesExact: true, HarborChartsExact: true,
		},
		Local: platform.LocalIntegrationStatus{
			Required: true, LoadBalancerReady: true,
			HostAccessObserved: true, LocalDNSReady: true, CATrustReady: true,
			RootCAFingerprint: strings.Repeat("a", 64),
			CAFingerprint:     strings.Repeat("a", 64),
			ResolverPath:      "/resolver", CAPath: "/ca",
			PublicIngressVIP: "10.77.0.20", PassthroughIngressVIP: "10.77.0.21",
			AccessURLs: urls,
		},
	}
}
