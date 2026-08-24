package update

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"

	"gopkg.in/yaml.v3"
)

func TestWrapperPolicySemanticsRequireExactOpenSearchTraffic(t *testing.T) {
	t.Parallel()
	resources := []renderedResource{
		testRenderedResource(openSearchNamespace, "PeerAuthentication", map[string]any{
			"spec": map[string]any{"mtls": map[string]any{"mode": "STRICT"}},
		}),
		testRenderedResource(openSearchNamespace, "AuthorizationPolicy", map[string]any{
			"spec": map[string]any{"action": "ALLOW", "rules": []any{
				map[string]any{"from": []any{map[string]any{"source": map[string]any{
					"namespaces": []any{openSearchNamespace},
				}}}},
			}},
		}),
		testRenderedResource(openSearchNamespace, "AuthorizationPolicy", map[string]any{
			"spec": map[string]any{
				"action": "ALLOW",
				"selector": map[string]any{"matchLabels": map[string]any{
					"app.kubernetes.io/name": "opensearch",
				}},
				"rules": []any{map[string]any{
					"from": []any{map[string]any{"source": map[string]any{
						"principals": []any{"cluster.local/ns/fluentbit/sa/fluentbit-fluent-bit"},
					}}},
					"to": []any{map[string]any{"operation": map[string]any{"ports": []any{"9200"}}}},
				}},
			},
		}),
		testRenderedResource(openSearchNamespace, "NetworkPolicy", map[string]any{
			"spec": map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{
					"app.kubernetes.io/name": "opensearch",
				}},
				"policyTypes": []any{"Ingress"},
				"ingress": []any{map[string]any{
					"from": []any{map[string]any{
						"namespaceSelector": map[string]any{"matchLabels": map[string]any{
							"kubernetes.io/metadata.name": "fluentbit",
						}},
						"podSelector": map[string]any{"matchLabels": map[string]any{
							"app.kubernetes.io/name": "fluent-bit",
						}},
					}},
					"ports": []any{map[string]any{"port": 9200, "protocol": "TCP"}},
				}},
			},
		}),
		testRenderedResource(fluentBitNamespace, "NetworkPolicy", map[string]any{
			"spec": map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{
					"app.kubernetes.io/name": "fluent-bit",
				}},
				"policyTypes": []any{"Egress"},
				"egress": []any{map[string]any{
					"to": []any{map[string]any{
						"namespaceSelector": map[string]any{"matchLabels": map[string]any{
							"kubernetes.io/metadata.name": "opensearch",
						}},
						"podSelector": map[string]any{"matchLabels": map[string]any{
							"app.kubernetes.io/name": "opensearch",
						}},
					}},
					"ports": []any{map[string]any{"port": 9200, "protocol": "TCP"}},
				}},
			},
		}),
	}
	if !hasStrictPeerAuthentication(resources, openSearchNamespace) {
		t.Fatal("strict peer authentication was not recognized")
	}
	if !hasSameNamespaceAuthorization(resources, openSearchNamespace) {
		t.Fatal("same-namespace authorization was not recognized")
	}
	if !hasFluentBitAuthorization(resources) {
		t.Fatal("exact Fluent Bit authorization was not recognized")
	}
	if !hasOpenSearchIngress(resources) {
		t.Fatal("exact target ingress was not recognized")
	}
	if !hasFluentBitEgress(resources) {
		t.Fatal("exact source egress was not recognized")
	}
	without := func(index int) []renderedResource {
		result := make([]renderedResource, 0, len(resources)-1)
		result = append(result, resources[:index]...)
		return append(result, resources[index+1:]...)
	}
	if hasFluentBitAuthorization(without(2)) {
		t.Fatal("missing Fluent Bit authorization was accepted")
	}
	if hasOpenSearchIngress(without(3)) {
		t.Fatal("missing OpenSearch target ingress was accepted")
	}
	if hasFluentBitEgress(without(4)) {
		t.Fatal("missing Fluent Bit source egress was accepted")
	}

	source := mapAt(mapSlice(mapSlice(mapAt(resources[2].object, "spec")["rules"])[0]["from"])[0], "source")
	source["principals"] = []any{"cluster.local/ns/fluentbit/sa/other"}
	if hasFluentBitAuthorization(resources) {
		t.Fatal("authorization for the wrong principal was accepted")
	}
	source["principals"] = []any{"cluster.local/ns/fluentbit/sa/fluentbit-fluent-bit"}
	resources[2].object["spec"].(map[string]any)["selector"].(map[string]any)["matchLabels"].(map[string]any)["app.kubernetes.io/name"] = "dashboards"
	if hasFluentBitAuthorization(resources) {
		t.Fatal("authorization for the wrong target selector was accepted")
	}
	resources[2].object["spec"].(map[string]any)["selector"].(map[string]any)["matchLabels"].(map[string]any)["app.kubernetes.io/name"] = "opensearch"
	operation := mapAt(mapSlice(mapSlice(mapAt(resources[2].object, "spec")["rules"])[0]["to"])[0], "operation")
	operation["ports"] = []any{"9201"}
	if hasFluentBitAuthorization(resources) {
		t.Fatal("authorization for the wrong port was accepted")
	}
	operation["ports"] = []any{"9200"}
	resources[3].object["spec"].(map[string]any)["ingress"].([]any)[0].(map[string]any)["ports"].([]any)[0].(map[string]any)["port"] = 9201
	if hasOpenSearchIngress(resources) {
		t.Fatal("target ingress on the wrong port was accepted")
	}
	resources[3].object["spec"].(map[string]any)["ingress"].([]any)[0].(map[string]any)["ports"].([]any)[0].(map[string]any)["port"] = 9200
	resources[4].object["spec"].(map[string]any)["egress"].([]any)[0].(map[string]any)["to"].([]any)[0].(map[string]any)["namespaceSelector"].(map[string]any)["matchLabels"].(map[string]any)["kubernetes.io/metadata.name"] = "logging"
	if hasFluentBitEgress(resources) {
		t.Fatal("source egress to the wrong namespace was accepted")
	}
	resources[4].object["spec"].(map[string]any)["egress"].([]any)[0].(map[string]any)["to"].([]any)[0].(map[string]any)["namespaceSelector"].(map[string]any)["matchLabels"].(map[string]any)["kubernetes.io/metadata.name"] = openSearchNamespace
	resources[4].object["spec"].(map[string]any)["egress"].([]any)[0].(map[string]any)["ports"].([]any)[0].(map[string]any)["port"] = 9201
	if hasFluentBitEgress(resources) {
		t.Fatal("source egress on the wrong port was accepted")
	}
}

func TestWrapperMeshNamespacesRequireSidecarInjection(t *testing.T) {
	t.Parallel()
	resource := renderedResource{
		key: resourceKey{name: fluentBitNamespace, kind: "Namespace"},
		object: map[string]any{"metadata": map[string]any{
			"name":   fluentBitNamespace,
			"labels": map[string]any{"istio-injection": "enabled"},
		}},
	}
	if !hasInjectedNamespace([]renderedResource{resource}, fluentBitNamespace) {
		t.Fatal("enabled namespace injection was not recognized")
	}
	resource.object["metadata"].(map[string]any)["labels"].(map[string]any)["istio-injection"] = "disabled"
	if hasInjectedNamespace([]renderedResource{resource}, fluentBitNamespace) {
		t.Fatal("disabled namespace injection was accepted")
	}
}

func TestWrapperReleaseTopologyUsesOneSharedSource(t *testing.T) {
	t.Parallel()
	collector, support, consumers, registry, _ := wrapperTopologyFixture()
	if err := validateSharedWrapperSource(collector, registry, support); err != nil {
		t.Fatalf("shared wrapper source: %v", err)
	}
	if err := validateWrapperReleaseTopology(collector, consumers, support); err != nil {
		t.Fatalf("wrapper release topology: %v", err)
	}
}

func TestWrapperReleaseTopologyRejectsSourceAndSchemaDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*releaseValueCollector, *config.SupportSource, resourceKey)
		source bool
	}{
		{
			name: "missing source",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				delete(collector.repositories, key)
			},
			source: true,
		},
		{
			name: "duplicate source",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				collector.rendered = append(collector.rendered, renderedResource{key: key})
			},
			source: true,
		},
		{
			name: "source URL",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				source := collector.repositories[key]
				source.url = "http://forgejo/atum-upstreams/not-wrapper.git"
				collector.repositories[key] = source
			},
			source: true,
		},
		{
			name: "source branch",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				source := collector.repositories[key]
				source.refBranch = "release"
				collector.repositories[key] = source
			},
			source: true,
		},
		{
			name: "source commit",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				source := collector.repositories[key]
				source.refCommit = strings.Repeat("b", 40)
				collector.repositories[key] = source
			},
			source: true,
		},
		{
			name: "source tag",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				source := collector.repositories[key]
				source.refTag = "0.4.15"
				collector.repositories[key] = source
			},
			source: true,
		},
		{
			name: "release source binding",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, _ resourceKey) {
				releases := collector.releases["opensearch-wrapper"]
				releases[0].source.name = "other-wrapper"
				collector.releases["opensearch-wrapper"] = releases
			},
		},
		{
			name: "chart path",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, _ resourceKey) {
				releases := collector.releases["opensearch-wrapper"]
				releases[0].chart = "charts/wrapper"
				collector.releases["opensearch-wrapper"] = releases
			},
		},
		{
			name: "reconcile strategy",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, _ resourceKey) {
				releases := collector.releases["opensearch-wrapper"]
				releases[0].reconcile = "ChartVersion"
				collector.releases["opensearch-wrapper"] = releases
			},
		},
		{
			name: "missing release",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, _ resourceKey) {
				delete(collector.releases, "opensearch-wrapper")
			},
		},
		{
			name: "extra release",
			mutate: func(collector *releaseValueCollector, _ *config.SupportSource, key resourceKey) {
				collector.releases["opensearch-dashboards-wrapper"] = []releaseValues{{
					key: resourceKey{
						namespace: openSearchNamespace,
						name:      "opensearch-dashboards-wrapper",
					},
					source: key, chart: "chart", reconcile: "Revision",
				}}
			},
		},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			collector, support, consumers, registry, sourceKey := wrapperTopologyFixture()
			test.mutate(collector, &support, sourceKey)
			var err error
			if test.source {
				err = validateSharedWrapperSource(collector, registry, support)
			} else {
				err = validateWrapperReleaseTopology(collector, consumers, support)
			}
			if err == nil {
				t.Fatalf("%s drift was accepted", test.name)
			}
		})
	}
}

func TestCurrentWrapperContractValuesOnlySuppressesStaleConsumers(t *testing.T) {
	t.Parallel()
	platform := config.Platform{Charts: []config.TrackedChart{{
		ID: "opensearch", ValuesPath: "packages.opensearch",
	}}}
	values := map[string]any{
		"wrapper": map[string]any{"sourceType": "git"},
		"packages": map[string]any{
			"opensearch": map[string]any{
				"enabled": true,
				"wrapper": map[string]any{"enabled": true},
			},
		},
	}
	inputSnapshot := cloneMap(values)
	stale, err := currentWrapperContractValues(values, platform, nil)
	if err != nil {
		t.Fatalf("prepare stale wrapper baseline: %v", err)
	}
	if stringAt(mapAt(stale, "wrapper"), "sourceType") != "helmRepo" {
		t.Fatal("stale baseline did not suppress the unresolved Git source")
	}
	wrapper := mapAt(mapAt(mapAt(stale, "packages"), "opensearch"), "wrapper")
	if enabled, _ := wrapper["enabled"].(bool); enabled {
		t.Fatal("stale baseline retained the unresolved wrapper release")
	}
	original := mapAt(mapAt(mapAt(values, "packages"), "opensearch"), "wrapper")
	if enabled, _ := original["enabled"].(bool); !enabled {
		t.Fatal("stale baseline mutated operational values")
	}
	if !reflect.DeepEqual(values, inputSnapshot) {
		t.Fatal("stale baseline mutated its input")
	}
	secondStale, err := currentWrapperContractValues(stale, platform, nil)
	if err != nil {
		t.Fatalf("repeat stale wrapper baseline: %v", err)
	}
	if !reflect.DeepEqual(stale, secondStale) {
		t.Fatal("stale wrapper baseline changed on the second pass")
	}
	var firstFailures, secondFailures []string
	firstTerminal := recordWrapperCandidateFailure(
		&firstFailures, "3.30.0", "3.30.0", false,
		assertiveError("wrapper source contract: source moved"),
	)
	secondTerminal := recordWrapperCandidateFailure(
		&secondFailures, "3.30.0", "3.30.0", false,
		assertiveError("wrapper source contract: source moved"),
	)
	if !reflect.DeepEqual(firstFailures, secondFailures) || firstTerminal != nil || secondTerminal != nil {
		t.Fatal("wrapper compatibility classification changed on the second pass")
	}

	current, err := currentWrapperContractValues(values, platform, []config.SupportSource{{ID: "wrapper"}})
	if err != nil {
		t.Fatalf("prepare current wrapper baseline: %v", err)
	}
	if current["wrapper"].(map[string]any)["sourceType"] != "git" {
		t.Fatal("resolved wrapper baseline was suppressed")
	}
}

func TestWrapperMeshContractIsInactiveWithoutConsumers(t *testing.T) {
	t.Parallel()
	if err := validatePlatformMeshContract(
		resolvedGit{},
		config.Platform{},
		nil,
		nil,
		map[string]any{},
		"",
		"",
	); err != nil {
		t.Fatalf("inactive wrapper contract: %v", err)
	}
}

func TestWrapperMeshContractRequiresSupportForActiveConsumers(t *testing.T) {
	t.Parallel()
	platform := config.Platform{Charts: []config.TrackedChart{
		{ID: "opensearch-operator", ValuesPath: "packages.opensearch-operator"},
		{ID: "opensearch", ValuesPath: "packages.opensearch"},
	}}
	values := map[string]any{"packages": map[string]any{
		"opensearch-operator": map[string]any{
			"enabled":   true,
			"wrapper":   map[string]any{"enabled": true},
			"namespace": map[string]any{"name": operatorNamespace},
		},
		"opensearch": map[string]any{
			"enabled":   true,
			"wrapper":   map[string]any{"enabled": true},
			"namespace": map[string]any{"name": openSearchNamespace},
		},
	}}
	err := validatePlatformMeshContract(resolvedGit{}, platform, nil, nil, values, "", "")
	if err == nil || !strings.Contains(err.Error(), "one resolved wrapper support source") {
		t.Fatalf("active wrapper contract without support = %v", err)
	}
}

func TestWrapperCandidateFailureClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		coordinate string
		failure    error
	}{
		{
			name:       "source",
			coordinate: "3.30.0",
			failure:    assertiveError("wrapper source contract: source moved"),
		},
		{
			name:       "mesh",
			coordinate: "3.30.0/Kubernetes 1.35.4",
			failure:    assertiveError("wrapper mesh contract: schema changed"),
		},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var failures []string
			terminalErr := recordWrapperCandidateFailure(
				&failures, "3.30.0", test.coordinate, false, test.failure,
			)
			if terminalErr != nil {
				t.Fatalf("ordinary candidate failure became terminal: %v", terminalErr)
			}
			expected := test.coordinate + ": " + test.failure.Error()
			if len(failures) != 1 || failures[0] != expected {
				t.Fatalf("ordinary rejections = %#v", failures)
			}

			failures = nil
			terminalErr = recordWrapperCandidateFailure(
				&failures, "3.30.0", test.coordinate, true, test.failure,
			)
			if len(failures) != 0 || terminalErr == nil ||
				!strings.Contains(terminalErr.Error(), "pinned Big Bang 3.30.0") ||
				!strings.Contains(terminalErr.Error(), test.failure.Error()) {
				t.Fatalf("pinned classification = (%#v, %v)", failures, terminalErr)
			}
		})
	}
}

func TestWrappedPackagesDependOnTheirPolicyOwners(t *testing.T) {
	t.Parallel()
	collector := newReleaseValueCollector("bigbang")
	consumers := []config.WrapperConsumer{
		{PackageKey: "opensearch-operator", ReleaseName: "opensearch-operator-wrapper", Namespace: operatorNamespace},
		{PackageKey: "opensearch", ReleaseName: "opensearch-wrapper", Namespace: openSearchNamespace},
	}
	collector.releases["opensearch-operator"] = []releaseValues{{
		key: resourceKey{namespace: operatorNamespace, name: "opensearch-operator"},
		dependencies: []resourceKey{
			{namespace: operatorNamespace, name: "opensearch-operator-wrapper"},
		},
	}}
	collector.releases["opensearch"] = []releaseValues{{
		key: resourceKey{namespace: openSearchNamespace, name: "opensearch"},
		dependencies: []resourceKey{
			{namespace: operatorNamespace, name: "opensearch-operator"},
			{namespace: openSearchNamespace, name: "opensearch-wrapper"},
		},
	}}
	collector.releases["opensearch-dashboards"] = []releaseValues{{
		key: resourceKey{namespace: openSearchNamespace, name: "opensearch-dashboards"},
		dependencies: []resourceKey{
			{namespace: openSearchNamespace, name: "opensearch"},
		},
	}}
	if err := validateMainReleaseDependencies(collector, consumers); err != nil {
		t.Fatalf("canonical dependency graph: %v", err)
	}
	dashboards := collector.releases["opensearch-dashboards"]
	dashboards[0].dependencies = append(
		dashboards[0].dependencies,
		resourceKey{namespace: openSearchNamespace, name: "opensearch-dashboards-wrapper"},
	)
	collector.releases["opensearch-dashboards"] = dashboards
	if err := validateMainReleaseDependencies(collector, consumers); err == nil {
		t.Fatal("separate Dashboards wrapper dependency was accepted")
	}
}

func TestControlPlaneCIDRUsesMergedProfileValue(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	operational := readWrapperTestValues(t, filepath.Join(root, "platform/apps/bigbang/values.yaml"))
	cloud := readWrapperTestValues(t, filepath.Join(root, "platform/profiles/cloud/prep/values.yaml"))
	local := readWrapperTestValues(t, filepath.Join(root, "platform/profiles/local/prep/values.yaml"))

	portableValues, err := config.MergePlatformValues(operational, nil, cloud)
	if err != nil {
		t.Fatalf("merge portable platform values: %v", err)
	}
	localValues, err := config.MergePlatformValues(operational, nil, local)
	if err != nil {
		t.Fatalf("merge local platform values: %v", err)
	}
	portableCIDR, _ := mapAt(portableValues, "networkPolicies")["controlPlaneCidr"].(string)
	localCIDR, _ := mapAt(localValues, "networkPolicies")["controlPlaneCidr"].(string)
	if portableCIDR != "0.0.0.0/0" {
		t.Fatalf("portable control-plane CIDR = %q", portableCIDR)
	}
	if localCIDR != "10.77.0.8/29" {
		t.Fatalf("local control-plane CIDR = %q", localCIDR)
	}

	policy := func(cidr string) []renderedResource {
		return []renderedResource{controlPlaneResource(cidr)}
	}
	if !hasControlPlaneEgress(policy(portableCIDR), portableCIDR) ||
		hasControlPlaneEgress(policy(portableCIDR), localCIDR) {
		t.Fatal("semantic inspector did not require the portable merged CIDR")
	}
	if !hasControlPlaneEgress(policy(localCIDR), localCIDR) ||
		hasControlPlaneEgress(policy(localCIDR), portableCIDR) {
		t.Fatal("semantic inspector did not require the local merged CIDR")
	}
}

func TestIstiodWebhookIngressRequiresExactControlPlaneCIDR(t *testing.T) {
	t.Parallel()

	policy := func(cidrs ...string) []renderedResource {
		from := make([]any, len(cidrs))
		for index, cidr := range cidrs {
			from[index] = map[string]any{"ipBlock": map[string]any{"cidr": cidr}}
		}
		return []renderedResource{testRenderedResource(
			"istio-system",
			"NetworkPolicy",
			map[string]any{"spec": map[string]any{
				"policyTypes": []any{"Ingress"},
				"ingress": []any{map[string]any{
					"from": from,
					"ports": []any{
						map[string]any{"port": 443, "protocol": "TCP"},
						map[string]any{"port": 15017, "protocol": "TCP"},
					},
				}},
			}},
		)}
	}
	const local = "10.77.0.8/29"
	if !hasIstiodWebhookIngress(policy(local), local) {
		t.Fatal("exact control-plane webhook ingress was rejected")
	}
	if hasIstiodWebhookIngress(policy("10.77.0.0/24"), local) {
		t.Fatal("wrong control-plane webhook ingress was accepted")
	}
	if hasIstiodWebhookIngress(policy(local, "0.0.0.0/0"), local) {
		t.Fatal("broad webhook ingress remained accepted beside the exact policy")
	}
	if !hasIstiodWebhookIngress(policy("0.0.0.0/0"), "0.0.0.0/0") {
		t.Fatal("portable broad control-plane contract was rejected")
	}
}

func TestWrapperNamespaceBaselinePolicies(t *testing.T) {
	t.Parallel()
	resources := operatorWrapperResources("10.77.0.8/29")
	if err := validateNamespaceWrapper(resources, operatorNamespace); err != nil {
		t.Fatalf("baseline wrapper policies: %v", err)
	}
	if !hasControlPlaneEgress(resources, "10.77.0.8/29") {
		t.Fatal("local control-plane CIDR was not recognized")
	}
	if hasControlPlaneEgress(resources, "0.0.0.0/0") {
		t.Fatal("portable CIDR matched a local policy")
	}
}

func TestWrapperNamespaceRejectsPolicySchemaDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func([]renderedResource) []renderedResource
	}{
		{
			name: "strict authentication",
			mutate: func(resources []renderedResource) []renderedResource {
				mapAt(resources[0].object, "spec", "mtls")["mode"] = "PERMISSIVE"
				return resources
			},
		},
		{
			name: "same namespace authorization",
			mutate: func(resources []renderedResource) []renderedResource {
				source := mapAt(mapSlice(mapSlice(mapAt(resources[1].object, "spec")["rules"])[0]["from"])[0], "source")
				source["namespaces"] = []any{"other"}
				return resources
			},
		},
		{
			name: "default deny",
			mutate: func(resources []renderedResource) []renderedResource {
				return append(resources[:2], resources[3:]...)
			},
		},
		{
			name: "DNS egress",
			mutate: func(resources []renderedResource) []renderedResource {
				ports := mapSlice(mapSlice(mapAt(resources[3].object, "spec")["egress"])[0]["ports"])
				ports[0]["port"] = 54
				return resources
			},
		},
		{
			name: "intra namespace",
			mutate: func(resources []renderedResource) []renderedResource {
				mapAt(resources[4].object, "spec")["egress"] = []any{}
				return resources
			},
		},
		{
			name: "Istio sidecar",
			mutate: func(resources []renderedResource) []renderedResource {
				ports := mapSlice(mapSlice(mapAt(resources[5].object, "spec")["egress"])[0]["ports"])
				ports[0]["port"] = 15013
				return resources
			},
		},
		{
			name: "extra network policy",
			mutate: func(resources []renderedResource) []renderedResource {
				return append(resources, testRenderedResource(operatorNamespace, "NetworkPolicy", map[string]any{
					"spec": map[string]any{"podSelector": map[string]any{}},
				}))
			},
		},
		{
			name: "extra peer authentication",
			mutate: func(resources []renderedResource) []renderedResource {
				return append(resources, testRenderedResource(operatorNamespace, "PeerAuthentication", map[string]any{
					"spec": map[string]any{"mtls": map[string]any{"mode": "STRICT"}},
				}))
			},
		},
		{
			name: "extra authorization policy",
			mutate: func(resources []renderedResource) []renderedResource {
				return append(resources, testRenderedResource(operatorNamespace, "AuthorizationPolicy", map[string]any{
					"spec": map[string]any{"rules": []any{}},
				}))
			},
		},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateNamespaceWrapper(
				test.mutate(operatorWrapperResources("10.77.0.8/29")),
				operatorNamespace,
			); err == nil {
				t.Fatalf("%s schema drift was accepted", test.name)
			}
		})
	}
}

type assertiveError string

func (err assertiveError) Error() string { return string(err) }

func wrapperTopologyFixture() (
	*releaseValueCollector,
	config.SupportSource,
	[]config.WrapperConsumer,
	config.SourceRegistry,
	resourceKey,
) {
	commit := strings.Repeat("a", 40)
	support := config.SupportSource{
		ID: "wrapper", ValuesPath: "wrapper", ChartPath: "chart",
		Source: config.GitSource{Branch: "main", Commit: commit},
	}
	collector := newReleaseValueCollector("bigbang")
	sourceKey := resourceKey{namespace: "bigbang", name: "bigbang-wrapper", kind: "GitRepository"}
	collector.repositories[sourceKey] = repositoryResource{
		key: sourceKey, url: "http://forgejo/atum-upstreams/wrapper.git",
		refBranch: "main", refCommit: commit,
	}
	collector.rendered = append(collector.rendered, renderedResource{key: sourceKey})
	for _, namespace := range []string{openSearchNamespace, operatorNamespace} {
		name := namespace + "-wrapper"
		collector.releases[name] = []releaseValues{{
			key:    resourceKey{namespace: namespace, name: name},
			source: sourceKey, chart: "chart", reconcile: "Revision",
		}}
	}
	consumers := []config.WrapperConsumer{
		{ReleaseName: "opensearch-operator-wrapper", Namespace: operatorNamespace},
		{ReleaseName: "opensearch-wrapper", Namespace: openSearchNamespace},
	}
	registry := config.SourceRegistry{
		ClusterURL:           "http://forgejo",
		UpstreamOrganization: "atum-upstreams",
	}
	return collector, support, consumers, registry, sourceKey
}

func readWrapperTestValues(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return values
}

func operatorWrapperResources(cidr string) []renderedResource {
	return []renderedResource{
		testRenderedResource(operatorNamespace, "PeerAuthentication", map[string]any{
			"spec": map[string]any{"mtls": map[string]any{"mode": "STRICT"}},
		}),
		testRenderedResource(operatorNamespace, "AuthorizationPolicy", map[string]any{
			"spec": map[string]any{"rules": []any{map[string]any{
				"from": []any{map[string]any{"source": map[string]any{
					"namespaces": []any{operatorNamespace},
				}}},
			}}},
		}),
		testRenderedResource(operatorNamespace, "NetworkPolicy", map[string]any{
			"spec": map[string]any{
				"podSelector": map[string]any{},
				"policyTypes": []any{"Ingress", "Egress"},
				"ingress":     []any{},
				"egress":      []any{},
			},
		}),
		testRenderedResource(operatorNamespace, "NetworkPolicy", map[string]any{
			"spec": map[string]any{"egress": []any{map[string]any{"ports": []any{
				map[string]any{"port": 53, "protocol": "UDP"},
			}}}},
		}),
		testRenderedResource(operatorNamespace, "NetworkPolicy", map[string]any{
			"spec": map[string]any{
				"ingress": []any{
					map[string]any{"from": []any{
						map[string]any{"podSelector": map[string]any{}},
					}},
				},
				"egress": []any{
					map[string]any{"to": []any{
						map[string]any{"podSelector": map[string]any{}},
					}},
				},
			},
		}),
		testRenderedResource(operatorNamespace, "NetworkPolicy", map[string]any{
			"spec": map[string]any{"egress": []any{map[string]any{
				"ports": []any{map[string]any{"port": 15012}},
				"to": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{
					"istio": "pilot",
				}}}},
			}}},
		}),
		controlPlaneResource(cidr),
	}
}

func controlPlaneResource(cidr string) renderedResource {
	ipBlock := map[string]any{"cidr": cidr}
	if cidr == "0.0.0.0/0" {
		ipBlock["except"] = []any{"169.254.169.254/32"}
	}
	spec := map[string]any{
		"podSelector": map[string]any{},
		"policyTypes": []any{"Egress"},
		"egress": []any{
			map[string]any{"to": []any{
				map[string]any{"ipBlock": ipBlock},
			}},
		},
	}
	return testRenderedResource(operatorNamespace, "NetworkPolicy", map[string]any{"spec": spec})
}

func testRenderedResource(namespace, kind string, object map[string]any) renderedResource {
	return renderedResource{
		key:    resourceKey{namespace: namespace, name: "test", kind: kind},
		object: object,
	}
}
