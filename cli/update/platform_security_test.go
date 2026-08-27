package update

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestValidateOpenSearchMeshContract(t *testing.T) {
	t.Parallel()
	if err := validateOpenSearchMeshContract(validMeshInspections()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOpenSearchMeshContractRejectsDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(map[string]chartInspection)
	}{
		{"namespace injection disabled", func(v map[string]chartInspection) {
			x := v["bigbang"]
			x.Security.Namespaces[0].InjectionEligible = false
			v["bigbang"] = x
		}},
		{"workload opt out", workloadAnnotationMutation(
			"package/fluentbit", "sidecar.istio.io/inject", "false",
		)},
		{"host networking", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Workloads[0].HostNetwork = true
			v["chart/opensearch"] = x
		}},
		{"non boolean host networking", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Workloads[0].HostNetworkValid = false
			v["chart/opensearch"] = x
		}},
		{"excluded inbound", workloadAnnotationMutation(
			"chart/opensearch",
			"traffic.sidecar.istio.io/excludeInboundPorts", "9200",
		)},
		{"excluded outbound", workloadAnnotationMutation(
			"chart/opensearch-dashboards",
			"traffic.sidecar.istio.io/excludeOutboundPorts", "9200",
		)},
		{"excluded nonnumeric", workloadAnnotationMutation(
			"chart/opensearch",
			"traffic.sidecar.istio.io/excludeInboundPorts", "http",
		)},
		{"inclusive inbound omission", workloadAnnotationMutation(
			"chart/opensearch",
			"traffic.sidecar.istio.io/includeInboundPorts", "9300",
		)},
		{"inclusive outbound omission", workloadAnnotationMutation(
			"package/fluentbit",
			"traffic.sidecar.istio.io/includeOutboundPorts", "9300",
		)},
		{"inclusive nonnumeric", workloadAnnotationMutation(
			"chart/opensearch",
			"traffic.sidecar.istio.io/includeInboundPorts", "http",
		)},
		{"excluded outbound IP ranges", workloadAnnotationMutation(
			"package/fluentbit",
			"traffic.sidecar.istio.io/excludeOutboundIPRanges", "10.0.0.0/8",
		)},
		{"partial outbound IP capture", workloadAnnotationMutation(
			"chart/opensearch-dashboards",
			"traffic.sidecar.istio.io/includeOutboundIPRanges", "10.0.0.0/8",
		)},
		{"excluded interface", workloadAnnotationMutation(
			"package/fluentbit",
			"traffic.sidecar.istio.io/excludeInterfaces", "eth0",
		)},
		{"kubevirt interface", workloadAnnotationMutation(
			"chart/opensearch-dashboards",
			"traffic.sidecar.istio.io/kubevirtInterfaces", "eth0",
		)},
		{"disabled interception", workloadAnnotationMutation(
			"package/fluentbit", "sidecar.istio.io/interceptionMode", "NONE",
		)},
		{"partial selected workload selector", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			delete(x.Security.Workloads[0].Selector.Labels, "app.kubernetes.io/instance")
			v["chart/opensearch"] = x
		}},
		{"service target port", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Services[0].Ports[0].TargetPort = 9300
			v["chart/opensearch"] = x
		}},
		{"permissive peer authentication", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.PeerAuthentications[0].Mode = "PERMISSIVE"
			v["wrapper/wrapper"] = x
		}},
		{"selected workload permissive override", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.PeerAuthentications = append(
				x.Security.PeerAuthentications,
				peerAuthenticationObservation{
					Resource: testResource(
						"security.istio.io/v1beta1", "PeerAuthentication",
						"opensearch", "workload-override",
						"wrapper/templates/peerauthentication.yaml#1",
					),
					Selector: exactTestSelector(selectedOpenSearchLabels()),
					Mode:     "PERMISSIVE", ModeValid: true, PortsValid: true,
				},
			)
			v["wrapper/wrapper"] = x
		}},
		{"selected port permissive override", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.PeerAuthentications = append(
				x.Security.PeerAuthentications,
				peerAuthenticationObservation{
					Resource: testResource(
						"security.istio.io/v1beta1", "PeerAuthentication",
						"opensearch", "port-override",
						"wrapper/templates/peerauthentication.yaml#1",
					),
					Selector: exactTestSelector(selectedOpenSearchLabels()),
					Mode:     "STRICT", ModeValid: true, PortsValid: true,
					PortModes: []peerPortModeObservation{{Port: 9200, Mode: "PERMISSIVE"}},
				},
			)
			v["wrapper/wrapper"] = x
		}},
		{"wrong service account", func(v map[string]chartInspection) {
			x := v["package/fluentbit"]
			x.Security.Workloads[0].ServiceAccount = "default"
			v["package/fluentbit"] = x
		}},
		{"wrong principal", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.AuthorizationPolicies[0].Rules[0].From[0].Principals[0] =
				"cluster.local/ns/fluentbit/sa/default"
			v["wrapper/wrapper"] = x
		}},
		{"authorization from omitted", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.AuthorizationPolicies[0].Rules[0].FromPresent = false
			v["wrapper/wrapper"] = x
		}},
		{"authorization to omitted", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.AuthorizationPolicies[0].Rules[0].ToPresent = false
			v["wrapper/wrapper"] = x
		}},
		{"authorization broad rule added", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.AuthorizationPolicies[0].Rules = append(
				x.Security.AuthorizationPolicies[0].Rules,
				authorizationRuleObservation{},
			)
			v["wrapper/wrapper"] = x
		}},
		{"egress wildcard peer", func(v map[string]chartInspection) {
			x := v["package/fluentbit"]
			x.Security.NetworkPolicies[0].Egress[0].Peers =
				append(x.Security.NetworkPolicies[0].Egress[0].Peers, networkPeerObservation{})
			v["package/fluentbit"] = x
		}},
		{"egress wildcard rule", func(v map[string]chartInspection) {
			x := v["package/fluentbit"]
			x.Security.NetworkPolicies[0].Egress = append(
				x.Security.NetworkPolicies[0].Egress,
				networkRuleObservation{PeersPresent: true, PeersValid: true},
			)
			v["package/fluentbit"] = x
		}},
		{"ingress ip block", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.NetworkPolicies[0].Ingress[0].Peers[0].IPBlockPresent = true
			v["wrapper/wrapper"] = x
		}},
		{"ingress wrong policy type", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			x.Security.NetworkPolicies[0].PolicyTypes[0] = "Egress"
			v["wrapper/wrapper"] = x
		}},
		{"ingress partial selector", func(v map[string]chartInspection) {
			x := v["wrapper/wrapper"]
			delete(x.Security.NetworkPolicies[0].Selector.Labels,
				"app.kubernetes.io/instance")
			v["wrapper/wrapper"] = x
		}},
		{"probe drift", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Workloads[0].ReadinessPort = 0
			v["chart/opensearch"] = x
		}},
		{"selected workload missing behind lookalike", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Workloads[0].Resource.Name = "opensearch-lookalike"
			v["chart/opensearch"] = x
		}},
		{"selected workload ambiguous", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Workloads = append(x.Security.Workloads, x.Security.Workloads[0])
			v["chart/opensearch"] = x
		}},
		{"selected service missing behind lookalike", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Services[0].Resource.Name = "opensearch-lookalike"
			v["chart/opensearch"] = x
		}},
		{"selected service ambiguous", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Services = append(x.Security.Services, x.Security.Services[0])
			v["chart/opensearch"] = x
		}},
		{"networked init replacement", func(v map[string]chartInspection) {
			x := v["chart/opensearch"]
			x.Security.Workloads[0].ConfigInitCount = 0
			x.Security.Workloads[0].ConfigInitLocal = false
			v["chart/opensearch"] = x
		}},
		{"probe rewrite disabled", func(v map[string]chartInspection) {
			x := v["package/istiod"]
			x.Security.ProbeRewrites = nil
			v["package/istiod"] = x
		}},
		{"wrong Istiod ConfigMap", func(v map[string]chartInspection) {
			x := v["package/istiod"]
			x.Security.ProbeRewrites[0].Resource.Name = "lookalike-injector"
			v["package/istiod"] = x
		}},
		{"ambiguous Istiod ConfigMap", func(v map[string]chartInspection) {
			x := v["package/istiod"]
			x.Security.ProbeRewrites = append(
				x.Security.ProbeRewrites, x.Security.ProbeRewrites[0],
			)
			v["package/istiod"] = x
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := validMeshInspections()
			test.mutate(values)
			if err := validateOpenSearchMeshContract(values); err == nil {
				t.Fatal("invalid selected-render security shape was accepted")
			}
		})
	}
}

func workloadAnnotationMutation(
	artifact string, key string, value string,
) func(map[string]chartInspection) {
	return func(values map[string]chartInspection) {
		inspection := values[artifact]
		inspection.Security.Workloads[0].Capture.Values[key] = value
		values[artifact] = inspection
	}
}

func TestMeshContractErrorsIncludeRenderedResourceLocation(t *testing.T) {
	t.Parallel()
	values := validMeshInspections()
	wrapper := values["wrapper/wrapper"]
	wrapper.Security.AuthorizationPolicies[0].Rules[0].FromPresent = false
	values["wrapper/wrapper"] = wrapper
	err := validateOpenSearchMeshContract(values)
	for _, expected := range []string{
		"security.istio.io/v1/AuthorizationPolicy",
		"opensearch/allow-fluentbit-opensearch",
		"wrapper/templates/authorizationpolicy.yaml#0",
	} {
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

func TestMeshContractRejectsNonWrapperPeerWeakeningWithSource(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"PERMISSIVE", "DISABLE"} {
		t.Run(mode, func(t *testing.T) {
			values := validMeshInspections()
			inspection := values["package/istiod"]
			inspection.Security.PeerAuthentications = append(
				inspection.Security.PeerAuthentications,
				peerAuthenticationObservation{
					Resource: testResource(
						"security.istio.io/v1beta1", "PeerAuthentication",
						"opensearch", "selected-port-weakening",
						"istiod/templates/selected-port-weakening.yaml#0",
					),
					Selector: exactTestSelector(selectedOpenSearchLabels()),
					Mode:     "STRICT", ModeValid: true, PortsValid: true,
					PortModes: []peerPortModeObservation{{Port: 9200, Mode: mode}},
				},
			)
			values["package/istiod"] = inspection

			var renderError *artifactRenderError
			err := validateOpenSearchMeshContract(values)
			if !errors.As(err, &renderError) ||
				renderError.id != "package/istiod" ||
				!strings.Contains(err.Error(),
					"istiod/templates/selected-port-weakening.yaml#0") {
				t.Fatalf("%s weakening attribution = %v", mode, err)
			}
		})
	}
}

func TestMeshContractRejectsCrossArtifactExpectedPolicyDuplicate(t *testing.T) {
	t.Parallel()
	values := validMeshInspections()
	wrapper := values["wrapper/wrapper"]
	openSearch := values["chart/opensearch"]
	duplicate := wrapper.Security.AuthorizationPolicies[0]
	duplicate.Resource.Path = "opensearch/templates/conflicting-authorization.yaml#0"
	openSearch.Security.AuthorizationPolicies = append(
		openSearch.Security.AuthorizationPolicies, duplicate,
	)
	values["chart/opensearch"] = openSearch

	var renderError *artifactRenderError
	err := validateOpenSearchMeshContract(values)
	if !errors.As(err, &renderError) ||
		renderError.id != "chart/opensearch" ||
		!strings.Contains(err.Error(),
			"opensearch/templates/conflicting-authorization.yaml#0") {
		t.Fatalf("cross-artifact duplicate attribution = %v", err)
	}
}

func TestMeshContractReportsActualSelectedArtifact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		artifact string
		path     string
		mutate   func(map[string]chartInspection)
	}{
		{
			name: "fluent bit workload", artifact: "package/fluentbit",
			path: "fluentbit/templates/daemonset.yaml#0",
			mutate: func(values map[string]chartInspection) {
				inspection := values["package/fluentbit"]
				inspection.Security.Workloads[0].ServiceAccount = "default"
				values["package/fluentbit"] = inspection
			},
		},
		{
			name: "wrapper policy", artifact: "wrapper/wrapper",
			path: "wrapper/templates/authorizationpolicy.yaml#0",
			mutate: func(values map[string]chartInspection) {
				inspection := values["wrapper/wrapper"]
				inspection.Security.AuthorizationPolicies[0].RulesValid = false
				values["wrapper/wrapper"] = inspection
			},
		},
		{
			name: "istiod probe rewrite", artifact: "package/istiod",
			path: "istiod/templates/configmap-values.yaml#0",
			mutate: func(values map[string]chartInspection) {
				inspection := values["package/istiod"]
				inspection.Security.ProbeRewrites[0].Enabled = false
				values["package/istiod"] = inspection
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := validMeshInspections()
			test.mutate(values)
			var renderError *artifactRenderError
			err := validateOpenSearchMeshContract(values)
			if !errors.As(err, &renderError) ||
				renderError.id != test.artifact ||
				!strings.Contains(err.Error(), test.path) {
				t.Fatalf("source attribution = %v", err)
			}
		})
	}
}

func TestSecurityObservationRejectsOversizedProofInputs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"metadata", func(object map[string]any) {
			labels := mapAt(
				mapAt(mapAt(object, "spec"), "template"), "metadata", "labels",
			)
			for index := 0; index <= maxSecurityMetadataItems; index++ {
				labels["extra-"+strconv.Itoa(index)] = "value"
			}
		}},
		{"selector", func(object map[string]any) {
			labels := mapAt(mapAt(object, "spec"), "selector", "matchLabels")
			for index := 0; index <= maxSecuritySelectorItems; index++ {
				labels["extra-"+strconv.Itoa(index)] = "value"
			}
		}},
		{"init containers", func(object map[string]any) {
			spec := mapAt(mapAt(mapAt(object, "spec"), "template"), "spec")
			values := make([]any, maxSecurityListItems+1)
			for index := range values {
				values[index] = map[string]any{"name": "init"}
			}
			spec["initContainers"] = values
		}},
		{"command argument", func(object map[string]any) {
			spec := mapAt(mapAt(mapAt(object, "spec"), "template"), "spec")
			init := spec["initContainers"].([]any)[0].(map[string]any)
			init["args"] = []any{strings.Repeat("x", maxSecurityStringBytes+1)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := selectedOpenSearchWorkloadObject()
			test.mutate(object)
			var observed platformSecurityObservation
			observePlatformSecurity(
				object, "opensearch/templates/statefulset.yaml#0", &observed,
			)
			values := validMeshInspections()
			openSearch := values["chart/opensearch"]
			openSearch.Security.Workloads = observed.Workloads
			openSearch.Security.Overflow = observed.Overflow
			values["chart/opensearch"] = openSearch
			err := validateOpenSearchMeshContract(values)
			if err == nil ||
				!strings.Contains(err.Error(), "opensearch/templates/statefulset.yaml#0") {
				t.Fatalf("oversized %s observation error = %v", test.name, err)
			}
		})
	}
}

func TestMergePlatformSecurityObservationBoundsAndAttributesEveryCategory(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		fill  func(*platformSecurityObservation, int, string)
		count func(platformSecurityObservation) int
		path  func(platformSecurityObservation) string
	}{
		{
			name: "namespaces",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.Namespaces = make([]namespaceSecurityObservation, count)
				for index := range value.Namespaces {
					value.Namespaces[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.Namespaces)
			},
			path: func(value platformSecurityObservation) string {
				return value.Namespaces[0].Resource.Path
			},
		},
		{
			name: "workloads",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.Workloads = make([]workloadSecurityObservation, count)
				for index := range value.Workloads {
					value.Workloads[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.Workloads)
			},
			path: func(value platformSecurityObservation) string {
				return value.Workloads[0].Resource.Path
			},
		},
		{
			name: "services",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.Services = make([]serviceSecurityObservation, count)
				for index := range value.Services {
					value.Services[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.Services)
			},
			path: func(value platformSecurityObservation) string {
				return value.Services[0].Resource.Path
			},
		},
		{
			name: "peer authentications",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.PeerAuthentications = make([]peerAuthenticationObservation, count)
				for index := range value.PeerAuthentications {
					value.PeerAuthentications[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.PeerAuthentications)
			},
			path: func(value platformSecurityObservation) string {
				return value.PeerAuthentications[0].Resource.Path
			},
		},
		{
			name: "authorization policies",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.AuthorizationPolicies =
					make([]authorizationPolicyObservation, count)
				for index := range value.AuthorizationPolicies {
					value.AuthorizationPolicies[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.AuthorizationPolicies)
			},
			path: func(value platformSecurityObservation) string {
				return value.AuthorizationPolicies[0].Resource.Path
			},
		},
		{
			name: "network policies",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.NetworkPolicies = make([]networkPolicyObservation, count)
				for index := range value.NetworkPolicies {
					value.NetworkPolicies[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.NetworkPolicies)
			},
			path: func(value platformSecurityObservation) string {
				return value.NetworkPolicies[0].Resource.Path
			},
		},
		{
			name: "probe rewrites",
			fill: func(value *platformSecurityObservation, count int, path string) {
				value.ProbeRewrites = make([]probeRewriteObservation, count)
				for index := range value.ProbeRewrites {
					value.ProbeRewrites[index].Resource.Path = path
				}
			},
			count: func(value platformSecurityObservation) int {
				return len(value.ProbeRewrites)
			},
			path: func(value platformSecurityObservation) string {
				return value.ProbeRewrites[0].Resource.Path
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var first platformSecurityObservation
			var second platformSecurityObservation
			test.fill(&first, maxSecurityResources, "templates/first.yaml#0")
			test.fill(&second, 1, "templates/overflow.yaml#0")
			var combined platformSecurityObservation
			mergePlatformSecurityObservation(&combined, first, "first-instance/")
			mergePlatformSecurityObservation(&combined, second, "second-instance/")

			if test.count(combined) != maxSecurityResources {
				t.Fatalf("retained observations = %d", test.count(combined))
			}
			if got := test.path(combined); got !=
				"first-instance/templates/first.yaml#0" {
				t.Fatalf("retained path = %q", got)
			}
			if combined.Overflow == nil ||
				combined.Overflow.Path !=
					"second-instance/templates/overflow.yaml#0" {
				t.Fatalf("overflow = %#v", combined.Overflow)
			}

			values := validMeshInspections()
			root := values["bigbang"]
			root.Security = combined
			values["bigbang"] = root
			var renderError *artifactRenderError
			err := validateOpenSearchMeshContract(values)
			if !errors.As(err, &renderError) ||
				renderError.id != "bigbang" ||
				!strings.Contains(err.Error(),
					"second-instance/templates/overflow.yaml#0") {
				t.Fatalf("candidate overflow attribution = %v", err)
			}
		})
	}
}

func TestMergePlatformSecurityObservationPrefixesSourceOverflow(t *testing.T) {
	t.Parallel()
	source := platformSecurityObservation{
		Overflow: &renderedResource{Path: "templates/overflow.yaml#0"},
	}
	var combined platformSecurityObservation
	mergePlatformSecurityObservation(&combined, source, "release-instance/")
	if combined.Overflow == nil ||
		combined.Overflow.Path != "release-instance/templates/overflow.yaml#0" {
		t.Fatalf("overflow = %#v", combined.Overflow)
	}
}

func TestAuthorizationPolicyObservationRejectsMalformedOrOversizedTopLevel(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"scalar rule", func(object map[string]any) {
			spec := mapAt(object, "spec")
			spec["rules"] = append(spec["rules"].([]any), "broad")
		}},
		{"oversized rule list", func(object map[string]any) {
			spec := mapAt(object, "spec")
			rules := make([]any, maxSecurityListItems+1)
			for index := range rules {
				rules[index] = map[string]any{}
			}
			spec["rules"] = rules
		}},
		{"oversized action", func(object map[string]any) {
			mapAt(object, "spec")["action"] =
				strings.Repeat("A", maxSecurityStringBytes+1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := selectedAuthorizationPolicyObject()
			test.mutate(object)
			var observed platformSecurityObservation
			observePlatformSecurity(
				object, "wrapper/templates/authorizationpolicy.yaml#0", &observed,
			)
			values := validMeshInspections()
			wrapper := values["wrapper/wrapper"]
			wrapper.Security.AuthorizationPolicies =
				observed.AuthorizationPolicies
			values["wrapper/wrapper"] = wrapper
			err := validateOpenSearchMeshContract(values)
			if err == nil ||
				!strings.Contains(
					err.Error(), "wrapper/templates/authorizationpolicy.yaml#0",
				) {
				t.Fatalf("invalid %s observation error = %v", test.name, err)
			}
		})
	}
}

func selectedAuthorizationPolicyObject() map[string]any {
	return map[string]any{
		"apiVersion": "security.istio.io/v1",
		"kind":       "AuthorizationPolicy",
		"metadata": map[string]any{
			"name": "allow-fluentbit-opensearch", "namespace": "opensearch",
		},
		"spec": map[string]any{
			"action": "ALLOW",
			"selector": map[string]any{"matchLabels": map[string]any{
				"app.kubernetes.io/name":     "opensearch",
				"app.kubernetes.io/instance": "opensearch",
			}},
			"rules": []any{map[string]any{
				"from": []any{map[string]any{"source": map[string]any{
					"principals": []any{
						"cluster.local/ns/fluentbit/sa/fluentbit-fluent-bit",
					},
				}}},
				"to": []any{map[string]any{"operation": map[string]any{
					"ports": []any{"9200"},
				}}},
			}},
		},
	}
}

func selectedOpenSearchWorkloadObject() map[string]any {
	labels := map[string]any{
		"app.kubernetes.io/name":     "opensearch",
		"app.kubernetes.io/instance": "opensearch",
	}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata": map[string]any{
			"name": "opensearch-cluster-master", "namespace": "opensearch",
		},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": cloneAnyMap(labels)},
			"template": map[string]any{
				"metadata": map[string]any{
					"labels":      cloneAnyMap(labels),
					"annotations": map[string]any{},
				},
				"spec": map[string]any{
					"containers": []any{map[string]any{
						"startupProbe": map[string]any{
							"tcpSocket": map[string]any{"port": 9200},
						},
						"readinessProbe": map[string]any{
							"tcpSocket": map[string]any{"port": 9200},
						},
					}},
					"initContainers": []any{map[string]any{
						"name": "configfile",
						"command": []any{
							"cp -r /tmp/configfolder/*  /tmp/config/",
						},
					}},
				},
			},
		},
	}
}

func cloneAnyMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestWrapperArtifactBindingUsesGeneratedSource(t *testing.T) {
	t.Parallel()
	registry := testChartRegistry()
	values := map[string]any{"wrapper": map[string]any{"helmRepo": map[string]any{
		"repoName": "atum", "chartName": "wrapper", "tag": "0.4.15",
	}}}
	support := []testSupportSourceInput{{
		id: "wrapper", valuesPath: "wrapper", version: "0.4.15",
	}}
	bindings, _, err := artifactBindings(
		registry, nil, supportSourceConfigs(support), nil, values,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].id != "wrapper" ||
		bindings[0].chart != "wrapper" || bindings[0].version != "0.4.15" ||
		!strings.HasSuffix(bindings[0].sourceURL, "/charts") {
		t.Fatalf("wrapper binding = %#v", bindings)
	}
	values["wrapper"].(map[string]any)["helmRepo"].(map[string]any)["tag"] = "0.4.14"
	if _, _, err := artifactBindings(
		registry, nil, supportSourceConfigs(support), nil, values,
	); err == nil {
		t.Fatal("mismatched wrapper handoff was accepted")
	}
}

func TestWrapperReleaseCollectorPreservesInstances(t *testing.T) {
	t.Parallel()
	collector := newReleaseValueCollector("bigbang")
	repository := map[string]any{
		"kind":     "HelmRepository",
		"metadata": map[string]any{"name": "atum", "namespace": "bigbang"},
		"spec":     map[string]any{"url": "oci://registry.test/charts"},
	}
	if err := collector.observe(repository); err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"opensearch", "opensearch-dashboards"} {
		release := map[string]any{
			"kind": "HelmRelease",
			"metadata": map[string]any{
				"name": "wrapper-" + namespace, "namespace": namespace,
			},
			"spec": map[string]any{
				"targetNamespace": namespace,
				"chart": map[string]any{"spec": map[string]any{
					"chart": "wrapper", "version": "0.4.15",
					"sourceRef": map[string]any{
						"kind": "HelmRepository", "name": "atum", "namespace": "bigbang",
					},
				}},
			},
		}
		if err := collector.observe(release); err != nil {
			t.Fatal(err)
		}
	}
	instances, err := collector.valuesForArtifacts([]artifactBinding{{
		id: "wrapper", sourceKind: "HelmRepository",
		sourceName: "atum", sourceNamespace: "bigbang",
		sourceURL: "oci://registry.test/charts",
		chart:     "wrapper", version: "0.4.15", defaultReconcile: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(instances["wrapper"]) != 2 {
		t.Fatalf("wrapper instances = %d", len(instances["wrapper"]))
	}
}

func validMeshInspections() map[string]chartInspection {
	openSearchLabels := selectedOpenSearchLabels()
	fluentLabels := selectedFluentBitLabels()
	port := []networkPortObservation{{
		Port: 9200, PortValid: true, Protocol: "TCP",
		ProtocolPresent: true, ProtocolValid: true,
	}}
	exactRule := func(namespace string, labels map[string]string) networkRuleObservation {
		return networkRuleObservation{
			PeersPresent: true, PeersValid: true,
			Peers: []networkPeerObservation{{
				NamespaceSelector: exactTestSelector(map[string]string{
					"kubernetes.io/metadata.name": namespace,
				}),
				PodSelector: exactTestSelector(labels),
			}},
			PortsPresent: true, PortsValid: true, Ports: port,
		}
	}
	return map[string]chartInspection{
		"bigbang": {Security: platformSecurityObservation{
			Namespaces: []namespaceSecurityObservation{
				{Resource: testResource("v1", "Namespace", "", "opensearch", "bigbang/templates/opensearch.yaml#0"),
					InjectionEligible: true, MetadataValid: true},
				{Resource: testResource("v1", "Namespace", "", "fluentbit", "bigbang/templates/fluentbit.yaml#0"),
					InjectionEligible: true, MetadataValid: true},
			},
		}},
		"chart/opensearch": {Security: platformSecurityObservation{
			Workloads: []workloadSecurityObservation{{
				Resource: testResource("apps/v1", "StatefulSet", "opensearch",
					"opensearch-cluster-master", "opensearch/templates/statefulset.yaml#0"),
				Selector:         exactTestSelector(openSearchLabels),
				PodLabels:        openSearchLabels,
				Capture:          captureObservation{Values: map[string]string{}, Valid: true},
				MetadataValid:    true,
				HostNetworkValid: true, StartupPort: 9200, ReadinessPort: 9200,
				InitContainerCount: 1, ConfigInitCount: 1,
				InitValid: true, ConfigInitLocal: true,
			}},
			Services: []serviceSecurityObservation{{
				Resource: testResource("v1", "Service", "opensearch",
					"opensearch-cluster-master", "opensearch/templates/service.yaml#0"),
				Selector: exactTestSelector(openSearchLabels),
				Ports: []servicePortObservation{{
					Port: 9200, PortValid: true, TargetPort: 9200, TargetPortValid: true,
				}},
			}},
		}},
		"package/fluentbit": {Security: platformSecurityObservation{
			Workloads: []workloadSecurityObservation{{
				Resource: testResource("apps/v1", "DaemonSet", "fluentbit",
					"fluentbit-fluent-bit", "fluentbit/templates/daemonset.yaml#0"),
				Selector:      exactTestSelector(fluentLabels),
				PodLabels:     fluentLabels,
				Capture:       captureObservation{Values: map[string]string{}, Valid: true},
				MetadataValid: true, InitValid: true,
				ServiceAccount: "fluentbit-fluent-bit", HostNetworkValid: true,
			}},
			NetworkPolicies: []networkPolicyObservation{{
				Resource: testResource("networking.k8s.io/v1", "NetworkPolicy", "fluentbit",
					"allow-egress-from-fluent-bit-to-ns-opensearch-pod-opensearch-tcp-port-9200",
					"fluentbit/templates/networkpolicy.yaml#0"),
				Selector:           exactTestSelector(fluentLabels),
				PolicyTypesPresent: true, PolicyTypesValid: true,
				PolicyTypes:   []string{"Egress"},
				EgressPresent: true, EgressValid: true,
				Egress: []networkRuleObservation{exactRule("opensearch", openSearchLabels)},
			}},
		}},
		"wrapper/wrapper": {Security: platformSecurityObservation{
			PeerAuthentications: []peerAuthenticationObservation{{
				Resource: testResource("security.istio.io/v1beta1", "PeerAuthentication",
					"opensearch", "opensearch", "wrapper/templates/peerauthentication.yaml#0"),
				Mode: "STRICT", ModeValid: true, PortsValid: true,
			}},
			AuthorizationPolicies: []authorizationPolicyObservation{
				{
					Resource: testResource("security.istio.io/v1", "AuthorizationPolicy",
						"opensearch", "allow-fluentbit-opensearch",
						"wrapper/templates/authorizationpolicy.yaml#0"),
					Selector: exactTestSelector(openSearchLabels),
					Action:   "ALLOW", ActionValid: true,
					RulesPresent: true, RulesValid: true,
					Rules: []authorizationRuleObservation{{
						FromPresent: true, FromValid: true,
						From: []authorizationSourceObservation{{
							PrincipalsPresent: true, PrincipalsValid: true,
							Principals: []string{
								"cluster.local/ns/fluentbit/sa/fluentbit-fluent-bit",
							},
						}},
						ToPresent: true, ToValid: true,
						To: []authorizationOperationObservation{{
							PortsPresent: true, PortsValid: true, Ports: []int{9200},
						}},
					}},
				},
				{
					Resource: testResource("security.istio.io/v1", "AuthorizationPolicy",
						"opensearch", "allow-intra-namespace",
						"wrapper/templates/allow-intra-namespace.yaml#0"),
					Action: "ALLOW", ActionValid: true,
					RulesPresent: true, RulesValid: true,
				},
			},
			NetworkPolicies: []networkPolicyObservation{
				{
					Resource: testResource("networking.k8s.io/v1", "NetworkPolicy",
						"opensearch", "allow-fluentbit-opensearch",
						"wrapper/templates/networkpolicy.yaml#0"),
					Selector:           exactTestSelector(openSearchLabels),
					PolicyTypesPresent: true, PolicyTypesValid: true,
					PolicyTypes:    []string{"Ingress"},
					IngressPresent: true, IngressValid: true,
					Ingress: []networkRuleObservation{exactRule("fluentbit", fluentLabels)},
				},
				{
					Resource: testResource("networking.k8s.io/v1", "NetworkPolicy",
						"opensearch", "allow-intra-namespace",
						"wrapper/templates/networkpolicy-intranamespace.yaml#0"),
					PolicyTypesPresent: true, PolicyTypesValid: true,
					PolicyTypes:    []string{"Ingress", "Egress"},
					IngressPresent: true, IngressValid: true,
					EgressPresent: true, EgressValid: true,
				},
			},
		}},
		"chart/opensearch-dashboards": {Security: platformSecurityObservation{
			Workloads: []workloadSecurityObservation{{
				Resource: testResource("apps/v1", "Deployment", "opensearch",
					"opensearch-dashboards", "dashboards/templates/deployment.yaml#0"),
				Selector:      exactTestSelector(selectedDashboardsLabels()),
				PodLabels:     selectedDashboardsLabels(),
				Capture:       captureObservation{Values: map[string]string{}, Valid: true},
				MetadataValid: true, InitValid: true, HostNetworkValid: true,
			}},
		}},
		"package/istiod": {Security: platformSecurityObservation{
			ProbeRewrites: []probeRewriteObservation{{
				Resource: testResource("v1", "ConfigMap", "istio-system",
					"values", "istiod/templates/configmap-values.yaml#0"),
				Enabled: true,
			}},
		}},
	}
}

func exactTestSelector(labels map[string]string) selectorObservation {
	return selectorObservation{Present: true, Valid: true, Labels: labels}
}

func testResource(
	apiVersion string, kind string, namespace string, name string, path string,
) renderedResource {
	return renderedResource{
		APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, Path: path,
	}
}

func testChartRegistry() config.Registry {
	return config.Registry{Host: "registry.test", Project: "charts"}
}

type testSupportSourceInput struct {
	id         string
	valuesPath string
	version    string
}

func supportSourceConfigs(inputs []testSupportSourceInput) []config.SupportSource {
	result := make([]config.SupportSource, len(inputs))
	for index := range inputs {
		result[index] = config.SupportSource{
			ID: inputs[index].id, ValuesPath: inputs[index].valuesPath,
			Source: config.GitSource{Version: inputs[index].version},
		}
	}
	return result
}

func TestMeshContractErrorsRemainAttributed(t *testing.T) {
	t.Parallel()
	values := validMeshInspections()
	delete(values, "chart/opensearch")
	var renderError *artifactRenderError
	if err := validateOpenSearchMeshContract(values); !errors.As(err, &renderError) ||
		renderError.id != "chart/opensearch" {
		t.Fatalf("error attribution = %#v", renderError)
	}
}
