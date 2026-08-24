package update

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/identity"

	"gopkg.in/yaml.v3"
)

func TestIdentityValuesProjectCanonicalContractDeterministically(t *testing.T) {
	t.Parallel()

	contract, err := identity.Load("../..", "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	first, err := identityValues(contract)
	if err != nil {
		t.Fatal(err)
	}
	second, err := identityValues(contract)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identity projection is not deterministic")
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "localhost") {
		t.Fatalf("identity projection retains a placeholder localhost chain: %s", text)
	}
	for _, client := range contract.Clients() {
		if client.Integration == identity.FluxReconciliation {
			continue
		}
		if !strings.Contains(text, client.ID) {
			t.Errorf("identity projection omits client %s", client.ID)
		}
	}
	if strings.Contains(text, "ATUM_HEADLAMP_CLIENT_SECRET") {
		t.Fatal("public PKCE Headlamp projection contains a client secret")
	}
	openSearchHosts := mapSlice(mapAt(first, "packages", "opensearch", "istio")["hosts"])
	if len(openSearchHosts) != 1 ||
		!reflectsOnly(stringSlice(openSearchHosts[0]["names"]), "opensearch") ||
		!reflectsOnly(stringSlice(openSearchHosts[0]["domains"]), contract.Domain()) {
		t.Fatalf("OpenSearch wrapper does not project its canonical domain: %#v", openSearchHosts)
	}
	selectors := mapSlice(openSearchHosts[0]["selectors"])
	if len(selectors) != 1 ||
		!exactLabelSelector(selectors[0], "protect", "keycloak") {
		t.Fatalf("OpenSearch wrapper has an invalid workload selector: %#v", selectors)
	}
}

func TestIdentityProjectionFollowsCanonicalApplicationIdentity(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(
		data, []byte("id: atum-headlamp"), []byte("id: renamed-headlamp"), 1)
	contract, err := identity.Parse(changed, "changed-contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := identityValues(contract)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "renamed-headlamp") ||
		strings.Contains(string(encoded), "atum-headlamp") {
		t.Fatalf("application projection did not follow the canonical client identity: %s", encoded)
	}
	duplicate := bytes.Replace(
		data, []byte("application: kiali"), []byte("application: headlamp"), 1)
	if _, err := identity.Parse(duplicate, "duplicate-application.yaml"); err == nil ||
		!strings.Contains(err.Error(), `application projection "headlamp" is duplicated`) {
		t.Fatalf("duplicate application projection error = %v", err)
	}
}

func TestConfigureIdentityValuesFromUsesExactPrecedence(t *testing.T) {
	t.Parallel()

	release := map[string]any{"spec": map[string]any{}}
	if err := configureIdentityValuesFrom(release); err != nil {
		t.Fatal(err)
	}
	values, _ := nestedValue(release, "spec.valuesFrom")
	valuesFrom, _ := values.([]any)
	if len(valuesFrom) != 5 ||
		!matchesValuesSource(valuesFrom[0], "ConfigMap", "bigbang-operational-values", "values.yaml", "", false) ||
		!matchesValuesSource(valuesFrom[1], "ConfigMap", "bigbang-generated-values", "values.yaml", "", false) ||
		!matchesValuesSource(valuesFrom[2], "ConfigMap", "bigbang-target-values", "values.yaml", "", false) ||
		!matchesValuesSource(valuesFrom[3], "Secret", "atum-platform-identity-values", "values.yaml", "", true) ||
		!matchesValuesSource(valuesFrom[4], "Secret", "atum-sso-ca", "ca.crt", "sso.certificateAuthority.cert", true) {
		t.Fatalf("identity valuesFrom = %#v", valuesFrom)
	}
	valuesFrom[4].(map[string]any)["targetPath"] = "sso.ca"
	if matchesValuesSource(valuesFrom[4], "Secret", "atum-sso-ca", "ca.crt",
		"sso.certificateAuthority.cert", true) {
		t.Fatal("renamed SSO CA target path was accepted")
	}
}

func TestIdentityReconciliationScriptsOwnExactMapperAndCallbacks(t *testing.T) {
	t.Parallel()

	project, err := config.LoadWithOptions("../..", config.LoadOptions{
		AllowStale:                    true,
		AllowMissingGeneratedIdentity: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(project.Root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	context, err := newIdentityRenderContext(project.Desired, contract, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	keycloak := keycloakReconciliationScript(context)
	if count := strings.Count(keycloak, "protocolMapper=oidc-group-membership-mapper"); count != 1 {
		t.Fatalf("Keycloak group mapper writers = %d, want one", count)
	}
	if count := strings.Count(keycloak, "protocolMapper=oidc-audience-mapper"); count != 2 {
		t.Fatalf("Keycloak audience mapper writers = %d, want two", count)
	}
	for _, required := range []string{
		"/opt/keycloak/bin/kcadm.sh",
		"config truststore",
		"set-password",
		"default-client-scopes",
		"delete users/\"$bootstrap_id\"",
	} {
		if !strings.Contains(keycloak, required) {
			t.Errorf("Keycloak reconciliation omits %q", required)
		}
	}
	for _, client := range contract.Clients() {
		for _, callback := range client.Callbacks {
			if !strings.Contains(keycloak, callback) {
				t.Errorf("Keycloak reconciliation omits callback %s", callback)
			}
		}
	}
	openBao := openBaoReconciliationScript(context)
	for _, required := range []string{
		"oidc_discovery_ca=@/var/run/atum-ca/ca.crt",
		"identity/group-alias",
		"policies=atum-admin",
		"bao read -field=oidc_discovery_url",
	} {
		if !strings.Contains(openBao, required) {
			t.Errorf("OpenBao reconciliation omits %q", required)
		}
	}
	if strings.Contains(keycloak, "set -x") || strings.Contains(openBao, "set -x") {
		t.Fatal("identity reconciliation enables shell tracing")
	}
}

func TestIdentityManifestRenderingConvergesWithoutPlaintextSecrets(t *testing.T) {
	t.Parallel()

	project, err := config.LoadWithOptions("../..", config.LoadOptions{
		AllowStale:                    true,
		AllowMissingGeneratedIdentity: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(project.Root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := identityValues(contract)
	if err != nil {
		t.Fatal(err)
	}
	render := func() map[string][]byte {
		t.Helper()
		tree := newCandidateTree(project.Root)
		if err := renderIdentityManifests(tree, project.Desired, contract, values); err != nil {
			t.Fatal(err)
		}
		return tree.Files()
	}
	first := render()
	second := render()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identity manifest rendering does not converge byte-for-byte")
	}
	if err := validateGeneratedIdentityManifests(
		first, project.Desired, contract, values,
	); err != nil {
		t.Fatalf("canonical generated identity manifests were rejected: %v", err)
	}
	for _, relative := range [...]string{
		"platform/clusters/atum/prep.yaml",
		"platform/clusters/atum/bigbang.yaml",
	} {
		document, err := singleIdentityDocument(first, relative)
		if err != nil {
			t.Fatal(err)
		}
		force, found := mapAt(document, "spec")["force"].(bool)
		if !found || force {
			t.Fatalf("rendered Flux consumer %s force = %v, %t; want explicit false",
				relative, force, found)
		}
	}
	for _, relative := range []string{
		"platform/profiles/local/identity/keycloak-reconcile.yaml",
		"platform/profiles/local/identity/openbao-reconcile.yaml",
		"platform/profiles/local/prep/identity-values.yaml",
		"platform/clusters/atum/platform-profile-identity.yaml",
	} {
		data := first[relative]
		if len(data) == 0 {
			t.Errorf("identity rendering omits %s", relative)
			continue
		}
		if strings.Contains(string(data), "local_secret") {
			t.Errorf("identity rendering retains a placeholder secret in %s", relative)
		}
	}
	if strings.Contains(string(first["platform/profiles/local/identity/credentials.yaml"]),
		"ATUM_IDENTITY_ADMIN_PASSWORD: atum") {
		t.Fatal("rendered credentials contain a plaintext projection instead of Flux substitution")
	}
	for _, mutation := range []struct {
		name, path, old, replacement string
	}{
		{
			"CA mount", "platform/profiles/local/identity/keycloak-reconcile.yaml",
			"mountPath: /var/run/atum-ca", "mountPath: /var/run/other-ca",
		},
		{
			"Job deadline", "platform/profiles/local/identity/openbao-reconcile.yaml",
			"activeDeadlineSeconds: 900", "activeDeadlineSeconds: 0",
		},
		{
			"Job digest", "platform/profiles/local/identity/keycloak-reconcile.yaml",
			"atum.dev/identity-digest: ${ATUM_IDENTITY_DIGEST}",
			"atum.dev/identity-revision: ${ATUM_IDENTITY_DIGEST}",
		},
		{
			"topology handoff", "platform/clusters/atum/platform-profile-identity.yaml",
			"- name: platform-profile-access", "- name: bigbang",
		},
		{
			"source namespace", "platform/clusters/atum/platform-profile-identity.yaml",
			"  sourceRef:\n    kind: GitRepository\n    name: flux-system",
			"  sourceRef:\n    kind: GitRepository\n    name: flux-system\n    namespace: other",
		},
		{
			"profile force missing", "platform/clusters/atum/platform-profile-prep.yaml",
			"  force: false\n", "",
		},
		{
			"profile force changed", "platform/clusters/atum/platform-profile-access.yaml",
			"  force: false", "  force: true",
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := cloneIdentityFiles(first)
			text := string(candidate[mutation.path])
			if !strings.Contains(text, mutation.old) {
				t.Fatalf("mutation source %q is absent from %s", mutation.old, mutation.path)
			}
			candidate[mutation.path] = []byte(strings.Replace(
				text, mutation.old, mutation.replacement, 1))
			if err := validateGeneratedIdentityManifests(
				candidate, project.Desired, contract, values,
			); err == nil {
				t.Fatalf("semantic mutation of %s was accepted", mutation.path)
			}
		})
	}
	for _, mutation := range []struct {
		name    string
		command func([]any) []any
	}{
		{
			name: "command arity",
			command: func(command []any) []any {
				return append(append([]any(nil), command...), "unused")
			},
		},
		{
			name: "script position",
			command: func(command []any) []any {
				return []any{command[0], command[2], command[1]}
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := cloneIdentityFiles(first)
			path := "platform/profiles/local/identity/keycloak-reconcile.yaml"
			documents, err := identityDocuments(candidate, path)
			if err != nil || len(documents) != 1 {
				t.Fatalf("decode canonical Keycloak Job: %v", err)
			}
			container := mapSlice(mapAt(
				mapAt(mapAt(documents[0], "spec"), "template"), "spec")["containers"])[0]
			container["command"] = mutation.command(container["command"].([]any))
			candidate[path], err = yaml.Marshal(documents[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := validateGeneratedIdentityManifests(
				candidate, project.Desired, contract, values,
			); err == nil {
				t.Fatalf("semantic %s mutation was accepted", mutation.name)
			}
		})
	}
	for _, mutation := range []struct {
		name   string
		mutate func(*testing.T, map[string][]byte)
	}{
		{
			name: "unowned certificate resource",
			mutate: func(t *testing.T, candidate map[string][]byte) {
				t.Helper()
				path := "platform/profiles/local/access/certificates/kustomization.yaml"
				document, err := singleIdentityDocument(candidate, path)
				if err != nil {
					t.Fatal(err)
				}
				document["resources"] = append(
					document["resources"].([]any), "unowned-policy.yaml")
				candidate[path], err = yaml.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "second CA carrier document",
			mutate: func(t *testing.T, candidate map[string][]byte) {
				t.Helper()
				path := "platform/profiles/local/access/certificates/harbor-sso-ca.yaml"
				candidate[path] = append(candidate[path], []byte(`---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: unowned
  namespace: harbor
spec:
  podSelector: {}
`)...)
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := cloneIdentityFiles(first)
			mutation.mutate(t, candidate)
			if err := validateGeneratedIdentityManifests(
				candidate, project.Desired, contract, values,
			); err == nil {
				t.Fatalf("semantic %s mutation was accepted", mutation.name)
			}
		})
	}
}

func cloneIdentityFiles(source map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(source))
	for path, data := range source {
		result[path] = append([]byte(nil), data...)
	}
	return result
}

func TestOpenSearchIdentityWrapperRejectsRenamedRouteField(t *testing.T) {
	t.Parallel()

	route := map[string]any{"spec": map[string]any{
		"hosts":    []any{"opensearch.atum.test"},
		"gateways": []any{"istio-gateway/public-ingressgateway"},
		"http": []any{map[string]any{"route": []any{map[string]any{
			"destination": map[string]any{
				"host": "opensearch-dashboards",
				"port": map[string]any{"number": 5601},
			},
		}}}},
	}}
	if !isOpenSearchDashboardRoute(route, "opensearch.atum.test") {
		t.Fatal("exact OpenSearch Dashboards route was not recognized")
	}
	duplicateDestination := cloneMap(route)
	http := duplicateDestination["spec"].(map[string]any)["http"].([]any)[0].(map[string]any)
	http["route"] = append(
		http["route"].([]any),
		cloneValue(http["route"].([]any)[0]),
	)
	if isOpenSearchDashboardRoute(duplicateDestination, "opensearch.atum.test") {
		t.Fatal("duplicate OpenSearch Dashboards destination was accepted")
	}
	route["spec"].(map[string]any)["http"].([]any)[0].(map[string]any)["route"].([]any)[0].(map[string]any)["destination"].(map[string]any)["host"] = "dashboards"
	if isOpenSearchDashboardRoute(route, "opensearch.atum.test") {
		t.Fatal("renamed OpenSearch Dashboards service was accepted")
	}
}

func TestOpenSearchIdentityWrapperRejectsDuplicateCanonicalHost(t *testing.T) {
	t.Parallel()

	route := map[string]any{"spec": map[string]any{
		"hosts":    []any{"search.atum.test"},
		"gateways": []any{"istio-gateway/public-ingressgateway"},
		"http": []any{map[string]any{"route": []any{map[string]any{
			"destination": map[string]any{
				"host": "opensearch-dashboards",
				"port": map[string]any{"number": 5601},
			},
		}}}},
	}}
	resources := []renderedResource{
		{key: resourceKey{namespace: openSearchNamespace, kind: "VirtualService"}, object: route},
		{key: resourceKey{namespace: openSearchNamespace, kind: "VirtualService"}, object: cloneMap(route)},
	}
	err := validateOpenSearchRouteCardinality(resources, "search.atum.test")
	if err == nil || !strings.Contains(err.Error(), "rendered 2 VirtualServices") {
		t.Fatalf("duplicate canonical OpenSearch host error = %v", err)
	}
}
