package update

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/identity"
	platformv1alpha1 "atum/operator/api/v1alpha1"

	"sigs.k8s.io/yaml"
)

func TestOperatorConfigurationProjectsIdentityKindAndCanonicalClaims(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	data, err := operatorConfiguration(contract)
	if err != nil {
		t.Fatal(err)
	}
	var configuration platformv1alpha1.PlatformIdentityConfiguration
	if err := yaml.Unmarshal(data, &configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.Kind != "PlatformIdentityConfiguration" ||
		configuration.APIVersion != platformv1alpha1.GroupVersion.String() ||
		configuration.Name != platformv1alpha1.SingletonName ||
		configuration.Namespace != platformv1alpha1.SingletonNamespace {
		t.Fatalf("identity projection metadata = %#v", configuration.TypeMeta)
	}
	wantScopes := [...]string{"openid", "profile", "email", "groups"}
	if len(configuration.Spec.Keycloak.Scopes) != len(wantScopes) {
		t.Fatalf("scope count = %d", len(configuration.Spec.Keycloak.Scopes))
	}
	for index := range wantScopes {
		if configuration.Spec.Keycloak.Scopes[index] != wantScopes[index] ||
			configuration.Spec.Vault.Role.Scopes[index] != wantScopes[index] {
			t.Fatalf("canonical scope projection = %v / %v",
				configuration.Spec.Keycloak.Scopes, configuration.Spec.Vault.Role.Scopes)
		}
	}
	if configuration.Spec.Keycloak.GroupsScope.ClaimName != wantScopes[len(wantScopes)-1] {
		t.Fatalf("groups scope projection = %#v", configuration.Spec.Keycloak.GroupsScope)
	}
}

func TestIdentityValuesRetainSupportedUpstreamLogoutDefaults(t *testing.T) {
	t.Parallel()

	values := loadLocalIdentityValues(t)
	addons := values["addons"].(map[string]any)
	authservice := addons["authservice"].(map[string]any)
	for name, value := range authservice["chains"].(map[string]any) {
		if value == nil {
			continue
		}
		chain := value.(map[string]any)
		if path, overridden := chain["logout_path"]; overridden {
			t.Fatalf("authservice chain %s overrides upstream logout path with %#v", name, path)
		}
	}
	harbor := addons["harbor"].(map[string]any)
	harborValues := harbor["values"].(map[string]any)
	upstream := harborValues["upstream"].(map[string]any)
	core := upstream["core"].(map[string]any)
	var settings map[string]any
	if err := json.Unmarshal([]byte(core["configureUserSettings"].(string)), &settings); err != nil {
		t.Fatal(err)
	}
	if value, unsupported := settings["oidc_logout_endpoint_enabled"]; unsupported {
		t.Fatalf("Harbor settings include unsupported oidc_logout_endpoint_enabled=%#v", value)
	}
}

func TestIdentityValuesRetainBigBangSSOCASecretDefault(t *testing.T) {
	t.Parallel()

	values := loadLocalIdentityValues(t)
	sso := values["sso"].(map[string]any)
	if authority, overridden := sso["certificateAuthority"]; overridden {
		t.Fatalf("identity values override Big Bang's SSO CA Secret contract: %#v", authority)
	}
}

func TestIdentityValuesUseBigBangKialiSSOContract(t *testing.T) {
	t.Parallel()

	values := loadLocalIdentityValues(t)
	kiali := values["kiali"].(map[string]any)
	if len(kiali) != 1 {
		t.Fatalf("Kiali identity values bypass Big Bang's SSO contract: %#v", kiali)
	}
	sso := kiali["sso"].(map[string]any)
	if sso["enabled"] != true ||
		sso["client_id"] != "atum-kiali" ||
		sso["client_secret"] != "${ATUM_KIALI_CLIENT_SECRET}" {
		t.Fatalf("Kiali SSO values = %#v", sso)
	}
}

func TestIdentityValuesScopeSSOEgressToPassthroughVIPAndGateway(t *testing.T) {
	t.Parallel()

	values := loadLocalIdentityValues(t)
	assertIdentityGatewayEgress(
		t,
		values,
		"sso",
		"10.77.0.21/32",
		"passthrough-ingressgateway",
	)
}

func TestIdentityValuesScopeVaultEgressToPublicVIPAndGateway(t *testing.T) {
	t.Parallel()

	values := loadLocalIdentityValues(t)
	assertIdentityGatewayEgress(
		t,
		values,
		"vaultIngress",
		"10.77.0.20/32",
		"public-ingressgateway",
	)
	monitoring := values["monitoring"].(map[string]any)
	monitoringValues := monitoring["values"].(map[string]any)
	networkPolicies := monitoringValues["networkPolicies"].(map[string]any)
	egress := networkPolicies["egress"].(map[string]any)
	from := egress["from"].(map[string]any)
	prometheus := from["prometheus"].(map[string]any)
	to := prometheus["to"].(map[string]any)
	definition := to["definition"].(map[string]any)
	if definition["vaultIngress"] != true {
		t.Fatalf("Prometheus Vault egress = %#v", definition)
	}
}

func assertIdentityGatewayEgress(
	t *testing.T,
	values map[string]any,
	definitionName string,
	wantCIDR string,
	wantGateway string,
) {
	t.Helper()

	networkPolicies := values["networkPolicies"].(map[string]any)
	egress := networkPolicies["egress"].(map[string]any)
	definitions := egress["definitions"].(map[string]any)
	definition := definitions[definitionName].(map[string]any)
	to := definition["to"].([]any)
	if len(to) != 2 {
		t.Fatalf("%s egress destinations = %#v", definitionName, to)
	}
	vip := to[0].(map[string]any)
	ipBlock := vip["ipBlock"].(map[string]any)
	if ipBlock["cidr"] != wantCIDR || len(vip) != 1 {
		t.Fatalf("%s VIP destination = %#v", definitionName, vip)
	}
	destination := to[1].(map[string]any)
	namespaceSelector := destination["namespaceSelector"].(map[string]any)
	namespaceLabels := namespaceSelector["matchLabels"].(map[string]any)
	podSelector := destination["podSelector"].(map[string]any)
	podLabels := podSelector["matchLabels"].(map[string]any)
	if namespaceLabels["kubernetes.io/metadata.name"] != "istio-gateway" ||
		podLabels["app.kubernetes.io/name"] != wantGateway ||
		podLabels["istio"] != "ingressgateway" ||
		len(destination) != 2 {
		t.Fatalf("%s egress destination = %#v", definitionName, destination)
	}
	ports := definition["ports"].([]any)
	if len(ports) != 2 {
		t.Fatalf("%s egress ports = %#v", definitionName, ports)
	}
	for index, wanted := range []int{443, 8443} {
		port := ports[index].(map[string]any)
		if port["port"] != wanted || port["protocol"] != "TCP" {
			t.Fatalf("%s egress port %d = %#v", definitionName, index, port)
		}
	}
}

func TestIdentityValuesMountPolicyReporterOIDCCA(t *testing.T) {
	t.Parallel()

	values := loadLocalIdentityValues(t)
	reporter := values["kyvernoReporter"].(map[string]any)
	reporterValues := reporter["values"].(map[string]any)
	upstream := reporterValues["upstream"].(map[string]any)
	ui := upstream["ui"].(map[string]any)
	openIDConnect := ui["openIDConnect"].(map[string]any)
	if openIDConnect["certificate"] != policyReporterCACertificatePath ||
		openIDConnect["skipTLS"] == true {
		t.Fatalf("Policy Reporter OIDC trust = %#v", openIDConnect)
	}

	extraVolumes := ui["extraVolumes"].(map[string]any)
	volumeMounts := extraVolumes["volumeMounts"].([]any)
	volumes := extraVolumes["volumes"].([]any)
	if len(volumeMounts) != 1 || len(volumes) != 1 {
		t.Fatalf("Policy Reporter CA volumes = %#v / %#v", volumeMounts, volumes)
	}
	mount := volumeMounts[0].(map[string]any)
	if mount["name"] != "atum-sso-ca" ||
		mount["mountPath"] != "/var/run/atum-sso" ||
		mount["readOnly"] != true {
		t.Fatalf("Policy Reporter CA mount = %#v", mount)
	}
	volume := volumes[0].(map[string]any)
	secret := volume["secret"].(map[string]any)
	items := secret["items"].([]any)
	if volume["name"] != "atum-sso-ca" ||
		secret["secretName"] != "atum-sso-ca" ||
		len(items) != 1 {
		t.Fatalf("Policy Reporter CA volume = %#v", volume)
	}
	item := items[0].(map[string]any)
	if item["key"] != "ca.crt" || item["path"] != "ca.crt" {
		t.Fatalf("Policy Reporter CA item = %#v", item)
	}

	manifests := upstream["extraManifests"].([]any)
	if len(manifests) != 1 ||
		manifests[0] != policyReporterCACertificateManifest {
		t.Fatalf("Policy Reporter CA manifests = %#v", manifests)
	}
}

func TestOperatorNetworkPolicySelectsIngressVIPsAndGateways(t *testing.T) {
	t.Parallel()

	text := readPlatformText(t, "platform/apps/atum-operator/network-policy.yaml")
	for _, cidr := range []string{"10.77.0.20/32", "10.77.0.21/32"} {
		if strings.Count(text, "cidr: "+cidr) != 1 {
			t.Fatalf("operator network policy does not contain exactly one %s", cidr)
		}
	}
	for _, name := range []string{"public-ingressgateway", "passthrough-ingressgateway"} {
		if strings.Count(text, "- "+name) != 1 {
			t.Fatalf("operator network policy does not select exactly one %s", name)
		}
	}
	if strings.Count(text, "port: 443") != 1 ||
		strings.Count(text, "port: 8443") != 1 ||
		!strings.Contains(text, "kubernetes.io/metadata.name: istio-gateway") {
		t.Fatalf("operator network policy does not select gateway VIPs and HTTPS endpoints:\n%s", text)
	}
}

func TestOperatorImageProjectionComposesWithRenderedCandidate(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const relative = "platform/apps/atum-operator/deployment.yaml"
	tree := newCandidateTree(root)
	if err := tree.Set(relative, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: atum-operator
  labels:
    test.atum.dev/rendered-candidate: retained
spec:
  template:
    spec:
      containers:
        - name: manager
          image: 10.77.0.9:32443/atum/atum-operator:0.1.1
`)); err != nil {
		t.Fatal(err)
	}
	images := []config.Image{{
		ID:      "atum-operator",
		Version: "0.1.1",
		Target:  "10.77.0.9:32443/atum/atum-operator:build-test",
	}}
	if err := projectOperatorImage(tree, images); err != nil {
		t.Fatal(err)
	}
	first, err := tree.CandidateData(relative)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "test.atum.dev/rendered-candidate: retained") {
		t.Fatalf("operator image projection discarded rendered candidate:\n%s", first)
	}
	if !strings.Contains(string(first), "atum/atum-operator:build-test") {
		t.Fatalf("operator image projection did not use resolved target:\n%s", first)
	}
	if err := projectOperatorImage(tree, images); err != nil {
		t.Fatal(err)
	}
	second, err := tree.CandidateData(relative)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("operator image projection is not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func loadLocalIdentityValues(t *testing.T) map[string]any {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := identityValues(contract, &config.LocalAccess{
		PublicIngressVIP:      "10.77.0.20",
		PassthroughIngressVIP: "10.77.0.21",
	})
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestFluxRenderValuesSubstituteOnlyUpdaterInspectionCopy(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	desired := config.Document{
		Infrastructure: config.Infrastructure{
			Active: "local",
			Targets: map[string]config.InfrastructureTarget{
				"local": {
					PlatformProfile: "local",
					LocalAccess: &config.LocalAccess{
						Domain: "atum.test",
					},
				},
			},
		},
	}
	values := map[string]any{
		"domain": "${ATUM_PLATFORM_DOMAIN}",
		"identity": []any{
			"https://vault.${ATUM_PLATFORM_DOMAIN}",
			"${ATUM_ALERTMANAGER_CLIENT_SECRET}",
			"${ATUM_IDENTITY_BOOTSTRAP_PASSWORD}",
		},
	}
	rendered, err := renderFluxSubstitutedValues(desired, contract, values)
	if err != nil {
		t.Fatal(err)
	}
	if values["domain"] != "${ATUM_PLATFORM_DOMAIN}" {
		t.Fatalf("persisted values were mutated: %#v", values)
	}
	if rendered["domain"] != "atum.test" {
		t.Fatalf("rendered domain = %#v", rendered["domain"])
	}
	if _, persisted := values["sso"]; persisted {
		t.Fatalf("persisted values gained updater-only SSO CA: %#v", values)
	}
	certificateAuthority := mapAt(
		rendered,
		"sso",
		"certificateAuthority",
	)
	certificate, _ := certificateAuthority["cert"].(string)
	if !strings.Contains(certificate, "BEGIN CERTIFICATE") {
		t.Fatalf("rendered SSO CA = %#v", certificateAuthority)
	}
	identityValues := rendered["identity"].([]any)
	if identityValues[0] != "https://vault.atum.test" ||
		identityValues[1] != renderOnlyIdentityCredential ||
		identityValues[2] != renderOnlyIdentityCredential {
		t.Fatalf("rendered identity values = %#v", identityValues)
	}

	_, err = renderFluxSubstitutedValues(
		desired,
		contract,
		map[string]any{"unknown": "${ATUM_UNDECLARED_VALUE}"},
	)
	if err == nil || !strings.Contains(err.Error(), "ATUM_UNDECLARED_VALUE") {
		t.Fatalf("unknown substitution error = %v", err)
	}
}
