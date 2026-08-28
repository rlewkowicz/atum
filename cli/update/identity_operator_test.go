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
}

func TestIdentityValuesRetainSupportedUpstreamLogoutDefaults(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := identityValues(contract)
	if err != nil {
		t.Fatal(err)
	}
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

func TestIdentityValuesUseBigBangKialiSSOContract(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values, err := identityValues(contract)
	if err != nil {
		t.Fatal(err)
	}
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
