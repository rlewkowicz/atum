package update

import (
	"path/filepath"
	"testing"

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
