package v1alpha1

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func TestGeneratedSchemaOwnsAdmissionContract(t *testing.T) {
	t.Parallel()

	root := filepath.Clean(filepath.Join("..", "..", ".."))
	generatedPath := filepath.Join(root, "config", "crd", "bases",
		"platform.atum.dev_platformidentityconfigurations.yaml")
	generated, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := os.ReadFile(filepath.Join(root, "platform", "apps",
		"atum-operator", "crd.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, projected) {
		t.Fatal("Flux CRD projection differs from marker-generated schema")
	}

	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(generated, &crd); err != nil {
		t.Fatal(err)
	}
	if crd.Name != "platformidentityconfigurations.platform.atum.dev" ||
		crd.Spec.Names.Kind != "PlatformIdentityConfiguration" ||
		len(crd.Spec.Names.ShortNames) != 1 ||
		crd.Spec.Names.ShortNames[0] != "atumidentity" {
		t.Fatalf("generated identity = %#v", crd.Spec.Names)
	}
	rootSchema := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	if len(rootSchema.Required) != 1 || rootSchema.Required[0] != "spec" {
		t.Fatalf("root required fields = %v", rootSchema.Required)
	}
	if len(rootSchema.XValidations) != 1 ||
		rootSchema.XValidations[0].Rule != "self.metadata.name == 'atum'" {
		t.Fatalf("root singleton validation = %#v", rootSchema.XValidations)
	}
	roleNameSchema := rootSchema.Properties["spec"].
		Properties["vault"].
		Properties["role"].
		Properties["name"]
	if len(roleNameSchema.Enum) != 1 ||
		string(roleNameSchema.Enum[0].Raw) != `"atum-admin"` {
		t.Fatalf("Vault role name admission = %#v", roleNameSchema.Enum)
	}
	clientIDSchema := rootSchema.Properties["spec"].
		Properties["keycloak"].
		Properties["clients"].
		Items.Schema.
		Properties["id"]
	vaultClientIDSchema := rootSchema.Properties["spec"].
		Properties["vault"].
		Properties["role"].
		Properties["clientID"]
	if clientIDSchema.MinLength == nil || *clientIDSchema.MinLength != 1 ||
		clientIDSchema.MaxLength == nil || *clientIDSchema.MaxLength != 63 ||
		vaultClientIDSchema.MinLength == nil || *vaultClientIDSchema.MinLength != 1 ||
		vaultClientIDSchema.MaxLength == nil || *vaultClientIDSchema.MaxLength != 63 {
		t.Fatalf(
			"CEL client ID bounds = keycloak(%v,%v), vault(%v,%v)",
			clientIDSchema.MinLength,
			clientIDSchema.MaxLength,
			vaultClientIDSchema.MinLength,
			vaultClientIDSchema.MaxLength,
		)
	}
	scopesSchema := rootSchema.Properties["spec"].
		Properties["keycloak"].
		Properties["scopes"]
	if len(scopesSchema.XValidations) != 1 ||
		scopesSchema.XValidations[0].Rule !=
			"self == ['openid', 'profile', 'email', 'groups']" ||
		scopesSchema.XValidations[0].Message !=
			"scopes must be openid, profile, email, groups in canonical order" {
		t.Fatalf("Keycloak scope admission = %#v", scopesSchema.XValidations)
	}
	encoded := string(generated)
	for _, required := range []string{
		"self.metadata.name == 'atum'",
		"self == oldSelf",
		"x-kubernetes-list-map-keys:",
		"x-kubernetes-list-type: set",
		"vault.role.clientID must name one declared confidential client",
		"Vault role scopes must equal the canonical Keycloak scopes",
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("generated schema does not contain %q", required)
		}
	}
	for _, forbidden := range []string{
		strings.Join([]string{"Platform", "Configuration"}, ""),
		strings.Join([]string{"platform", "configurations"}, ""),
		"scripts:",
		"commands:",
		"mappers:",
		"attributes:",
		"providerURL",
		"uniqueItems: true",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("generated schema contains forbidden extension %q", forbidden)
		}
	}
}

func TestGeneratedRoleHasFixedSecretCustody(t *testing.T) {
	t.Parallel()

	root := filepath.Clean(filepath.Join("..", "..", ".."))
	generated, err := os.ReadFile(filepath.Join(root, "config", "rbac", "role.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	projected, err := os.ReadFile(filepath.Join(root, "platform", "apps",
		"atum-operator", "controller-role.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, projected) {
		t.Fatal("Flux Role projection differs from marker-generated RBAC")
	}
	var role rbacv1.Role
	if err := yaml.Unmarshal(generated, &role); err != nil {
		t.Fatal(err)
	}
	if role.Namespace != SingletonNamespace || role.Name != "atum-operator" {
		t.Fatalf("generated Role identity = %s/%s", role.Namespace, role.Name)
	}
	foundSecrets := false
	foundSingletonPatch := false
	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource == "platformidentityconfigurations" {
				for _, verb := range rule.Verbs {
					if verb != "patch" {
						continue
					}
					if len(rule.ResourceNames) != 1 ||
						rule.ResourceNames[0] != SingletonName {
						t.Fatalf(
							"PlatformIdentityConfiguration patch custody = %v",
							rule.ResourceNames,
						)
					}
					foundSingletonPatch = true
				}
			}
			if resource != "secrets" {
				continue
			}
			foundSecrets = true
			if len(rule.ResourceNames) != 2 ||
				rule.ResourceNames[0] != "atum-provider-ca" ||
				rule.ResourceNames[1] != "atum-provider-credentials" {
				t.Fatalf("Secret custody = %v", rule.ResourceNames)
			}
		}
	}
	if !foundSecrets {
		t.Fatal("generated Role has no fixed Secret rule")
	}
	if !foundSingletonPatch {
		t.Fatal("generated Role cannot patch the singleton finalizer")
	}
}
