package orchestration

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestInitialKubernetesOIDCRequiresRootCA(t *testing.T) {
	t.Parallel()

	service := kubernetesOIDCTestService(t, nil)
	if _, err := service.initialKubernetesOIDC(); err == nil ||
		!strings.Contains(err.Error(), "root CA certificate is required") {
		t.Fatalf("missing root CA error = %v", err)
	}
}

func TestInitialKubernetesOIDCProjectsCanonicalAuthentication(t *testing.T) {
	t.Parallel()

	const rootCA = "-----BEGIN CERTIFICATE-----\natum-root\n-----END CERTIFICATE-----\n"
	projection, err := kubernetesOIDCTestService(t, []byte(rootCA)).initialKubernetesOIDC()
	if err != nil {
		t.Fatal(err)
	}
	if projection == nil || !projection.Enabled || len(projection.JWT) != 1 {
		t.Fatalf("OIDC projection = %#v", projection)
	}
	authenticator := projection.JWT[0]
	if authenticator.Issuer.URL != "https://keycloak.atum.test/auth/realms/master" ||
		authenticator.Issuer.CertificateAuthority != rootCA ||
		authenticator.Issuer.AudienceMatchPolicy != "MatchAny" {
		t.Fatalf("issuer projection = %#v", authenticator.Issuer)
	}
	if want := []string{"atum-headlamp", "atum-kiali"}; !reflect.DeepEqual(
		authenticator.Issuer.Audiences,
		want,
	) {
		t.Fatalf("audiences = %v, want %v", authenticator.Issuer.Audiences, want)
	}
	if authenticator.ClaimMappings.Username != (prefixedClaim{
		Claim:  "preferred_username",
		Prefix: "oidc:",
	}) || authenticator.ClaimMappings.Groups != (prefixedClaim{
		Claim:  "groups",
		Prefix: "oidc:",
	}) {
		t.Fatalf("claim mappings = %#v", authenticator.ClaimMappings)
	}

	if projection.Anonymous.Enabled {
		t.Fatalf("anonymous authentication = %#v", projection.Anonymous)
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"conditions"`) ||
		!strings.Contains(string(encoded), `"anonymous":{"enabled":false}`) {
		t.Fatalf("anonymous authentication projection = %s", encoded)
	}
}

func kubernetesOIDCTestService(t *testing.T, rootCA []byte) Service {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return Service{
		Project: &config.Project{
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
		},
		RootCAPEM: rootCA,
	}
}
