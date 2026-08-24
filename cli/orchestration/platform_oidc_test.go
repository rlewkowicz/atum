package orchestration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atum/cli/identity"
	"atum/cli/infra"
)

func TestPlatformOIDCSpecUsesCanonicalIdentityAndSelectedAPI(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rootCA, err := infra.ValidateRootCA(testOIDCRootCertificate(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer rootCA.Clear()
	spec, err := NewPlatformOIDCSpec(contract, rootCA, "1.35.4")
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Clear()
	rendered := string(spec.config)
	for _, exact := range []string{
		"apiVersion: apiserver.config.k8s.io/v1",
		"url: https://keycloak.atum.test/auth/realms/master",
		"certificateAuthority: |",
		"audienceMatchPolicy: MatchAny",
		"claim: preferred_username",
		"claim: groups",
		"prefix: 'oidc:'",
	} {
		if !strings.Contains(rendered, exact) {
			t.Errorf("serialized authentication configuration omits %q:\n%s", exact, rendered)
		}
	}
	if spec.authenticationPath != "/etc/kubernetes/apiserver-authentication-config-v1.yaml" ||
		len(spec.configDigest) != 64 || len(spec.audienceDigest) != 64 {
		t.Fatalf("unexpected immutable OIDC identity: %#v", spec)
	}
}

func TestInitialKubernetesOIDCOmitsUnavailableCA(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	audiences, err := contractAudiences(contract)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(kubesprayOIDCProjection{
		Enabled: true, JWT: contractJWT(contract, audiences, ""),
		Anonymous: anonymousAuth{Enabled: true, Conditions: []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(data)
	if strings.Contains(rendered, "certificateAuthority") ||
		!strings.Contains(rendered, `"audienceMatchPolicy":"MatchAny"`) ||
		!strings.Contains(rendered, `"claim":"preferred_username"`) {
		t.Fatalf("invalid initial Kubespray OIDC projection: %s", rendered)
	}
	if api, err := AuthenticationConfigAPIVersion("v1.33.5"); err == nil || api != "" ||
		!strings.Contains(err.Error(), "last_config_info") {
		t.Fatalf("Kubernetes 1.33 final authentication boundary = %q, %v", api, err)
	}
	for _, version := range []string{"v1.34.0", "1.35.4"} {
		if api, err := AuthenticationConfigAPIVersion(version); err != nil || api != "v1" {
			t.Fatalf("Kubernetes %s authentication API = %q, %v", version, api, err)
		}
	}
}

func testOIDCRootCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "atum-test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPlatformOIDCReceiptRequiresEveryExactFieldAndNode(t *testing.T) {
	t.Parallel()

	spec := &PlatformOIDCSpec{
		issuer:       "https://keycloak.atum.test/auth/realms/master",
		configDigest: strings.Repeat("1", 64), caFingerprint: strings.Repeat("A", 64),
		audienceDigest: strings.Repeat("2", 64),
	}
	exact := map[string]string{
		"schemaVersion": PlatformOIDCReceiptSchema,
		"issuer":        spec.issuer, "configDigest": spec.configDigest,
		"caFingerprint": spec.caFingerprint, "audienceDigest": spec.audienceDigest,
		"verifiedNodes": "3",
	}
	if ready, failure := ValidatePlatformOIDCReceipt(spec, exact, 3); !ready || failure != "" {
		t.Fatalf("exact receipt = %t, %q", ready, failure)
	}
	stale := make(map[string]string, len(exact))
	for key, value := range exact {
		stale[key] = value
	}
	stale["verifiedNodes"] = "2"
	if ready, failure := ValidatePlatformOIDCReceipt(spec, stale, 3); ready ||
		!strings.Contains(failure, "want 3") {
		t.Fatalf("stale receipt = %t, %q", ready, failure)
	}
	if ready, failure := ValidatePlatformOIDCReceipt(spec, exact, 0); ready ||
		!strings.Contains(failure, "control-plane node set is empty") {
		t.Fatalf("empty control-plane set = %t, %q", ready, failure)
	}
	if ready, failure := ValidatePlatformOIDCReceipt(spec, exact, 2); ready ||
		!strings.Contains(failure, "want 2") {
		t.Fatalf("worker-inclusive receipt = %t, %q", ready, failure)
	}
	if ready, failure := ValidatePlatformOIDCReceipt(spec, nil, 3); ready ||
		!strings.Contains(failure, "receipt is absent") {
		t.Fatalf("missing receipt = %t, %q", ready, failure)
	}
}

func TestExistingKubesprayCompletesOIDCHandoffBeforeIdentity(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{"current configuration replay", "upgrade"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			events := make([]string, 0, 4)
			step := func(name string, err error) func() error {
				return func() error {
					events = append(events, name)
					return err
				}
			}
			if err := completeExistingKubesprayHandoff(
				step("kubespray", nil),
				step("health", nil),
				step("platform-oidc", nil),
			); err != nil {
				t.Fatal(err)
			}
			events = append(events, "identity")
			if got := strings.Join(events, ","); got !=
				"kubespray,health,platform-oidc,identity" {
				t.Fatalf("completion order = %s", got)
			}

			events = events[:0]
			failure := errors.New("OIDC handoff failed")
			err := completeExistingKubesprayHandoff(
				step("kubespray", nil),
				step("health", nil),
				step("platform-oidc", failure),
			)
			if !errors.Is(err, failure) {
				t.Fatalf("handoff error = %v", err)
			}
			if got := strings.Join(events, ","); got !=
				"kubespray,health,platform-oidc" {
				t.Fatalf("failed completion order = %s", got)
			}
		})
	}
}
