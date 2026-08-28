package secrets

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/progress"

	"golang.org/x/crypto/bcrypt"
)

func TestLoadOrCreateLocalRejectsUnsupportedSchemaWithoutMutation(t *testing.T) {
	project := testProject(t)
	data := []byte(`{
  "schemaVersion": "atum.dev/secrets/v2",
  "forgejo": {"username":"old_admin","adminPassword":"123456789012345678901234"},
  "harbor": {"adminPassword":"abcdefghijklmnopqrstuvwx","secretKey":"0123456789abcdef"}
}
`)
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{}); err == nil {
		t.Fatal("unsupported schema was accepted")
	} else if created {
		t.Fatal("unsupported schema was replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(data) {
		t.Fatal("unsupported schema document changed")
	}
}

func TestLoadOrCreateLocal(t *testing.T) {
	project := testProject(t)

	document, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("missing local secrets were not created")
	}
	defer document.Clear()
	if err := document.Validate(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("local secrets mode is %04o, want 0600", mode)
	}

	reloaded, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing local secrets were replaced")
	}
	defer reloaded.Clear()
	if !reflect.DeepEqual(reloaded, document) {
		t.Fatal("reloaded local secrets differ from the generated document")
	}
}

func TestLoadOrCreateLocalCancellationLeavesValidFileUntouched(t *testing.T) {
	project := testProject(t)
	document, _, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	document.Clear()
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)

	unlock, err := fssecure.LockContext(
		t.Context(), project.Root, localSecretsLock, 25*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := LoadOrCreateLocal(ctx, project, SOPSAdapter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load error = %v, want context.Canceled", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(after, before) {
		t.Fatal("canceled local load changed the valid secrets file")
	}
}

func TestStatefulProjectionIsStableFormattedAndClearable(t *testing.T) {
	t.Parallel()
	document, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	first, err := document.DeriveStatefulProjection()
	if err != nil {
		t.Fatal(err)
	}
	second, err := document.DeriveStatefulProjection()
	if err != nil {
		t.Fatal(err)
	}
	firstData, err := first.MarshalAnsibleJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := second.MarshalAnsibleJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstData) != string(secondData) {
		t.Fatal("unchanged stateful seed produced a different projection")
	}
	kubernetesData, err := first.MarshalKubernetesSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(kubernetesData)
	var kubernetesSecret map[string]any
	if err := json.Unmarshal(kubernetesData, &kubernetesSecret); err != nil {
		t.Fatal(err)
	}
	if kubernetesSecret["immutable"] != true {
		t.Fatal("stateful installation projection is mutable")
	}
	if value := string(first.values[statefulGarageAccessKeyIDKey]); len(value) != 26 || value[:2] != "GK" {
		t.Fatalf("Garage access key ID = %q", value)
	}
	for _, key := range []string{
		statefulGarageAdminTokenKey, statefulGarageSecretKeyKey, statefulDigestKey,
	} {
		if len(first.values[key]) != 64 {
			t.Fatalf("%s length = %d", key, len(first.values[key]))
		}
	}
	for _, key := range []string{
		statefulGitLabSecretKeyBaseKey,
		statefulGitLabOTPKeyBaseKey,
		statefulGitLabDBKeyBaseKey,
		statefulGitLabEncryptedSettingsKeyBaseKey,
	} {
		if len(first.values[key]) != 128 {
			t.Fatalf("%s length = %d", key, len(first.values[key]))
		}
	}
	for _, key := range []string{
		statefulGitLabActiveRecordPrimaryKey,
		statefulGitLabActiveRecordDeterministicKey,
		statefulGitLabActiveRecordSaltKey,
	} {
		if len(first.values[key]) != 32 {
			t.Fatalf("%s length = %d", key, len(first.values[key]))
		}
	}
	quotedSigningKey := make(
		[]byte,
		0,
		len(first.values[statefulGitLabOIDCSigningKey])+2,
	)
	quotedSigningKey = append(quotedSigningKey, '"')
	quotedSigningKey = append(
		quotedSigningKey,
		first.values[statefulGitLabOIDCSigningKey]...,
	)
	quotedSigningKey = append(quotedSigningKey, '"')
	signingKeyPEM, err := strconv.Unquote(string(quotedSigningKey))
	clear(quotedSigningKey)
	if err != nil {
		t.Fatalf("decode GitLab OpenID Connect signing key: %v", err)
	}
	block, rest := pem.Decode([]byte(signingKeyPEM))
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("GitLab OpenID Connect signing key is not one RSA PEM block")
	}
	signingKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse GitLab OpenID Connect signing key: %v", err)
	}
	if err := signingKey.Validate(); err != nil {
		t.Fatalf("validate GitLab OpenID Connect signing key: %v", err)
	}
	if signingKey.N.BitLen() != 2048 {
		t.Fatalf(
			"GitLab OpenID Connect signing key bits = %d",
			signingKey.N.BitLen(),
		)
	}
	for _, pair := range [][2]string{
		{statefulOpenSearchAdminPasswordKey, statefulOpenSearchAdminHashKey},
		{statefulOpenSearchDashboardsPasswordKey, statefulOpenSearchDashboardsHashKey},
		{statefulFluentBitPasswordKey, statefulFluentBitHashKey},
	} {
		if err := bcrypt.CompareHashAndPassword(first.values[pair[1]], first.values[pair[0]]); err != nil {
			t.Fatalf("%s does not authenticate its derived password: %v", pair[1], err)
		}
	}
	if string(first.values[statefulOpenSearchAdminPasswordKey]) ==
		string(first.values[statefulOpenSearchDashboardsPasswordKey]) ||
		string(first.values[statefulOpenSearchAdminPasswordKey]) ==
			string(first.values[statefulFluentBitPasswordKey]) {
		t.Fatal("OpenSearch service credentials are not independent")
	}
	if len(first.values[statefulOpenSearchDashboardsCookieKey]) != 32 {
		t.Fatalf(
			"OpenSearch Dashboards cookie length = %d",
			len(first.values[statefulOpenSearchDashboardsCookieKey]),
		)
	}
	clear(firstData)
	clear(secondData)
	first.Clear()
	second.Clear()
	if len(first.values) != 0 || len(first.digest) != 0 {
		t.Fatal("stateful projection retained cleartext after Clear")
	}
}

func TestDeterministicBcryptInputBoundsAndFormat(t *testing.T) {
	t.Parallel()
	password := []byte("independent-test-password")
	salt := []byte("0123456789abcdef")
	hash, err := deterministicBcrypt(password, salt, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hash)
	if len(hash) != 60 || !bytes.HasPrefix(hash, []byte("$2y$10$")) {
		t.Fatalf("bcrypt format length=%d prefix-valid=%t", len(hash), bytes.HasPrefix(hash, []byte("$2y$10$")))
	}
	if err := bcrypt.CompareHashAndPassword(hash, password); err != nil {
		t.Fatalf("bcrypt output does not verify: %v", err)
	}
	for _, invalid := range []struct {
		password []byte
		salt     []byte
		cost     uint8
	}{
		{nil, salt, 10},
		{make([]byte, 73), salt, 10},
		{password, salt[:15], 10},
		{password, salt, 3},
		{password, salt, 32},
	} {
		if value, err := deterministicBcrypt(
			invalid.password, invalid.salt, invalid.cost,
		); err == nil {
			clear(value)
			t.Fatal("invalid deterministic bcrypt input was accepted")
		}
	}
}

func TestRootCAPublicProjectionContainsNoPrivateKey(t *testing.T) {
	t.Parallel()
	document, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	data, err := rootCAPublicKubernetesSecret(document)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["immutable"] != true ||
		mapAtAny(manifest, "metadata")["name"] != "atum-platform-root-ca-public" {
		t.Fatal("public root CA projection has invalid identity or mutability")
	}
	stringData := mapAtAny(manifest, "stringData")
	if len(stringData) != 2 || stringData["ATUM_ROOT_CA_DIGEST"] == nil {
		t.Fatal("public root CA projection has unexpected keys")
	}
	encoded, _ := stringData["ATUM_ROOT_CA_CERTIFICATE_B64"].(string)
	certificate, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(certificate)
	if !bytes.Equal(certificate, document.RootCA.Certificate.Bytes()) ||
		strings.Contains(string(data), "tls.key") ||
		strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("public root CA projection contains wrong or private material")
	}
}

func TestEncryptedFluxSecretEnvelopeTypesImmutable(t *testing.T) {
	t.Parallel()

	envelope := func(immutable string, extra string) []byte {
		field := ""
		if immutable != "" {
			field = `,"immutable":` + immutable
		}
		return []byte(`{
			"apiVersion":"v1",
			"kind":"Secret",
			"metadata":{"name":"test","namespace":"flux-system"},
			"type":"Opaque",
			"stringData":{"value":"ENC[AES256_GCM,data:test]"},
			"sops":{"age":[],"encrypted_regex":"^(data|stringData)$","mac":"ENC[]"}` +
			field + extra + `}`)
	}
	for _, test := range []struct {
		name      string
		immutable string
	}{
		{name: "pki/root-ca.json", immutable: "true"},
		{name: "root-ca-public.json", immutable: "true"},
		{name: "stateful.json", immutable: "true"},
		{name: "identity.json", immutable: "false"},
		{name: "operator.json", immutable: "false"},
		{name: "omitted"},
	} {
		if err := validateEncryptedFluxEnvelope(
			envelope(test.immutable, ""), test.name,
		); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
	}
	if err := validateEncryptedFluxEnvelope(
		envelope(`"true"`, ""), "non-boolean.json",
	); err == nil {
		t.Fatal("non-boolean immutable field was accepted")
	}
	if err := validateEncryptedFluxEnvelope(
		envelope("", `,"unknown":true`), "unknown.json",
	); err == nil {
		t.Fatal("unrecognized encrypted Secret field was accepted")
	}
}

func TestFluxPKIKustomizationExcludesSubstitutedAccessCertificates(t *testing.T) {
	t.Parallel()
	text := string(fluxPKIKustomization)
	if !strings.Contains(text, "../../../profiles/local/prep/certificates") {
		t.Fatal("generated PKI source omits its prep certificates")
	}
	if strings.Contains(text, "../../../profiles/local/access") ||
		strings.Contains(text, "ATUM_PLATFORM_DOMAIN") {
		t.Fatal("generated PKI source claims substituted profile-access certificates")
	}
	access, err := os.ReadFile(
		filepath.Join(
			"..", "..", "platform", "clusters", "atum",
			"platform-profile-access.yaml",
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(access, []byte("name: platform-certificates")) ||
		!bytes.Contains(access, []byte("ATUM_PLATFORM_DOMAIN")) ||
		!bytes.Contains(access, []byte("path: ./platform/profiles/${ATUM_PLATFORM_PROFILE}/access")) {
		t.Fatal("profile-access does not solely order and substitute access certificates")
	}
	accessSource, err := os.ReadFile(
		filepath.Join(
			"..", "..", "platform", "profiles", "local", "access",
			"kustomization.yaml",
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(accessSource, []byte("  - certificates")) {
		t.Fatal("profile-access source omits its sole access-certificate input")
	}
	pkiOwner, err := os.ReadFile(
		filepath.Join(
			"..", "..", "platform", "clusters", "atum",
			"platform-certificates.yaml",
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pkiOwner, []byte("path: ./platform/secrets/atum/pki")) ||
		bytes.Contains(pkiOwner, []byte("postBuild:")) ||
		bytes.Contains(pkiOwner, []byte("ATUM_PLATFORM_DOMAIN")) {
		t.Fatal("platform-certificates crosses into substituted profile-access ownership")
	}
}

func mapAtAny(value map[string]any, key string) map[string]any {
	result, _ := value[key].(map[string]any)
	return result
}

func TestLoadOrCreateLocalPreservesInvalidFile(t *testing.T) {
	project := testProject(t)
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const invalid = "{not-json}\n"
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{}); err == nil {
		t.Fatal("invalid local secrets were accepted")
	} else if created {
		t.Fatal("invalid local secrets were replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != invalid {
		t.Fatal("invalid local secrets changed")
	}
}

func TestLoadOrCreateLocalDoesNotMaskInvalidSOPS(t *testing.T) {
	project := testProject(t)
	path := filepath.Join(project.Root, project.Desired.Secrets.SOPSFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not: sops\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{}); err == nil {
		t.Fatal("invalid SOPS secrets were accepted")
	} else if created {
		t.Fatal("invalid SOPS secrets were masked by local credentials")
	}
	if _, err := os.Stat(filepath.Join(project.Root, project.Desired.Secrets.LocalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local secrets stat error is %v, want os.ErrNotExist", err)
	}
}

func TestLoadReportsNotFound(t *testing.T) {
	if _, err := Load(t.Context(), testProject(t), SOPSAdapter{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error is %v, want ErrNotFound", err)
	}
}

func TestLocalInitDoesNotRequireSOPS(t *testing.T) {
	project := testProject(t)
	path, err := Init(
		t.Context(),
		project,
		SOPSAdapter{},
		InitOptions{Local: true},
	)
	if err != nil {
		t.Fatalf("initialize local secrets without SOPS: %v", err)
	}
	if path != project.Desired.Secrets.LocalFile {
		t.Fatalf("local secrets path = %q, want %q", path, project.Desired.Secrets.LocalFile)
	}
	document, err := Load(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatalf("load local-only secrets without SOPS: %v", err)
	}
	defer document.Clear()
	if err := document.Validate(); err != nil {
		t.Fatalf("validate local-only secrets: %v", err)
	}
}

func TestEnsureReportsSavedPath(t *testing.T) {
	project := testProject(t)
	reporter := new(eventRecorder)
	ctx := progress.WithReporter(t.Context(), reporter)

	document, err := Ensure(ctx, project, SOPSAdapter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
	if len(*reporter) != 2 {
		t.Fatalf("Ensure() reported %d events, want 2", len(*reporter))
	}
	event := (*reporter)[1]
	if event.Phase != progress.Credentials || event.ID != "secrets" || event.State != progress.Complete {
		t.Fatalf("Ensure() completion event is %#v", event)
	}
	const detail = "secrets saved to .atum/secrets.local.json (Git-ignored)"
	if event.Detail != detail {
		t.Fatalf("Ensure() detail is %q, want %q", event.Detail, detail)
	}
}

type eventRecorder []progress.Event

func (recorder *eventRecorder) Report(event progress.Event) {
	*recorder = append(*recorder, event)
}

func testProject(t *testing.T) *config.Project {
	t.Helper()
	return &config.Project{
		Root: t.TempDir(),
		Desired: config.Document{Secrets: config.Secrets{
			SOPSFile:  "secrets/atum.sops.yaml",
			LocalFile: ".atum/secrets.local.json",
		}},
	}
}
