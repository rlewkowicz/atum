package infra

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDNSPostWriteVerificationUsesConfigurationInspector(t *testing.T) {
	t.Parallel()

	facts := LocalAccessFacts{
		Domain: "atum.test", DNSServer: "10.77.0.1",
		PublicIngressVIP: "10.77.0.20", PassthroughIngressVIP: "10.77.0.21",
		PassthroughHosts: []string{"keycloak"},
	}
	calls := 0
	err := verifyDNSPostWrite(
		context.Background(),
		facts,
		func(_ context.Context, observed LocalAccessFacts) (AccessStatus, error) {
			calls++
			if observed.Domain != facts.Domain {
				t.Fatalf("configuration facts = %#v, want %#v", observed, facts)
			}
			return AccessStatus{
				ResolverExact: true, ResolvedActive: true, ResolvConfManaged: true,
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("verify DNS post-write configuration: %v", err)
	}
	if calls != 1 {
		t.Fatalf("configuration inspector calls = %d, want 1", calls)
	}
}

func TestDNSPostWriteVerificationRejectsIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	err := verifyDNSPostWrite(
		context.Background(),
		LocalAccessFacts{},
		func(context.Context, LocalAccessFacts) (AccessStatus, error) {
			return AccessStatus{
				ResolverExact: true, ResolvedActive: true,
				PublicLookupExact: true, PassthroughLookupsExact: true,
			}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "post-write verification failed") {
		t.Fatalf("incomplete DNS configuration error = %v", err)
	}
}

func TestLocalAccessFactsAreDeterministicAndSafe(t *testing.T) {
	t.Parallel()

	facts := LocalAccessFacts{
		Domain:                "atum.test",
		DNSServer:             "10.77.0.1",
		PublicIngressVIP:      "10.77.0.20",
		PassthroughIngressVIP: "10.77.0.21",
		PassthroughHosts:      []string{"keycloak"},
	}
	if err := validateAccessFacts(facts); err != nil {
		t.Fatalf("validate facts: %v", err)
	}
	want := []byte("[Resolve]\nDNS=10.77.0.1\nDomains=~atum.test\n")
	first := resolverContent(facts)
	second := resolverContent(facts)
	if !bytes.Equal(first, want) || !bytes.Equal(first, second) {
		t.Fatalf("resolver content = %q and %q, want %q", first, second, want)
	}

	duplicate := facts
	duplicate.PassthroughHosts = []string{"keycloak", "keycloak"}
	if err := validateAccessFacts(duplicate); err == nil ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate facts error = %v", err)
	}
	for _, domain := range []string{"../atum.test", "Atum.test", "atum.test/../../etc"} {
		if err := ValidateAccessDomain(domain); err == nil {
			t.Errorf("unsafe domain %q accepted", domain)
		}
	}
	if err := validatePassthroughLabel("../keycloak", facts.Domain); err == nil {
		t.Fatal("unsafe passthrough label accepted")
	}
	if canonicalExecutable("relative/tool") != "" {
		t.Fatal("relative executable accepted")
	}
}

func TestSecureRootExecutableAcceptsFedoraExecuteOnlySudo(t *testing.T) {
	t.Parallel()

	if !secureRootExecutable(unix.Stat_t{
		Mode: unix.S_IFREG | 0o4111,
		Uid:  0,
		Gid:  0,
	}) {
		t.Fatal("root-owned mode-4111 executable was rejected")
	}
	for _, identity := range []unix.Stat_t{
		{Mode: unix.S_IFREG | 0o4111, Uid: 1, Gid: 0},
		{Mode: unix.S_IFREG | 0o4133, Uid: 0, Gid: 0},
		{Mode: unix.S_IFDIR | 0o4111, Uid: 0, Gid: 0},
	} {
		if secureRootExecutable(identity) {
			t.Fatalf("insecure executable identity accepted: %#v", identity)
		}
	}
}

func TestBoundedCommandOutput(t *testing.T) {
	t.Parallel()

	var output boundedOutput
	first := bytes.Repeat([]byte("a"), commandLimit-1)
	second := []byte("bc")
	if written, err := output.Write(first); err != nil || written != len(first) {
		t.Fatalf("first write = %d, %v", written, err)
	}
	if written, err := output.Write(second); err != nil || written != len(second) {
		t.Fatalf("second write = %d, %v", written, err)
	}
	if len(output.Bytes()) != commandLimit || !output.overflow ||
		output.Bytes()[commandLimit-1] != 'b' {
		t.Fatalf("bounded output length/overflow/tail = %d, %t, %q",
			len(output.Bytes()), output.overflow, output.Bytes()[commandLimit-1])
	}
}

func TestResolverAnswerAcceptsResolvectlOutputForms(t *testing.T) {
	t.Parallel()

	const host = "headlamp.atum.test"
	for _, fields := range [][]string{
		{host, "IN", "A", "10.77.0.20"},
		{host, "IN", "A", "10.77.0.20", "--", "link:", "virbr1"},
		{host + ":", "10.77.0.20"},
		{host + ".", "10.77.0.20", "--", "link:", "virbr1"},
	} {
		address, valid := resolverAnswer(fields, host)
		if !valid || address.String() != "10.77.0.20" {
			t.Errorf("resolverAnswer(%q) = %s, %t", fields, address, valid)
		}
	}
	for _, fields := range [][]string{
		{host, "IN", "A", "10.77.0.20", "--", "link:"},
		{host, "IN", "AAAA", "10.77.0.20"},
		{host, "IN", "A", "10.77.0.20", "unexpected"},
		{"other.atum.test", "IN", "A", "10.77.0.20"},
	} {
		if _, valid := resolverAnswer(fields, host); valid {
			t.Errorf("resolverAnswer(%q) accepted malformed output", fields)
		}
	}
}

func TestValidateRootCA(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	certificate := testRootCertificate(t, now, "atum-test", true)
	validated, err := ValidateRootCA(certificate, now)
	if err != nil {
		t.Fatalf("validate root CA: %v", err)
	}
	if !bytes.Equal(validated.PEM, bytes.TrimSpace(certificate)) ||
		len(validated.Fingerprint) != 64 {
		t.Fatalf("validated CA PEM/fingerprint is not canonical: %d bytes, %q",
			len(validated.PEM), validated.Fingerprint)
	}
	again, err := ValidateRootCA(certificate, now)
	if err != nil || again.Fingerprint != validated.Fingerprint ||
		!bytes.Equal(again.PEM, validated.PEM) {
		t.Fatalf("repeated CA validation = %#v, %v", again, err)
	}
	if _, err := ValidateRootCA(certificate, now.Add(25*time.Hour)); err == nil ||
		!strings.Contains(err.Error(), "not valid") {
		t.Fatalf("expired CA error = %v", err)
	}
	if _, err := ValidateRootCA(
		testRootCertificate(t, now, "other", true), now,
	); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("wrong-subject CA error = %v", err)
	}
	if _, err := ValidateRootCA(
		testRootCertificate(t, now, "atum-test", false), now,
	); err == nil || !strings.Contains(err.Error(), "must be a CA") {
		t.Fatalf("leaf certificate error = %v", err)
	}
}

func testRootCertificate(t *testing.T, now time.Time, commonName string, isCA bool) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	usage := x509.KeyUsageDigitalSignature
	if isCA {
		usage |= x509.KeyUsageCertSign
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
