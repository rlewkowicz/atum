package infra

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/process"

	"golang.org/x/sys/unix"
)

const (
	ResolverDropInPath   = "/etc/systemd/resolved.conf.d/99-atum-test.conf"
	FedoraAnchorPath     = "/etc/pki/ca-trust/source/anchors/atum-test-ca.crt"
	DebianAnchorPath     = "/usr/local/share/ca-certificates/atum-test-ca.crt"
	RootCertificateLimit = 1 << 20

	resolverStateLimit = 4 << 10
	commandLimit       = 16 << 10
	rootCASubject      = "CN=atum-test"
	osReleasePath      = "/usr/lib/os-release"
	osReleaseLimit     = 16 << 10
)

var (
	systemctlCandidates  = [...]string{"/usr/bin/systemctl", "/bin/systemctl"}
	resolvectlCandidates = [...]string{"/usr/bin/resolvectl", "/bin/resolvectl"}
	trustCandidates      = [...]trustCandidate{
		{family: FedoraTrustStore, updater: trustUpdater{
			binary: "/usr/bin/update-ca-trust", anchor: FedoraAnchorPath, arguments: []string{"extract"}}},
		{family: FedoraTrustStore, updater: trustUpdater{
			binary: "/usr/sbin/update-ca-trust", anchor: FedoraAnchorPath, arguments: []string{"extract"}}},
		{family: DebianTrustStore, updater: trustUpdater{
			binary: "/usr/sbin/update-ca-certificates", anchor: DebianAnchorPath}},
		{family: DebianTrustStore, updater: trustUpdater{
			binary: "/usr/bin/update-ca-certificates", anchor: DebianAnchorPath}},
	}
)

type AccessCapabilityNeed uint8

const (
	ObserveDNS AccessCapabilityNeed = 1 << iota
)

type AccessCapabilities struct {
	Systemctl  string
	Resolvectl string
}

type TrustUpdater struct {
	Binary    string
	Arguments []string
}

type trustUpdater struct {
	binary    string
	anchor    string
	arguments []string
}

type TrustStoreFamily uint8

const (
	FedoraTrustStore TrustStoreFamily = iota + 1
	DebianTrustStore
)

type trustCandidate struct {
	family  TrustStoreFamily
	updater trustUpdater
}

type TrustStoreDescriptor struct {
	Family TrustStoreFamily
	Anchor string
}

// LocalAccessFacts are the immutable desired facts owned by config.LocalAccess.
// This service derives all host paths and content from these values.
type LocalAccessFacts struct {
	Domain                string
	DNSServer             string
	PublicIngressVIP      string
	PassthroughIngressVIP string
	PassthroughHosts      []string
}

type AccessStatus struct {
	ResolverPath            string
	ResolverContent         string
	ResolverPresent         bool
	ResolverExact           bool
	ResolvedActive          bool
	ResolvConfTarget        string
	ResolvConfManaged       bool
	PublicLookupExact       bool
	PassthroughLookupsExact bool
	PassthroughLookupCount  int
	AnchorPath              string
	AnchorPresent           bool
	AnchorFingerprint       string
}

func (status AccessStatus) DNSExact() bool {
	return status.ResolverExact && status.ResolvedActive && status.ResolvConfManaged
}

type ValidatedCA struct {
	PEM         []byte
	Fingerprint string
}

type rootValidity uint8

const (
	rootAnyValidity rootValidity = iota
	rootCurrentValidity
	rootRemovalValidity
)

type managedFileReceipt struct {
	path  string
	data  []byte
	limit int64
	mode  os.FileMode
}

type AccessRemovalPlan struct {
	facts    LocalAccessFacts
	files    []managedFileReceipt
	resolver bool
	trust    bool
}

func (plan AccessRemovalPlan) Empty() bool { return len(plan.files) == 0 }

func (plan AccessRemovalPlan) CapabilityNeed() AccessCapabilityNeed {
	if plan.resolver {
		return ObserveDNS
	}
	return 0
}

func (plan AccessRemovalPlan) RefreshesTrust() bool { return plan.trust }

func (plan AccessRemovalPlan) AuthorizationDigest() string {
	digest := sha256.New()
	if plan.resolver {
		_, _ = digest.Write([]byte{1})
	} else {
		_, _ = digest.Write([]byte{0})
	}
	if plan.trust {
		_, _ = digest.Write([]byte{1})
	} else {
		_, _ = digest.Write([]byte{0})
	}
	for index := range plan.files {
		_, _ = digest.Write([]byte(plan.files[index].path))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(plan.files[index].data)
		_, _ = digest.Write([]byte{0})
	}
	sum := digest.Sum(nil)
	defer clear(sum)
	return strings.ToUpper(hex.EncodeToString(sum))
}

func (plan *AccessRemovalPlan) Clear() {
	if plan == nil {
		return
	}
	for index := range plan.files {
		plan.files[index].Clear()
	}
	plan.files = nil
}

func (receipt *managedFileReceipt) Clear() {
	if receipt == nil {
		return
	}
	clear(receipt.data)
	receipt.data = nil
}

func (certificate *ValidatedCA) Clear() {
	if certificate == nil {
		return
	}
	clear(certificate.PEM)
	certificate.PEM = nil
}

type AccessService struct {
	Runner       process.Runner
	Output       io.Writer
	EUID         int
	Capabilities AccessCapabilities
	TrustStore   TrustStoreDescriptor
	TrustUpdater TrustUpdater
	Now          func() time.Time
}

func (service AccessService) Status(ctx context.Context, facts LocalAccessFacts) (AccessStatus, error) {
	status, err := service.DNSConfigurationStatus(ctx, facts)
	if err != nil {
		return AccessStatus{}, err
	}
	capabilitiesValid := ValidateAccessCapabilities(
		service.Capabilities, ObserveDNS) == nil
	resolvectl := service.Capabilities.Resolvectl
	if capabilitiesValid && service.Runner != nil && status.ResolvedActive {
		status.PublicLookupExact = service.lookup(ctx, resolvectl, "headlamp."+facts.Domain, facts.PublicIngressVIP)
		status.PassthroughLookupsExact = service.passthroughLookupsExact(
			ctx, resolvectl, facts)
	}
	if service.TrustStore.Anchor != "" {
		if err := ValidateTrustStore(service.TrustStore); err != nil {
			return status, err
		}
		status.AnchorPath = service.TrustStore.Anchor
		anchor, anchorFound, readErr := readManagedHostFile(
			status.AnchorPath, RootCertificateLimit, 0o644)
		if readErr != nil {
			return status, readErr
		}
		defer clear(anchor)
		if anchorFound {
			status.AnchorPresent = true
			status.AnchorFingerprint = certificateFingerprint(anchor)
		}
	}
	return status, nil
}

// DNSConfigurationStatus inspects only resolver configuration and service
// activation. It deliberately never issues public or passthrough lookups.
func (service AccessService) DNSConfigurationStatus(
	ctx context.Context,
	facts LocalAccessFacts,
) (AccessStatus, error) {
	if err := validateAccessFacts(facts); err != nil {
		return AccessStatus{}, err
	}
	status := AccessStatus{
		ResolverPath:           ResolverDropInPath,
		PassthroughLookupCount: len(facts.PassthroughHosts),
	}
	content, found, err := readManagedHostFile(ResolverDropInPath, resolverStateLimit, 0o644)
	if err != nil {
		return status, err
	}
	if found {
		status.ResolverPresent = true
		status.ResolverContent = string(content)
		status.ResolverExact = bytes.Equal(content, resolverContent(facts))
	}
	status.ResolvConfTarget, status.ResolvConfManaged, err = resolvedResolvConf()
	if err != nil {
		return status, err
	}
	systemctl := service.Capabilities.Systemctl
	capabilitiesValid := ValidateAccessCapabilities(
		service.Capabilities, ObserveDNS) == nil
	if capabilitiesValid && service.Runner != nil {
		status.ResolvedActive = service.runQuiet(ctx, systemctl, "is-active", "--quiet", "systemd-resolved.service") == nil
	}
	return status, nil
}

func (service AccessService) InstallDNS(ctx context.Context, facts LocalAccessFacts) error {
	if err := service.requireRoot(); err != nil {
		return err
	}
	if err := validateAccessFacts(facts); err != nil {
		return err
	}
	if err := ValidateAccessCapabilities(
		service.Capabilities, ObserveDNS); err != nil {
		return err
	}
	systemctl := service.Capabilities.Systemctl
	if systemctl == "" || service.Runner == nil {
		return errors.New("systemctl is required to install local DNS")
	}
	if err := service.runQuiet(ctx, systemctl, "is-active", "--quiet", "systemd-resolved.service"); err != nil {
		return errors.New("systemd-resolved must be active before installing local DNS")
	}
	target, managed, err := resolvedResolvConf()
	if err != nil {
		return err
	}
	if !managed {
		if target == "" {
			return errors.New("/etc/resolv.conf is not a systemd-resolved symlink; refusing to replace it")
		}
		return fmt.Errorf("/etc/resolv.conf points to %q; it must link to a systemd-resolved managed file", target)
	}
	if err := ensureRootDirectory(filepath.Dir(ResolverDropInPath), 0o755, true); err != nil {
		return err
	}
	if err := atomicHostFile(ResolverDropInPath, resolverContent(facts), 0o644); err != nil {
		return err
	}
	if err := service.runQuiet(
		ctx, systemctl,
		"reload-or-restart", "systemd-resolved.service",
	); err != nil {
		return fmt.Errorf("reload systemd-resolved: %w", err)
	}
	if err := verifyDNSPostWrite(
		ctx, facts, service.DNSConfigurationStatus); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return service.print("local DNS saved to %s\n", ResolverDropInPath)
}

type dnsConfigurationInspector func(
	context.Context,
	LocalAccessFacts,
) (AccessStatus, error)

func verifyDNSPostWrite(
	ctx context.Context,
	facts LocalAccessFacts,
	inspect dnsConfigurationInspector,
) error {
	if inspect == nil {
		return errors.New("DNS configuration inspector is required")
	}
	status, err := inspect(ctx, facts)
	if err != nil {
		return err
	}
	if !status.DNSExact() {
		return fmt.Errorf(
			"local DNS post-write verification failed at %s", ResolverDropInPath)
	}
	return nil
}

func (service AccessService) InstallCA(ctx context.Context, facts LocalAccessFacts, certificate []byte) error {
	if err := service.requireRoot(); err != nil {
		return err
	}
	if err := validateAccessFacts(facts); err != nil {
		return err
	}
	if err := ValidateTrustUpdater(service.TrustStore, service.TrustUpdater); err != nil {
		return err
	}
	validated, err := ValidateRootCA(certificate, service.now())
	if err != nil {
		return err
	}
	defer validated.Clear()
	if service.Runner == nil {
		return errors.New("CA trust command runner is unavailable")
	}
	if err := atomicHostFile(service.TrustStore.Anchor, validated.PEM, 0o644); err != nil {
		return err
	}
	if err := ValidateTrustUpdater(service.TrustStore, service.TrustUpdater); err != nil {
		return err
	}
	if err := service.runQuiet(
		ctx, service.TrustUpdater.Binary, service.TrustUpdater.Arguments...); err != nil {
		return fmt.Errorf("update system CA trust: %w", err)
	}
	written, found, err := readManagedHostFile(
		service.TrustStore.Anchor, RootCertificateLimit, 0o644)
	defer clear(written)
	if err != nil || !found || !bytes.Equal(written, validated.PEM) ||
		certificateFingerprint(written) != validated.Fingerprint {
		if err == nil {
			err = errors.New("installed certificate differs from validated root")
		}
		return fmt.Errorf(
			"local CA post-write verification failed at %s: %w",
			service.TrustStore.Anchor, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (service AccessService) CompareCA(
	certificate ValidatedCA,
) (path, fingerprint string, exact bool, err error) {
	if len(certificate.PEM) == 0 || certificate.Fingerprint == "" ||
		certificateFingerprint(certificate.PEM) != certificate.Fingerprint {
		return "", "", false, errors.New("validated root CA is required")
	}
	if err := ValidateTrustStore(service.TrustStore); err != nil {
		return "", certificate.Fingerprint, false, err
	}
	anchor := service.TrustStore.Anchor
	current, currentFound, err := readManagedHostFile(anchor, RootCertificateLimit, 0o644)
	if err != nil {
		return anchor, certificate.Fingerprint, false, err
	}
	defer clear(current)
	return anchor, certificate.Fingerprint,
		currentFound && bytes.Equal(current, certificate.PEM) &&
			certificateFingerprint(current) == certificate.Fingerprint, nil
}

func (service AccessService) PlanUninstall(facts LocalAccessFacts) (AccessRemovalPlan, error) {
	if err := validateAccessFacts(facts); err != nil {
		return AccessRemovalPlan{}, err
	}
	if err := ValidateTrustStore(service.TrustStore); err != nil {
		return AccessRemovalPlan{}, err
	}
	plan := AccessRemovalPlan{facts: facts, files: make([]managedFileReceipt, 0, 2)}
	resolver, found, err := readManagedHostFile(ResolverDropInPath, resolverStateLimit, 0o644)
	if err != nil {
		return AccessRemovalPlan{}, err
	}
	if found {
		if !bytes.Equal(resolver, resolverContent(facts)) {
			clear(resolver)
			return AccessRemovalPlan{}, fmt.Errorf(
				"refusing to remove non-Atum resolver content at %s", ResolverDropInPath)
		}
		plan.files = append(plan.files, managedFileReceipt{
			path: ResolverDropInPath, data: resolver, limit: resolverStateLimit,
			mode: 0o644,
		})
		plan.resolver = true
	}
	path := service.TrustStore.Anchor
	anchor, anchorFound, readErr := readManagedHostFile(path, RootCertificateLimit, 0o644)
	if readErr != nil {
		plan.Clear()
		return AccessRemovalPlan{}, readErr
	}
	if anchorFound {
		validated, validateErr := validateRootCA(anchor, service.now(), rootRemovalValidity)
		if validateErr != nil {
			clear(anchor)
			plan.Clear()
			return AccessRemovalPlan{}, fmt.Errorf(
				"refusing to remove non-Atum CA anchor at %s: %w", path, validateErr)
		}
		validated.Clear()
		plan.files = append(plan.files, managedFileReceipt{
			path: path, data: anchor, limit: RootCertificateLimit,
			mode: 0o644,
		})
		plan.trust = true
	}
	return plan, nil
}

func (service AccessService) Uninstall(ctx context.Context, plan AccessRemovalPlan) (err error) {
	if err := service.requireRoot(); err != nil {
		return err
	}
	if service.Runner == nil {
		return errors.New("local access command runner is unavailable")
	}
	defer plan.Clear()
	if err := validateAccessFacts(plan.facts); err != nil {
		return err
	}
	if plan.Empty() {
		return nil
	}
	if err := ValidateAccessCapabilities(
		service.Capabilities, plan.CapabilityNeed()); err != nil {
		return err
	}
	if plan.trust {
		if err := ValidateTrustUpdater(service.TrustStore, service.TrustUpdater); err != nil {
			return err
		}
	}
	verified, err := service.PlanUninstall(plan.facts)
	if err != nil {
		return err
	}
	defer verified.Clear()
	if !sameRemovalPlan(plan, verified) {
		return errors.New("local access removal state changed after authorization")
	}
	for index := range plan.files {
		if err := removeHostFile(plan.files[index].path, plan.files[index].mode); err != nil {
			return err
		}
	}
	if plan.resolver {
		if err := service.runQuiet(
			ctx, service.Capabilities.Systemctl,
			"reload-or-restart", "systemd-resolved.service",
		); err != nil {
			return fmt.Errorf("reload systemd-resolved: %w", err)
		}
	}
	if plan.trust {
		if err := ValidateTrustUpdater(service.TrustStore, service.TrustUpdater); err != nil {
			return err
		}
		if err := service.runQuiet(
			ctx, service.TrustUpdater.Binary, service.TrustUpdater.Arguments...); err != nil {
			return fmt.Errorf("update system CA trust: %w", err)
		}
	}
	for index := range plan.files {
		if _, found, readErr := readManagedHostFile(
			plan.files[index].path, plan.files[index].limit,
			plan.files[index].mode); readErr != nil {
			return readErr
		} else if found {
			return fmt.Errorf("removed host path %s is still present", plan.files[index].path)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func sameRemovalPlan(left, right AccessRemovalPlan) bool {
	if left.resolver != right.resolver || left.trust != right.trust ||
		len(left.files) != len(right.files) {
		return false
	}
	for index := range left.files {
		if left.files[index].path != right.files[index].path ||
			left.files[index].limit != right.files[index].limit ||
			left.files[index].mode != right.files[index].mode ||
			!bytes.Equal(left.files[index].data, right.files[index].data) {
			return false
		}
	}
	return true
}

func ValidateRootCA(data []byte, now time.Time) (ValidatedCA, error) {
	return validateRootCA(data, now, rootCurrentValidity)
}

func validateRootCA(data []byte, now time.Time, validity rootValidity) (ValidatedCA, error) {
	canonical, fingerprint, err := parseRootCA(data, now, validity)
	if err != nil {
		return ValidatedCA{}, err
	}
	return ValidatedCA{PEM: canonical, Fingerprint: fingerprint}, nil
}

func parseRootCA(
	data []byte,
	now time.Time,
	validity rootValidity,
) ([]byte, string, error) {
	if len(data) == 0 || len(data) > RootCertificateLimit {
		return nil, "", fmt.Errorf(
			"root CA must contain between 1 and %d bytes", RootCertificateLimit)
	}
	trimmed := bytes.TrimSpace(data)
	begin := []byte("-----BEGIN CERTIFICATE-----")
	end := []byte("-----END CERTIFICATE-----")
	if !bytes.HasPrefix(trimmed, begin) || bytes.Count(trimmed, []byte("-----BEGIN")) != 1 ||
		bytes.Count(trimmed, []byte("-----END")) != 1 || bytes.Count(trimmed, begin) != 1 ||
		bytes.Count(trimmed, end) != 1 {
		return nil, "", errors.New("root CA must be exactly one canonical PEM certificate")
	}
	block, rest := pem.Decode(trimmed)
	if block != nil {
		defer clear(block.Bytes)
	}
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", errors.New("root CA must be exactly one canonical PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse root CA: %w", err)
	}
	if certificate.Subject.String() != rootCASubject {
		return nil, "", fmt.Errorf(
			"root CA subject is %q, want %q", certificate.Subject.String(), rootCASubject)
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, "", errors.New(
			"root certificate must be a CA with certificate-signing usage")
	}
	if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) ||
		certificate.CheckSignatureFrom(certificate) != nil {
		return nil, "", errors.New("root CA must be self-signed")
	}
	if validity != rootAnyValidity && now.Before(certificate.NotBefore) {
		return nil, "", fmt.Errorf(
			"root CA is not valid before %s", certificate.NotBefore.UTC().Format(time.RFC3339))
	}
	if validity == rootCurrentValidity && !now.Before(certificate.NotAfter) {
		return nil, "", fmt.Errorf(
			"root CA is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	digest := sha256.Sum256(certificate.Raw)
	return append([]byte(nil), trimmed...),
		strings.ToUpper(hex.EncodeToString(digest[:])), nil
}

func validateAccessFacts(facts LocalAccessFacts) error {
	if err := ValidateAccessDomain(facts.Domain); err != nil {
		return err
	}
	for _, value := range []string{facts.DNSServer, facts.PublicIngressVIP, facts.PassthroughIngressVIP} {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return fmt.Errorf("invalid local access IPv4 address %q", value)
		}
	}
	if len(facts.PassthroughHosts) == 0 ||
		len(facts.PassthroughHosts) > config.MaxPassthroughHosts {
		return fmt.Errorf("local access passthrough hosts must contain between 1 and %d labels",
			config.MaxPassthroughHosts)
	}
	seen := make(map[string]struct{}, len(facts.PassthroughHosts))
	keycloakCount := 0
	for _, label := range facts.PassthroughHosts {
		if err := validatePassthroughLabel(label, facts.Domain); err != nil {
			return err
		}
		if _, duplicate := seen[label]; duplicate {
			return fmt.Errorf("local access passthrough host %q is duplicated", label)
		}
		seen[label] = struct{}{}
		if label == "keycloak" {
			keycloakCount++
		}
	}
	if keycloakCount != 1 {
		return errors.New("local access passthrough hosts must contain \"keycloak\" exactly once")
	}
	return nil
}

func validatePassthroughLabel(label, domain string) error {
	if label == "" || len(label) > 63 || strings.ToLower(label) != label {
		return fmt.Errorf("invalid local access passthrough host %q", label)
	}
	for index, character := range label {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			(character != '-' || index == 0 || index == len(label)-1) {
			return fmt.Errorf("invalid local access passthrough host %q", label)
		}
	}
	if err := ValidateAccessDomain(label + "." + domain); err != nil {
		return fmt.Errorf("invalid local access passthrough host %q: %w", label, err)
	}
	return nil
}

func ValidateAccessDomain(domain string) error {
	if domain == "" || len(domain) > 253 || strings.ToLower(domain) != domain ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.ContainsAny(domain, "/\\ \t\r\n") {
		return fmt.Errorf("invalid local access domain %q", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid local access domain %q", domain)
		}
		for index, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				(character != '-' || index == 0 || index == len(label)-1) {
				return fmt.Errorf("invalid local access domain %q", domain)
			}
		}
	}
	return nil
}

func ValidateRootFingerprint(fingerprint string) error {
	if err := ValidateSHA256Digest(fingerprint); err != nil {
		return errors.New("root CA fingerprint must be 64 uppercase hexadecimal characters")
	}
	return nil
}

func ValidateSHA256Digest(value string) error {
	if len(value) != sha256.Size*2 {
		return errors.New("SHA-256 digest must be 64 uppercase hexadecimal characters")
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'A' || character > 'F') {
			return errors.New("SHA-256 digest must be 64 uppercase hexadecimal characters")
		}
	}
	return nil
}

func resolverContent(facts LocalAccessFacts) []byte {
	return []byte("[Resolve]\nDNS=" + facts.DNSServer + "\nDomains=~" + facts.Domain + "\n")
}

func resolvedResolvConf() (string, bool, error) {
	etcFD, err := secureHostDirectoryFD("/etc")
	if err != nil {
		return "", false, fmt.Errorf("inspect /etc/resolv.conf: %w", err)
	}
	defer unix.Close(etcFD)
	var linkInfo unix.Stat_t
	if err := unix.Fstatat(etcFD, "resolv.conf", &linkInfo, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", false, fmt.Errorf("inspect /etc/resolv.conf: %w", err)
	}
	if linkInfo.Mode&unix.S_IFMT != unix.S_IFLNK {
		return "", false, nil
	}
	if linkInfo.Uid != 0 || linkInfo.Gid != 0 {
		return "", false, errors.New("/etc/resolv.conf is not root-owned")
	}
	var targetBuffer [4096]byte
	size, err := unix.Readlinkat(etcFD, "resolv.conf", targetBuffer[:])
	if err != nil {
		return "", false, fmt.Errorf("read /etc/resolv.conf link: %w", err)
	}
	if size == len(targetBuffer) {
		return "", false, errors.New("/etc/resolv.conf link target exceeds 4095 bytes")
	}
	target := string(targetBuffer[:size])
	cleaned := filepath.Clean(target)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Clean(filepath.Join("/etc", cleaned))
	}
	managed := cleaned == "/run/systemd/resolve/stub-resolv.conf" ||
		cleaned == "/run/systemd/resolve/resolv.conf"
	if managed {
		targetFD, targetErr := unix.Open(
			cleaned, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if targetErr != nil {
			return cleaned, false, nil
		}
		defer unix.Close(targetFD)
		var targetInfo unix.Stat_t
		targetErr = unix.Fstat(targetFD, &targetInfo)
		if targetErr != nil || targetInfo.Mode&unix.S_IFMT != unix.S_IFREG {
			return cleaned, false, nil
		}
	}
	return cleaned, managed, nil
}

func (service AccessService) lookup(ctx context.Context, binary, host, address string) bool {
	var output boundedOutput
	err := service.Runner.Run(ctx, process.Command{
		Name:   binary,
		Args:   []string{"query", "--legend=no", "--type=A", host},
		Stdout: &output, Stderr: &output,
	})
	if err != nil || output.overflow {
		return false
	}
	expected, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	answers := 0
	for _, line := range bytes.Split(output.Bytes(), []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) == 0 {
			continue
		}
		answer, valid := resolverAnswer(fields, host)
		if !valid || !answer.Is4() {
			return false
		}
		answers++
		if answers > 1 || answer != expected {
			return false
		}
	}
	return answers == 1
}

func (service AccessService) passthroughLookupsExact(
	ctx context.Context,
	binary string,
	facts LocalAccessFacts,
) bool {
	hosts := append([]string(nil), facts.PassthroughHosts...)
	sort.Strings(hosts)
	exact := true
	for _, label := range hosts {
		if ctx.Err() != nil {
			return false
		}
		if !service.lookup(
			ctx, binary, label+"."+facts.Domain, facts.PassthroughIngressVIP) {
			exact = false
		}
	}
	return exact
}

func resolverAnswer(fields []string, host string) (netip.Addr, bool) {
	matchesHost := func(value string) bool {
		value = strings.TrimSuffix(value, ":")
		value = strings.TrimSuffix(value, ".")
		return value == host
	}
	if len(fields) >= 4 && matchesHost(fields[0]) &&
		fields[1] == "IN" && fields[2] == "A" {
		address, err := netip.ParseAddr(fields[3])
		return address, err == nil && resolverLinkSuffix(fields[4:])
	}
	if len(fields) >= 2 && matchesHost(fields[0]) {
		address, err := netip.ParseAddr(fields[1])
		return address, err == nil && resolverLinkSuffix(fields[2:])
	}
	return netip.Addr{}, false
}

func resolverLinkSuffix(fields []string) bool {
	return len(fields) == 0 ||
		len(fields) == 3 && fields[0] == "--" &&
			fields[1] == "link:" && fields[2] != ""
}

func (service AccessService) runQuiet(ctx context.Context, name string, arguments ...string) error {
	var output boundedOutput
	return service.Runner.Run(ctx, process.Command{
		Name: name, Args: arguments, Stdout: &output, Stderr: &output,
	})
}

func (service AccessService) requireRoot() error {
	if service.EUID != 0 {
		return errors.New("local host access mutation requires root")
	}
	return nil
}

func (service AccessService) now() time.Time {
	if service.Now != nil {
		return service.Now()
	}
	return time.Now()
}

func (service AccessService) print(format string, values ...any) error {
	if service.Output == nil {
		return nil
	}
	_, err := fmt.Fprintf(service.Output, format, values...)
	return err
}

type boundedOutput struct {
	data     [commandLimit]byte
	size     int
	overflow bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	original := len(data)
	remaining := len(output.data) - output.size
	if remaining > 0 {
		copied := copy(output.data[output.size:], data[:min(len(data), remaining)])
		output.size += copied
	}
	if original > remaining {
		output.overflow = true
	}
	return original, nil
}

func (output *boundedOutput) Bytes() []byte { return output.data[:output.size] }

func certificateFingerprint(data []byte) string {
	canonical, fingerprint, err := parseRootCA(data, time.Time{}, rootAnyValidity)
	clear(canonical)
	if err != nil {
		return ""
	}
	return fingerprint
}

func SelectTrustStore() (TrustStoreDescriptor, error) {
	family, err := classifyDistribution()
	if err != nil {
		return TrustStoreDescriptor{}, err
	}
	var anchor string
	switch family {
	case FedoraTrustStore:
		anchor = FedoraAnchorPath
	case DebianTrustStore:
		anchor = DebianAnchorPath
	default:
		return TrustStoreDescriptor{}, errors.New("unsupported CA trust store family")
	}
	if !secureAnchorDirectory(anchor) {
		return TrustStoreDescriptor{}, fmt.Errorf(
			"selected CA trust anchor directory is unavailable or unsafe: %s",
			filepath.Dir(anchor))
	}
	return TrustStoreDescriptor{Family: family, Anchor: anchor}, nil
}

func ValidateTrustStore(store TrustStoreDescriptor) error {
	selected, err := SelectTrustStore()
	if err != nil {
		return err
	}
	if selected != store {
		return errors.New("selected CA trust store identity is unavailable or changed")
	}
	return nil
}

func SelectAccessCapabilities(
	need AccessCapabilityNeed,
) (AccessCapabilities, error) {
	var selected AccessCapabilities
	if need&ObserveDNS != 0 {
		selected.Systemctl = firstExecutable(systemctlCandidates[:])
		selected.Resolvectl = firstExecutable(resolvectlCandidates[:])
	}
	return selected, nil
}

func ValidateAccessCapabilities(
	capabilities AccessCapabilities,
	need AccessCapabilityNeed,
) error {
	if need&ObserveDNS != 0 {
		if canonicalExecutable(capabilities.Systemctl) != capabilities.Systemctl {
			return errors.New("selected systemctl identity is unavailable or changed")
		}
		if canonicalExecutable(capabilities.Resolvectl) != capabilities.Resolvectl {
			return errors.New("selected resolvectl identity is unavailable or changed")
		}
	}
	return nil
}

func SelectTrustUpdater(store TrustStoreDescriptor) (TrustUpdater, error) {
	if err := ValidateTrustStore(store); err != nil {
		return TrustUpdater{}, err
	}
	selected, err := selectTrustUpdater(store)
	if err != nil {
		return TrustUpdater{}, err
	}
	return TrustUpdater{
		Binary: selected.binary, Arguments: append([]string(nil), selected.arguments...),
	}, nil
}

func ValidateTrustUpdater(store TrustStoreDescriptor, updater TrustUpdater) error {
	selected, err := SelectTrustUpdater(store)
	if err != nil {
		return err
	}
	if selected.Binary == "" {
		return errors.New("selected CA trust updater is unavailable")
	}
	if selected.Binary != updater.Binary ||
		!stringSlicesEqual(selected.Arguments, updater.Arguments) {
		return errors.New("selected CA trust updater identity is unavailable or changed")
	}
	return nil
}

func selectTrustUpdater(store TrustStoreDescriptor) (trustUpdater, error) {
	var selected trustUpdater
	for _, candidate := range trustCandidates {
		if candidate.family != store.Family || candidate.updater.anchor != store.Anchor {
			continue
		}
		updater := candidate.updater
		binary := canonicalExecutable(updater.binary)
		if binary == "" {
			continue
		}
		updater.binary = binary
		if selected.binary == "" {
			selected = updater
			continue
		}
		if selected.binary != updater.binary || selected.anchor != updater.anchor ||
			!stringSlicesEqual(selected.arguments, updater.arguments) {
			return trustUpdater{}, errors.New(
				"supported distribution has ambiguous CA trust updater identities")
		}
	}
	return selected, nil
}

func classifyDistribution() (TrustStoreFamily, error) {
	data, found, err := readSystemHostFile(osReleasePath, osReleaseLimit)
	if err != nil {
		return 0, fmt.Errorf("inspect supported distribution identity: %w", err)
	}
	if !found {
		return 0, fmt.Errorf("supported distribution identity is absent at %s", osReleasePath)
	}
	defer clear(data)
	values := make(map[string]string, 2)
	for _, rawLine := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSpace(string(rawLine))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, ok := strings.Cut(line, "=")
		if !ok || (key != "ID" && key != "ID_LIKE") {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return 0, fmt.Errorf("distribution identity contains duplicate %s", key)
		}
		value, err := parseOSReleaseValue(rawValue)
		if err != nil {
			return 0, fmt.Errorf("parse distribution identity %s: %w", key, err)
		}
		values[key] = strings.ToLower(value)
	}
	if values["ID"] == "" {
		return 0, errors.New("distribution identity has no ID")
	}
	fedora := false
	debian := false
	identities := append([]string{values["ID"]}, strings.Fields(values["ID_LIKE"])...)
	for _, identity := range identities {
		switch identity {
		case "fedora", "rhel", "centos", "rocky", "almalinux":
			fedora = true
		case "debian", "ubuntu", "linuxmint":
			debian = true
		default:
			if !validOSReleaseIdentity(identity) {
				return 0, fmt.Errorf("distribution identity %q is malformed", identity)
			}
		}
	}
	if fedora == debian {
		if fedora {
			return 0, errors.New("distribution identity contradicts Fedora/RHEL and Debian families")
		}
		return 0, fmt.Errorf("distribution %q is not a supported Fedora/RHEL or Debian family", values["ID"])
	}
	if fedora {
		return FedoraTrustStore, nil
	}
	return DebianTrustStore, nil
}

func parseOSReleaseValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty value")
	}
	if raw[0] == '"' {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", err
		}
		return value, nil
	}
	if raw[0] == '\'' {
		if len(raw) < 2 || raw[len(raw)-1] != '\'' ||
			strings.ContainsRune(raw[1:len(raw)-1], '\'') {
			return "", errors.New("invalid single-quoted value")
		}
		return raw[1 : len(raw)-1], nil
	}
	if strings.ContainsAny(raw, "\\\"'`$") {
		return "", errors.New("unsafe unquoted value")
	}
	return raw, nil
}

func validOSReleaseIdentity(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func secureAnchorDirectory(anchor string) bool {
	descriptor, err := secureHostDirectoryFD(filepath.Dir(anchor))
	if err != nil {
		return false
	}
	return unix.Close(descriptor) == nil
}

func firstExecutable(candidates []string) string {
	for _, candidate := range candidates {
		if canonical := canonicalExecutable(candidate); canonical != "" {
			return canonical
		}
	}
	return ""
}

func CanonicalHostExecutable(path string) string {
	return canonicalExecutable(path)
}

func canonicalExecutable(path string) string {
	if !filepath.IsAbs(path) {
		return ""
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(canonical) {
		return ""
	}
	canonical = filepath.Clean(canonical)
	// O_PATH obtains metadata without requiring read permission. This is
	// required for Fedora's root-owned, execute-only mode-4111 sudo binary.
	descriptor, info, found, err := openHostDescriptor(canonical, unix.O_PATH)
	if err != nil || !found {
		return ""
	}
	defer unix.Close(descriptor)
	if !secureRootExecutable(info) {
		return ""
	}
	return canonical
}

func secureRootExecutable(info unix.Stat_t) bool {
	return info.Mode&unix.S_IFMT == unix.S_IFREG && info.Mode&0o111 != 0 &&
		info.Mode&0o022 == 0 && info.Uid == 0 && info.Gid == 0
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
