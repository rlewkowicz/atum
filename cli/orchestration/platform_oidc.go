package orchestration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/identity"
	"atum/cli/infra"
	"atum/cli/progress"

	"github.com/Masterminds/semver/v3"
	"go.yaml.in/yaml/v3"
)

const (
	PlatformOIDCReceiptNamespace = "kube-system"
	PlatformOIDCReceiptName      = "atum-authentication"
	PlatformOIDCReceiptSchema    = "atum.dev/cluster-authentication/v1"
	platformOIDCVariablesPath    = ".atum/state/platform-oidc.json"
)

var exactAuthenticationObservation = semver.MustParse("1.34.0")

type authenticationConfiguration struct {
	APIVersion string             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string             `json:"kind" yaml:"kind"`
	JWT        []jwtAuthenticator `json:"jwt" yaml:"jwt"`
	Anonymous  anonymousAuth      `json:"anonymous" yaml:"anonymous"`
}

type jwtAuthenticator struct {
	Issuer        jwtIssuer     `json:"issuer" yaml:"issuer"`
	ClaimMappings claimMappings `json:"claimMappings" yaml:"claimMappings"`
}

type jwtIssuer struct {
	URL                  string   `json:"url" yaml:"url"`
	CertificateAuthority string   `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
	Audiences            []string `json:"audiences" yaml:"audiences"`
	AudienceMatchPolicy  string   `json:"audienceMatchPolicy" yaml:"audienceMatchPolicy"`
}

type claimMappings struct {
	Username prefixedClaim `json:"username" yaml:"username"`
	Groups   prefixedClaim `json:"groups" yaml:"groups"`
}

type prefixedClaim struct {
	Claim  string `json:"claim" yaml:"claim"`
	Prefix string `json:"prefix" yaml:"prefix"`
}

type anonymousAuth struct {
	Enabled    bool  `json:"enabled" yaml:"enabled"`
	Conditions []any `json:"conditions" yaml:"conditions"`
}

type kubesprayOIDCProjection struct {
	Enabled   bool               `json:"enabled"`
	JWT       []jwtAuthenticator `json:"jwt"`
	Anonymous anonymousAuth      `json:"anonymous"`
}

// PlatformOIDCSpec is an immutable projection of the canonical identity,
// selected Kubernetes API, and observed local root CA.
type PlatformOIDCSpec struct {
	apiVersion         string
	issuer             string
	audiences          []string
	config             []byte
	configDigest       string
	caFingerprint      string
	audienceDigest     string
	authenticationPath string
}

func NewPlatformOIDCSpec(
	contract *identity.Contract,
	rootCA infra.ValidatedCA,
	kubernetes string,
) (*PlatformOIDCSpec, error) {
	if contract == nil {
		return nil, errors.New("local identity contract is required")
	}
	if len(rootCA.PEM) == 0 || rootCA.Fingerprint == "" {
		return nil, errors.New("validated local root CA is required")
	}
	apiVersion, err := AuthenticationConfigAPIVersion(kubernetes)
	if err != nil {
		return nil, err
	}
	audiences, err := contractAudiences(contract)
	if err != nil {
		return nil, err
	}
	configuration := authenticationConfiguration{
		APIVersion: "apiserver.config.k8s.io/" + apiVersion,
		Kind:       "AuthenticationConfiguration",
		JWT:        contractJWT(contract, audiences, string(rootCA.PEM)),
		Anonymous:  anonymousAuth{Enabled: true, Conditions: []any{}},
	}
	serialized, err := yaml.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("serialize Kubernetes authentication configuration: %w", err)
	}
	configSum := sha256.Sum256(serialized)
	audienceSum := sha256.Sum256([]byte(strings.Join(audiences, "\x00")))
	return &PlatformOIDCSpec{
		apiVersion: apiVersion, issuer: contract.Issuer(),
		audiences: append([]string(nil), audiences...), config: serialized,
		configDigest: hex.EncodeToString(configSum[:]), caFingerprint: rootCA.Fingerprint,
		audienceDigest: hex.EncodeToString(audienceSum[:]),
		authenticationPath: "/etc/kubernetes/apiserver-authentication-config-" +
			apiVersion + ".yaml",
	}, nil
}

func contractAudiences(contract *identity.Contract) ([]string, error) {
	audiences := make([]string, 0, 2)
	for _, client := range contract.Clients() {
		if client.Audience {
			audiences = append(audiences, client.ID)
		}
	}
	sort.Strings(audiences)
	if len(audiences) != 2 || audiences[0] != "atum-headlamp" || audiences[1] != "atum-kiali" {
		return nil, errors.New("identity contract must declare the Headlamp and Kiali Kubernetes audiences")
	}
	return audiences, nil
}

func contractJWT(
	contract *identity.Contract,
	audiences []string,
	certificateAuthority string,
) []jwtAuthenticator {
	return []jwtAuthenticator{{
		Issuer: jwtIssuer{
			URL: contract.Issuer(), CertificateAuthority: certificateAuthority,
			Audiences: audiences, AudienceMatchPolicy: "MatchAny",
		},
		ClaimMappings: claimMappings{
			Username: prefixedClaim{Claim: "preferred_username", Prefix: "oidc:"},
			Groups:   prefixedClaim{Claim: contract.GroupClaim(), Prefix: "oidc:"},
		},
	}}
}

func (service Service) initialKubernetesOIDC() (*kubesprayOIDCProjection, error) {
	relative, required := service.Project.Desired.ActiveIdentityContractPath()
	if !required {
		return nil, nil
	}
	contract, err := identity.Load(service.Project.Root, relative)
	if err != nil {
		return nil, err
	}
	audiences, err := contractAudiences(contract)
	if err != nil {
		return nil, err
	}
	return &kubesprayOIDCProjection{
		Enabled: true, JWT: contractJWT(contract, audiences, ""),
		Anonymous: anonymousAuth{Enabled: true, Conditions: []any{}},
	}, nil
}

// reconcileExistingPlatformOIDC completes Kubespray's ownership handoff on an
// existing cluster. Before Flux has published a local CA there is no final
// configuration to hand back; once either lifecycle artifact exists, the
// CA-bearing ReconcilePlatformOIDC owner must complete before convergence.
func (service Service) reconcileExistingPlatformOIDC(
	ctx context.Context,
	client *clusterClient,
	kubernetes string,
) error {
	relative, required := service.Project.Desired.ActiveIdentityContractPath()
	if !required {
		return nil
	}
	_, receiptFound, err := client.ConfigMapData(
		ctx, PlatformOIDCReceiptNamespace, PlatformOIDCReceiptName)
	if err != nil {
		return fmt.Errorf("read existing Kubernetes OIDC receipt: %w", err)
	}
	raw, caFound, err := client.SecretValue(
		ctx, "cert-manager", "atum-test-root-ca", "tls.crt")
	if err != nil {
		return fmt.Errorf("read existing local root CA for Kubernetes OIDC: %w", err)
	}
	defer clear(raw)
	if !caFound {
		if receiptFound {
			return errors.New("existing Kubernetes OIDC receipt has no local root CA")
		}
		return nil
	}
	rootCA, err := infra.ValidateRootCA(raw, time.Now())
	if err != nil {
		return fmt.Errorf("validate existing local root CA for Kubernetes OIDC: %w", err)
	}
	defer rootCA.Clear()
	contract, err := identity.Load(service.Project.Root, relative)
	if err != nil {
		return err
	}
	spec, err := NewPlatformOIDCSpec(contract, rootCA, kubernetes)
	if err != nil {
		return err
	}
	defer spec.Clear()
	return service.ReconcilePlatformOIDC(ctx, spec)
}

// AuthenticationConfigAPIVersion is the single selected-version projection
// shared by runtime serialization and updater compatibility inspection.
func AuthenticationConfigAPIVersion(kubernetes string) (string, error) {
	version, err := semver.NewVersion(strings.TrimPrefix(kubernetes, "v"))
	if err != nil {
		return "", fmt.Errorf("parse selected Kubernetes version %q: %w", kubernetes, err)
	}
	if version.LessThan(exactAuthenticationObservation) {
		return "", fmt.Errorf(
			"Kubernetes %s lacks the exact last_config_info authentication reload hash observation required for final OIDC readiness",
			kubernetes)
	}
	return "v1", nil
}

func (spec *PlatformOIDCSpec) ConfigDigest() string   { return spec.configDigest }
func (spec *PlatformOIDCSpec) CAFingerprint() string  { return spec.caFingerprint }
func (spec *PlatformOIDCSpec) AudienceDigest() string { return spec.audienceDigest }
func (spec *PlatformOIDCSpec) Issuer() string         { return spec.issuer }

func (spec *PlatformOIDCSpec) Clear() {
	if spec == nil {
		return
	}
	clear(spec.config)
	spec.config = nil
}

func (service Service) ReconcilePlatformOIDC(
	ctx context.Context,
	spec *PlatformOIDCSpec,
) (resultErr error) {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	if spec == nil || len(spec.config) == 0 {
		return errors.New("immutable platform OIDC specification is required")
	}
	variables := struct {
		OIDC map[string]any `json:"atum_platform_oidc"`
	}{OIDC: map[string]any{
		"schemaVersion": PlatformOIDCReceiptSchema,
		"apiVersion":    spec.apiVersion, "issuer": spec.issuer,
		"audiences": append([]string(nil), spec.audiences...),
		"config":    string(spec.config), "configDigest": spec.configDigest,
		"caFingerprint": spec.caFingerprint, "audienceDigest": spec.audienceDigest,
		"authenticationPath": spec.authenticationPath,
	}}
	data, err := config.MarshalJSON(variables)
	if err != nil {
		return fmt.Errorf("encode platform OIDC variables: %w", err)
	}
	defer clear(data)
	if err := fssecure.WriteRegular(service.Project.Root, platformOIDCVariablesPath, data, 0o600); err != nil {
		return fmt.Errorf("write platform OIDC variables: %w", err)
	}
	defer func() {
		removeErr := fssecure.RemoveRegular(service.Project.Root, platformOIDCVariablesPath)
		if removeErr != nil {
			removeErr = fmt.Errorf("remove platform OIDC variables: %w", removeErr)
		}
		resultErr = errors.Join(resultErr, removeErr)
	}()
	variablesPath, err := fssecure.Resolve(service.Project.Root, platformOIDCVariablesPath, false)
	if err != nil {
		return err
	}
	arguments := []string{
		"--inventory", service.installInventoryPath(),
		"--extra-vars", "@" + variablesPath,
		filepath.Join(service.Project.Desired.Orchestration.Directory, "playbooks", "platform-oidc.yml"),
	}
	activity := progress.Target{Phase: progress.Platform, ID: "cluster-oidc", Label: "Cluster OIDC"}
	if err := service.RunAnsible(ctx, activity, arguments); err != nil {
		return fmt.Errorf("reconcile Kubernetes OIDC: %w", err)
	}
	return nil
}

func ValidatePlatformOIDCReceipt(
	spec *PlatformOIDCSpec,
	data map[string]string,
	expectedNodes int,
) (bool, string) {
	if spec == nil {
		return false, "expected Kubernetes OIDC specification is unavailable"
	}
	if data == nil {
		return false, "kube-system/atum-authentication receipt is absent"
	}
	if expectedNodes < 1 {
		return false, "observed control-plane node set is empty"
	}
	expectations := [...]struct {
		key, want, label string
	}{
		{"schemaVersion", PlatformOIDCReceiptSchema, "schema version"},
		{"issuer", spec.issuer, "issuer"},
		{"configDigest", spec.configDigest, "authentication configuration digest"},
		{"caFingerprint", spec.caFingerprint, "CA fingerprint"},
		{"audienceDigest", spec.audienceDigest, "audience digest"},
	}
	for _, expected := range expectations {
		if data[expected.key] != expected.want {
			return false, expected.label + " does not match the expected OIDC specification"
		}
	}
	verifiedNodes, err := strconv.Atoi(data["verifiedNodes"])
	if err != nil || verifiedNodes < 1 {
		return false, "verified node count is invalid"
	}
	if verifiedNodes != expectedNodes {
		return false, fmt.Sprintf("verified node count is %d, want %d", verifiedNodes, expectedNodes)
	}
	if len(data) != len(expectations)+1 {
		return false, "receipt contains fields outside the orchestration schema"
	}
	return true, ""
}
