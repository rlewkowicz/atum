package orchestration

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"atum/cli/identity"

	"github.com/Masterminds/semver/v3"
)

var exactAuthenticationConfiguration = semver.MustParse("1.34.0")

type jwtAuthenticator struct {
	Issuer        jwtIssuer     `json:"issuer"`
	ClaimMappings claimMappings `json:"claimMappings"`
}

type jwtIssuer struct {
	URL                  string   `json:"url"`
	CertificateAuthority string   `json:"certificateAuthority"`
	Audiences            []string `json:"audiences"`
	AudienceMatchPolicy  string   `json:"audienceMatchPolicy"`
}

type claimMappings struct {
	Username prefixedClaim `json:"username"`
	Groups   prefixedClaim `json:"groups"`
}

type prefixedClaim struct {
	Claim  string `json:"claim"`
	Prefix string `json:"prefix"`
}

type anonymousAuth struct {
	Enabled    bool  `json:"enabled"`
	Conditions []any `json:"conditions"`
}

type kubesprayOIDCProjection struct {
	Enabled   bool               `json:"enabled"`
	JWT       []jwtAuthenticator `json:"jwt"`
	Anonymous anonymousAuth      `json:"anonymous"`
}

func contractAudiences(contract *identity.Contract) ([]string, error) {
	audiences := make([]string, 0, 2)
	for _, client := range contract.Clients() {
		if client.Audience {
			audiences = append(audiences, client.ID)
		}
	}
	sort.Strings(audiences)
	if len(audiences) != 2 ||
		audiences[0] != "atum-headlamp" ||
		audiences[1] != "atum-kiali" {
		return nil, errors.New(
			"identity contract must declare the Headlamp and Kiali Kubernetes audiences",
		)
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
	if len(service.RootCAPEM) == 0 {
		return nil, errors.New(
			"validated root CA certificate is required before initial Kubernetes OIDC configuration",
		)
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
		Enabled: true,
		JWT: contractJWT(
			contract,
			audiences,
			string(service.RootCAPEM),
		),
		Anonymous: anonymousAuth{Enabled: true, Conditions: []any{}},
	}, nil
}

// AuthenticationConfigAPIVersion is the selected-version projection shared
// by Kubespray serialization and updater compatibility inspection.
func AuthenticationConfigAPIVersion(kubernetes string) (string, error) {
	version, err := semver.NewVersion(strings.TrimPrefix(kubernetes, "v"))
	if err != nil {
		return "", fmt.Errorf(
			"parse selected Kubernetes version %q: %w",
			kubernetes,
			err,
		)
	}
	if version.LessThan(exactAuthenticationConfiguration) {
		return "", fmt.Errorf(
			"Kubernetes %s lacks the required v1 AuthenticationConfiguration API",
			kubernetes,
		)
	}
	return "v1", nil
}
