package orchestration

import (
	"errors"
	"sort"

	"atum/cli/identity"
	"atum/cli/kube"
)

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
	Enabled    bool                      `json:"enabled"`
	Conditions [4]anonymousAuthCondition `json:"conditions"`
}

type anonymousAuthCondition struct {
	Path string `json:"path"`
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
	anonymousPaths := kube.ScopedAnonymousPaths()
	return &kubesprayOIDCProjection{
		Enabled: true,
		JWT: contractJWT(
			contract,
			audiences,
			string(service.RootCAPEM),
		),
		Anonymous: anonymousAuth{
			Enabled: true,
			Conditions: [4]anonymousAuthCondition{
				{Path: anonymousPaths[0]},
				{Path: anonymousPaths[1]},
				{Path: anonymousPaths[2]},
				{Path: anonymousPaths[3]},
			},
		},
	}, nil
}
