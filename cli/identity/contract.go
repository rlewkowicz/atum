// Package identity owns the canonical local human-identity contract and its
// credential projection. Consumers receive immutable ordered views.
package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"

	"atum/cli/fssecure"

	"go.yaml.in/yaml/v3"
)

const SchemaVersion = "atum.dev/identity/v1"

const (
	ProfilePrepKustomizationName     = "platform-profile-prep"
	ProfileAccessKustomizationName   = "platform-profile-access"
	ProfileIdentityKustomizationName = "platform-profile-identity"
	KeycloakJobNamespace             = "keycloak"
	KeycloakJobName                  = "atum-keycloak-reconcile"
	KeycloakJobOwner                 = "keycloak"
	OpenBaoJobNamespace              = "vault"
	OpenBaoJobName                   = "atum-openbao-reconcile"
	OpenBaoJobOwner                  = "openbao"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	hostnamePattern   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type ClientType string
type Integration string
type Category string
type Access string
type Application string

const (
	PublicPKCE   ClientType = "public-pkce"
	Confidential ClientType = "confidential"

	NativeOIDC         Integration = "native-oidc"
	Authservice        Integration = "authservice"
	FluxReconciliation Integration = "flux-reconciliation"

	Headlamp       Application = "headlamp"
	Kiali          Application = "kiali"
	Grafana        Application = "grafana"
	GitLab         Application = "gitlab"
	PolicyReporter Application = "policy-reporter"
	Harbor         Application = "harbor"
	OpenBao        Application = "openbao"
	Prometheus     Application = "prometheus"
	Alertmanager   Application = "alertmanager"
	OpenSearch     Application = "opensearch"

	Identity      Category = "identity"
	Development   Category = "development"
	Observability Category = "observability"

	Browser Access = "browser"
	Token   Access = "token"
)

type Administrator struct {
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	Group      string `yaml:"group"`
	ServerRole string `yaml:"serverRole"`
}

type Client struct {
	ID                   string      `yaml:"id"`
	Application          Application `yaml:"application"`
	Type                 ClientType  `yaml:"type"`
	Host                 string      `yaml:"host"`
	Category             Category    `yaml:"category"`
	Integration          Integration `yaml:"integration"`
	SecretPurpose        string      `yaml:"secretPurpose,omitempty"`
	Callbacks            []string    `yaml:"callbacks"`
	AdministratorMapping string      `yaml:"administratorMapping"`
	Audience             bool        `yaml:"audience,omitempty"`
}

type Endpoint struct {
	ID       string   `yaml:"id"`
	Host     string   `yaml:"host"`
	Category Category `yaml:"category"`
	Access   Access   `yaml:"access"`
}

type contractFile struct {
	SchemaVersion       string        `yaml:"schemaVersion"`
	Realm               string        `yaml:"realm"`
	Issuer              string        `yaml:"issuer"`
	Scopes              []string      `yaml:"scopes"`
	GroupClaim          string        `yaml:"groupClaim"`
	Administrator       Administrator `yaml:"administrator"`
	AdditionalEndpoints []Endpoint    `yaml:"additionalEndpoints"`
	Clients             []Client      `yaml:"clients"`
}

type Contract struct {
	schemaVersion string
	realm         string
	issuer        string
	scopes        []string
	groupClaim    string
	administrator Administrator
	endpoints     []Endpoint
	clients       []Client
	byID          map[string]int
	byHost        map[string]int
	byApplication map[Application]int
	canonical     []byte
}

func Load(root, relative string) (*Contract, error) {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("identity contract %s is required: %w", relative, err)
		}
		return nil, fmt.Errorf("open identity contract %s: %w", relative, err)
	}
	defer file.Close()
	return decode(file, relative)
}

// Parse decodes a detached candidate contract. It lets the updater validate
// and render one transaction without bypassing the contract's ownership.
func Parse(data []byte, source string) (*Contract, error) {
	return decode(bytes.NewReader(data), source)
}

func decode(reader io.Reader, source string) (*Contract, error) {
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var decoded contractFile
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode identity contract %s: %w", source, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode identity contract %s: multiple YAML documents are not allowed", source)
		}
		return nil, fmt.Errorf("decode identity contract %s: %w", source, err)
	}
	canonical, err := yaml.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("encode canonical identity contract: %w", err)
	}
	contract := &Contract{
		schemaVersion: decoded.SchemaVersion,
		realm:         decoded.Realm,
		issuer:        decoded.Issuer,
		scopes:        append([]string(nil), decoded.Scopes...),
		groupClaim:    decoded.GroupClaim,
		administrator: decoded.Administrator,
		endpoints:     append([]Endpoint(nil), decoded.AdditionalEndpoints...),
		clients:       append([]Client(nil), decoded.Clients...),
		byID:          make(map[string]int, len(decoded.Clients)),
		byHost:        make(map[string]int, len(decoded.Clients)),
		byApplication: make(map[Application]int, len(decoded.Clients)),
		canonical:     canonical,
	}
	for index := range contract.clients {
		contract.clients[index].Callbacks = append([]string(nil), contract.clients[index].Callbacks...)
	}
	if err := contract.validate(); err != nil {
		return nil, fmt.Errorf("identity contract %s: %w", source, err)
	}
	return contract, nil
}

func (contract *Contract) validate() error {
	if contract.schemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	issuer, err := url.Parse(contract.issuer)
	if err != nil || contract.realm != "master" || issuer.Scheme != "https" ||
		issuer.Path != "/auth/realms/master" || issuer.RawQuery != "" || issuer.Fragment != "" ||
		issuer.User != nil || issuer.Port() != "" || len(issuer.Hostname()) <= len("keycloak.") ||
		len(issuer.Hostname()) > 253 || !hostnamePattern.MatchString(issuer.Hostname()) ||
		issuer.Hostname()[:len("keycloak.")] != "keycloak." {
		return errors.New("issuer must declare the local Keycloak master realm")
	}
	domain := issuer.Hostname()[len("keycloak."):]
	if contract.groupClaim != "groups" {
		return errors.New("groupClaim must be groups")
	}
	scopeSet := make(map[string]struct{}, len(contract.scopes))
	for _, scope := range contract.scopes {
		if !identifierPattern.MatchString(scope) {
			return fmt.Errorf("scope %q is invalid", scope)
		}
		if _, exists := scopeSet[scope]; exists {
			return fmt.Errorf("scope %q is duplicated", scope)
		}
		scopeSet[scope] = struct{}{}
	}
	for _, required := range [...]string{"openid", "profile", "email", "groups"} {
		if _, exists := scopeSet[required]; !exists {
			return fmt.Errorf("required scope %q is absent", required)
		}
	}
	admin := contract.administrator
	if admin.Username != "atum" || admin.Password != "atum" || admin.Group != "atum-admins" || admin.ServerRole != "admin" {
		return errors.New("administrator must be atum/atum in atum-admins with server role admin")
	}
	callbacks := make(map[string]struct{}, len(contract.clients))
	purposes := make(map[string]struct{}, len(contract.clients))
	applications := make(map[Application]struct{}, len(contract.clients))
	endpointIDs := make(map[string]struct{}, len(contract.endpoints))
	for index, endpoint := range contract.endpoints {
		if !identifierPattern.MatchString(endpoint.ID) {
			return fmt.Errorf("additional endpoint %d has invalid id %q", index, endpoint.ID)
		}
		if _, exists := endpointIDs[endpoint.ID]; exists {
			return fmt.Errorf("additional endpoint id %q is duplicated", endpoint.ID)
		}
		if _, exists := contract.byHost[endpoint.Host]; exists {
			return fmt.Errorf("endpoint host %q is duplicated", endpoint.Host)
		}
		if len(endpoint.Host) > 253 || !hostnamePattern.MatchString(endpoint.Host) {
			return fmt.Errorf("endpoint %s has invalid host %q", endpoint.ID, endpoint.Host)
		}
		if len(endpoint.Host) <= len(domain)+1 || endpoint.Host[len(endpoint.Host)-len(domain)-1:] != "."+domain {
			return fmt.Errorf("endpoint %s host %q is outside issuer domain %q", endpoint.ID, endpoint.Host, domain)
		}
		switch endpoint.Category {
		case Identity, Development, Observability:
		default:
			return fmt.Errorf("endpoint %s has unknown category %q", endpoint.ID, endpoint.Category)
		}
		if endpoint.Access != Browser && endpoint.Access != Token {
			return fmt.Errorf("endpoint %s has unknown access %q", endpoint.ID, endpoint.Access)
		}
		endpointIDs[endpoint.ID] = struct{}{}
		contract.byHost[endpoint.Host] = -index - 1
	}
	for index, client := range contract.clients {
		if !identifierPattern.MatchString(client.ID) {
			return fmt.Errorf("client %d has invalid id %q", index, client.ID)
		}
		if _, exists := contract.byID[client.ID]; exists {
			return fmt.Errorf("client id %q is duplicated", client.ID)
		}
		switch client.Application {
		case Headlamp, Kiali, Grafana, GitLab, PolicyReporter, Harbor, OpenBao,
			Prometheus, Alertmanager, OpenSearch:
		default:
			return fmt.Errorf("client %s has unsupported application %q", client.ID, client.Application)
		}
		if _, exists := applications[client.Application]; exists {
			return fmt.Errorf("application projection %q is duplicated", client.Application)
		}
		applications[client.Application] = struct{}{}
		if _, exists := contract.byHost[client.Host]; exists {
			return fmt.Errorf("client host %q is duplicated", client.Host)
		}
		if len(client.Host) > 253 || !hostnamePattern.MatchString(client.Host) {
			return fmt.Errorf("client %s has invalid host %q", client.ID, client.Host)
		}
		if len(client.Host) <= len(domain)+1 || client.Host[len(client.Host)-len(domain)-1:] != "."+domain {
			return fmt.Errorf("client %s host %q is outside issuer domain %q", client.ID, client.Host, domain)
		}
		contract.byID[client.ID], contract.byHost[client.Host] = index, index
		contract.byApplication[client.Application] = index
		if client.Type != PublicPKCE && client.Type != Confidential {
			return fmt.Errorf("client %s has unknown type %q", client.ID, client.Type)
		}
		switch client.Integration {
		case NativeOIDC, Authservice, FluxReconciliation:
		default:
			return fmt.Errorf("client %s has unknown integration %q", client.ID, client.Integration)
		}
		expectedType, expectedIntegration, expectedAudience, expectedMapping :=
			applicationContract(client.Application, admin.Group)
		if client.Type != expectedType || client.Integration != expectedIntegration ||
			client.Audience != expectedAudience ||
			client.AdministratorMapping != expectedMapping {
			return fmt.Errorf(
				"client %s does not match the %s application projection contract",
				client.ID, client.Application)
		}
		switch client.Category {
		case Identity, Development, Observability:
		default:
			return fmt.Errorf("client %s has unknown category %q", client.ID, client.Category)
		}
		if client.Type == PublicPKCE {
			if client.SecretPurpose != "" {
				return fmt.Errorf("public client %s must not declare secretPurpose", client.ID)
			}
		} else if !identifierPattern.MatchString(client.SecretPurpose) {
			return fmt.Errorf("confidential client %s must declare a valid secretPurpose", client.ID)
		} else if _, exists := purposes[client.SecretPurpose]; exists {
			return fmt.Errorf("secret purpose %q is duplicated", client.SecretPurpose)
		} else {
			purposes[client.SecretPurpose] = struct{}{}
		}
		if len(client.Callbacks) == 0 || client.AdministratorMapping == "" {
			return fmt.Errorf("client %s must declare callbacks and administratorMapping", client.ID)
		}
		for _, callback := range client.Callbacks {
			parsed, err := url.Parse(callback)
			if err != nil || parsed.Scheme != "https" || parsed.Hostname() != client.Host || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				return fmt.Errorf("client %s callback %q must be public HTTPS on its declared host", client.ID, callback)
			}
			if _, exists := callbacks[callback]; exists {
				return fmt.Errorf("callback %q is duplicated", callback)
			}
			callbacks[callback] = struct{}{}
		}
	}
	for _, required := range [...]Application{
		Headlamp, Kiali, Grafana, GitLab, PolicyReporter, Harbor, OpenBao,
		Prometheus, Alertmanager, OpenSearch,
	} {
		if _, exists := applications[required]; !exists {
			return fmt.Errorf("required application projection %q is absent", required)
		}
	}
	return nil
}

func applicationContract(application Application, administratorGroup string) (
	ClientType,
	Integration,
	bool,
	string,
) {
	switch application {
	case Headlamp:
		return PublicPKCE, NativeOIDC, true,
			"oidc:" + administratorGroup + "=cluster-admin"
	case Kiali:
		return Confidential, NativeOIDC, true, "authenticated-cluster-admin"
	case Grafana:
		return Confidential, NativeOIDC, false, "Admin"
	case GitLab:
		return Confidential, NativeOIDC, false, "adminGroups"
	case PolicyReporter:
		return Confidential, NativeOIDC, false, "authenticated-ui-admin"
	case Harbor:
		return Confidential, NativeOIDC, false, "oidc-admin-group"
	case OpenBao:
		return Confidential, FluxReconciliation, false, "administrator-policy"
	case Prometheus, Alertmanager, OpenSearch:
		return Confidential, Authservice, false, "authenticated"
	default:
		return "", "", false, ""
	}
}

func (contract *Contract) SchemaVersion() string        { return contract.schemaVersion }
func (contract *Contract) Realm() string                { return contract.realm }
func (contract *Contract) Issuer() string               { return contract.issuer }
func (contract *Contract) Scopes() []string             { return append([]string(nil), contract.scopes...) }
func (contract *Contract) GroupClaim() string           { return contract.groupClaim }
func (contract *Contract) Administrator() Administrator { return contract.administrator }
func (contract *Contract) AdditionalEndpoints() []Endpoint {
	return append([]Endpoint(nil), contract.endpoints...)
}
func (contract *Contract) Clients() []Client {
	result := make([]Client, len(contract.clients))
	copy(result, contract.clients)
	for index := range result {
		result[index].Callbacks = append([]string(nil), result[index].Callbacks...)
	}
	return result
}
func (contract *Contract) Client(id string) (Client, bool) {
	index, exists := contract.byID[id]
	if !exists {
		return Client{}, false
	}
	client := contract.clients[index]
	client.Callbacks = append([]string(nil), client.Callbacks...)
	return client, true
}
func (contract *Contract) ClientForApplication(application Application) (Client, bool) {
	index, exists := contract.byApplication[application]
	if !exists {
		return Client{}, false
	}
	client := contract.clients[index]
	client.Callbacks = append([]string(nil), client.Callbacks...)
	return client, true
}
func (contract *Contract) Canonical() []byte { return append([]byte(nil), contract.canonical...) }
func (contract *Contract) Domain() string {
	issuer, err := url.Parse(contract.issuer)
	if err != nil {
		return ""
	}
	return issuer.Hostname()[len("keycloak."):]
}
