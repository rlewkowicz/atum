package command

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"atum/cli/identity"
	"atum/cli/platform"
	atumsecrets "atum/cli/secrets"
	"atum/cli/tui"
)

type completionRoute struct {
	name     string
	category identity.Category
	access   identity.Access
}

func (a *app) platformCompletion(
	ctx context.Context,
	status platform.Status,
) (tui.Completion, error) {
	if a.dryRun {
		return tui.Completion{}, nil
	}
	if !status.Reconciliation.Complete() || !status.Delivery.Compliant() ||
		!status.Local.Exact() {
		return tui.Completion{}, errors.New("local access is not exact; completion withheld")
	}
	relative, required := a.project.Desired.ActiveIdentityContractPath()
	if !required {
		return tui.Completion{}, nil
	}
	contract, err := identity.Load(a.project.Root, relative)
	if err != nil {
		return tui.Completion{}, err
	}
	loader := a.secretLoader
	if loader == nil {
		loader = atumsecrets.Load
	}
	credentials, err := loader(ctx, a.project, a.sops)
	if err != nil {
		return tui.Completion{}, fmt.Errorf("load completion credentials: %w", err)
	}
	defer credentials.Clear()
	target, found := a.project.Desired.ActiveTarget()
	if !found || target.LocalAccess == nil {
		return tui.Completion{}, errors.New("local completion requires the active local-access target")
	}
	projection, err := identity.Derive(
		contract,
		credentials.Identity.Seed.Bytes(),
		a.project.Desired.Project.Cluster,
		target.LocalAccess.Domain,
	)
	if err != nil {
		return tui.Completion{}, fmt.Errorf("derive completion credentials: %w", err)
	}
	defer projection.Clear()

	routes := make(map[string]completionRoute,
		len(contract.Clients())+len(contract.AdditionalEndpoints()))
	for _, client := range contract.Clients() {
		routes[client.Host] = completionRoute{
			name:     applicationAccessName(client.Application),
			category: client.Category, access: identity.Browser,
		}
	}
	protocol := make([]tui.CompletionEndpoint, 0, len(contract.AdditionalEndpoints()))
	for _, endpoint := range contract.AdditionalEndpoints() {
		name := endpointAccessName(endpoint.ID)
		routes[endpoint.Host] = completionRoute{
			name: name, category: endpoint.Category, access: endpoint.Access,
		}
		if endpoint.Access == identity.Token {
			protocol = append(protocol, tui.CompletionEndpoint{
				Name: name, URL: "https://" + endpoint.Host,
			})
		}
	}

	grouped := map[identity.Category][]tui.CompletionEndpoint{
		identity.Identity: nil, identity.Development: nil, identity.Observability: nil,
	}
	applications := make([]tui.CompletionEndpoint, 0)
	seenBrowser := make(map[string]struct{}, len(status.Local.AccessURLs))
	for _, raw := range status.Local.AccessURLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return tui.Completion{}, fmt.Errorf("invalid exact platform access URL %q", raw)
		}
		route, known := routes[parsed.Hostname()]
		if known && route.access == identity.Browser {
			grouped[route.category] = append(grouped[route.category],
				tui.CompletionEndpoint{Name: route.name, URL: raw})
			seenBrowser[parsed.Hostname()] = struct{}{}
			continue
		}
		if !known {
			applications = append(applications,
				tui.CompletionEndpoint{Name: parsed.Hostname(), URL: raw})
		}
	}
	for host, route := range routes {
		if route.access == identity.Browser {
			if _, found := seenBrowser[host]; !found {
				return tui.Completion{}, fmt.Errorf(
					"exact platform access routes omit %s", host)
			}
		}
	}

	groups := make([]tui.CompletionGroup, 0, 3)
	for _, category := range [...]identity.Category{
		identity.Identity, identity.Development, identity.Observability,
	} {
		endpoints := grouped[category]
		if len(endpoints) != 0 {
			groups = append(groups, tui.CompletionGroup{
				Name: completionCategoryName(category), Endpoints: endpoints,
			})
		}
	}
	issuer, err := url.Parse(contract.Issuer())
	if err != nil {
		return tui.Completion{}, fmt.Errorf("parse canonical SSO issuer: %w", err)
	}
	admin := contract.Administrator()
	return tui.NewCompletion(tui.CompletionSpec{
		ResolverPath: status.Local.ResolverPath, CAPath: status.Local.CAPath,
		CAFingerprint: status.Local.CAFingerprint, PublicVIP: status.Local.PublicIngressVIP,
		PassthroughVIP: status.Local.PassthroughIngressVIP, SSOIssuer: contract.Issuer(),
		AdministratorURL: issuer.Scheme + "://" + issuer.Host + "/auth/admin/master/console/",
		Username:         admin.Username, Password: projection.AdministratorPassword(),
		BrowserGroups: groups, ProtocolEndpoints: protocol,
		UncategorizedWebApps: applications,
	})
}

func completionCategoryName(category identity.Category) string {
	switch category {
	case identity.Identity:
		return "Identity services"
	case identity.Development:
		return "Development services"
	case identity.Observability:
		return "Observability services"
	default:
		return "Applications"
	}
}

func applicationAccessName(application identity.Application) string {
	switch application {
	case identity.Headlamp:
		return "Headlamp"
	case identity.Kiali:
		return "Kiali"
	case identity.Grafana:
		return "Grafana"
	case identity.GitLab:
		return "GitLab"
	case identity.PolicyReporter:
		return "Policy Reporter"
	case identity.Harbor:
		return "Harbor"
	case identity.Vault:
		return "Vault"
	case identity.Prometheus:
		return "Prometheus"
	case identity.Alertmanager:
		return "Alertmanager"
	case identity.OpenSearch:
		return "OpenSearch Dashboards"
	default:
		return string(application)
	}
}

func endpointAccessName(id string) string {
	switch id {
	case "keycloak":
		return "Keycloak"
	case "gitlab-kas":
		return "GitLab KAS"
	case "gitlab-registry":
		return "GitLab registry"
	default:
		return id
	}
}
