package tui

import (
	"strings"
	"unicode"

	"atum/cli/config"
	"atum/cli/progress"
)

type Scope uint8

const (
	ScopeInfrastructure Scope = 1 << iota
	ScopeOrchestration
	ScopePlatform
	ScopeAll = ScopeInfrastructure | ScopeOrchestration | ScopePlatform
)

type itemSpec struct {
	id    string
	label string
}

type phaseSpec struct {
	id    progress.Phase
	label string
	items []itemSpec
}

var displayNames = map[string]string{
	"authservice": "Authservice", "cert-manager": "cert-manager",
	"buildx": "Docker Buildx", "docker": "Docker Engine",
	"fluent-bit": "Fluent Bit", "forgejo": "Forgejo", "gitlab": "GitLab",
	"grafana": "Grafana", "harbor": "Big Bang Harbor", "headlamp": "Headlamp", "istio-crds": "Istio CRDs",
	"istio-gateway": "Istio gateways", "istiod": "Istiod", "keycloak": "Keycloak",
	"kiali": "Kiali", "kube-vip": "kube-vip", "kube-vip-cloud-provider": "kube-vip cloud provider",
	"kyverno": "Kyverno", "kyverno-policies": "Kyverno policies",
	"kyverno-reporter": "Kyverno reporter", "local-path-provisioner": "Local-path storage",
	"local-certificates": "Local certificates", "local-dns": "Local DNS",
	"monitoring": "Monitoring", "openbao": "OpenBao", "openssh": "OpenSSH client", "opensearch": "OpenSearch",
	"opensearch-dashboards": "OpenSearch Dashboards", "opensearch-operator": "OpenSearch operator",
	"platform-profile-access": "Platform profile access", "platform-profile-prep": "Platform profile prerequisites",
	"prometheus-operator-crds": "Prometheus operator CRDs", "python": "Python",
	"systemd-resolved": "systemd-resolved", "terraform-cli": "Terraform CLI",
	"tempo": "Tempo", "vault": "OpenBao", "velero": "Velero", "virsh": "virsh",
}

func projectPhases(project *config.Project, scope Scope) []phaseSpec {
	phases := make([]phaseSpec, 0, 5)
	phases = append(phases, phaseSpec{id: progress.Preflight, label: "Preflight"})
	phases = append(phases, phaseSpec{
		id: progress.Credentials, label: "Credentials",
		items: []itemSpec{{id: "secrets", label: "Platform secrets"}},
	})
	if scope&ScopeInfrastructure != 0 {
		items := []itemSpec{{id: "terraform", label: "Terraform state"}}
		target, _ := project.Desired.ActiveTarget()
		if target.LocalAccess != nil {
			items = append(items,
				itemSpec{id: "network", label: "Network"},
				itemSpec{id: "load-balancer", label: "Load balancer"},
				itemSpec{id: "bastion", label: "Bastion"},
				itemSpec{id: "seed-forgejo", label: "Forgejo"},
				itemSpec{id: "seed-harbor", label: "Seed Harbor"},
				itemSpec{id: "nodes", label: "Nodes"},
				itemSpec{id: "storage", label: "Storage"},
			)
		}
		phases = append(phases, phaseSpec{
			id: progress.Infrastructure, label: "Infrastructure",
			items: items,
		})
	}
	if scope&ScopeOrchestration != 0 {
		phases = append(phases, phaseSpec{id: progress.Orchestration, label: "Orchestration"})
	}
	if scope&ScopePlatform != 0 {
		items := []itemSpec{
			{id: "bundle", label: "Deployment bundle"},
			{id: "bundle-materialization", label: "Bundle materialization"},
			{id: "compatibility-builds", label: "Compatibility builds"},
			{id: "harbor-seed", label: "Seed Harbor publication"},
			{id: "forgejo", label: "Forgejo sources"},
			{id: "flux", label: "Flux"},
			{id: "prep", label: "Platform prerequisites"},
			{id: "platform-profile-prep", label: "Platform profile prerequisites"},
			{id: "sources", label: "Internal sources"},
			{id: "images", label: "Runtime images"},
			{id: "bigbang", label: "Big Bang"},
			{id: "platform-profile-access", label: "Platform profile access"},
		}
		seen := map[string]struct{}{
			"bundle": {}, "bundle-materialization": {}, "compatibility-builds": {}, "harbor-seed": {}, "forgejo": {}, "flux": {}, "prep": {},
			"sources": {}, "images": {}, "bigbang": {}, "platform-profile-prep": {}, "platform-profile-access": {},
		}
		appendItem := func(id string) {
			if id == "" {
				return
			}
			if _, found := seen[id]; found {
				return
			}
			seen[id] = struct{}{}
			items = append(items, itemSpec{id: id, label: displayName(id)})
		}
		for _, chart := range project.Desired.ActiveBootstrapCharts() {
			appendItem(chart.ID)
		}
		target, _ := project.Desired.ActiveTarget()
		if target.LocalAccess != nil {
			appendItem("local-dns")
			appendItem("local-certificates")
		}
		for _, pkg := range project.Desired.Platform.Packages {
			appendItem(pkg.ID)
		}
		for _, chart := range project.Desired.Platform.Charts {
			appendItem(chart.ID)
		}
		phases = append(phases, phaseSpec{id: progress.Platform, label: "Platform", items: items})
	}
	return phases
}

func displayName(id string) string {
	if label, found := displayNames[id]; found {
		return label
	}
	words := strings.FieldsFunc(id, func(character rune) bool {
		return character == '-' || character == '_' || character == '.'
	})
	for index, word := range words {
		runes := []rune(word)
		if len(runes) != 0 {
			runes[0] = unicode.ToUpper(runes[0])
			words[index] = string(runes)
		}
	}
	return strings.Join(words, " ")
}
