// Package preflight owns prerequisite selection and immutable external-tool
// identities for Atum-managed workflows.
package preflight

import (
	"context"
	"time"
)

type Scope uint8

const (
	invalidScope Scope = iota
	Infrastructure
	OrchestrationPrepare
	OrchestrationInventory
	OrchestrationConverge
	OrchestrationAnsible
	Delivery
	LibvirtPermissionsInstall
	LibvirtPermissionsFile
	LibvirtForwarding
	TerraformDirect
	FluxDirect
	VeleroDirect
	CommittedSecrets
	ArtifactPublication
	Platform
	Full
	AccessDNS
	AccessCA
	AccessUninstall
)

type Tool string

const (
	Terraform  Tool = "terraform-cli"
	Docker     Tool = "docker"
	Buildx     Tool = "buildx"
	Python     Tool = "python"
	OpenSSH    Tool = "openssh"
	Flux       Tool = "flux"
	SOPS       Tool = "sops"
	Velero     Tool = "velero"
	Virsh      Tool = "virsh"
	Firewall   Tool = "firewall-cmd"
	Restorecon Tool = "restorecon"
	Getfacl    Tool = "getfacl"
	Setfacl    Tool = "setfacl"
	KVM        Tool = "kvm"
	Resolver   Tool = "systemd-resolved"
	ServiceMgr Tool = "systemctl"
	Sudo       Tool = "sudo"
	Trust      Tool = "trust-store"
)

type probe func(context.Context, *capture) Result

// Specification is immutable after selection. Results are stored separately
// in fixed declaration-order slots so concurrent completion cannot affect
// diagnostics or presentation order.
type Specification struct {
	Tool       Tool
	Label      string
	InstallURL string
	Override   string
	Required   string
	Timeout    time.Duration
	probe      probe
}

type Result struct {
	Tool     Tool
	Label    string
	Binary   string
	Version  string
	Identity string
	Health   string
	Problem  string
}

func (result Result) OK() bool {
	return result.Problem == ""
}

type Report struct {
	results []Result
}

func (report Report) Results() []Result {
	return append([]Result(nil), report.results...)
}

func (report Report) Result(tool Tool) (Result, bool) {
	for index := range report.results {
		if report.results[index].Tool == tool {
			return report.results[index], true
		}
	}
	return Result{}, false
}

func (report Report) Binary(tool Tool) string {
	result, _ := report.Result(tool)
	return result.Binary
}

func (report Report) Identity(tool Tool) string {
	result, _ := report.Result(tool)
	return result.Identity
}
