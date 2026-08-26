package preflight

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/infra"
	"atum/cli/process"
	"atum/cli/progress"

	"github.com/Masterminds/semver/v3"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const (
	outputLimit    = 4 << 10
	defaultTimeout = 10 * time.Second
	sopsSupported  = ">= 3.9.0, < 4.0.0"
)

const (
	terraformInstall  = "https://developer.hashicorp.com/terraform/install"
	fluxInstall       = "https://fluxcd.io/flux/installation/"
	sopsInstall       = "https://github.com/getsops/sops/releases"
	veleroInstall     = "https://velero.io/docs/main/basic-install/"
	dockerInstall     = "https://docs.docker.com/engine/install/"
	buildxInstall     = "https://docs.docker.com/build/install-buildx/"
	pythonInstall     = "https://www.python.org/downloads/"
	sshInstall        = "https://www.openssh.com/portable.html"
	libvirtInstall    = "https://libvirt.org/downloads.html"
	firewalldInstall  = "https://firewalld.org/documentation/installation.html"
	restoreconInstall = "https://github.com/SELinuxProject/selinux"
	aclInstall        = "https://savannah.nongnu.org/projects/acl/"
	resolverInstall   = "https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html"
	sudoInstall       = "https://www.sudo.ws/getting-started/"
	fedoraTrust       = "https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/"
	debianTrust       = "https://manpages.debian.org/update-ca-certificates"
)

type Environment func(string) string

type Service struct {
	Project            *config.Project
	Runner             process.Runner
	Environment        Environment
	Parallelism        int
	ForwardingPlan     infra.ForwardingPlan
	AccessCapabilities infra.AccessCapabilities
	AccessTrustStore   infra.TrustStoreDescriptor
	AccessTrustUpdater infra.TrustUpdater
	AccessSudo         string
}

type Error struct {
	failures []failure
}

type failure struct {
	spec   Specification
	result Result
}

func (err *Error) Error() string {
	if err == nil || len(err.failures) == 0 {
		return ""
	}
	var message strings.Builder
	message.WriteString("preflight failed")
	for _, item := range err.failures {
		message.WriteString("\n- ")
		message.WriteString(itemLine(item))
	}
	return message.String()
}

type capture struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func newCapture() *capture {
	return &capture{data: make([]byte, 0, 128)}
}

func (capture *capture) Write(data []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	remaining := outputLimit - len(capture.data)
	if remaining > 0 {
		capture.data = append(capture.data, data[:min(len(data), remaining)]...)
	}
	if len(data) > remaining {
		capture.truncated = true
	}
	return len(data), nil
}

func (capture *capture) reset() {
	capture.mu.Lock()
	capture.data = capture.data[:0]
	capture.truncated = false
	capture.mu.Unlock()
}

func (capture *capture) text() (string, bool) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return sanitize(string(capture.data)), capture.truncated
}

func (service Service) Check(ctx context.Context, scope Scope) (Report, error) {
	if service.Project == nil {
		return Report{}, errors.New("Atum project is not loaded")
	}
	if service.Runner == nil {
		return Report{}, errors.New("preflight command runner is unavailable")
	}
	specifications, err := service.specifications(scope)
	if err != nil {
		return Report{}, err
	}
	results := make([]Result, len(specifications))
	group, groupContext := errgroup.WithContext(ctx)
	parallelism := service.Parallelism
	if parallelism <= 0 {
		parallelism = service.Project.Desired.Updates.Parallelism
	}
	group.SetLimit(min(config.EffectiveWorkLimit(
		parallelism,
		service.Project.Desired.Updates.Parallelism,
		config.DefaultWorkLimit,
	), max(1, len(specifications))))
	for index := range specifications {
		index := index
		group.Go(func() error {
			specification := specifications[index]
			probeContext, cancel := context.WithTimeout(groupContext, specification.Timeout)
			defer cancel()
			result := specification.probe(probeContext, newCapture())
			result.Tool = specification.Tool
			result.Label = specification.Label
			if result.Problem == "" {
				if err := probeContext.Err(); err != nil {
					result.Problem = contextProblem(err)
				}
			}
			results[index] = result
			return nil
		})
	}
	_ = group.Wait()
	report := Report{results: results}
	failures := make([]failure, 0, len(results))
	for index, result := range results {
		detail := resultDetail(result)
		if result.OK() {
			progress.Done(ctx, progress.Preflight, string(result.Tool), result.Label, detail)
			continue
		}
		item := failure{spec: specifications[index], result: result}
		failures = append(failures, item)
		progress.Fail(ctx, progress.Preflight, string(result.Tool), result.Label,
			errors.New(itemLine(item)))
	}
	if len(failures) != 0 {
		progress.Finish(ctx, progress.Preflight, progress.Failed, "requirements unavailable")
		return report, &Error{failures: failures}
	}
	progress.Finish(ctx, progress.Preflight, progress.Complete, "all requirements satisfied")
	return report, nil
}

func itemLine(item failure) string {
	var message strings.Builder
	message.Grow(len(item.result.Problem) + len(item.spec.InstallURL) + 64)
	message.WriteString(string(item.spec.Tool))
	message.WriteString(": ")
	message.WriteString(item.result.Problem)
	if item.spec.Required != "" && !strings.Contains(item.result.Problem, item.spec.Required) {
		message.WriteString("; require ")
		message.WriteString(item.spec.Required)
	}
	if item.spec.Override != "" {
		message.WriteString("; override ")
		message.WriteString(item.spec.Override)
	}
	message.WriteString("; install: ")
	message.WriteString(item.spec.InstallURL)
	return message.String()
}

func resultDetail(result Result) string {
	parts := make([]string, 0, 3)
	if result.Binary != "" {
		parts = append(parts, result.Binary)
	}
	if result.Version != "" {
		parts = append(parts, result.Version)
	}
	if result.Health != "" {
		parts = append(parts, result.Health)
	}
	return strings.Join(parts, " — ")
}

func (service Service) specifications(scope Scope) ([]Specification, error) {
	requirements, err := requirementsFor(scope)
	if err != nil {
		return nil, err
	}
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists && (requirements.terraform || requirements.localTarget) {
		return nil, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	needLocal := requirements.localTarget && target.LocalAccess != nil
	needForwardingVirsh := false
	if requirements.forwarding {
		if !service.ForwardingPlan.Valid() {
			return nil, errors.New("valid libvirt forwarding plan is required")
		}
		needForwardingVirsh = service.ForwardingPlan.RequiresVirsh()
	} else if service.ForwardingPlan.Valid() {
		return nil, errors.New("libvirt forwarding plan is not valid for selected preflight scope")
	}

	specifications := make([]Specification, 0, 11)
	if requirements.terraform {
		constraint, err := terraformConstraint(service.Project.Root, target.Directory)
		if err != nil {
			problem := "inspect active required_version: " + sanitize(err.Error())
			specifications = append(specifications, Specification{
				Tool: Terraform, Label: "Terraform", InstallURL: terraformInstall,
				Override: "ATUM_TERRAFORM_BIN", Required: "active target required_version",
				Timeout: defaultTimeout,
				probe: func(context.Context, *capture) Result {
					return Result{Problem: problem}
				},
			})
		} else {
			specifications = append(specifications, service.commandSpec(
				Terraform, "Terraform", "ATUM_TERRAFORM_BIN", "terraform",
				"required_version "+constraint, terraformInstall,
				[]string{"version", "-json"},
				func(output string) (string, string, error) {
					version, err := checkTerraformVersion(output, constraint)
					return version, version, err
				},
			))
		}
	}
	if requirements.docker {
		docker := service.binary("ATUM_DOCKER_BIN", "docker")
		specifications = append(specifications,
			service.commandSpecWithBinary(
				Docker, "Docker Engine", "ATUM_DOCKER_BIN", docker,
				"reachable Docker client and daemon", dockerInstall,
				[]string{"version", "--format", "client={{.Client.Version}} server={{.Server.Version}}"},
				dockerVersionParser,
			),
			service.commandSpecWithBinary(
				Buildx, "Docker Buildx", "ATUM_DOCKER_BIN", docker,
				"Docker Buildx plugin", buildxInstall,
				[]string{"buildx", "version"},
				identityParser,
			),
		)
	}
	if requirements.python {
		specifications = append(specifications, service.pythonSpec())
	}
	if requirements.ssh {
		specifications = append(specifications, service.commandSpec(
			OpenSSH, "OpenSSH client", "ATUM_SSH_BIN", "ssh",
			"OpenSSH client", sshInstall, []string{"-V"}, identityParser,
		))
	}
	if requirements.flux {
		targetVersion := service.Project.Desired.Platform.Flux.Version
		specifications = append(specifications, service.commandSpec(
			Flux, "Flux CLI", "ATUM_FLUX_BIN", "flux",
			"stable Flux "+fluxLine(targetVersion), fluxInstall, []string{"--version"},
			func(output string) (string, string, error) {
				version, err := checkFluxVersion(output, targetVersion)
				return version, version, err
			},
		))
	}
	if requirements.sops {
		specifications = append(specifications, service.commandSpec(
			SOPS, "SOPS", "ATUM_SOPS_BIN", "sops",
			"official SOPS "+sopsSupported, sopsInstall, []string{"--version"},
			func(output string) (string, string, error) {
				version, err := checkSOPSVersion(output)
				return version, "sops " + version, err
			},
		))
	}
	if requirements.velero {
		specifications = append(specifications, service.commandSpec(
			Velero, "Velero CLI", "ATUM_VELERO_BIN", "velero",
			"usable Velero client", veleroInstall, []string{"version", "--client-only"},
			veleroVersionParser,
		))
	}
	if needLocal {
		uri := strings.TrimSpace(service.environment("TF_VAR_libvirt_uri"))
		if uri == "" {
			uri = "qemu:///system?socket=/run/libvirt/virtqemud-sock"
		}
		specifications = append(specifications, service.virshSpec(uri), kvmSpec())
	}
	if requirements.restorecon {
		if restorecon, selected := service.restoreconSpec(); selected {
			specifications = append(specifications, restorecon)
		}
	}
	if requirements.acl {
		specifications = append(specifications,
			service.commandSpec(
				Getfacl, "POSIX ACL reader", "ATUM_GETFACL_BIN", "getfacl",
				"usable getfacl", aclInstall, []string{"--version"}, identityParser,
			),
			service.commandSpec(
				Setfacl, "POSIX ACL writer", "ATUM_SETFACL_BIN", "setfacl",
				"usable setfacl", aclInstall, []string{"--version"}, identityParser,
			),
		)
	}
	if requirements.firewall {
		specifications = append(specifications, service.firewallSpec())
	}
	if needForwardingVirsh {
		specifications = append(specifications, service.virshSpec("qemu:///system"))
	}
	if requirements.resolver {
		specifications = append(specifications, accessCapabilitySpec(
			Resolver, "systemd-resolved client", service.AccessCapabilities.Resolvectl,
			"resolvectl", resolverInstall,
		))
	}
	if requirements.serviceManager {
		specifications = append(specifications, accessCapabilitySpec(
			ServiceMgr, "systemd service manager", service.AccessCapabilities.Systemctl,
			"systemctl", resolverInstall,
		))
	}
	if requirements.sudo {
		specifications = append(specifications, accessCapabilitySpec(
			Sudo, "sudo authorization", service.AccessSudo,
			"sudo", sudoInstall,
		))
	}
	if requirements.trust {
		installURL := fedoraTrust
		if service.AccessTrustStore.Family == infra.DebianTrustStore {
			installURL = debianTrust
		}
		specifications = append(specifications, accessCapabilitySpec(
			Trust, "CA trust store", service.AccessTrustUpdater.Binary,
			"system CA trust updater", installURL,
		))
	}
	return specifications, nil
}

type requirementSet struct {
	terraform      bool
	docker         bool
	python         bool
	ssh            bool
	flux           bool
	sops           bool
	velero         bool
	localTarget    bool
	restorecon     bool
	acl            bool
	firewall       bool
	forwarding     bool
	resolver       bool
	serviceManager bool
	sudo           bool
	trust          bool
}

func requirementsFor(scope Scope) (requirementSet, error) {
	switch scope {
	case Infrastructure:
		return requirementSet{terraform: true, localTarget: true}, nil
	case OrchestrationPrepare:
		return requirementSet{python: true}, nil
	case OrchestrationInventory:
		return requirementSet{terraform: true}, nil
	case OrchestrationConverge:
		return requirementSet{terraform: true, python: true, ssh: true}, nil
	case OrchestrationAnsible:
		return requirementSet{python: true, ssh: true}, nil
	case Delivery:
		return requirementSet{docker: true}, nil
	case LibvirtPermissionsInstall:
		return requirementSet{restorecon: true, acl: true}, nil
	case LibvirtPermissionsFile:
		return requirementSet{acl: true}, nil
	case LibvirtForwarding:
		return requirementSet{firewall: true, forwarding: true}, nil
	case TerraformDirect:
		return requirementSet{terraform: true}, nil
	case FluxDirect:
		return requirementSet{flux: true}, nil
	case VeleroDirect:
		return requirementSet{velero: true}, nil
	case CommittedSecrets:
		return requirementSet{sops: true}, nil
	case ArtifactPublication:
		return requirementSet{docker: true, python: true, ssh: true, sops: true}, nil
	case Platform:
		return requirementSet{docker: true, python: true, ssh: true, flux: true, sops: true}, nil
	case Full:
		return requirementSet{
			terraform: true, docker: true, python: true, ssh: true, flux: true,
			sops: true, localTarget: true,
		}, nil
	case AccessDNS:
		return requirementSet{resolver: true, serviceManager: true, sudo: true}, nil
	case AccessCA:
		return requirementSet{sudo: true, trust: true}, nil
	case AccessUninstall:
		return requirementSet{
			resolver: true, serviceManager: true, sudo: true, trust: true,
		}, nil
	default:
		return requirementSet{}, fmt.Errorf("unsupported preflight scope %d", scope)
	}
}

func accessCapabilitySpec(
	tool Tool,
	label, binary, required, install string,
) Specification {
	return Specification{
		Tool: tool, Label: label, InstallURL: install,
		Required: required, Timeout: defaultTimeout,
		probe: func(context.Context, *capture) Result {
			if binary == "" {
				return Result{Problem: "binary not found"}
			}
			return Result{Binary: binary, Version: filepath.Base(binary), Identity: binary, Health: "available"}
		},
	}
}

type outputParser func(string) (version, identity string, err error)

func (service Service) commandSpec(
	tool Tool,
	label, override, fallback, required, install string,
	arguments []string,
	parser outputParser,
) Specification {
	return service.commandSpecWithBinary(tool, label, override,
		service.binary(override, fallback), required, install, arguments, parser)
}

func (service Service) commandSpecWithBinary(
	tool Tool,
	label, override, binary, required, install string,
	arguments []string,
	parser outputParser,
) Specification {
	return Specification{
		Tool: tool, Label: label, InstallURL: install, Override: override,
		Required: required, Timeout: defaultTimeout,
		probe: func(ctx context.Context, output *capture) Result {
			if binary == "" {
				return Result{Problem: "binary not found"}
			}
			err := service.Runner.Run(ctx, process.Command{
				Name: binary, Args: arguments, Dir: service.Project.Root,
				Stdout: output, Stderr: output,
			})
			text, truncated := output.text()
			if err != nil {
				return Result{Binary: binary, Problem: commandProblem(ctx, err, text)}
			}
			if truncated {
				return Result{Binary: binary, Problem: "version output exceeds 4 KiB"}
			}
			version, identity, err := parser(text)
			if err != nil {
				return Result{Binary: binary, Version: version, Problem: err.Error()}
			}
			return Result{Binary: binary, Version: version, Identity: identity, Health: "ready"}
		},
	}
}

func (service Service) pythonSpec() Specification {
	const script = "import sys, venv; assert sys.version_info >= (3, 11); print(sys.executable + '|' + '.'.join(map(str, sys.version_info[:3])))"
	candidates := []string{}
	if configured := strings.TrimSpace(service.environment("ATUM_PYTHON_BIN")); configured != "" {
		candidates = append(candidates, configured)
	} else {
		candidates = append(candidates, "python3.12", "python3.11", "python3.13", "python3.14", "python3")
	}
	return Specification{
		Tool: Python, Label: "Python", InstallURL: pythonInstall,
		Override: "ATUM_PYTHON_BIN", Required: "Python >= 3.11 with venv",
		Timeout: defaultTimeout,
		probe: func(ctx context.Context, output *capture) Result {
			var lastProblem string
			for _, candidate := range candidates {
				binary := resolveBinary(candidate)
				if binary == "" {
					lastProblem = "binary not found"
					continue
				}
				output.reset()
				err := service.Runner.Run(ctx, process.Command{
					Name: binary, Args: []string{"-c", script}, Dir: service.Project.Root,
					Stdout: output, Stderr: output,
				})
				text, truncated := output.text()
				if err != nil {
					lastProblem = commandProblem(ctx, err, text)
					if ctx.Err() != nil {
						return Result{Binary: binary, Problem: lastProblem}
					}
					continue
				}
				if truncated {
					lastProblem = "version output exceeds 4 KiB"
					continue
				}
				executable, version, found := strings.Cut(text, "|")
				if !found || executable == "" || version == "" {
					lastProblem = "returned an invalid version identity"
					continue
				}
				return Result{
					Binary: binary, Version: version, Identity: executable + "|" + version,
					Health: "venv importable",
				}
			}
			if lastProblem == "" {
				lastProblem = "binary not found"
			}
			return Result{Problem: lastProblem}
		},
	}
}

func (service Service) virshSpec(uri string) Specification {
	binary := service.binary("ATUM_VIRSH_BIN", "virsh")
	return service.statefulCommandSpec(
		Virsh, "libvirt", libvirtInstall, "ATUM_VIRSH_BIN",
		"virsh and connection "+uri, binary,
		[]string{"-c", uri, "uri"}, uri,
		"connection returned an unexpected URI", "connected "+uri,
		sameLibvirtURI,
	)
}

func sameLibvirtURI(left, right string) bool {
	leftURI, leftErr := url.Parse(left)
	rightURI, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil ||
		leftURI.Scheme == "" || rightURI.Scheme == "" {
		return false
	}
	sameUser := leftURI.User == nil && rightURI.User == nil
	if leftURI.User != nil && rightURI.User != nil {
		sameUser = leftURI.User.String() == rightURI.User.String()
	}
	return leftURI.Scheme == rightURI.Scheme &&
		sameUser &&
		leftURI.Host == rightURI.Host &&
		leftURI.Path == rightURI.Path &&
		leftURI.Query().Encode() == rightURI.Query().Encode() &&
		leftURI.Fragment == rightURI.Fragment
}

func (service Service) firewallSpec() Specification {
	binary := service.binary("ATUM_FIREWALL_CMD_BIN", "firewall-cmd")
	return service.statefulCommandSpec(
		Firewall, "firewalld", firewalldInstall, "ATUM_FIREWALL_CMD_BIN",
		"running firewalld", binary, []string{"--state"}, "running",
		"firewalld is not running", "running", exactState,
	)
}

func exactState(left, right string) bool { return left == right }

func (service Service) statefulCommandSpec(
	tool Tool,
	label, installURL, override, required, binary string,
	stateArguments []string,
	expectedState, stateProblem, health string,
	matches func(string, string) bool,
) Specification {
	return Specification{
		Tool: tool, Label: label, InstallURL: installURL,
		Override: override, Required: required,
		Timeout: defaultTimeout,
		probe: func(ctx context.Context, output *capture) Result {
			version, problem := service.initialCommandIdentity(
				ctx, binary, []string{"--version"}, output)
			if problem.Problem != "" {
				return problem
			}
			diagnostics := newCapture()
			if err := service.Runner.Run(ctx, process.Command{
				Name: binary, Args: stateArguments, Dir: service.Project.Root,
				Stdout: output, Stderr: diagnostics,
			}); err != nil {
				state, _ := output.text()
				diagnostic, _ := diagnostics.text()
				if state != "" && diagnostic != "" {
					state += "; " + diagnostic
				} else if diagnostic != "" {
					state = diagnostic
				}
				return Result{
					Binary: binary, Version: version,
					Problem: commandProblem(ctx, err, state),
				}
			}
			state, stateTruncated := output.text()
			_, diagnosticTruncated := diagnostics.text()
			if stateTruncated || diagnosticTruncated {
				return Result{
					Binary: binary, Version: version,
					Problem: stateProblem + ": output exceeds 4 KiB",
				}
			}
			if !matches(state, expectedState) {
				return Result{
					Binary: binary, Version: version,
					Problem: fmt.Sprintf("%s: got %q", stateProblem, state),
				}
			}
			return Result{
				Binary: binary, Version: version, Identity: binary + "|" + version,
				Health: health,
			}
		},
	}
}

func (service Service) initialCommandIdentity(
	ctx context.Context,
	binary string,
	arguments []string,
	output *capture,
) (string, Result) {
	if binary == "" {
		return "", Result{Problem: "binary not found"}
	}
	if err := service.Runner.Run(ctx, process.Command{
		Name: binary, Args: arguments, Dir: service.Project.Root,
		Stdout: output, Stderr: output,
	}); err != nil {
		text, _ := output.text()
		return "", Result{Binary: binary, Problem: commandProblem(ctx, err, text)}
	}
	identity, truncated := output.text()
	if truncated || identity == "" {
		return "", Result{Binary: binary, Problem: "returned an invalid version identity"}
	}
	output.reset()
	return identity, Result{}
}

func (service Service) restoreconSpec() (Specification, bool) {
	configured := strings.TrimSpace(service.environment("ATUM_RESTORECON_BIN"))
	binary := resolveBinary(configured)
	if configured == "" {
		binary = resolveBinary("restorecon")
		if binary == "" {
			return Specification{}, false
		}
	}
	return Specification{
		Tool: Restorecon, Label: "SELinux relabel", InstallURL: restoreconInstall,
		Override: "ATUM_RESTORECON_BIN", Required: "usable restorecon when selected",
		Timeout: defaultTimeout,
		probe: func(ctx context.Context, output *capture) Result {
			if binary == "" {
				return Result{Problem: "binary not found"}
			}
			if err := service.Runner.Run(ctx, process.Command{
				Name: binary, Args: []string{"-n", "/dev/null"}, Dir: service.Project.Root,
				Stdout: output, Stderr: output,
			}); err != nil {
				text, _ := output.text()
				return Result{Binary: binary, Problem: commandProblem(ctx, err, text)}
			}
			_, truncated := output.text()
			if truncated {
				return Result{Binary: binary, Problem: "probe output exceeds 4 KiB"}
			}
			return Result{Binary: binary, Version: "selected", Identity: binary, Health: "usable"}
		},
	}, true
}

func kvmSpec() Specification {
	return Specification{
		Tool: KVM, Label: "KVM", InstallURL: libvirtInstall,
		Required: "read/write access to /dev/kvm", Timeout: defaultTimeout,
		probe: func(context.Context, *capture) Result {
			info, err := os.Stat("/dev/kvm")
			if err != nil {
				return Result{Binary: "/dev/kvm", Problem: "device is unavailable"}
			}
			if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice == 0 {
				return Result{Binary: "/dev/kvm", Problem: "path is not a character device"}
			}
			if err := unix.Access("/dev/kvm", unix.R_OK|unix.W_OK); err != nil {
				return Result{Binary: "/dev/kvm", Problem: "device is not readable and writable"}
			}
			return Result{Binary: "/dev/kvm", Version: "character device", Health: "usable"}
		},
	}
}

func (service Service) binary(override, fallback string) string {
	value := strings.TrimSpace(service.environment(override))
	if value == "" {
		value = fallback
	}
	return resolveBinary(value)
}

func resolveBinary(value string) string {
	if value == "" {
		return ""
	}
	path, err := exec.LookPath(value)
	if err != nil {
		return ""
	}
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}

func (service Service) environment(name string) string {
	if service.Environment != nil {
		return service.Environment(name)
	}
	return os.Getenv(name)
}

func identityParser(output string) (string, string, error) {
	if output == "" {
		return "", "", errors.New("returned an empty version identity")
	}
	return output, output, nil
}

func checkSOPSVersion(output string) (string, error) {
	fields := strings.Fields(output)
	if len(fields) < 2 || fields[0] != "sops" {
		return "", errors.New("returned an invalid official SOPS version signature")
	}
	version, err := semver.NewVersion(strings.TrimPrefix(fields[1], "v"))
	if err != nil || version.Prerelease() != "" || version.Metadata() != "" {
		return "", fmt.Errorf("returned an invalid stable SOPS version %q", fields[1])
	}
	constraint, err := semver.NewConstraint(sopsSupported)
	if err != nil {
		return "", fmt.Errorf("parse supported SOPS range: %w", err)
	}
	if !constraint.Check(version) {
		return version.String(), fmt.Errorf(
			"SOPS %s does not satisfy supported range %s",
			version,
			sopsSupported,
		)
	}
	return version.String(), nil
}

func commandProblem(ctx context.Context, err error, output string) string {
	if ctx.Err() != nil {
		return contextProblem(ctx.Err())
	}
	problem := "probe failed: " + sanitize(err.Error())
	if output != "" {
		problem += " (" + sanitize(output) + ")"
	}
	return problem
}

func contextProblem(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "probe timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "probe canceled"
	}
	return sanitize(err.Error())
}

func sanitize(value string) string {
	fields := strings.Fields(strings.ToValidUTF8(value, "�"))
	result := strings.Join(fields, " ")
	const diagnosticLimit = 512
	if len(result) <= diagnosticLimit {
		return result
	}
	end := diagnosticLimit
	for end > 0 && !utf8.ValidString(result[:end]) {
		end--
	}
	return result[:end] + "…"
}

func fluxLine(target string) string {
	version, err := semverParts(target)
	if err != nil {
		return target
	}
	return fmt.Sprintf("%d.%d.x", version[0], version[1])
}

func semverParts(value string) ([2]uint64, error) {
	version, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	if err != nil {
		return [2]uint64{}, err
	}
	return [2]uint64{version.Major(), version.Minor()}, nil
}

func terraformConstraint(root, directory string) (string, error) {
	file, err := fssecure.OpenRegular(root, filepath.Join(directory, "versions.tf"))
	if err != nil {
		return "", fmt.Errorf("open active Terraform versions.tf: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, outputLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return "", errors.Join(readErr, closeErr)
	}
	if len(data) > outputLimit {
		return "", errors.New("active Terraform versions.tf exceeds 4 KiB")
	}
	filename := filepath.Join(directory, "versions.tf")
	parsed, diagnostics := hclparse.NewParser().ParseHCL(data, filename)
	if diagnostics.HasErrors() {
		return "", fmt.Errorf("parse active Terraform versions.tf: %s", diagnostics.Error())
	}
	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		return "", errors.New("active Terraform versions.tf has an unsupported syntax body")
	}
	for _, block := range body.Blocks {
		if block.Type != "terraform" {
			continue
		}
		attribute, exists := block.Body.Attributes["required_version"]
		if !exists {
			continue
		}
		value, diagnostics := attribute.Expr.Value(&hcl.EvalContext{})
		if diagnostics.HasErrors() || value.Type() != cty.String || !value.IsKnown() {
			return "", errors.New("active Terraform required_version must be a literal string")
		}
		constraint := strings.TrimSpace(value.AsString())
		if constraint == "" {
			return "", errors.New("active Terraform required_version is empty")
		}
		return constraint, nil
	}
	return "", errors.New("active Terraform versions.tf has no required_version")
}
