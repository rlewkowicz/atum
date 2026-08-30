package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/infra"
	"atum/cli/kube"
	"atum/cli/platform"
	"atum/cli/preflight"
	"atum/cli/process"
	"atum/cli/progress"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
)

var accessSudoCandidates = [...]string{"/usr/bin/sudo", "/bin/sudo"}

const (
	localDNSConvergenceTimeout = 5 * time.Minute
	localDNSRetryInterval      = 2 * time.Second
	localDNSProbeTimeout       = 10 * time.Second
)

var internalProcessEnvironment = [...]string{
	"HOME=/root",
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
}

const (
	internalRootProcess   = "root"
	internalVerifyProcess = "verify"
)

func internalEnvironment(processType string) []string {
	environment := append([]string(nil), internalProcessEnvironment[:]...)
	if processType == internalVerifyProcess {
		environment[0] = "HOME=/"
	}
	return environment
}

func (a *app) accessCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "access",
		Short: "Manage local workstation DNS and CA trust",
	}
	for _, action := range []string{"install", "status", "uninstall"} {
		action := action
		subcommand := &cobra.Command{
			Use:   action,
			Short: action + " local workstation access",
			Args:  cobra.NoArgs,
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
				return a.runAccessAction(cmd.Context(), action)
			}),
		}
		if action == "status" {
			subcommand.Annotations = map[string]string{"atum.dev/read-only": "true"}
		}
		command.AddCommand(subcommand)
	}
	return command
}

func hostAccessHelperCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "__host-access ACTION [FACTS...]",
		Hidden: true,
		Args:   cobra.ArbitraryArgs,
		Annotations: map[string]string{
			"atum.dev/no-project": "true", "atum.dev/internal-process": internalRootProcess,
		},
		RunE: func(cmd *cobra.Command, arguments []string) error {
			if os.Geteuid() != 0 {
				return errors.New("host access helper requires root")
			}
			if len(arguments) == 0 {
				return errors.New("host access helper action is required")
			}
			service := infra.AccessService{
				Runner: process.ExecRunner{}, Output: io.Discard, EUID: os.Geteuid(),
			}
			switch arguments[0] {
			case "dns-install":
				facts, err := helperFacts(arguments[1:])
				if err != nil {
					return err
				}
				capabilities, err := infra.SelectAccessCapabilities(infra.ObserveDNS)
				if err != nil {
					return err
				}
				service.Capabilities = capabilities
				return service.InstallDNS(cmd.Context(), facts)
			case "ca-install":
				facts, err := helperFacts(arguments[1:])
				if err != nil {
					return err
				}
				data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), infra.RootCertificateLimit+1))
				if err != nil {
					return fmt.Errorf("read public root CA: %w", err)
				}
				defer clear(data)
				if len(data) > infra.RootCertificateLimit {
					return errors.New("public root CA exceeds 1 MiB")
				}
				trustStore, err := infra.SelectTrustStore()
				if err != nil {
					return err
				}
				updater, err := infra.SelectTrustUpdater(trustStore)
				if err != nil {
					return err
				}
				service.TrustStore = trustStore
				service.TrustUpdater = updater
				return service.InstallCA(cmd.Context(), facts, data)
			case "uninstall":
				if len(arguments) < 7 {
					return errors.New(
						"host access uninstall helper requires authorization digest and facts")
				}
				authorization := arguments[1]
				if err := infra.ValidateSHA256Digest(authorization); err != nil {
					return fmt.Errorf("invalid host access removal authorization: %w", err)
				}
				facts, err := helperFacts(arguments[2:])
				if err != nil {
					return err
				}
				trustStore, err := infra.SelectTrustStore()
				if err != nil {
					return err
				}
				service.TrustStore = trustStore
				plan, err := service.PlanUninstall(facts)
				if err != nil {
					return err
				}
				defer plan.Clear()
				if subtle.ConstantTimeCompare(
					[]byte(plan.AuthorizationDigest()), []byte(authorization)) != 1 {
					return errors.New("local access removal state changed after authorization")
				}
				capabilities, err := infra.SelectAccessCapabilities(plan.CapabilityNeed())
				if err != nil {
					return err
				}
				service.Capabilities = capabilities
				if plan.RefreshesTrust() {
					updater, err := infra.SelectTrustUpdater(trustStore)
					if err != nil {
						return err
					}
					service.TrustUpdater = updater
				}
				return service.Uninstall(cmd.Context(), plan)
			default:
				return fmt.Errorf("unsupported host access helper action %q", arguments[0])
			}
		},
	}
	return command
}

func trustedHTTPSVerifierCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "__verify-host-access DOMAIN PUBLIC-VIP ROOT-FINGERPRINT",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		Annotations: map[string]string{
			"atum.dev/no-project": "true", "atum.dev/internal-process": internalVerifyProcess,
		},
		RunE: func(cmd *cobra.Command, arguments []string) error {
			if os.Geteuid() == 0 {
				return errors.New("host access HTTPS verifier must be unprivileged")
			}
			return verifyDirectSystemHTTPS(
				cmd.Context(), arguments[0], arguments[1], arguments[2])
		},
	}
}

func enforceInternalProcessEnvironment(processType string) error {
	if processType != internalRootProcess && processType != internalVerifyProcess {
		return fmt.Errorf("unsupported internal process type %q", processType)
	}
	os.Clearenv()
	var failures []error
	for _, entry := range internalEnvironment(processType) {
		name, value, _ := strings.Cut(entry, "=")
		if err := os.Setenv(name, value); err != nil {
			failures = append(failures, fmt.Errorf(
				"set internal process %s: %w", name, err))
		}
	}
	return errors.Join(failures...)
}

func helperFacts(arguments []string) (infra.LocalAccessFacts, error) {
	if len(arguments) < 5 ||
		len(arguments) > 4+config.MaxPassthroughHosts {
		return infra.LocalAccessFacts{}, fmt.Errorf(
			"host access helper requires domain, DNS, public VIP, passthrough VIP, and 1-%d passthrough hosts",
			config.MaxPassthroughHosts)
	}
	hosts := append([]string(nil), arguments[4:]...)
	sort.Strings(hosts)
	return infra.LocalAccessFacts{
		Domain: arguments[0], DNSServer: arguments[1],
		PublicIngressVIP: arguments[2], PassthroughIngressVIP: arguments[3],
		PassthroughHosts: hosts,
	}, nil
}

func (a *app) runAccessAction(ctx context.Context, action string) error {
	facts, local, err := a.localAccessFacts()
	if err != nil {
		return err
	}
	if !local {
		return errors.New("active target has no supported local workstation access configuration")
	}
	switch action {
	case "status":
		status, err := a.localAccessStatus(ctx, facts)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(a.out,
			"resolver path: %s\nresolver content: %q\nresolver content exact: %t\nsystemd-resolved active: %t\n"+
				"/etc/resolv.conf target: %s\nsystemd-resolved managed: %t\n"+
				"headlamp lookup: %t\nexact passthrough lookups: %t\npassthrough host count: %d\n"+
				"CA path: %s\nCA fingerprint: %s\n"+
				"reference Fedora/RHEL CA path: %s\nreference Debian CA path: %s\n",
			status.ResolverPath, status.ResolverContent, status.ResolverExact, status.ResolvedActive,
			status.ResolvConfTarget, status.ResolvConfManaged,
			status.PublicLookupExact, status.PassthroughLookupsExact,
			status.PassthroughLookupCount,
			status.AnchorPath, status.AnchorFingerprint,
			infra.FedoraAnchorPath, infra.DebianAnchorPath,
		)
		return err
	case "install":
		if err := a.requireNativePlatformForLocalAccess(ctx); err != nil {
			return err
		}
		if err := a.ensureLocalDNS(ctx); err != nil {
			return err
		}
		return a.ensureLocalCA(ctx)
	case "uninstall":
		if a.dryRun {
			a.logger.InfoContext(ctx, "local access uninstall would remove only Atum-managed host files")
			return nil
		}
		trustStore, err := infra.SelectTrustStore()
		if err != nil {
			return err
		}
		service := infra.AccessService{Now: time.Now, TrustStore: trustStore}
		plan, err := service.PlanUninstall(facts)
		if err != nil {
			return err
		}
		defer plan.Clear()
		if plan.Empty() {
			_, err := fmt.Fprintln(a.out, "local access is not installed")
			return err
		}
		scope := preflight.AccessUninstall
		need := plan.CapabilityNeed()
		if !plan.RefreshesTrust() {
			scope = preflight.AccessDNS
		} else if need == 0 {
			scope = preflight.AccessCA
		}
		capabilities, err := infra.SelectAccessCapabilities(need)
		if err != nil {
			return err
		}
		var updater infra.TrustUpdater
		if plan.RefreshesTrust() {
			updater, err = infra.SelectTrustUpdater(trustStore)
			if err != nil {
				return err
			}
		}
		sudo := selectAccessSudo()
		if err := a.checkAccessPreflight(
			ctx, scope, capabilities, trustStore, updater, sudo); err != nil {
			return err
		}
		helperArguments := []string{"uninstall", plan.AuthorizationDigest()}
		helperArguments = append(helperArguments, factsArguments(facts)...)
		return a.withTerminal(func(input io.Reader, output, errorOutput io.Writer) error {
			return a.runPrivilegedHelper(
				ctx, capabilities, trustStore, updater, sudo, nil,
				terminalStreams{input: input, output: output, errorOutput: errorOutput},
				helperArguments...)
		})
	default:
		return fmt.Errorf("unsupported access action %q", action)
	}
}

func (a *app) requireNativePlatformForLocalAccess(ctx context.Context) error {
	status, err := a.platformService().Status(ctx)
	if err != nil {
		return fmt.Errorf(
			"observe native platform readiness before local access install: %w",
			err,
		)
	}
	if !status.Reconciliation.Complete() {
		return fmt.Errorf(
			"native Flux reconciliation is incomplete; local access was not changed: %s",
			nativeReconciliationDiagnostics(status.Reconciliation),
		)
	}
	if !status.Delivery.Compliant() {
		detail := strings.Join(status.Delivery.Issues, "; ")
		if detail == "" {
			detail = fmt.Sprintf(
				"publicationExact=%t forgejoExact=%t harborImagesExact=%t harborChartsExact=%t",
				status.Delivery.PublicationExact,
				status.Delivery.ForgejoExact,
				status.Delivery.HarborImagesExact,
				status.Delivery.HarborChartsExact,
			)
		}
		return fmt.Errorf(
			"platform delivery compliance is incomplete; local access was not changed: %s",
			detail,
		)
	}
	return nil
}

func nativeReconciliationDiagnostics(
	status platform.ReconciliationStatus,
) string {
	issues := make([]string, 0)
	appendIssue := func(resource platform.ResourceStatus) {
		if resource.Ready {
			return
		}
		detail := resource.Message
		if detail == "" {
			detail = "Ready condition is false"
		}
		issues = append(issues, resource.Name+": "+detail)
	}
	for _, resources := range [][]platform.ResourceStatus{
		status.GitRepositories,
		status.Kustomizations,
		status.OCIRepositories,
		status.HelmReleases,
		status.Certificates,
		status.PlatformIdentityConfigurations,
	} {
		for _, resource := range resources {
			appendIssue(resource)
		}
	}
	if len(issues) == 0 {
		return "required native resources are absent"
	}
	return strings.Join(issues, "; ")
}

func (a *app) localAccessFacts() (infra.LocalAccessFacts, bool, error) {
	target, found := a.project.Desired.ActiveTarget()
	if !found {
		return infra.LocalAccessFacts{}, false, fmt.Errorf(
			"active infrastructure target %q is not defined",
			a.project.Desired.Infrastructure.Active,
		)
	}
	if target.LocalAccess == nil {
		return infra.LocalAccessFacts{}, false, nil
	}
	access := target.LocalAccess
	passthroughHosts := append([]string(nil), access.PassthroughHosts...)
	sort.Strings(passthroughHosts)
	return infra.LocalAccessFacts{
		Domain: access.Domain, DNSServer: access.DNSServer,
		PublicIngressVIP:      access.PublicIngressVIP,
		PassthroughIngressVIP: access.PassthroughIngressVIP,
		PassthroughHosts:      passthroughHosts,
	}, true, nil
}

func (a *app) localAccessStatus(ctx context.Context, facts infra.LocalAccessFacts) (infra.AccessStatus, error) {
	trustStore, err := infra.SelectTrustStore()
	if err != nil {
		return infra.AccessStatus{}, err
	}
	capabilities, err := infra.SelectAccessCapabilities(infra.ObserveDNS)
	if err != nil {
		return infra.AccessStatus{}, err
	}
	return (infra.AccessService{
		Runner: a.runner, Output: a.out, EUID: effectiveUID(),
		Capabilities: capabilities, TrustStore: trustStore,
	}).Status(ctx, facts)
}

func (a *app) observePlatformHostAccess(ctx context.Context, status *platform.Status) error {
	return a.observePlatformHostAccessWithDNS(ctx, status, nil)
}

func (a *app) observePlatformHostAccessWithDNS(
	ctx context.Context,
	status *platform.Status,
	dns *infra.AccessStatus,
) error {
	if status == nil || !status.Local.Required {
		return nil
	}
	facts, local, err := a.localAccessFacts()
	if err != nil {
		return err
	}
	if !local {
		return errors.New("platform requires local access but active target has no local access facts")
	}
	var host infra.AccessStatus
	if dns == nil {
		host, err = a.localAccessStatus(ctx, facts)
	} else {
		host, err = a.localCAStatus(ctx, facts)
		if err == nil {
			projectDNSStatus(&host, *dns)
		}
	}
	if err != nil {
		return err
	}
	status.Local.HostAccessObserved = true
	status.Local.ResolverPath = host.ResolverPath
	status.Local.ResolverReady = host.DNSExact()
	status.Local.PublicDNSReady = host.PublicLookupExact
	status.Local.PassthroughDNSReady = host.PassthroughLookupsExact
	status.Local.LocalDNSReady = status.Local.ResolverReady &&
		status.Local.PublicDNSReady && status.Local.PassthroughDNSReady
	status.Local.CAPath = host.AnchorPath
	status.Local.CAFingerprint = host.AnchorFingerprint
	status.Local.CATrustReady = host.AnchorPresent &&
		status.Local.RootCAFingerprint != "" &&
		host.AnchorFingerprint == status.Local.RootCAFingerprint
	if dns == nil {
		if status.Local.LocalDNSReady {
			progress.Done(ctx, progress.Platform, "local-dns", "Local DNS",
				"resolver and public/passthrough lookups exact")
		} else {
			progress.Fail(ctx, progress.Platform, "local-dns", "Local DNS",
				errors.New("resolver, public DNS, or exact passthrough DNS not exact"))
		}
	}
	if status.Local.CATrustReady {
		progress.Done(ctx, progress.Platform, "local-certificates", "Local certificates",
			"host CA trust fingerprint exact")
	} else {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates",
			errors.New("host CA trust fingerprint not exact"))
	}
	return nil
}

func projectDNSStatus(target *infra.AccessStatus, observed infra.AccessStatus) {
	target.ResolverPath = observed.ResolverPath
	target.ResolverExact = observed.ResolverExact
	target.ResolvedActive = observed.ResolvedActive
	target.ResolvConfManaged = observed.ResolvConfManaged
	target.PublicLookupExact = observed.PublicLookupExact
	target.PassthroughLookupsExact = observed.PassthroughLookupsExact
}

func (a *app) localCAStatus(ctx context.Context, facts infra.LocalAccessFacts) (infra.AccessStatus, error) {
	trustStore, err := infra.SelectTrustStore()
	if err != nil {
		return infra.AccessStatus{}, err
	}
	return (infra.AccessService{TrustStore: trustStore}).Status(ctx, facts)
}

func (a *app) localDNSStatus(ctx context.Context, facts infra.LocalAccessFacts) (infra.AccessStatus, error) {
	capabilities, err := infra.SelectAccessCapabilities(infra.ObserveDNS)
	if err != nil {
		return infra.AccessStatus{}, err
	}
	return (infra.AccessService{
		Runner: a.runner, Output: a.out, EUID: effectiveUID(),
		Capabilities: capabilities,
	}).Status(ctx, facts)
}

func (a *app) localDNSConfigurationStatus(
	ctx context.Context,
	facts infra.LocalAccessFacts,
) (infra.AccessStatus, error) {
	capabilities, err := infra.SelectAccessCapabilities(infra.ObserveDNS)
	if err != nil {
		return infra.AccessStatus{}, err
	}
	return (infra.AccessService{
		Runner: a.runner, Output: a.out, EUID: effectiveUID(),
		Capabilities: capabilities,
	}).DNSConfigurationStatus(ctx, facts)
}

func (a *app) ensureLocalDNS(ctx context.Context) error {
	facts, local, err := a.localAccessFacts()
	if err != nil || !local {
		return err
	}
	progress.Start(ctx, progress.Platform, "local-dns", "Local DNS",
		"inspecting resolver configuration")
	status, err := a.localDNSConfigurationStatus(ctx, facts)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-dns", "Local DNS", err)
		return err
	}
	if status.DNSExact() {
		progress.Done(ctx, progress.Platform, "local-dns", "Local DNS",
			"resolver configuration already exact")
		return nil
	}
	if a.dryRun {
		a.logger.InfoContext(ctx, "local DNS would be installed", "path", infra.ResolverDropInPath)
		progress.Done(ctx, progress.Platform, "local-dns", "Local DNS",
			"resolver configuration installation planned")
		return nil
	}
	capabilities, err := infra.SelectAccessCapabilities(infra.ObserveDNS)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-dns", "Local DNS", err)
		return err
	}
	managedReport := a.preflight
	sudo := selectAccessSudo()
	if err := a.checkAccessPreflight(
		ctx, preflight.AccessDNS, capabilities, infra.TrustStoreDescriptor{},
		infra.TrustUpdater{}, sudo); err != nil {
		a.preflight = managedReport
		progress.Fail(ctx, progress.Platform, "local-dns", "Local DNS", err)
		return err
	}
	defer func() { a.preflight = managedReport }()
	progress.Update(ctx, progress.Platform, "local-dns", "Local DNS",
		"administrator authorization required for resolver installation", 0, 0)
	err = a.withTerminal(func(input io.Reader, output, errorOutput io.Writer) error {
		return a.runPrivilegedHelper(
			ctx, capabilities, infra.TrustStoreDescriptor{}, infra.TrustUpdater{}, sudo, nil,
			terminalStreams{input: input, output: output, errorOutput: errorOutput},
			append([]string{"dns-install"}, factsArguments(facts)...)...)
	})
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-dns", "Local DNS", err)
		return err
	}
	progress.Done(ctx, progress.Platform, "local-dns", "Local DNS",
		"resolver configuration installed")
	return nil
}

type localDNSObservation struct {
	cancel context.CancelFunc
	done   <-chan localDNSResult
}

type localDNSResult struct {
	status infra.AccessStatus
	err    error
}

func (a *app) startLocalDNSObservation(ctx context.Context) (*localDNSObservation, error) {
	facts, local, err := a.localAccessFacts()
	if err != nil {
		return nil, err
	}
	if !local || a.dryRun {
		done := make(chan localDNSResult, 1)
		done <- localDNSResult{}
		close(done)
		return &localDNSObservation{done: done}, nil
	}
	capabilities, err := infra.SelectAccessCapabilities(infra.ObserveDNS)
	if err != nil {
		return nil, err
	}
	probeService := infra.AccessService{
		Runner: a.runner, Output: a.out, EUID: effectiveUID(),
		Capabilities: capabilities,
	}
	workerContext, cancel := context.WithTimeout(ctx, localDNSConvergenceTimeout)
	observation := &localDNSObservation{cancel: cancel}
	done := make(chan localDNSResult, 1)
	observation.done = done
	go func() {
		defer cancel()
		progress.Start(workerContext, progress.Platform, "local-dns", "Local DNS",
			"observing resolver and public/passthrough lookups")
		var last infra.AccessStatus
		err := runLocalDNSObservation(
			workerContext,
			localDNSRetryInterval,
			localDNSProbeTimeout,
			func(probeContext context.Context) (infra.AccessStatus, error) {
				status, probeErr := probeService.Status(probeContext, facts)
				last = status
				return status, probeErr
			},
			func(status infra.AccessStatus) bool {
				return status.DNSExact() &&
					status.PublicLookupExact && status.PassthroughLookupsExact
			},
			func(attempt int) {
				progress.Update(workerContext, progress.Platform, "local-dns", "Local DNS",
					fmt.Sprintf("resolver observation retry %d", attempt), 0, 0)
			},
		)
		err = finishLocalDNSObservation(ctx, workerContext, last, facts, err)
		done <- localDNSResult{status: last, err: err}
		close(done)
	}()
	return observation, nil
}

func finishLocalDNSObservation(
	parentContext, workerContext context.Context,
	status infra.AccessStatus,
	facts infra.LocalAccessFacts,
	err error,
) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	if parentContext.Err() != nil {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = localDNSLookupError(status, facts)
	}
	reportLocalDNSResult(workerContext, err)
	return err
}

func reportLocalDNSResult(ctx context.Context, err error) {
	if err == nil {
		progress.Done(ctx, progress.Platform, "local-dns", "Local DNS",
			"resolver and public/passthrough lookups exact")
	} else {
		progress.Fail(ctx, progress.Platform, "local-dns", "Local DNS", err)
	}
}

func runLocalDNSObservation(
	ctx context.Context,
	interval, probeTimeout time.Duration,
	probe func(context.Context) (infra.AccessStatus, error),
	ready func(infra.AccessStatus) bool,
	retry func(int),
) error {
	if interval <= 0 || probeTimeout <= 0 || probe == nil || ready == nil {
		return errors.New("valid local DNS observation configuration is required")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for attempt := 1; ; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
		status, err := probe(probeContext)
		probeExpired := errors.Is(probeContext.Err(), context.DeadlineExceeded)
		cancel()
		if err == nil && ready(status) {
			return nil
		}
		if err != nil && !probeExpired && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if retry != nil {
			retry(attempt)
		}
		timer.Reset(interval)
	}
}

func (observation *localDNSObservation) Wait() (infra.AccessStatus, error) {
	if observation == nil {
		return infra.AccessStatus{}, errors.New("local DNS observation is required")
	}
	result := <-observation.done
	return result.status, result.err
}

func (observation *localDNSObservation) Cancel() {
	if observation != nil && observation.cancel != nil {
		observation.cancel()
		<-observation.done
	}
}

func localDNSLookupError(
	status infra.AccessStatus,
	facts infra.LocalAccessFacts,
) error {
	if !status.PublicLookupExact {
		return fmt.Errorf("resolvectl query headlamp.%s did not return public VIP %s",
			facts.Domain, facts.PublicIngressVIP)
	}
	if !status.PassthroughLookupsExact {
		return fmt.Errorf(
			"one or more exact passthrough DNS names did not return passthrough VIP %s",
			facts.PassthroughIngressVIP)
	}
	return errors.New("local DNS lookups did not converge")
}

func (a *app) ensureLocalCA(ctx context.Context) error {
	facts, local, err := a.localAccessFacts()
	if err != nil || !local || a.dryRun {
		if local && a.dryRun {
			progress.Start(ctx, progress.Platform, "local-certificates", "Local certificates",
				"inspecting host CA trust")
			progress.Done(ctx, progress.Platform, "local-certificates", "Local certificates",
				"host CA trust installation planned")
		}
		return err
	}
	progress.Start(ctx, progress.Platform, "local-certificates", "Local certificates",
		"inspecting host CA trust")
	certificate, err := a.inClusterRootCA(ctx)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	defer certificate.Clear()
	trustStore, err := infra.SelectTrustStore()
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	service := infra.AccessService{TrustStore: trustStore}
	anchorPath, _, anchorExact, err := service.CompareCA(certificate)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	if anchorExact {
		if err := a.verifyTrustedHTTPS(
			ctx, facts.Domain, facts.PublicIngressVIP,
			certificate.Fingerprint); err != nil {
			progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
			return err
		}
		progress.Done(ctx, progress.Platform, "local-certificates", "Local certificates",
			"host CA trust already exact")
		return nil
	}
	updater, err := infra.SelectTrustUpdater(trustStore)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	managedReport := a.preflight
	sudo := selectAccessSudo()
	if err := a.checkAccessPreflight(
		ctx, preflight.AccessCA, infra.AccessCapabilities{}, trustStore, updater, sudo); err != nil {
		a.preflight = managedReport
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	defer func() { a.preflight = managedReport }()
	progress.Update(ctx, progress.Platform, "local-certificates", "Local certificates",
		"administrator authorization required for CA installation", 0, 0)
	if err := a.withTerminal(func(input io.Reader, output, errorOutput io.Writer) error {
		return a.runPrivilegedHelper(
			ctx, infra.AccessCapabilities{}, trustStore, updater, sudo,
			bytes.NewReader(certificate.PEM),
			terminalStreams{input: input, output: output, errorOutput: errorOutput},
			append([]string{"ca-install"}, factsArguments(facts)...)...)
	}); err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	anchorPath, _, anchorExact, err = service.CompareCA(certificate)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	if !anchorExact {
		err := fmt.Errorf(
			"host CA fingerprint at %s does not match the in-cluster root", anchorPath)
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	if err := a.verifyTrustedHTTPS(
		ctx, facts.Domain, facts.PublicIngressVIP,
		certificate.Fingerprint); err != nil {
		progress.Fail(ctx, progress.Platform, "local-certificates", "Local certificates", err)
		return err
	}
	progress.Done(ctx, progress.Platform, "local-certificates", "Local certificates",
		"host CA trust installed and verified")
	return nil
}

func (a *app) inClusterRootCA(ctx context.Context) (infra.ValidatedCA, error) {
	kubeconfig := a.env("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(
			a.project.Root,
			a.project.Desired.Orchestration.Inventory,
			"artifacts",
			"admin.conf",
		)
	}
	observer, err := kube.New(kubeconfig)
	if err != nil {
		return infra.ValidatedCA{}, err
	}
	data, found, err := observer.SecretValue(ctx, "cert-manager", "atum-test-root-ca", corev1.TLSCertKey)
	if err != nil {
		return infra.ValidatedCA{}, fmt.Errorf("read in-cluster root CA: %w", err)
	}
	if !found {
		return infra.ValidatedCA{}, errors.New("in-cluster root CA cert-manager/atum-test-root-ca tls.crt is absent")
	}
	defer clear(data)
	return infra.ValidateRootCA(data, time.Now())
}

func (a *app) verifyTrustedHTTPS(
	ctx context.Context,
	domain, publicVIP, fingerprint string,
) error {
	if err := validateTrustedHTTPSIdentity(domain, publicVIP, fingerprint); err != nil {
		return err
	}
	executable, err := internalExecutablePath()
	if err != nil {
		return err
	}
	name := executable
	arguments := []string{"__verify-host-access", domain, publicVIP, fingerprint}
	var identity *process.Identity
	if os.Geteuid() == 0 {
		uid, gid, err := unprivilegedProjectOwner(a.project.Root)
		if err != nil {
			return err
		}
		name = "/proc/self/exe"
		identity = &process.Identity{
			UID: uid,
			GID: gid,
		}
	}
	if err := a.runner.Run(ctx, process.Command{
		Name: name, Args: arguments,
		Env: internalEnvironment(internalVerifyProcess), ExactEnv: true,
		Identity: identity,
		Stdout:   a.out, Stderr: a.err,
	}); err != nil {
		return fmt.Errorf("fresh system-trust HTTPS verification failed: %w", err)
	}
	return nil
}

func verifyDirectSystemHTTPS(
	ctx context.Context,
	domain, publicVIP, fingerprint string,
) error {
	if err := validateTrustedHTTPSIdentity(domain, publicVIP, fingerprint); err != nil {
		return err
	}
	expected, err := hex.DecodeString(fingerprint)
	if err != nil {
		return errors.New("decode validated root CA fingerprint")
	}
	defer clear(expected)
	verificationContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dialAddress := net.JoinHostPort(publicVIP, "443")
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	host := "headlamp." + domain
	request, err := http.NewRequestWithContext(
		verificationContext, http.MethodGet, "https://"+host, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("verify trusted HTTPS for %s: %w", request.URL.Host, err)
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		_ = response.Body.Close()
		return fmt.Errorf(
			"verify trusted HTTPS for %s: response has no verified TLS chain", host)
	}
	for _, chain := range response.TLS.VerifiedChains {
		if len(chain) == 0 {
			_ = response.Body.Close()
			return fmt.Errorf(
				"verify trusted HTTPS for %s: verified TLS chain is empty", host)
		}
		digest := sha256.Sum256(chain[len(chain)-1].Raw)
		matches := subtle.ConstantTimeCompare(digest[:], expected) == 1
		clear(digest[:])
		if !matches {
			_ = response.Body.Close()
			return fmt.Errorf(
				"verify trusted HTTPS for %s: verified chain terminates at an unexpected root",
				host)
		}
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("complete trusted HTTPS response for %s: %w", host, err)
	}
	return nil
}

func validateTrustedHTTPSIdentity(domain, publicVIP, fingerprint string) error {
	if err := infra.ValidateAccessDomain(domain); err != nil {
		return err
	}
	address, err := netip.ParseAddr(publicVIP)
	if err != nil || !address.Is4() || address.IsUnspecified() ||
		address.IsLoopback() || address.IsMulticast() {
		return fmt.Errorf("invalid public ingress IPv4 address %q", publicVIP)
	}
	return infra.ValidateRootFingerprint(fingerprint)
}

type terminalStreams struct {
	input       io.Reader
	output      io.Writer
	errorOutput io.Writer
}

func (a *app) runPrivilegedHelper(
	ctx context.Context,
	capabilities infra.AccessCapabilities,
	trustStore infra.TrustStoreDescriptor,
	updater infra.TrustUpdater,
	sudo string,
	input io.Reader,
	terminal terminalStreams,
	arguments ...string,
) error {
	var need infra.AccessCapabilityNeed
	refreshTrust := false
	if len(arguments) != 0 {
		switch arguments[0] {
		case "dns-install":
			need = infra.ObserveDNS
		case "ca-install":
			refreshTrust = true
		case "uninstall":
			if capabilities.Systemctl != "" {
				need = infra.ObserveDNS
			}
			if updater.Binary != "" {
				refreshTrust = true
			}
		default:
			return fmt.Errorf("unsupported privileged local access action %q", arguments[0])
		}
	}
	if err := validatePrivilegedIdentities(
		capabilities, trustStore, updater, sudo, need, refreshTrust); err != nil {
		return err
	}
	if authorization := sudoAuthorizationFromContext(ctx); authorization != nil {
		if err := authorization.require(ctx, sudo); err != nil {
			return err
		}
	} else if err := a.runner.Run(ctx, process.Command{
		Name: sudo, Args: []string{"-v"}, Foreground: true,
		Stdin: terminal.input, Stdout: terminal.output, Stderr: terminal.errorOutput,
	}); err != nil {
		return fmt.Errorf("sudo authorization failed: %w", err)
	}
	executable, err := internalExecutablePath()
	if err != nil {
		return err
	}
	if err := validatePrivilegedIdentities(
		capabilities, trustStore, updater, sudo, need, refreshTrust); err != nil {
		return err
	}
	helperArguments := make([]string, 0, len(arguments)+3)
	helperArguments = append(helperArguments, "-n", "--", executable, "__host-access")
	helperArguments = append(helperArguments, arguments...)
	helperInput := input
	if helperInput == nil {
		helperInput = terminal.input
	}
	if err := a.runner.Run(ctx, process.Command{
		Name: sudo, Args: helperArguments, Env: internalEnvironment(internalRootProcess),
		ExactEnv: true, Stdin: helperInput,
		Stdout: terminal.output, Stderr: terminal.errorOutput,
	}); err != nil {
		return fmt.Errorf("privileged local access helper failed: %w", err)
	}
	return nil
}

func validatePrivilegedIdentities(
	capabilities infra.AccessCapabilities,
	trustStore infra.TrustStoreDescriptor,
	updater infra.TrustUpdater,
	sudo string,
	need infra.AccessCapabilityNeed,
	refreshTrust bool,
) error {
	if err := infra.ValidateAccessCapabilities(capabilities, need); err != nil {
		return err
	}
	if refreshTrust {
		if err := infra.ValidateTrustUpdater(trustStore, updater); err != nil {
			return err
		}
	}
	if infra.CanonicalHostExecutable(sudo) != sudo {
		return errors.New("selected sudo identity is unavailable or changed")
	}
	return nil
}

func internalExecutablePath() (string, error) {
	path, _, err := runningExecutablePaths()
	return path, err
}

func runningExecutablePaths() (string, string, error) {
	if runtime.GOOS != "linux" {
		return "", "", errors.New(
			"internal Atum commands require Linux /proc executable identity")
	}
	path := fmt.Sprintf("/proc/%d/exe", os.Getpid())
	before, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("inspect running Atum image: %w", err)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve running Atum image: %w", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("recheck running Atum image: %w", err)
	}
	if !os.SameFile(before, after) || !before.Mode().IsRegular() ||
		before.Mode().Perm()&0o111 == 0 || !filepath.IsAbs(target) ||
		strings.HasSuffix(target, " (deleted)") {
		return "", "", errors.New("running Atum image identity is unavailable or changed")
	}
	targetInfo, err := os.Stat(target)
	if err != nil || !os.SameFile(after, targetInfo) {
		return "", "", errors.New("running Atum target identity is unavailable or changed")
	}
	return path, target, nil
}

func unprivilegedProjectOwner(root string) (uint32, uint32, error) {
	if !filepath.IsAbs(root) {
		return 0, 0, errors.New("project root must be absolute")
	}
	directory, err := unix.Open(
		root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("inspect project owner: %w", err)
	}
	defer unix.Close(directory)
	var identity unix.Stat_t
	if err := unix.Fstat(directory, &identity); err != nil {
		return 0, 0, fmt.Errorf("inspect project owner: %w", err)
	}
	if identity.Mode&unix.S_IFMT != unix.S_IFDIR || identity.Uid == 0 || identity.Gid == 0 {
		return 0, 0, errors.New(
			"root invocation requires a non-root project owner for HTTPS verification")
	}
	return identity.Uid, identity.Gid, nil
}

func selectAccessSudo() string {
	for _, candidate := range accessSudoCandidates {
		if canonical := infra.CanonicalHostExecutable(candidate); canonical != "" {
			return canonical
		}
	}
	return ""
}

func factsArguments(facts infra.LocalAccessFacts) []string {
	arguments := make([]string, 4, 4+len(facts.PassthroughHosts))
	arguments[0] = facts.Domain
	arguments[1] = facts.DNSServer
	arguments[2] = facts.PublicIngressVIP
	arguments[3] = facts.PassthroughIngressVIP
	hosts := append([]string(nil), facts.PassthroughHosts...)
	sort.Strings(hosts)
	return append(arguments, hosts...)
}
