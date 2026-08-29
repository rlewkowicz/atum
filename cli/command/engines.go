package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/fssecure"
	"atum/cli/infra"
	"atum/cli/orchestration"
	"atum/cli/preflight"
	"atum/cli/process"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
)

func (a *app) runTerraform(ctx context.Context, args ...string) error {
	return a.runTerraformWithEnvironment(ctx, nil, args...)
}

type terraformRuntime struct {
	binary      string
	target      config.InfrastructureTarget
	environment []string
}

func (a *app) terraformRuntime(additionalEnvironment []string) (terraformRuntime, error) {
	if err := a.ensureProjectLoaded(); err != nil {
		return terraformRuntime{}, err
	}
	target, exists := a.project.Desired.ActiveTarget()
	if !exists {
		return terraformRuntime{}, fmt.Errorf("active infrastructure target %q is not defined", a.project.Desired.Infrastructure.Active)
	}
	terraform, err := a.requiredBinary(preflight.Terraform)
	if err != nil {
		return terraformRuntime{}, err
	}
	environment, err := a.terraformEnvironment(target, additionalEnvironment)
	if err != nil {
		return terraformRuntime{}, err
	}
	return terraformRuntime{binary: terraform, target: target, environment: environment}, nil
}

func (a *app) terraformEnvironment(
	target config.InfrastructureTarget,
	additional []string,
) ([]string, error) {
	for _, relative := range []string{
		".atum",
		filepath.Join(".atum", "runtime"),
		filepath.Join(".atum", "runtime", "terraform"),
	} {
		if _, err := fssecure.EnsureDirectoryMode(a.root, relative, 0o711); err != nil {
			return nil, fmt.Errorf("prepare Terraform runtime boundary: %w", err)
		}
	}
	runtimeDirectory := filepath.Join(a.root, ".atum", "runtime", "terraform")
	environment, err := terraformTargetEnvironment(target, additional)
	if err != nil {
		return nil, err
	}
	return append(environment, "TMPDIR="+runtimeDirectory), nil
}

func terraformTargetEnvironment(target config.InfrastructureTarget, additional []string) ([]string, error) {
	const localVariableCount = 7
	capacity := len(additional)
	if target.LocalAccess != nil {
		capacity += localVariableCount
	}
	environment := make([]string, 0, capacity)
	if target.LocalAccess != nil {
		access := target.LocalAccess
		rangeStart, rangeEnd, found := strings.Cut(access.LoadBalancerRange, "-")
		if !found {
			return nil, fmt.Errorf("local access load-balancer range %q is invalid", access.LoadBalancerRange)
		}
		loadBalancerRange, err := json.Marshal(struct {
			Start string `json:"start"`
			End   string `json:"end"`
		}{Start: rangeStart, End: rangeEnd})
		if err != nil {
			return nil, fmt.Errorf("encode local access load-balancer range: %w", err)
		}
		passthroughHosts := append([]string(nil), access.PassthroughHosts...)
		sort.Strings(passthroughHosts)
		encodedHosts, err := json.Marshal(passthroughHosts)
		if err != nil {
			return nil, fmt.Errorf("encode local access passthrough hosts: %w", err)
		}
		environment = append(environment,
			"TF_VAR_platform_domain="+access.Domain,
			"TF_VAR_dns_server="+access.DNSServer,
			"TF_VAR_public_ingress_vip="+access.PublicIngressVIP,
			"TF_VAR_passthrough_ingress_vip="+access.PassthroughIngressVIP,
			"TF_VAR_load_balancer_range="+string(loadBalancerRange),
			"TF_VAR_passthrough_hosts="+string(encodedHosts),
			"TF_VAR_ssh_private_key_path="+target.SSH.PrivateKeyPath,
		)
	}
	environment = append(environment, additional...)
	return environment, nil
}

func (a *app) runTerraformCommand(ctx context.Context, runtime terraformRuntime, args ...string) error {
	terraformArgs := make([]string, 0, len(args)+1)
	terraformArgs = append(terraformArgs, "-chdir="+runtime.target.Directory)
	terraformArgs = append(terraformArgs, args...)
	return a.runCommand(ctx, "Terraform", process.Command{
		Name: runtime.binary,
		Args: terraformArgs,
		Dir:  a.root,
		Env:  runtime.environment,
	})
}

func (a *app) terraformBastionResourceIdentity(ctx context.Context) (string, error) {
	if a.outputRunner == nil {
		return "", errors.New("Terraform bastion identity requires an output runner")
	}
	runtime, err := a.terraformRuntime(nil)
	if err != nil {
		return "", err
	}
	defer clearEnvironment(runtime.environment)
	output, err := a.outputRunner.Output(ctx, process.Command{
		Name: runtime.binary,
		Args: []string{
			"-chdir=" + runtime.target.Directory,
			"output",
			"-raw",
			"bastion_resource_identity",
		},
		Dir: a.root,
		Env: runtime.environment,
	})
	if err != nil {
		return "", fmt.Errorf("observe Terraform bastion resource identity: %w", err)
	}
	return parseTerraformBastionIdentity(output)
}

func parseTerraformBastionIdentity(output []byte) (string, error) {
	if len(output) > 1024 {
		return "", errors.New("Terraform bastion resource identity exceeds 1 KiB")
	}
	identity := strings.TrimSpace(string(output))
	if identity == "" || strings.ContainsAny(identity, "\r\n\x00") {
		return "", errors.New("Terraform bastion resource identity is invalid")
	}
	return identity, nil
}

func (a *app) runTerraformWithEnvironment(ctx context.Context, environment []string, args ...string) error {
	runtime, err := a.terraformRuntime(environment)
	if err != nil {
		return err
	}
	defer clearEnvironment(runtime.environment)
	return a.runTerraformCommand(ctx, runtime, args...)
}

func (a *app) runTerraformAction(ctx context.Context, action string, args ...string) error {
	return a.runTerraformActionWithEnvironment(ctx, action, nil, args...)
}

func (a *app) runTerraformActionWithEnvironment(
	ctx context.Context,
	action string,
	environment []string,
	args ...string,
) error {
	label := "Terraform " + action
	progress.Start(ctx, progress.Infrastructure, "terraform", label, "initializing")
	runtime, err := a.terraformRuntime(environment)
	if err != nil {
		progress.Fail(ctx, progress.Infrastructure, "terraform", label, err)
		return err
	}
	defer clearEnvironment(runtime.environment)
	if terraformInformational(args) {
		err := a.runTerraformCommand(ctx, runtime, append([]string{action}, args...)...)
		if err != nil {
			progress.Fail(ctx, progress.Infrastructure, "terraform", label, err)
			return err
		}
		progress.Done(ctx, progress.Infrastructure, "terraform", label, "complete")
		progress.Finish(ctx, progress.Infrastructure, progress.Complete, "complete")
		return nil
	}
	if err := a.runTerraformCommand(ctx, runtime, "init", "-input=false"); err != nil {
		err = fmt.Errorf("initialize Terraform target: %w", err)
		progress.Fail(ctx, progress.Infrastructure, "terraform", label, err)
		return err
	}
	progress.Update(ctx, progress.Infrastructure, "terraform", label, "converging", 0, 0)
	terraformArgs := make([]string, 0, len(args)+3)
	terraformArgs = append(terraformArgs, action)
	terraformArgs = append(terraformArgs, args...)
	if runtime.target.AutoApprove && (action == "apply" || action == "destroy") && !hasTerraformAutoApprove(args) {
		terraformArgs = append(terraformArgs, "-auto-approve")
	}
	if !a.raw && terraformStructuredOutput(action, runtime.target.AutoApprove, args) && !hasTerraformJSON(args) {
		terraformArgs = append(terraformArgs, "-json")
	}
	if err := a.runTerraformCommand(ctx, runtime, terraformArgs...); err != nil {
		progress.Fail(ctx, progress.Infrastructure, "terraform", label, err)
		return err
	}
	if action == "destroy" && !a.dryRun {
		if err := a.orchestrationService().ClearLocalState(); err != nil {
			err = fmt.Errorf("clear local orchestration state after Terraform destroy: %w", err)
			progress.Fail(ctx, progress.Infrastructure, "terraform", label, err)
			return err
		}
	}
	detail := "converged"
	switch action {
	case "destroy":
		detail = "destroyed"
	case "plan":
		detail = "plan complete"
	}
	progress.Done(ctx, progress.Infrastructure, "terraform", label, detail)
	progress.Finish(ctx, progress.Infrastructure, progress.Complete, detail)
	return nil
}

type terraformSeed struct {
	environment []string
	publication *delivery.Publication
	credentials atumsecrets.Document
}

func (seed *terraformSeed) ClearEnvironment() {
	if seed == nil {
		return
	}
	clearEnvironment(seed.environment)
	seed.environment = nil
}

// clearEnvironment releases the unavoidable immutable strings accepted by the
// operating-system process environment as soon as the native tool returns.
func clearEnvironment(environment []string) {
	for index := range environment {
		environment[index] = ""
	}
	clear(environment)
}

func (seed *terraformSeed) Clear() {
	if seed == nil {
		return
	}
	seed.ClearEnvironment()
	seed.credentials.Clear()
	seed.publication = nil
}

func (a *app) seedTerraformEnvironment(ctx context.Context) (terraformSeed, error) {
	publication := a.publication
	if publication == nil ||
		publication.Seed.File == "" ||
		publication.Seed.SHA256 == "" {
		return terraformSeed{}, errors.New("minimal Terraform seed payload is unavailable")
	}
	credentials, err := atumsecrets.Ensure(ctx, a.project, a.sops, a.logger)
	if err != nil {
		return terraformSeed{}, err
	}
	seed := a.project.Desired.Delivery.Seed
	environment := make([]string, 0, 11)
	environment = append(environment,
		"TF_VAR_seed_archive_path="+filepath.Join(a.project.Root, publication.Seed.File),
		"TF_VAR_seed_archive_sha256="+publication.Seed.SHA256,
		"TF_VAR_seed_forgejo_image="+seed.Forgejo.Image.Source,
		"TF_VAR_seed_kubespray_files_image="+seed.KubesprayFiles.Image.Source,
		"TF_VAR_seed_forgejo_url="+seed.Forgejo.URL,
		"TF_VAR_seed_forgejo_username="+credentials.Forgejo.Username,
		"TF_VAR_seed_forgejo_admin_password="+string(credentials.Forgejo.AdminPassword.Bytes()),
		"TF_VAR_seed_harbor_version="+seed.Harbor.Version,
		"TF_VAR_seed_harbor_url="+seed.Harbor.URL,
		"TF_VAR_seed_harbor_admin_password="+string(credentials.Harbor.AdminPassword.Bytes()),
		"TF_VAR_seed_harbor_secret_key="+string(credentials.Harbor.SecretKey.Bytes()),
	)
	return terraformSeed{
		publication: publication,
		credentials: credentials,
		environment: environment,
	}, nil
}

func terraformInformational(args []string) bool {
	for _, argument := range args {
		switch argument {
		case "-help", "--help", "-version", "--version":
			return true
		}
	}
	return false
}

func hasTerraformAutoApprove(args []string) bool {
	for _, argument := range args {
		if argument == "-auto-approve" || strings.HasPrefix(argument, "-auto-approve=") {
			return true
		}
	}
	return false
}

func hasTerraformJSON(args []string) bool {
	for _, argument := range args {
		if argument == "-json" || strings.HasPrefix(argument, "-json=") {
			return true
		}
	}
	return false
}

func terraformStructuredOutput(action string, autoApprove bool, args []string) bool {
	if action == "plan" {
		return true
	}
	return (action == "apply" || action == "destroy") && (autoApprove || hasTerraformAutoApprove(args))
}

func effectiveUID() int { return os.Geteuid() }

func (a *app) runLibvirtPermissions(ctx context.Context, action string) error {
	if a.dryRun && action != "status" {
		a.logger.InfoContext(ctx, "dry-run libvirt permission mutation", "action", action)
		return nil
	}
	scope := preflight.LibvirtPermissionsFile
	if action == "install" {
		scope = preflight.LibvirtPermissionsInstall
	} else if action != "status" && action != "uninstall" {
		return fmt.Errorf("unsupported libvirt permissions action %q", action)
	}
	if err := a.checkPreflight(ctx, scope); err != nil {
		return err
	}
	service := infra.LibvirtService{
		Runner:        a.runner,
		OutputRunner:  a.outputRunner,
		Out:           a.out,
		EUID:          effectiveUID(),
		ProjectRoot:   a.root,
		RestoreconBin: a.preflight.Binary(preflight.Restorecon),
		GetfaclBin:    a.preflight.Binary(preflight.Getfacl),
		SetfaclBin:    a.preflight.Binary(preflight.Setfacl),
	}
	return service.Permissions(ctx, action)
}

func (a *app) runLibvirtForwarding(ctx context.Context, action string) error {
	if a.dryRun && action != "status" {
		a.logger.InfoContext(ctx, "dry-run libvirt forwarding mutation", "action", action)
		return nil
	}
	plan, err := infra.PlanForwarding(action)
	if err != nil {
		return err
	}
	if err := a.checkForwardingPreflight(ctx, plan); err != nil {
		return err
	}
	service := infra.LibvirtService{
		Runner:       a.runner,
		OutputRunner: a.outputRunner,
		Out:          a.out,
		EUID:         effectiveUID(),
		VirshBin:     a.preflight.Binary(preflight.Virsh),
		FirewallBin:  a.preflight.Binary(preflight.Firewall),
	}
	return service.Forwarding(ctx, plan)
}

func (a *app) orchestrationService() orchestration.Service {
	return orchestration.Service{
		Project:        a.project,
		Runner:         a.runner,
		Logger:         a.logger,
		Env:            a.env,
		PythonBin:      a.preflight.Binary(preflight.Python),
		PythonIdentity: a.preflight.Identity(preflight.Python),
		SSHBin:         a.preflight.Binary(preflight.OpenSSH),
	}
}

func (a *app) runOrchestrationPrepare(ctx context.Context) error {
	if a.dryRun {
		a.logger.InfoContext(ctx, "dry-run orchestration tool preparation",
			"releases", len(a.project.Desired.Orchestration.Releases))
		return nil
	}
	toolchains, err := a.orchestrationService().Prepare(ctx)
	if err != nil {
		return err
	}
	for _, toolchain := range toolchains {
		if _, err := fmt.Fprintf(a.out, "%s\t%s\t%s\n",
			toolchain.Release.Kubernetes,
			toolchain.Release.Kubespray.Version,
			toolchain.Source,
		); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) runAnsiblePlaybook(ctx context.Context, args ...string) error {
	if err := a.checkPreflight(ctx, preflight.OrchestrationAnsible); err != nil {
		return err
	}
	if a.dryRun {
		a.logger.InfoContext(ctx, "dry-run Ansible passthrough")
		return nil
	}
	return a.orchestrationService().RunAnsible(ctx, progress.Target{
		Phase: progress.Orchestration,
		ID:    "activity",
		Label: "Ansible activity",
	}, args)
}

func (a *app) runOrchestrationInventory(ctx context.Context) error {
	inventoryPath := a.orchestrationInventoryPath()
	return a.generateOrchestrationInventory(ctx, inventoryPath)
}

func (a *app) generateOrchestrationInventory(ctx context.Context, inventoryPath string) error {
	progress.Start(ctx, progress.Orchestration, "inventory", "Inventory", "deriving from Terraform outputs")
	if a.dryRun {
		a.logger.InfoContext(ctx, "dry-run orchestration inventory", "output", inventoryPath)
		progress.Done(ctx, progress.Orchestration, "inventory", "Inventory", "planned")
		return nil
	}
	target, exists := a.project.Desired.ActiveTarget()
	if !exists {
		return fmt.Errorf("active infrastructure target %q is not defined", a.project.Desired.Infrastructure.Active)
	}
	terraform, err := a.requiredBinary(preflight.Terraform)
	if err != nil {
		return err
	}
	environment, err := a.terraformEnvironment(target, nil)
	if err != nil {
		return err
	}
	service := orchestration.InventoryService{
		OutputRunner: a.outputRunner,
		Root:         a.root,
		TerraformBin: terraform,
		TerraformDir: target.Directory,
		Environment:  environment,
		AnsibleUser:  a.project.Desired.Orchestration.AnsibleUser,
	}
	if err := service.Generate(ctx, inventoryPath); err != nil {
		progress.Fail(ctx, progress.Orchestration, "inventory", "Inventory", err)
		return err
	}
	progress.Done(ctx, progress.Orchestration, "inventory", "Inventory", "derived from Terraform")
	return nil
}

func (a *app) runOrchestrationPlan(ctx context.Context) (orchestration.UpgradePlan, error) {
	plan, err := a.orchestrationService().Plan(ctx)
	if err != nil {
		return orchestration.UpgradePlan{}, err
	}
	if err := a.printOrchestrationPlan(plan); err != nil {
		return orchestration.UpgradePlan{}, err
	}
	return plan, nil
}

func (a *app) printOrchestrationPlan(plan orchestration.UpgradePlan) error {
	current := plan.Current
	if current == "" {
		current = "absent"
	}
	if _, err := fmt.Fprintf(a.out, "current=%s target=%s order=%s\n",
		current, plan.Target, plan.Order); err != nil {
		return err
	}
	for _, step := range plan.Steps {
		if _, err := fmt.Fprintf(a.out, "upgrade=%s kubespray=%s commit=%s\n",
			step.Kubernetes, step.Kubespray.Version, step.Kubespray.Commit); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) runOrchestrationConverge(ctx context.Context, mode orchestration.ConvergenceMode, args ...string) error {
	service := a.orchestrationService()
	if a.dryRun {
		plan, err := service.Plan(ctx)
		if err != nil {
			return err
		}
		if err := service.ValidatePlan(plan, mode); err != nil {
			return err
		}
		return a.printOrchestrationPlan(plan)
	}
	inventoryPath := a.orchestrationInventoryPath()
	credentials, err := atumsecrets.Load(ctx, a.project, a.sops)
	if err != nil {
		return fmt.Errorf("load root CA for Kubespray: %w", err)
	}
	service.RootCAPEM = append(
		service.RootCAPEM,
		credentials.RootCA.Certificate.Bytes()...,
	)
	credentials.Clear()
	defer clear(service.RootCAPEM)
	if err := a.generateOrchestrationInventory(ctx, inventoryPath); err != nil {
		return err
	}
	if _, err := a.convergeOrchestration(ctx, service, inventoryPath, args, mode, nil); err != nil {
		progress.Finish(ctx, progress.Orchestration, progress.Failed, err.Error())
		return err
	}
	progress.Finish(ctx, progress.Orchestration, progress.Complete, "cluster healthy")
	return nil
}

func (a *app) convergeOrchestration(
	ctx context.Context,
	service orchestration.Service,
	inventoryPath string,
	rawArgs []string,
	mode orchestration.ConvergenceMode,
	platformHandoff func() error,
) (bool, error) {
	limit := len(a.project.Desired.Orchestration.Releases)*2 + 3
	planning := true
	platformApplied := false
	progress.Start(ctx, progress.Orchestration, "plan", "Convergence plan",
		"inspecting the live cluster and committed release ladder")
	for range limit {
		plan, err := service.Plan(ctx)
		if err != nil {
			if planning {
				progress.Fail(ctx, progress.Orchestration, "plan", "Convergence plan", err)
			}
			return platformApplied, err
		}
		if err := service.ValidatePlan(plan, mode); err != nil {
			if planning {
				progress.Fail(ctx, progress.Orchestration, "plan", "Convergence plan", err)
			}
			return platformApplied, err
		}
		if planning {
			progress.Done(ctx, progress.Orchestration, "plan", "Convergence plan", convergencePlanDetail(plan))
			planning = false
		}
		if plan.Order == orchestration.PlatformFirst && platformHandoff != nil {
			if err := platformHandoff(); err != nil {
				return platformApplied, err
			}
			platformApplied = true
			continue
		}
		if _, err := service.ConvergePlanned(ctx, plan, inventoryPath, rawArgs, mode); err != nil {
			return platformApplied, err
		}
		if plan.Order == orchestration.AlreadyCurrent {
			return platformApplied, nil
		}
	}
	return platformApplied, errors.New(
		"orchestration convergence exceeded the committed release and platform handoff bound",
	)
}

func convergencePlanDetail(plan orchestration.UpgradePlan) string {
	switch plan.Order {
	case orchestration.InstallTarget:
		return "fresh cluster install to Kubernetes " + plan.Target
	case orchestration.PlatformFirst:
		return "platform reconciliation before Kubernetes " + plan.Target
	case orchestration.KubernetesFirst:
		next := plan.Target
		if len(plan.Steps) == 1 {
			next = plan.Steps[0].Kubernetes
		}
		return "Kubernetes " + plan.Current + " → " + next +
			" toward " + plan.Target + " before platform reconciliation"
	case orchestration.AlreadyCurrent:
		return "Kubernetes " + plan.Target + " is current; verifying health"
	default:
		return "selected " + string(plan.Order)
	}
}

func (a *app) orchestrationInventoryPath() string {
	return filepath.Join(a.project.Desired.Orchestration.Inventory, "hosts.yaml")
}

func (a *app) runFlux(ctx context.Context, args ...string) error {
	if err := a.checkPreflight(ctx, preflight.FluxDirect); err != nil {
		return err
	}
	flux, err := a.requiredBinary(preflight.Flux)
	if err != nil {
		return err
	}
	return a.run(ctx, "Flux", flux, args...)
}

func (a *app) runVelero(ctx context.Context, args ...string) error {
	if err := a.checkPreflight(ctx, preflight.VeleroDirect); err != nil {
		return err
	}
	velero, err := a.requiredBinary(preflight.Velero)
	if err != nil {
		return err
	}
	return a.run(ctx, "Velero", velero, args...)
}
