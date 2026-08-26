package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/infra"
	"atum/cli/orchestration"
	"atum/cli/platform"
	"atum/cli/preflight"
	"atum/cli/process"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
	"atum/cli/tui"
	"atum/cli/update"

	"github.com/spf13/cobra"
)

type Options struct {
	Runner       process.Runner
	OutputRunner process.OutputRunner
	In           io.Reader
	Out          io.Writer
	Err          io.Writer
	Env          func(string) string
}

type app struct {
	runner        process.Runner
	outputRunner  process.OutputRunner
	terminal      func(func(io.Reader, io.Writer, io.Writer) error) error
	in            io.Reader
	out           io.Writer
	err           io.Writer
	env           func(string) string
	logger        *slog.Logger
	project       *config.Project
	rootHint      string
	root          string
	logFormat     string
	dryRun        bool
	raw           bool
	projectUnlock func()
	preflight     preflight.Report
	publication   *delivery.Publication
	sops          atumsecrets.SOPSAdapter
	secretLoader  func(
		context.Context,
		*config.Project,
		atumsecrets.SOPSAdapter,
	) (atumsecrets.Document, error)
}

func New(options Options) *cobra.Command {
	if options.Runner == nil {
		options.Runner = process.ExecRunner{}
	}
	if options.OutputRunner == nil {
		if outputRunner, ok := options.Runner.(process.OutputRunner); ok {
			options.OutputRunner = outputRunner
		}
	}
	if options.Out == nil {
		options.Out = os.Stdout
	}
	if options.In == nil {
		options.In = os.Stdin
	}
	if options.Err == nil {
		options.Err = os.Stderr
	}
	if options.Env == nil {
		options.Env = os.Getenv
	}

	a := &app{
		runner:       options.Runner,
		outputRunner: options.OutputRunner,
		in:           options.In,
		out:          options.Out,
		err:          options.Err,
		env:          options.Env,
		logFormat:    "text",
		secretLoader: atumsecrets.Load,
	}

	rootCmd := &cobra.Command{
		Use:              "atum",
		Short:            "Converge Atum infrastructure, Kubernetes, and Big Bang",
		SilenceUsage:     true,
		SilenceErrors:    true,
		TraverseChildren: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if processType := commandAnnotation(cmd, "atum.dev/internal-process"); processType != "" {
				if err := enforceInternalProcessEnvironment(processType); err != nil {
					return err
				}
			}
			if err := a.configureLogger(); err != nil {
				return err
			}
			if commandAnnotation(cmd, "atum.dev/no-project") == "true" {
				return nil
			}
			if commandAnnotation(cmd, "atum.dev/update-writer") == "true" {
				root, err := config.Discover(a.rootHint)
				if err != nil {
					return err
				}
				a.root = root
				return nil
			}
			if err := a.loadProject(
				cmd.Context(),
				commandAnnotation(cmd, "atum.dev/allow-stale") == "true",
				commandAnnotation(cmd, "atum.dev/allow-missing-flux-secrets") == "true",
			); err != nil {
				return err
			}
			return a.ensureCommandAllowed(cmd)
		},
		PersistentPostRun: func(_ *cobra.Command, _ []string) {
			a.unlockProject()
		},
	}
	rootCmd.SetOut(options.Out)
	rootCmd.SetErr(options.Err)
	rootCmd.SetIn(options.In)
	rootCmd.PersistentFlags().BoolVar(&a.dryRun, "dry-run", false, "describe mutations without executing them")
	rootCmd.PersistentFlags().BoolVar(&a.raw, "raw", false, "stream subprocess output directly instead of rendering the deployment dashboard")
	rootCmd.PersistentFlags().StringVar(&a.rootHint, "root", "", "project root or path to atum.json")
	rootCmd.PersistentFlags().StringVar(&a.logFormat, "log-format", "text", "log format: text or json")

	rootCmd.AddCommand(
		a.validateCommand(),
		a.secretsCommand(),
		a.pullCommand(),
		a.imagesCommand(),
		a.infraCommand(),
		a.orchestrationCommand(),
		a.platformCommand(),
		a.applyCommand(),
		a.destroyCommand(),
		a.uninstallCommand(),
		hostAccessHelperCommand(),
		trustedHTTPSVerifierCommand(),
	)
	return rootCmd
}

func commandAnnotation(command *cobra.Command, key string) string {
	for current := command; current != nil; current = current.Parent() {
		if value := current.Annotations[key]; value != "" {
			return value
		}
	}
	return ""
}

func (a *app) ensureCommandAllowed(command *cobra.Command) error {
	if commandAnnotation(command, "atum.dev/read-only") == "true" {
		return nil
	}
	if commandAnnotation(command, "atum.dev/allow-missing-flux-secrets") == "true" {
		return nil
	}
	if err := a.ensureMutationAllowed(); err != nil {
		a.unlockProject()
		return err
	}
	return nil
}

func (a *app) imagesCommand() *cobra.Command {
	images := &cobra.Command{
		Use:   "images",
		Short: "Publish locked images to Harbor",
	}
	var publishOptions delivery.PublishOptions
	publish := &cobra.Command{
		Use:         "publish",
		Short:       "Mirror official images and build selected compatibility images",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"atum.dev/allow-stale": "true"},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			return a.withDashboard(cmd.Context(), "image publication", tui.ScopePlatform, func(ctx context.Context) error {
				if a.dryRun {
					a.logger.InfoContext(ctx, "image publication would run", "profile", publishOptions.Profile, "group", publishOptions.Group)
					return nil
				}
				service, err := a.deliveryService(ctx)
				if err != nil {
					return err
				}
				result, err := service.Publish(ctx, publishOptions)
				if err != nil {
					return err
				}
				a.logger.InfoContext(ctx, "image publication complete",
					"profile", result.Lock.Profile,
					"published", result.Published,
					"reused", result.Reused,
				)
				return nil
			})
		}),
	}
	bindPublishFlags(publish, &publishOptions)

	images.AddCommand(publish)
	return images
}

func (a *app) deliveryService(ctx context.Context) (*delivery.Service, error) {
	docker, err := a.checkDeliveryPreflight(ctx)
	if err != nil {
		return nil, err
	}
	service, err := delivery.NewService(a.root, a.logger, a.runner, a.env, docker)
	if err != nil {
		return nil, err
	}
	a.preflight = preflight.Report{}
	a.unlockProject()
	return service, nil
}

func bindPublishFlags(command *cobra.Command, options *delivery.PublishOptions) {
	command.Flags().StringVar(&options.Profile, "profile", "", "delivery profile (defaults to atum.json)")
	command.Flags().StringVar(
		&options.Group,
		"group",
		defaultImageGroup,
		"image scope: platform, prep, bigbang, build-system, or kubespray",
	)
	command.Flags().StringSliceVar(&options.Targets, "targets", nil, "specific image ids to publish")
	command.Flags().BoolVar(&options.Force, "force", false, "replace matching build and mirror results")
	command.Flags().IntVar(&options.Parallelism, "parallelism", 0, "maximum concurrent registry transfers (defaults to atum.json)")
}

func (a *app) configureLogger() error {
	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(a.logFormat)) {
	case "text":
		handler = slog.NewTextHandler(a.err, &slog.HandlerOptions{Level: slog.LevelInfo})
	case "json":
		handler = slog.NewJSONHandler(a.err, &slog.HandlerOptions{Level: slog.LevelInfo})
	default:
		return fmt.Errorf("unsupported log format %q", a.logFormat)
	}
	a.logger = slog.New(handler)
	return nil
}

func (a *app) loadProject(
	ctx context.Context,
	allowStale bool,
	allowMissingFluxSecrets bool,
) error {
	root, err := config.Discover(a.rootHint)
	if err != nil {
		return err
	}
	unlock, err := update.LockProject(ctx, root)
	if err != nil {
		return fmt.Errorf("lock project state: %w", err)
	}
	if err := update.RecoverLocked(root); err != nil {
		unlock()
		return fmt.Errorf("recover interrupted upstream update: %w", err)
	}
	project, err := config.LoadWithOptions(root, config.LoadOptions{
		AllowStale:              allowStale,
		AllowMissingFluxSecrets: allowMissingFluxSecrets,
	})
	if err != nil {
		unlock()
		return err
	}
	a.projectUnlock = unlock
	a.project = project
	a.preflight = preflight.Report{}
	a.sops = atumsecrets.SOPSAdapter{}
	a.root = project.Root
	return nil
}

func (a *app) unlockProject() {
	if a.projectUnlock != nil {
		a.projectUnlock()
		a.projectUnlock = nil
	}
}

func (a *app) withProjectUnlock(run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		defer a.unlockProject()
		return run(cmd, args)
	}
}

func (a *app) pullCommand() *cobra.Command {
	pull := &cobra.Command{
		Use:   "pull",
		Short: "Resolve declarative upstream updates",
	}
	var check bool
	var parallelism int
	updates := &cobra.Command{
		Use:         "updates [bigbang-commit]",
		Short:       "Resolve stable compatible upstream releases into Atum state",
		Args:        cobra.MaximumNArgs(1),
		Annotations: map[string]string{"atum.dev/update-writer": "true"},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
			bigBangCommit := ""
			if len(args) != 0 {
				bigBangCommit = args[0]
			}
			service := update.NewService(a.root, a.logger)
			result, err := service.Pull(cmd.Context(), update.Options{
				Check:         check || a.dryRun,
				BigBangCommit: bigBangCommit,
				Parallelism:   parallelism,
			})
			if err != nil {
				return err
			}
			if len(result.Changed) == 0 {
				a.logger.InfoContext(cmd.Context(), "upstream state is current")
				return nil
			}
			for _, path := range result.Changed {
				_, _ = fmt.Fprintln(a.out, path)
			}
			if check {
				return fmt.Errorf("%d managed files require upstream updates", len(result.Changed))
			}
			if a.dryRun {
				a.logger.InfoContext(cmd.Context(), "upstream state would be updated", "files", len(result.Changed))
				return nil
			}
			a.logger.InfoContext(cmd.Context(), "upstream state updated", "files", len(result.Changed))
			return nil
		}),
	}
	updates.Flags().BoolVar(&check, "check", false, "report available updates without changing tracked files")
	updates.Flags().IntVar(&parallelism, "parallelism", 0, "maximum concurrent update workers (defaults to atum.json, capped at 24 CPUs)")
	pull.AddCommand(updates)
	return pull
}

func (a *app) validateCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "validate",
		Short:       "Validate desired and resolved Atum state",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"atum.dev/read-only": "true"},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			target, err := a.project.Desired.Orchestration.TargetRelease()
			if err != nil {
				return err
			}
			deliveryState := "resolved"
			if a.project.Lock.Delivery.Pending() {
				deliveryState = "pending"
			}
			a.logger.InfoContext(cmd.Context(), "Atum state is valid",
				"root", a.project.Root,
				"cluster", a.project.Desired.Project.Cluster,
				"kubernetes", target.Kubernetes,
				"bigbang", a.project.Desired.Platform.BigBang.Version,
				"delivery", deliveryState,
				"images", len(a.project.Desired.Delivery.Images),
			)
			return nil
		}),
	}
}

func (a *app) infraCommand() *cobra.Command {
	command := &cobra.Command{
		Use:         "infra",
		Short:       "Converge the active Terraform infrastructure target",
		Annotations: map[string]string{"atum.dev/allow-stale": "true"},
	}
	for _, action := range []string{"plan", "apply", "destroy"} {
		action := action
		subcommand := &cobra.Command{
			Use:                action + " [terraform args...]",
			Short:              strings.ToUpper(action[:1]) + action[1:] + " the active infrastructure target",
			Args:               cobra.ArbitraryArgs,
			DisableFlagParsing: true,
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
				return a.runInfrastructureAction(cmd.Context(), action, args)
			}),
		}
		command.AddCommand(subcommand)
	}
	terraform := &cobra.Command{
		Use:                "terraform [args...]",
		Short:              "Pass arguments directly to Terraform for the active target",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
			return a.withDashboard(cmd.Context(), "Terraform", tui.ScopeInfrastructure, func(ctx context.Context) error {
				if err := a.checkPreflight(ctx, preflight.TerraformDirect); err != nil {
					return err
				}
				return a.runTerraform(ctx, args...)
			})
		}),
	}
	libvirt := &cobra.Command{Use: "libvirt", Short: "Manage local system-libvirt host integration"}
	libvirt.AddCommand(
		a.libvirtActionCommand("permissions", "Manage all-user libvirt permissions", a.runLibvirtPermissions),
		a.libvirtActionCommand("forwarding", "Manage bridge-scoped Docker forwarding rules", a.runLibvirtForwarding),
	)
	command.AddCommand(terraform, libvirt, a.accessCommand())
	return command
}

func (a *app) runInfrastructureAction(ctx context.Context, action string, args []string) error {
	preflightDone := false
	managedApply := action == "apply" && !terraformInformational(args)
	if managedApply {
		if err := a.checkPreflight(ctx, preflight.Infrastructure); err != nil {
			return err
		}
		preflightDone = true
	}
	return a.withDashboard(ctx, "infrastructure "+action, tui.ScopeInfrastructure, func(ctx context.Context) error {
		if !preflightDone {
			if err := a.checkPreflight(ctx, preflight.Infrastructure); err != nil {
				return err
			}
		}
		return a.runTerraformAction(ctx, action, args...)
	})
}

func (a *app) libvirtActionCommand(
	name, short string,
	run func(context.Context, string) error,
) *cobra.Command {
	command := &cobra.Command{Use: name, Short: short}
	for _, action := range []string{"install", "status", "uninstall"} {
		action := action
		subcommand := &cobra.Command{
			Use:   action,
			Short: strings.ToUpper(action[:1]) + action[1:] + " " + name,
			Args:  cobra.NoArgs,
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
				title := "libvirt " + name + " " + action
				return a.withDashboard(cmd.Context(), title, tui.ScopeInfrastructure, func(ctx context.Context) error {
					return run(ctx, action)
				})
			}),
		}
		if action == "status" {
			subcommand.Annotations = map[string]string{"atum.dev/read-only": "true"}
		}
		command.AddCommand(subcommand)
	}
	return command
}

func (a *app) orchestrationCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "orchestration",
		Aliases: []string{"orch"},
		Short:   "Prepare and converge the exact Kubespray release ladder",
	}
	command.AddCommand(
		&cobra.Command{
			Use:   "prepare",
			Short: "Hydrate exact Kubespray sources and Python tool caches",
			Args:  cobra.NoArgs,
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
				return a.withDashboard(cmd.Context(), "orchestration prepare", tui.ScopeOrchestration, func(ctx context.Context) error {
					if err := a.checkPreflight(ctx, preflight.OrchestrationPrepare); err != nil {
						return err
					}
					return a.runOrchestrationPrepare(ctx)
				})
			}),
		},
		&cobra.Command{
			Use:   "inventory",
			Short: "Generate the active cluster inventory from Terraform output",
			Args:  cobra.NoArgs,
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
				return a.withDashboard(cmd.Context(), "orchestration inventory", tui.ScopeOrchestration, func(ctx context.Context) error {
					if err := a.checkPreflight(ctx, preflight.OrchestrationInventory); err != nil {
						return err
					}
					return a.runOrchestrationInventory(ctx)
				})
			}),
		},
		&cobra.Command{
			Use:         "plan",
			Short:       "Discover live state and print the exact install or upgrade ladder",
			Args:        cobra.NoArgs,
			Annotations: map[string]string{"atum.dev/read-only": "true"},
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
				_, err := a.runOrchestrationPlan(cmd.Context())
				return err
			}),
		},
		a.orchestrationConvergeCommand("apply", orchestration.ApplyConvergence),
		a.orchestrationConvergeCommand("upgrade", orchestration.UpgradeConvergence),
		&cobra.Command{
			Use:                "ansible [ansible-playbook args...]",
			Short:              "Pass arguments directly to Ansible using the target Kubespray toolchain",
			Args:               cobra.ArbitraryArgs,
			DisableFlagParsing: true,
			RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
				return a.withDashboard(cmd.Context(), "Ansible", tui.ScopeOrchestration, func(ctx context.Context) error {
					return a.runAnsiblePlaybook(ctx, args...)
				})
			}),
		},
	)
	return command
}

func (a *app) orchestrationConvergeCommand(name string, mode orchestration.ConvergenceMode) *cobra.Command {
	return &cobra.Command{
		Use:                name + " [ansible-playbook options...]",
		Short:              strings.ToUpper(name[:1]) + name[1:] + " Kubernetes through the exact release ladder",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
			return a.withDashboard(cmd.Context(), "orchestration "+name, tui.ScopeOrchestration, func(ctx context.Context) error {
				if err := a.checkPreflight(ctx, preflight.OrchestrationConverge); err != nil {
					return err
				}
				return a.runOrchestrationConverge(ctx, mode, args...)
			})
		}),
	}
}

func (a *app) applyCommand() *cobra.Command {
	var applyOptions platform.ApplyOptions
	command := &cobra.Command{
		Use:   "apply",
		Short: "Converge infrastructure, Kubernetes, and the platform",
		Args:  cobra.NoArgs,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			if err := a.checkPreflight(cmd.Context(), preflight.Full); err != nil {
				return err
			}
			return a.withDashboardCompletion(
				cmd.Context(), "full deployment", tui.ScopeAll,
				func(ctx context.Context) (tui.Completion, error) {
					if err := a.ensurePublication(ctx, preflight.Full); err != nil {
						return tui.Completion{}, err
					}
					service := a.orchestrationService()
					preflight, err := service.Plan(ctx)
					if err != nil {
						return tui.Completion{}, fmt.Errorf("orchestration preflight: %w", err)
					}
					if err := service.ValidatePlan(preflight, orchestration.FullConvergence); err != nil {
						return tui.Completion{}, fmt.Errorf("orchestration preflight: %w", err)
					}
					var seed terraformSeed
					if !a.dryRun {
						seed, err = a.seedTerraformEnvironment(ctx)
						if err != nil {
							return tui.Completion{}, err
						}
						defer seed.Clear()
					}
					if err := a.runTerraformActionWithEnvironment(ctx, "apply", seed.environment); err != nil {
						return tui.Completion{}, err
					}
					seed.ClearEnvironment()
					if a.dryRun {
						return tui.Completion{}, a.printOrchestrationPlan(preflight)
					}
					platformService, err := a.managedPlatformService()
					if err != nil {
						return tui.Completion{}, err
					}
					handoff, err := platformService.Seed(
						ctx,
						seed.publication,
						seed.credentials,
						platform.PrepareOptions{},
					)
					seed.Clear()
					if err != nil {
						return tui.Completion{}, err
					}
					defer handoff.Clear()
					service.RootCAPEM = handoff.RootCAPEM()
					defer clear(service.RootCAPEM)
					if err := a.generateOrchestrationInventory(ctx, a.orchestrationInventoryPath()); err != nil {
						return tui.Completion{}, err
					}
					if err := a.runFullConvergence(
						ctx, service, platformService, handoff, applyOptions,
					); err != nil {
						return tui.Completion{}, err
					}
					// Host DNS and trust are local integration, not a cluster
					// control plane. Mutate them only after Flux reports its
					// complete native dependency graph ready.
					if err := a.ensureLocalDNS(ctx); err != nil {
						return tui.Completion{}, err
					}
					dns, err := a.startLocalDNSObservation(ctx)
					if err != nil {
						return tui.Completion{}, err
					}
					defer dns.Cancel()
					status, err := a.completePlatformApply(ctx, dns)
					if err != nil {
						return tui.Completion{}, err
					}
					return a.platformCompletion(ctx, status)
				})
		}),
	}
	command.Flags().DurationVar(
		&applyOptions.Timeout,
		"timeout",
		platform.DefaultReadinessTimeout,
		"bounded platform readiness timeout",
	)
	return command
}

func (a *app) verifyLocalAccessStatus(
	ctx context.Context,
	status *platform.Status,
	dns *infra.AccessStatus,
) error {
	target, found := a.project.Desired.ActiveTarget()
	if !found || target.LocalAccess == nil || a.dryRun {
		return nil
	}
	result, err := a.platformService().Status(ctx)
	if err != nil {
		return err
	}
	if err := a.observePlatformHostAccessWithDNS(ctx, &result, dns); err != nil {
		return err
	}
	if !result.Reconciliation.Complete() || !result.Delivery.Compliant() ||
		!result.Local.Exact() {
		return errors.New("local access is not exact")
	}
	*status = result
	return nil
}

func (a *app) completePlatformApply(
	ctx context.Context,
	dns *localDNSObservation,
) (platform.Status, error) {
	if err := a.ensureLocalCA(ctx); err != nil {
		return platform.Status{}, err
	}
	dnsStatus, err := dns.Wait()
	if err != nil {
		return platform.Status{}, err
	}
	var status platform.Status
	if err := a.verifyLocalAccessStatus(ctx, &status, &dnsStatus); err != nil {
		return platform.Status{}, err
	}
	finishPlatformApply(ctx)
	return status, nil
}

func finishPlatformApply(ctx context.Context) {
	progress.Finish(ctx, progress.Platform, progress.Complete, "platform healthy")
}

func (a *app) ensurePublication(ctx context.Context, scope preflight.Scope) error {
	progress.Start(ctx, progress.Platform, "publication", "Publication inputs", "resolving canonical local inputs")
	deliveryPending := a.project.Lock.Delivery.Pending()
	if a.dryRun {
		a.logger.InfoContext(ctx, "publication inputs would be resolved into ignored local state", "deliveryPending", deliveryPending)
		progress.Done(ctx, progress.Platform, "publication", "Publication inputs", "resolution planned")
		return nil
	}
	progress.Update(ctx, progress.Platform, "publication", "Publication inputs", "resolving exact local inputs", 0, 0)
	root := a.project.Root
	service, err := delivery.NewService(
		root,
		a.logger,
		a.runner,
		a.env,
		a.preflight.Binary(preflight.Docker),
	)
	if err != nil {
		return err
	}
	a.preflight = preflight.Report{}
	a.unlockProject()
	runtimeProject, publication, err := service.Prepare(ctx, delivery.PublishOptions{})
	if err != nil {
		err = fmt.Errorf("resolve local publication inputs: %w", err)
		progress.Fail(ctx, progress.Platform, "publication", "Publication inputs", err)
		return err
	}
	if err := a.loadProject(ctx, false, false); err != nil {
		err = fmt.Errorf("reload declarative state after local publication resolution: %w", err)
		progress.Fail(ctx, progress.Platform, "publication", "Publication inputs", err)
		return err
	}
	a.project = runtimeProject
	a.publication = publication
	a.preflight = preflight.Report{}
	if err := a.checkPreflight(ctx, scope); err != nil {
		return err
	}
	a.logger.InfoContext(ctx, "publication inputs ready", "source", publication.SourceSHA256, "deliveryPending", deliveryPending)
	progress.Done(ctx, progress.Platform, "publication", "Publication inputs", "resolved and verified")
	return nil
}

func (a *app) runFullConvergence(
	ctx context.Context,
	service orchestration.Service,
	platformService platform.Service,
	handoff *platform.Handoff,
	options platform.ApplyOptions,
) error {
	applyPlatform := func() error {
		return platformService.ApplySeeded(ctx, handoff, options)
	}
	platformApplied, err := a.convergeOrchestration(
		ctx,
		service,
		a.orchestrationInventoryPath(),
		nil,
		orchestration.FullConvergence,
		applyPlatform,
	)
	if err != nil {
		progress.Finish(ctx, progress.Orchestration, progress.Failed, err.Error())
		return err
	}
	progress.Finish(ctx, progress.Orchestration, progress.Complete, "cluster healthy")
	if platformApplied {
		return nil
	}
	return applyPlatform()
}
