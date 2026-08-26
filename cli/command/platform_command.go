package command

import (
	"context"
	"encoding/json"
	"errors"

	"atum/cli/platform"
	"atum/cli/preflight"
	"atum/cli/tui"

	"github.com/spf13/cobra"
)

func (a *app) platformCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "platform",
		Aliases: []string{"plat"},
		Short:   "Prepare, reconcile, and inspect the Flux platform",
	}
	var prepareOptions platform.PrepareOptions
	prepare := &cobra.Command{
		Use:   "prepare",
		Short: "Publish exact seed artifacts and bootstrap Flux from Forgejo main",
		Args:  cobra.NoArgs,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			return a.withDashboard(cmd.Context(), "platform prepare", tui.ScopePlatform, func(ctx context.Context) error {
				if err := a.checkPreflight(ctx, preflight.Platform); err != nil {
					return err
				}
				if err := a.ensurePublication(ctx, preflight.Platform); err != nil {
					return err
				}
				service, err := a.managedPlatformService()
				if err != nil {
					return err
				}
				return service.Prepare(ctx, prepareOptions)
			})
		}),
	}
	prepare.Flags().DurationVar(
		&prepareOptions.Timeout,
		"timeout",
		platform.DefaultReadinessTimeout,
		"bounded readiness timeout",
	)
	prepare.Flags().IntVar(&prepareOptions.Parallelism, "parallelism", 0, "maximum concurrent OCI publications")

	var applyOptions platform.ApplyOptions
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Converge preparation services and the complete Big Bang platform",
		Args:  cobra.NoArgs,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			if err := a.checkPreflight(cmd.Context(), preflight.Platform); err != nil {
				return err
			}
			return a.withDashboardCompletion(
				cmd.Context(), "platform apply", tui.ScopePlatform,
				func(ctx context.Context) (tui.Completion, error) {
					if err := a.ensurePublication(ctx, preflight.Platform); err != nil {
						return tui.Completion{}, err
					}
					service, err := a.managedPlatformService()
					if err != nil {
						return tui.Completion{}, err
					}
					if err := service.Apply(ctx, applyOptions); err != nil {
						return tui.Completion{}, err
					}
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
	apply.Flags().DurationVar(
		&applyOptions.Timeout,
		"timeout",
		platform.DefaultReadinessTimeout,
		"bounded readiness timeout",
	)

	status := &cobra.Command{
		Use:         "status",
		Short:       "Report native Flux, delivery, and local-integration status",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"atum.dev/read-only": "true"},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			result, err := a.platformService().Status(cmd.Context())
			if err != nil {
				return err
			}
			if err := a.observePlatformHostAccess(cmd.Context(), &result); err != nil {
				return err
			}
			encoder := json.NewEncoder(a.out)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(result); err != nil {
				return err
			}
			if !result.Reconciliation.Complete() {
				return errors.New("Flux reconciliation is incomplete")
			}
			if !result.Delivery.Compliant() {
				return errors.New("platform delivery compliance is incomplete")
			}
			if !result.Local.Exact() {
				return errors.New("local platform integration is incomplete")
			}
			return nil
		}),
	}

	flux := &cobra.Command{
		Use:                "flux [args...]",
		Short:              "Pass arguments directly to the system Flux binary",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
			return a.withDashboard(cmd.Context(), "Flux", tui.ScopePlatform, func(ctx context.Context) error {
				return a.runFlux(ctx, args...)
			})
		}),
	}
	velero := &cobra.Command{
		Use:                "velero [args...]",
		Short:              "Pass backup and restore arguments directly to the system Velero binary",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, args []string) error {
			return a.withDashboard(cmd.Context(), "Velero", tui.ScopePlatform, func(ctx context.Context) error {
				return a.runVelero(ctx, args...)
			})
		}),
	}
	command.AddCommand(prepare, apply, status, flux, velero)
	return command
}

func (a *app) managedPlatformService() (platform.Service, error) {
	flux, err := a.requiredBinary(preflight.Flux)
	if err != nil {
		return platform.Service{}, err
	}
	service := a.platformService()
	service.FluxBin = flux
	return service, nil
}

func (a *app) platformService() platform.Service {
	orchestrationService := a.orchestrationService()
	return platform.Service{
		Project:       a.project,
		Publication:   a.publication,
		Logger:        a.logger,
		Runner:        a.runner,
		Environment:   a.env,
		DryRun:        a.dryRun,
		Out:           a.out,
		Orchestration: &orchestrationService,
		SOPS:          a.sops,
	}
}
