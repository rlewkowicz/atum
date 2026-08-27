package command

import (
	"fmt"

	"atum/cli/preflight"
	atumsecrets "atum/cli/secrets"

	"github.com/spf13/cobra"
)

func (a *app) secretsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "secrets",
		Short: "Initialize and validate typed platform credentials",
	}
	var options atumsecrets.InitOptions
	initialize := &cobra.Command{
		Use:   "init",
		Short: "Generate SOPS-encrypted or local-only credentials",
		Args:  cobra.NoArgs,
		Annotations: map[string]string{
			"atum.dev/allow-missing-flux-secrets": "true",
		},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			if err := options.Validate(); err != nil {
				return err
			}
			if a.dryRun {
				target := a.project.Desired.Secrets.SOPSFile
				if options.Local {
					target = a.project.Desired.Secrets.LocalFile
				}
				a.logger.InfoContext(cmd.Context(), "secrets would be initialized", "path", target)
				return nil
			}
			if !options.Local {
				if err := a.checkPreflight(cmd.Context(), preflight.CommittedSecrets); err != nil {
					return err
				}
			}
			path, err := atumsecrets.Init(cmd.Context(), a.project, a.sops, options)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(a.out, path)
			return err
		}),
	}
	initialize.Flags().BoolVar(&options.Local, "local", false, "write the ignored mode-0600 local override")
	initialize.Flags().StringSliceVar(&options.AgeRecipients, "age-recipient", nil, "age recipient for the committed SOPS document (repeatable)")

	validate := &cobra.Command{
		Use:   "validate",
		Short: "Decrypt, merge, and validate platform credentials",
		Args:  cobra.NoArgs,
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			if err := a.checkPreflight(cmd.Context(), preflight.CommittedSecrets); err != nil {
				return err
			}
			var (
				document atumsecrets.Document
				err      error
			)
			if a.dryRun {
				document, err = atumsecrets.Load(cmd.Context(), a.project, a.sops)
			} else {
				document, err = atumsecrets.Ensure(
					cmd.Context(),
					a.project,
					a.sops,
					a.logger,
				)
			}
			if err != nil {
				return err
			}
			defer document.Clear()
			_, err = fmt.Fprintln(a.out, "secrets are valid")
			return err
		}),
	}
	render := &cobra.Command{
		Use:   "render",
		Short: "Render SOPS-encrypted Flux Secret manifests into platform",
		Args:  cobra.NoArgs,
		Annotations: map[string]string{
			"atum.dev/allow-missing-flux-secrets": "true",
		},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			if err := a.checkPreflight(cmd.Context(), preflight.CommittedSecrets); err != nil {
				return err
			}
			if a.dryRun {
				a.logger.InfoContext(
					cmd.Context(),
					"Flux secret source would be rendered",
					"cluster",
					a.project.Desired.Project.Cluster,
				)
				return nil
			}
			result, err := atumsecrets.RenderFluxSource(
				cmd.Context(), a.project, a.sops,
			)
			if err != nil {
				return err
			}
			for _, path := range result.Paths {
				if _, err := fmt.Fprintln(a.out, path); err != nil {
					return err
				}
			}
			return nil
		}),
	}
	command.AddCommand(initialize, validate, render)
	return command
}
