package command

import (
	"fmt"

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
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			path, err := atumsecrets.Init(a.project, options)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(a.out, path)
			return err
		},
	}
	initialize.Flags().BoolVar(&options.Local, "local", false, "write the ignored mode-0600 local override")
	initialize.Flags().StringSliceVar(&options.AgeRecipients, "age-recipient", nil, "age recipient for the committed SOPS document (repeatable)")

	validate := &cobra.Command{
		Use:   "validate",
		Short: "Decrypt, merge, and validate platform credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			if a.dryRun {
				_, err = atumsecrets.Load(a.project)
			} else {
				_, err = atumsecrets.Ensure(cmd.Context(), a.project, a.logger)
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(a.out, "secrets are valid")
			return err
		},
	}
	command.AddCommand(initialize, validate)
	return command
}
