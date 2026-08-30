package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

const (
	destroyConfirmationPrompt            = "Are you sure? Type yes to destroy the active infrastructure target: "
	destroyKeepBastionConfirmationPrompt = "Are you sure? Type yes to destroy the cluster nodes and load balancer while retaining the seed bastion: "
	destroyConfirmationLimit             = 16
)

var errDestroyCancelled = errors.New("destroy cancelled")

func (a *app) destroyCommand() *cobra.Command {
	return a.destroyCommandWithMutation(func(ctx context.Context, terraformArgs []string) error {
		if err := a.uninstallActiveLocalAccess(ctx); err != nil {
			return fmt.Errorf("remove local workstation access: %w", err)
		}
		return a.runInfrastructureAction(ctx, "destroy", terraformArgs)
	})
}

func (a *app) destroyCommandWithMutation(mutate func(context.Context, []string) error) *cobra.Command {
	var force, keepBastion bool
	command := &cobra.Command{
		Use:   "destroy",
		Short: "Remove local access and destroy the active infrastructure target",
		Args:  cobra.NoArgs,
		Annotations: map[string]string{
			"atum.dev/allow-stale":      "true",
			projectLockBypassAnnotation: "true",
		},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			if !force && !a.dryRun {
				prompt := destroyConfirmationPrompt
				if keepBastion {
					prompt = destroyKeepBastionConfirmationPrompt
				}
				confirmed, err := confirmDestroy(a.in, a.out, prompt)
				if err != nil {
					return err
				}
				if !confirmed {
					if _, err := fmt.Fprintln(a.out, "Destroy cancelled."); err != nil {
						return err
					}
					return errDestroyCancelled
				}
			}
			return mutate(cmd.Context(), destroyTerraformArgs(keepBastion))
		}),
	}
	command.Flags().BoolVarP(
		&force,
		"force",
		"f",
		false,
		"destroy without interactive confirmation",
	)
	command.Flags().BoolVar(
		&keepBastion,
		"keep-bastion",
		false,
		"retain the seed bastion, its cache, network, and base image",
	)
	return command
}

func destroyTerraformArgs(keepBastion bool) []string {
	if !keepBastion {
		return nil
	}
	// Terraform has no negative target selector. This positive cluster-only
	// set retains the bastion, its data disk, seed plane, network, and base.
	return []string{
		"-target=libvirt_cloudinit_disk.load_balancer",
		"-target=libvirt_cloudinit_disk.node",
		"-target=libvirt_domain.load_balancer",
		"-target=libvirt_domain.node",
		"-target=libvirt_volume.load_balancer",
		"-target=libvirt_volume.node",
		"-target=libvirt_volume.node_data",
		"-target=terraform_data.node_storage_ready",
	}
}

func (a *app) uninstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "uninstall",
		Short:       "Remove Atum-managed local workstation access",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"atum.dev/allow-stale": "true"},
		RunE: a.withProjectUnlock(func(cmd *cobra.Command, _ []string) error {
			return a.runAccessAction(cmd.Context(), "uninstall")
		}),
	}
}

func (a *app) uninstallActiveLocalAccess(ctx context.Context) error {
	_, local, err := a.localAccessFacts()
	if err != nil || !local {
		return err
	}
	return a.runAccessAction(ctx, "uninstall")
}

func confirmDestroy(input io.Reader, output io.Writer, prompt string) (bool, error) {
	if _, err := io.WriteString(output, prompt); err != nil {
		return false, fmt.Errorf("write destroy confirmation prompt: %w", err)
	}
	reader := bufio.NewReaderSize(
		io.LimitReader(input, destroyConfirmationLimit),
		destroyConfirmationLimit,
	)
	answer, err := reader.ReadString('\n')
	if errors.Is(err, io.EOF) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read destroy confirmation: %w", err)
	}
	answer = strings.TrimSuffix(answer, "\n")
	answer = strings.TrimSuffix(answer, "\r")
	return answer == "yes", nil
}
