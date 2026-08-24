package orchestration

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"atum/cli/fssecure"
	"atum/cli/identity"
	"atum/cli/progress"
)

const platformIdentityVariablesPath = ".atum/state/platform-identity.json"

// ProjectPlatformIdentity performs the sole imperative credential handoff to
// Flux. The caller retains and clears the in-memory projection.
func (service Service) ProjectPlatformIdentity(
	ctx context.Context,
	projection *identity.BootstrapProjection,
) (resultErr error) {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	data, err := projection.MarshalAnsibleJSON()
	if err != nil {
		return err
	}
	if err := fssecure.WriteRegular(
		service.Project.Root, platformIdentityVariablesPath, data, 0o600,
	); err != nil {
		clear(data)
		return fmt.Errorf("write private platform identity variables: %w", err)
	}
	defer func() {
		clear(data)
		removeErr := fssecure.RemoveRegular(service.Project.Root, platformIdentityVariablesPath)
		if removeErr != nil {
			removeErr = fmt.Errorf("remove private platform identity variables: %w", removeErr)
		}
		resultErr = errors.Join(resultErr, removeErr)
	}()
	variablesPath, err := fssecure.Resolve(service.Project.Root, platformIdentityVariablesPath, false)
	if err != nil {
		return err
	}
	arguments := []string{
		"--inventory", service.installInventoryPath(),
		"--extra-vars", "@" + variablesPath,
		filepath.Join(service.Project.Desired.Orchestration.Directory, "playbooks", "platform-identity-secret.yml"),
	}
	activity := progress.Target{Phase: progress.Platform, ID: "flux", Label: "Flux"}
	if err := service.RunAnsible(ctx, activity, arguments); err != nil {
		return fmt.Errorf("apply Flux identity bootstrap Secret: %w", err)
	}
	return nil
}
