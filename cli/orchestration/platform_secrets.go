package orchestration

import (
	"context"
	"errors"
	"fmt"

	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
)

// ProjectFluxSOPSIdentity transfers only the Flux decryption credential over
// the shared bounded private-input path after Flux bootstrap has created its
// namespace. Application Secrets remain owned by Flux's encrypted Git source.
func (service Service) ProjectFluxSOPSIdentity(
	ctx context.Context,
	projection *atumsecrets.FluxAgeIdentity,
) error {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	data, err := projection.MarshalAnsibleJSON()
	if err != nil {
		return err
	}
	defer clear(data)
	arguments := privateProjectionArguments(
		service.installInventoryPath(),
		service.Project.Desired.Orchestration.Directory,
		"platform-secrets.yml",
	)
	activity := progress.Target{Phase: progress.Platform, ID: "flux", Label: "Flux"}
	if err := service.runAnsibleInput(ctx, activity, arguments, data); err != nil {
		return fmt.Errorf("apply Flux SOPS decryption credential: %w", err)
	}
	return nil
}
