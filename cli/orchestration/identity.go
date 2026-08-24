package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/process"
	"atum/cli/progress"
)

const identityVariablesPath = ".atum/state/orchestration-identity.json"

func (service Service) writeIdentity(ctx context.Context, state ClusterState, prepared *Toolchain) error {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	platformConstraints := state.PlatformConstraints
	if platformConstraints == nil {
		platformConstraints = []config.CompatibilityConstraint{}
	}
	constraints, err := json.Marshal(platformConstraints)
	if err != nil {
		return fmt.Errorf("encode live platform constraints: %w", err)
	}
	variables := struct {
		Identity map[string]string `json:"atum_identity"`
	}{Identity: map[string]string{
		"schemaVersion":       identitySchema,
		"cluster":             service.Project.Desired.Project.Cluster,
		"desiredSha256":       service.Project.DesiredSHA256,
		"kubernetes":          state.Kubernetes,
		"kubesprayVersion":    state.KubesprayVersion,
		"kubesprayCommit":     state.KubesprayCommit,
		"bigBangVersion":      state.BigBangVersion,
		"bigBangCommit":       state.BigBangCommit,
		"platformConstraints": string(constraints),
		"orchestrationSha256": state.OrchestrationSHA256,
		"phase":               state.Phase,
		"targetKubernetes":    state.TargetKubernetes,
	}}
	data, err := config.MarshalJSON(variables)
	if err != nil {
		return fmt.Errorf("encode orchestration identity variables: %w", err)
	}
	if err := fssecure.WriteRegular(service.Project.Root, identityVariablesPath, data, 0o600); err != nil {
		return fmt.Errorf("write orchestration identity variables: %w", err)
	}
	variablesPath, err := fssecure.Resolve(service.Project.Root, identityVariablesPath, false)
	if err != nil {
		return err
	}
	arguments := []string{
		"--inventory", service.installInventoryPath(),
		"--extra-vars", "@" + variablesPath,
		filepath.Join(service.Project.Desired.Orchestration.Directory, "playbooks", "identity.yml"),
	}
	activity := progress.Target{Phase: progress.Orchestration, ID: "activity", Label: "Cluster identity"}
	if prepared == nil {
		if err := service.RunAnsible(ctx, activity, arguments); err != nil {
			return fmt.Errorf("reconcile cluster identity: %w", err)
		}
		return nil
	}
	environment, err := service.ansibleEnvironment(*prepared)
	if err != nil {
		return err
	}
	if err := service.runAnsiblePlaybook(ctx, process.Command{
		Name:     prepared.Ansible,
		Args:     arguments,
		Dir:      service.Project.Root,
		Env:      environment,
		Activity: activity,
	}); err != nil {
		return fmt.Errorf("reconcile cluster identity: %w", err)
	}
	return nil
}
