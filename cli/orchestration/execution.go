package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/process"
	"atum/cli/progress"

	"golang.org/x/sys/unix"
)

const (
	maxSSHControlDirectoryLength    = 64
	installConnectionTimeoutSeconds = 900
	installConnectionRetrySeconds   = 5
	installConnectionAttemptSeconds = 10
)

func (service Service) RunAnsible(ctx context.Context, activity progress.Target, args []string) error {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	target, err := service.Project.Desired.Orchestration.TargetRelease()
	if err != nil {
		return err
	}
	toolchains, err := service.prepareReleases(ctx, []config.ClusterRelease{target})
	if err != nil {
		return err
	}
	if len(toolchains) == 0 {
		return errors.New("orchestration release ladder is empty")
	}
	toolchain := toolchains[len(toolchains)-1]
	environment, err := service.ansibleEnvironment(toolchain)
	if err != nil {
		return err
	}
	return service.runAnsiblePlaybook(ctx, process.Command{
		Name:     toolchain.Ansible,
		Args:     append([]string(nil), args...),
		Dir:      service.Project.Root,
		Env:      environment,
		Activity: activity,
	})
}

func (service Service) runKubespray(
	ctx context.Context,
	toolchain Toolchain,
	inventoryPath, playbook string,
	rawArgs []string,
) error {
	id := "kubernetes:" + toolchain.Release.Kubernetes
	label := "Kubernetes " + toolchain.Release.Kubernetes
	detail := "installing cluster"
	if playbook == "upgrade-cluster.yml" {
		detail = "upgrading nodes serially"
	}
	progress.Start(ctx, progress.Orchestration, id, label, detail)
	if err := validateManagedAnsibleOptions(rawArgs); err != nil {
		progress.Fail(ctx, progress.Orchestration, id, label, err)
		return err
	}
	oidc, err := service.initialKubernetesOIDC()
	if err != nil {
		return fmt.Errorf("derive initial Kubernetes OIDC configuration: %w", err)
	}
	extraVars, err := json.Marshal(struct {
		Serial         int                      `json:"serial"`
		KubeVersion    string                   `json:"kube_version"`
		KubernetesOIDC *kubesprayOIDCProjection `json:"atum_kubernetes_oidc,omitempty"`
	}{Serial: 1, KubeVersion: toolchain.Release.Kubernetes, KubernetesOIDC: oidc})
	if err != nil {
		return fmt.Errorf("encode managed Kubespray variables: %w", err)
	}
	args := make([]string, 0, len(rawArgs)+7)
	args = append(args, rawArgs...)
	args = append(args,
		"--inventory", inventoryPath,
		"--forks", strconv.Itoa(service.Project.Desired.Orchestration.Forks),
		"--extra-vars", string(extraVars),
		filepath.Join(toolchain.Source, playbook),
	)
	environment, err := service.ansibleEnvironment(toolchain)
	if err != nil {
		return err
	}
	if err := service.runAnsiblePlaybook(ctx, process.Command{
		Name: toolchain.Ansible,
		Args: args,
		Dir:  service.Project.Root,
		Env:  environment,
		Activity: progress.Target{
			Phase: progress.Orchestration,
			ID:    "activity",
			Label: "Kubespray activity",
		},
	}); err != nil {
		progress.Fail(ctx, progress.Orchestration, id, label, err)
		return err
	}
	progress.Update(ctx, progress.Orchestration, id, label, "playbook complete; checking cluster health", 0, 0)
	return nil
}

func (service Service) runAnsiblePlaybook(ctx context.Context, command process.Command) error {
	activity := command.Activity
	if activity.ID == "" {
		activity = progress.Target{Phase: progress.Orchestration, ID: "activity", Label: "Ansible activity"}
	}
	progress.Start(ctx, activity.Phase, activity.ID, activity.Label, "starting playbook")
	if err := service.run(ctx, command); err != nil {
		progress.Fail(ctx, activity.Phase, activity.ID, activity.Label, err)
		return err
	}
	progress.Done(ctx, activity.Phase, activity.ID, activity.Label, "playbook complete")
	return nil
}

func (service Service) waitForInstallConnections(
	ctx context.Context,
	toolchain Toolchain,
	inventoryPath string,
) error {
	progress.Start(ctx, progress.Orchestration, "connections", "Node connections", "waiting for SSH")
	environment, err := service.ansibleEnvironment(toolchain)
	if err != nil {
		return err
	}
	// Connection readiness is an Ansible controller action and does not
	// benefit from a persistent Mitogen interpreter. Running it through
	// Mitogen can strand a fresh host connection until the outer 15-minute
	// timeout even after SSH and Python are ready. Keep Mitogen for the actual
	// Kubespray playbooks and use the built-in bounded linear strategy here.
	environment = append(environment, "ANSIBLE_STRATEGY=linear")
	arguments := []string{
		"--inventory", inventoryPath,
		"--forks", strconv.Itoa(service.Project.Desired.Orchestration.Forks),
		"all",
		"--module-name", "ansible.builtin.wait_for_connection",
		"--args", fmt.Sprintf(
			"connect_timeout=%d sleep=%d timeout=%d",
			installConnectionAttemptSeconds,
			installConnectionRetrySeconds,
			installConnectionTimeoutSeconds,
		),
	}
	if err := service.run(ctx, process.Command{
		Name: toolchain.AnsibleAdHoc,
		Args: arguments,
		Dir:  service.Project.Root,
		Env:  environment,
	}); err != nil {
		err = fmt.Errorf("wait for fresh-cluster SSH readiness: %w", err)
		progress.Fail(ctx, progress.Orchestration, "connections", "Node connections", err)
		return err
	}
	progress.Done(ctx, progress.Orchestration, "connections", "Node connections", "reachable")
	return nil
}

func (service Service) ansibleEnvironment(toolchain Toolchain) ([]string, error) {
	if service.SSHBin == "" {
		return nil, errors.New("validated OpenSSH preflight identity is required")
	}
	controlDirectory, err := service.ansibleControlDirectory()
	if err != nil {
		return nil, err
	}
	environment := make([]string, 0, len(toolchain.Environment)+2)
	environment = append(environment, toolchain.Environment...)
	environment = append(environment,
		"ANSIBLE_SSH_EXECUTABLE="+service.SSHBin,
		"ANSIBLE_SSH_CONTROL_PATH_DIR="+controlDirectory,
	)
	return environment, nil
}

func (service Service) ansibleControlDirectory() (string, error) {
	if service.Project == nil {
		return "", errors.New("Atum project is not loaded")
	}
	controlDirectory, err := fssecure.EnsureDirectory(
		service.Project.Root,
		filepath.Join(".atum", "runtime", "ansible"),
		0o700,
	)
	if err != nil {
		return "", fmt.Errorf("create Ansible control directory: %w", err)
	}
	if len(controlDirectory) > maxSSHControlDirectoryLength {
		return "", fmt.Errorf("Ansible control directory exceeds %d bytes", maxSSHControlDirectoryLength)
	}
	if err := validatePrivateRuntimeDirectory(controlDirectory); err != nil {
		return "", err
	}
	return controlDirectory, nil
}

func validatePrivateRuntimeDirectory(path string) error {
	var status unix.Stat_t
	if err := unix.Stat(path, &status); err != nil {
		return fmt.Errorf("inspect Ansible runtime directory: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR || int(status.Uid) != os.Geteuid() || status.Mode&0o077 != 0 {
		return fmt.Errorf("Ansible runtime directory %s must be owned by uid %d with no group or other access", path, os.Geteuid())
	}
	return nil
}

func validateManagedAnsibleOptions(args []string) error {
	for _, argument := range args {
		if argument == "-" || argument == "--" || !strings.HasPrefix(argument, "-") {
			return fmt.Errorf(
				"managed Kubespray accepts options only; pass option values as --option=value or use atum orchestration ansible for arbitrary playbooks: %q",
				argument,
			)
		}
	}
	return nil
}
