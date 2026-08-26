package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/process"
	"atum/cli/progress"

	"golang.org/x/sys/unix"
)

const (
	maxSSHControlDirectoryLength    = 64
	maxPrivateAnsibleInputBytes     = 64 << 10
	privateAnsibleFIFOOpenInterval  = 10 * time.Millisecond
	privateAnsibleFIFOWritePoll     = 100
	privateAnsibleFIFOCreationLimit = 16
	installConnectionTimeoutSeconds = 900
	installConnectionRetrySeconds   = 5
	installConnectionAttemptSeconds = 10
)

const privateAnsibleInputPlaceholder = "@atum-private-input"

var privateAnsibleFIFOSequence atomic.Uint64

func (service Service) RunAnsible(ctx context.Context, activity progress.Target, args []string) error {
	return service.runAnsibleInput(ctx, activity, args, nil)
}

func (service Service) runAnsibleInput(
	ctx context.Context,
	activity progress.Target,
	args []string,
	input []byte,
) (resultErr error) {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	if err := validatePrivateAnsibleInput(input); err != nil {
		return err
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
	command := process.Command{
		Name:     toolchain.Ansible,
		Args:     append([]string(nil), args...),
		Dir:      service.Project.Root,
		Env:      environment,
		Activity: activity,
	}
	if input == nil {
		return service.runAnsiblePlaybook(ctx, command)
	}

	runtimeDirectory, err := service.ansibleControlDirectory()
	if err != nil {
		return err
	}
	fifoPath, err := createPrivateAnsibleFIFO(runtimeDirectory)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, removePrivateAnsibleFIFO(fifoPath))
	}()
	command.Args, err = bindPrivateAnsibleArguments(command.Args, fifoPath)
	if err != nil {
		return err
	}
	writerContext, cancelWriter := context.WithCancel(ctx)
	writerResult := streamPrivateAnsibleInput(writerContext, fifoPath, input)
	runErr := service.runAnsiblePlaybook(ctx, command)
	cancelWriter()
	writerErr := <-writerResult
	if runErr != nil {
		return runErr
	}
	if writerErr != nil {
		return fmt.Errorf("stream private Ansible input: %w", writerErr)
	}
	return nil
}

func validatePrivateAnsibleInput(input []byte) error {
	if input == nil {
		return nil
	}
	if len(input) > maxPrivateAnsibleInputBytes {
		return fmt.Errorf(
			"private Ansible input exceeds %d bytes",
			maxPrivateAnsibleInputBytes,
		)
	}
	return nil
}

func privateProjectionArguments(inventory, orchestrationDirectory, playbook string) []string {
	return []string{
		"--inventory", inventory,
		"--extra-vars", privateAnsibleInputPlaceholder,
		filepath.Join(orchestrationDirectory, "playbooks", playbook),
	}
}

func bindPrivateAnsibleArguments(arguments []string, fifoPath string) ([]string, error) {
	bound := append([]string(nil), arguments...)
	replacements := 0
	for index := range bound {
		if bound[index] == privateAnsibleInputPlaceholder {
			bound[index] = "@" + fifoPath
			replacements++
		}
	}
	if replacements != 1 {
		return nil, fmt.Errorf(
			"private Ansible arguments contain %d input placeholders",
			replacements,
		)
	}
	return bound, nil
}

func createPrivateAnsibleFIFO(runtimeDirectory string) (string, error) {
	for range privateAnsibleFIFOCreationLimit {
		sequence := privateAnsibleFIFOSequence.Add(1)
		path := filepath.Join(
			runtimeDirectory,
			".atum-extra-vars-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatUint(sequence, 10)+".fifo",
		)
		if err := unix.Mkfifo(path, 0o600); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("create private Ansible input FIFO: %w", err)
		}
		if err := unix.Chmod(path, 0o600); err != nil {
			_ = unix.Unlink(path)
			return "", fmt.Errorf("set private Ansible input FIFO mode: %w", err)
		}
		var status unix.Stat_t
		if err := unix.Lstat(path, &status); err != nil {
			_ = unix.Unlink(path)
			return "", fmt.Errorf("inspect private Ansible input FIFO: %w", err)
		}
		if status.Mode&unix.S_IFMT != unix.S_IFIFO ||
			int(status.Uid) != os.Geteuid() ||
			status.Mode&0o777 != 0o600 {
			_ = unix.Unlink(path)
			return "", errors.New("private Ansible input FIFO has an invalid identity or mode")
		}
		return path, nil
	}
	return "", errors.New("allocate a unique private Ansible input FIFO")
}

func removePrivateAnsibleFIFO(path string) error {
	var status unix.Stat_t
	if err := unix.Lstat(path, &status); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect private Ansible input FIFO for cleanup: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("private Ansible input FIFO changed before cleanup")
	}
	if err := unix.Unlink(path); err != nil {
		return fmt.Errorf("remove private Ansible input FIFO: %w", err)
	}
	return nil
}

func streamPrivateAnsibleInput(ctx context.Context, path string, input []byte) <-chan error {
	result := make(chan error, 1)
	go func() {
		fd, err := openPrivateAnsibleFIFOWriter(ctx, path)
		if err == nil {
			err = writePrivateAnsibleFIFO(ctx, fd, input)
			err = errors.Join(err, unix.Close(fd))
		}
		result <- err
	}()
	return result
}

func openPrivateAnsibleFIFOWriter(ctx context.Context, path string) (int, error) {
	ticker := time.NewTicker(privateAnsibleFIFOOpenInterval)
	defer ticker.Stop()
	for {
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENXIO) && !errors.Is(err, unix.EINTR) {
			return -1, fmt.Errorf("open private Ansible input FIFO: %w", err)
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-ticker.C:
		}
	}
}

func writePrivateAnsibleFIFO(ctx context.Context, fd int, input []byte) error {
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for len(input) > 0 {
		written, err := unix.Write(fd, input)
		if written > 0 {
			input = input[written:]
		}
		if err == nil {
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("write private Ansible input FIFO: %w", err)
		}
		if _, err := unix.Poll(poll, privateAnsibleFIFOWritePoll); err != nil &&
			!errors.Is(err, unix.EINTR) {
			return fmt.Errorf("wait for private Ansible input FIFO: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return nil
}

func (service Service) runKubespray(
	ctx context.Context,
	toolchain Toolchain,
	inventoryPath, playbook string,
	rawArgs []string,
) (resultErr error) {
	id := "kubernetes:" + toolchain.Release.Kubernetes
	label := "Kubernetes " + toolchain.Release.Kubernetes
	detail := "installing cluster"
	if playbook == "upgrade-cluster.yml" {
		detail = "upgrading nodes serially"
	}
	progress.Start(ctx, progress.Orchestration, id, label, detail)
	oidc, err := service.initialKubernetesOIDC()
	if err != nil {
		return fmt.Errorf("derive initial Kubernetes OIDC configuration: %w", err)
	}
	managed, offlineServer, err := service.kubesprayOfflineInputs(ctx, toolchain)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, offlineServer.Close())
	}()
	managed["serial"] = 1
	managed["kube_version"] = toolchain.Release.Kubernetes
	if oidc != nil {
		managed["atum_kubernetes_oidc"] = oidc
	}
	extraVars, err := json.Marshal(managed)
	if err != nil {
		return fmt.Errorf("encode managed Kubespray variables: %w", err)
	}
	args := managedKubesprayArguments(
		inventoryPath,
		service.Project.Desired.Orchestration.Forks,
		string(extraVars),
		filepath.Join(toolchain.Source, playbook),
		rawArgs,
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

func managedKubesprayArguments(
	inventoryPath string,
	forks int,
	extraVars string,
	playbookPath string,
	rawArgs []string,
) []string {
	args := make([]string, 0, len(rawArgs)+7)
	args = append(args,
		"--inventory", inventoryPath,
		"--forks", strconv.Itoa(forks),
		"--extra-vars", extraVars,
		playbookPath,
	)
	return append(args, rawArgs...)
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
