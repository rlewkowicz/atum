package process

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"atum/cli/progress"
)

type Runner interface {
	Run(ctx context.Context, command Command) error
}

type OutputRunner interface {
	Output(ctx context.Context, command Command) ([]byte, error)
}

type Identity struct {
	UID uint32
	GID uint32
}

type Command struct {
	Name     string
	Args     []string
	Dir      string
	Env      []string
	ExactEnv bool
	Identity *Identity
	Activity progress.Target
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, command Command) error {
	cmd := newExecCommand(ctx, command)
	defer clearEnvironment(cmd.Env)
	cmd.Stdin = command.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = command.Stdout
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = command.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func (ExecRunner) Output(ctx context.Context, command Command) ([]byte, error) {
	cmd := newExecCommand(ctx, command)
	defer clearEnvironment(cmd.Env)
	cmd.Stdin = command.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Stderr = command.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	return cmd.Output()
}

func clearEnvironment(environment []string) {
	for index := range environment {
		environment[index] = ""
	}
	clear(environment)
}

func newExecCommand(ctx context.Context, command Command) *exec.Cmd {
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if command.Identity != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: command.Identity.UID,
			Gid: command.Identity.GID,
		}
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = command.Dir
	if command.ExactEnv {
		cmd.Env = append([]string(nil), command.Env...)
	} else if len(command.Env) > 0 {
		cmd.Env = mergedEnvironment(os.Environ(), command.Env)
	}
	return cmd
}

func mergedEnvironment(base, overrides []string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	merge := func(entries []string) {
		for _, entry := range entries {
			name, _, found := strings.Cut(entry, "=")
			if found && name != "" {
				values[name] = entry
			}
		}
	}
	merge(base)
	merge(overrides)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, len(names))
	for index, name := range names {
		result[index] = values[name]
	}
	return result
}
