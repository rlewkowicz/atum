package command

import (
	"context"
	"fmt"
	"path/filepath"

	"atum/cli/process"
)

func (a *app) run(ctx context.Context, identity, name string, args ...string) error {
	command := process.Command{Name: name, Args: append([]string(nil), args...), Dir: a.root}
	return a.runCommand(ctx, identity, command)
}

func (a *app) ensureMutationAllowed() error {
	if err := a.ensureProjectLoaded(); err != nil {
		return err
	}
	return a.project.Validate()
}

func (a *app) ensureProjectLoaded() error {
	if a.project == nil {
		return fmt.Errorf("Atum project is not loaded")
	}
	return nil
}

func (a *app) runCommand(ctx context.Context, identity string, command process.Command) error {
	if a.dryRun {
		a.logger.InfoContext(ctx, "dry-run external command", "tool", identity)
		return nil
	}
	a.logger.InfoContext(ctx, "running external command", "tool", identity)
	if err := a.runner.Run(ctx, command); err != nil {
		return fmt.Errorf("%s failed: %w", identity, err)
	}
	return nil
}

func (a *app) projectPath(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(a.root, name)
}
