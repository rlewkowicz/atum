package command

import (
	"context"
	"errors"
	"io"

	"atum/cli/config"
	"atum/cli/progress"
	"atum/cli/tui"
)

// withDashboard owns one presentation session for a managed operation. Domain
// services keep emitting progress through context and subprocesses keep their
// native byte streams; this boundary decides whether those streams are shown
// directly or summarized while being retained in the private raw log.
func (a *app) withDashboard(
	parent context.Context,
	title string,
	scope tui.Scope,
	run func(context.Context) error,
) error {
	return a.withDashboardProject(parent, a.project, title, scope, run)
}

// withDashboardAtRoot owns presentation for a managed operation that must load
// and lock its own project state. The minimal project supplies only the
// repository root needed for private logs and update-specific phase layout.
func (a *app) withDashboardAtRoot(
	parent context.Context,
	title string,
	scope tui.Scope,
	run func(context.Context) error,
) error {
	return a.withDashboardProject(
		parent,
		&config.Project{Root: a.root},
		title,
		scope,
		run,
	)
}

func (a *app) withDashboardProject(
	parent context.Context,
	project *config.Project,
	title string,
	scope tui.Scope,
	run func(context.Context) error,
) error {
	if run == nil {
		return errors.New("managed operation is unavailable")
	}
	return a.withDashboardProjectCompletion(
		parent,
		project,
		title,
		scope,
		func(ctx context.Context) (tui.Completion, error) {
			return tui.Completion{}, run(ctx)
		},
	)
}

func (a *app) withDashboardCompletion(
	parent context.Context,
	title string,
	scope tui.Scope,
	run func(context.Context) (tui.Completion, error),
) error {
	return a.withDashboardProjectCompletion(
		parent,
		a.project,
		title,
		scope,
		run,
	)
}

func (a *app) withDashboardProjectCompletion(
	parent context.Context,
	project *config.Project,
	title string,
	scope tui.Scope,
	run func(context.Context) (tui.Completion, error),
) error {
	if project == nil {
		return errors.New("Atum project is not loaded")
	}
	if run == nil {
		return errors.New("managed operation is unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	session, err := tui.New(tui.Options{
		Project: project,
		Title:   title,
		Scope:   scope,
		Raw:     a.raw,
		Input:   a.in,
		Output:  a.out,
		Error:   a.err,
		Cancel:  cancel,
	})
	if err != nil {
		return err
	}

	originalRunner := a.runner
	originalOutputRunner := a.outputRunner
	originalTerminal := a.terminal
	originalOut := a.out
	originalErr := a.err
	originalLogger := a.logger
	a.runner = session.WrapRunner(originalRunner)
	if originalOutputRunner != nil {
		a.outputRunner = session.WrapOutputRunner(originalOutputRunner)
	}
	a.terminal = session.WithTerminal
	a.logger = session.Logger(a.logFormat)
	if !a.raw {
		a.out = session.LogWriter()
		a.err = session.LogWriter()
	}
	defer func() {
		a.runner = originalRunner
		a.outputRunner = originalOutputRunner
		a.terminal = originalTerminal
		a.out = originalOut
		a.err = originalErr
		a.logger = originalLogger
	}()

	ctx = progress.WithReporter(ctx, session)
	completion, runErr := run(ctx)
	if runErr == nil {
		if cancellation := ctx.Err(); cancellation != nil {
			completion = tui.Completion{}
			runErr = cancellation
		}
	}
	return session.Finish(completion, runErr)
}

func (a *app) withTerminal(
	work func(io.Reader, io.Writer, io.Writer) error,
) error {
	if work == nil {
		return errors.New("terminal callback is required")
	}
	if a.terminal != nil {
		return a.terminal(work)
	}
	return work(a.in, a.out, a.err)
}
