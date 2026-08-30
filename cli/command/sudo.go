package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"atum/cli/preflight"
	"atum/cli/process"
)

const sudoAuthorizationRefreshInterval = time.Minute

type sudoAuthorizationContextKey struct{}

type sudoAuthorization struct {
	runner process.Runner
	sudo   string
	cancel context.CancelFunc
	done   chan struct{}

	refreshMu sync.Mutex
	errMu     sync.RWMutex
	err       error
}

func (a *app) withLocalAccessAuthorization(
	ctx context.Context,
	run func(context.Context) error,
) error {
	if run == nil {
		return errors.New("authorized operation is unavailable")
	}
	if a.dryRun {
		return run(ctx)
	}
	_, local, err := a.localAccessFacts()
	if err != nil {
		return err
	}
	if !local {
		return run(ctx)
	}
	sudo := a.preflight.Binary(preflight.Sudo)
	if sudo == "" {
		sudo = selectAccessSudo()
	}
	authorization, err := a.authorizeSudo(ctx, sudo)
	if err != nil {
		return err
	}
	defer authorization.Close()
	return run(context.WithValue(ctx, sudoAuthorizationContextKey{}, authorization))
}

func (a *app) authorizeSudo(
	ctx context.Context,
	sudo string,
) (*sudoAuthorization, error) {
	if sudo == "" {
		return nil, errors.New("sudo authorization is unavailable")
	}
	err := a.withTerminal(func(input io.Reader, output, errorOutput io.Writer) error {
		return a.runner.Run(ctx, process.Command{
			Name: sudo, Args: []string{"-v"}, Foreground: true,
			Stdin: input, Stdout: output, Stderr: errorOutput,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("sudo authorization failed: %w", err)
	}

	leaseContext, cancel := context.WithCancel(ctx)
	authorization := &sudoAuthorization{
		runner: a.runner,
		sudo:   sudo,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if err := authorization.refresh(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf(
			"sudo authorization cannot be reused non-interactively: %w", err)
	}
	go authorization.maintain(leaseContext)
	return authorization, nil
}

func (authorization *sudoAuthorization) maintain(ctx context.Context) {
	defer close(authorization.done)
	ticker := time.NewTicker(sudoAuthorizationRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := authorization.refresh(ctx); err != nil {
				if ctx.Err() == nil {
					authorization.setError(fmt.Errorf(
						"sudo authorization refresh failed: %w", err))
				}
				return
			}
		}
	}
}

func (authorization *sudoAuthorization) require(ctx context.Context, sudo string) error {
	if authorization == nil {
		return errors.New("sudo authorization is unavailable")
	}
	if authorization.sudo != sudo {
		return errors.New("sudo authorization identity changed")
	}
	authorization.errMu.RLock()
	err := authorization.err
	authorization.errMu.RUnlock()
	if err != nil {
		return err
	}
	if err := authorization.refresh(ctx); err != nil {
		err = fmt.Errorf("sudo authorization is no longer valid: %w", err)
		authorization.setError(err)
		return err
	}
	return nil
}

func (authorization *sudoAuthorization) refresh(ctx context.Context) error {
	authorization.refreshMu.Lock()
	defer authorization.refreshMu.Unlock()
	return authorization.runner.Run(ctx, process.Command{
		Name:  authorization.sudo,
		Args:  []string{"-n", "-v"},
		Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard,
	})
}

func (authorization *sudoAuthorization) setError(err error) {
	authorization.errMu.Lock()
	if authorization.err == nil {
		authorization.err = err
	}
	authorization.errMu.Unlock()
}

func (authorization *sudoAuthorization) Close() {
	if authorization == nil {
		return
	}
	authorization.cancel()
	<-authorization.done
}

func sudoAuthorizationFromContext(ctx context.Context) *sudoAuthorization {
	authorization, _ := ctx.Value(sudoAuthorizationContextKey{}).(*sudoAuthorization)
	return authorization
}
