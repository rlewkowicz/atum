package command

import (
	"context"
	"errors"

	"atum/cli/infra"
	"atum/cli/preflight"
)

func (a *app) checkPreflight(ctx context.Context, scope preflight.Scope) error {
	return a.checkPreflightWithForwarding(ctx, scope, infra.ForwardingPlan{})
}

func (a *app) checkForwardingPreflight(ctx context.Context, plan infra.ForwardingPlan) error {
	return a.checkPreflightWithForwarding(ctx, preflight.LibvirtForwarding, plan)
}

func (a *app) checkPreflightWithForwarding(
	ctx context.Context,
	scope preflight.Scope,
	plan infra.ForwardingPlan,
) error {
	report, err := (preflight.Service{
		Project:        a.project,
		Runner:         a.runner,
		Environment:    a.env,
		Parallelism:    a.project.Desired.Updates.Parallelism,
		ForwardingPlan: plan,
	}).Check(ctx, scope)
	a.preflight = report
	return err
}

func (a *app) checkAccessPreflight(
	ctx context.Context,
	scope preflight.Scope,
	capabilities infra.AccessCapabilities,
	trustStore infra.TrustStoreDescriptor,
	trustUpdater infra.TrustUpdater,
	sudo string,
) error {
	report, err := (preflight.Service{
		Project: a.project, Runner: a.runner, Environment: a.env,
		Parallelism:        a.project.Desired.Updates.Parallelism,
		AccessCapabilities: capabilities,
		AccessTrustStore:   trustStore,
		AccessTrustUpdater: trustUpdater,
		AccessSudo:         sudo,
	}).Check(ctx, scope)
	a.preflight = report
	return err
}

func (a *app) checkDeliveryPreflight(ctx context.Context) (string, error) {
	if err := a.checkPreflight(ctx, preflight.Delivery); err != nil {
		return "", err
	}
	docker := a.preflight.Binary(preflight.Docker)
	if docker == "" {
		return "", errors.New("delivery preflight returned no validated Docker binary")
	}
	return docker, nil
}

func (a *app) requiredBinary(tool preflight.Tool) (string, error) {
	binary := a.preflight.Binary(tool)
	if binary == "" {
		return "", errors.New("validated " + string(tool) + " preflight identity is required")
	}
	return binary, nil
}
