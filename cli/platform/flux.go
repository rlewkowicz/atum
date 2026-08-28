package platform

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/identity"
	"atum/cli/process"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
)

// bootstrapFlux is deliberately linear. Flux bootstrap owns controller
// installation and the root source; Atum owns only exact source publication,
// credentials, and the SOPS key projection that must precede reconciliation.
func (service Service) bootstrapFlux(
	ctx context.Context,
	publication *delivery.Publication,
	handoff *Handoff,
	timeout time.Duration,
) error {
	if handoff == nil {
		return fmt.Errorf("verified platform handoff is unavailable")
	}
	forgejo := handoff.forgejo
	if forgejo == nil || len(forgejo.fluxToken) == 0 {
		return fmt.Errorf("Forgejo read credentials are unavailable")
	}
	sources := service.Project.Desired.Platform.Sources
	version := service.Project.Desired.Platform.Flux.Version
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	repositoryURL := strings.TrimSuffix(sources.ClusterURL, "/") + "/" +
		sources.Organization + "/" + sources.Repository + ".git"
	clusterPath := filepath.ToSlash(filepath.Join(
		service.Project.Desired.Platform.Directory,
		"clusters",
		service.Project.Desired.Project.Cluster,
	))
	registry := strings.TrimSuffix(service.Project.Desired.Delivery.Registry.Host, "/") +
		"/" + strings.Trim(service.Project.Desired.Delivery.Registry.Project, "/")
	environment := []string{"KUBECONFIG=" + service.kubeconfig()}

	progress.Start(ctx, progress.Platform, "flux", "Flux", "checking bootstrap prerequisites")
	if err := service.runFlux(ctx, []string{"check", "--pre"}, environment); err != nil {
		return fmt.Errorf("check Flux bootstrap prerequisites: %w", err)
	}
	if err := forgejo.waitExactBranch(
		ctx, sources.Organization, sources.Repository, "main", publication.SourceCommit,
	); err != nil {
		return fmt.Errorf("verify candidate platform source: %w", err)
	}

	credentials, err := atumsecrets.Load(ctx, service.Project, service.SOPS)
	if err != nil {
		return fmt.Errorf("load required platform secrets: %w", err)
	}
	defer credentials.Clear()
	statefulProjection, err := credentials.DeriveStatefulProjection()
	if err != nil {
		return fmt.Errorf("derive required platform secrets: %w", err)
	}
	defer statefulProjection.Clear()
	if handoff.identityContract == nil {
		return errors.New("local platform identity contract is unavailable")
	}
	identityProjection, err := service.deriveIdentityProjection(
		handoff.identityContract, credentials,
	)
	if err != nil {
		return err
	}
	defer identityProjection.Clear()
	ageIdentity, err := atumsecrets.EnsureFluxAgeIdentity(ctx, service.Project)
	if err != nil {
		return err
	}
	defer ageIdentity.Clear()
	rootCADigest, err := credentials.RootCADigest()
	if err != nil {
		return err
	}
	if err := atumsecrets.ValidateFluxSource(
		service.Project,
		publication.SourceRoot,
		statefulProjection.Digest(),
		identityProjection.Digest(),
		rootCADigest,
		ageIdentity.Recipient(),
	); err != nil {
		return fmt.Errorf("validate declarative Flux secret source: %w", err)
	}
	statefulProjection.Clear()
	identityProjection.Clear()
	credentials.Clear()

	fluxEnvironment := []string{
		"GIT_PASSWORD=" + string(forgejo.fluxToken.Bytes()),
		"KUBECONFIG=" + service.kubeconfig(),
	}
	fluxErr := service.runFlux(ctx, []string{
		"bootstrap", "git",
		"--url=" + repositoryURL,
		"--username=" + forgejo.username,
		"--branch=main",
		"--path=" + clusterPath,
		"--version=" + version,
		"--components=" + config.FluxBootstrapComponents,
		"--registry=" + registry,
		"--allow-insecure-http",
		"--token-auth",
		"--silent",
		"--author-name=Atum",
		"--author-email=atum@localhost",
		"--timeout=" + timeout.String(),
	}, fluxEnvironment)
	forgejo.fluxToken.Clear()
	if fluxErr != nil {
		return fmt.Errorf("bootstrap Flux from exact Forgejo source: %w", fluxErr)
	}
	if err := forgejo.waitExactBranch(
		ctx, sources.Organization, sources.Repository, "main", publication.SourceCommit,
	); err != nil {
		return fmt.Errorf("Flux bootstrap changed the declarative main source: %w", err)
	}
	if err := service.Orchestration.ProjectFluxSOPSIdentity(ctx, ageIdentity); err != nil {
		return err
	}
	ageIdentity.Clear()
	progress.Done(ctx, progress.Platform, "flux", "Flux", "bootstrap installed from exact main source")
	return nil
}

func consumeStatefulProjection(
	projection **atumsecrets.StatefulProjection,
	project func(*atumsecrets.StatefulProjection) error,
) error {
	if projection == nil || *projection == nil {
		return fmt.Errorf("required stateful projection is unavailable")
	}
	current := *projection
	defer func() {
		current.Clear()
		*projection = nil
	}()
	if project == nil {
		return fmt.Errorf("stateful projection writer is unavailable")
	}
	return project(current)
}

func consumeIdentityProjection(
	projection **identity.BootstrapProjection,
	project func(*identity.BootstrapProjection) error,
) error {
	if projection == nil || *projection == nil {
		return nil
	}
	current := *projection
	defer func() {
		current.Clear()
		*projection = nil
	}()
	if project == nil {
		return fmt.Errorf("identity projection writer is unavailable")
	}
	return project(current)
}

func (service Service) runFlux(ctx context.Context, arguments, environment []string) error {
	binary := service.FluxBin
	if binary == "" {
		return fmt.Errorf("validated Flux preflight identity is required")
	}
	if service.Runner == nil {
		return fmt.Errorf("Flux runner is unavailable")
	}
	commandEnvironment := append([]string(nil), environment...)
	defer func() {
		for index := range commandEnvironment {
			commandEnvironment[index] = ""
		}
		clear(commandEnvironment)
		for index := range environment {
			environment[index] = ""
		}
		clear(environment)
	}()
	return service.Runner.Run(ctx, process.Command{
		Name:   binary,
		Args:   append([]string(nil), arguments...),
		Dir:    service.Project.Root,
		Env:    commandEnvironment,
		Stdout: service.Out,
		Stderr: service.Out,
	})
}
