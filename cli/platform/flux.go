package platform

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"atum/cli/delivery"
	"atum/cli/identity"
	"atum/cli/process"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
)

const fluxComponents = "source-controller,kustomize-controller,helm-controller,notification-controller"

// bootstrapFlux is deliberately linear. Flux bootstrap owns controller
// installation and the root source; Atum owns only the publication, credential,
// and source-activation handoffs that must precede it.
func (service Service) bootstrapFlux(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
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
	environment := []string{"KUBECONFIG=" + service.kubeconfig()}

	progress.Start(ctx, progress.Platform, "flux", "Flux", "checking bootstrap prerequisites")
	if err := service.runFlux(ctx, []string{"check", "--pre"}, environment); err != nil {
		return fmt.Errorf("check Flux bootstrap prerequisites: %w", err)
	}
	if err := forgejo.waitExactBranch(
		ctx, sources.Organization, sources.Repository, "main", bundle.SourceCommit,
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
	if err := atumsecrets.ValidateFluxSource(
		service.Project,
		statefulProjection.Digest(),
		identityProjection.Digest(),
		ageIdentity.Recipient(),
	); err != nil {
		return fmt.Errorf("validate declarative Flux secret source: %w", err)
	}
	statefulProjection.Clear()
	identityProjection.Clear()
	credentials.Clear()

	progress.Update(ctx, progress.Platform, "forgejo", "Forgejo sources",
		"activating exact platform and upstream source snapshots", 0, len(bundle.Repositories)+1)
	if err := forgejo.activateAtumSource(
		ctx, bundle, sources.Organization, sources.Repository,
	); err != nil {
		return fmt.Errorf("activate exact platform source: %w", err)
	}
	if err := forgejo.activateUpstreams(
		ctx,
		bundle.Repositories,
		sources.UpstreamOrganization,
		service.Project.Desired.Updates.Parallelism,
	); err != nil {
		return fmt.Errorf("activate exact upstream sources: %w", err)
	}
	if err := forgejo.waitExactBranch(
		ctx, sources.Organization, sources.Repository, deployedBranch, bundle.SourceCommit,
	); err != nil {
		return fmt.Errorf("verify deployed platform source: %w", err)
	}
	fluxEnvironment := []string{
		"GIT_PASSWORD=" + string(forgejo.fluxToken.Bytes()),
		"KUBECONFIG=" + service.kubeconfig(),
	}
	fluxErr := service.runFlux(ctx, []string{
		"bootstrap", "git",
		"--url=" + repositoryURL,
		"--username=" + forgejo.username,
		"--branch=" + deployedBranch,
		"--path=" + clusterPath,
		"--version=" + version,
		"--components=" + fluxComponents,
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
		ctx, sources.Organization, sources.Repository, deployedBranch, bundle.SourceCommit,
	); err != nil {
		return fmt.Errorf("Flux bootstrap changed the declarative source branch: %w", err)
	}
	if err := service.Orchestration.ProjectFluxSOPSIdentity(ctx, ageIdentity); err != nil {
		return err
	}
	ageIdentity.Clear()
	if err := service.reconcileFluxKustomization(
		ctx, "platform-secrets", timeout,
	); err != nil {
		return err
	}
	if err := service.reconcileFluxKustomization(ctx, "flux-system", timeout); err != nil {
		return err
	}
	progress.Done(ctx, progress.Platform, "flux", "Flux", "bootstrap source reconciled")
	return nil
}

func (service Service) reconcileFluxKustomization(
	ctx context.Context,
	name string,
	timeout time.Duration,
) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("Flux Kustomization name is required")
	}
	progress.Start(ctx, progress.Platform, "flux-"+name, "Flux "+name, "reconciling native dependency graph")
	if err := service.runFlux(ctx, []string{
		"reconcile", "kustomization", name,
		"--namespace=flux-system",
		"--with-source",
		"--timeout=" + timeout.String(),
	}, []string{"KUBECONFIG=" + service.kubeconfig()}); err != nil {
		progress.Fail(ctx, progress.Platform, "flux-"+name, "Flux "+name, err)
		return fmt.Errorf("reconcile Flux Kustomization %s: %w", name, err)
	}
	progress.Done(ctx, progress.Platform, "flux-"+name, "Flux "+name, "native Ready condition reached")
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
