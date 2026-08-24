package platform

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"atum/cli/delivery"
	"atum/cli/identity"
	"atum/cli/kube"
	"atum/cli/process"
	"atum/cli/progress"

	"k8s.io/apimachinery/pkg/util/wait"
)

const fluxComponents = "source-controller,kustomize-controller,helm-controller,notification-controller"

func (service Service) bootstrapFlux(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	handoff *Handoff,
	timeout time.Duration,
) error {
	if handoff == nil {
		return fmt.Errorf("verified platform handoff is unavailable")
	}
	forgejo := handoff.forgejo
	if forgejo == nil || forgejo.fluxToken == "" {
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
	progress.Start(ctx, progress.Platform, "flux", "Flux", "installing exact controllers before source admission")
	err := admitFluxRoot(fluxAdmissionSteps{
		installControllers: func() error {
			if err := service.runFlux(ctx, []string{
				"install",
				"--namespace=flux-system",
				"--version=" + version,
				"--components=" + fluxComponents,
				"--timeout=" + timeout.String(),
			}, []string{"KUBECONFIG=" + service.kubeconfig()}); err != nil {
				return fmt.Errorf("install Flux controllers before source admission: %w", err)
			}
			return nil
		},
		verifyCandidate: func() error {
			if err := forgejo.waitExactBranch(
				ctx, sources.Organization, sources.Repository, "main", bundle.SourceCommit,
			); err != nil {
				return fmt.Errorf("verify candidate platform source before identity projection: %w", err)
			}
			return nil
		},
		projectIdentity: func() error {
			if handoff.identityContract == nil {
				return nil
			}
			projection, err := service.deriveIdentityProjection(
				handoff.identityContract, handoff.credentials,
			)
			if err != nil {
				return err
			}
			err = consumeIdentityProjection(
				&projection,
				func(projection *identity.BootstrapProjection) error {
					return service.Orchestration.ProjectPlatformIdentity(ctx, projection)
				},
			)
			if err != nil {
				return fmt.Errorf("project platform identity before Flux source admission: %w", err)
			}
			return nil
		},
		activateSource: func() error {
			return activateSourceOnce(&handoff.activated, func() error {
				progress.Start(ctx, progress.Platform, "forgejo", "Forgejo sources",
					"advancing the planner-approved platform source after identity admission")
				if err := forgejo.activateAtumSource(
					ctx, bundle, sources.Organization, sources.Repository,
				); err != nil {
					progress.Fail(ctx, progress.Platform, "forgejo", "Forgejo sources", err)
					return fmt.Errorf("activate exact platform source: %w", err)
				}
				progress.Update(ctx, progress.Platform, "forgejo", "Forgejo sources",
					"deployed branch advanced with lease", 1, len(bundle.Repositories)+1)
				if err := forgejo.activateUpstreams(
					ctx,
					bundle.Repositories,
					sources.UpstreamOrganization,
					service.Project.Desired.Updates.Parallelism,
				); err != nil {
					progress.Fail(ctx, progress.Platform, "forgejo", "Forgejo sources", err)
					return fmt.Errorf("activate exact upstream sources: %w", err)
				}
				progress.Done(ctx, progress.Platform, "forgejo", "Forgejo sources",
					"platform and upstream branches advanced with leases")
				return nil
			})
		},
		verifyDeployed: func() error {
			if err := forgejo.waitExactBranch(
				ctx, sources.Organization, sources.Repository, deployedBranch, bundle.SourceCommit,
			); err != nil {
				return fmt.Errorf("verify deployed platform source before Flux bootstrap: %w", err)
			}
			return nil
		},
		bootstrapRoot: func() error {
			if err := service.runFlux(ctx, []string{
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
			}, []string{
				"GIT_PASSWORD=" + forgejo.fluxToken,
				"KUBECONFIG=" + service.kubeconfig(),
			}); err != nil {
				return fmt.Errorf("bootstrap Flux from exact Forgejo source: %w", err)
			}
			if err := forgejo.waitExactBranch(
				ctx, sources.Organization, sources.Repository, deployedBranch, bundle.SourceCommit,
			); err != nil {
				return fmt.Errorf("Flux bootstrap changed the declarative source branch: %w", err)
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	progress.Update(ctx, progress.Platform, "flux", "Flux", "controllers installed; reconciling source", 0, 0)
	if err := service.runFlux(ctx, []string{
		"reconcile", "kustomization", "flux-system",
		"--namespace=flux-system",
		"--with-source",
		"--timeout=" + timeout.String(),
	}, []string{"KUBECONFIG=" + service.kubeconfig()}); err != nil {
		return fmt.Errorf("reconcile Flux root Kustomization: %w", err)
	}
	if !deploymentsReady(ctx, client, "flux-system", strings.Split(fluxComponents, ",")) {
		return fmt.Errorf("Flux bootstrap returned before every controller was available")
	}
	progress.Done(ctx, progress.Platform, "flux", "Flux", "controllers and exact source ready")
	return nil
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

type fluxAdmissionSteps struct {
	installControllers func() error
	verifyCandidate    func() error
	projectIdentity    func() error
	activateSource     func() error
	verifyDeployed     func() error
	bootstrapRoot      func() error
}

func admitFluxRoot(steps fluxAdmissionSteps) error {
	for _, step := range [...]func() error{
		steps.installControllers,
		steps.verifyCandidate,
		steps.projectIdentity,
		steps.activateSource,
		steps.verifyDeployed,
		steps.bootstrapRoot,
	} {
		if step == nil {
			return fmt.Errorf("Flux admission step is unavailable")
		}
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func activateSourceOnce(activated *bool, activate func() error) error {
	if activated == nil {
		return fmt.Errorf("source activation state is unavailable")
	}
	if *activated {
		return nil
	}
	if activate == nil {
		return fmt.Errorf("source activation writer is unavailable")
	}
	if err := activate(); err != nil {
		return err
	}
	*activated = true
	return nil
}

func (service Service) waitPrep(ctx context.Context, client *kube.Observer, timeout time.Duration) error {
	progress.Start(ctx, progress.Platform, "prep", "Platform prerequisites", "waiting for Flux reconciliation")
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		ready := client.ResourceReady(ctx, kube.Kustomization, "flux-system", "prep") &&
			client.ResourceReady(ctx, kube.Kustomization, "flux-system", "platform-profile-prep")
		if ready {
			progress.Done(ctx, progress.Platform, "prep", "Platform prerequisites", "common and target prerequisites ready")
		} else {
			progress.Update(ctx, progress.Platform, "prep", "Platform prerequisites", "Flux reconciliation in progress", 0, 0)
		}
		return ready, nil
	})
	if err != nil {
		progress.Fail(ctx, progress.Platform, "prep", "Platform prerequisites", err)
		return fmt.Errorf("wait for Flux preparation Kustomization: %w", err)
	}
	return nil
}

func (service Service) runFlux(ctx context.Context, arguments, environment []string) error {
	binary := service.FluxBin
	if binary == "" {
		return fmt.Errorf("validated Flux preflight identity is required")
	}
	if service.Runner == nil {
		return fmt.Errorf("Flux runner is unavailable")
	}
	return service.Runner.Run(ctx, process.Command{
		Name:   binary,
		Args:   append([]string(nil), arguments...),
		Dir:    service.Project.Root,
		Env:    append([]string(nil), environment...),
		Stdout: service.Out,
		Stderr: service.Out,
	})
}
