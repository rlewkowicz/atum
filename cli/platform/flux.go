package platform

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"atum/cli/delivery"
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
	forgejo *forgejoControl,
	timeout time.Duration,
) error {
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
	progress.Start(ctx, progress.Platform, "flux", "Flux", "bootstrapping exact controllers and source")
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
	if err := forgejo.waitExactBranch(ctx, sources.Organization, sources.Repository, deployedBranch, bundle.SourceCommit); err != nil {
		return fmt.Errorf("Flux bootstrap changed the declarative source branch: %w", err)
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
