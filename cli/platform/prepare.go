package platform

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"atum/cli/delivery"
	"atum/cli/fssecure"
	"atum/cli/kube"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
)

func (service Service) Prepare(ctx context.Context, options PrepareOptions) error {
	if err := service.requireReadyCluster(ctx); err != nil {
		return err
	}
	if service.DryRun {
		service.logger().InfoContext(ctx, "platform preparation would publish exact sources and invoke Flux",
			"parallelism", options.Parallelism)
		return nil
	}
	credentials, bundle, err := service.platformInputs(ctx)
	if err != nil {
		return err
	}
	handoff, err := service.Seed(ctx, bundle, credentials, options)
	if err != nil {
		return err
	}
	return service.preparePlatform(ctx, handoff, options)
}

// Handoff carries one verified source and registry publication through the
// potentially long Kubespray convergence without repeating it. Its fields are
// deliberately private so callers cannot weaken the verified identities.
type Handoff struct {
	bundle      *delivery.DeploymentBundle
	forgejo     *forgejoControl
	credentials atumsecrets.Document
	publication publicationReceipt
	activated   bool
}

// Seed waits for the Terraform-owned bastion services and publishes the exact
// bundle before Kubernetes convergence begins. It does not access or mutate a
// cluster.
func (service Service) Seed(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	credentials atumsecrets.Document,
	options PrepareOptions,
) (*Handoff, error) {
	if err := service.Validate(); err != nil {
		return nil, err
	}
	if bundle == nil || service.Project.Lock.Bundle == nil ||
		bundle.ArchiveSHA256 != service.Project.Lock.Bundle.SHA256 ||
		bundle.Identity.ArchiveSHA256 != service.Project.Lock.Bundle.SHA256 {
		return nil, errors.New("exact deployment bundle is required")
	}
	if err := credentials.Validate(); err != nil {
		return nil, fmt.Errorf("validate seed credentials: %w", err)
	}
	timeout := timeoutOrDefault(options.Timeout)
	progress.Start(ctx, progress.Platform, "harbor-seed", "Seed Harbor publication", "waiting for bastion registry")
	registryCredentials, err := service.configureHarbor(ctx, credentials, timeout)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "harbor-seed", "Seed Harbor publication", err)
		return nil, err
	}
	progress.Update(ctx, progress.Platform, "harbor-seed", "Seed Harbor publication", "publishing exact OCI content", 0, len(bundle.Images)+len(bundle.Charts))
	if err := service.publishBundle(ctx, bundle, registryCredentials, options.Parallelism); err != nil {
		progress.Fail(ctx, progress.Platform, "harbor-seed", "Seed Harbor publication", err)
		return nil, fmt.Errorf("publish deployment bundle: %w", err)
	}
	progress.Done(ctx, progress.Platform, "harbor-seed", "Seed Harbor publication",
		fmt.Sprintf("%d images and %d charts published", len(bundle.Images), len(bundle.Charts)))
	progress.Start(ctx, progress.Platform, "forgejo", "Forgejo sources", "publishing exact source snapshots")
	forgejo, err := service.configureForgejo(ctx, bundle, credentials)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "forgejo", "Forgejo sources", err)
		return nil, err
	}
	progress.Done(ctx, progress.Platform, "forgejo", "Forgejo sources", "immutable sources ready for planner handoff")
	runtimeImages, err := bundle.RuntimeImageDigests(ctx)
	if err != nil {
		return nil, fmt.Errorf("retain seed runtime image receipt: %w", err)
	}
	return &Handoff{
		bundle:      bundle,
		forgejo:     forgejo,
		credentials: credentials,
		publication: publicationReceipt{
			registry: registryObservation{
				imageExact: true, chartsExact: true, chartsImmutable: true,
			},
			runtimeImages: runtimeImages,
		},
	}, nil
}

func (service Service) preparePlatform(
	ctx context.Context,
	handoff *Handoff,
	options PrepareOptions,
) error {
	if handoff == nil || handoff.bundle == nil || handoff.forgejo == nil {
		return errors.New("deployment bundle is required")
	}
	bundle := handoff.bundle
	timeout := timeoutOrDefault(options.Timeout)
	client, err := service.cluster()
	if err != nil {
		return err
	}
	progress.Start(ctx, progress.Platform, "bundle", "Deployment bundle", "importing on cluster nodes")
	if err := service.importBundle(ctx, bundle); err != nil {
		progress.Fail(ctx, progress.Platform, "bundle", "Deployment bundle", err)
		return err
	}
	if err := verifyClusterBundle(ctx, client, bundle.Identity); err != nil {
		progress.Fail(ctx, progress.Platform, "bundle", "Deployment bundle", err)
		return err
	}
	progress.Done(ctx, progress.Platform, "bundle", "Deployment bundle", "exact bundle imported")
	if !handoff.activated {
		progress.Start(ctx, progress.Platform, "forgejo", "Forgejo sources", "advancing the planner-approved platform source")
		sources := service.Project.Desired.Platform.Sources
		if err := handoff.forgejo.activateAtumSource(
			ctx, bundle, sources.Organization, sources.Repository,
		); err != nil {
			progress.Fail(ctx, progress.Platform, "forgejo", "Forgejo sources", err)
			return fmt.Errorf("activate exact platform source: %w", err)
		}
		progress.Update(ctx, progress.Platform, "forgejo", "Forgejo sources",
			"deployed branch advanced with lease", 1, len(bundle.Repositories)+1)
		if err := handoff.forgejo.activateUpstreams(
			ctx,
			bundle.Repositories,
			sources.UpstreamOrganization,
			service.Project.Desired.Updates.Parallelism,
		); err != nil {
			progress.Fail(ctx, progress.Platform, "forgejo", "Forgejo sources", err)
			return fmt.Errorf("activate exact upstream sources: %w", err)
		}
		handoff.activated = true
		progress.Done(ctx, progress.Platform, "forgejo", "Forgejo sources", "platform and upstream branches advanced with leases")
	}
	if handoff.forgejo.fluxToken == "" {
		token, err := handoff.forgejo.rotateFluxToken()
		if err != nil {
			return fmt.Errorf("rotate Flux read credential at platform handoff: %w", err)
		}
		handoff.forgejo.fluxToken = token
	}

	if err := service.bootstrapFlux(ctx, client, bundle, handoff.forgejo, timeout); err != nil {
		progress.Fail(ctx, progress.Platform, "flux", "Flux", err)
		return err
	}
	if err := service.waitPrep(ctx, client, timeout); err != nil {
		return err
	}
	service.logger().InfoContext(ctx, "platform preparation complete", "bundle", bundle.ArchiveSHA256)
	return nil
}

func (service Service) Apply(ctx context.Context, options ApplyOptions) error {
	if err := service.requireReadyCluster(ctx); err != nil {
		return err
	}
	if service.DryRun {
		service.logger().InfoContext(ctx, "platform application would publish sources, invoke Flux, and observe readiness")
		return nil
	}
	credentials, bundle, err := service.platformInputs(ctx)
	if err != nil {
		return err
	}
	handoff, err := service.Seed(ctx, bundle, credentials, PrepareOptions{Timeout: options.Timeout})
	if err != nil {
		return err
	}
	if err := service.preparePlatform(ctx, handoff, PrepareOptions{Timeout: options.Timeout}); err != nil {
		return err
	}
	return service.applyPlatform(
		ctx, handoff.bundle, handoff.credentials, handoff.publication, options)
}

func (service Service) platformInputs(
	ctx context.Context,
) (atumsecrets.Document, *delivery.DeploymentBundle, error) {
	credentials, err := service.credentials(ctx)
	if err != nil {
		return atumsecrets.Document{}, nil, err
	}
	bundle, err := service.deploymentBundle(ctx)
	if err != nil {
		return atumsecrets.Document{}, nil, err
	}
	return credentials, bundle, nil
}

func (service Service) ApplySeeded(ctx context.Context, handoff *Handoff, options ApplyOptions) error {
	if err := service.requireReadyCluster(ctx); err != nil {
		return err
	}
	if handoff == nil || handoff.bundle == nil || handoff.forgejo == nil {
		return errors.New("verified platform handoff is required")
	}
	if err := service.preparePlatform(ctx, handoff, PrepareOptions{Timeout: options.Timeout}); err != nil {
		return err
	}
	return service.applyPlatform(
		ctx, handoff.bundle, handoff.credentials, handoff.publication, options)
}

func (service Service) applyPlatform(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	credentials atumsecrets.Document,
	publication publicationReceipt,
	options ApplyOptions,
) error {
	if bundle == nil {
		return errors.New("deployment bundle is required")
	}
	timeout := timeoutOrDefault(options.Timeout)
	client, err := service.cluster()
	if err != nil {
		return err
	}
	progress.Start(ctx, progress.Platform, "bigbang", "Big Bang", "Flux reconciliation in progress")
	if err := service.waitPlatformReadiness(
		ctx, client, bundle, publication, timeout); err != nil {
		return err
	}
	status, err := service.statusWithBundle(ctx, client, bundle, credentials)
	if err != nil {
		return fmt.Errorf("verify converged platform: %w", err)
	}
	if !status.Ready() {
		return errors.New("Flux reconciliation completed without satisfying the exact readiness contract")
	}
	if err := service.Orchestration.RecordPlatform(ctx); err != nil {
		return fmt.Errorf("record platform identity: %w", err)
	}
	service.logger().InfoContext(ctx, "platform apply complete", "bundle", bundle.ArchiveSHA256)
	return nil
}

func (service Service) importBundle(ctx context.Context, bundle *delivery.DeploymentBundle) error {
	artifactRelative := service.Project.Lock.Bundle.File
	sidecarRelative := strings.TrimSuffix(artifactRelative, ".tar") + ".lock.json"
	artifact, err := fssecure.Resolve(service.Project.Root, artifactRelative, false)
	if err != nil {
		return err
	}
	sidecar, err := fssecure.Resolve(service.Project.Root, sidecarRelative, false)
	if err != nil {
		return err
	}
	inventory := filepath.Join(service.Project.Desired.Orchestration.Inventory, "hosts.yaml")
	playbook := filepath.Join(service.Project.Desired.Orchestration.Directory, "playbooks", "bundle-import.yml")
	if err := service.Orchestration.RunAnsible(ctx, progress.Target{
		Phase: progress.Platform,
		ID:    "bundle",
		Label: "Deployment bundle",
	}, []string{
		"--inventory", inventory,
		"--extra-vars", "atum_bundle_archive=" + artifact,
		"--extra-vars", "atum_bundle_lock=" + sidecar,
		playbook,
	}); err != nil {
		return fmt.Errorf("import deployment bundle %s: %w", bundle.ArchiveSHA256, err)
	}
	return nil
}

func verifyClusterBundle(ctx context.Context, client *kube.Observer, identity delivery.VerifiedBundle) error {
	current, found, err := client.ConfigMapData(ctx, "kube-system", "atum-bundle")
	if err != nil {
		return fmt.Errorf("read cluster deployment bundle identity: %w", err)
	}
	if !found {
		return errors.New("cluster deployment bundle identity is absent")
	}
	want := map[string]string{
		"schemaVersion": identity.SchemaVersion, "archiveSha256": identity.ArchiveSHA256,
		"desiredSha256": identity.DesiredSHA256, "inventorySha256": identity.InventorySHA256,
		"graphSha256": identity.GraphSHA256, "lockSha256": identity.LockSHA256,
		"sourceCommit": identity.SourceCommit,
	}
	for key, value := range want {
		if current[key] != value {
			return fmt.Errorf("cluster deployment bundle %s is %q, want %q", key, current[key], value)
		}
	}
	return nil
}
