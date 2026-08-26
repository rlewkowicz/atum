package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"atum/cli/delivery"
	"atum/cli/identity"
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
	credentials, publication, err := service.platformInputs(ctx)
	if err != nil {
		return err
	}
	handoff, err := service.Seed(ctx, publication, credentials, options)
	credentials.Clear()
	if err != nil {
		return err
	}
	defer handoff.Clear()
	return service.preparePlatform(ctx, handoff, options)
}

// Handoff carries one verified source and registry publication through the
// potentially long Kubespray convergence without repeating it. Its fields are
// deliberately private so callers cannot weaken the verified identities.
type Handoff struct {
	publication      *delivery.Publication
	forgejo          *forgejoControl
	identityContract *identity.Contract
	rootCAPEM        []byte
}

func (handoff *Handoff) Clear() {
	if handoff == nil {
		return
	}
	if handoff.forgejo != nil {
		handoff.forgejo.clear()
	}
	handoff.publication = nil
	handoff.forgejo = nil
	handoff.identityContract = nil
	clear(handoff.rootCAPEM)
	handoff.rootCAPEM = nil
}

func (handoff *Handoff) RootCAPEM() []byte {
	if handoff == nil {
		return nil
	}
	return append([]byte(nil), handoff.rootCAPEM...)
}

// Seed waits for the Terraform-owned bastion services and publishes the exact
// publication before Kubernetes convergence begins. It does not access or mutate a
// cluster.
func (service Service) Seed(
	ctx context.Context,
	publication *delivery.Publication,
	credentials atumsecrets.Document,
	options PrepareOptions,
) (*Handoff, error) {
	if err := service.Validate(); err != nil {
		return nil, err
	}
	if publication == nil ||
		publication.SourceSHA256 == "" ||
		len(publication.Images) != len(service.Project.Desired.Delivery.Images) ||
		len(publication.Charts) != len(service.Project.Lock.Resolved.Artifacts) {
		return nil, errors.New("canonical publication inputs are required")
	}
	if err := credentials.Validate(); err != nil {
		return nil, fmt.Errorf("validate seed credentials: %w", err)
	}
	contract, err := service.identityContract()
	if err != nil {
		return nil, err
	}
	if err := service.validateFluxSourceBeforePublication(
		ctx,
		publication.SourceRoot,
		contract,
		credentials,
	); err != nil {
		return nil, err
	}
	timeout := timeoutOrDefault(options.Timeout)
	progress.Start(ctx, progress.Platform, "harbor-publication", "Harbor publication", "waiting for bastion registry")
	registryCredentials, err := service.configureHarbor(ctx, credentials, timeout)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "harbor-publication", "Harbor publication", err)
		return nil, err
	}
	defer registryCredentials.Clear()
	progress.Update(ctx, progress.Platform, "harbor-publication", "Harbor publication", "publishing exact OCI content", 0, len(publication.Images)+len(publication.Charts))
	if err := service.publishPublication(ctx, publication, registryCredentials, options.Parallelism); err != nil {
		progress.Fail(ctx, progress.Platform, "harbor-publication", "Harbor publication", err)
		return nil, fmt.Errorf("publish canonical platform content: %w", err)
	}
	progress.Done(ctx, progress.Platform, "harbor-publication", "Harbor publication",
		fmt.Sprintf("%d images and %d charts published", len(publication.Images), len(publication.Charts)))
	progress.Start(ctx, progress.Platform, "forgejo", "Forgejo sources", "publishing exact source snapshots")
	forgejo, err := service.configureForgejo(ctx, publication, credentials)
	if err != nil {
		progress.Fail(ctx, progress.Platform, "forgejo", "Forgejo sources", err)
		return nil, err
	}
	progress.Done(ctx, progress.Platform, "forgejo", "Forgejo sources", "immutable sources ready for planner handoff")
	if err := delivery.SaveReceipt(service.Project, publication); err != nil {
		forgejo.clear()
		return nil, fmt.Errorf("persist immutable publication receipt: %w", err)
	}
	handoff := &Handoff{
		publication:      publication,
		forgejo:          forgejo,
		identityContract: contract,
		rootCAPEM:        append([]byte(nil), credentials.RootCA.Certificate.Bytes()...),
	}
	return handoff, nil
}

func (service Service) validateFluxSourceBeforePublication(
	ctx context.Context,
	sourceRoot string,
	contract *identity.Contract,
	credentials atumsecrets.Document,
) error {
	stateful, err := credentials.DeriveStatefulProjection()
	if err != nil {
		return err
	}
	defer stateful.Clear()
	identityProjection, err := service.deriveIdentityProjection(
		contract,
		credentials,
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
		sourceRoot,
		stateful.Digest(),
		identityProjection.Digest(),
		rootCADigest,
		ageIdentity.Recipient(),
	); err != nil {
		return fmt.Errorf(
			"validate exact Flux secret source before publication: %w",
			err,
		)
	}
	return nil
}

func (service Service) preparePlatform(
	ctx context.Context,
	handoff *Handoff,
	options PrepareOptions,
) error {
	if handoff == nil || handoff.publication == nil || handoff.forgejo == nil {
		return errors.New("verified publication handoff is required")
	}
	publication := handoff.publication
	timeout := timeoutOrDefault(options.Timeout)
	if len(handoff.forgejo.fluxToken) == 0 {
		token, err := handoff.forgejo.rotateFluxToken(ctx)
		if err != nil {
			return fmt.Errorf("rotate Flux read credential at platform handoff: %w", err)
		}
		handoff.forgejo.fluxToken.Clear()
		handoff.forgejo.fluxToken = token
	}

	if err := service.bootstrapFlux(ctx, publication, handoff, timeout); err != nil {
		progress.Fail(ctx, progress.Platform, "flux", "Flux", err)
		return err
	}
	service.logger().InfoContext(ctx, "platform preparation complete", "source", publication.SourceSHA256)
	return nil
}

func (service Service) identityContract() (*identity.Contract, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return nil, errors.New("active infrastructure target is undefined")
	}
	if target.PlatformProfile != "local" {
		return nil, nil
	}
	relative, exists := service.Project.Desired.ActiveIdentityContractPath()
	if !exists {
		return nil, errors.New("local identity contract path is undefined")
	}
	contract, err := identity.Load(service.Project.Root, relative)
	if err != nil {
		return nil, err
	}
	return contract, nil
}

func (service Service) deriveIdentityProjection(
	contract *identity.Contract,
	credentials atumsecrets.Document,
) (*identity.BootstrapProjection, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists || target.LocalAccess == nil {
		return nil, errors.New("local identity requires the active local-access target")
	}
	projection, err := identity.Derive(
		contract,
		credentials.Identity.Seed.Bytes(),
		service.Project.Desired.Project.Cluster,
		target.LocalAccess.Domain,
	)
	if err != nil {
		return nil, fmt.Errorf("derive platform identity projection: %w", err)
	}
	return projection, nil
}

func (service Service) Apply(ctx context.Context, options ApplyOptions) error {
	if err := service.requireReadyCluster(ctx); err != nil {
		return err
	}
	if service.DryRun {
		service.logger().InfoContext(ctx, "platform application would publish sources, invoke Flux, and observe readiness")
		return nil
	}
	credentials, publication, err := service.platformInputs(ctx)
	if err != nil {
		return err
	}
	handoff, err := service.Seed(ctx, publication, credentials, PrepareOptions{Timeout: options.Timeout})
	credentials.Clear()
	if err != nil {
		return err
	}
	defer handoff.Clear()
	if err := service.preparePlatform(ctx, handoff, PrepareOptions{Timeout: options.Timeout}); err != nil {
		return err
	}
	return service.applyPlatform(ctx, options)
}

func (service Service) platformInputs(
	ctx context.Context,
) (atumsecrets.Document, *delivery.Publication, error) {
	credentials, err := service.credentials(ctx)
	if err != nil {
		return atumsecrets.Document{}, nil, err
	}
	if service.Publication == nil {
		credentials.Clear()
		return atumsecrets.Document{}, nil, errors.New(
			"canonical local publication inputs are unavailable",
		)
	}
	return credentials, service.Publication, nil
}

func (service Service) ApplySeeded(ctx context.Context, handoff *Handoff, options ApplyOptions) error {
	if err := service.requireReadyCluster(ctx); err != nil {
		return err
	}
	if handoff == nil || handoff.publication == nil || handoff.forgejo == nil {
		return errors.New("verified platform handoff is required")
	}
	if err := service.preparePlatform(ctx, handoff, PrepareOptions{Timeout: options.Timeout}); err != nil {
		return err
	}
	return service.applyPlatform(ctx, options)
}

func (service Service) applyPlatform(
	ctx context.Context,
	options ApplyOptions,
) error {
	timeout := timeoutOrDefault(options.Timeout)
	if err := service.waitForPlatformReconciliation(ctx, timeout); err != nil {
		return err
	}
	service.logger().InfoContext(ctx, "platform apply complete")
	return nil
}

func (service Service) waitForPlatformReconciliation(
	ctx context.Context,
	timeout time.Duration,
) error {
	client, err := service.cluster()
	if err != nil {
		return err
	}
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		status, observeErr := observeFluxReconciliation(
			waitContext,
			client,
			service.Project,
		)
		if observeErr == nil && status.Complete() {
			return nil
		}
		select {
		case <-waitContext.Done():
			if observeErr != nil {
				return fmt.Errorf(
					"wait for native Flux reconciliation: %w: %v",
					waitContext.Err(),
					observeErr,
				)
			}
			pending := make([]string, 0, len(status.Kustomizations))
			if !status.BigBangSource.Ready {
				pending = append(pending, status.BigBangSource.Name)
			}
			if !status.BigBangRelease.Ready {
				pending = append(pending, status.BigBangRelease.Name)
			}
			for _, condition := range status.Kustomizations {
				if !condition.Ready {
					pending = append(pending, condition.Name)
				}
			}
			return fmt.Errorf(
				"wait for native Flux reconciliation: %w: pending %s",
				waitContext.Err(),
				strings.Join(pending, ", "),
			)
		case <-ticker.C:
		}
	}
}
