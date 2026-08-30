package platform

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/identity"
	"atum/cli/infra"
	"atum/cli/kube"
	atumoci "atum/cli/oci"
	atumsecrets "atum/cli/secrets"
	platformv1alpha1 "atum/operator/api/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var platformKustomizationGraph = [...]string{
	"flux-system",
	"platform-secrets",
	"prep",
	"platform-profile-prep",
	"bigbang",
	"platform-certificates",
	"platform-profile-access",
	"atum-operator",
}

// Status reports three independent dimensions. Flux owns reconciliation
// conditions, Atum owns delivery receipts, and Atum owns workstation/cluster
// connection receipts. None of these dimensions is used to infer a workload
// controller lifecycle.
func (service Service) Status(ctx context.Context) (Status, error) {
	if err := service.Validate(); err != nil {
		return Status{}, err
	}
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return Status{}, fmt.Errorf(
			"active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active,
		)
	}
	if target.PlatformProfile != "local" {
		return Status{}, fmt.Errorf(
			"Atum platform target %q is unsupported; only the local profile is end-to-end",
			service.Project.Desired.Infrastructure.Active,
		)
	}
	receipt, receiptErr := delivery.LoadReceipt(service.Project)
	compliance := publicationCompliance(receipt, receiptErr)
	if receiptErr == nil {
		service.observeSeedPublication(ctx, receipt, &compliance)
		recordKubesprayFilesObservation(
			&compliance,
			service.observeKubesprayFiles(ctx, receipt),
		)
	}
	client, err := service.cluster()
	if err != nil {
		return Status{}, err
	}

	reconciliation, err := observeFluxReconciliation(
		ctx,
		client,
		service.Project,
		receipt.SourceCommit,
	)
	if err != nil {
		return Status{}, fmt.Errorf("observe native Flux conditions: %w", err)
	}
	local, err := service.observeLocalIntegration(ctx, client)
	if err != nil {
		return Status{}, fmt.Errorf("observe local integration: %w", err)
	}
	return Status{
		PublicationSHA256: receipt.SourceSHA256,
		SourceCommit:      receipt.SourceCommit,
		ActiveProfile:     target.PlatformProfile,
		Reconciliation:    reconciliation,
		Delivery:          compliance,
		Local:             local,
	}, nil
}

func recordKubesprayFilesObservation(
	compliance *DeliveryComplianceStatus,
	err error,
) {
	if compliance == nil {
		return
	}
	if err != nil {
		compliance.KubesprayFilesExact = false
		compliance.Issues = append(
			compliance.Issues,
			"retained Kubespray files: "+err.Error(),
		)
		return
	}
	compliance.KubesprayFilesExact = true
}

func observeFluxReconciliation(
	ctx context.Context,
	client *kube.Observer,
	project *config.Project,
	sourceCommit string,
) (ReconciliationStatus, error) {
	objects, err := client.Resources(ctx, kube.Kustomization, "flux-system", "")
	if apierrors.IsNotFound(err) {
		objects = nil
		err = nil
	}
	if err != nil {
		return ReconciliationStatus{}, err
	}
	byName := make(map[string]*kube.Object, len(objects))
	for index := range objects {
		if _, duplicate := byName[objects[index].Name]; duplicate {
			return ReconciliationStatus{}, fmt.Errorf(
				"Flux Kustomization %s is duplicated", objects[index].Name,
			)
		}
		byName[objects[index].Name] = &objects[index]
	}
	result := ReconciliationStatus{
		Kustomizations: make([]ResourceStatus, 0, max(
			len(objects),
			len(platformKustomizationGraph),
		)),
	}
	for index := range objects {
		result.Kustomizations = append(
			result.Kustomizations,
			resourceStatus(&objects[index]),
		)
	}
	for _, name := range platformKustomizationGraph {
		if byName[name] == nil {
			result.Kustomizations = append(
				result.Kustomizations,
				ResourceStatus{
					Name:    "flux-system/" + name,
					Message: "Kustomization is absent",
				},
			)
		}
	}
	sortResourceStatuses(result.Kustomizations)
	result.GitRepositories, err = observeGitRepositories(
		ctx,
		client,
		project,
		sourceCommit,
	)
	if err != nil {
		return ReconciliationStatus{}, err
	}
	result.OCIRepositories, err = observeResourceStatuses(
		ctx,
		client,
		kube.OCIRepository,
	)
	if err != nil {
		return ReconciliationStatus{}, err
	}
	result.HelmReleases, err = observeResourceStatuses(
		ctx,
		client,
		kube.HelmRelease,
	)
	if err != nil {
		return ReconciliationStatus{}, err
	}
	if err := requireCurrentBigBangRoot(
		ctx,
		client,
		project,
		&result.OCIRepositories,
		&result.HelmReleases,
	); err != nil {
		return ReconciliationStatus{}, err
	}
	result.Certificates, err = observeResourceStatuses(
		ctx,
		client,
		kube.Certificate,
	)
	if err != nil {
		return ReconciliationStatus{}, err
	}
	result.PlatformIdentityConfigurations, err = observeExactResourceStatus(
		ctx,
		client,
		kube.PlatformIdentityConfiguration,
		platformv1alpha1.SingletonNamespace,
		platformv1alpha1.SingletonName,
	)
	if err != nil {
		return ReconciliationStatus{}, err
	}
	return result, nil
}

func requireCurrentBigBangRoot(
	ctx context.Context,
	client *kube.Observer,
	project *config.Project,
	sources *[]ResourceStatus,
	releases *[]ResourceStatus,
) error {
	artifact, err := project.BigBangArtifact()
	if err != nil {
		return err
	}
	url, tag, err := artifact.FluxOCITarget()
	if err != nil {
		return err
	}
	sourceObject, sourceFound, err := client.GetResource(
		ctx,
		kube.OCIRepository,
		"bigbang",
		"bigbang",
	)
	if err != nil {
		return err
	}
	releaseObject, releaseFound, err := client.GetResource(
		ctx,
		kube.HelmRelease,
		"bigbang",
		"bigbang",
	)
	if err != nil {
		return err
	}
	source := ensureResourceStatus(
		sources,
		"bigbang/bigbang",
		"required Big Bang OCIRepository is absent",
	)
	release := ensureResourceStatus(
		releases,
		"bigbang/bigbang",
		"required Big Bang HelmRelease is absent",
	)
	if !sourceFound || !releaseFound {
		return nil
	}
	observedURL, _, _ := unstructured.NestedString(
		sourceObject.Object,
		"spec",
		"url",
	)
	observedTag, _, _ := unstructured.NestedString(
		sourceObject.Object,
		"spec",
		"ref",
		"tag",
	)
	if observedURL != url || observedTag != tag {
		source.Ready = false
		source.Message = fmt.Sprintf(
			"observed %s:%s; waiting for %s:%s",
			observedURL,
			observedTag,
			url,
			tag,
		)
	}
	kind, _, _ := unstructured.NestedString(
		releaseObject.Object,
		"spec",
		"chartRef",
		"kind",
	)
	name, _, _ := unstructured.NestedString(
		releaseObject.Object,
		"spec",
		"chartRef",
		"name",
	)
	namespace, _, _ := unstructured.NestedString(
		releaseObject.Object,
		"spec",
		"chartRef",
		"namespace",
	)
	if kind != "OCIRepository" || name != "bigbang" ||
		(namespace != "" && namespace != "bigbang") {
		release.Ready = false
		release.Message = "HelmRelease does not reference the required Big Bang OCIRepository"
	}
	return nil
}

func readyConditionMessage(object map[string]any) string {
	conditions, _, _ := unstructured.NestedSlice(object, "status", "conditions")
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if condition["type"] != "Ready" {
			continue
		}
		reason, _ := condition["reason"].(string)
		message, _ := condition["message"].(string)
		switch {
		case reason != "" && message != "":
			return reason + ": " + firstLine(message)
		case message != "":
			return firstLine(message)
		case reason != "":
			return reason
		}
	}
	return "Ready condition is pending"
}

func firstLine(value string) string {
	if before, _, found := strings.Cut(strings.TrimSpace(value), "\n"); found {
		return before
	}
	return strings.TrimSpace(value)
}

func observeGitRepositories(
	ctx context.Context,
	client *kube.Observer,
	project *config.Project,
	sourceCommit string,
) ([]ResourceStatus, error) {
	objects, err := client.Resources(ctx, kube.GitRepository, "", "")
	if apierrors.IsNotFound(err) {
		return []ResourceStatus{{
			Name:    "flux-system/flux-system",
			Message: "GitRepository API is absent",
		}}, nil
	}
	if err != nil {
		return nil, err
	}
	sources := project.Desired.Platform.Sources
	rootURL := internalRepositoryURL(
		sources.ClusterURL, sources.Organization, sources.Repository,
	)
	statuses := make([]ResourceStatus, 0, max(1, len(objects)))
	rootFound := false
	for index := range objects {
		object := &objects[index]
		name := object.Namespace + "/" + object.Name
		status := resourceStatus(object)
		url, _, _ := unstructured.NestedString(objects[index].Object, "spec", "url")
		branch, _, _ := unstructured.NestedString(
			objects[index].Object, "spec", "ref", "branch",
		)
		if name != "flux-system/flux-system" ||
			normalizedRepositoryURL(url) != normalizedRepositoryURL(rootURL) {
			status.Ready = false
			status.Message = "unapproved Git source " + url
		} else {
			rootFound = true
			switch {
			case branch != "main":
				status.Ready = false
				status.Message = "platform source does not select main"
			case sourceCommit != "":
				revision, _, _ := unstructured.NestedString(
					object.Object,
					"status",
					"artifact",
					"revision",
				)
				if !strings.HasSuffix(revision, ":"+sourceCommit) {
					status.Ready = false
					status.Message = "platform source has not reconciled its exact published commit"
				}
			}
		}
		statuses = append(statuses, status)
	}
	if !rootFound {
		statuses = append(statuses, ResourceStatus{
			Name:    "flux-system/flux-system",
			Message: "required Forgejo main GitRepository is absent",
		})
	}
	sortResourceStatuses(statuses)
	return statuses, nil
}

func internalRepositoryURL(base, organization, repository string) string {
	return strings.TrimSuffix(base, "/") + "/" + organization + "/" + repository + ".git"
}

func normalizedRepositoryURL(value string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(value), "/"), ".git")
}

func observeResourceStatuses(
	ctx context.Context,
	client *kube.Observer,
	resource kube.Resource,
) ([]ResourceStatus, error) {
	objects, err := client.Resources(ctx, resource, "", "")
	if apierrors.IsNotFound(err) {
		return []ResourceStatus{{
			Name:    resourceKind(resource),
			Message: resourceKind(resource) + " API is absent",
		}}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return []ResourceStatus{{
			Name:    resourceKind(resource),
			Message: "no " + resourceKind(resource) + " resources are present",
		}}, nil
	}
	statuses := make([]ResourceStatus, len(objects))
	for index := range objects {
		statuses[index] = resourceStatus(&objects[index])
	}
	sortResourceStatuses(statuses)
	return statuses, nil
}

type resourceGetter interface {
	GetResource(context.Context, kube.Resource, string, string) (*kube.Object, bool, error)
}

func observeExactResourceStatus(
	ctx context.Context,
	client resourceGetter,
	resource kube.Resource,
	namespace string,
	name string,
) ([]ResourceStatus, error) {
	object, found, err := client.GetResource(ctx, resource, namespace, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return []ResourceStatus{{
			Name:    namespace + "/" + name,
			Message: "required " + resourceKind(resource) + " is absent",
		}}, nil
	}
	return []ResourceStatus{resourceStatus(object)}, nil
}

func resourceStatus(object *kube.Object) ResourceStatus {
	status := ResourceStatus{
		Name:  object.Namespace + "/" + object.Name,
		Ready: object.Ready,
	}
	if !status.Ready {
		status.Message = resourceReadinessMessage(object)
	}
	return status
}

func resourceReadinessMessage(object *kube.Object) string {
	if object == nil {
		return "resource is absent"
	}
	if object.DeletionTimestamp != nil {
		return "resource is deleting"
	}
	observed, found, err := unstructured.NestedInt64(
		object.Object,
		"status",
		"observedGeneration",
	)
	if err != nil {
		return "status observedGeneration is invalid"
	}
	if found && observed != object.Generation {
		return fmt.Sprintf(
			"status observedGeneration %d is stale for generation %d",
			observed,
			object.Generation,
		)
	}
	return readyConditionMessage(object.Object)
}

func resourceKind(resource kube.Resource) string {
	switch resource {
	case kube.GitRepository:
		return "GitRepository"
	case kube.Kustomization:
		return "Kustomization"
	case kube.OCIRepository:
		return "OCIRepository"
	case kube.HelmRelease:
		return "HelmRelease"
	case kube.Certificate:
		return "Certificate"
	case kube.PlatformIdentityConfiguration:
		return "PlatformIdentityConfiguration"
	default:
		return "resource"
	}
}

func sortResourceStatuses(statuses []ResourceStatus) {
	sort.Slice(statuses, func(left, right int) bool {
		return statuses[left].Name < statuses[right].Name
	})
}

func findResourceStatus(
	statuses []ResourceStatus,
	name string,
) *ResourceStatus {
	for index := range statuses {
		if statuses[index].Name == name {
			return &statuses[index]
		}
	}
	return nil
}

func ensureResourceStatus(
	statuses *[]ResourceStatus,
	name string,
	message string,
) *ResourceStatus {
	if status := findResourceStatus(*statuses, name); status != nil {
		return status
	}
	*statuses = append(*statuses, ResourceStatus{Name: name, Message: message})
	sortResourceStatuses(*statuses)
	return findResourceStatus(*statuses, name)
}

func publicationCompliance(
	receipt delivery.Receipt,
	err error,
) DeliveryComplianceStatus {
	if err != nil {
		return DeliveryComplianceStatus{
			Issues: []string{"local immutable publication receipt: " + err.Error()},
		}
	}
	return DeliveryComplianceStatus{
		PublicationExact: true,
	}
}

func (service Service) observeSeedPublication(
	ctx context.Context,
	receipt delivery.Receipt,
	status *DeliveryComplianceStatus,
) {
	credentials, err := atumsecrets.Load(ctx, service.Project, service.SOPS)
	if err != nil {
		status.Issues = append(status.Issues, "load delivery credentials: "+err.Error())
		return
	}
	defer credentials.Clear()
	sources := service.Project.Desired.Platform.Sources
	forgejo := &forgejoControl{
		url:           strings.TrimSuffix(sources.ExternalURL, "/"),
		username:      credentials.Forgejo.Username,
		adminPassword: credentials.Forgejo.AdminPassword.Clone(),
		root:          service.Project.Root,
	}
	api, forgejoErr := forgejo.apiClient(ctx)
	if forgejoErr == nil {
		var branchCommit string
		branch, _, branchErr := api.GetRepoBranch(
			sources.Organization,
			sources.Repository,
			"main",
		)
		if branchErr != nil {
			forgejoErr = branchErr
		} else if branch != nil && branch.Commit != nil {
			branchCommit = branch.Commit.ID
		}
		if branchCommit != receipt.SourceCommit {
			forgejoErr = fmt.Errorf(
				"main resolves to %s, want %s",
				branchCommit,
				receipt.SourceCommit,
			)
		}
	}
	forgejo.clear()
	if forgejoErr != nil {
		status.Issues = append(
			status.Issues,
			"Forgejo source observation: "+forgejoErr.Error(),
		)
	} else {
		status.ForgejoExact = true
	}

	registry, err := atumoci.NewClient(
		service.Project.Desired.Delivery.Registry,
		atumoci.Credentials{
			Username: "admin",
			Password: credentials.Harbor.AdminPassword,
		},
	)
	if err != nil {
		status.Issues = append(status.Issues, "Harbor observation: "+err.Error())
		return
	}
	defer registry.Clear()
	status.HarborImagesExact = observeHarborImages(
		ctx,
		registry,
		receipt,
		&status.Issues,
	)
	status.HarborChartsExact = observeHarborCharts(
		ctx,
		registry,
		receipt,
		&status.Issues,
	)
}

func observeHarborImages(
	ctx context.Context,
	registry *atumoci.Client,
	receipt delivery.Receipt,
	issues *[]string,
) bool {
	if len(receipt.Delivery.Images) == 0 {
		*issues = append(*issues, "Harbor image receipt is empty")
		return false
	}
	for _, image := range receipt.Delivery.Images {
		descriptor, err := registry.Resolve(ctx, image.Target)
		if err != nil || descriptor.Digest.String() != image.Digest {
			if err != nil {
				*issues = append(*issues, "Harbor image "+image.ID+": "+err.Error())
			} else {
				*issues = append(
					*issues,
					fmt.Sprintf(
						"Harbor image %s resolves to %s, want %s",
						image.ID,
						descriptor.Digest,
						image.Digest,
					),
				)
			}
			return false
		}
	}
	return true
}

func observeHarborCharts(
	ctx context.Context,
	registry *atumoci.Client,
	receipt delivery.Receipt,
	issues *[]string,
) bool {
	if len(receipt.Charts) == 0 {
		*issues = append(*issues, "Harbor chart receipt is empty")
		return false
	}
	for _, chart := range receipt.Charts {
		descriptor, err := registry.Resolve(ctx, chart.Target)
		if err != nil || descriptor.Digest.String() != chart.ManifestDigest {
			if err != nil {
				*issues = append(*issues, "Harbor chart "+chart.ID+": "+err.Error())
			} else {
				*issues = append(
					*issues,
					fmt.Sprintf(
						"Harbor chart %s resolves to %s, want %s",
						chart.ID,
						descriptor.Digest,
						chart.ManifestDigest,
					),
				)
			}
			return false
		}
	}
	return true
}

func (service Service) observeKubesprayFiles(
	ctx context.Context,
	receipt delivery.Receipt,
) error {
	manifest, err := delivery.MaterializeFileManifest(service.Project)
	if err != nil {
		return err
	}
	if manifest.Identity != receipt.KubesprayFiles {
		return fmt.Errorf("manifest identity differs from the publication receipt")
	}
	projection, err := delivery.ManifestKubesprayFileProjection(manifest)
	if err != nil {
		return err
	}
	return delivery.ObserveKubesprayFileProjection(
		ctx,
		service.Project.Desired.Delivery.Seed.KubesprayFiles.URL,
		projection,
		service.Project.Desired.Updates.Parallelism,
	)
}

func (service Service) observeLocalIntegration(
	ctx context.Context,
	client *kube.Observer,
) (LocalIntegrationStatus, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return LocalIntegrationStatus{}, fmt.Errorf(
			"active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active,
		)
	}
	if target.LocalAccess == nil {
		return LocalIntegrationStatus{}, nil
	}
	result := LocalIntegrationStatus{
		Required:              true,
		PublicIngressVIP:      target.LocalAccess.PublicIngressVIP,
		PassthroughIngressVIP: target.LocalAccess.PassthroughIngressVIP,
		LoadBalancerRange:     target.LocalAccess.LoadBalancerRange,
		AccessDomain:          target.LocalAccess.Domain,
	}
	var err error
	result.LoadBalancerReady, result.PublicIngressIPs,
		result.PassthroughIngressIPs, err = observeLocalLoadBalancer(
		ctx, client, target.LocalAccess,
	)
	if err != nil {
		return LocalIntegrationStatus{}, err
	}

	root, found, err := client.SecretValue(
		ctx, "cert-manager", "atum-test-root-ca", "tls.crt",
	)
	if err != nil {
		return LocalIntegrationStatus{}, fmt.Errorf("read local root CA: %w", err)
	}
	defer clear(root)
	relative, required := service.Project.Desired.ActiveIdentityContractPath()
	if !required {
		return result, nil
	}
	contract, err := identity.Load(service.Project.Root, relative)
	if err != nil {
		return LocalIntegrationStatus{}, err
	}
	result.AccessURLs = identityAccessURLs(contract)
	if !found {
		return result, nil
	}
	validated, err := infra.ValidateRootCA(root, time.Now())
	if err != nil {
		return result, nil
	}
	defer validated.Clear()
	result.RootCAFingerprint = validated.Fingerprint
	return result, nil
}

func identityAccessURLs(contract *identity.Contract) []string {
	unique := make(map[string]struct{})
	for _, client := range contract.Clients() {
		unique["https://"+client.Host] = struct{}{}
	}
	for _, endpoint := range contract.AdditionalEndpoints() {
		unique["https://"+endpoint.Host] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func observeLocalLoadBalancer(
	ctx context.Context,
	client *kube.Observer,
	access *config.LocalAccess,
) (bool, []string, []string, error) {
	public, publicFound, err := client.ServiceIngressIPs(
		ctx, "istio-gateway", "public-ingressgateway",
	)
	if err != nil {
		return false, nil, nil, err
	}
	passthrough, passthroughFound, err := client.ServiceIngressIPs(
		ctx, "istio-gateway", "passthrough-ingressgateway",
	)
	if err != nil {
		return false, nil, nil, err
	}
	allocator, allocatorFound, err := client.ConfigMapData(
		ctx, "kube-system", "kube-vip-cloud-provider",
	)
	if err != nil {
		return false, nil, nil, err
	}
	ready := publicFound && passthroughFound &&
		len(public) == 1 && public[0] == access.PublicIngressVIP &&
		len(passthrough) == 1 && passthrough[0] == access.PassthroughIngressVIP &&
		allocatorFound && len(allocator) == 1 &&
		allocator["range-global"] == access.LoadBalancerRange
	return ready, public, passthrough, nil
}
