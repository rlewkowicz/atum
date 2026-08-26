package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/identity"
	"atum/cli/infra"
	"atum/cli/kube"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const platformStatusIssueLimit = 128

var platformKustomizationGraph = [...]string{
	"flux-system",
	"platform-secrets",
	"prep",
	"platform-profile-prep",
	"bigbang",
	"platform-certificates",
	"platform-profile-access",
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
	receipt, err := delivery.LoadReceipt(service.Project)
	if err != nil {
		return Status{}, fmt.Errorf("load local publication receipt: %w", err)
	}
	client, err := service.cluster()
	if err != nil {
		return Status{}, err
	}

	reconciliation, err := observeFluxReconciliation(ctx, client, service.Project)
	if err != nil {
		return Status{}, fmt.Errorf("observe native Flux conditions: %w", err)
	}
	compliance, err := service.observeDeliveryCompliance(ctx, client, receipt)
	if err != nil {
		return Status{}, fmt.Errorf("observe delivery compliance: %w", err)
	}
	local, err := service.observeLocalIntegration(ctx, client)
	if err != nil {
		return Status{}, fmt.Errorf("observe local integration: %w", err)
	}
	return Status{
		PublicationSHA256: receipt.SourceSHA256,
		SourceCommit:   receipt.SourceCommit,
		ActiveProfile:  target.PlatformProfile,
		Reconciliation: reconciliation,
		Delivery:       compliance,
		Local:          local,
	}, nil
}

func observeFluxReconciliation(
	ctx context.Context,
	client *kube.Observer,
	project *config.Project,
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
		Kustomizations: make([]ResourceStatus, 0, len(platformKustomizationGraph)),
	}
	for _, name := range platformKustomizationGraph {
		object := byName[name]
		condition := ResourceStatus{Name: "flux-system/" + name}
		if object == nil {
			condition.Message = "Kustomization is absent"
		} else {
			condition.Ready = object.Ready
			if !condition.Ready {
				condition.Message = readyConditionMessage(object.Object)
			}
		}
		result.Kustomizations = append(result.Kustomizations, condition)
	}
	source, release, err := observeBigBangRoot(ctx, client, project)
	if err != nil {
		return ReconciliationStatus{}, err
	}
	result.BigBangSource = source
	result.BigBangRelease = release
	return result, nil
}

func observeBigBangRoot(
	ctx context.Context,
	client *kube.Observer,
	project *config.Project,
) (ResourceStatus, ResourceStatus, error) {
	artifact, err := project.BigBangArtifact()
	if err != nil {
		return ResourceStatus{}, ResourceStatus{}, err
	}
	url, tag, err := artifact.FluxOCITarget()
	if err != nil {
		return ResourceStatus{}, ResourceStatus{}, err
	}
	observation, err := client.ObserveFluxHelmRoot(
		ctx,
		"bigbang",
		"bigbang",
		kube.FluxRootTarget{URL: url, Tag: tag},
	)
	if err != nil {
		return ResourceStatus{}, ResourceStatus{}, err
	}
	source := ResourceStatus{Name: "bigbang/bigbang OCIRepository"}
	release := ResourceStatus{Name: "bigbang/bigbang HelmRelease"}
	if !observation.Found {
		source.Message = "OCIRepository is absent"
		release.Message = "HelmRelease is absent"
		return source, release, nil
	}
	if !observation.TargetCurrent {
		message := fmt.Sprintf(
			"observed prior tag %s; waiting for %s",
			observation.ObservedTag,
			tag,
		)
		source.Message = message
		release.Message = message
		return source, release, nil
	}
	source.Ready = observation.SourceReady
	source.Message = observation.SourceMessage
	release.Ready = observation.HelmReleaseReady
	release.Message = observation.HelmMessage
	return source, release, nil
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

func (service Service) observeDeliveryCompliance(
	ctx context.Context,
	client *kube.Observer,
	receipt delivery.Receipt,
) (DeliveryComplianceStatus, error) {
	result := DeliveryComplianceStatus{}
	sourceIssues, err := service.sourceComplianceIssues(ctx, client, receipt)
	if err != nil {
		return result, err
	}
	result.SourcesInternal = len(sourceIssues) == 0
	result.Issues = append(result.Issues, sourceIssues...)

	imageIssues, err := runtimeImageIssues(ctx, client, receipt.Delivery)
	if err != nil {
		return result, err
	}
	result.RuntimeImagesExact = len(imageIssues) == 0
	result.Issues = append(result.Issues, imageIssues...)
	sort.Strings(result.Issues)
	if len(result.Issues) > platformStatusIssueLimit {
		result.Issues = result.Issues[:platformStatusIssueLimit]
	}
	return result, nil
}

type expectedGitSource struct {
	id     string
	commit string
}

func (service Service) sourceComplianceIssues(
	ctx context.Context,
	client *kube.Observer,
	receipt delivery.Receipt,
) ([]string, error) {
	objects, err := client.Resources(ctx, kube.GitRepository, "", "")
	if apierrors.IsNotFound(err) {
		return []string{"Flux GitRepository API is absent"}, nil
	}
	if err != nil {
		return nil, err
	}
	sources := service.Project.Desired.Platform.Sources
	expected := make(map[string]expectedGitSource, 1)
	rootURL := internalRepositoryURL(
		sources.ClusterURL, sources.Organization, sources.Repository,
	)
	expected[normalizedRepositoryURL(rootURL)] = expectedGitSource{
		id: "platform", commit: receipt.SourceCommit,
	}

	seen := make(map[string]struct{}, len(expected))
	issues := make([]string, 0)
	for index := range objects {
		url, _, _ := unstructured.NestedString(objects[index].Object, "spec", "url")
		normalized := normalizedRepositoryURL(url)
		source, known := expected[normalized]
		if !known {
			issues = append(issues, fmt.Sprintf(
				"GitRepository %s/%s uses unapproved source %s",
				objects[index].Namespace, objects[index].Name, url,
			))
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			issues = append(issues, "published source "+source.id+" is rendered more than once")
			continue
		}
		seen[normalized] = struct{}{}
		revision, _, _ := unstructured.NestedString(
			objects[index].Object, "status", "artifact", "revision",
		)
		if !strings.Contains(revision, source.commit) {
			issues = append(issues, "published source "+source.id+" has not reconciled its exact commit")
		}
		branch, _, _ := unstructured.NestedString(
			objects[index].Object, "spec", "ref", "branch",
		)
		if branch != "main" {
			issues = append(issues, "platform source does not select main")
		}
	}
	for url, source := range expected {
		if _, found := seen[url]; !found {
			issues = append(issues, "published source "+source.id+" is absent")
		}
	}
	sort.Strings(issues)
	return issues, nil
}

func internalRepositoryURL(base, organization, repository string) string {
	return strings.TrimSuffix(base, "/") + "/" + organization + "/" + repository + ".git"
}

func normalizedRepositoryURL(value string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(value), "/"), ".git")
}

func runtimeImageIssues(
	ctx context.Context,
	client *kube.Observer,
	lock config.ImageLock,
) ([]string, error) {
	locked := make(map[string]map[string]struct{}, len(lock.Images))
	for _, image := range lock.Images {
		if _, duplicate := locked[image.Target]; duplicate {
			return nil, fmt.Errorf("publication target %s is duplicated", image.Target)
		}
		locked[image.Target] = map[string]struct{}{image.Digest: {}}
	}
	pods, err := client.Pods(ctx, "", "")
	if err != nil {
		return nil, err
	}
	issues := make([]string, 0)
	for index := range pods {
		if pods[index].Terminal() {
			continue
		}
		if issue := podLockedImageIssue(&pods[index], locked); issue != "" {
			issues = append(issues, issue)
		}
	}
	sort.Strings(issues)
	return issues, nil
}

func podLockedImageIssue(pod *kube.Pod, locked map[string]map[string]struct{}) string {
	for _, container := range pod.Containers {
		digests, tracked := locked[container.Image]
		digest := imageIDDigest(container.ImageID)
		if tracked {
			if _, accepted := digests[digest]; accepted {
				continue
			}
		}
		identity := pod.Namespace + "/" + pod.Name + " container " + container.Name
		if !tracked {
			return identity + " uses untracked image " + container.Image
		}
		if digest == "" {
			return identity + " has no verified runtime digest for " + container.Image
		}
		return identity + " resolved " + container.Image + " to " + digest
	}
	return ""
}

func imageIDDigest(imageID string) string {
	index := strings.LastIndex(imageID, "sha256:")
	if index < 0 {
		return ""
	}
	digest := imageID[index:]
	if len(digest) != len("sha256:")+sha256.Size*2 {
		return ""
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return ""
	}
	return digest
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
