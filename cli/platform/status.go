package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/fssecure"
	"atum/cli/identity"
	"atum/cli/infra"
	"atum/cli/kube"
	atumoci "atum/cli/oci"
	"atum/cli/orchestration"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"

	"github.com/fluxcd/pkg/envsubst"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sync/errgroup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"oras.land/oras-go/v2/errdef"
)

func (service Service) Status(ctx context.Context) (Status, error) {
	if err := service.Validate(); err != nil {
		return Status{}, err
	}
	project, err := delivery.LoadExecutionProject(service.Project)
	if err != nil {
		return Status{}, fmt.Errorf("load local deployment state: %w", err)
	}
	service.Project = project
	client, err := service.cluster()
	if err != nil {
		return Status{}, err
	}
	bundle, err := service.deploymentBundle(ctx)
	if err != nil {
		return Status{}, err
	}
	credentials, err := service.credentials(ctx)
	if err != nil {
		return Status{}, err
	}
	return service.statusWithBundle(ctx, client, bundle, credentials)
}

func (service Service) statusWithBundle(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	credentials atumsecrets.Document,
) (Status, error) {
	result, _, spec, err := service.collectStatus(ctx, client, bundle, &credentials, nil)
	if spec != nil {
		defer spec.Clear()
	}
	if err != nil {
		return Status{}, err
	}
	reportExactStatus(ctx, result)
	return result, nil
}

// collectStatus owns one complete platform observation round. A nil
// credentials pointer is permitted only for apply readiness after Seed has
// returned its private publication receipt; terminal status always supplies
// credentials and revalidates Harbor.
func (service Service) collectStatus(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	credentials *atumsecrets.Document,
	publication *publicationReceipt,
) (Status, platformSnapshot, *orchestration.PlatformOIDCSpec, error) {
	_, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return Status{}, platformSnapshot{}, nil, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	var snapshot platformSnapshot
	observations := statusObservations{}
	var registryTask statusFamilyTask
	if credentials != nil {
		registryTask = statusFamilyTask{name: "internal registry", run: func(familyContext context.Context) error {
			value, familyErr := service.observeInternalRegistry(
				familyContext, bundle, credentials.Harbor.AdminPassword)
			observations.registry = value
			return familyErr
		}}
	} else if publication == nil || !publication.registry.imageExact ||
		!publication.registry.chartsExact || !publication.registry.chartsImmutable ||
		len(publication.runtimeImages) == 0 {
		return Status{}, platformSnapshot{}, nil, errors.New(
			"verified seed publication receipt is required for apply readiness")
	} else {
		registryTask = statusFamilyTask{name: "seed publication receipt", run: func(context.Context) error {
			observations.registry = publication.registry
			return nil
		}}
	}
	if err := runStatusObservationRound(
		ctx,
		statusFamilyTask{name: "Kubernetes snapshot", run: func(familyContext context.Context) error {
			value, familyErr := collectPlatformSnapshot(familyContext, client)
			snapshot = value
			return familyErr
		}},
		registryTask,
		[]statusFamilyTask{
			{name: "core cluster", run: func(familyContext context.Context) error {
				value, familyErr := service.observeCoreCluster(familyContext, client, bundle, snapshot)
				observations.core = value
				return familyErr
			}},
			{name: "Helm and pod workloads", run: func(familyContext context.Context) error {
				var value workloadObservation
				var familyErr error
				if publication == nil {
					value, familyErr = service.observeWorkloads(familyContext, bundle, snapshot)
				} else {
					value = service.observeWorkloadSnapshot(snapshot, publication.runtimeImages)
				}
				observations.workloads = value
				return familyErr
			}},
			{name: "internal sources", run: func(familyContext context.Context) error {
				value, familyErr := service.observeInternalSources(familyContext, client, bundle, snapshot)
				observations.sources = value
				return familyErr
			}},
			{name: "cluster local access", run: func(familyContext context.Context) error {
				value, familyErr := service.observeLocalAccess(familyContext, client, snapshot)
				observations.local = value
				return familyErr
			}},
		},
	); err != nil {
		return Status{}, platformSnapshot{}, nil, err
	}
	defer clear(observations.local.certificates.rootPEM)
	oidcObservation, oidcSpec, err := service.observeClusterOIDC(
		snapshot, observations.local.certificates)
	if err != nil {
		return Status{}, platformSnapshot{}, nil, fmt.Errorf("observe cluster OIDC: %w", err)
	}
	observations.oidc = oidcObservation
	return mergeStatusObservations(service, observations), snapshot, oidcSpec, nil
}

const statusFamilyLimit = 4
const statusHarborImageLimit = statusFamilyLimit - 1

type platformSnapshot struct {
	resources     map[kube.Resource][]kube.Object
	pods          []kube.Pod
	nodes         []kube.Node
	oidcReceipt   map[string]string
	serverVersion string
}

var platformWorkloadResources = [...]kube.Resource{
	kube.Deployment,
	kube.StatefulSet,
	kube.DaemonSet,
}

func (snapshot platformSnapshot) resource(resource kube.Resource) []kube.Object {
	return snapshot.resources[resource]
}

type statusFamilyTask struct {
	name string
	run  func(context.Context) error
}

func runStatusObservationRound(
	ctx context.Context,
	snapshotTask, registryTask statusFamilyTask,
	dependentTasks []statusFamilyTask,
) error {
	snapshotReady := make(chan struct{})
	var snapshotErr error
	tasks := make([]statusFamilyTask, 0, len(dependentTasks)+2)
	tasks = append(tasks, statusFamilyTask{
		name: snapshotTask.name,
		run: func(taskContext context.Context) error {
			snapshotErr = snapshotTask.run(taskContext)
			close(snapshotReady)
			return snapshotErr
		},
	}, registryTask)
	for index := range dependentTasks {
		dependent := dependentTasks[index]
		tasks = append(tasks, statusFamilyTask{
			name: dependent.name,
			run: func(taskContext context.Context) error {
				select {
				case <-snapshotReady:
					if snapshotErr != nil {
						return context.Canceled
					}
					return dependent.run(taskContext)
				case <-taskContext.Done():
					return taskContext.Err()
				}
			},
		})
	}
	return runStatusFamilies(ctx, statusFamilyLimit, tasks)
}

func runStatusFamilies(ctx context.Context, limit int, tasks []statusFamilyTask) error {
	if limit < 1 {
		return errors.New("status family concurrency limit must be positive")
	}
	familyErrors := make([]error, len(tasks))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(limit)
	for index := range tasks {
		index := index
		group.Go(func() error {
			familyErrors[index] = tasks[index].run(groupContext)
			return familyErrors[index]
		})
	}
	_ = group.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	for index, err := range familyErrors {
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("observe %s: %w", tasks[index].name, err)
		}
	}
	for index, err := range familyErrors {
		if err != nil {
			return fmt.Errorf("observe %s: %w", tasks[index].name, err)
		}
	}
	return nil
}

func collectPlatformSnapshot(ctx context.Context, client *kube.Observer) (platformSnapshot, error) {
	resources := [...]struct {
		name     string
		resource kube.Resource
	}{
		{name: "GitRepositories", resource: kube.GitRepository},
		{name: "OCIRepositories", resource: kube.OCIRepository},
		{name: "HelmRepositories", resource: kube.HelmRepository},
		{name: "Kustomizations", resource: kube.Kustomization},
		{name: "HelmReleases", resource: kube.HelmRelease},
		{name: "Certificates", resource: kube.Certificate},
		{name: "ClusterIssuers", resource: kube.ClusterIssuer},
		{name: "VirtualServices", resource: kube.VirtualService},
		{name: "Deployments", resource: kube.Deployment},
		{name: "StatefulSets", resource: kube.StatefulSet},
		{name: "DaemonSets", resource: kube.DaemonSet},
		{name: "Jobs", resource: kube.Job},
	}
	type resourceResult struct {
		resource kube.Resource
		items    []kube.Object
	}
	results := make([]resourceResult, len(resources))
	var pods []kube.Pod
	var nodes []kube.Node
	var oidcReceipt map[string]string
	var serverVersion string
	tasks := make([]statusFamilyTask, 0, len(resources)+4)
	for index := range resources {
		index := index
		tasks = append(tasks, statusFamilyTask{
			name: resources[index].name,
			run: func(taskContext context.Context) error {
				items, err := client.Resources(
					taskContext, resources[index].resource, "", "")
				if apierrors.IsNotFound(err) {
					items, err = nil, nil
				}
				if err != nil {
					return err
				}
				results[index] = resourceResult{
					resource: resources[index].resource, items: items,
				}
				return nil
			},
		})
	}
	tasks = append(tasks, statusFamilyTask{name: "Kubernetes Pods", run: func(taskContext context.Context) error {
		var err error
		pods, err = client.Pods(taskContext, "", "")
		return err
	}})
	tasks = append(tasks, statusFamilyTask{name: "Kubernetes Nodes", run: func(taskContext context.Context) error {
		var err error
		nodes, err = client.Nodes(taskContext)
		return err
	}})
	tasks = append(tasks, statusFamilyTask{name: "Kubernetes OIDC receipt", run: func(taskContext context.Context) error {
		value, found, err := client.ConfigMapData(
			taskContext,
			orchestration.PlatformOIDCReceiptNamespace,
			orchestration.PlatformOIDCReceiptName,
		)
		if err != nil {
			return err
		}
		if found {
			oidcReceipt = value
		}
		return nil
	}})
	tasks = append(tasks, statusFamilyTask{name: "Kubernetes version", run: func(taskContext context.Context) error {
		var err error
		serverVersion, err = client.ServerVersion(taskContext)
		return err
	}})
	if err := runStatusFamilies(ctx, statusFamilyLimit, tasks); err != nil {
		return platformSnapshot{}, fmt.Errorf("collect platform snapshot: %w", err)
	}
	canonicalizePlatformPods(pods)
	snapshot := platformSnapshot{
		resources: make(map[kube.Resource][]kube.Object, len(results)),
		pods:      pods, nodes: nodes, oidcReceipt: oidcReceipt, serverVersion: serverVersion,
	}
	for index := range results {
		snapshot.resources[results[index].resource] = results[index].items
	}
	return snapshot, nil
}

func canonicalizePlatformPods(pods []kube.Pod) {
	sort.Slice(pods, func(left, right int) bool {
		if pods[left].Namespace != pods[right].Namespace {
			return pods[left].Namespace < pods[right].Namespace
		}
		return pods[left].Name < pods[right].Name
	})
}

type coreClusterObservation struct {
	bundleSHA256, sourceCommit                          string
	bundleReady, fluxReady, prepReady, profilePrepReady bool
	bigBangReady, profileAccessReady                    bool
	profileIdentityReady                                bool
	profileIdentityFailure                              string
}

type workloadObservation struct {
	helmReleases                          []ResourceStatus
	activeHelmReleases, readyHelmReleases int
	activeWorkloads, readyWorkloads       int
	nonReadyPods                          int
	imageIssues                           []string
	imageIssueCount                       int
}

type sourceObservation struct {
	ociSources []ResourceStatus
	issues     []string
	issueCount int
}

type registryObservation struct {
	imageExact, chartsExact, chartsImmutable bool
}

type publicationReceipt struct {
	registry      registryObservation
	runtimeImages map[string]map[string]struct{}
}

type localAccessObservation struct {
	loadBalancer localLoadBalancerObservation
	certificates localCertificateObservation
	issuerReady  bool
	accessURLs   []string
	routesReady  bool
}

type statusObservations struct {
	core      coreClusterObservation
	workloads workloadObservation
	sources   sourceObservation
	registry  registryObservation
	local     localAccessObservation
	oidc      clusterOIDCObservation
}

type clusterOIDCObservation struct {
	ready   bool
	failure string
}

func (service Service) observeCoreCluster(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	snapshot platformSnapshot,
) (coreClusterObservation, error) {
	var result coreClusterObservation
	if live, found, err := client.ConfigMapData(ctx, "kube-system", "atum-bundle"); err == nil && found {
		result.bundleSHA256 = live["archiveSha256"]
		result.sourceCommit = live["sourceCommit"]
	}
	result.bundleReady = verifyClusterBundle(ctx, client, bundle.Identity) == nil
	result.fluxReady = deploymentsReady(ctx, client, "flux-system", []string{
		"source-controller", "kustomize-controller", "helm-controller", "notification-controller",
	})
	kustomizations := snapshot.resource(kube.Kustomization)
	result.prepReady = snapshotResourceReady(kustomizations, "flux-system", "prep")
	result.profilePrepReady = snapshotResourceReady(
		kustomizations, "flux-system", "platform-profile-prep")
	result.bigBangReady = snapshotResourceReady(kustomizations, "flux-system", "bigbang")
	result.profileAccessReady = snapshotResourceReady(
		kustomizations, "flux-system", identity.ProfileAccessKustomizationName)
	result.profileIdentityReady = snapshotResourceReady(
		kustomizations, "flux-system", identity.ProfileIdentityKustomizationName)
	if _, required := service.Project.Desired.ActiveIdentityContractPath(); required {
		jobsReady, failure := identityJobsStatus(snapshot.resource(kube.Job))
		result.profileIdentityReady = result.profileIdentityReady && jobsReady
		result.profileIdentityFailure = failure
	}
	return result, nil
}

func identityJobsStatus(jobs []kube.Object) (bool, string) {
	const keycloakJob, openBaoJob = uint8(1), uint8(2)
	remaining := keycloakJob | openBaoJob
	for index := range jobs {
		job := &jobs[index]
		key := job.GetNamespace() + "/" + job.GetName()
		var bit uint8
		var label string
		switch key {
		case identity.KeycloakJobNamespace + "/" + identity.KeycloakJobName:
			bit, label = keycloakJob, identity.KeycloakJobOwner
		case identity.OpenBaoJobNamespace + "/" + identity.OpenBaoJobName:
			bit, label = openBaoJob, identity.OpenBaoJobOwner
		default:
			continue
		}
		if job.GetDeletionTimestamp() != nil {
			continue
		}
		if job.GetLabels()["atum.dev/identity-job"] != label {
			return false, key + " has an invalid identity owner label"
		}
		if jobFailed(job.Object) {
			return false, key + " reports a failed terminal condition"
		}
		if !kube.IsReady(job) {
			return false, ""
		}
		remaining &^= bit
	}
	return remaining == 0, ""
}

func jobFailed(object map[string]any) bool {
	conditions, found, err := unstructured.NestedSlice(object, "status", "conditions")
	if err != nil || !found {
		return false
	}
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if condition["type"] == "Failed" && condition["status"] == "True" {
			return true
		}
	}
	return false
}

func (service Service) observeWorkloads(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	snapshot platformSnapshot,
) (workloadObservation, error) {
	lockedImages, err := bundle.RuntimeImageDigests(ctx)
	if err != nil {
		return workloadObservation{}, err
	}
	return service.observeWorkloadSnapshot(snapshot, lockedImages), nil
}

func (service Service) observeWorkloadSnapshot(
	snapshot platformSnapshot,
	lockedImages map[string]map[string]struct{},
) workloadObservation {
	result := workloadObservation{
		helmReleases: make([]ResourceStatus, 0, len(snapshot.resource(kube.HelmRelease))),
		imageIssues:  make([]string, 0, platformStatusIssueLimit),
	}
	inactiveBootstrap := service.inactiveBootstrapIDs()
	helmReleases := snapshot.resource(kube.HelmRelease)
	for index := range helmReleases {
		release := &helmReleases[index]
		if release.GetDeletionTimestamp() != nil {
			continue
		}
		if _, inactive := inactiveBootstrap[release.GetName()]; inactive {
			continue
		}
		result.activeHelmReleases++
		ready := kube.IsReady(release)
		result.helmReleases = append(result.helmReleases, ResourceStatus{
			Name: release.GetNamespace() + "/" + release.GetName(), Ready: ready,
		})
		if ready {
			result.readyHelmReleases++
		}
	}
	sort.Slice(result.helmReleases, func(left, right int) bool {
		return result.helmReleases[left].Name < result.helmReleases[right].Name
	})
	for _, resource := range platformWorkloadResources {
		workloads := snapshot.resource(resource)
		for index := range workloads {
			workload := &workloads[index]
			if workload.GetDeletionTimestamp() != nil ||
				workload.GetLabels()["helm.toolkit.fluxcd.io/name"] == "" {
				continue
			}
			result.activeWorkloads++
			if workloadControllerReady(resource, workload) {
				result.readyWorkloads++
			}
		}
	}
	for index := range snapshot.pods {
		pod := &snapshot.pods[index]
		if !pod.Deleting && !pod.Terminal() && !pod.Ready {
			result.nonReadyPods++
		}
		if systemNamespace(pod.Namespace) || pod.Terminal() {
			continue
		}
		if issue := podLockedImageIssue(pod, lockedImages); issue != "" {
			result.imageIssueCount++
			if len(result.imageIssues) < platformStatusIssueLimit {
				result.imageIssues = append(result.imageIssues, issue)
			}
		}
	}
	return result
}

func workloadControllerReady(resource kube.Resource, workload *kube.Object) bool {
	if workload == nil || workload.GetDeletionTimestamp() != nil {
		return false
	}
	observed, found, err := unstructured.NestedInt64(
		workload.Object, "status", "observedGeneration")
	if err != nil || !found || observed != workload.GetGeneration() {
		return false
	}
	switch resource {
	case kube.Deployment:
		desired := nestedReplicas(workload.Object, 1, "spec", "replicas")
		return nestedReplicas(workload.Object, 0, "status", "updatedReplicas") >= desired &&
			nestedReplicas(workload.Object, 0, "status", "readyReplicas") >= desired &&
			nestedReplicas(workload.Object, 0, "status", "availableReplicas") >= desired
	case kube.StatefulSet:
		desired := nestedReplicas(workload.Object, 1, "spec", "replicas")
		partition := nestedReplicas(
			workload.Object, 0, "spec", "updateStrategy", "rollingUpdate", "partition")
		if partition > desired {
			partition = desired
		}
		return nestedReplicas(workload.Object, 0, "status", "updatedReplicas") >= desired-partition &&
			nestedReplicas(workload.Object, 0, "status", "readyReplicas") >= desired
	case kube.DaemonSet:
		desired, found, err := unstructured.NestedInt64(
			workload.Object, "status", "desiredNumberScheduled")
		if err != nil || !found {
			return false
		}
		return nestedReplicas(workload.Object, 0, "status", "updatedNumberScheduled") >= desired &&
			nestedReplicas(workload.Object, 0, "status", "numberReady") >= desired &&
			nestedReplicas(workload.Object, 0, "status", "numberAvailable") >= desired
	default:
		return false
	}
}

func nestedReplicas(object map[string]any, fallback int64, fields ...string) int64 {
	value, found, err := unstructured.NestedInt64(object, fields...)
	if err != nil || !found {
		return fallback
	}
	return value
}

func (service Service) observeInternalSources(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	snapshot platformSnapshot,
) (sourceObservation, error) {
	result := sourceObservation{issues: make([]string, 0, platformStatusIssueLimit)}
	addIssue := func(issue string) {
		result.issueCount++
		if len(result.issues) < platformStatusIssueLimit {
			result.issues = append(result.issues, issue)
		}
	}
	if exact, err := service.profileObjectsExactSnapshot(ctx, client, snapshot); err != nil {
		return sourceObservation{}, err
	} else if !exact {
		addIssue("profile-specific objects remain outside the active profile")
	}
	if exact, err := service.exactGitSourcesSnapshot(bundle, snapshot.resource(kube.GitRepository)); err != nil {
		return sourceObservation{}, err
	} else if !exact {
		addIssue("Git repositories differ from the locked source set")
	}
	if exact, err := service.exactOCISourcesSnapshot(bundle, snapshot.resource(kube.OCIRepository)); err != nil {
		return sourceObservation{}, err
	} else if !exact {
		addIssue("OCI repositories differ from the locked chart set")
	}
	var err error
	result.ociSources, err = service.activeOCIStatusesSnapshot(
		bundle, snapshot.resource(kube.OCIRepository))
	if err != nil {
		return sourceObservation{}, err
	}
	if exact, err := service.exactHelmSourcesSnapshot(bundle, snapshot.resource(kube.HelmRepository)); err != nil {
		return sourceObservation{}, err
	} else if !exact {
		addIssue("Helm repositories differ from the locked chart set")
	}
	if exact, err := service.exactFluxConsumersSnapshot(ctx, client, bundle, snapshot); err != nil {
		return sourceObservation{}, err
	} else if !exact {
		addIssue("Flux consumers differ from the locked source bindings")
	}
	return result, nil
}

func (service Service) observeInternalRegistry(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	adminPassword string,
) (registryObservation, error) {
	var result registryObservation
	var err error
	result.imageExact, err = service.exactHarborImages(ctx, bundle, adminPassword)
	if err != nil {
		return registryObservation{}, err
	}
	result.chartsExact, err = service.exactHarborCharts(ctx, bundle, adminPassword)
	if err != nil {
		return registryObservation{}, err
	}
	harbor, err := newHarborControl(
		service.Project.Desired.Delivery.Registry, adminPassword)
	if err != nil {
		return registryObservation{}, err
	}
	result.chartsImmutable, err = harbor.chartsImmutable(ctx)
	if err != nil {
		return registryObservation{}, err
	}
	return result, nil
}

func (service Service) observeLocalAccess(
	ctx context.Context,
	client *kube.Observer,
	snapshot platformSnapshot,
) (localAccessObservation, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return localAccessObservation{}, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	var loadBalancer localLoadBalancerObservation
	var certificates localCertificateObservation
	if err := runStatusFamilies(ctx, 2, []statusFamilyTask{
		{name: "load balancer", run: func(taskContext context.Context) error {
			var err error
			loadBalancer, err = service.observeLocalLoadBalancer(taskContext, client)
			return err
		}},
		{name: "certificates", run: func(taskContext context.Context) error {
			var err error
			certificates, err = service.observeLocalCertificatesSnapshot(
				taskContext, client, snapshot)
			return err
		}},
	}); err != nil {
		return localAccessObservation{}, err
	}
	accessURLs, err := service.accessURLsSnapshot(snapshot.resource(kube.VirtualService))
	if err != nil {
		return localAccessObservation{}, err
	}
	routesReady, err := service.identityRoutesReady(accessURLs)
	if err != nil {
		return localAccessObservation{}, err
	}
	return localAccessObservation{
		loadBalancer: loadBalancer,
		certificates: certificates,
		issuerReady: target.LocalAccess == nil ||
			localPKIReadySnapshot(snapshot),
		accessURLs:  accessURLs,
		routesReady: routesReady,
	}, nil
}

func (service Service) identityRoutesReady(accessURLs []string) (bool, error) {
	relative, required := service.Project.Desired.ActiveIdentityContractPath()
	if !required {
		return true, nil
	}
	contract, err := identity.Load(service.Project.Root, relative)
	if err != nil {
		return false, err
	}
	expected := make(map[string]struct{}, len(contract.Clients())+len(contract.AdditionalEndpoints()))
	for _, client := range contract.Clients() {
		expected["https://"+client.Host] = struct{}{}
	}
	for _, endpoint := range contract.AdditionalEndpoints() {
		if endpoint.Access == identity.Browser {
			expected["https://"+endpoint.Host] = struct{}{}
		}
	}
	for _, observed := range accessURLs {
		delete(expected, observed)
	}
	return len(expected) == 0, nil
}

func mergeStatusObservations(service Service, observed statusObservations) Status {
	target, _ := service.Project.Desired.ActiveTarget()
	result := Status{
		BundleSHA256: observed.core.bundleSHA256, SourceCommit: observed.core.sourceCommit,
		ActiveProfile: target.PlatformProfile, BundleReady: observed.core.bundleReady,
		FluxReady: observed.core.fluxReady, PrepReady: observed.core.prepReady,
		ProfilePrepReady: observed.core.profilePrepReady, BigBangReady: observed.core.bigBangReady,
		ProfileAccessReady:     observed.core.profileAccessReady,
		ProfileIdentityReady:   observed.core.profileIdentityReady,
		ProfileIdentityFailure: observed.core.profileIdentityFailure,
		ClusterOIDCReady:       observed.oidc.ready,
		ClusterOIDCFailure:     observed.oidc.failure,
		OCISources:             observed.sources.ociSources, HelmReleases: observed.workloads.helmReleases,
		ActiveHelmReleases: observed.workloads.activeHelmReleases,
		ReadyHelmReleases:  observed.workloads.readyHelmReleases,
		ActiveWorkloads:    observed.workloads.activeWorkloads,
		ReadyWorkloads:     observed.workloads.readyWorkloads,
		NonReadyPods:       observed.workloads.nonReadyPods,
		InternalImageOnly:  observed.workloads.imageIssueCount == 0 && observed.registry.imageExact,
		ImageIssueCount:    observed.workloads.imageIssueCount,
		ImageIssues:        observed.workloads.imageIssues,
		InternalSourcesOnly: observed.sources.issueCount == 0 &&
			observed.registry.chartsExact && observed.registry.chartsImmutable,
		SourceIssueCount:      observed.sources.issueCount,
		SourceIssues:          observed.sources.issues,
		LoadBalancerRequired:  target.LocalAccess != nil,
		LoadBalancerReady:     observed.local.loadBalancer.ready,
		PublicIngressIPs:      observed.local.loadBalancer.publicIPs,
		PassthroughIngressIPs: observed.local.loadBalancer.passthroughIPs,
		CertificatesRequired:  target.LocalAccess != nil,
		CertificatesReady:     observed.local.certificates.ready,
		Certificates:          observed.local.certificates.resources,
		RootCAFingerprint:     observed.local.certificates.rootFingerprint,
		IssuerReady:           observed.local.issuerReady,
		AccessURLs:            observed.local.accessURLs,
		RoutesReady:           observed.local.routesReady,
	}
	_, result.ProfileIdentityRequired = service.Project.Desired.ActiveIdentityContractPath()
	result.ClusterOIDCRequired = result.ProfileIdentityRequired
	if !observed.registry.imageExact {
		result.addImageIssue("Harbor publication differs from the locked image set")
	}
	if !observed.registry.chartsExact {
		result.addSourceIssue("Harbor chart publication differs from the locked chart set")
	}
	if !observed.registry.chartsImmutable {
		result.addSourceIssue("Harbor chart tags are not immutable")
	}
	if target.LocalAccess != nil {
		result.AccessDomain = target.LocalAccess.Domain
		result.PublicIngressVIP = target.LocalAccess.PublicIngressVIP
		result.PassthroughIngressVIP = target.LocalAccess.PassthroughIngressVIP
		result.LoadBalancerRange = target.LocalAccess.LoadBalancerRange
	}
	return result
}

func snapshotResource(
	objects []kube.Object,
	namespace, name string,
) (*kube.Object, bool) {
	for index := range objects {
		if objects[index].GetNamespace() == namespace && objects[index].GetName() == name {
			return &objects[index], true
		}
	}
	return nil, false
}

func snapshotResourceReady(objects []kube.Object, namespace, name string) bool {
	object, found := snapshotResource(objects, namespace, name)
	return found && kube.IsReady(object)
}

const accessURLLimit = 128

func (service Service) accessURLsSnapshot(objects []kube.Object) ([]string, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return nil, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	if target.LocalAccess == nil {
		return nil, nil
	}
	domain := strings.ToLower(target.LocalAccess.Domain)
	unique := make(map[string]struct{}, min(len(objects), accessURLLimit))
	for index := range objects {
		hosts, found, nestedErr := unstructured.NestedStringSlice(
			objects[index].Object, "spec", "hosts")
		if nestedErr != nil {
			return nil, fmt.Errorf("read VirtualService %s/%s hosts: %w",
				objects[index].GetNamespace(), objects[index].GetName(), nestedErr)
		}
		if !found {
			continue
		}
		for _, rawHost := range hosts {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawHost), "."))
			if host == "" || strings.Contains(host, "*") ||
				(host != domain && !strings.HasSuffix(host, "."+domain)) {
				continue
			}
			url := "https://" + host
			if _, duplicate := unique[url]; duplicate {
				return nil, fmt.Errorf("local access route %s is declared more than once", url)
			}
			unique[url] = struct{}{}
			if len(unique) > accessURLLimit {
				return nil, fmt.Errorf("local access route count exceeds %d", accessURLLimit)
			}
		}
	}
	result := make([]string, 0, len(unique))
	for url := range unique {
		result = append(result, url)
	}
	sort.Strings(result)
	return result, nil
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func (service Service) inactiveBootstrapIDs() map[string]struct{} {
	active := make(map[string]struct{}, len(service.Project.Desired.ActiveBootstrapCharts()))
	for _, chart := range service.Project.Desired.ActiveBootstrapCharts() {
		active[chart.ID] = struct{}{}
	}
	inactive := make(map[string]struct{},
		len(service.Project.Desired.Platform.Bootstrap.Charts)-len(active))
	for _, chart := range service.Project.Desired.Platform.Bootstrap.Charts {
		if _, found := active[chart.ID]; !found {
			inactive[chart.ID] = struct{}{}
		}
	}
	return inactive
}

func (service Service) activeOCIStatusesSnapshot(
	bundle *delivery.DeploymentBundle,
	objects []kube.Object,
) ([]ResourceStatus, error) {
	expected, err := bootstrapOCISources(bundle, service.Project.Desired.ActiveBootstrapCharts())
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]ResourceStatus, len(keys))
	for index := range keys {
		namespace, name, found := strings.Cut(keys[index], "/")
		if !found {
			return nil, fmt.Errorf("invalid expected OCIRepository identity %q", keys[index])
		}
		object, objectFound := snapshotResource(objects, namespace, name)
		result[index] = ResourceStatus{
			Name: keys[index], Ready: objectFound && kube.IsReady(object),
		}
	}
	return result, nil
}

func (service Service) profileObjectsExactSnapshot(
	ctx context.Context,
	client *kube.Observer,
	snapshot platformSnapshot,
) (bool, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return false, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	if target.LocalAccess != nil {
		return true, nil
	}
	for _, identity := range []struct {
		resource  kube.Resource
		namespace string
		name      string
	}{
		{resource: kube.HelmRelease, namespace: "kube-system", name: "kube-vip"},
		{resource: kube.HelmRelease, namespace: "kube-system", name: "kube-vip-cloud-provider"},
		{resource: kube.ClusterIssuer, name: "atum-test-selfsigned"},
		{resource: kube.ClusterIssuer, name: "atum-test-ca"},
		{resource: kube.Certificate, namespace: "cert-manager", name: "atum-test-root-ca"},
		{resource: kube.Certificate, namespace: "istio-gateway", name: "public-cert"},
		{resource: kube.Certificate, namespace: "keycloak", name: "keycloak-tls"},
	} {
		if _, found := snapshotResource(
			snapshot.resource(identity.resource), identity.namespace, identity.name); found {
			return false, nil
		}
	}
	_, allocatorFound, err := client.ConfigMapData(
		ctx, "kube-system", "kube-vip-cloud-provider")
	if err != nil {
		return false, fmt.Errorf("read inactive profile allocator: %w", err)
	}
	return !allocatorFound, nil
}

func reportExactStatus(ctx context.Context, status Status) {
	report := func(id, label, detail string, ready bool) {
		if ready {
			progress.Done(ctx, progress.Platform, id, label, detail)
			return
		}
		progress.Fail(ctx, progress.Platform, id, label, errors.New(detail+" not satisfied"))
	}
	report("bundle", "Deployment bundle", "exact bundle active", status.BundleReady)
	report("flux", "Flux", "controllers healthy", status.FluxReady)
	report("prep", "Platform prerequisites", "common prerequisites ready", status.PrepReady)
	report("platform-profile-prep", "Platform profile prerequisites",
		"active profile prerequisites ready", status.ProfilePrepReady)
	if status.InternalSourcesOnly {
		progress.Done(ctx, progress.Platform, "sources", "Internal sources", "exact internal sources")
	} else {
		progress.Fail(ctx, progress.Platform, "sources", "Internal sources", errors.New(status.sourceFailureDetail()))
	}
	if status.InternalImageOnly {
		progress.Done(ctx, progress.Platform, "images", "Runtime images", "exact internal images")
	} else {
		progress.Fail(ctx, progress.Platform, "images", "Runtime images", errors.New(status.imageFailureDetail()))
	}
	report("bigbang", "Big Bang",
		fmt.Sprintf("%d/%d releases; %d/%d workloads; %d non-ready pods",
			status.ReadyHelmReleases, status.ActiveHelmReleases,
			status.ReadyWorkloads, status.ActiveWorkloads, status.NonReadyPods),
		status.BigBangReady && status.ActiveHelmReleases > 0 &&
			status.ReadyHelmReleases == status.ActiveHelmReleases &&
			status.ReadyWorkloads == status.ActiveWorkloads && status.NonReadyPods == 0,
	)
	report("platform-profile-access", "Platform profile access",
		"active profile access ready", status.ProfileAccessReady)
	if status.ProfileIdentityRequired {
		if status.ProfileIdentityFailure != "" {
			progress.Fail(ctx, progress.Platform, "platform-profile-identity",
				"Platform profile identity", errors.New(status.ProfileIdentityFailure))
		} else {
			report("platform-profile-identity", "Platform profile identity",
				"identity reconciliation complete", status.ProfileIdentityReady)
		}
	}
	if status.ClusterOIDCRequired {
		if status.ClusterOIDCFailure != "" {
			progress.Fail(ctx, progress.Platform, "cluster-oidc",
				"Cluster OIDC", errors.New(status.ClusterOIDCFailure))
		} else {
			report("cluster-oidc", "Cluster OIDC",
				"all control-plane authentication digests exact", status.ClusterOIDCReady)
		}
	}
	if status.LoadBalancerRequired {
		report("kube-vip", "kube-vip", "gateway VIPs and allocator range exact", status.LoadBalancerReady)
	}
	if status.CertificatesRequired {
		detail := "waiting for issuers, SANs, Secrets, and validity"
		if status.CertificatesReady {
			detail = "cluster certificates exact; waiting for host CA trust"
		}
		progress.Update(ctx, progress.Platform, "local-certificates", "Local certificates",
			detail, 0, 0)
	}
}

type certificateExpectation struct {
	namespace string
	name      string
	secret    string
	dnsNames  []string
}

type localCertificateObservation struct {
	ready           bool
	rootFingerprint string
	rootPEM         []byte
	resources       []ResourceStatus
}

func localPKIReadySnapshot(snapshot platformSnapshot) bool {
	return snapshotResourceReady(
		snapshot.resource(kube.ClusterIssuer), "", "atum-test-selfsigned") &&
		snapshotResourceReady(
			snapshot.resource(kube.Certificate), "cert-manager", "atum-test-root-ca") &&
		snapshotResourceReady(snapshot.resource(kube.ClusterIssuer), "", "atum-test-ca")
}

func (service Service) observeLocalCertificatesSnapshot(
	ctx context.Context,
	client *kube.Observer,
	snapshot platformSnapshot,
) (localCertificateObservation, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return localCertificateObservation{}, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	if target.LocalAccess == nil {
		return localCertificateObservation{ready: true}, nil
	}
	domain := target.LocalAccess.Domain
	expectations := [...]certificateExpectation{
		{
			namespace: "istio-gateway",
			name:      "public-cert",
			secret:    "public-cert",
			dnsNames:  []string{domain, "*." + domain},
		},
		{
			namespace: "keycloak",
			name:      "keycloak-tls",
			secret:    "keycloak-tls",
			dnsNames:  []string{"keycloak." + domain},
		},
	}
	type observation struct {
		ready bool
		err   error
	}
	var observed [len(expectations)]observation
	group, groupContext := errgroup.WithContext(ctx)
	now := time.Now()
	for index := range expectations {
		index := index
		group.Go(func() error {
			observed[index].ready, observed[index].err =
				certificateReadySnapshot(
					groupContext, client, snapshot.resource(kube.Certificate), expectations[index], now)
			return observed[index].err
		})
	}
	if err := group.Wait(); err != nil {
		return localCertificateObservation{}, fmt.Errorf("observe local certificates: %w", err)
	}
	result := localCertificateObservation{
		ready: true, resources: make([]ResourceStatus, 0, len(expectations)),
	}
	for index := range observed {
		result.resources = append(result.resources, ResourceStatus{
			Name:  expectations[index].namespace + "/" + expectations[index].name,
			Ready: observed[index].ready,
		})
		if !observed[index].ready {
			result.ready = false
		}
	}
	root, found, err := client.SecretValue(
		ctx, "cert-manager", "atum-test-root-ca", "tls.crt")
	if err != nil {
		return localCertificateObservation{}, fmt.Errorf("read local root CA: %w", err)
	}
	if found {
		defer clear(root)
		certificate, validationErr := infra.ValidateRootCA(root, time.Now())
		if validationErr == nil {
			result.rootFingerprint = certificate.Fingerprint
			result.rootPEM = append([]byte(nil), certificate.PEM...)
			certificate.Clear()
		} else {
			result.ready = false
		}
	} else {
		result.ready = false
	}
	result.ready = result.ready && localPKIReadySnapshot(snapshot)
	return result, nil
}

func (service Service) observeClusterOIDC(
	snapshot platformSnapshot,
	certificates localCertificateObservation,
) (clusterOIDCObservation, *orchestration.PlatformOIDCSpec, error) {
	relative, required := service.Project.Desired.ActiveIdentityContractPath()
	if !required {
		return clusterOIDCObservation{ready: true}, nil, nil
	}
	if !certificates.ready || len(certificates.rootPEM) == 0 {
		return clusterOIDCObservation{
			failure: "validated local root CA is unavailable",
		}, nil, nil
	}
	contract, err := identity.Load(service.Project.Root, relative)
	if err != nil {
		return clusterOIDCObservation{}, nil, err
	}
	spec, err := orchestration.NewPlatformOIDCSpec(contract, infra.ValidatedCA{
		PEM: certificates.rootPEM, Fingerprint: certificates.rootFingerprint,
	}, snapshot.serverVersion)
	if err != nil {
		return clusterOIDCObservation{}, nil, err
	}
	if snapshot.oidcReceipt == nil {
		return clusterOIDCObservation{
			failure: "kube-system/atum-authentication receipt is absent",
		}, spec, nil
	}
	ready, failure := orchestration.ValidatePlatformOIDCReceipt(
		spec, snapshot.oidcReceipt, controlPlaneNodeCount(snapshot.nodes))
	return clusterOIDCObservation{ready: ready, failure: failure}, spec, nil
}

func controlPlaneNodeCount(nodes []kube.Node) int {
	count := 0
	for index := range nodes {
		if nodes[index].ControlPlane {
			count++
		}
	}
	return count
}

func certificateReadySnapshot(
	ctx context.Context,
	client *kube.Observer,
	certificates []kube.Object,
	expected certificateExpectation,
	now time.Time,
) (bool, error) {
	object, found := snapshotResource(certificates, expected.namespace, expected.name)
	if !found || !kube.IsReady(object) {
		return false, nil
	}
	return certificateObjectReady(ctx, client, object, expected, now)
}

func certificateObjectReady(
	ctx context.Context,
	client *kube.Observer,
	object *kube.Object,
	expected certificateExpectation,
	now time.Time,
) (bool, error) {
	secretName, _, _ := unstructured.NestedString(object.Object, "spec", "secretName")
	dnsNames, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "dnsNames")
	issuerName, _, _ := unstructured.NestedString(object.Object, "spec", "issuerRef", "name")
	issuerKind, _, _ := unstructured.NestedString(object.Object, "spec", "issuerRef", "kind")
	issuerGroup, _, _ := unstructured.NestedString(object.Object, "spec", "issuerRef", "group")
	if secretName != expected.secret || !sameStrings(dnsNames, expected.dnsNames) ||
		issuerName != "atum-test-ca" || issuerKind != "ClusterIssuer" ||
		issuerGroup != "cert-manager.io" {
		return false, nil
	}
	secret, secretFound, err := client.TLSSecret(ctx, expected.namespace, expected.secret)
	if err != nil {
		return false, fmt.Errorf("read certificate Secret %s/%s: %w",
			expected.namespace, expected.secret, err)
	}
	defer clear(secret.Certificate)
	if !secretFound || secret.Namespace != expected.namespace || secret.Name != expected.secret ||
		secret.Type != "kubernetes.io/tls" || !secret.CertificatePresent ||
		!secret.PrivateKeyPresent {
		return false, nil
	}
	certificatePEM := bytes.TrimSpace(secret.Certificate)
	certificateBegin := []byte("-----BEGIN CERTIFICATE-----")
	if !bytes.HasPrefix(certificatePEM, certificateBegin) ||
		bytes.Contains(certificatePEM[len(certificateBegin):], certificateBegin) {
		return false, nil
	}
	block, rest := pem.Decode(certificatePEM)
	if block == nil {
		return false, nil
	}
	defer clear(block.Bytes)
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return false, nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, nil
	}
	return !leaf.IsCA && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) &&
		sameStrings(leaf.DNSNames, expected.dnsNames) && certificateServerAuth(leaf), nil
}

func certificateServerAuth(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func sameStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, value := range actual {
		actualCount, expectedCount := 0, 0
		for _, candidate := range actual {
			if candidate == value {
				actualCount++
			}
		}
		for _, candidate := range expected {
			if candidate == value {
				expectedCount++
			}
		}
		if actualCount != expectedCount {
			return false
		}
	}
	return true
}

type localLoadBalancerObservation struct {
	ready          bool
	publicIPs      []string
	passthroughIPs []string
}

func (service Service) observeLocalLoadBalancer(
	ctx context.Context,
	client *kube.Observer,
) (localLoadBalancerObservation, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return localLoadBalancerObservation{}, fmt.Errorf("active infrastructure target %q is not defined",
			service.Project.Desired.Infrastructure.Active)
	}
	if target.LocalAccess == nil {
		return localLoadBalancerObservation{ready: true}, nil
	}

	type serviceObservation struct {
		ips   []string
		found bool
		err   error
	}
	services := [...]struct {
		name string
		want string
	}{
		{name: "public-ingressgateway", want: target.LocalAccess.PublicIngressVIP},
		{name: "passthrough-ingressgateway", want: target.LocalAccess.PassthroughIngressVIP},
	}
	var observed [2]serviceObservation
	var allocator struct {
		data  map[string]string
		found bool
		err   error
	}
	group, groupContext := errgroup.WithContext(ctx)
	for index := range services {
		index := index
		group.Go(func() error {
			observed[index].ips, observed[index].found, observed[index].err =
				client.ServiceIngressIPs(groupContext, "istio-gateway", services[index].name)
			return observed[index].err
		})
	}
	group.Go(func() error {
		allocator.data, allocator.found, allocator.err =
			client.ConfigMapData(groupContext, "kube-system", "kube-vip-cloud-provider")
		return allocator.err
	})
	if err := group.Wait(); err != nil {
		return localLoadBalancerObservation{}, fmt.Errorf("observe local Service load balancer: %w", err)
	}
	result := localLoadBalancerObservation{
		ready: true, publicIPs: observed[0].ips, passthroughIPs: observed[1].ips,
	}
	for index := range services {
		if !observed[index].found || len(observed[index].ips) != 1 ||
			observed[index].ips[0] != services[index].want {
			result.ready = false
		}
	}
	result.ready = result.ready && allocator.found && len(allocator.data) == 1 &&
		allocator.data["range-global"] == target.LocalAccess.LoadBalancerRange
	return result, nil
}

func (status *Status) addImageIssue(issue string) {
	status.ImageIssueCount++
	if len(status.ImageIssues) < platformStatusIssueLimit {
		status.ImageIssues = append(status.ImageIssues, issue)
	}
}

func (status *Status) addSourceIssue(issue string) {
	status.InternalSourcesOnly = false
	status.SourceIssueCount++
	if len(status.SourceIssues) < platformStatusIssueLimit {
		status.SourceIssues = append(status.SourceIssues, issue)
	}
}

func (status Status) imageFailureDetail() string {
	if len(status.ImageIssues) == 0 {
		return "runtime images differ from the locked image set"
	}
	detail := "runtime image mismatch: " + status.ImageIssues[0]
	if status.ImageIssueCount > 1 {
		detail += fmt.Sprintf(" (+%d more)", status.ImageIssueCount-1)
	}
	return detail
}

func (status Status) sourceFailureDetail() string {
	if len(status.SourceIssues) == 0 {
		return "internal sources differ from the locked source set"
	}
	detail := "source mismatch: " + status.SourceIssues[0]
	if status.SourceIssueCount > 1 {
		detail += fmt.Sprintf(" (+%d more)", status.SourceIssueCount-1)
	}
	return detail
}

func (service Service) exactHarborImages(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	adminPassword string,
) (bool, error) {
	registry, err := atumoci.NewClient(service.Project.Desired.Delivery.Registry, atumoci.Credentials{
		Username: "admin", Password: adminPassword,
	})
	if err != nil {
		return false, err
	}
	var exact atomic.Bool
	exact.Store(true)
	err = runStatusImageChecks(
		ctx,
		service.Project.Desired.Updates.Parallelism,
		len(bundle.Images),
		func(checkContext context.Context, index int) error {
			image := bundle.Images[index]
			descriptor, err := registry.Resolve(checkContext, image.Target)
			if errors.Is(err, errdef.ErrNotFound) {
				exact.Store(false)
				return nil
			}
			if err != nil {
				return err
			}
			if descriptor.Digest.String() != image.Digest {
				exact.Store(false)
				return nil
			}
			return registry.ValidateLinuxAMD64(checkContext, image.Target, descriptor)
		},
	)
	if err != nil {
		return false, fmt.Errorf("verify Harbor image publication: %w", err)
	}
	return exact.Load(), nil
}

func runStatusImageChecks(
	ctx context.Context,
	configuredParallelism, count int,
	check func(context.Context, int) error,
) error {
	group, groupContext := errgroup.WithContext(ctx)
	parallelism := min(max(configuredParallelism, 1), statusHarborImageLimit)
	group.SetLimit(parallelism)
	for index := range count {
		index := index
		group.Go(func() error {
			return check(groupContext, index)
		})
	}
	return group.Wait()
}

func (service Service) exactHarborCharts(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	adminPassword string,
) (bool, error) {
	credentials := registryCredentials{Username: "admin", Password: adminPassword}
	resolver, err := atumoci.NewClient(service.Project.Desired.Delivery.Registry, atumoci.Credentials{
		Username: credentials.Username, Password: credentials.Password, CACert: credentials.CA,
	})
	if err != nil {
		return false, err
	}
	for _, chart := range bundle.Charts {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		descriptor, err := resolver.Resolve(ctx, chart.Target)
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		relative, err := filepath.Rel(service.Project.Root, chart.Path)
		if err != nil {
			return false, fmt.Errorf("resolve bundled chart %s: %w", chart.ID, err)
		}
		file, err := fssecure.OpenRegular(service.Project.Root, relative)
		if err != nil {
			return false, fmt.Errorf("inspect bundled chart %s: %w", chart.ID, err)
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil {
			return false, errors.Join(statErr, closeErr)
		}
		if !info.Mode().IsRegular() || info.Size() != chart.Size || chart.Size <= 0 || chart.Size > config.ChartArchiveLimit {
			return false, fmt.Errorf("bundled chart %s has invalid size %d", chart.ID, info.Size())
		}
		if err := resolver.ValidateHelmChart(ctx, chart.Target, descriptor, chart.ArchiveSHA256, info.Size()); err != nil {
			return false, fmt.Errorf("verify Harbor chart %s: %w", chart.ID, err)
		}
	}
	return true, nil
}

const platformStatusIssueLimit = 16

type assetReadiness struct {
	releasesReady  int
	releasesTotal  int
	workloadsReady int
	workloadsTotal int
	podsReady      int
	podsTotal      int
	activity       string
	activityRank   uint8
}

type platformReadinessIndex struct {
	ids     []string
	set     map[string]struct{}
	aliases map[string]string
}

func newPlatformReadinessIndex(
	project *config.Project,
	wrapperConsumers []config.WrapperConsumer,
) platformReadinessIndex {
	activeBootstrap := project.Desired.ActiveBootstrapCharts()
	capacity :=
		len(activeBootstrap) +
			len(project.Desired.Platform.Packages) + len(project.Desired.Platform.Charts)
	index := platformReadinessIndex{
		ids:     make([]string, 0, capacity),
		set:     make(map[string]struct{}, capacity),
		aliases: make(map[string]string, capacity),
	}
	appendAsset := func(id string, aliases ...string) {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			return
		}
		if _, found := index.set[id]; !found {
			index.set[id] = struct{}{}
			index.ids = append(index.ids, id)
		}
		for _, raw := range aliases {
			alias := strings.ToLower(strings.TrimSpace(raw))
			if alias == "" || alias == id {
				continue
			}
			if previous, found := index.aliases[alias]; !found {
				index.aliases[alias] = id
			} else if previous != id {
				// An ambiguous alias is deliberately unusable. Exact canonical
				// IDs still take precedence in match.
				index.aliases[alias] = ""
			}
		}
	}
	for _, chart := range activeBootstrap {
		appendAsset(chart.ID, chart.Name)
	}
	for _, pkg := range project.Desired.Platform.Packages {
		appendAsset(pkg.ID, pkg.RenderedFluxName())
	}
	for _, chart := range project.Desired.Platform.Charts {
		appendAsset(chart.ID, chart.Name, valuesPathLeaf(chart.ValuesPath))
	}
	for _, consumer := range wrapperConsumers {
		appendAsset(consumer.OwnerID, consumer.ReleaseName)
	}
	return index
}

func valuesPathLeaf(value string) string {
	value = strings.TrimSpace(value)
	if boundary := strings.LastIndexByte(value, '.'); boundary >= 0 {
		return value[boundary+1:]
	}
	return value
}

func (index platformReadinessIndex) exact(candidate string) string {
	if _, found := index.set[candidate]; found {
		return candidate
	}
	return index.aliases[candidate]
}

func (index platformReadinessIndex) match(candidates ...string) string {
	for _, raw := range candidates {
		candidate := strings.ToLower(strings.TrimSpace(raw))
		if candidate == "" {
			continue
		}
		if matched := index.exact(candidate); matched != "" {
			return matched
		}
		matched, matchedLength := "", 0
		for boundary := 1; boundary < len(candidate)-1; boundary++ {
			if candidate[boundary] != '-' {
				continue
			}
			if prefix := candidate[:boundary]; len(prefix) > matchedLength {
				if id := index.exact(prefix); id != "" {
					matched, matchedLength = id, len(prefix)
				}
			}
			if suffix := candidate[boundary+1:]; len(suffix) > matchedLength {
				if id := index.exact(suffix); id != "" {
					matched, matchedLength = id, len(suffix)
				}
			}
		}
		if matched != "" {
			return matched
		}
	}
	return ""
}

const applyReadinessInterval = 2 * time.Second

func (service Service) coordinatePlatformApply(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	publication publicationReceipt,
) error {
	values, err := mergedBigBangValues(bundle, service.Project.Desired)
	if err != nil {
		return err
	}
	wrapperConsumers, err := config.ActiveWrapperConsumers(service.Project.Desired.Platform, values)
	if err != nil {
		return fmt.Errorf("project active wrapper consumers: %w", err)
	}
	index := newPlatformReadinessIndex(service.Project, wrapperConsumers)
	assets := make(map[string]assetReadiness, len(index.ids))
	namespaces := make(map[string]string, len(index.ids))
	contract, err := service.identityContract()
	if err != nil {
		return err
	}
	observe := func(roundContext context.Context) (platformApplyObservation, error) {
		status, snapshot, spec, err := service.collectStatus(
			roundContext, client, bundle, nil, &publication)
		if err != nil {
			return platformApplyObservation{}, err
		}
		reportApplyReadiness(roundContext, status)
		projectAssetReadiness(snapshot, index, assets, namespaces)
		reportAssetReadiness(roundContext, index, assets)
		return platformApplyObservation{
			platformReady: status.readyBeforeClusterOIDC(),
			oidcPrerequisitesReady: status.ProfileIdentityReady &&
				status.CertificatesReady && status.RootCAFingerprint != "" &&
				spec != nil,
			oidcFailure: status.ProfileIdentityFailure,
			oidcSpec:    spec,
		}, nil
	}
	err = coordinateApplyObligations(
		ctx, applyReadinessInterval, contract != nil, observe,
		service.Orchestration.ReconcilePlatformOIDC,
	)
	return finishPlatformReadiness(ctx, err)
}

type platformApplyObservation struct {
	platformReady          bool
	oidcPrerequisitesReady bool
	oidcFailure            string
	oidcSpec               *orchestration.PlatformOIDCSpec
}

func (observation *platformApplyObservation) clear() {
	if observation.oidcSpec != nil {
		observation.oidcSpec.Clear()
		observation.oidcSpec = nil
	}
}

func coordinateApplyObligations(
	ctx context.Context,
	interval time.Duration,
	oidcRequired bool,
	observe func(context.Context) (platformApplyObservation, error),
	reconcile func(context.Context, *orchestration.PlatformOIDCSpec) error,
) error {
	if interval <= 0 {
		return errors.New("apply observation interval must be positive")
	}
	if observe == nil || (oidcRequired && reconcile == nil) {
		return errors.New("complete apply observation and reconciliation functions are required")
	}
	coordinationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.NewTimer(0)
	defer timer.Stop()
	oidcResults := make(chan error, 1)
	platformReady := false
	oidcDone := !oidcRequired
	oidcRunning := false

	waitForOIDC := func(primary error) error {
		if !oidcRunning {
			return primary
		}
		oidcErr := <-oidcResults
		oidcRunning = false
		return joinPlatformObligations([2]error{primary, oidcErr})
	}

	for !platformReady || !oidcDone {
		select {
		case <-coordinationContext.Done():
			cancel()
			return waitForOIDC(coordinationContext.Err())
		case oidcErr := <-oidcResults:
			oidcRunning = false
			if oidcErr != nil {
				cancel()
				return oidcErr
			}
			oidcDone = true
		case <-timer.C:
			observation, err := observe(coordinationContext)
			if err != nil {
				observation.clear()
				if coordinationContext.Err() != nil {
					cancel()
					return waitForOIDC(coordinationContext.Err())
				}
				if !retryableObservationError(err) {
					cancel()
					return waitForOIDC(err)
				}
				reportPlatformObservationRetry(coordinationContext)
			} else {
				platformReady = platformReady || observation.platformReady
				if observation.oidcFailure != "" {
					observation.clear()
					cancel()
					return waitForOIDC(errors.New(observation.oidcFailure))
				}
				if !oidcDone && !oidcRunning {
					if observation.oidcPrerequisitesReady {
						if observation.oidcSpec == nil {
							cancel()
							return errors.New(
								"OIDC prerequisites are ready without an immutable specification")
						}
						spec := observation.oidcSpec
						observation.oidcSpec = nil
						oidcRunning = true
						go func() {
							defer spec.Clear()
							oidcResults <- reconcile(coordinationContext, spec)
						}()
					} else {
						progress.Update(
							coordinationContext, progress.Platform,
							"cluster-oidc", "Cluster OIDC",
							"waiting for profile identity and local root CA", 0, 0)
					}
				}
				observation.clear()
			}
			if !platformReady || !oidcDone {
				timer.Reset(interval)
			}
		}
	}
	return nil
}

func finishPlatformReadiness(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if parentErr := ctx.Err(); parentErr != nil {
		if errors.Is(parentErr, context.DeadlineExceeded) {
			return fmt.Errorf("wait for platform readiness: %w", parentErr)
		}
		return parentErr
	}
	result := fmt.Errorf("wait for platform readiness: %w", err)
	progress.Fail(ctx, progress.Platform, "bigbang", "Big Bang", result)
	return result
}

func waitReadinessCycles(
	ctx context.Context,
	timeout, interval time.Duration,
	observe func(context.Context) (bool, error),
) error {
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return waitReadinessCyclesContext(waitContext, interval, observe, reportPlatformObservationRetry)
}

func waitReadinessCyclesContext(
	waitContext context.Context,
	interval time.Duration,
	observe func(context.Context) (bool, error),
	reportRetry func(context.Context),
) error {
	if interval <= 0 {
		return errors.New("readiness observation interval must be positive")
	}
	if observe == nil {
		return errors.New("readiness observer is required")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-waitContext.Done():
			return waitContext.Err()
		case <-timer.C:
		}
		ready, err := observe(waitContext)
		if err == nil && ready {
			return nil
		}
		if err != nil {
			if waitContext.Err() != nil {
				return waitContext.Err()
			}
			if !retryableObservationError(err) {
				return err
			}
			if reportRetry != nil {
				reportRetry(waitContext)
			}
		}
		timer.Reset(interval)
	}
}

func reportPlatformObservationRetry(ctx context.Context) {
	progress.Update(ctx, progress.Platform, "bigbang", "Big Bang",
		"Kubernetes API observation interrupted; retrying", 0, 0)
}

func retryableObservationError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) || apierrors.IsTooManyRequests(err) ||
		apierrors.IsServiceUnavailable(err)
}

func reportApplyReadiness(ctx context.Context, status Status) {
	if status.FluxReady {
		progress.Done(ctx, progress.Platform, "flux", "Flux", "controllers healthy")
	} else {
		progress.Start(ctx, progress.Platform, "flux", "Flux", "waiting for controllers")
	}
	if status.InternalSourcesOnly {
		progress.Done(ctx, progress.Platform, "sources", "Internal sources",
			"live source and consumer bindings exact")
	} else {
		progress.Update(ctx, progress.Platform, "sources", "Internal sources",
			status.sourceFailureDetail(), 0, 0)
	}
	if status.InternalImageOnly {
		progress.Done(ctx, progress.Platform, "images", "Runtime images",
			"live pod images match the seed publication")
	} else {
		progress.Update(ctx, progress.Platform, "images", "Runtime images",
			status.imageFailureDetail(), 0, 0)
	}
	if status.LoadBalancerRequired {
		if status.LoadBalancerReady {
			progress.Done(ctx, progress.Platform, "kube-vip", "kube-vip",
				"gateway VIPs and allocator range exact")
		} else {
			progress.Update(ctx, progress.Platform, "kube-vip", "kube-vip",
				"waiting for gateway VIPs and allocator range", 0, 0)
		}
	}
	if status.CertificatesRequired {
		detail := "waiting for issuers, SANs, Secrets, and validity"
		if status.CertificatesReady {
			detail = "cluster certificates exact; waiting for host CA trust"
		}
		progress.Update(ctx, progress.Platform, "local-certificates", "Local certificates",
			detail, 0, 0)
	}
	if status.PrepReady {
		progress.Done(ctx, progress.Platform, "prep", "Platform prerequisites", "common prerequisites ready")
	} else {
		progress.Update(ctx, progress.Platform, "prep", "Platform prerequisites",
			"waiting for common prerequisites", 0, 0)
	}
	if status.ProfilePrepReady {
		progress.Done(ctx, progress.Platform, "platform-profile-prep", "Platform profile prerequisites",
			"active profile prerequisites ready")
	} else {
		progress.Update(ctx, progress.Platform, "platform-profile-prep", "Platform profile prerequisites",
			"waiting for active profile prerequisites", 0, 0)
	}
	if status.ProfileAccessReady {
		progress.Done(ctx, progress.Platform, "platform-profile-access", "Platform profile access",
			"active profile access ready")
	} else {
		progress.Update(ctx, progress.Platform, "platform-profile-access", "Platform profile access",
			"waiting for active profile access", 0, 0)
	}
	if status.ProfileIdentityRequired {
		if status.ProfileIdentityFailure != "" {
			progress.Fail(ctx, progress.Platform, "platform-profile-identity",
				"Platform profile identity", errors.New(status.ProfileIdentityFailure))
		} else if status.ProfileIdentityReady {
			progress.Done(ctx, progress.Platform, "platform-profile-identity", "Platform profile identity",
				"identity reconciliation complete")
		} else {
			progress.Update(ctx, progress.Platform, "platform-profile-identity", "Platform profile identity",
				"waiting for identity reconciliation", 0, 0)
		}
	}
	bigBangHealthy := status.BigBangReady && status.ProfileAccessReady &&
		status.ActiveHelmReleases > 0 &&
		status.ActiveHelmReleases == status.ReadyHelmReleases &&
		status.ActiveWorkloads == status.ReadyWorkloads && status.NonReadyPods == 0
	if bigBangHealthy {
		progress.Done(ctx, progress.Platform, "bigbang", "Big Bang",
			fmt.Sprintf("%d/%d releases; %d/%d workloads; all pods ready",
				status.ReadyHelmReleases, status.ActiveHelmReleases,
				status.ReadyWorkloads, status.ActiveWorkloads))
	} else {
		progress.Update(ctx, progress.Platform, "bigbang", "Big Bang",
			fmt.Sprintf("%d/%d releases; %d/%d workloads; %d non-ready pods",
				status.ReadyHelmReleases, status.ActiveHelmReleases,
				status.ReadyWorkloads, status.ActiveWorkloads, status.NonReadyPods), 0, 0)
	}
}

func projectAssetReadiness(
	snapshot platformSnapshot,
	index platformReadinessIndex,
	assets map[string]assetReadiness,
	namespaces map[string]string,
) {
	clear(assets)
	clear(namespaces)
	releases := snapshot.resource(kube.HelmRelease)
	for itemIndex := range releases {
		item := &releases[itemIndex]
		if item.GetDeletionTimestamp() != nil {
			continue
		}
		source, _, _ := unstructured.NestedString(item.Object, "spec", "chart", "spec", "sourceRef", "name")
		chartRef, _, _ := unstructured.NestedString(item.Object, "spec", "chartRef", "name")
		id := index.match(
			item.GetName(), item.GetLabels()["app.kubernetes.io/name"],
			item.GetLabels()["app.kubernetes.io/instance"], chartRef, source, item.GetNamespace(),
		)
		if id == "" || id == "kube-vip" {
			continue
		}
		asset := assets[id]
		asset.releasesTotal++
		if kube.IsReady(item) {
			asset.releasesReady++
		} else if activity, rank := helmReleaseActivity(item.Object); rank > asset.activityRank {
			asset.activity = activity
			asset.activityRank = rank
		}
		assets[id] = asset
		namespace, _, _ := unstructured.NestedString(item.Object, "spec", "targetNamespace")
		if namespace == "" {
			namespace = item.GetNamespace()
		}
		if previous, found := namespaces[namespace]; !found {
			namespaces[namespace] = id
		} else if previous != id {
			namespaces[namespace] = ""
		}
	}
	for _, resource := range platformWorkloadResources {
		workloads := snapshot.resource(resource)
		for workloadIndex := range workloads {
			workload := &workloads[workloadIndex]
			if workload.GetDeletionTimestamp() != nil {
				continue
			}
			labels := workload.GetLabels()
			id := index.match(
				labels["helm.toolkit.fluxcd.io/name"], labels["app.kubernetes.io/instance"],
				labels["app.kubernetes.io/name"], labels["app"], labels["release"],
				workload.GetName(),
			)
			if id == "" {
				id = namespaces[workload.GetNamespace()]
			}
			if id == "" || id == "kube-vip" {
				continue
			}
			asset := assets[id]
			asset.workloadsTotal++
			if workloadControllerReady(resource, workload) {
				asset.workloadsReady++
			}
			assets[id] = asset
		}
	}
	for podIndex := range snapshot.pods {
		pod := &snapshot.pods[podIndex]
		if pod.Deleting || pod.Terminal() {
			continue
		}
		labels := pod.Labels
		id := index.match(
			labels["helm.toolkit.fluxcd.io/name"], labels["app.kubernetes.io/instance"],
			labels["app.kubernetes.io/name"], labels["app"], labels["release"],
		)
		if id == "" {
			id = namespaces[pod.Namespace]
		}
		if id == "" || id == "kube-vip" {
			continue
		}
		asset := assets[id]
		asset.podsTotal++
		if pod.Ready {
			asset.podsReady++
		}
		assets[id] = asset
	}
}

func helmReleaseActivity(object map[string]any) (string, uint8) {
	status, found := object["status"].(map[string]any)
	if !found {
		return "waiting for release status", 1
	}
	conditions, found := status["conditions"].([]any)
	if !found {
		return "waiting for release status", 1
	}
	readyActivity := ""
	for _, value := range conditions {
		condition, valid := value.(map[string]any)
		if !valid {
			continue
		}
		conditionType, _ := condition["type"].(string)
		conditionStatus, _ := condition["status"].(string)
		message, _ := condition["message"].(string)
		message = firstLine(message)
		if conditionType == "Reconciling" && conditionStatus == "True" && message != "" {
			return message, 3
		}
		if conditionType == "Ready" && conditionStatus != "True" && message != "" {
			readyActivity = message
		}
	}
	if readyActivity != "" {
		return readyActivity, 2
	}
	return "waiting for release readiness", 1
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if line, _, found := strings.Cut(value, "\n"); found {
		return strings.TrimSpace(line)
	}
	return value
}

func reportAssetReadiness(ctx context.Context, index platformReadinessIndex, assets map[string]assetReadiness) {
	for _, id := range index.ids {
		if id == "kube-vip" {
			continue
		}
		asset := assets[id]
		if asset.releasesTotal == 0 {
			progress.Start(ctx, progress.Platform, id, "", "waiting for release")
			continue
		}
		detail := "releases ready"
		current, total := asset.releasesReady, asset.releasesTotal
		if asset.workloadsTotal > 0 {
			detail = fmt.Sprintf("workloads ready; releases %d/%d",
				asset.releasesReady, asset.releasesTotal)
			current, total = asset.workloadsReady, asset.workloadsTotal
		}
		if asset.podsTotal > 0 {
			detail = fmt.Sprintf("pods ready; workloads %d/%d; releases %d/%d",
				asset.workloadsReady, asset.workloadsTotal,
				asset.releasesReady, asset.releasesTotal)
			current, total = asset.podsReady, asset.podsTotal
		}
		if asset.activity != "" {
			detail = fmt.Sprintf("%s; releases %d/%d", asset.activity, asset.releasesReady, asset.releasesTotal)
		}
		if asset.releasesReady == asset.releasesTotal &&
			asset.workloadsReady == asset.workloadsTotal &&
			asset.podsReady == asset.podsTotal {
			if asset.podsTotal > 0 {
				detail = fmt.Sprintf("pods %d/%d; workloads %d/%d; releases %d/%d",
					asset.podsReady, asset.podsTotal,
					asset.workloadsReady, asset.workloadsTotal,
					asset.releasesReady, asset.releasesTotal)
			} else if asset.workloadsTotal > 0 {
				detail = fmt.Sprintf("workloads %d/%d; releases %d/%d",
					asset.workloadsReady, asset.workloadsTotal,
					asset.releasesReady, asset.releasesTotal)
			} else {
				detail = fmt.Sprintf("releases %d/%d", asset.releasesReady, asset.releasesTotal)
			}
			progress.Done(ctx, progress.Platform, id, "", detail)
		} else {
			progress.Update(ctx, progress.Platform, id, "", detail, current, total)
		}
	}
}

type sourceIdentity struct {
	url           string
	tag           string
	branch        string
	commit        string
	revision      string
	interval      string
	timeout       string
	secret        string
	requireIgnore bool
}

func (service Service) exactGitSourcesSnapshot(
	bundle *delivery.DeploymentBundle,
	objects []kube.Object,
) (bool, error) {
	sources := service.Project.Desired.Platform.Sources
	clusterURL := strings.TrimSuffix(sources.ClusterURL, "/")
	expectedByKey := make(map[string]sourceIdentity, 2+len(service.Project.Desired.Platform.Packages))
	addExpected := func(reference config.PackageSourceReference, identity sourceIdentity) error {
		key := reference.Key()
		if _, duplicate := expectedByKey[key]; duplicate {
			return fmt.Errorf("exact source status has duplicate expected GitRepository %s", key)
		}
		expectedByKey[key] = identity
		return nil
	}
	if err := addExpected(config.PackageSourceReference{
		Name: "flux-system", Namespace: "flux-system",
	}, sourceIdentity{
		url:    clusterURL + "/" + sources.Organization + "/" + sources.Repository + ".git",
		branch: deployedBranch, revision: bundle.SourceCommit, interval: "1m0s", timeout: "60s", secret: "flux-system",
	}); err != nil {
		return false, err
	}
	packageInterval, bigBang, err := expectedBigBangSources(bundle, service.Project.Desired)
	if err != nil {
		return false, err
	}
	if err := addExpected(config.PackageSourceReference{
		Name: "bigbang", Namespace: "bigbang",
	}, bigBang); err != nil {
		return false, err
	}
	values, err := mergedBigBangValues(bundle, service.Project.Desired)
	if err != nil {
		return false, err
	}
	inventory, err := config.RepositoryInventory(service.Project.Desired, service.Project.Lock.Resolved)
	if err != nil {
		return false, err
	}
	packages := make(map[string]config.Package, len(service.Project.Desired.Platform.Packages))
	for _, pkg := range service.Project.Desired.Platform.Packages {
		packages[pkg.ID] = pkg
	}
	for _, repository := range inventory {
		if repository.ID == "bigbang" || repository.ID == "flux" {
			continue
		}
		url := internalGitSourceURL(sources, sources.UpstreamOrganization, repository.ID)
		if repository.ID == "wrapper" {
			if err := addExpected(config.BigBangWrapperSourceReference(), sourceIdentity{
				url: url, branch: repository.Source.Branch, commit: repository.Source.Commit,
				revision: repository.Source.Commit, interval: packageInterval, timeout: "60s",
			}); err != nil {
				return false, err
			}
			continue
		}
		pkg, found := packages[repository.ID]
		if !found {
			return false, fmt.Errorf("repository inventory package %s has no desired package", repository.ID)
		}
		packageValues, found := nestedValuesMap(values, pkg.ValuesPath)
		if !found {
			return false, fmt.Errorf("Big Bang values omit package path %s", pkg.ValuesPath)
		}
		reference, err := config.RenderedPackageSourceReference(pkg, packageValues)
		if err != nil {
			return false, err
		}
		if err := addExpected(
			reference,
			gitSourceIdentity(url, repository.Source, packageInterval),
		); err != nil {
			return false, err
		}
	}
	seenKeys := make(map[string]struct{}, len(expectedByKey))
	for index := range objects {
		item := &objects[index]
		key := (config.PackageSourceReference{
			Name: item.GetName(), Namespace: item.GetNamespace(),
		}).Key()
		identity, found := expectedByKey[key]
		if !found {
			return false, nil
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return false, nil
		}
		seenKeys[key] = struct{}{}
		if !exactGitSource(item, identity) {
			return false, nil
		}
	}
	return len(seenKeys) == len(expectedByKey), nil
}

func exactGitSource(item *kube.Object, identity sourceIdentity) bool {
	object := item.Object
	url, _, _ := unstructured.NestedString(object, "spec", "url")
	tag, _, _ := unstructured.NestedString(object, "spec", "ref", "tag")
	commit, _, _ := unstructured.NestedString(object, "spec", "ref", "commit")
	branch, _, _ := unstructured.NestedString(object, "spec", "ref", "branch")
	secret, _, _ := unstructured.NestedString(object, "spec", "secretRef", "name")
	ref, refFound, _ := unstructured.NestedMap(object, "spec", "ref")
	secretRef, secretFound, _ := unstructured.NestedMap(object, "spec", "secretRef")
	spec, specFound, _ := unstructured.NestedMap(object, "spec")
	interval, _, _ := unstructured.NestedString(object, "spec", "interval")
	timeout, timeoutFound, _ := unstructured.NestedString(object, "spec", "timeout")
	ignore, ignoreFound, _ := unstructured.NestedString(object, "spec", "ignore")
	revision, revisionFound, _ := unstructured.NestedString(object, "status", "artifact", "revision")
	exactSecret := (!secretFound && identity.secret == "") ||
		(secretFound && len(secretRef) == 1 && secret == identity.secret && identity.secret != "")
	exactTimeout := (!timeoutFound && identity.timeout == "") ||
		(timeoutFound && timeout == identity.timeout && identity.timeout != "")
	exactIgnore := (!ignoreFound && !identity.requireIgnore) ||
		(ignoreFound && identity.requireIgnore && strings.TrimSpace(ignore) != "")
	refFields := 0
	for _, value := range []string{identity.tag, identity.branch, identity.commit} {
		if value != "" {
			refFields++
		}
	}
	specFields := 3
	if identity.secret != "" {
		specFields++
	}
	if identity.timeout != "" {
		specFields++
	}
	if identity.requireIgnore {
		specFields++
	}
	wantedRevision := identity.revision
	if wantedRevision == "" {
		wantedRevision = identity.commit
	}
	return kube.IsReady(item) &&
		url == identity.url && tag == identity.tag && branch == identity.branch && commit == identity.commit &&
		interval == identity.interval && specFound && len(spec) == specFields &&
		refFound && len(ref) == refFields && exactSecret && exactTimeout && exactIgnore &&
		revisionFound && wantedRevision != "" &&
		(revision == wantedRevision || strings.HasSuffix(revision, ":"+wantedRevision))
}

func gitSourceIdentity(
	url string,
	source config.GitSource,
	interval string,
) sourceIdentity {
	tag := selectedGitTag(source)
	if source.Commit != "" && source.Branch != "" {
		tag = ""
	}
	return sourceIdentity{
		url: url,
		tag: tag, branch: source.Branch, commit: source.Commit,
		revision: source.Commit, interval: interval, timeout: "60s", requireIgnore: true,
	}
}

// FluxManifestIdentity is the shared Kubernetes identity envelope decoded from
// repository-owned Flux manifests.
type FluxManifestIdentity struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Namespace string `yaml:"namespace"`
		Name      string `yaml:"name"`
	} `yaml:"metadata"`
}

type bigBangSourceManifest struct {
	FluxManifestIdentity `yaml:",inline"`
	Spec                 struct {
		Interval string `yaml:"interval"`
		Timeout  string `yaml:"timeout"`
		URL      string `yaml:"url"`
		Ref      struct {
			Tag    string `yaml:"tag"`
			Branch string `yaml:"branch"`
			Commit string `yaml:"commit"`
		} `yaml:"ref"`
	} `yaml:"spec"`
}

func expectedBigBangSources(
	bundle *delivery.DeploymentBundle,
	desired config.Document,
) (string, sourceIdentity, error) {
	values, err := mergedBigBangValues(bundle, desired)
	if err != nil {
		return "", sourceIdentity{}, fmt.Errorf("read effective Big Bang values: %w", err)
	}
	flux, _ := values["flux"].(map[string]any)
	packageInterval, _ := flux["interval"].(string)
	if strings.TrimSpace(packageInterval) == "" {
		return "", sourceIdentity{}, errors.New("Big Bang operational values have no Flux interval")
	}

	sourcePath := filepath.Join(bundle.SourceRoot, "platform", "apps", "bigbang", "source-bigbang.yaml")
	sourceData, err := readBounded(sourcePath, 1<<20)
	if err != nil {
		return "", sourceIdentity{}, fmt.Errorf("read Big Bang source: %w", err)
	}
	var source bigBangSourceManifest
	if err := decodeSingleYAML(sourceData, &source, "platform/apps/bigbang/source-bigbang.yaml"); err != nil {
		return "", sourceIdentity{}, err
	}
	if source.APIVersion != "source.toolkit.fluxcd.io/v1" || source.Kind != "GitRepository" ||
		source.Metadata.Namespace != "bigbang" || source.Metadata.Name != "bigbang" ||
		strings.TrimSpace(source.Spec.Interval) == "" || strings.TrimSpace(source.Spec.Timeout) == "" ||
		strings.TrimSpace(source.Spec.URL) == "" || source.Spec.Ref.Commit == "" {
		return "", sourceIdentity{}, errors.New("Big Bang source does not declare the exact internal immutable GitRepository")
	}
	refFields := 0
	for _, value := range []string{source.Spec.Ref.Tag, source.Spec.Ref.Branch, source.Spec.Ref.Commit} {
		if value != "" {
			refFields++
		}
	}
	if refFields < 1 || (source.Spec.Ref.Tag != "" && source.Spec.Ref.Branch != "") {
		return "", sourceIdentity{}, errors.New("Big Bang source has an ambiguous Git reference")
	}
	return packageInterval, sourceIdentity{
		url: source.Spec.URL, tag: source.Spec.Ref.Tag, branch: source.Spec.Ref.Branch,
		commit: source.Spec.Ref.Commit, revision: source.Spec.Ref.Commit,
		interval: source.Spec.Interval, timeout: source.Spec.Timeout,
	}, nil
}

func selectedGitTag(source config.GitSource) string {
	if source.Ref != "" {
		return source.Ref
	}
	return source.Version
}

func internalGitSourceURL(sources config.SourceRegistry, organization, repository string) string {
	return strings.TrimSuffix(sources.ClusterURL, "/") + "/" + organization + "/" + repository + ".git"
}

func normalizedGitSourceURL(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	return strings.TrimSuffix(value, ".git")
}

func (service Service) exactOCISourcesSnapshot(
	bundle *delivery.DeploymentBundle,
	objects []kube.Object,
) (bool, error) {
	expected, err := bootstrapOCISources(bundle, service.Project.Desired.ActiveBootstrapCharts())
	if err != nil {
		return false, err
	}
	seen := make(map[string]struct{}, len(expected))
	for index := range objects {
		item := &objects[index]
		object := item.Object
		key := item.GetNamespace() + "/" + item.GetName()
		identity, found := expected[key]
		if !found {
			return false, nil
		}
		url, _, _ := unstructured.NestedString(object, "spec", "url")
		tag, _, _ := unstructured.NestedString(object, "spec", "ref", "tag")
		mediaType, _, _ := unstructured.NestedString(object, "spec", "layerSelector", "mediaType")
		operation, _, _ := unstructured.NestedString(object, "spec", "layerSelector", "operation")
		provider, _, _ := unstructured.NestedString(object, "spec", "provider")
		timeout, _, _ := unstructured.NestedString(object, "spec", "timeout")
		ref, refFound, _ := unstructured.NestedMap(object, "spec", "ref")
		layer, layerFound, _ := unstructured.NestedMap(object, "spec", "layerSelector")
		spec, specFound, _ := unstructured.NestedMap(object, "spec")
		interval, _, _ := unstructured.NestedString(object, "spec", "interval")
		insecure, _, _ := unstructured.NestedBool(object, "spec", "insecure")
		if !kube.IsReady(item) || url != identity.url || tag != identity.tag || !insecure ||
			interval != identity.interval || provider != identity.provider || timeout != identity.timeout ||
			!specFound || len(spec) != 7 ||
			mediaType != identity.mediaType || operation != identity.operation ||
			!refFound || len(ref) != 1 || !layerFound || len(layer) != 2 {
			return false, nil
		}
		if _, duplicate := seen[key]; duplicate {
			return false, nil
		}
		seen[key] = struct{}{}
	}
	return len(seen) == len(expected), nil
}

type ociSourceIdentity struct {
	url       string
	tag       string
	interval  string
	provider  string
	timeout   string
	mediaType string
	operation string
}

type ociSourceManifest struct {
	FluxManifestIdentity `yaml:",inline"`
	Spec                 struct {
		Insecure bool   `yaml:"insecure"`
		Interval string `yaml:"interval"`
		Provider string `yaml:"provider"`
		Timeout  string `yaml:"timeout"`
		URL      string `yaml:"url"`
		Ref      struct {
			Tag string `yaml:"tag"`
		} `yaml:"ref"`
		Layer struct {
			MediaType string `yaml:"mediaType"`
			Operation string `yaml:"operation"`
		} `yaml:"layerSelector"`
	} `yaml:"spec"`
}

type bootstrapHelmReleaseManifest struct {
	FluxManifestIdentity `yaml:",inline"`
	Spec                 struct {
		ChartRef struct {
			Kind      string `yaml:"kind"`
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"chartRef"`
	} `yaml:"spec"`
}

type bootstrapConsumer struct {
	id              string
	namespace       string
	sourceName      string
	sourceNamespace string
}

func bootstrapConsumers(
	bundle *delivery.DeploymentBundle,
	charts []config.Chart,
) ([]bootstrapConsumer, error) {
	consumers := make([]bootstrapConsumer, 0, len(charts))
	for _, chart := range charts {
		relative := filepath.ToSlash(filepath.Join(filepath.Dir(chart.Values), "helmrelease.yaml"))
		manifestPath, err := fssecure.Resolve(bundle.SourceRoot, filepath.FromSlash(relative), false)
		if err != nil {
			return nil, fmt.Errorf("resolve bootstrap HelmRelease %s: %w", relative, err)
		}
		data, err := readBounded(manifestPath, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read bootstrap HelmRelease %s: %w", relative, err)
		}
		var manifest bootstrapHelmReleaseManifest
		if err := decodeSingleYAMLProjection(data, &manifest, relative); err != nil {
			return nil, err
		}
		if manifest.APIVersion != "helm.toolkit.fluxcd.io/v2" || manifest.Kind != "HelmRelease" ||
			manifest.Metadata.Name != chart.ID || manifest.Metadata.Namespace == "" ||
			manifest.Spec.ChartRef.Kind != "OCIRepository" || manifest.Spec.ChartRef.Name == "" ||
			manifest.Spec.ChartRef.Namespace != manifest.Metadata.Namespace {
			return nil, fmt.Errorf("bootstrap HelmRelease %s does not exactly bind its OCIRepository", relative)
		}
		consumers = append(consumers, bootstrapConsumer{
			id: chart.ID, namespace: manifest.Metadata.Namespace,
			sourceName: manifest.Spec.ChartRef.Name, sourceNamespace: manifest.Spec.ChartRef.Namespace,
		})
	}
	return consumers, nil
}

func bootstrapOCISources(
	bundle *delivery.DeploymentBundle,
	charts []config.Chart,
) (map[string]ociSourceIdentity, error) {
	expected := make(map[string]ociSourceIdentity, len(charts))
	for _, chart := range charts {
		path, err := fssecure.Resolve(bundle.SourceRoot, filepath.FromSlash(chart.FluxSource), false)
		if err != nil {
			return nil, fmt.Errorf("resolve bootstrap chart source %s: %w", chart.FluxSource, err)
		}
		data, err := readBounded(path, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read bootstrap chart source %s: %w", chart.FluxSource, err)
		}
		var manifest ociSourceManifest
		if err := decodeSingleYAML(data, &manifest, chart.FluxSource); err != nil {
			return nil, err
		}
		separator := strings.LastIndexByte(chart.Target, ':')
		if separator <= strings.LastIndexByte(chart.Target, '/') {
			return nil, fmt.Errorf("bootstrap chart %s target %q has no immutable tag", chart.ID, chart.Target)
		}
		wantedURL := "oci://" + chart.Target[:separator]
		if manifest.APIVersion != "source.toolkit.fluxcd.io/v1" || manifest.Kind != "OCIRepository" ||
			manifest.Metadata.Namespace == "" || manifest.Metadata.Name == "" || manifest.Spec.URL != wantedURL ||
			!manifest.Spec.Insecure || manifest.Spec.Interval != "30m" ||
			manifest.Spec.Provider != "generic" || manifest.Spec.Timeout != "60s" ||
			manifest.Spec.Ref.Tag != chart.Version ||
			manifest.Spec.Layer.MediaType != "application/vnd.cncf.helm.chart.content.v1.tar+gzip" ||
			manifest.Spec.Layer.Operation != "copy" {
			return nil, fmt.Errorf("bootstrap chart source %s does not declare the exact internal OCIRepository", chart.FluxSource)
		}
		key := manifest.Metadata.Namespace + "/" + manifest.Metadata.Name
		if _, duplicate := expected[key]; duplicate {
			return nil, fmt.Errorf("bootstrap chart sources repeat OCIRepository %s", key)
		}
		expected[key] = ociSourceIdentity{
			url: wantedURL, tag: chart.Version, interval: manifest.Spec.Interval,
			provider: manifest.Spec.Provider, timeout: manifest.Spec.Timeout,
			mediaType: manifest.Spec.Layer.MediaType, operation: manifest.Spec.Layer.Operation,
		}
	}
	return expected, nil
}

func (service Service) exactHelmSourcesSnapshot(
	bundle *delivery.DeploymentBundle,
	objects []kube.Object,
) (bool, error) {
	wantedURL := "oci://" + service.Project.Desired.Platform.Bootstrap.Registry.Host + "/" +
		service.Project.Desired.Platform.Bootstrap.Registry.Project
	expected, err := trackedHelmSources(bundle, service.Project.Desired.Platform.Charts, wantedURL)
	if err != nil {
		return false, err
	}
	seen := make(map[string]struct{}, len(expected))
	for index := range objects {
		item := &objects[index]
		object := item.Object
		key := item.GetNamespace() + "/" + item.GetName()
		if _, found := expected[key]; !found {
			return false, nil
		}
		url, _, _ := unstructured.NestedString(object, "spec", "url")
		typeName, _, _ := unstructured.NestedString(object, "spec", "type")
		interval, _, _ := unstructured.NestedString(object, "spec", "interval")
		provider, _, _ := unstructured.NestedString(object, "spec", "provider")
		spec, specFound, _ := unstructured.NestedMap(object, "spec")
		// Flux does not reconcile HelmRepository objects with spec.type=oci;
		// helm-controller resolves them directly for each HelmRelease. Their
		// status is intentionally empty, so exactness comes from the immutable
		// source specification and the ready consumers checked below.
		insecure, _, _ := unstructured.NestedBool(object, "spec", "insecure")
		if item.GetDeletionTimestamp() != nil || url != wantedURL || typeName != "oci" || interval != "30m" ||
			provider != "generic" || !insecure || !specFound || len(spec) != 5 {
			return false, nil
		}
		if _, duplicate := seen[key]; duplicate {
			return false, nil
		}
		seen[key] = struct{}{}
	}
	return len(seen) == len(expected), nil
}

type helmSourceManifest struct {
	FluxManifestIdentity `yaml:",inline"`
	Spec                 struct {
		Insecure bool   `yaml:"insecure"`
		Interval string `yaml:"interval"`
		Provider string `yaml:"provider"`
		URL      string `yaml:"url"`
		Type     string `yaml:"type"`
	} `yaml:"spec"`
}

func trackedHelmSources(
	bundle *delivery.DeploymentBundle,
	charts []config.TrackedChart,
	wantedURL string,
) (map[string]struct{}, error) {
	byPath := make(map[string]struct{}, len(charts))
	expected := make(map[string]struct{}, len(charts))
	for _, chart := range charts {
		if _, found := byPath[chart.FluxSource]; found {
			continue
		}
		byPath[chart.FluxSource] = struct{}{}
		path, err := fssecure.Resolve(bundle.SourceRoot, filepath.FromSlash(chart.FluxSource), false)
		if err != nil {
			return nil, fmt.Errorf("resolve tracked chart source %s: %w", chart.FluxSource, err)
		}
		data, err := readBounded(path, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read tracked chart source %s: %w", chart.FluxSource, err)
		}
		var manifest helmSourceManifest
		if err := decodeSingleYAML(data, &manifest, chart.FluxSource); err != nil {
			return nil, err
		}
		if manifest.APIVersion != "source.toolkit.fluxcd.io/v1" || manifest.Kind != "HelmRepository" ||
			manifest.Metadata.Namespace == "" || manifest.Metadata.Name == "" || manifest.Spec.URL != wantedURL ||
			!manifest.Spec.Insecure || manifest.Spec.Interval != "30m" ||
			manifest.Spec.Provider != "generic" || manifest.Spec.Type != "oci" {
			return nil, fmt.Errorf("tracked chart source %s does not declare the exact internal HelmRepository", chart.FluxSource)
		}
		key := manifest.Metadata.Namespace + "/" + manifest.Metadata.Name
		if _, duplicate := expected[key]; duplicate {
			return nil, fmt.Errorf("tracked chart sources repeat HelmRepository %s", key)
		}
		expected[key] = struct{}{}
	}
	return expected, nil
}

type chartBinding struct {
	id      string
	name    string
	version string
}

type fluxConsumerExpectation struct {
	apiVersion string
	kind       string
	namespace  string
	name       string
	spec       map[string]any
}

type fluxConsumerManifest struct {
	FluxManifestIdentity `yaml:",inline"`
	Spec                 map[string]any `yaml:"spec"`
}

func bundledFluxConsumerExpectations(
	bundle *delivery.DeploymentBundle,
	desired config.Document,
) ([]fluxConsumerExpectation, error) {
	target, exists := desired.ActiveTarget()
	if !exists {
		return nil, fmt.Errorf(
			"active infrastructure target %q is not defined", desired.Infrastructure.Active)
	}
	domain := ""
	if target.LocalAccess != nil {
		domain = target.LocalAccess.Domain
	}
	clusterRoot := filepath.ToSlash(filepath.Join(
		desired.Platform.Directory, "clusters", desired.Project.Cluster))
	files := [...]string{
		"prep.yaml",
		"platform-profile-prep.yaml",
		"bigbang.yaml",
		"platform-profile-access.yaml",
		"platform-profile-identity.yaml",
	}
	expectations := make([]fluxConsumerExpectation, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		relative := clusterRoot + "/" + file
		path, err := fssecure.Resolve(bundle.SourceRoot, filepath.FromSlash(relative), false)
		if err != nil {
			return nil, fmt.Errorf("resolve bundled Flux consumer %s: %w", relative, err)
		}
		data, err := readBounded(path, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("read bundled Flux consumer %s: %w", relative, err)
		}
		rendered, err := envsubst.Eval(string(data), func(name string) (string, bool) {
			switch name {
			case "ATUM_PLATFORM_PROFILE":
				return target.PlatformProfile, true
			case "ATUM_PLATFORM_DOMAIN":
				return domain, true
			default:
				return "", false
			}
		})
		if err != nil {
			return nil, fmt.Errorf("substitute bundled Flux consumer %s: %w", relative, err)
		}
		var manifest fluxConsumerManifest
		if err := decodeSingleYAML([]byte(rendered), &manifest, relative); err != nil {
			return nil, err
		}
		if manifest.APIVersion != "kustomize.toolkit.fluxcd.io/v1" ||
			manifest.Kind != "Kustomization" ||
			manifest.Metadata.Namespace == "" || manifest.Metadata.Name == "" ||
			len(manifest.Spec) == 0 {
			return nil, fmt.Errorf(
				"bundled Flux consumer %s does not declare an exact Kustomization", relative)
		}
		key := manifest.Metadata.Namespace + "/" + manifest.Metadata.Name
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("bundled Flux consumers repeat Kustomization %s", key)
		}
		seen[key] = struct{}{}
		expectations = append(expectations, fluxConsumerExpectation{
			apiVersion: manifest.APIVersion,
			kind:       manifest.Kind,
			namespace:  manifest.Metadata.Namespace,
			name:       manifest.Metadata.Name,
			spec:       manifest.Spec,
		})
	}
	return expectations, nil
}

func exactFluxConsumerObjects(
	objects []kube.Object,
	expectations []fluxConsumerExpectation,
) bool {
	for _, expected := range expectations {
		object, found := snapshotResource(objects, expected.namespace, expected.name)
		if !found || object.GetDeletionTimestamp() != nil ||
			object.Object["apiVersion"] != expected.apiVersion ||
			object.Object["kind"] != expected.kind {
			return false
		}
		spec, found, err := unstructured.NestedMap(object.Object, "spec")
		if err != nil || !found || !reflect.DeepEqual(spec, expected.spec) {
			return false
		}
	}
	return true
}

func (service Service) exactFluxConsumersSnapshot(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	snapshot platformSnapshot,
) (bool, error) {
	target, exists := service.Project.Desired.ActiveTarget()
	if !exists {
		return false, fmt.Errorf("active infrastructure target %q is not defined", service.Project.Desired.Infrastructure.Active)
	}
	expectations, err := bundledFluxConsumerExpectations(bundle, service.Project.Desired)
	if err != nil {
		return false, err
	}
	if !exactFluxConsumerObjects(snapshot.resource(kube.Kustomization), expectations) {
		return false, nil
	}
	rootFlux, found := snapshotResource(
		snapshot.resource(kube.Kustomization), "flux-system", "flux-system")
	if !found {
		return false, nil
	}
	profile, profileFound, _ := unstructured.NestedString(
		rootFlux.Object, "spec", "postBuild", "substitute", "ATUM_PLATFORM_PROFILE",
	)
	domain, domainFound, _ := unstructured.NestedString(
		rootFlux.Object, "spec", "postBuild", "substitute", "ATUM_PLATFORM_DOMAIN",
	)
	expectedDomain := ""
	if target.LocalAccess != nil {
		expectedDomain = target.LocalAccess.Domain
	}
	substitutions, substitutionsFound, _ := unstructured.NestedMap(
		rootFlux.Object, "spec", "postBuild", "substitute",
	)
	if !profileFound || !domainFound || profile != target.PlatformProfile || domain != expectedDomain ||
		!substitutionsFound || len(substitutions) != 2 {
		return false, nil
	}
	activeCharts := service.Project.Desired.ActiveBootstrapCharts()
	activeBootstrap := make(map[string]struct{}, len(activeCharts))
	for i := range activeCharts {
		activeBootstrap[activeCharts[i].ID] = struct{}{}
	}
	bootstrap, err := bootstrapConsumers(bundle, service.Project.Desired.Platform.Bootstrap.Charts)
	if err != nil {
		return false, err
	}
	for _, release := range bootstrap {
		_, active := activeBootstrap[release.id]
		object, found := snapshotResource(
			snapshot.resource(kube.HelmRelease), release.namespace, release.id)
		if !active {
			if found {
				return false, nil
			}
			continue
		}
		if !found {
			return false, nil
		}
		kind, _, _ := unstructured.NestedString(object.Object, "spec", "chartRef", "kind")
		name, _, _ := unstructured.NestedString(object.Object, "spec", "chartRef", "name")
		namespace, _, _ := unstructured.NestedString(object.Object, "spec", "chartRef", "namespace")
		ref, found, _ := unstructured.NestedMap(object.Object, "spec", "chartRef")
		if kind != "OCIRepository" || name != release.sourceName ||
			namespace != release.sourceNamespace || !found || len(ref) != 3 {
			return false, nil
		}
	}

	root, found := snapshotResource(snapshot.resource(kube.HelmRelease), "bigbang", "bigbang")
	if !found {
		return false, nil
	}
	if !exactChartSource(root.Object, "GitRepository", "bigbang", "bigbang") {
		return false, nil
	}
	rootChart, _, _ := unstructured.NestedString(root.Object, "spec", "chart", "spec", "chart")
	rootStrategy, _, _ := unstructured.NestedString(root.Object, "spec", "chart", "spec", "reconcileStrategy")
	if rootChart != "./chart" || rootStrategy != "Revision" {
		return false, nil
	}
	if exact, err := service.exactBigBangValues(ctx, client, bundle, root.Object); err != nil {
		return false, err
	} else if !exact {
		return false, nil
	}

	values, err := mergedBigBangValues(bundle, service.Project.Desired)
	if err != nil {
		return false, err
	}
	wrapperConsumers, err := config.ActiveWrapperConsumers(service.Project.Desired.Platform, values)
	if err != nil {
		return false, fmt.Errorf("project active wrapper consumers: %w", err)
	}
	expectedGitSources := make(map[string]consumerGitSource, len(service.Project.Desired.Platform.Packages)+1)
	for _, pkg := range service.Project.Desired.Platform.Packages {
		packageValues, found := nestedValuesMap(values, pkg.ValuesPath)
		if !found {
			return false, fmt.Errorf("Big Bang values omit package path %s", pkg.ValuesPath)
		}
		reference, expected, exact := packageGitConsumerExpectation(
			pkg, packageValues, service.Project.Desired.Platform.Sources,
		)
		if !exact {
			return false, nil
		}
		if err := addExpectedConsumerGitSource(expectedGitSources, reference, expected); err != nil {
			return false, err
		}
	}
	for _, support := range service.Project.Lock.Resolved.SupportSources {
		expectedURL := internalGitSourceURL(
			service.Project.Desired.Platform.Sources,
			service.Project.Desired.Platform.Sources.UpstreamOrganization,
			support.ID,
		)
		releaseKeys := make(map[string]struct{}, len(wrapperConsumers))
		for _, consumer := range wrapperConsumers {
			releaseKeys[consumer.ReleaseKey()] = struct{}{}
		}
		reference := config.BigBangWrapperSourceReference()
		if err := addExpectedConsumerGitSource(expectedGitSources, reference, consumerGitSource{
			url: expectedURL, sourceName: reference.Name, sourceNamespace: reference.Namespace,
			chartPath: support.ChartPath, reconcileStrategy: "Revision",
			releaseKeys: releaseKeys, consumption: consumerReleaseExactSet,
		}); err != nil {
			return false, err
		}
	}
	gitSources, exact := packageConsumerSourcesSnapshot(
		snapshot.resource(kube.GitRepository), expectedGitSources)
	if !exact {
		return false, nil
	}
	helmSources := make(map[string][]chartBinding, len(service.Project.Desired.Platform.Charts))
	sourceNames := make(map[string]string, len(service.Project.Desired.Platform.Charts))
	for _, chart := range service.Project.Desired.Platform.Charts {
		name, found := sourceNames[chart.FluxSource]
		if !found {
			var err error
			name, err = trackedChartSourceName(bundle, chart.FluxSource)
			if err != nil {
				return false, err
			}
			sourceNames[chart.FluxSource] = name
		}
		helmSources[name] = append(helmSources[name], chartBinding{id: chart.ID, name: chart.Name, version: chart.Version})
	}

	releases := make([]kube.Object, 0, len(snapshot.resource(kube.HelmRelease)))
	for _, release := range snapshot.resource(kube.HelmRelease) {
		if release.GetLabels()["app.kubernetes.io/part-of"] == "bigbang" {
			releases = append(releases, release)
		}
	}
	seenGitConsumers := make(map[string]map[string]struct{}, len(gitSources))
	seenHelm := make(map[string]struct{}, len(service.Project.Desired.Platform.Charts))
	for index := range releases {
		object := releases[index].Object
		kind, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "kind")
		name, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "name")
		chart, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "chart")
		reconcileStrategy, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "reconcileStrategy")
		switch kind {
		case "GitRepository":
			expected, sourceKey, exact := exactGitConsumerRelease(releases[index], gitSources)
			if !exact {
				return false, nil
			}
			seen := seenGitConsumers[sourceKey]
			if seen == nil {
				seen = make(map[string]struct{})
				seenGitConsumers[sourceKey] = seen
			}
			if !recordExpectedConsumerRelease(
				expected,
				releases[index].GetName(),
				releases[index].GetNamespace(),
				seen,
			) {
				return false, nil
			}
		case "HelmRepository":
			version, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "version")
			bindingID, found := knownChartBinding(helmSources[name], chart, version)
			if reconcileStrategy != "Revision" || !found || !exactChartSource(object, kind, name, "bigbang") ||
				releases[index].GetName() != bindingID {
				return false, nil
			}
			seenHelm[bindingID] = struct{}{}
		default:
			return false, nil
		}
	}
	return exactConsumerReleaseSets(gitSources, seenGitConsumers) &&
		len(seenHelm) == len(service.Project.Desired.Platform.Charts), nil
}

func packageGitConsumerExpectation(
	pkg config.Package,
	values map[string]any,
	registry config.SourceRegistry,
) (config.PackageSourceReference, consumerGitSource, bool) {
	gitValues, _ := values["git"].(map[string]any)
	chartPath, _ := gitValues["path"].(string)
	if strings.TrimSpace(chartPath) == "" {
		chartPath = "./chart"
	}
	repository, _ := gitValues["repo"].(string)
	expectedURL := internalGitSourceURL(
		registry, registry.UpstreamOrganization, pkg.ID,
	)
	if normalizedGitSourceURL(repository) != normalizedGitSourceURL(expectedURL) {
		return config.PackageSourceReference{}, consumerGitSource{}, false
	}
	sourceReference, err := config.RenderedPackageSourceReference(pkg, values)
	if err != nil {
		return config.PackageSourceReference{}, consumerGitSource{}, false
	}
	reconcileStrategy := "ChartVersion"
	var releaseKeys map[string]struct{}
	consumption := consumerReleaseAtLeastOne
	defaultReconcile := true
	if pkg.Integration == "generic" {
		reconcileStrategy = "Revision"
		releaseKeys = map[string]struct{}{
			sourceReference.Key(): {},
		}
		consumption = consumerReleaseExactSet
		defaultReconcile = false
	}
	expected := consumerGitSource{
		url: expectedURL, sourceName: sourceReference.Name, sourceNamespace: sourceReference.Namespace,
		chartPath: chartPath, reconcileStrategy: reconcileStrategy,
		defaultReconcile: defaultReconcile,
		releaseKeys: releaseKeys, consumption: consumption,
	}
	return sourceReference, expected, true
}

func exactGitConsumerRelease(
	release kube.Object,
	sources map[string]consumerGitSource,
) (consumerGitSource, string, bool) {
	object := release.Object
	kind, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "kind")
	name, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "name")
	namespace, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "namespace")
	chart, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "chart")
	strategy, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "reconcileStrategy")
	key := (config.PackageSourceReference{Name: name, Namespace: namespace}).Key()
	expected, found := sources[key]
	reconcileMatches := strategy == expected.reconcileStrategy ||
		(expected.defaultReconcile && strategy == "")
	if !found || kind != "GitRepository" || !reconcileMatches ||
		!exactChartSource(object, kind, name, namespace) ||
		chart != expected.chartPath || !config.SafeRepositoryChartPath(chart) {
		return consumerGitSource{}, "", false
	}
	return expected, key, true
}

type consumerReleaseMode uint8

const (
	consumerReleaseAtLeastOne consumerReleaseMode = iota + 1
	consumerReleaseExactSet
)

type consumerGitSource struct {
	url               string
	sourceName        string
	sourceNamespace   string
	chartPath         string
	reconcileStrategy string
	defaultReconcile  bool
	releaseKeys       map[string]struct{}
	consumption       consumerReleaseMode
}

func addExpectedConsumerGitSource(
	expected map[string]consumerGitSource,
	reference config.PackageSourceReference,
	source consumerGitSource,
) error {
	key := reference.Key()
	if _, duplicate := expected[key]; duplicate {
		return fmt.Errorf("exact consumer status has duplicate expected GitRepository %s", key)
	}
	expected[key] = source
	return nil
}

func recordExpectedConsumerRelease(
	source consumerGitSource,
	name, namespace string,
	seen map[string]struct{},
) bool {
	key := (config.PackageSourceReference{Name: name, Namespace: namespace}).Key()
	if source.consumption == consumerReleaseExactSet {
		if _, known := source.releaseKeys[key]; !known {
			return false
		}
	} else if source.consumption != consumerReleaseAtLeastOne {
		return false
	}
	if _, duplicate := seen[key]; duplicate {
		return false
	}
	seen[key] = struct{}{}
	return true
}

func exactConsumerReleaseSets(
	sources map[string]consumerGitSource,
	seen map[string]map[string]struct{},
) bool {
	for key, source := range sources {
		count := len(seen[key])
		switch source.consumption {
		case consumerReleaseAtLeastOne:
			if count == 0 {
				return false
			}
		case consumerReleaseExactSet:
			if count != len(source.releaseKeys) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func packageConsumerSourcesSnapshot(
	objects []kube.Object,
	expected map[string]consumerGitSource,
) (map[string]consumerGitSource, bool) {
	result := make(map[string]consumerGitSource, len(expected))
	for index := range objects {
		item := &objects[index]
		if item.GetNamespace() == "bigbang" && item.GetName() == "bigbang" {
			continue
		}
		key := (config.PackageSourceReference{
			Name: item.GetName(), Namespace: item.GetNamespace(),
		}).Key()
		source, found := expected[key]
		if !found {
			if item.GetLabels()["app.kubernetes.io/part-of"] == "bigbang" {
				return nil, false
			}
			continue
		}
		url, _, _ := unstructured.NestedString(item.Object, "spec", "url")
		if normalizedGitSourceURL(url) != normalizedGitSourceURL(source.url) {
			return nil, false
		}
		if _, duplicate := result[key]; duplicate {
			return nil, false
		}
		result[key] = source
	}
	return result, len(result) == len(expected)
}

func (service Service) exactBigBangValues(
	ctx context.Context,
	client *kube.Observer,
	bundle *delivery.DeploymentBundle,
	root map[string]any,
) (bool, error) {
	valuesFrom, found, err := unstructured.NestedSlice(root, "spec", "valuesFrom")
	if err != nil || !found || len(valuesFrom) != 3 {
		return false, err
	}
	expected := []map[string]any{
		{"kind": "ConfigMap", "name": "bigbang-operational-values", "valuesKey": "values.yaml"},
		{"kind": "ConfigMap", "name": "bigbang-generated-values", "valuesKey": "values.yaml"},
		{"kind": "ConfigMap", "name": "bigbang-target-values", "valuesKey": "values.yaml"},
	}
	for index, value := range valuesFrom {
		actual, ok := value.(map[string]any)
		if !ok || !sameStringMap(actual, expected[index]) {
			return false, nil
		}
	}
	profilePath, exists := service.Project.Desired.ActiveProfileValuesPath()
	if !exists {
		return false, errors.New("active target has no platform profile values")
	}
	for _, item := range []struct {
		name, relative string
		profile        bool
	}{
		{name: "bigbang-operational-values", relative: service.Project.Desired.Platform.Values.Operational},
		{name: "bigbang-generated-values", relative: service.Project.Desired.Platform.Values.Generated},
		{name: "bigbang-target-values", relative: profilePath, profile: true},
	} {
		data, err := readBounded(filepath.Join(bundle.SourceRoot, filepath.FromSlash(item.relative)), 8<<20)
		if err != nil {
			return false, err
		}
		if item.profile {
			target, exists := service.Project.Desired.ActiveTarget()
			if !exists {
				return false, fmt.Errorf(
					"active infrastructure target %q is not defined",
					service.Project.Desired.Infrastructure.Active)
			}
			domain := ""
			if target.LocalAccess != nil {
				domain = target.LocalAccess.Domain
			}
			data, err = substituteProfileValues(data, domain)
			if err != nil {
				return false, fmt.Errorf(
					"substitute active profile values %s: %w", item.relative, err)
			}
		}
		current, found, err := client.ConfigMapData(ctx, "bigbang", item.name)
		if !found && err == nil {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if len(current) != 1 || current["values.yaml"] != string(data) {
			return false, nil
		}
	}
	return true, nil
}

func substituteProfileValues(data []byte, domain string) ([]byte, error) {
	rendered, err := envsubst.Eval(string(data), func(name string) (string, bool) {
		if name == "ATUM_PLATFORM_DOMAIN" {
			return domain, true
		}
		return "", false
	})
	if err != nil {
		return nil, err
	}
	return []byte(rendered), nil
}

func sameStringMap(actual, expected map[string]any) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func mergedBigBangValues(bundle *delivery.DeploymentBundle, desired config.Document) (map[string]any, error) {
	read := func(relative string) (map[string]any, error) {
		file := filepath.Join(bundle.SourceRoot, filepath.FromSlash(relative))
		data, err := readBounded(file, 8<<20)
		if err != nil {
			return nil, err
		}
		var values map[string]any
		if err := decodeSingleYAML(data, &values, relative); err != nil {
			return nil, err
		}
		return values, nil
	}
	values, err := desired.ResolvePlatformValues(read)
	if err != nil {
		return nil, err
	}
	return values.Merged, nil
}

func nestedValuesMap(values map[string]any, dottedPath string) (map[string]any, bool) {
	current := values
	for _, segment := range strings.Split(dottedPath, ".") {
		next, ok := current[segment].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func exactChartSource(object map[string]any, kind, name, namespace string) bool {
	actualKind, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "kind")
	actualName, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "name")
	actualNamespace, _, _ := unstructured.NestedString(object, "spec", "chart", "spec", "sourceRef", "namespace")
	ref, found, _ := unstructured.NestedMap(object, "spec", "chart", "spec", "sourceRef")
	return found && len(ref) == 3 && actualKind == kind && actualName == name && actualNamespace == namespace
}

func trackedChartSourceName(bundle *delivery.DeploymentBundle, relative string) (string, error) {
	file, err := fssecure.Resolve(bundle.SourceRoot, filepath.FromSlash(relative), false)
	if err != nil {
		return "", err
	}
	data, err := readBounded(file, 1<<20)
	if err != nil {
		return "", err
	}
	var manifest helmSourceManifest
	if err := decodeSingleYAML(data, &manifest, relative); err != nil {
		return "", err
	}
	if manifest.Metadata.Namespace != "bigbang" || manifest.Metadata.Name == "" {
		return "", fmt.Errorf("tracked chart source %s has no exact Big Bang object identity", relative)
	}
	return manifest.Metadata.Name, nil
}

func knownChartBinding(bindings []chartBinding, name, version string) (string, bool) {
	for _, binding := range bindings {
		if binding.name == name && binding.version == version {
			return binding.id, true
		}
	}
	return "", false
}

func decodeSingleYAML(data []byte, destination any, source string) error {
	return decodeSingleYAMLDocument(data, destination, source, true)
}

func decodeSingleYAMLProjection(data []byte, destination any, source string) error {
	return decodeSingleYAMLDocument(data, destination, source, false)
}

func decodeSingleYAMLDocument(data []byte, destination any, source string, knownFields bool) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(knownFields)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode source %s: %w", source, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("source %s contains multiple YAML documents", source)
		}
		return fmt.Errorf("decode trailing source %s: %w", source, err)
	}
	return nil
}

func systemNamespace(namespace string) bool {
	switch namespace {
	case "", "kube-system", "kube-public", "kube-node-lease":
		return true
	default:
		return false
	}
}

func deploymentsReady(ctx context.Context, client *kube.Observer, namespace string, names []string) bool {
	return client.DeploymentsReady(ctx, namespace, names)
}

func podLockedImageIssue(pod *kube.Pod, locked map[string]map[string]struct{}) string {
	issue := func(name, image, imageID string) string {
		digests, found := locked[image]
		digest := imageIDDigest(imageID)
		_, accepted := digests[digest]
		if found && accepted {
			return ""
		}
		identity := pod.Namespace + "/" + pod.Name + " container " + name
		if !found {
			return identity + " uses untracked image " + image
		}
		if digest == "" {
			if !pod.Ready {
				// A declared image has no runtime identity until its container
				// starts. Pod readiness already keeps the platform pending;
				// do not misreport that ordinary transition as lock drift.
				return ""
			}
			return identity + " has no verified runtime digest for " + image
		}
		return identity + " resolved " + image + " to " + digest
	}
	for _, container := range pod.Containers {
		if mismatch := issue(container.Name, container.Image, container.ImageID); mismatch != "" {
			return mismatch
		}
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
