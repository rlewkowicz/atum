package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/kube"
	"atum/cli/orchestration"
	"atum/cli/progress"

	"go.yaml.in/yaml/v3"
)

type statusEventRecorder struct {
	mu     sync.Mutex
	events []progress.Event
}

func (recorder *statusEventRecorder) Report(event progress.Event) {
	recorder.mu.Lock()
	recorder.events = append(recorder.events, event)
	recorder.mu.Unlock()
}

func (recorder *statusEventRecorder) snapshot() []progress.Event {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]progress.Event(nil), recorder.events...)
}

func TestStatusReadyContract(t *testing.T) {
	t.Parallel()

	status := Status{
		BundleReady:             true,
		FluxReady:               true,
		PrepReady:               true,
		ProfilePrepReady:        true,
		BigBangReady:            true,
		ProfileAccessReady:      true,
		ProfileIdentityRequired: true,
		ProfileIdentityReady:    true,
		ClusterOIDCRequired:     true,
		ClusterOIDCReady:        true,
		LoadBalancerReady:       true,
		CertificatesReady:       true,
		RoutesReady:             true,
		ActiveHelmReleases:      2,
		ReadyHelmReleases:       2,
		ActiveWorkloads:         2,
		ReadyWorkloads:          2,
		InternalImageOnly:       true,
		InternalSourcesOnly:     true,
		RootCAFingerprint:       "ROOT",
		CAFingerprint:           "ROOT",
		LocalDNSReady:           true,
		CATrustReady:            true,
		HostAccessObserved:      true,
		LoadBalancerRequired:    true,
		CertificatesRequired:    true,
	}
	if !status.Ready() {
		t.Fatal("complete status is not ready")
	}
	status.CAFingerprint = "OTHER"
	if status.Ready() {
		t.Fatal("mismatched observed CA is ready")
	}
	status.HostAccessObserved = false
	if !status.Ready() {
		t.Fatal("unobserved optional host state blocks cluster readiness")
	}
	status.ReadyHelmReleases--
	if status.Ready() {
		t.Fatal("non-ready active HelmRelease is ready")
	}
}

func TestStatusReadyRequiresEveryExactObservation(t *testing.T) {
	t.Parallel()

	ready := Status{
		BundleReady: true, FluxReady: true, PrepReady: true, ProfilePrepReady: true,
		BigBangReady: true, ProfileAccessReady: true, LoadBalancerRequired: true,
		ProfileIdentityRequired: true, ProfileIdentityReady: true,
		ClusterOIDCRequired: true, ClusterOIDCReady: true,
		LoadBalancerReady: true, CertificatesRequired: true, CertificatesReady: true,
		RoutesReady: true, ActiveHelmReleases: 1, ReadyHelmReleases: 1,
		ActiveWorkloads: 1, ReadyWorkloads: 1,
		InternalImageOnly: true, InternalSourcesOnly: true,
	}
	tests := []struct {
		name   string
		mutate func(*Status)
	}{
		{name: "bundle", mutate: func(status *Status) { status.BundleReady = false }},
		{name: "Flux", mutate: func(status *Status) { status.FluxReady = false }},
		{name: "common prerequisites", mutate: func(status *Status) { status.PrepReady = false }},
		{name: "profile prerequisites", mutate: func(status *Status) { status.ProfilePrepReady = false }},
		{name: "Big Bang", mutate: func(status *Status) { status.BigBangReady = false }},
		{name: "profile access", mutate: func(status *Status) { status.ProfileAccessReady = false }},
		{name: "profile identity", mutate: func(status *Status) { status.ProfileIdentityReady = false }},
		{name: "profile identity failure", mutate: func(status *Status) {
			status.ProfileIdentityFailure = "reconciliation failed"
		}},
		{name: "cluster OIDC", mutate: func(status *Status) { status.ClusterOIDCReady = false }},
		{name: "cluster OIDC failure", mutate: func(status *Status) {
			status.ClusterOIDCFailure = "authentication digest differs"
		}},
		{name: "load balancer", mutate: func(status *Status) { status.LoadBalancerReady = false }},
		{name: "certificates", mutate: func(status *Status) { status.CertificatesReady = false }},
		{name: "routes", mutate: func(status *Status) { status.RoutesReady = false }},
		{name: "release count", mutate: func(status *Status) { status.ActiveHelmReleases = 0 }},
		{name: "release readiness", mutate: func(status *Status) { status.ReadyHelmReleases = 0 }},
		{name: "workload readiness", mutate: func(status *Status) { status.ReadyWorkloads = 0 }},
		{name: "pod readiness", mutate: func(status *Status) { status.NonReadyPods = 1 }},
		{name: "runtime images", mutate: func(status *Status) { status.InternalImageOnly = false }},
		{name: "internal sources", mutate: func(status *Status) { status.InternalSourcesOnly = false }},
	}
	if !ready.Ready() {
		t.Fatal("exact readiness fixture is not ready")
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			status := ready
			test.mutate(&status)
			if status.Ready() {
				t.Fatalf("status with non-ready %s is ready", test.name)
			}
		})
	}
}

func TestIdentityJobsRequireBothExactTerminalSuccesses(t *testing.T) {
	t.Parallel()

	complete := func(namespace, name, owner string) kube.Object {
		return kube.Object{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{"atum.dev/identity-job": owner},
			Ready:     true,
			Object: map[string]any{"status": map[string]any{"conditions": []any{
				map[string]any{"type": "Complete", "status": "True"},
			}}},
		}
	}
	jobs := []kube.Object{
		complete("keycloak", "atum-keycloak-reconcile", "keycloak"),
		complete("vault", "atum-openbao-reconcile", "openbao"),
	}
	ready, failure := identityJobsStatus(jobs)
	if !ready || failure != "" {
		t.Fatal("two exact completed identity Jobs are not ready")
	}
	jobs[1].Object["status"].(map[string]any)["conditions"] = []any{
		map[string]any{"type": "Failed", "status": "True"},
	}
	ready, failure = identityJobsStatus(jobs)
	if ready || failure == "" {
		t.Fatal("failed OpenBao Job is identity-ready")
	}
	jobs[1] = complete("vault", "atum-openbao-reconcile", "other")
	ready, failure = identityJobsStatus(jobs)
	if ready || failure == "" {
		t.Fatal("Job with the wrong identity owner label is ready")
	}
}

func TestRunStatusFamiliesBoundsConcurrency(t *testing.T) {
	t.Parallel()

	const limit = 3
	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, limit)
	release := make(chan struct{})
	tasks := make([]statusFamilyTask, 8)
	for index := range tasks {
		tasks[index] = statusFamilyTask{name: "bounded", run: func(context.Context) error {
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			active.Add(-1)
			return nil
		}}
	}
	done := make(chan error, 1)
	go func() {
		done <- runStatusFamilies(context.Background(), limit, tasks)
	}()
	for range limit {
		<-started
	}
	if got := maximum.Load(); got != limit {
		t.Fatalf("maximum concurrent families = %d, want %d", got, limit)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("run bounded status families: %v", err)
	}
}

func TestRunStatusFamiliesCancelsSiblingsAndNamesFailure(t *testing.T) {
	t.Parallel()

	failed := errors.New("registry unavailable")
	cancelled := make(chan struct{})
	err := runStatusFamilies(context.Background(), 2, []statusFamilyTask{
		{name: "waiting source", run: func(ctx context.Context) error {
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		}},
		{name: "internal registry", run: func(context.Context) error {
			return failed
		}},
	})
	if !errors.Is(err, failed) || !strings.Contains(err.Error(), "internal registry") {
		t.Fatalf("family error = %v, want named registry failure", err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("failed family did not cancel its sibling")
	}
}

func TestRunStatusFamiliesReportsDeterministicFailureOrder(t *testing.T) {
	t.Parallel()

	first := errors.New("first")
	second := errors.New("second")
	err := runStatusFamilies(context.Background(), 2, []statusFamilyTask{
		{name: "core cluster", run: func(context.Context) error { return first }},
		{name: "local access", run: func(context.Context) error { return second }},
	})
	if !errors.Is(err, first) || errors.Is(err, second) ||
		!strings.Contains(err.Error(), "core cluster") {
		t.Fatalf("family error = %v, want deterministic first family failure", err)
	}
}

func TestJoinPlatformObligationsPreservesPreciseFailure(t *testing.T) {
	t.Parallel()

	precise := errors.New("control-plane node atum-2 did not reload authentication")
	if err := joinPlatformObligations([2]error{
		context.Canceled, precise,
	}); !errors.Is(err, precise) || errors.Is(err, context.Canceled) {
		t.Fatalf("joined terminal failure = %v", err)
	}
	first := errors.New("Flux readiness failed")
	second := errors.New("OIDC reconciliation failed")
	err := joinPlatformObligations([2]error{first, second})
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("independent obligation failures were hidden: %v", err)
	}
}

func TestCoordinateApplyUsesOneObservationStreamForBothObligations(t *testing.T) {
	t.Parallel()

	var observations atomic.Int32
	reconcileStarted := make(chan struct{})
	releaseReconcile := make(chan struct{})
	observe := func(context.Context) (platformApplyObservation, error) {
		round := observations.Add(1)
		if round == 2 {
			select {
			case <-reconcileStarted:
			default:
				t.Fatal("platform observation did not overlap OIDC reconciliation")
			}
			close(releaseReconcile)
		}
		return platformApplyObservation{
			platformReady:          round >= 2,
			oidcPrerequisitesReady: true,
			oidcSpec:               &orchestration.PlatformOIDCSpec{},
		}, nil
	}
	reconcile := func(
		ctx context.Context,
		_ *orchestration.PlatformOIDCSpec,
	) error {
		close(reconcileStarted)
		select {
		case <-releaseReconcile:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := coordinateApplyObligations(
		ctx, time.Millisecond, true, observe, reconcile,
	); err != nil {
		t.Fatal(err)
	}
	if got := observations.Load(); got != 2 {
		t.Fatalf("status collection rounds = %d, want 2", got)
	}
}

func TestStatusRoundStartsRegistryWhileSnapshotIsBlocked(t *testing.T) {
	t.Parallel()

	snapshotStarted := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	registryStarted := make(chan struct{})
	releaseRegistry := make(chan struct{})
	dependentStarted := make(chan struct{})
	var snapshotComplete atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- runStatusObservationRound(
			context.Background(),
			statusFamilyTask{name: "Kubernetes snapshot", run: func(ctx context.Context) error {
				close(snapshotStarted)
				select {
				case <-releaseSnapshot:
					snapshotComplete.Store(true)
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}},
			statusFamilyTask{name: "internal registry", run: func(ctx context.Context) error {
				close(registryStarted)
				select {
				case <-releaseRegistry:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}},
			[]statusFamilyTask{
				{name: "snapshot consumer", run: func(context.Context) error {
					if !snapshotComplete.Load() {
						return errors.New("snapshot consumer started before snapshot completion")
					}
					close(dependentStarted)
					return nil
				}},
			},
		)
	}()
	<-snapshotStarted
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-registryStarted:
	case <-timer.C:
		close(releaseSnapshot)
		close(releaseRegistry)
		<-done
		t.Fatal("registry family did not start while the Kubernetes snapshot was blocked")
	}
	close(releaseSnapshot)
	dependentTimer := time.NewTimer(time.Second)
	defer dependentTimer.Stop()
	select {
	case <-dependentStarted:
	case <-dependentTimer.C:
		close(releaseRegistry)
		<-done
		t.Fatal("snapshot consumer did not start while the registry family was blocked")
	}
	close(releaseRegistry)
	if err := <-done; err != nil {
		t.Fatalf("run status observation round: %v", err)
	}
}

func TestStatusImageChecksStayBelowOuterFamilyLimit(t *testing.T) {
	t.Parallel()

	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, statusHarborImageLimit)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runStatusImageChecks(
			context.Background(),
			16,
			8,
			func(context.Context, int) error {
				current := active.Add(1)
				for {
					observed := maximum.Load()
					if current <= observed || maximum.CompareAndSwap(observed, current) {
						break
					}
				}
				select {
				case started <- struct{}{}:
				default:
				}
				<-release
				active.Add(-1)
				return nil
			},
		)
	}()
	for range statusHarborImageLimit {
		<-started
	}
	if got := maximum.Load(); got != statusHarborImageLimit {
		t.Fatalf("maximum concurrent image checks = %d, want %d", got, statusHarborImageLimit)
	}
	if statusHarborImageLimit >= statusFamilyLimit {
		t.Fatalf("image limit %d is not below outer family limit %d",
			statusHarborImageLimit, statusFamilyLimit)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("run bounded status image checks: %v", err)
	}
}

func TestReadinessCyclesDoNotOverlapAndWaitAfterSlowRound(t *testing.T) {
	t.Parallel()

	const interval = 20 * time.Millisecond
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan time.Time, 1)
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- waitReadinessCycles(
			context.Background(), time.Second, interval,
			func(context.Context) (bool, error) {
				switch calls.Add(1) {
				case 1:
					close(firstStarted)
					<-releaseFirst
					return false, nil
				case 2:
					secondStarted <- time.Now()
					return true, nil
				default:
					return false, errors.New("overlapping readiness round")
				}
			},
		)
	}()
	<-firstStarted
	select {
	case <-secondStarted:
		t.Fatal("second readiness round overlapped the blocked first round")
	case <-time.After(2 * interval):
	}
	released := time.Now()
	close(releaseFirst)
	started := <-secondStarted
	if elapsed := started.Sub(released); elapsed < interval {
		t.Fatalf("second round started after %s, want at least %s", elapsed, interval)
	}
	if err := <-done; err != nil {
		t.Fatalf("wait readiness cycles: %v", err)
	}
}

func TestReadinessCyclesRetryRetryableFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	err := waitReadinessCycles(
		context.Background(), time.Second, time.Millisecond,
		func(context.Context) (bool, error) {
			if calls.Add(1) == 1 {
				return false, context.DeadlineExceeded
			}
			return true, nil
		},
	)
	if err != nil {
		t.Fatalf("retry readiness observation: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("readiness observation calls = %d, want 2", got)
	}
}

func TestPlatformReadinessCancellationBelongsToCaller(t *testing.T) {
	t.Parallel()

	recorder := &statusEventRecorder{}
	base := progress.WithReporter(context.Background(), recorder)
	ctx, cancel := context.WithCancel(base)
	cancel()
	err := finishPlatformReadiness(ctx, context.Canceled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readiness = %v, want context cancellation", err)
	}
	for _, event := range recorder.snapshot() {
		if event.ID == "bigbang" && event.State == progress.Failed {
			t.Fatal("caller cancellation was published as a Big Bang component failure")
		}
	}

	recorder = &statusEventRecorder{}
	err = finishPlatformReadiness(
		progress.WithReporter(context.Background(), recorder),
		context.DeadlineExceeded,
	)
	if !errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(err.Error(), "wait for platform readiness") {
		t.Fatalf("readiness deadline = %v, want owned timeout failure", err)
	}
	events := recorder.snapshot()
	if len(events) != 1 || events[0].ID != "bigbang" || events[0].State != progress.Failed {
		t.Fatalf("readiness timeout events = %#v, want one Big Bang failure", events)
	}
}

func TestApplyProgressPublishesSourcesAndImagesBeforeWorkloads(t *testing.T) {
	t.Parallel()

	recorder := &statusEventRecorder{}
	ctx := progress.WithReporter(context.Background(), recorder)
	reportApplyReadiness(ctx, Status{
		InternalSourcesOnly: true,
		InternalImageOnly:   true,
		ActiveHelmReleases:  4,
		ReadyHelmReleases:   2,
		NonReadyPods:        3,
	})
	events := recorder.snapshot()
	states := make(map[string]progress.State, len(events))
	for _, event := range events {
		states[event.ID] = event.State
	}
	if states["sources"] != progress.Complete || states["images"] != progress.Complete {
		t.Fatalf("early source/image states = %#v, want complete", states)
	}
	if states["bigbang"] != progress.Running {
		t.Fatalf("Big Bang state = %v, want running", states["bigbang"])
	}
}

func TestKubeVIPAndCertificatesHaveSingleTerminalOwners(t *testing.T) {
	t.Parallel()

	project := &config.Project{Desired: config.Document{
		Infrastructure: config.Infrastructure{
			Active: "local",
			Targets: map[string]config.InfrastructureTarget{
				"local": {PlatformProfile: "local", LocalAccess: &config.LocalAccess{}},
			},
		},
		Platform: config.Platform{Bootstrap: config.BootstrapCharts{Charts: []config.Chart{
			{ID: "kube-vip"},
		}}},
	}}
	index := newPlatformReadinessIndex(project, nil)
	recorder := &statusEventRecorder{}
	ctx := progress.WithReporter(context.Background(), recorder)
	reportAssetReadiness(ctx, index, map[string]assetReadiness{
		"kube-vip": {releasesReady: 1, releasesTotal: 1},
	})
	reportApplyReadiness(ctx, Status{
		LoadBalancerRequired: true,
		LoadBalancerReady:    true,
		CertificatesRequired: true,
		CertificatesReady:    true,
	})
	var vipTerminal, certificateTerminal int
	for _, event := range recorder.snapshot() {
		if event.State != progress.Complete && event.State != progress.Failed {
			continue
		}
		switch event.ID {
		case "kube-vip":
			vipTerminal++
		case "local-certificates":
			certificateTerminal++
		}
	}
	if vipTerminal != 1 {
		t.Fatalf("kube-vip terminal events = %d, want one exact-owner event", vipTerminal)
	}
	if certificateTerminal != 0 {
		t.Fatalf("cluster certificate terminal events = %d, want partial state", certificateTerminal)
	}
}

func TestWrapperReleaseReadinessIsAttributedToPackageOwner(t *testing.T) {
	t.Parallel()

	platform := config.Platform{
		Charts: []config.TrackedChart{
			{ID: "opensearch", ValuesPath: "packages.OpenSearch"},
			{ID: "opensearch-operator", ValuesPath: "packages.opensearch-operator"},
		},
	}
	values := map[string]any{"packages": map[string]any{
		"OpenSearch": map[string]any{"wrapper": map[string]any{"enabled": true}},
		"opensearch-operator": map[string]any{
			"namespace": map[string]any{"name": "opensearch-system"},
			"wrapper":   map[string]any{"enabled": true},
		},
	}}
	consumers, err := config.ActiveWrapperConsumers(platform, values)
	if err != nil {
		t.Fatalf("active wrapper consumers: %v", err)
	}
	project := &config.Project{Desired: config.Document{Platform: platform}}
	index := newPlatformReadinessIndex(project, consumers)
	if got := index.match("open-search-wrapper"); got != "opensearch" {
		t.Fatalf("OpenSearch wrapper owner = %q, want opensearch", got)
	}
	if got := index.match("opensearch-operator-wrapper"); got != "opensearch-operator" {
		t.Fatalf("operator wrapper owner = %q, want opensearch-operator", got)
	}
	if len(index.ids) != 2 {
		t.Fatalf("wrapper aliases created %d readiness rows, want two package rows", len(index.ids))
	}
}

func TestDesiredWorkloadBlocksAssetWithoutAnAdmittedPod(t *testing.T) {
	t.Parallel()

	project := &config.Project{Desired: config.Document{Platform: config.Platform{
		Packages: []config.Package{{ID: "monitoring", ValuesPath: "monitoring"}},
	}}}
	index := newPlatformReadinessIndex(project, nil)
	deployment := kube.Object{
		Name: "monitoring", Namespace: "monitoring", Generation: 2,
		Labels: map[string]string{"helm.toolkit.fluxcd.io/name": "monitoring"},
		Object: map[string]any{
			"spec": map[string]any{"replicas": int64(1)},
			"status": map[string]any{
				"observedGeneration": int64(2),
				"updatedReplicas":    int64(0),
				"readyReplicas":      int64(0),
				"availableReplicas":  int64(0),
			},
		},
	}
	release := kube.Object{
		Name: "monitoring", Namespace: "bigbang", Ready: true,
		Object: map[string]any{"spec": map[string]any{"targetNamespace": "monitoring"}},
	}
	snapshot := platformSnapshot{resources: map[kube.Resource][]kube.Object{
		kube.HelmRelease: {release},
		kube.Deployment:  {deployment},
	}}
	assets := make(map[string]assetReadiness)
	projectAssetReadiness(snapshot, index, assets, make(map[string]string))
	asset := assets["monitoring"]
	if asset.releasesReady != 1 || asset.releasesTotal != 1 ||
		asset.workloadsReady != 0 || asset.workloadsTotal != 1 {
		t.Fatalf("zero-pod workload projection = %#v", asset)
	}

	service := Service{Project: project}
	workloads := service.observeWorkloadSnapshot(snapshot, nil)
	if workloads.activeWorkloads != 1 || workloads.readyWorkloads != 0 {
		t.Fatalf("aggregate workload projection = %#v", workloads)
	}
}

func TestWorkloadControllerReadinessUsesDesiredRolloutState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resource kube.Resource
		spec     map[string]any
		status   map[string]any
		ready    bool
	}{
		{
			name: "deployment ready", resource: kube.Deployment,
			spec: map[string]any{"replicas": int64(2)},
			status: map[string]any{
				"observedGeneration": int64(3), "updatedReplicas": int64(2),
				"readyReplicas": int64(2), "availableReplicas": int64(2),
			},
			ready: true,
		},
		{
			name: "deployment update pending", resource: kube.Deployment,
			spec: map[string]any{"replicas": int64(2)},
			status: map[string]any{
				"observedGeneration": int64(3), "updatedReplicas": int64(1),
				"readyReplicas": int64(2), "availableReplicas": int64(2),
			},
		},
		{
			name: "stateful partition ready", resource: kube.StatefulSet,
			spec: map[string]any{
				"replicas": int64(3),
				"updateStrategy": map[string]any{"rollingUpdate": map[string]any{
					"partition": int64(1),
				}},
			},
			status: map[string]any{
				"observedGeneration": int64(3), "updatedReplicas": int64(2),
				"readyReplicas": int64(3),
			},
			ready: true,
		},
		{
			name: "daemon unavailable", resource: kube.DaemonSet,
			status: map[string]any{
				"observedGeneration": int64(3), "desiredNumberScheduled": int64(3),
				"updatedNumberScheduled": int64(3), "numberReady": int64(2),
				"numberAvailable": int64(2),
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			workload := kube.Object{
				Generation: 3,
				Object:     map[string]any{"spec": test.spec, "status": test.status},
			}
			if got := workloadControllerReady(test.resource, &workload); got != test.ready {
				t.Fatalf("workload readiness = %v, want %v", got, test.ready)
			}
		})
	}
}

func TestSharedWrapperSourceRejectsUnexpectedAndDuplicateConsumers(t *testing.T) {
	t.Parallel()

	source := consumerGitSource{
		restrictReleases: true,
		releases: map[string]string{
			"open-search-wrapper":         "open-search",
			"opensearch-operator-wrapper": "opensearch-system",
		},
	}
	seen := make(map[string]struct{})
	if !recordExpectedConsumerRelease(source, "open-search-wrapper", "open-search", seen) {
		t.Fatal("declared wrapper consumer was rejected")
	}
	if recordExpectedConsumerRelease(source, "open-search-wrapper", "open-search", seen) {
		t.Fatal("duplicate wrapper consumer was accepted")
	}
	if recordExpectedConsumerRelease(source, "dashboards-wrapper", "opensearch", seen) {
		t.Fatal("unowned wrapper consumer was accepted")
	}
	if recordExpectedConsumerRelease(source, "opensearch-operator-wrapper", "wrong", seen) {
		t.Fatal("wrapper consumer with a conflicting namespace was accepted")
	}
}

func TestPackageConsumerSourcesAcceptSharedWrapperSource(t *testing.T) {
	t.Parallel()

	repository := kube.Object{
		Name: "bigbang-wrapper", Namespace: "bigbang",
		Object: map[string]any{
			"spec": map[string]any{"url": "http://forgejo/atum-upstreams/wrapper.git"},
		},
	}
	expected := map[string]consumerGitSource{
		"http://forgejo/atum-upstreams/wrapper": {
			chartPath: "chart", reconcileStrategy: "Revision",
		},
	}
	sources, exact := packageConsumerSourcesSnapshot([]kube.Object{repository}, expected)
	if !exact {
		t.Fatal("shared wrapper source was not exact")
	}
	if got := sources["bigbang-wrapper"]; got.reconcileStrategy != "Revision" || got.chartPath != "chart" {
		t.Fatalf("wrapper consumer source = %#v", got)
	}
}

func TestExactGitSourceRequiresConfiguredTimeout(t *testing.T) {
	t.Parallel()

	commit := strings.Repeat("a", 40)
	item := kube.Object{
		Ready: true,
		Object: map[string]any{
			"spec": map[string]any{
				"url":      "http://forgejo/atum-upstreams/wrapper.git",
				"ref":      map[string]any{"branch": "main", "commit": commit},
				"interval": "2m",
				"timeout":  "60s",
			},
			"status": map[string]any{
				"artifact": map[string]any{"revision": "main@sha1:" + commit},
			},
		},
	}
	identity := sourceIdentity{
		url: "http://forgejo/atum-upstreams/wrapper.git", branch: "main",
		commit: commit, revision: commit,
		interval: "2m", timeout: "60s",
	}
	if !exactGitSource(&item, identity) {
		t.Fatal("exact Git source with the configured timeout was rejected")
	}

	spec := item.Object["spec"].(map[string]any)
	delete(spec, "timeout")
	if exactGitSource(&item, identity) {
		t.Fatal("Git source without the configured timeout was accepted")
	}
	spec["timeout"] = "30s"
	if exactGitSource(&item, identity) {
		t.Fatal("Git source with a different timeout was accepted")
	}
}

func TestMergeStatusObservationsIsDeterministic(t *testing.T) {
	t.Parallel()

	service := Service{Project: &config.Project{Desired: config.Document{
		Infrastructure: config.Infrastructure{
			Active: "local",
			Targets: map[string]config.InfrastructureTarget{
				"local": {
					PlatformProfile: "local",
					LocalAccess: &config.LocalAccess{
						Domain: "atum.test", PublicIngressVIP: "10.0.0.2",
						PassthroughIngressVIP: "10.0.0.3", LoadBalancerRange: "10.0.0.2-10.0.0.3",
					},
				},
			},
		},
	}}}
	observed := statusObservations{
		core: coreClusterObservation{
			bundleSHA256: "bundle", sourceCommit: "commit", bundleReady: true,
			fluxReady: true, prepReady: true, profilePrepReady: true,
			bigBangReady: true, profileAccessReady: true,
		},
		workloads: workloadObservation{
			helmReleases:       []ResourceStatus{{Name: "a/a", Ready: true}},
			activeHelmReleases: 1, readyHelmReleases: 1,
			imageIssues: []string{"pod mismatch"}, imageIssueCount: 1,
		},
		sources: sourceObservation{
			ociSources: []ResourceStatus{{Name: "b/b", Ready: true}},
			issues:     []string{"source mismatch"}, issueCount: 1,
		},
		registry: registryObservation{},
		local: localAccessObservation{
			loadBalancer: localLoadBalancerObservation{
				ready: true, publicIPs: []string{"10.0.0.2"},
				passthroughIPs: []string{"10.0.0.3"},
			},
			certificates: localCertificateObservation{
				ready: true, rootFingerprint: "ROOT",
				resources: []ResourceStatus{{Name: "cert/cert", Ready: true}},
			},
			issuerReady: true, accessURLs: []string{"https://headlamp.atum.test"},
			routesReady: true,
		},
	}
	first := mergeStatusObservations(service, observed)
	second := mergeStatusObservations(service, observed)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("merge changed across identical observations:\nfirst: %#v\nsecond: %#v", first, second)
	}
	wantImageIssues := []string{
		"pod mismatch", "Harbor publication differs from the locked image set",
	}
	if !reflect.DeepEqual(first.ImageIssues, wantImageIssues) {
		t.Fatalf("image issue order = %#v, want %#v", first.ImageIssues, wantImageIssues)
	}
	wantSourceIssues := []string{
		"source mismatch",
		"Harbor chart publication differs from the locked chart set",
		"Harbor chart tags are not immutable",
	}
	if !reflect.DeepEqual(first.SourceIssues, wantSourceIssues) {
		t.Fatalf("source issue order = %#v, want %#v", first.SourceIssues, wantSourceIssues)
	}
}

func TestPodPermutationProducesIdenticalBoundedImageDiagnostics(t *testing.T) {
	t.Parallel()

	pods := make([]kube.Pod, platformStatusIssueLimit+2)
	for index := range pods {
		namespace := "team-b"
		if index%2 != 0 {
			namespace = "team-a"
		}
		pods[index] = kube.Pod{
			Name:      fmt.Sprintf("pod-%02d", len(pods)-index),
			Namespace: namespace,
			Ready:     true,
			Containers: []kube.PodContainer{{
				Name: "application", Image: fmt.Sprintf("registry.invalid/image-%02d:tag", index),
			}},
		}
	}
	reversed := make([]kube.Pod, len(pods))
	for index := range pods {
		reversed[len(pods)-1-index] = pods[index]
	}
	canonicalizePlatformPods(pods)
	canonicalizePlatformPods(reversed)

	service := Service{Project: &config.Project{Desired: config.Document{
		Infrastructure: config.Infrastructure{
			Active: "test",
			Targets: map[string]config.InfrastructureTarget{
				"test": {PlatformProfile: "test"},
			},
		},
	}}}
	observe := func(items []kube.Pod) Status {
		workloads := service.observeWorkloadSnapshot(
			platformSnapshot{resources: map[kube.Resource][]kube.Object{}, pods: items},
			map[string]map[string]struct{}{},
		)
		return mergeStatusObservations(service, statusObservations{
			workloads: workloads,
			registry: registryObservation{
				imageExact: true, chartsExact: true, chartsImmutable: true,
			},
		})
	}
	first := observe(pods)
	second := observe(reversed)
	if !reflect.DeepEqual(first.ImageIssues, second.ImageIssues) {
		t.Fatalf("image issues differ across equivalent pod permutations:\nfirst: %#v\nsecond: %#v",
			first.ImageIssues, second.ImageIssues)
	}
	if len(first.ImageIssues) != platformStatusIssueLimit {
		t.Fatalf("bounded image issue count = %d, want %d",
			len(first.ImageIssues), platformStatusIssueLimit)
	}
	if first.imageFailureDetail() != second.imageFailureDetail() {
		t.Fatalf("first failure detail differs across pod permutations:\nfirst: %q\nsecond: %q",
			first.imageFailureDetail(), second.imageFailureDetail())
	}
}

func TestControlPlaneNodeCountExcludesWorkers(t *testing.T) {
	t.Parallel()

	nodes := []kube.Node{
		{Name: "control-1", ControlPlane: true},
		{Name: "worker-1"},
		{Name: "control-2", ControlPlane: true},
	}
	if got := controlPlaneNodeCount(nodes); got != 2 {
		t.Fatalf("control-plane node count = %d, want 2", got)
	}
	if got := controlPlaneNodeCount(nodes[1:2]); got != 0 {
		t.Fatalf("worker-only control-plane node count = %d, want 0", got)
	}
}

func TestPendingLockedImageIsNotReportedAsDrift(t *testing.T) {
	t.Parallel()

	const (
		image  = "registry.example/application:v1"
		digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	locked := map[string]map[string]struct{}{image: {digest: {}}}
	pod := kube.Pod{
		Name: "application-0", Namespace: "application",
		Containers: []kube.PodContainer{{Name: "application", Image: image}},
	}
	if issue := podLockedImageIssue(&pod, locked); issue != "" {
		t.Fatalf("pending locked image reported as drift: %s", issue)
	}

	pod.Ready = true
	if issue := podLockedImageIssue(&pod, locked); !strings.Contains(issue, "has no verified runtime digest") {
		t.Fatalf("ready image without a runtime identity issue = %q", issue)
	}

	pod.Ready = false
	pod.Containers[0].ImageID =
		"containerd://sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if issue := podLockedImageIssue(&pod, locked); !strings.Contains(issue, " resolved ") {
		t.Fatalf("pending image with a conflicting runtime identity issue = %q", issue)
	}
}

func TestBundledFluxConsumersRejectTimingDrift(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	desired := writeFluxConsumerBundleFixture(t, root)
	expectations, err := bundledFluxConsumerExpectations(
		&delivery.DeploymentBundle{SourceRoot: root}, desired)
	if err != nil {
		t.Fatalf("decode bundled Flux consumers: %v", err)
	}
	if len(expectations) != 5 {
		t.Fatalf("bundled Flux consumer count = %d, want five", len(expectations))
	}
	for _, expected := range expectations {
		if strings.Contains(fmt.Sprint(expected.spec), "${ATUM_") {
			t.Fatalf("bundled Flux consumer %s retains an unsubstituted profile value", expected.name)
		}
		force, found := expected.spec["force"].(bool)
		want := expected.name == "platform-profile-identity"
		if !found || force != want {
			t.Fatalf("bundled Flux consumer %s force = %v, %t; want %t",
				expected.name, force, found, want)
		}
	}
	canonical := fluxConsumerObjects(expectations)
	if !exactFluxConsumerObjects(canonical, expectations) {
		t.Fatal("canonical bundled Flux consumer topology was rejected")
	}

	for _, name := range []string{
		"platform-profile-prep",
		"platform-profile-access",
		"platform-profile-identity",
	} {
		for _, field := range []string{"interval", "retryInterval", "timeout"} {
			for _, absent := range []bool{false, true} {
				mutation := "changed"
				if absent {
					mutation = "missing"
				}
				t.Run(name+"/"+field+"/"+mutation, func(t *testing.T) {
					objects := fluxConsumerObjects(expectations)
					spec := fluxConsumerObjectSpec(t, objects, name)
					if absent {
						delete(spec, field)
					} else {
						spec[field] = "1s"
					}
					if exactFluxConsumerObjects(objects, expectations) {
						t.Fatalf("%s %s %s was accepted", name, mutation, field)
					}
				})
			}
		}
	}
	objects := fluxConsumerObjects(expectations)
	fluxConsumerObjectSpec(t, objects, "bigbang")["timeout"] = "1s"
	if exactFluxConsumerObjects(objects, expectations) {
		t.Fatal("changed bigbang timeout was accepted")
	}
	for _, expected := range expectations {
		for _, missing := range []bool{false, true} {
			mutation := "changed"
			if missing {
				mutation = "missing"
			}
			t.Run(expected.name+"/force/"+mutation, func(t *testing.T) {
				objects := fluxConsumerObjects(expectations)
				spec := fluxConsumerObjectSpec(t, objects, expected.name)
				if missing {
					delete(spec, "force")
				} else {
					spec["force"] = !expected.spec["force"].(bool)
				}
				if exactFluxConsumerObjects(objects, expectations) {
					t.Fatalf("%s %s force was accepted", expected.name, mutation)
				}
			})
		}
	}
}

func writeFluxConsumerBundleFixture(t *testing.T, root string) config.Document {
	t.Helper()
	type fixture struct {
		file, name, path, interval, retry, timeout string
		wait, force                                bool
		dependencies                               []string
		profile, identity                          bool
	}
	fixtures := [...]fixture{
		{
			file: "prep.yaml", name: "prep", path: "./platform/apps/prep",
			interval: "10m", retry: "2m", timeout: "15m",
		},
		{
			file: "platform-profile-prep.yaml", name: "platform-profile-prep",
			path:     "./platform/profiles/${ATUM_PLATFORM_PROFILE}/prep",
			interval: "10m", retry: "2m", timeout: "15m", wait: true,
			dependencies: []string{"prep"}, profile: true, identity: true,
		},
		{
			file: "bigbang.yaml", name: "bigbang", path: "./platform/apps/bigbang",
			interval: "10m", retry: "2m", timeout: "35m", wait: true,
			dependencies: []string{"prep", "platform-profile-prep"},
		},
		{
			file: "platform-profile-access.yaml", name: "platform-profile-access",
			path:     "./platform/profiles/${ATUM_PLATFORM_PROFILE}/access",
			interval: "10m", retry: "2m", timeout: "15m", wait: true,
			dependencies: []string{"bigbang"}, profile: true,
		},
		{
			file: "platform-profile-identity.yaml", name: "platform-profile-identity",
			path:     "./platform/profiles/${ATUM_PLATFORM_PROFILE}/identity",
			interval: "10m", retry: "2m", timeout: "20m", wait: true, force: true,
			dependencies: []string{"platform-profile-access"}, profile: true, identity: true,
		},
	}
	directory := filepath.Join(root, "platform", "clusters", "atum")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create Flux consumer fixture directory: %v", err)
	}
	for _, item := range fixtures {
		spec := map[string]any{
			"interval": item.interval, "retryInterval": item.retry, "timeout": item.timeout,
			"prune": true, "wait": item.wait,
			"sourceRef": map[string]any{
				"kind": "GitRepository", "name": "flux-system",
			},
			"path": item.path,
		}
		spec["force"] = item.force
		if len(item.dependencies) != 0 {
			dependencies := make([]any, len(item.dependencies))
			for index, name := range item.dependencies {
				dependencies[index] = map[string]any{"name": name}
			}
			spec["dependsOn"] = dependencies
		}
		if item.profile {
			postBuild := map[string]any{"substitute": map[string]any{
				"ATUM_PLATFORM_DOMAIN": "${ATUM_PLATFORM_DOMAIN}",
			}}
			if item.identity {
				postBuild["substituteFrom"] = []any{map[string]any{
					"kind": "Secret", "name": "atum-platform-identity", "optional": true,
				}}
			}
			spec["postBuild"] = postBuild
		}
		data, err := yaml.Marshal(map[string]any{
			"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
			"kind":       "Kustomization",
			"metadata": map[string]any{
				"name": item.name, "namespace": "flux-system",
			},
			"spec": spec,
		})
		if err != nil {
			t.Fatalf("encode bundled Flux consumer %s: %v", item.name, err)
		}
		if err := os.WriteFile(filepath.Join(directory, item.file), data, 0o600); err != nil {
			t.Fatalf("write bundled Flux consumer %s: %v", item.name, err)
		}
	}
	return config.Document{
		Project:  config.ProjectConfig{Cluster: "atum"},
		Platform: config.Platform{Directory: "platform"},
		Infrastructure: config.Infrastructure{
			Active: "local",
			Targets: map[string]config.InfrastructureTarget{
				"local": {
					PlatformProfile: "local",
					LocalAccess:     &config.LocalAccess{Domain: "atum.test"},
				},
			},
		},
	}
}

func fluxConsumerObjects(expectations []fluxConsumerExpectation) []kube.Object {
	objects := make([]kube.Object, len(expectations))
	for index, expected := range expectations {
		spec := make(map[string]any, len(expected.spec))
		for key, value := range expected.spec {
			spec[key] = value
		}
		objects[index] = kube.Object{
			Name: expected.name, Namespace: expected.namespace,
			Object: map[string]any{
				"apiVersion": expected.apiVersion,
				"kind":       expected.kind,
				"spec":       spec,
			},
		}
	}
	return objects
}

func fluxConsumerObjectSpec(t *testing.T, objects []kube.Object, name string) map[string]any {
	t.Helper()
	for index := range objects {
		if objects[index].Name == name {
			return objects[index].Object["spec"].(map[string]any)
		}
	}
	t.Fatalf("Flux consumer fixture omits %s", name)
	return nil
}

func TestSubstituteProfileValuesUsesFluxSemantics(t *testing.T) {
	t.Parallel()

	input := []byte("domain: ${ATUM_PLATFORM_DOMAIN}\nescaped: $${ATUM_PLATFORM_DOMAIN}\n")
	got, err := substituteProfileValues(input, "atum.test")
	if err != nil {
		t.Fatalf("substitute profile values: %v", err)
	}
	want := "domain: atum.test\nescaped: ${ATUM_PLATFORM_DOMAIN}\n"
	if string(got) != want {
		t.Fatalf("substituted profile values = %q, want %q", got, want)
	}
}

func TestBootstrapConsumersUseExactHelmReleaseBinding(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	values := filepath.Join("platform", "apps", "kube-vip", "values.yaml")
	release := filepath.Join(root, filepath.Dir(values), "helmrelease.yaml")
	if err := os.MkdirAll(filepath.Dir(release), 0o755); err != nil {
		t.Fatalf("create manifest directory: %v", err)
	}
	manifest := []byte(`apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: kube-vip
  namespace: kube-system
spec:
  chartRef:
    kind: OCIRepository
    name: kube-vip
    namespace: kube-system
`)
	if err := os.WriteFile(release, manifest, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	got, err := bootstrapConsumers(
		&delivery.DeploymentBundle{SourceRoot: root},
		[]config.Chart{{ID: "kube-vip", Values: filepath.ToSlash(values)}},
	)
	if err != nil {
		t.Fatalf("bootstrap consumers: %v", err)
	}
	want := []bootstrapConsumer{{
		id:              "kube-vip",
		namespace:       "kube-system",
		sourceName:      "kube-vip",
		sourceNamespace: "kube-system",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrap consumers = %#v, want %#v", got, want)
	}
}
