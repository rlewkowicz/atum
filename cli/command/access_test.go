package command

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"atum/cli/infra"
	"atum/cli/progress"
)

type accessEventRecorder struct {
	events chan progress.Event
}

func (recorder accessEventRecorder) Report(event progress.Event) {
	recorder.events <- event
}

func TestLocalDNSObservationBoundsProbeAndDoesNotOverlap(t *testing.T) {
	t.Parallel()

	const (
		probeTimeout = 15 * time.Millisecond
		interval     = 10 * time.Millisecond
	)
	var active atomic.Int32
	var maximum atomic.Int32
	var calls atomic.Int32
	secondStarted := make(chan time.Time, 1)
	firstFinished := make(chan time.Time, 1)
	err := runLocalDNSObservation(
		context.Background(),
		interval,
		probeTimeout,
		func(ctx context.Context) (infra.AccessStatus, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			if calls.Add(1) == 1 {
				<-ctx.Done()
				firstFinished <- time.Now()
				return infra.AccessStatus{}, ctx.Err()
			}
			secondStarted <- time.Now()
			return infra.AccessStatus{PublicLookupExact: true}, nil
		},
		func(status infra.AccessStatus) bool {
			return status.PublicLookupExact
		},
		nil,
	)
	if err != nil {
		t.Fatalf("observe local DNS: %v", err)
	}
	finished := <-firstFinished
	started := <-secondStarted
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent DNS probes = %d, want 1", maximum.Load())
	}
	if elapsed := started.Sub(finished); elapsed < interval {
		t.Fatalf("DNS retry started after %s, want at least %s", elapsed, interval)
	}
}

func TestSlowLocalDNSProbeDoesNotDelayIndependentReadiness(t *testing.T) {
	t.Parallel()

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	dnsDone := make(chan error, 1)
	go func() {
		dnsDone <- runLocalDNSObservation(
			context.Background(),
			time.Millisecond,
			time.Second,
			func(context.Context) (infra.AccessStatus, error) {
				close(probeStarted)
				<-releaseProbe
				return infra.AccessStatus{PublicLookupExact: true}, nil
			},
			func(status infra.AccessStatus) bool { return status.PublicLookupExact },
			nil,
		)
	}()
	<-probeStarted
	readinessStarted := make(chan struct{})
	go close(readinessStarted)
	select {
	case <-readinessStarted:
	case <-time.After(100 * time.Millisecond):
		close(releaseProbe)
		t.Fatal("slow DNS probe delayed independent readiness work")
	}
	close(releaseProbe)
	if err := <-dnsDone; err != nil {
		t.Fatalf("observe local DNS: %v", err)
	}
}

func TestLocalDNSObservationHonorsLifetimeFromWorkerStart(t *testing.T) {
	t.Parallel()

	worker, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runLocalDNSObservation(
		worker,
		time.Second,
		time.Second,
		func(ctx context.Context) (infra.AccessStatus, error) {
			<-ctx.Done()
			return infra.AccessStatus{}, ctx.Err()
		},
		func(infra.AccessStatus) bool { return false },
		nil,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS lifetime error = %v, want deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("DNS lifetime elapsed = %s, deadline began too late", elapsed)
	}
}

func TestLocalDNSObservationReportsRetriesAndPermanentFailure(t *testing.T) {
	t.Parallel()

	failed := errors.New("resolver unavailable")
	var calls atomic.Int32
	var retries atomic.Int32
	err := runLocalDNSObservation(
		context.Background(),
		time.Millisecond,
		time.Second,
		func(context.Context) (infra.AccessStatus, error) {
			if calls.Add(1) == 1 {
				return infra.AccessStatus{}, context.DeadlineExceeded
			}
			return infra.AccessStatus{}, failed
		},
		func(infra.AccessStatus) bool { return false },
		func(int) { retries.Add(1) },
	)
	if !errors.Is(err, failed) {
		t.Fatalf("DNS observation error = %v, want %v", err, failed)
	}
	if calls.Load() != 2 || retries.Load() != 1 {
		t.Fatalf("DNS calls/retries = %d/%d, want 2/1", calls.Load(), retries.Load())
	}
}

func TestLocalDNSResultOwnsTerminalProgress(t *testing.T) {
	t.Parallel()

	recorder := accessEventRecorder{events: make(chan progress.Event, 2)}
	ctx := progress.WithReporter(context.Background(), recorder)
	reportLocalDNSResult(ctx, nil)
	failed := errors.New("resolver failed")
	reportLocalDNSResult(ctx, failed)
	complete := <-recorder.events
	failure := <-recorder.events
	if complete.ID != "local-dns" || complete.State != progress.Complete {
		t.Fatalf("DNS completion event = %#v", complete)
	}
	if failure.ID != "local-dns" || failure.State != progress.Failed ||
		failure.Detail != failed.Error() {
		t.Fatalf("DNS failure event = %#v", failure)
	}
}

func TestLocalDNSWorkerDeadlineOwnsOneFailure(t *testing.T) {
	t.Parallel()

	recorder := accessEventRecorder{events: make(chan progress.Event, 1)}
	parent := progress.WithReporter(context.Background(), recorder)
	worker, cancel := context.WithTimeout(parent, time.Millisecond)
	defer cancel()
	<-worker.Done()
	facts := infra.LocalAccessFacts{
		Domain: "atum.test", PublicIngressVIP: "10.0.0.2",
		PassthroughIngressVIP: "10.0.0.3",
	}
	err := finishLocalDNSObservation(
		parent, worker, infra.AccessStatus{}, facts, worker.Err())
	if err == nil {
		t.Fatal("worker deadline returned nil")
	}
	event := <-recorder.events
	if event.ID != "local-dns" || event.State != progress.Failed {
		t.Fatalf("DNS timeout event = %#v", event)
	}
	select {
	case duplicate := <-recorder.events:
		t.Fatalf("duplicate DNS terminal event = %#v", duplicate)
	default:
	}
}

func TestLocalDNSWorkerCancellationHasNoTerminalEvent(t *testing.T) {
	t.Parallel()

	recorder := accessEventRecorder{events: make(chan progress.Event, 1)}
	parent := progress.WithReporter(context.Background(), recorder)
	worker, cancelWorker := context.WithCancel(parent)
	cancelWorker()
	err := finishLocalDNSObservation(
		parent, worker, infra.AccessStatus{}, infra.LocalAccessFacts{}, worker.Err())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("worker cancellation = %v, want context cancellation", err)
	}
	select {
	case event := <-recorder.events:
		t.Fatalf("cancellation published terminal event = %#v", event)
	default:
	}
}

func TestLocalDNSCancelRetiresWorkerWithoutTerminalEvent(t *testing.T) {
	t.Parallel()

	recorder := accessEventRecorder{events: make(chan progress.Event, 1)}
	parent := progress.WithReporter(context.Background(), recorder)
	worker, cancelWorker := context.WithCancel(parent)
	done := make(chan localDNSResult, 1)
	observation := &localDNSObservation{cancel: cancelWorker, done: done}
	go func() {
		<-worker.Done()
		err := finishLocalDNSObservation(
			parent, worker, infra.AccessStatus{}, infra.LocalAccessFacts{}, worker.Err())
		done <- localDNSResult{err: err}
		close(done)
	}()
	observation.Cancel()
	select {
	case event := <-recorder.events:
		t.Fatalf("explicit worker retirement published terminal event = %#v", event)
	default:
	}
}

func TestFinalHostProjectionUsesCachedDNSStatus(t *testing.T) {
	t.Parallel()

	target := infra.AccessStatus{AnchorFingerprint: "ROOT"}
	cached := infra.AccessStatus{
		ResolverPath: "/resolver", ResolverExact: true, ResolvedActive: true,
		ResolvConfManaged: true, PublicLookupExact: true,
		PassthroughLookupsExact: true,
	}
	projectDNSStatus(&target, cached)
	if !target.DNSExact() || !target.PublicLookupExact ||
		!target.PassthroughLookupsExact || target.AnchorFingerprint != "ROOT" {
		t.Fatalf("cached DNS projection = %#v", target)
	}
}

func TestPlatformPhaseCompletionFollowsCommandOwnedRows(t *testing.T) {
	t.Parallel()

	recorder := accessEventRecorder{events: make(chan progress.Event, 3)}
	ctx := progress.WithReporter(context.Background(), recorder)
	progress.Done(ctx, progress.Platform, "local-dns", "Local DNS", "exact")
	progress.Done(ctx, progress.Platform, "local-certificates", "Local certificates", "exact")
	finishPlatformApply(ctx)
	events := []progress.Event{<-recorder.events, <-recorder.events, <-recorder.events}
	if events[0].ID != "local-dns" || events[1].ID != "local-certificates" ||
		events[2].ID != "*" || events[2].State != progress.Complete {
		t.Fatalf("platform completion sequence = %#v", events)
	}
}
