// Package progress defines the small, domain-neutral event contract used by
// Atum's managed workflows. Domain services report semantic state through the
// context; renderers decide whether that state becomes a TUI, compact text, or
// only an audit-log entry.
package progress

import (
	"context"
	"time"
)

type Phase string

const (
	Preflight      Phase = "preflight"
	Credentials    Phase = "credentials"
	Infrastructure Phase = "infrastructure"
	Orchestration  Phase = "orchestration"
	Platform       Phase = "platform"
)

type State uint8

const (
	Pending State = iota
	Running
	Complete
	Failed
)

type Event struct {
	Phase   Phase
	ID      string
	Label   string
	Detail  string
	State   State
	Restart bool
	Current int
	Total   int
	Time    time.Time
}

type Target struct {
	Phase Phase
	ID    string
	Label string
}

type Reporter interface {
	Report(Event)
}

type reporterKey struct{}

func WithReporter(ctx context.Context, reporter Reporter) context.Context {
	if reporter == nil {
		return ctx
	}
	return context.WithValue(ctx, reporterKey{}, reporter)
}

func Report(ctx context.Context, event Event) {
	if ctx == nil {
		return
	}
	reporter, _ := ctx.Value(reporterKey{}).(Reporter)
	if reporter == nil {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	reporter.Report(event)
}

func Start(ctx context.Context, phase Phase, id, label, detail string) {
	Report(ctx, Event{Phase: phase, ID: id, Label: label, Detail: detail, State: Running, Restart: true})
}

func Update(ctx context.Context, phase Phase, id, label, detail string, current, total int) {
	Report(ctx, Event{
		Phase: phase, ID: id, Label: label, Detail: detail,
		State: Running, Current: current, Total: total,
	})
}

func Done(ctx context.Context, phase Phase, id, label, detail string) {
	Report(ctx, Event{Phase: phase, ID: id, Label: label, Detail: detail, State: Complete})
}

func Fail(ctx context.Context, phase Phase, id, label string, err error) {
	detail := "failed"
	if err != nil {
		detail = err.Error()
	}
	Report(ctx, Event{Phase: phase, ID: id, Label: label, Detail: detail, State: Failed})
}

// Finish marks every unfinished item in a phase with the supplied terminal
// state. Renderers treat the reserved item ID as a phase-wide transition.
func Finish(ctx context.Context, phase Phase, state State, detail string) {
	Report(ctx, Event{Phase: phase, ID: "*", Detail: detail, State: state})
}
