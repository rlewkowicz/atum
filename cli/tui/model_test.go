package tui

import (
	"errors"
	"strings"
	"testing"

	"atum/cli/progress"
)

func TestFinalModelShowsCompletionOnlyOnSuccess(t *testing.T) {
	t.Parallel()

	completion, err := NewCompletion(testCompletionSpec())
	if err != nil {
		t.Fatalf("construct completion: %v", err)
	}
	success := newModel("apply", ".atum/logs/apply.log", nil, nil)
	success.width = 76
	_, _ = success.Update(finishMsg{completion: completion})
	if view := success.View(); !strings.Contains(view, "Access") ||
		!strings.Contains(view, "Username") {
		t.Fatalf("successful final view omits access:\n%s", view)
	}

	failed := newModel("apply", ".atum/logs/apply.log", nil, nil)
	_, _ = failed.Update(finishMsg{completion: completion, err: errors.New("failed")})
	if view := failed.View(); strings.Contains(view, "Username") ||
		strings.Contains(view, "keycloak.atum.test") ||
		!strings.Contains(view, "Error  failed") {
		t.Fatalf("failed final view disclosed completion:\n%s", view)
	}
}

func TestProgressRenderingIncludesItemsAndBytes(t *testing.T) {
	t.Parallel()

	event := progress.Event{
		Phase:        progress.Platform,
		ID:           "harbor-publication",
		Label:        "Harbor publication",
		Detail:       "publishing",
		State:        progress.Running,
		Current:      3,
		Total:        8,
		BytesCurrent: 1536,
		BytesTotal:   4096,
	}
	if compact := compactEvent(event); !strings.Contains(compact, "3/8") ||
		!strings.Contains(compact, "1.5 KiB/4.0 KiB") {
		t.Fatalf("compact progress omits item or byte counts: %s", compact)
	}
	model := newModel("publish", "raw.log", nil, nil)
	model.apply(event)
	if view := model.View(); !strings.Contains(view, "3/8") ||
		!strings.Contains(view, "1.5 KiB/4.0 KiB") {
		t.Fatalf("TUI progress omits item or byte counts: %s", view)
	}
}

func TestSeedPlaneBytesIsStrict(t *testing.T) {
	t.Parallel()

	if got := seedPlaneBytes("loading bytes=4096"); got != 4096 {
		t.Fatalf("seed bytes = %d, want 4096", got)
	}
	for _, input := range []string{"loading", "bytes=-1", "bytes=invalid"} {
		if got := seedPlaneBytes(input); got != 0 {
			t.Fatalf("seed bytes for %q = %d, want 0", input, got)
		}
	}
}
