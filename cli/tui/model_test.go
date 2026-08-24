package tui

import (
	"errors"
	"strings"
	"testing"
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
