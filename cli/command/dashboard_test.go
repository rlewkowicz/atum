package command

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/tui"
)

func TestDashboardCancellationWithholdsCompletionInCompactAndRawModes(t *testing.T) {
	t.Parallel()

	completion := dashboardTestCompletion(t)
	for _, raw := range []bool{false, true} {
		raw := raw
		t.Run(map[bool]string{false: "compact", true: "raw"}[raw], func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			var output, errorOutput bytes.Buffer
			a := &app{
				project: &config.Project{Root: root},
				in:      bytes.NewReader(nil),
				out:     &output,
				err:     &errorOutput,
				raw:     raw,
			}
			parent, cancel := context.WithCancel(context.Background())
			cancel()
			err := a.withDashboardCompletion(
				parent, "canceled completion", tui.ScopePlatform,
				func(context.Context) (tui.Completion, error) {
					return completion, nil
				},
			)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("dashboard cancellation error = %v", err)
			}
			assertNoDashboardCompletion(t, output.String())
			assertNoDashboardCompletion(t, errorOutput.String())

			entries, err := os.ReadDir(filepath.Join(root, ".atum", "logs"))
			if err != nil {
				t.Fatalf("read session logs: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("session log count = %d, want 1", len(entries))
			}
			logData, err := os.ReadFile(
				filepath.Join(root, ".atum", "logs", entries[0].Name()))
			if err != nil {
				t.Fatalf("read session log: %v", err)
			}
			assertNoDashboardCompletion(t, string(logData))
		})
	}
}

func dashboardTestCompletion(t *testing.T) tui.Completion {
	t.Helper()
	completion, err := tui.NewCompletion(tui.CompletionSpec{
		ResolverPath: "/resolver", CAPath: "/ca",
		CAFingerprint: strings.Repeat("a", 64),
		PublicVIP:     "10.77.0.20", PassthroughVIP: "10.77.0.21",
		SSOIssuer:        "https://keycloak.atum.test/auth/realms/master",
		AdministratorURL: "https://keycloak.atum.test/auth/admin/master/console/",
		Username:         "atum", Password: "dashboard-secret",
		BrowserGroups: []tui.CompletionGroup{{
			Name: "Identity services",
			Endpoints: []tui.CompletionEndpoint{{
				Name: "Keycloak", URL: "https://keycloak.atum.test",
			}},
		}},
		ProtocolEndpoints: []tui.CompletionEndpoint{{
			Name: "GitLab registry", URL: "https://registry.atum.test",
		}},
	})
	if err != nil {
		t.Fatalf("construct dashboard completion: %v", err)
	}
	return completion
}

func assertNoDashboardCompletion(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{
		"dashboard-secret", "https://keycloak.atum.test", "https://registry.atum.test",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("canceled dashboard disclosed %q in %q", secret, text)
		}
	}
}
