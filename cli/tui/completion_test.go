package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestCompletionCopiesAndValidatesInputs(t *testing.T) {
	t.Parallel()

	spec := testCompletionSpec()
	completion, err := NewCompletion(spec)
	if err != nil {
		t.Fatalf("construct completion: %v", err)
	}
	spec.BrowserGroups[0].Endpoints[0].URL = "https://changed.invalid"
	spec.ProtocolEndpoints[0].Name = "changed"
	text := renderCompletionText(completion)
	if strings.Contains(text, "changed") ||
		!strings.Contains(text, "https://keycloak.atum.test") {
		t.Fatalf("completion retained mutable input: %s", text)
	}

	invalid := testCompletionSpec()
	invalid.Password = ""
	if _, err := NewCompletion(invalid); err == nil {
		t.Fatal("completion without password was accepted")
	}
}

func TestCompletionInteractiveWidthsAndFullText(t *testing.T) {
	t.Parallel()

	completion, err := NewCompletion(testCompletionSpec())
	if err != nil {
		t.Fatalf("construct completion: %v", err)
	}
	for _, width := range []int{40, 76, 112} {
		rendered := renderCompletion(completion, width)
		if !strings.Contains(rendered, "Access") ||
			!strings.Contains(rendered, "Applications") {
			t.Fatalf("width %d completion omitted sections:\n%s", width, rendered)
		}
		for _, line := range strings.Split(rendered, "\n") {
			if got := ansi.StringWidth(line); got > width {
				t.Fatalf("width %d rendered %d-cell line %q", width, got, line)
			}
		}
	}
	text := renderCompletionText(completion)
	for _, exact := range []string{
		"https://keycloak.atum.test/auth/realms/master",
		"https://unknown.atum.test/a/complete/path",
		"https://registry.atum.test",
	} {
		if !strings.Contains(text, exact) {
			t.Errorf("full completion text omits %q:\n%s", exact, text)
		}
	}
}

func testCompletionSpec() CompletionSpec {
	return CompletionSpec{
		ResolverPath:  "/etc/systemd/resolved.conf.d/atum-test.conf",
		CAPath:        "/etc/pki/ca-trust/source/anchors/atum-test-root-ca.crt",
		CAFingerprint: strings.Repeat("a", 64),
		PublicVIP:     "10.77.0.20", PassthroughVIP: "10.77.0.21",
		SSOIssuer:        "https://keycloak.atum.test/auth/realms/master",
		AdministratorURL: "https://keycloak.atum.test/auth/admin/master/console/",
		Username:         "atum", Password: "atum",
		BrowserGroups: []CompletionGroup{
			{Name: "Identity services", Endpoints: []CompletionEndpoint{
				{Name: "Keycloak", URL: "https://keycloak.atum.test"},
			}},
			{Name: "Development services", Endpoints: []CompletionEndpoint{
				{Name: "Headlamp", URL: "https://headlamp.atum.test"},
			}},
			{Name: "Observability services", Endpoints: []CompletionEndpoint{
				{Name: "Grafana", URL: "https://grafana.atum.test"},
			}},
		},
		ProtocolEndpoints: []CompletionEndpoint{
			{Name: "GitLab registry", URL: "https://registry.atum.test"},
		},
		UncategorizedWebApps: []CompletionEndpoint{
			{Name: "unknown.atum.test", URL: "https://unknown.atum.test/a/complete/path"},
		},
	}
}
