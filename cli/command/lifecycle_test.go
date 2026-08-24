package command

import (
	"bytes"
	"strings"
	"testing"

	"atum/cli/platform"
)

func TestConfirmDestroyRequiresExactYes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		input     string
		confirmed bool
	}{
		{name: "line", input: "yes\n", confirmed: true},
		{name: "end of input", input: "yes", confirmed: true},
		{name: "CRLF", input: "yes\r\n", confirmed: true},
		{name: "uppercase", input: "YES\n"},
		{name: "leading whitespace", input: " yes\n"},
		{name: "trailing whitespace", input: "yes \n"},
		{name: "different answer", input: "no\n"},
		{name: "prefix", input: "yesplease\n"},
		{name: "over limit", input: strings.Repeat("y", destroyConfirmationLimit+1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			confirmed, err := confirmDestroy(strings.NewReader(test.input), &output)
			if err != nil {
				t.Fatalf("confirm destroy: %v", err)
			}
			if confirmed != test.confirmed {
				t.Fatalf("confirmed = %t, want %t", confirmed, test.confirmed)
			}
			if output.String() != destroyConfirmationPrompt {
				t.Fatalf("prompt = %q, want %q", output.String(), destroyConfirmationPrompt)
			}
		})
	}
}

func TestLifecycleCommandsAreTopLevelAndForceIsShorthand(t *testing.T) {
	t.Parallel()

	root := New(Options{})
	destroy, _, err := root.Find([]string{"destroy"})
	if err != nil {
		t.Fatalf("find destroy: %v", err)
	}
	if destroy.Parent() != root {
		t.Fatal("destroy command is not top-level")
	}
	force := destroy.Flags().Lookup("force")
	if force == nil || force.Shorthand != "f" {
		t.Fatalf("destroy force flag = %#v, want -f shorthand", force)
	}
	uninstall, _, err := root.Find([]string{"uninstall"})
	if err != nil {
		t.Fatalf("find uninstall: %v", err)
	}
	if uninstall.Parent() != root {
		t.Fatal("uninstall command is not top-level")
	}
}

func TestApplyUsesPlatformReadinessBudget(t *testing.T) {
	t.Parallel()

	root := New(Options{})
	apply, _, err := root.Find([]string{"apply"})
	if err != nil {
		t.Fatalf("find apply: %v", err)
	}
	timeout, err := apply.Flags().GetDuration("timeout")
	if err != nil {
		t.Fatalf("read apply timeout: %v", err)
	}
	if timeout != platform.DefaultReadinessTimeout {
		t.Fatalf("apply timeout = %s, want %s", timeout, platform.DefaultReadinessTimeout)
	}
}
