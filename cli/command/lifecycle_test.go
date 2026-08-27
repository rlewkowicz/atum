package command

import (
	"bytes"
	"context"
	"errors"
	"io"
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
		{name: "end of input", input: "yes"},
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
			confirmed, err := confirmDestroy(
				strings.NewReader(test.input),
				&output,
				destroyConfirmationPrompt,
			)
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

func TestDestroyCancellationStopsBeforeMutation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "end of input"},
		{name: "explicit rejection", input: "no\n"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			mutations := 0
			application := &app{
				in:  strings.NewReader(test.input),
				out: &output,
			}
			command := application.destroyCommandWithMutation(
				func(context.Context, []string) error {
					mutations++
					return nil
				},
			)
			command.SetArgs([]string{})
			command.SilenceErrors = true
			command.SilenceUsage = true

			err := command.Execute()
			if !errors.Is(err, errDestroyCancelled) {
				t.Fatalf("execute error = %v, want %v", err, errDestroyCancelled)
			}
			if mutations != 0 {
				t.Fatalf("lifecycle mutations = %d, want 0", mutations)
			}
			wantOutput := destroyConfirmationPrompt + "Destroy cancelled.\n"
			if output.String() != wantOutput {
				t.Fatalf("output = %q, want %q", output.String(), wantOutput)
			}
		})
	}
}

func TestDestroyCancellationPreservesOutputError(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("cancellation output unavailable")
	output := &failOnWrite{
		remaining: 1,
		err:       writeErr,
	}
	mutations := 0
	application := &app{
		in:  strings.NewReader("no\n"),
		out: output,
	}
	command := application.destroyCommandWithMutation(func(context.Context, []string) error {
		mutations++
		return nil
	})
	command.SetArgs([]string{})
	command.SilenceErrors = true
	command.SilenceUsage = true

	err := command.Execute()
	if !errors.Is(err, writeErr) {
		t.Fatalf("execute error = %v, want write error %v", err, writeErr)
	}
	if mutations != 0 {
		t.Fatalf("lifecycle mutations = %d, want 0", mutations)
	}
}

func TestDestroyForceBypassesOnlyConfirmation(t *testing.T) {
	t.Parallel()

	mutationErr := errors.New("lifecycle mutation failed")
	mutations := 0
	application := &app{
		in:  errReader{err: errors.New("confirmation input must not be read")},
		out: io.Discard,
	}
	command := application.destroyCommandWithMutation(func(context.Context, []string) error {
		mutations++
		return mutationErr
	})
	command.SetArgs([]string{"--force"})
	command.SilenceErrors = true
	command.SilenceUsage = true

	if err := command.Execute(); !errors.Is(err, mutationErr) {
		t.Fatalf("execute error = %v, want lifecycle error %v", err, mutationErr)
	}
	if mutations != 1 {
		t.Fatalf("lifecycle mutations = %d, want 1", mutations)
	}
}

func TestDestroyKeepBastionForwardsExactTerraformTargets(t *testing.T) {
	t.Parallel()

	var terraformArgs []string
	application := &app{
		in:  errReader{err: errors.New("confirmation input must not be read")},
		out: io.Discard,
	}
	command := application.destroyCommandWithMutation(
		func(_ context.Context, args []string) error {
			terraformArgs = args
			return nil
		},
	)
	command.SetArgs([]string{"--force", "--keep-bastion"})
	command.SilenceErrors = true
	command.SilenceUsage = true

	if err := command.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	want := []string{
		"-target=libvirt_cloudinit_disk.load_balancer",
		"-target=libvirt_cloudinit_disk.node",
		"-target=libvirt_domain.load_balancer",
		"-target=libvirt_domain.node",
		"-target=libvirt_volume.load_balancer",
		"-target=libvirt_volume.node",
	}
	if strings.Join(terraformArgs, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Terraform arguments = %#v, want %#v", terraformArgs, want)
	}
}

func TestDestroyKeepBastionUsesScopedConfirmation(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	application := &app{
		in:  strings.NewReader("no\n"),
		out: &output,
	}
	command := application.destroyCommandWithMutation(
		func(context.Context, []string) error {
			t.Fatal("destroy mutation ran after cancellation")
			return nil
		},
	)
	command.SetArgs([]string{"--keep-bastion"})
	command.SilenceErrors = true
	command.SilenceUsage = true

	if err := command.Execute(); !errors.Is(err, errDestroyCancelled) {
		t.Fatalf("execute error = %v, want %v", err, errDestroyCancelled)
	}
	want := destroyKeepBastionConfirmationPrompt + "Destroy cancelled.\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestLifecycleCommandsAreTopLevelAndDestroyFlagsAreExposed(t *testing.T) {
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
	if keepBastion := destroy.Flags().Lookup("keep-bastion"); keepBastion == nil {
		t.Fatal("destroy --keep-bastion flag is absent")
	}
	uninstall, _, err := root.Find([]string{"uninstall"})
	if err != nil {
		t.Fatalf("find uninstall: %v", err)
	}
	if uninstall.Parent() != root {
		t.Fatal("uninstall command is not top-level")
	}
}

type failOnWrite struct {
	remaining int
	err       error
}

func (writer *failOnWrite) Write(payload []byte) (int, error) {
	if writer.remaining == 0 {
		return 0, writer.err
	}
	writer.remaining--
	return len(payload), nil
}

type errReader struct {
	err error
}

func (reader errReader) Read([]byte) (int, error) {
	return 0, reader.err
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
	deploy, _, err := root.Find([]string{"deploy"})
	if err != nil {
		t.Fatalf("find deploy alias: %v", err)
	}
	if deploy != apply {
		t.Fatal("deploy must resolve to the canonical apply command")
	}
}

func TestArtifactsPublishExposesOnlyCanonicalPublicationControls(t *testing.T) {
	t.Parallel()

	root := New(Options{})
	publish, _, err := root.Find([]string{"artifacts", "publish"})
	if err != nil {
		t.Fatalf("find artifacts publish: %v", err)
	}
	for _, name := range []string{"profile", "group", "targets", "force"} {
		if flag := publish.Flags().Lookup(name); flag != nil {
			t.Errorf("artifacts publish unexpectedly exposes --%s", name)
		}
	}
	for _, name := range []string{"parallelism", "timeout"} {
		if flag := publish.Flags().Lookup(name); flag == nil {
			t.Errorf("artifacts publish omits --%s", name)
		}
	}
	if command, _, err := root.Find([]string{"images", "publish"}); err == nil && command.Name() == "images" {
		t.Fatal("stale images publish command remains available")
	}
}
