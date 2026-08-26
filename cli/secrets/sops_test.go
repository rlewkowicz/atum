package secrets

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"atum/cli/process"
)

type sopsRunnerFunc func(context.Context, process.Command) error

func (run sopsRunnerFunc) Run(ctx context.Context, command process.Command) error {
	return run(ctx, command)
}

func TestSOPSAdapterUsesBoundedPrivateStdin(t *testing.T) {
	t.Parallel()
	const plaintext = `{"secret":"never-an-argument"}`
	var observed process.Command
	adapter := SOPSAdapter{
		binary: "/usr/bin/sops",
		runner: sopsRunnerFunc(func(_ context.Context, command process.Command) error {
			observed = command
			input, err := io.ReadAll(command.Stdin)
			if err != nil {
				return err
			}
			if string(input) != plaintext {
				t.Fatalf("SOPS stdin = %q", input)
			}
			_, err = command.Stdout.Write([]byte("ciphertext"))
			return err
		}),
	}
	output, err := adapter.run(t.Context(), []string{"--encrypt", "/dev/stdin"}, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output)
	if string(output) != "ciphertext" {
		t.Fatalf("SOPS output = %q", output)
	}
	if observed.Name != adapter.binary || observed.Stderr != io.Discard {
		t.Fatalf("SOPS command = %#v", observed)
	}
	for _, argument := range observed.Args {
		if strings.Contains(argument, "never-an-argument") {
			t.Fatal("plaintext appeared in SOPS arguments")
		}
	}
}

func TestSOPSAdapterHonorsCallerCancellation(t *testing.T) {
	t.Parallel()
	adapter := SOPSAdapter{
		binary: "/usr/bin/sops",
		runner: sopsRunnerFunc(func(ctx context.Context, _ process.Command) error {
			<-ctx.Done()
			return ctx.Err()
		}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := adapter.run(ctx, []string{"--decrypt", "/dev/stdin"}, []byte("ciphertext")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled SOPS error = %v, want context.Canceled", err)
	}
}

func TestSOPSAdapterRejectsBoundOverflow(t *testing.T) {
	t.Parallel()
	adapter := SOPSAdapter{
		binary: "/usr/bin/sops",
		runner: sopsRunnerFunc(func(_ context.Context, command process.Command) error {
			block := make([]byte, fileLimit+1)
			defer clear(block)
			_, err := command.Stdout.Write(block)
			return err
		}),
	}
	if _, err := adapter.run(
		t.Context(),
		[]string{"--decrypt", "/dev/stdin"},
		[]byte("ciphertext"),
	); err == nil || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("overflowing SOPS output error = %v", err)
	}
}

func TestSOPSAdapterClearsCapturedOutputOnFailure(t *testing.T) {
	t.Parallel()

	var captured *boundedBuffer
	adapter := SOPSAdapter{
		binary: "/usr/bin/sops",
		runner: sopsRunnerFunc(func(_ context.Context, command process.Command) error {
			captured = command.Stdout.(*boundedBuffer)
			_, _ = command.Stdout.Write([]byte("sensitive diagnostic payload"))
			return errors.New("SOPS failed")
		}),
	}
	if _, err := adapter.run(
		t.Context(),
		[]string{"--decrypt", "/dev/stdin"},
		[]byte("ciphertext"),
	); err == nil {
		t.Fatal("failed SOPS command was accepted")
	}
	if captured == nil {
		t.Fatal("SOPS output buffer was not observed")
	}
	if captured.buffer.Len() != 0 || captured.overflow {
		t.Fatal("SOPS output buffer retained bytes after failure")
	}
}

func TestNewSOPSAdapterRequiresExactAbsoluteSelection(t *testing.T) {
	t.Parallel()

	runner := sopsRunnerFunc(func(context.Context, process.Command) error { return nil })
	for _, invalid := range []string{"", "sops", "/usr/bin/../bin/sops"} {
		if _, err := NewSOPSAdapter(invalid, runner); err == nil {
			t.Errorf("invalid SOPS selection %q was accepted", invalid)
		}
	}
	if _, err := NewSOPSAdapter("/usr/bin/sops", nil); err == nil {
		t.Fatal("nil SOPS runner was accepted")
	}
	adapter, err := NewSOPSAdapter("/opt/atum/tools/sops", runner)
	if err != nil {
		t.Fatalf("construct exact SOPS adapter: %v", err)
	}
	if adapter.binary != "/opt/atum/tools/sops" {
		t.Fatalf("adapter binary = %q", adapter.binary)
	}
}

func TestNormalizeRecipientsRejectsArgumentSeparators(t *testing.T) {
	t.Parallel()
	if _, err := normalizeRecipients([]string{"age1valid,age1second"}); err == nil {
		t.Fatal("comma-separated recipient input was accepted")
	}
	got, err := normalizeRecipients([]string{" age1example ", "age1example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "age1example" {
		t.Fatalf("normalized recipients = %#v", got)
	}
}
