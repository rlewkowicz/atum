package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"atum/cli/config"
	"atum/cli/process"
	atumsecrets "atum/cli/secrets"
)

type serviceRunnerFunc func(context.Context, process.Command) error

func (run serviceRunnerFunc) Run(ctx context.Context, command process.Command) error {
	return run(ctx, command)
}

func TestCredentialsUseInjectedExactSOPSAdapter(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	project := &config.Project{
		Root: root,
		Desired: config.Document{Secrets: config.Secrets{
			SOPSFile: "secrets/atum.sops.yaml", LocalFile: ".atum/secrets.local.json",
		}},
	}
	expected, _, err := atumsecrets.LoadOrCreateLocal(
		t.Context(),
		project,
		atumsecrets.SOPSAdapter{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, project.Desired.Secrets.LocalFile)); err != nil {
		t.Fatal(err)
	}
	defer expected.Clear()
	ciphertext := []byte("encrypted SOPS document")
	path := filepath.Join(root, project.Desired.Secrets.SOPSFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	const selected = "/opt/atum/tools/sops"
	adapter, err := atumsecrets.NewSOPSAdapter(
		selected,
		serviceRunnerFunc(func(_ context.Context, command process.Command) error {
			if command.Name != selected {
				t.Fatalf("SOPS command = %q, want %q", command.Name, selected)
			}
			input, err := io.ReadAll(command.Stdin)
			if err != nil {
				return err
			}
			if !bytes.Equal(input, ciphertext) {
				t.Fatalf("SOPS stdin = %q", input)
			}
			_, err = command.Stdout.Write(plaintext)
			return err
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	service := Service{Project: project, DryRun: true, SOPS: adapter}
	actual, err := service.credentials(t.Context())
	if err != nil {
		t.Fatalf("load platform credentials: %v", err)
	}
	defer actual.Clear()
	if err := actual.Validate(); err != nil {
		t.Fatalf("validate platform credentials: %v", err)
	}
}
