package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"atum/cli/config"
	"atum/cli/progress"
)

func TestLoadOrCreateLocalMigratesCompleteV1(t *testing.T) {
	project := testProject(t)
	legacy := struct {
		SchemaVersion string         `json:"schemaVersion"`
		Forgejo       ForgejoSecrets `json:"forgejo"`
		Harbor        HarborSecrets  `json:"harbor"`
	}{
		SchemaVersion: schemaVersionV1,
		Forgejo: ForgejoSecrets{
			Username: "legacy_admin", AdminPassword: "123456789012345678901234",
		},
		Harbor: HarborSecrets{
			AdminPassword: "abcdefghijklmnopqrstuvwx", SecretKey: "0123456789abcdef",
		},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(project); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("read-only load error = %v, want migration requirement", err)
	}
	document, created, err := LoadOrCreateLocal(project)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("migration was reported as fresh credential creation")
	}
	if document.Forgejo != legacy.Forgejo || document.Harbor != legacy.Harbor {
		t.Fatal("v1 credentials changed during migration")
	}
	seed, err := base64.RawStdEncoding.DecodeString(document.Identity.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatalf("migrated seed is invalid: length %d, error %v", len(seed), err)
	}
	clear(seed)
	reloaded, err := Load(project)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != document {
		t.Fatal("migrated document was not stable")
	}
}

func TestLoadOrCreateLocalSerializesV1Migration(t *testing.T) {
	project := testProject(t)
	legacy := []byte(`{
  "schemaVersion": "atum.dev/secrets/v1",
  "forgejo": {"username":"legacy_admin","adminPassword":"123456789012345678901234"},
  "harbor": {"adminPassword":"abcdefghijklmnopqrstuvwx","secretKey":"0123456789abcdef"}
}
`)
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	results := make([]Document, 8)
	errs := make([]error, len(results))
	var group sync.WaitGroup
	group.Add(len(results))
	for index := range results {
		go func() {
			defer group.Done()
			results[index], _, errs[index] = LoadOrCreateLocal(project)
		}()
	}
	group.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("migration %d failed: %v", index, err)
		}
		if results[index] != results[0] {
			t.Fatalf("migration %d observed a different canonical document", index)
		}
	}
}

func TestLoadOrCreateLocal(t *testing.T) {
	project := testProject(t)

	document, created, err := LoadOrCreateLocal(project)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("missing local secrets were not created")
	}
	if err := document.Validate(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("local secrets mode is %04o, want 0600", mode)
	}

	reloaded, created, err := LoadOrCreateLocal(project)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing local secrets were replaced")
	}
	if reloaded != document {
		t.Fatal("reloaded local secrets differ from the generated document")
	}
}

func TestLoadOrCreateLocalPreservesInvalidFile(t *testing.T) {
	project := testProject(t)
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const invalid = "{not-json}\n"
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, created, err := LoadOrCreateLocal(project); err == nil {
		t.Fatal("invalid local secrets were accepted")
	} else if created {
		t.Fatal("invalid local secrets were replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != invalid {
		t.Fatal("invalid local secrets changed")
	}
}

func TestLoadOrCreateLocalDoesNotMaskInvalidSOPS(t *testing.T) {
	project := testProject(t)
	path := filepath.Join(project.Root, project.Desired.Secrets.SOPSFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not: sops\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, created, err := LoadOrCreateLocal(project); err == nil {
		t.Fatal("invalid SOPS secrets were accepted")
	} else if created {
		t.Fatal("invalid SOPS secrets were masked by local credentials")
	}
	if _, err := os.Stat(filepath.Join(project.Root, project.Desired.Secrets.LocalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local secrets stat error is %v, want os.ErrNotExist", err)
	}
}

func TestLoadReportsNotFound(t *testing.T) {
	if _, err := Load(testProject(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error is %v, want ErrNotFound", err)
	}
}

func TestEnsureReportsSavedPath(t *testing.T) {
	project := testProject(t)
	reporter := new(eventRecorder)
	ctx := progress.WithReporter(context.Background(), reporter)

	if _, err := Ensure(ctx, project, nil); err != nil {
		t.Fatal(err)
	}
	if len(*reporter) != 2 {
		t.Fatalf("Ensure() reported %d events, want 2", len(*reporter))
	}
	event := (*reporter)[1]
	if event.Phase != progress.Credentials || event.ID != "secrets" || event.State != progress.Complete {
		t.Fatalf("Ensure() completion event is %#v", event)
	}
	const detail = "secrets saved to .atum/secrets.local.json (Git-ignored)"
	if event.Detail != detail {
		t.Fatalf("Ensure() detail is %q, want %q", event.Detail, detail)
	}
}

type eventRecorder []progress.Event

func (recorder *eventRecorder) Report(event progress.Event) {
	*recorder = append(*recorder, event)
}

func testProject(t *testing.T) *config.Project {
	t.Helper()
	return &config.Project{
		Root: t.TempDir(),
		Desired: config.Document{Secrets: config.Secrets{
			SOPSFile:  "secrets/atum.sops.yaml",
			LocalFile: ".atum/secrets.local.json",
		}},
	}
}
