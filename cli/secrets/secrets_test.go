package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/progress"
)

func TestLoadOrCreateLocalRejectsUnsupportedSchemaWithoutMutation(t *testing.T) {
	project := testProject(t)
	data := []byte(`{
  "schemaVersion": "atum.dev/secrets/v2",
  "forgejo": {"username":"old_admin","adminPassword":"123456789012345678901234"},
  "harbor": {"adminPassword":"abcdefghijklmnopqrstuvwx","secretKey":"0123456789abcdef"}
}
`)
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{}); err == nil {
		t.Fatal("unsupported schema was accepted")
	} else if created {
		t.Fatal("unsupported schema was replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(data) {
		t.Fatal("unsupported schema document changed")
	}
}

func TestLoadOrCreateLocal(t *testing.T) {
	project := testProject(t)

	document, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("missing local secrets were not created")
	}
	defer document.Clear()
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

	reloaded, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing local secrets were replaced")
	}
	defer reloaded.Clear()
	if !reflect.DeepEqual(reloaded, document) {
		t.Fatal("reloaded local secrets differ from the generated document")
	}
}

func TestLoadOrCreateLocalCancellationLeavesValidFileUntouched(t *testing.T) {
	project := testProject(t)
	document, _, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	document.Clear()
	path := filepath.Join(project.Root, project.Desired.Secrets.LocalFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)

	unlock, err := fssecure.LockContext(
		t.Context(), project.Root, localSecretsLock, 25*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := LoadOrCreateLocal(ctx, project, SOPSAdapter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled load error = %v, want context.Canceled", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(after, before) {
		t.Fatal("canceled local load changed the valid secrets file")
	}
}

func TestStatefulProjectionIsStableFormattedAndClearable(t *testing.T) {
	t.Parallel()
	document, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	first, err := document.DeriveStatefulProjection()
	if err != nil {
		t.Fatal(err)
	}
	second, err := document.DeriveStatefulProjection()
	if err != nil {
		t.Fatal(err)
	}
	firstData, err := first.MarshalAnsibleJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := second.MarshalAnsibleJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(firstData) != string(secondData) {
		t.Fatal("unchanged stateful seed produced a different projection")
	}
	if value := string(first.values[statefulGarageAccessKeyIDKey]); len(value) != 26 || value[:2] != "GK" {
		t.Fatalf("Garage access key ID = %q", value)
	}
	for _, key := range []string{
		statefulGarageAdminTokenKey, statefulGarageSecretKeyKey, statefulDigestKey,
	} {
		if len(first.values[key]) != 64 {
			t.Fatalf("%s length = %d", key, len(first.values[key]))
		}
	}
	for _, key := range []string{
		statefulGitLabSecretKeyBaseKey,
		statefulGitLabOTPKeyBaseKey,
		statefulGitLabDBKeyBaseKey,
		statefulGitLabEncryptedSettingsKeyBaseKey,
	} {
		if len(first.values[key]) != 128 {
			t.Fatalf("%s length = %d", key, len(first.values[key]))
		}
	}
	for _, key := range []string{
		statefulGitLabActiveRecordPrimaryKey,
		statefulGitLabActiveRecordDeterministicKey,
		statefulGitLabActiveRecordSaltKey,
	} {
		if len(first.values[key]) != 32 {
			t.Fatalf("%s length = %d", key, len(first.values[key]))
		}
	}
	clear(firstData)
	clear(secondData)
	first.Clear()
	second.Clear()
	if len(first.values) != 0 || len(first.digest) != 0 {
		t.Fatal("stateful projection retained cleartext after Clear")
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

	if _, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{}); err == nil {
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

	if _, created, err := LoadOrCreateLocal(t.Context(), project, SOPSAdapter{}); err == nil {
		t.Fatal("invalid SOPS secrets were accepted")
	} else if created {
		t.Fatal("invalid SOPS secrets were masked by local credentials")
	}
	if _, err := os.Stat(filepath.Join(project.Root, project.Desired.Secrets.LocalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local secrets stat error is %v, want os.ErrNotExist", err)
	}
}

func TestLoadReportsNotFound(t *testing.T) {
	if _, err := Load(t.Context(), testProject(t), SOPSAdapter{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error is %v, want ErrNotFound", err)
	}
}

func TestLocalInitDoesNotRequireSOPS(t *testing.T) {
	project := testProject(t)
	path, err := Init(
		t.Context(),
		project,
		SOPSAdapter{},
		InitOptions{Local: true},
	)
	if err != nil {
		t.Fatalf("initialize local secrets without SOPS: %v", err)
	}
	if path != project.Desired.Secrets.LocalFile {
		t.Fatalf("local secrets path = %q, want %q", path, project.Desired.Secrets.LocalFile)
	}
	document, err := Load(t.Context(), project, SOPSAdapter{})
	if err != nil {
		t.Fatalf("load local-only secrets without SOPS: %v", err)
	}
	defer document.Clear()
	if err := document.Validate(); err != nil {
		t.Fatalf("validate local-only secrets: %v", err)
	}
}

func TestEnsureReportsSavedPath(t *testing.T) {
	project := testProject(t)
	reporter := new(eventRecorder)
	ctx := progress.WithReporter(t.Context(), reporter)

	document, err := Ensure(ctx, project, SOPSAdapter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer document.Clear()
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
