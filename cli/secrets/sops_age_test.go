package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	filippoage "filippo.io/age"
)

func TestLoadOrCreateLocalMigratesSOPSV1WithPartialOverride(t *testing.T) {
	project := testProject(t)
	ageIdentity, err := filippoage.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(sopsAgeKeyEnvironment, ageIdentity.String())
	legacy := Document{
		SchemaVersion: schemaVersionV1,
		Forgejo: ForgejoSecrets{
			Username: "legacy_admin", AdminPassword: "123456789012345678901234",
		},
		Harbor: HarborSecrets{
			AdminPassword: "abcdefghijklmnopqrstuvwx", SecretKey: "0123456789abcdef",
		},
	}
	encrypted, err := encryptDocument(legacy, []string{ageIdentity.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	sopsPath := filepath.Join(project.Root, project.Desired.Secrets.SOPSFile)
	if err := os.MkdirAll(filepath.Dir(sopsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sopsPath, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), encrypted...)
	clear(encrypted)

	document, created, err := LoadOrCreateLocal(project)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("SOPS migration was reported as fresh credential creation")
	}
	if document.Forgejo != legacy.Forgejo || document.Harbor != legacy.Harbor {
		t.Fatal("SOPS v1 credentials changed during migration")
	}
	after, err := os.ReadFile(sopsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("SOPS v1 document was rewritten")
	}
	reloaded, err := Load(project)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != document {
		t.Fatal("SOPS v1 plus local v2 seed did not load canonically")
	}
	clear(after)
	clear(original)
}
