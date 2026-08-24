package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCanonicalContract(t *testing.T) {
	root := repositoryRoot(t)
	contract, err := Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if contract.Realm() != "master" || contract.Domain() != "atum.test" {
		t.Fatalf("unexpected realm/domain %q/%q", contract.Realm(), contract.Domain())
	}
	if contract.GroupClaim() != "groups" || len(contract.Scopes()) != 4 ||
		len(contract.AdditionalEndpoints()) != 3 {
		t.Fatal("contract scopes, group claim, or additional endpoint projection is incomplete")
	}
	clients := contract.Clients()
	if len(clients) != 10 {
		t.Fatalf("client count = %d, want 10", len(clients))
	}
	clients[0].Callbacks[0] = "mutated"
	headlamp, ok := contract.Client("atum-headlamp")
	if !ok || headlamp.Callbacks[0] == "mutated" || headlamp.Type != PublicPKCE {
		t.Fatal("contract did not return an immutable client projection")
	}
}

func TestLoadRejectsDuplicateAndUnknownContractState(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "contract.yaml")
	source := `schemaVersion: atum.dev/identity/v1
realm: master
issuer: https://keycloak.atum.test/auth/realms/master
administrator: {username: atum, password: atum, group: atum-admins, serverRole: admin}
clients:
  - id: atum-one
    type: confidential
    host: one.atum.test
    category: development
    integration: unknown
    secretPurpose: shared
    callbacks: [https://one.atum.test/callback]
    administratorMapping: admin
`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, "contract.yaml"); err == nil || !strings.Contains(err.Error(), "unknown integration") {
		t.Fatalf("unknown integration error = %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
