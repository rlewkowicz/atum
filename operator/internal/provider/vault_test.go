package provider

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testVault(t *testing.T, handler http.Handler) *Vault {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	vault, err := NewVault(server.URL, certificate, "vault-test-token")
	if err != nil {
		server.Close()
		t.Fatalf("new Vault client: %v", err)
	}
	t.Cleanup(func() {
		vault.Close()
		server.Close()
	})
	return vault
}

func TestVaultRejectsUnownedMountWithoutMutation(t *testing.T) {
	mutated := false
	vault := testVault(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != "vault-test-token" ||
			request.Header.Get("Authorization") != "" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.Method != http.MethodGet {
			mutated = true
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"data":{"oidc/":{"accessor":"auth_oidc","description":"another owner"}}}`))
	}))
	_, err := vault.ensureMount(context.Background(), "oidc")
	if err == nil || !IsTerminal(err) || !strings.Contains(err.Error(), "without") {
		t.Fatalf("ownership error = %v", err)
	}
	if mutated {
		t.Fatal("unowned mount was mutated")
	}
}

func TestVaultCleanupCompletesAfterScopedCollisionRepair(t *testing.T) {
	repaired := false
	authReads := 0
	deleted := make(map[string]bool)
	vault := testVault(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != "vault-test-token" ||
			request.Header.Get("Authorization") != "" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/sys/auth":
			authReads++
			description := vaultMountDescription
			if !repaired && authReads == 2 {
				description = "another owner"
			}
			_, _ = response.Write([]byte(`{"data":{"oidc/":{"accessor":"auth_oidc","description":"` +
				description + `"},"ldap/":{"accessor":"auth_ldap","description":"another owner"}}}`))
		case request.Method == http.MethodGet && request.URL.Query().Get("list") == "true":
			_, _ = response.Write([]byte(`{"data":{"keys":[]}}`))
		case request.Method == http.MethodDelete:
			deleted[request.URL.Path] = true
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	err := vault.Cleanup(context.Background())
	if err == nil || !IsTerminal(err) {
		t.Fatalf("cleanup collision = %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("collision mutated provider state: %v", deleted)
	}
	repaired = true
	if err := vault.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup after external repair: %v", err)
	}
	if !deleted["/v1/sys/auth/oidc"] {
		t.Fatal("marked OIDC mount was not retired")
	}
	if deleted["/v1/sys/auth/ldap"] {
		t.Fatal("unowned LDAP mount was retired")
	}
}
