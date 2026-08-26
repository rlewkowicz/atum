package provider

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	return testClientWithAuthentication(t, keycloakBearer("token"), handler)
}

func testClientWithAuthentication(t *testing.T, auth authentication, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := newClient(server.URL, auth, certificate)
	if err != nil {
		server.Close()
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() {
		client.CloseIdleConnections()
		server.Close()
	})
	return client, server
}

func TestClosedAuthenticationHeaders(t *testing.T) {
	bearer, _ := testClientWithAuthentication(t, keycloakBearer("keycloak-token"), http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer keycloak-token" ||
			request.Header.Get("X-Vault-Token") != "" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	if err := bearer.JSON(context.Background(), http.MethodGet, "/admin", nil, nil); err != nil {
		t.Fatalf("Keycloak bearer request: %v", err)
	}

	anonymousClient, _ := testClientWithAuthentication(t, anonymous(), http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.Header.Get("X-Vault-Token") != "" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = response.Write([]byte(`{"access_token":"token"}`))
	}))
	var token keycloakToken
	if err := anonymousClient.Form(context.Background(), "/token", nil, &token); err != nil {
		t.Fatalf("anonymous form grant: %v", err)
	}

	const vaultSecret = "vault-diagnostic-secret"
	vaultClient, _ := testClientWithAuthentication(t, vaultToken(vaultSecret), http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Error(response, vaultSecret, http.StatusForbidden)
	}))
	err := vaultClient.JSON(context.Background(), http.MethodGet, "/v1/sys/auth", nil, nil)
	if err == nil || strings.Contains(err.Error(), vaultSecret) {
		t.Fatalf("Vault token leaked through diagnostics: %v", err)
	}
}

func TestClientBoundsAndSanitizesResponses(t *testing.T) {
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/large" {
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
			return
		}
		if request.URL.Path == "/form" {
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte(strings.Repeat("x", maxResponseBytes+1)))
			return
		}
		http.Error(response, "provider-secret-value", http.StatusUnauthorized)
	}))
	err := client.JSON(context.Background(), http.MethodGet, "/large", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("large response error = %v", err)
	}
	err = client.JSON(context.Background(), http.MethodGet, "/error", nil, nil)
	if err == nil || strings.Contains(err.Error(), "provider-secret-value") {
		t.Fatalf("unsanitized provider error = %v", err)
	}
	err = client.Form(context.Background(), "/form", nil, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("large form response error = %v", err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	followed := false
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/target" {
			followed = true
		}
		http.Redirect(response, request, "/target", http.StatusFound)
	}))
	err := client.JSON(context.Background(), http.MethodGet, "/source", nil, nil)
	if err == nil || followed {
		t.Fatalf("redirect error = %v, followed = %t", err, followed)
	}
}

func TestClosedProviderVocabulary(t *testing.T) {
	if got := CredentialKey("atum-vault"); got != "ATUM_VAULT_CLIENT_SECRET" {
		t.Fatalf("credential key = %q", got)
	}
	body, err := policyBody("PlatformAdministration")
	if err != nil || !strings.HasPrefix(body, vaultPolicyMarker) {
		t.Fatalf("policy body = %q, error = %v", body, err)
	}
	if _, err := policyBody("Arbitrary"); err == nil {
		t.Fatal("arbitrary policy purpose was accepted")
	}
}
