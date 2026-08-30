package provider

import (
	platformv1alpha1 "atum/operator/api/v1alpha1"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"
)

func TestKeycloakClientBodyRequiresPKCEOnlyForPublicClients(t *testing.T) {
	t.Parallel()

	public, err := keycloakClientBody(platformv1alpha1.KeycloakClient{
		ID:   "atum-headlamp",
		Kind: platformv1alpha1.ClientPublicPKCE,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	publicAttributes := public["attributes"].(map[string]string)
	if publicAttributes["pkce.code.challenge.method"] != "S256" || public["publicClient"] != true {
		t.Fatalf("public client body = %#v", public)
	}
	if _, exists := public["secret"]; exists {
		t.Fatalf("public client has secret: %#v", public)
	}

	confidential, err := keycloakClientBody(platformv1alpha1.KeycloakClient{
		ID:   "atum-grafana",
		Kind: platformv1alpha1.ClientConfidential,
	}, map[string][]byte{CredentialKey("atum-grafana"): []byte("fixed-secret")})
	if err != nil {
		t.Fatal(err)
	}
	confidentialAttributes := confidential["attributes"].(map[string]string)
	if _, exists := confidentialAttributes["pkce.code.challenge.method"]; exists {
		t.Fatalf("confidential client requires PKCE: %#v", confidential)
	}
	if confidential["publicClient"] != false || confidential["secret"] != "fixed-secret" {
		t.Fatalf("confidential client body = %#v", confidential)
	}
}

func TestKeycloakCleanupRetainsUnownedBootstrapAdministrator(t *testing.T) {
	var lock sync.Mutex
	deleted := make(map[string]bool)
	profileCleaned := false
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/clients":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/groups":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/client-scopes":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/users":
			_ = json.NewEncoder(response).Encode([]keycloakObject{
				{ID: "bootstrap-id", Username: "atum-bootstrap"},
				{ID: "managed-id", Username: "managed", Attributes: map[string]any{
					ownerMarkerKey: []any{ownerMarkerValue},
				}},
			})
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/users/profile":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"attributes": []any{ownershipProfileAttribute()},
			})
		case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/master/users/profile":
			var profile map[string]any
			if err := json.NewDecoder(request.Body).Decode(&profile); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			attributes, err := profileAttributes(profile)
			if err != nil || len(attributes) != 0 {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			profileCleaned = true
			response.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete:
			lock.Lock()
			deleted[request.URL.Path] = true
			lock.Unlock()
			response.WriteHeader(http.StatusNoContent)
		default:
			http.Error(response, "unexpected request", http.StatusNotFound)
		}
	})
	client, _ := testClient(t, handler)
	keycloak := &Keycloak{client: client, realm: "master"}
	if err := keycloak.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deleted["/admin/realms/master/users/bootstrap-id"] {
		t.Fatal("unowned bootstrap administrator was deleted")
	}
	if !deleted["/admin/realms/master/users/managed-id"] {
		t.Fatal("marked administrator was not deleted")
	}
	if !profileCleaned {
		t.Fatal("managed user profile attribute was not removed")
	}
}

func TestKeycloakPaginatedPruneDeletesOnlyPageTwoMarkedClient(t *testing.T) {
	firstPage := make([]keycloakObject, keycloakPageSize)
	for index := range firstPage {
		firstPage[index] = keycloakObject{
			ID:       fmt.Sprintf("unowned-%03d", index),
			ClientID: fmt.Sprintf("peer-%03d", index),
		}
	}
	secondPage := []keycloakObject{
		{
			ID:         "marked-page-two",
			ClientID:   "removed",
			Attributes: map[string]any{ownerMarkerKey: ownerMarkerValue},
		},
		{ID: "unowned-page-two", ClientID: "unowned-peer"},
	}
	var queries []string
	var deletes []string
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			queries = append(queries, request.URL.RawQuery)
			switch request.URL.Query().Get("first") {
			case "0":
				_ = json.NewEncoder(response).Encode(firstPage)
			case "100":
				_ = json.NewEncoder(response).Encode(secondPage)
			default:
				response.WriteHeader(http.StatusBadRequest)
			}
		case http.MethodDelete:
			deletes = append(deletes, request.URL.Path)
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	if err := keycloak.pruneCollection(
		context.Background(), realmCollection(realmClients), "clientId", nil,
	); err != nil {
		t.Fatalf("prune clients: %v", err)
	}
	if !reflect.DeepEqual(queries, []string{"first=0&max=100", "first=100&max=100"}) {
		t.Fatalf("page queries = %v", queries)
	}
	if !reflect.DeepEqual(deletes, []string{"/admin/realms/master/clients/marked-page-two"}) {
		t.Fatalf("deleted clients = %v", deletes)
	}
}

func TestKeycloakFinalizerCleanupFindsPageTwoMarkedUser(t *testing.T) {
	firstUsers := make([]keycloakObject, keycloakPageSize)
	for index := range firstUsers {
		firstUsers[index] = keycloakObject{
			ID:       fmt.Sprintf("unowned-user-%03d", index),
			Username: fmt.Sprintf("peer-%03d", index),
		}
	}
	var userQueries []string
	var deletes []string
	profileCleaned := false
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/users":
			userQueries = append(userQueries, request.URL.RawQuery)
			if request.URL.Query().Get("first") == "0" {
				_ = json.NewEncoder(response).Encode(firstUsers)
			} else {
				_ = json.NewEncoder(response).Encode([]keycloakObject{
					{
						ID:         "marked-user",
						Username:   "removed",
						Attributes: map[string]any{ownerMarkerKey: ownerMarkerValue},
					},
					{ID: "unowned-user", Username: "unowned-peer"},
				})
			}
		case request.Method == http.MethodGet &&
			(request.URL.Path == "/admin/realms/master/clients" ||
				request.URL.Path == "/admin/realms/master/groups"):
			if request.URL.Query().Get("first") != "0" ||
				request.URL.Query().Get("max") != "100" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/client-scopes":
			if request.URL.RawQuery != "" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/admin/realms/master/users/profile":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"attributes": []any{ownershipProfileAttribute()},
			})
		case request.Method == http.MethodPut && request.URL.Path == "/admin/realms/master/users/profile":
			profileCleaned = true
			response.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete:
			deletes = append(deletes, request.URL.Path)
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	if err := keycloak.Cleanup(context.Background()); err != nil {
		t.Fatalf("finalizer cleanup: %v", err)
	}
	if !reflect.DeepEqual(userQueries, []string{
		"briefRepresentation=false&first=0&max=100",
		"briefRepresentation=false&first=100&max=100",
	}) {
		t.Fatalf("user page queries = %v", userQueries)
	}
	if !reflect.DeepEqual(deletes, []string{"/admin/realms/master/users/marked-user"}) {
		t.Fatalf("deleted objects = %v", deletes)
	}
	if !profileCleaned {
		t.Fatal("managed user profile attribute was not removed")
	}
}

func TestKeycloakReconcilesAdminOnlyOwnershipProfileAttribute(t *testing.T) {
	t.Parallel()

	profile := map[string]any{
		"attributes": []any{
			map[string]any{
				"name":        "username",
				"multivalued": false,
			},
		},
		"groups": []any{
			map[string]any{"name": "user-metadata"},
		},
		"futureField": "preserved",
	}
	puts := 0
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			if request.URL.Path != "/admin/realms/master/users/profile" {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(response).Encode(profile)
		case http.MethodPut:
			if request.URL.Path != "/admin/realms/master/users/profile" {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			var updated map[string]any
			if err := json.NewDecoder(request.Body).Decode(&updated); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			profile = updated
			puts++
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	for attempt := 0; attempt < 2; attempt++ {
		if err := keycloak.reconcileOwnershipProfileAttribute(context.Background()); err != nil {
			t.Fatalf("reconcile ownership profile attempt %d: %v", attempt+1, err)
		}
	}
	if puts != 1 {
		t.Fatalf("user profile PUTs = %d, want 1", puts)
	}
	if profile["futureField"] != "preserved" {
		t.Fatalf("future profile field = %#v", profile["futureField"])
	}
	attributes, err := profileAttributes(profile)
	if err != nil {
		t.Fatal(err)
	}
	index, exists, err := profileOwnershipAttribute(attributes)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || !profileOwnershipAttributeCurrent(attributes[index]) {
		t.Fatalf("ownership attribute = %#v", attributes)
	}
}

func TestKeycloakRejectsUnownedOwnershipProfileAttribute(t *testing.T) {
	t.Parallel()

	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{
			"attributes": []any{
				map[string]any{"name": ownerMarkerKey},
			},
		})
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	err := keycloak.reconcileOwnershipProfileAttribute(context.Background())
	if err == nil || !IsTerminal(err) {
		t.Fatalf("ownership conflict = %v", err)
	}
}

func TestKeycloakOwnershipListsRequestFullRepresentations(t *testing.T) {
	t.Parallel()

	queries := make(map[string]string)
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		queries[request.URL.Path] = request.URL.RawQuery
		_, _ = response.Write([]byte(`[]`))
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	if _, err := keycloak.list(context.Background(), realmCollection(realmUsers), "exact=true&username=atum"); err != nil {
		t.Fatal(err)
	}
	if _, err := keycloak.list(context.Background(), realmCollection(realmGroups), "exact=true&search=atum-admins"); err != nil {
		t.Fatal(err)
	}
	if query := queries["/admin/realms/master/users"]; query != "briefRepresentation=false&exact=true&first=0&max=100&username=atum" {
		t.Fatalf("user query = %q", query)
	}
	if query := queries["/admin/realms/master/groups"]; query != "briefRepresentation=false&exact=true&first=0&max=100&search=atum-admins" {
		t.Fatalf("group query = %q", query)
	}
}

func TestKeycloakCollectionTraversalRejectsUnsafeProgress(t *testing.T) {
	fullPage := make([]keycloakObject, keycloakPageSize)
	for index := range fullPage {
		fullPage[index] = keycloakObject{ID: fmt.Sprintf("id-%03d", index)}
	}
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(response).Encode(fullPage)
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	if _, err := keycloak.list(
		context.Background(), realmCollection(realmClients), "first=7",
	); err == nil {
		t.Fatal("caller-selected first offset was accepted")
	}
	if _, err := keycloak.list(
		context.Background(), keycloakCollection{kind: 255}, "",
	); err == nil {
		t.Fatal("unknown collection capability was accepted")
	}
	if _, err := keycloak.list(
		context.Background(), realmCollection(realmClients), "",
	); err == nil {
		t.Fatal("repeated full page was accepted")
	}
}

func TestKeycloakCollectionTraversalPreservesFixedFilters(t *testing.T) {
	var query string
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		query = request.URL.RawQuery
		_, _ = response.Write([]byte(`[]`))
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	if _, err := keycloak.list(
		context.Background(),
		realmCollection(realmClients),
		"clientId=realm-management",
	); err != nil {
		t.Fatalf("filtered client list: %v", err)
	}
	if query != "clientId=realm-management&first=0&max=100" {
		t.Fatalf("filtered page query = %q", query)
	}
}

func TestKeycloakGrantsAdministratorRoleBeforeEnablingCredential(t *testing.T) {
	t.Parallel()

	var operations []string
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet &&
			request.URL.Path == "/admin/realms/master/roles/admin":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"id":   "realm-admin-id",
				"name": "admin",
			})
		case request.Method == http.MethodPost &&
			request.URL.Path == "/admin/realms/master/users/administrator-id/role-mappings/realm":
			operations = append(operations, "role")
			response.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPut &&
			request.URL.Path == "/admin/realms/master/users/administrator-id/reset-password":
			operations = append(operations, "password")
			response.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", request.Method, request.URL.RequestURI())
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	if err := keycloak.reconcileAdministratorAuthority(
		context.Background(),
		"administrator-id",
		"admin",
		[]byte("fixed-password"),
	); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(operations, []string{"role", "password"}) {
		t.Fatalf("administrator authority operations = %v", operations)
	}
}

func TestKeycloakUpsertPreservesOwnedIdentity(t *testing.T) {
	t.Parallel()

	var writes []string
	client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			_ = json.NewEncoder(response).Encode([]keycloakObject{{
				ID:       "client-uuid",
				ClientID: "atum-headlamp",
				Attributes: map[string]any{
					ownerMarkerKey: ownerMarkerValue,
				},
			}})
		case http.MethodPut:
			writes = append(writes, request.URL.Path)
			response.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", request.Method)
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	keycloak := &Keycloak{client: client, realm: "master"}
	id, err := keycloak.upsert(
		context.Background(),
		realmCollection(realmClients),
		"clientId=atum-headlamp",
		"clientId",
		"atum-headlamp",
		map[string]any{
			"clientId": "atum-headlamp",
			"attributes": map[string]string{
				ownerMarkerKey: ownerMarkerValue,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if id != "client-uuid" ||
		!reflect.DeepEqual(writes, []string{"/admin/realms/master/clients/client-uuid"}) {
		t.Fatalf("upsert id/writes = %q/%v", id, writes)
	}
}

func TestAudienceMapperCreateAndUpdatePayloads(t *testing.T) {
	for _, test := range []struct {
		name       string
		existing   []keycloakObject
		wantMethod string
		wantPath   string
	}{
		{
			name:       "create",
			wantMethod: http.MethodPost,
			wantPath:   "/admin/realms/master/clients/client-uuid/protocol-mappers/models",
		},
		{
			name: "update",
			existing: []keycloakObject{{
				ID:     "mapper-uuid",
				Name:   "audience-atum-client",
				Config: map[string]any{ownerMarkerKey: ownerMarkerValue},
			}},
			wantMethod: http.MethodPut,
			wantPath:   "/admin/realms/master/clients/client-uuid/protocol-mappers/models/mapper-uuid",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			payloads := make(chan map[string]any, 1)
			client, _ := testClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodGet {
					if request.URL.RawQuery != "" {
						response.WriteHeader(http.StatusBadRequest)
						return
					}
					_ = json.NewEncoder(response).Encode(test.existing)
					return
				}
				if request.Method != test.wantMethod || request.URL.Path != test.wantPath {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				var payload map[string]any
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					response.WriteHeader(http.StatusBadRequest)
					return
				}
				payloads <- payload
				response.WriteHeader(http.StatusNoContent)
			}))
			keycloak := &Keycloak{client: client, realm: "master"}
			if err := keycloak.upsertAudienceMapper(
				context.Background(), "client-uuid", "atum-client",
			); err != nil {
				t.Fatalf("upsert audience mapper: %v", err)
			}
			payload := <-payloads
			config, ok := payload["config"].(map[string]any)
			if !ok {
				t.Fatalf("mapper config = %#v", payload["config"])
			}
			if test.wantMethod == http.MethodPut {
				if got := payload["id"]; got != "mapper-uuid" {
					t.Errorf("mapper id = %#v, want mapper-uuid", got)
				}
			} else if _, exists := payload["id"]; exists {
				t.Errorf("create mapper unexpectedly contains id: %#v", payload["id"])
			}
			for key, want := range map[string]string{
				"access.token.claim": "true",
				"id.token.claim":     "true",
				ownerMarkerKey:       ownerMarkerValue,
			} {
				if got := config[key]; got != want {
					t.Errorf("mapper config %s = %#v, want %q", key, got, want)
				}
			}
		})
	}
}
