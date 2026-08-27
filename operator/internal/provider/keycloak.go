package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	platformv1alpha1 "atum/operator/api/v1alpha1"
)

const (
	ownerMarkerKey   = "platform.atum.dev/owner"
	ownerMarkerValue = "atum-system/atum"
	keycloakPageSize = 100
)

type keycloakCollectionKind uint8

const (
	realmClients keycloakCollectionKind = iota
	realmGroups
	realmUsers
	realmClientScopes
	clientProtocolMappers
	clientScopeProtocolMappers
)

type keycloakCollection struct {
	kind     keycloakCollectionKind
	parentID string
}

func realmCollection(kind keycloakCollectionKind) keycloakCollection {
	return keycloakCollection{kind: kind}
}

func clientMappersCollection(clientID string) keycloakCollection {
	return keycloakCollection{kind: clientProtocolMappers, parentID: clientID}
}

func clientScopeMappersCollection(scopeID string) keycloakCollection {
	return keycloakCollection{kind: clientScopeProtocolMappers, parentID: scopeID}
}

func (collection keycloakCollection) path() (string, bool, error) {
	switch collection.kind {
	case realmClients:
		return "/clients", true, nil
	case realmGroups:
		return "/groups", true, nil
	case realmUsers:
		return "/users", true, nil
	case realmClientScopes:
		return "/client-scopes", false, nil
	case clientProtocolMappers:
		if collection.parentID == "" {
			return "", false, errors.New("client mapper collection has no parent")
		}
		return "/clients/" + url.PathEscape(collection.parentID) + "/protocol-mappers/models", false, nil
	case clientScopeProtocolMappers:
		if collection.parentID == "" {
			return "", false, errors.New("client-scope mapper collection has no parent")
		}
		return "/client-scopes/" + url.PathEscape(collection.parentID) + "/protocol-mappers/models", false, nil
	default:
		return "", false, fmt.Errorf("unsupported Keycloak collection capability %d", collection.kind)
	}
}

type Keycloak struct {
	client *Client
	realm  string
}

type keycloakToken struct {
	AccessToken string `json:"access_token"`
}

type keycloakObject struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name,omitempty"`
	Username   string         `json:"username,omitempty"`
	ClientID   string         `json:"clientId,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
}

func NewKeycloak(ctx context.Context, baseURL string, ca []byte, realm, username, password string) (*Keycloak, error) {
	anonymous, err := newClient(baseURL, anonymous(), ca)
	if err != nil {
		return nil, err
	}
	var token keycloakToken
	err = anonymous.Form(ctx, "/realms/"+url.PathEscape(realm)+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {username},
		"password":   {password},
	}, &token)
	anonymous.CloseIdleConnections()
	if err != nil {
		return nil, fmt.Errorf("authenticate Keycloak administrator: %w", err)
	}
	if token.AccessToken == "" {
		return nil, errors.New("Keycloak returned an empty administrator token")
	}
	client, err := newClient(baseURL, keycloakBearer(token.AccessToken), ca)
	if err != nil {
		return nil, err
	}
	return &Keycloak{client: client, realm: realm}, nil
}

func (k *Keycloak) Close() { k.client.CloseIdleConnections() }

func (k *Keycloak) admin(pathValue string) string {
	return "/admin/realms/" + url.PathEscape(k.realm) + pathValue
}

func CredentialKey(clientID string) string {
	return strings.ToUpper(strings.ReplaceAll(clientID, "-", "_")) + "_CLIENT_SECRET"
}

func exact(items []keycloakObject, field, wanted string) (keycloakObject, bool, error) {
	var found keycloakObject
	matches := 0
	for _, item := range items {
		value := item.Name
		switch field {
		case "username":
			value = item.Username
		case "clientId":
			value = item.ClientID
		}
		if value == wanted {
			found = item
			matches++
		}
	}
	if matches > 1 {
		return keycloakObject{}, false, Conflict("%s %q is duplicated", field, wanted)
	}
	return found, matches == 1, nil
}

func marked(values map[string]any) bool {
	value, exists := values[ownerMarkerKey]
	if !exists {
		return false
	}
	switch typed := value.(type) {
	case string:
		return typed == ownerMarkerValue
	case []any:
		return len(typed) == 1 && typed[0] == ownerMarkerValue
	default:
		return false
	}
}

func objectMarked(object keycloakObject) bool {
	return marked(object.Attributes) || marked(object.Config)
}

func (k *Keycloak) list(ctx context.Context, collection keycloakCollection, query string) ([]keycloakObject, error) {
	collectionPath, paginated, err := collection.path()
	if err != nil {
		return nil, err
	}
	filter, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("parse Keycloak %s collection filter: %w", collectionPath, err)
	}
	if filter.Has("first") || filter.Has("max") {
		return nil, fmt.Errorf("Keycloak %s collection filter cannot set first or max", collectionPath)
	}
	if !paginated {
		var items []keycloakObject
		path := k.admin(collectionPath)
		if encoded := filter.Encode(); encoded != "" {
			path += "?" + encoded
		}
		if err := k.client.JSON(ctx, http.MethodGet, path, nil, &items); err != nil {
			return nil, err
		}
		if err := validateKeycloakIdentities(collectionPath, items, nil); err != nil {
			return nil, err
		}
		return items, nil
	}
	return k.paginatedList(ctx, collectionPath, filter)
}

func (k *Keycloak) paginatedList(ctx context.Context, collectionPath string, filter url.Values) ([]keycloakObject, error) {
	var items []keycloakObject
	seenIDs := make(map[string]struct{}, keycloakPageSize)
	seenPages := make(map[string]struct{})
	offset := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("enumerate Keycloak %s collection: %w", collectionPath, err)
		}
		filter.Set("first", fmt.Sprintf("%d", offset))
		filter.Set("max", fmt.Sprintf("%d", keycloakPageSize))
		var page []keycloakObject
		if err := k.client.JSON(ctx, http.MethodGet, k.admin(collectionPath)+"?"+filter.Encode(), nil, &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return items, nil
		}
		if len(page) > keycloakPageSize {
			return nil, fmt.Errorf(
				"Keycloak %s collection returned %d records for maximum page size %d",
				collectionPath, len(page), keycloakPageSize,
			)
		}
		signature := keycloakPageSignature(page)
		if len(page) == keycloakPageSize {
			if _, repeated := seenPages[signature]; repeated {
				return nil, fmt.Errorf("Keycloak %s collection repeated full page at offset %d", collectionPath, offset)
			}
			seenPages[signature] = struct{}{}
		}
		if err := validateKeycloakIdentities(collectionPath, page, seenIDs); err != nil {
			return nil, err
		}
		items = append(items, page...)
		if len(page) < keycloakPageSize {
			return items, nil
		}
		maxInt := int(^uint(0) >> 1)
		if len(page) > maxInt-offset {
			return nil, fmt.Errorf("Keycloak %s collection offset overflow at %d", collectionPath, offset)
		}
		next := offset + len(page)
		if next <= offset {
			return nil, fmt.Errorf("Keycloak %s collection made no progress at offset %d", collectionPath, offset)
		}
		offset = next
	}
}

func validateKeycloakIdentities(collectionPath string, items []keycloakObject, seen map[string]struct{}) error {
	if seen == nil {
		seen = make(map[string]struct{}, len(items))
	}
	for index := range items {
		if items[index].ID == "" {
			return fmt.Errorf("Keycloak %s collection returned an empty identity at index %d", collectionPath, index)
		}
		if _, duplicate := seen[items[index].ID]; duplicate {
			return fmt.Errorf("Keycloak %s collection returned duplicate identity %q", collectionPath, items[index].ID)
		}
		seen[items[index].ID] = struct{}{}
	}
	return nil
}

func keycloakPageSignature(items []keycloakObject) string {
	var signature strings.Builder
	for index := range items {
		signature.WriteString(items[index].ID)
		signature.WriteByte(0)
	}
	return signature.String()
}

func (k *Keycloak) upsert(ctx context.Context, collection keycloakCollection, query, field, name string, body map[string]any) (string, error) {
	collectionPath, _, err := collection.path()
	if err != nil {
		return "", err
	}
	items, err := k.list(ctx, collection, query)
	if err != nil {
		return "", err
	}
	current, exists, err := exact(items, field, name)
	if err != nil {
		return "", err
	}
	if exists && !objectMarked(current) {
		return "", Conflict("%s %q exists without %s=%s", collectionPath, name, ownerMarkerKey, ownerMarkerValue)
	}
	if !exists {
		if err := k.client.JSON(ctx, http.MethodPost, k.admin(collectionPath), body, nil); err != nil {
			return "", err
		}
		items, err = k.list(ctx, collection, query)
		if err != nil {
			return "", err
		}
		current, exists, err = exact(items, field, name)
		if err != nil {
			return "", err
		}
		if !exists || !objectMarked(current) {
			return "", fmt.Errorf("created %s %q was not observable with its ownership marker", collectionPath, name)
		}
	}
	if err := k.client.JSON(ctx, http.MethodPut, k.admin(collectionPath+"/"+url.PathEscape(current.ID)), body, nil); err != nil {
		return "", err
	}
	return current.ID, nil
}

func (k *Keycloak) Reconcile(ctx context.Context, domain string, intent platformv1alpha1.KeycloakIntent, secrets map[string][]byte) error {
	admin := intent.Administrator
	userID, err := k.upsert(ctx, realmCollection(realmUsers), "exact=true&username="+url.QueryEscape(admin.Username), "username", admin.Username, map[string]any{
		"username":      admin.Username,
		"enabled":       true,
		"email":         admin.Username + "@" + domain,
		"emailVerified": true,
		"firstName":     admin.Username,
		"lastName":      "Administrator",
		"attributes":    map[string][]string{ownerMarkerKey: {ownerMarkerValue}},
	})
	if err != nil {
		return fmt.Errorf("administrator: %w", err)
	}
	if err := k.client.JSON(ctx, http.MethodPut, k.admin("/users/"+url.PathEscape(userID)+"/reset-password"), map[string]any{
		"type": "password", "value": string(secrets["ATUM_IDENTITY_ADMIN_PASSWORD"]), "temporary": false,
	}, nil); err != nil {
		return fmt.Errorf("administrator password: %w", err)
	}
	groupID, err := k.upsert(ctx, realmCollection(realmGroups), "exact=true&search="+url.QueryEscape(admin.Group), "name", admin.Group, map[string]any{
		"name":       admin.Group,
		"attributes": map[string][]string{ownerMarkerKey: {ownerMarkerValue}},
	})
	if err != nil {
		return fmt.Errorf("administrator group: %w", err)
	}
	if err := k.client.JSON(ctx, http.MethodPut, k.admin("/users/"+url.PathEscape(userID)+"/groups/"+url.PathEscape(groupID)), nil, nil); err != nil {
		return fmt.Errorf("administrator group membership: %w", err)
	}
	if err := k.reconcileRealmRole(ctx, userID, admin.RealmRole); err != nil {
		return err
	}
	scopeID, err := k.upsert(ctx, realmCollection(realmClientScopes), "", "name", intent.GroupsScope.Name, map[string]any{
		"name":     intent.GroupsScope.Name,
		"protocol": "openid-connect",
		"attributes": map[string]string{
			"include.in.token.scope":    "true",
			"display.on.consent.screen": "false",
			ownerMarkerKey:              ownerMarkerValue,
		},
	})
	if err != nil {
		return fmt.Errorf("groups scope: %w", err)
	}
	if err := k.upsertGroupsMapper(ctx, scopeID, intent.GroupsScope); err != nil {
		return err
	}
	scopeIDs, err := k.defaultScopeIDs(ctx, intent.Scopes, scopeID, intent.GroupsScope.Name)
	if err != nil {
		return err
	}
	for _, desired := range intent.Clients {
		if err := k.reconcileClient(ctx, scopeIDs, desired, secrets); err != nil {
			return fmt.Errorf("client %s: %w", desired.ID, err)
		}
	}
	return k.prune(ctx, intent)
}

func (k *Keycloak) reconcileRealmRole(ctx context.Context, userID, realmRole string) error {
	clients, err := k.list(ctx, realmCollection(realmClients), "clientId=realm-management")
	if err != nil {
		return fmt.Errorf("realm-management client: %w", err)
	}
	management, exists, err := exact(clients, "clientId", "realm-management")
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("realm-management client is absent")
	}
	roleName := "realm-" + realmRole
	var role map[string]any
	if err := k.client.JSON(ctx, http.MethodGet, k.admin("/clients/"+url.PathEscape(management.ID)+"/roles/"+url.PathEscape(roleName)), nil, &role); err != nil {
		return fmt.Errorf("realm-management role %s: %w", roleName, err)
	}
	if err := k.client.JSON(ctx, http.MethodPost, k.admin("/users/"+url.PathEscape(userID)+"/role-mappings/clients/"+url.PathEscape(management.ID)), []any{role}, nil); err != nil {
		return fmt.Errorf("administrator realm role: %w", err)
	}
	return nil
}

func (k *Keycloak) defaultScopeIDs(ctx context.Context, names []string, groupsID, groupsName string) ([]string, error) {
	scopes, err := k.list(ctx, realmCollection(realmClientScopes), "")
	if err != nil {
		return nil, err
	}
	byName := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		if _, duplicate := byName[scope.Name]; duplicate {
			return nil, Conflict("client scope %q is duplicated", scope.Name)
		}
		byName[scope.Name] = scope.ID
	}
	byName[groupsName] = groupsID
	result := make([]string, 0, len(names)-1)
	for _, name := range names {
		if name == "openid" {
			continue
		}
		lookup := name
		if name == "groups" {
			lookup = groupsName
		}
		id := byName[lookup]
		if id == "" {
			return nil, fmt.Errorf("required client scope %q is absent", lookup)
		}
		result = append(result, id)
	}
	return result, nil
}

func (k *Keycloak) upsertGroupsMapper(ctx context.Context, scopeID string, scope platformv1alpha1.GroupsScope) error {
	collection := clientScopeMappersCollection(scopeID)
	collectionPath, _, err := collection.path()
	if err != nil {
		return err
	}
	mappers, err := k.list(ctx, collection, "")
	if err != nil {
		return err
	}
	current, exists, err := exact(mappers, "name", scope.Name)
	if err != nil {
		return err
	}
	body := map[string]any{
		"name":           scope.Name,
		"protocol":       "openid-connect",
		"protocolMapper": "oidc-group-membership-mapper",
		"config": map[string]string{
			"claim.name":           scope.ClaimName,
			"full.path":            "false",
			"id.token.claim":       "true",
			"access.token.claim":   "true",
			"userinfo.token.claim": "true",
			ownerMarkerKey:         ownerMarkerValue,
		},
	}
	if !exists {
		return k.client.JSON(ctx, http.MethodPost, k.admin(collectionPath), body, nil)
	}
	if !objectMarked(current) {
		return Conflict("groups mapper %q exists without Atum ownership", scope.Name)
	}
	return k.client.JSON(ctx, http.MethodPut, k.admin(collectionPath+"/"+url.PathEscape(current.ID)), body, nil)
}

func (k *Keycloak) reconcileClient(ctx context.Context, scopeIDs []string, desired platformv1alpha1.KeycloakClient, secrets map[string][]byte) error {
	confidential := desired.Kind == platformv1alpha1.ClientConfidential
	body := map[string]any{
		"clientId":                  desired.ID,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              !confidential,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"redirectUris":              desired.RedirectURIs,
		"webOrigins":                desired.WebOrigins,
		"attributes": map[string]string{
			ownerMarkerKey:               ownerMarkerValue,
			"pkce.code.challenge.method": "S256",
		},
	}
	if confidential {
		key := CredentialKey(desired.ID)
		secret := secrets[key]
		if len(secret) == 0 {
			return fmt.Errorf("fixed credential key %q is empty", key)
		}
		body["secret"] = string(secret)
	}
	clientID, err := k.upsert(ctx, realmCollection(realmClients), "clientId="+url.QueryEscape(desired.ID), "clientId", desired.ID, body)
	if err != nil {
		return err
	}
	for _, scopeID := range scopeIDs {
		if err := k.client.JSON(ctx, http.MethodPut, k.admin("/clients/"+url.PathEscape(clientID)+"/default-client-scopes/"+url.PathEscape(scopeID)), nil, nil); err != nil {
			return fmt.Errorf("default scope: %w", err)
		}
	}
	if desired.Audience {
		return k.upsertAudienceMapper(ctx, clientID, desired.ID)
	}
	return k.deleteAudienceMapper(ctx, clientID, desired.ID)
}

func (k *Keycloak) clientMappers(ctx context.Context, clientUUID string) ([]keycloakObject, string, error) {
	collection := clientMappersCollection(clientUUID)
	collectionPath, _, err := collection.path()
	if err != nil {
		return nil, "", err
	}
	mappers, err := k.list(ctx, collection, "")
	return mappers, collectionPath, err
}

func (k *Keycloak) deleteAudienceMapper(ctx context.Context, clientUUID, audience string) error {
	mappers, collection, err := k.clientMappers(ctx, clientUUID)
	if err != nil {
		return err
	}
	name := "audience-" + audience
	current, exists, err := exact(mappers, "name", name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if !objectMarked(current) {
		return Conflict("audience mapper %q exists without Atum ownership", name)
	}
	return k.client.JSON(ctx, http.MethodDelete, k.admin(collection+"/"+url.PathEscape(current.ID)), nil, nil)
}

func (k *Keycloak) upsertAudienceMapper(ctx context.Context, clientUUID, audience string) error {
	mappers, collection, err := k.clientMappers(ctx, clientUUID)
	if err != nil {
		return err
	}
	name := "audience-" + audience
	current, exists, err := exact(mappers, "name", name)
	if err != nil {
		return err
	}
	body := map[string]any{
		"name":           name,
		"protocol":       "openid-connect",
		"protocolMapper": "oidc-audience-mapper",
		"config": map[string]string{
			"included.client.audience": audience,
			"access.token.claim":       "true",
			"id.token.claim":           "true",
			ownerMarkerKey:             ownerMarkerValue,
		},
	}
	if !exists {
		return k.client.JSON(ctx, http.MethodPost, k.admin(collection), body, nil)
	}
	if !objectMarked(current) {
		return Conflict("audience mapper %q exists without Atum ownership", name)
	}
	return k.client.JSON(ctx, http.MethodPut, k.admin(collection+"/"+url.PathEscape(current.ID)), body, nil)
}

func (k *Keycloak) prune(ctx context.Context, intent platformv1alpha1.KeycloakIntent) error {
	clients := make(map[string]struct{}, len(intent.Clients))
	for _, item := range intent.Clients {
		clients[item.ID] = struct{}{}
	}
	if err := k.pruneCollection(ctx, realmCollection(realmClients), "clientId", clients); err != nil {
		return fmt.Errorf("prune clients: %w", err)
	}
	if err := k.pruneCollection(ctx, realmCollection(realmUsers), "username", map[string]struct{}{intent.Administrator.Username: {}}); err != nil {
		return fmt.Errorf("prune users: %w", err)
	}
	if err := k.pruneCollection(ctx, realmCollection(realmGroups), "name", map[string]struct{}{intent.Administrator.Group: {}}); err != nil {
		return fmt.Errorf("prune groups: %w", err)
	}
	if err := k.pruneCollection(ctx, realmCollection(realmClientScopes), "name", map[string]struct{}{intent.GroupsScope.Name: {}}); err != nil {
		return fmt.Errorf("prune client scopes: %w", err)
	}
	return nil
}

func (k *Keycloak) pruneCollection(ctx context.Context, collection keycloakCollection, field string, desired map[string]struct{}) error {
	collectionPath, _, err := collection.path()
	if err != nil {
		return err
	}
	items, err := k.list(ctx, collection, "")
	if err != nil {
		return err
	}
	var errs []error
	for _, item := range items {
		if !objectMarked(item) {
			continue
		}
		name := item.Name
		switch field {
		case "username":
			name = item.Username
		case "clientId":
			name = item.ClientID
		}
		if _, keep := desired[name]; keep {
			continue
		}
		errs = append(errs, k.client.JSON(ctx, http.MethodDelete, k.admin(collectionPath+"/"+url.PathEscape(item.ID)), nil, nil))
	}
	return errors.Join(errs...)
}

func (k *Keycloak) Cleanup(ctx context.Context) error {
	var errs []error
	for _, collection := range []keycloakCollection{
		realmCollection(realmClients),
		realmCollection(realmGroups),
		realmCollection(realmClientScopes),
		realmCollection(realmUsers),
	} {
		if err := k.pruneCollection(ctx, collection, "", nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
