package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	platformv1alpha1 "atum/operator/api/v1alpha1"
)

const (
	vaultMountDescription    = ownerMarkerKey + "=" + ownerMarkerValue
	vaultPolicyMarker        = "# " + ownerMarkerKey + "=" + ownerMarkerValue + "\n"
	vaultPlatformAdminPolicy = `path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}`
)

type Vault struct {
	client *Client
}

func NewVault(baseURL string, ca []byte, token string) (*Vault, error) {
	client, err := newClient(baseURL, vaultToken(token), ca)
	if err != nil {
		return nil, err
	}
	return &Vault{client: client}, nil
}

func (v *Vault) Close() { v.client.CloseIdleConnections() }

type jsonMount struct {
	Accessor    string `json:"accessor"`
	Description string `json:"description"`
}

type vaultGroup struct {
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type vaultList struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

type vaultGroupAlias struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	MountAccessor string `json:"mount_accessor,omitempty"`
	CanonicalID   string `json:"canonical_id,omitempty"`
}

func (v *Vault) authMounts(ctx context.Context) (map[string]jsonMount, error) {
	var mounts struct {
		Data map[string]jsonMount `json:"data"`
	}
	if err := v.client.JSON(ctx, http.MethodGet, "/v1/sys/auth", nil, &mounts); err != nil {
		return nil, fmt.Errorf("read auth mounts: %w", err)
	}
	return mounts.Data, nil
}

func (v *Vault) ensureMount(ctx context.Context, authPath string) (jsonMount, error) {
	mounts, err := v.authMounts(ctx)
	if err != nil {
		return jsonMount{}, err
	}
	mountKey := authPath + "/"
	mount, exists := mounts[mountKey]
	if exists && mount.Description != vaultMountDescription {
		return jsonMount{}, Conflict("Vault auth mount %q exists without %s", authPath, vaultMountDescription)
	}
	if !exists {
		if err := v.client.JSON(ctx, http.MethodPost, "/v1/sys/auth/"+url.PathEscape(authPath), map[string]any{
			"type": "oidc", "description": vaultMountDescription,
		}, nil); err != nil {
			return jsonMount{}, fmt.Errorf("enable OIDC auth: %w", err)
		}
		mounts, err = v.authMounts(ctx)
		if err != nil {
			return jsonMount{}, err
		}
		mount, exists = mounts[mountKey]
		if !exists || mount.Description != vaultMountDescription {
			return jsonMount{}, errors.New("created OIDC auth mount was not observable with its ownership marker")
		}
	}
	if mount.Accessor == "" {
		return jsonMount{}, fmt.Errorf("OIDC auth mount %q has no accessor", authPath)
	}
	return mount, nil
}

func (v *Vault) Reconcile(ctx context.Context, issuer string, ca []byte, intent platformv1alpha1.VaultIntent, secrets map[string][]byte) error {
	mount, err := v.ensureMount(ctx, intent.AuthPath)
	if err != nil {
		return err
	}
	role := intent.Role
	credentialKey := CredentialKey(role.ClientID)
	clientSecret := secrets[credentialKey]
	if len(clientSecret) == 0 {
		return fmt.Errorf("fixed Vault client credential key %q is empty", credentialKey)
	}
	if err := v.client.JSON(ctx, http.MethodPost, "/v1/auth/"+url.PathEscape(intent.AuthPath)+"/config", map[string]any{
		"oidc_discovery_url":    issuer,
		"oidc_client_id":        role.ClientID,
		"oidc_discovery_ca_pem": string(ca),
		"oidc_client_secret":    string(clientSecret),
		"default_role":          role.Name,
	}, nil); err != nil {
		return fmt.Errorf("configure OIDC auth: %w", err)
	}
	if err := v.reconcilePolicy(ctx, intent.Policy); err != nil {
		return err
	}
	if err := v.client.JSON(ctx, http.MethodPost, "/v1/auth/"+url.PathEscape(intent.AuthPath)+"/role/"+url.PathEscape(role.Name), map[string]any{
		"role_type":             "oidc",
		"user_claim":            "preferred_username",
		"groups_claim":          role.GroupsClaim,
		"allowed_redirect_uris": role.RedirectURIs,
		"oidc_scopes":           role.Scopes,
		"bound_audiences":       []string{role.ClientID},
		"policies":              []string{intent.Policy.Name},
		"ttl":                   "1h",
		"bound_claims":          map[string]any{"groups": []string{intent.ExternalGroup.Claim}},
	}, nil); err != nil {
		return fmt.Errorf("OIDC role %s: %w", role.Name, err)
	}
	groupID, err := v.upsertExternalGroup(ctx, intent.ExternalGroup)
	if err != nil {
		return err
	}
	if err := v.upsertGroupAlias(ctx, mount.Accessor, groupID, intent.ExternalGroup); err != nil {
		return err
	}
	return v.prune(ctx, intent, mount, groupID)
}

func policyBody(purpose platformv1alpha1.VaultPolicyPurpose) (string, error) {
	if purpose != platformv1alpha1.VaultPlatformAdministration {
		return "", fmt.Errorf("unsupported Vault policy purpose %q", purpose)
	}
	return vaultPolicyMarker + vaultPlatformAdminPolicy, nil
}

func (v *Vault) readPolicy(ctx context.Context, name string) (string, bool, error) {
	var response struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if err := v.client.JSON(ctx, http.MethodGet, "/v1/sys/policies/acl/"+url.PathEscape(name), nil, &response, http.StatusOK, http.StatusNotFound); err != nil {
		return "", false, err
	}
	return response.Data.Policy, response.Data.Policy != "", nil
}

func (v *Vault) reconcilePolicy(ctx context.Context, policy platformv1alpha1.VaultPolicy) error {
	body, err := policyBody(policy.Purpose)
	if err != nil {
		return err
	}
	current, exists, err := v.readPolicy(ctx, policy.Name)
	if err != nil {
		return err
	}
	if exists && !strings.HasPrefix(current, vaultPolicyMarker) {
		return Conflict("Vault policy %q exists without %s", policy.Name, vaultPolicyDescription())
	}
	if err := v.client.JSON(ctx, http.MethodPut, "/v1/sys/policies/acl/"+url.PathEscape(policy.Name), map[string]any{"policy": body}, nil); err != nil {
		return fmt.Errorf("policy %s: %w", policy.Name, err)
	}
	return nil
}

func vaultPolicyDescription() string {
	return strings.TrimSpace(vaultPolicyMarker)
}

func (v *Vault) upsertExternalGroup(ctx context.Context, desired platformv1alpha1.VaultExternalGroup) (string, error) {
	var current struct {
		Data vaultGroup `json:"data"`
	}
	err := v.client.JSON(ctx, http.MethodGet, "/v1/identity/group/name/"+url.PathEscape(desired.Name), nil, &current, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return "", err
	}
	if current.Data.ID != "" && current.Data.Metadata[ownerMarkerKey] != ownerMarkerValue {
		return "", Conflict("external group %q exists without Atum ownership", desired.Name)
	}
	body := map[string]any{
		"name":     desired.Name,
		"type":     "external",
		"policies": []string{desired.PolicyName},
		"metadata": map[string]string{ownerMarkerKey: ownerMarkerValue},
	}
	var written struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	endpoint := "/v1/identity/group"
	if current.Data.ID != "" {
		endpoint = "/v1/identity/group/id/" + url.PathEscape(current.Data.ID)
	}
	if err := v.client.JSON(ctx, http.MethodPost, endpoint, body, &written); err != nil {
		return "", fmt.Errorf("external group: %w", err)
	}
	if written.Data.ID != "" {
		return written.Data.ID, nil
	}
	if current.Data.ID != "" {
		return current.Data.ID, nil
	}
	return "", errors.New("Vault did not return the external group identity")
}

func (v *Vault) upsertGroupAlias(ctx context.Context, mountAccessor, groupID string, desired platformv1alpha1.VaultExternalGroup) error {
	alias, exists, err := v.findGroupAlias(ctx, desired.Claim, mountAccessor)
	if err != nil {
		return err
	}
	if exists && alias.CanonicalID != groupID {
		owned, err := v.groupIsOwned(ctx, alias.CanonicalID)
		if err != nil {
			return err
		}
		if !owned {
			return Conflict("external group alias %q points outside Atum-owned provider state", desired.Claim)
		}
	}
	body := map[string]any{
		"name":           desired.Claim,
		"canonical_id":   groupID,
		"mount_accessor": mountAccessor,
	}
	endpoint := "/v1/identity/group-alias"
	if exists {
		endpoint = "/v1/identity/group-alias/id/" + url.PathEscape(alias.ID)
	}
	return v.client.JSON(ctx, http.MethodPost, endpoint, body, nil)
}

func (v *Vault) groupIsOwned(ctx context.Context, id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	var response struct {
		Data vaultGroup `json:"data"`
	}
	if err := v.client.JSON(
		ctx,
		http.MethodGet,
		"/v1/identity/group/id/"+url.PathEscape(id),
		nil,
		&response,
		http.StatusOK,
		http.StatusNotFound,
	); err != nil {
		return false, err
	}
	return response.Data.ID != "" && response.Data.Metadata[ownerMarkerKey] == ownerMarkerValue, nil
}

func (v *Vault) listIDs(ctx context.Context, endpoint string) ([]string, error) {
	var listed vaultList
	if err := v.client.JSON(ctx, http.MethodGet, endpoint+"?list=true", nil, &listed, http.StatusOK, http.StatusNotFound); err != nil {
		return nil, err
	}
	return listed.Data.Keys, nil
}

func (v *Vault) findGroupAlias(ctx context.Context, name, accessor string) (vaultGroupAlias, bool, error) {
	ids, err := v.listIDs(ctx, "/v1/identity/group-alias/id")
	if err != nil {
		return vaultGroupAlias{}, false, err
	}
	var found vaultGroupAlias
	matches := 0
	for _, id := range ids {
		var response struct {
			Data vaultGroupAlias `json:"data"`
		}
		if err := v.client.JSON(ctx, http.MethodGet, "/v1/identity/group-alias/id/"+url.PathEscape(id), nil, &response); err != nil {
			return vaultGroupAlias{}, false, err
		}
		if response.Data.Name == name && response.Data.MountAccessor == accessor {
			found = response.Data
			matches++
		}
	}
	if matches > 1 {
		return vaultGroupAlias{}, false, Conflict("external group alias %q is duplicated", name)
	}
	return found, matches == 1, nil
}

func (v *Vault) prune(ctx context.Context, intent platformv1alpha1.VaultIntent, desiredMount jsonMount, groupID string) error {
	if err := v.pruneAliases(ctx, map[string]struct{}{
		desiredAliasKey(intent.ExternalGroup.Claim, desiredMount.Accessor, groupID): {},
	}); err != nil {
		return err
	}
	if err := v.pruneGroups(ctx, map[string]struct{}{intent.ExternalGroup.Name: {}}); err != nil {
		return err
	}
	if err := v.prunePolicies(ctx, map[string]struct{}{intent.Policy.Name: {}}); err != nil {
		return err
	}
	mounts, err := v.authMounts(ctx)
	if err != nil {
		return err
	}
	for key, mount := range mounts {
		if mount.Description != vaultMountDescription || key == intent.AuthPath+"/" {
			continue
		}
		if err := v.cleanupMount(ctx, strings.TrimSuffix(key, "/")); err != nil {
			return err
		}
	}
	return nil
}

func desiredAliasKey(name, accessor, groupID string) string {
	return name + "\x00" + accessor + "\x00" + groupID
}

func (v *Vault) pruneAliases(ctx context.Context, desired map[string]struct{}) error {
	ids, err := v.listIDs(ctx, "/v1/identity/group-alias/id")
	if err != nil {
		return err
	}
	ownedGroups := make(map[string]bool)
	checkedGroups := make(map[string]struct{})
	for _, id := range ids {
		var response struct {
			Data vaultGroupAlias `json:"data"`
		}
		if err := v.client.JSON(ctx, http.MethodGet, "/v1/identity/group-alias/id/"+url.PathEscape(id), nil, &response); err != nil {
			return err
		}
		alias := response.Data
		if _, keep := desired[desiredAliasKey(alias.Name, alias.MountAccessor, alias.CanonicalID)]; keep {
			continue
		}
		if _, checked := checkedGroups[alias.CanonicalID]; !checked {
			owned, err := v.groupIsOwned(ctx, alias.CanonicalID)
			if err != nil {
				return err
			}
			ownedGroups[alias.CanonicalID] = owned
			checkedGroups[alias.CanonicalID] = struct{}{}
		}
		if !ownedGroups[alias.CanonicalID] {
			continue
		}
		if err := v.client.JSON(ctx, http.MethodDelete, "/v1/identity/group-alias/id/"+url.PathEscape(alias.ID), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) pruneGroups(ctx context.Context, desired map[string]struct{}) error {
	ids, err := v.listIDs(ctx, "/v1/identity/group/id")
	if err != nil {
		return err
	}
	for _, id := range ids {
		var response struct {
			Data vaultGroup `json:"data"`
		}
		if err := v.client.JSON(ctx, http.MethodGet, "/v1/identity/group/id/"+url.PathEscape(id), nil, &response); err != nil {
			return err
		}
		group := response.Data
		if group.Metadata[ownerMarkerKey] != ownerMarkerValue {
			continue
		}
		if _, keep := desired[group.Name]; keep {
			continue
		}
		if err := v.client.JSON(ctx, http.MethodDelete, "/v1/identity/group/id/"+url.PathEscape(group.ID), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) prunePolicies(ctx context.Context, desired map[string]struct{}) error {
	names, err := v.listIDs(ctx, "/v1/sys/policies/acl")
	if err != nil {
		return err
	}
	for _, name := range names {
		body, exists, err := v.readPolicy(ctx, name)
		if err != nil {
			return err
		}
		if !exists || !strings.HasPrefix(body, vaultPolicyMarker) {
			continue
		}
		if _, keep := desired[name]; keep {
			continue
		}
		if err := v.client.JSON(ctx, http.MethodDelete, "/v1/sys/policies/acl/"+url.PathEscape(name), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) cleanupMount(ctx context.Context, authPath string) error {
	mounts, err := v.authMounts(ctx)
	if err != nil {
		return err
	}
	mount, exists := mounts[authPath+"/"]
	if !exists {
		return nil
	}
	if mount.Description != vaultMountDescription {
		return Conflict("refusing to clean unowned Vault auth mount %q", authPath)
	}
	roles, err := v.listIDs(ctx, "/v1/auth/"+url.PathEscape(authPath)+"/role")
	if err != nil {
		return err
	}
	foreign := make([]string, 0, len(roles))
	declaredRoleExists := false
	for _, role := range roles {
		if role == platformv1alpha1.VaultPlatformAdministrationRoleName {
			declaredRoleExists = true
			continue
		}
		foreign = append(foreign, role)
	}
	if len(foreign) != 0 {
		slices.Sort(foreign)
		return Conflict(
			"Vault auth mount %q contains foreign roles [%s]; remove them before cleanup",
			authPath,
			strings.Join(foreign, ", "),
		)
	}
	if declaredRoleExists {
		if err := v.client.JSON(
			ctx,
			http.MethodDelete,
			"/v1/auth/"+url.PathEscape(authPath)+"/role/"+
				url.PathEscape(platformv1alpha1.VaultPlatformAdministrationRoleName),
			nil,
			nil,
		); err != nil {
			return fmt.Errorf(
				"retire declared Vault OIDC role %s: %w",
				platformv1alpha1.VaultPlatformAdministrationRoleName,
				err,
			)
		}
	}
	return v.client.JSON(ctx, http.MethodDelete, "/v1/sys/auth/"+url.PathEscape(authPath), nil, nil)
}

func (v *Vault) Cleanup(ctx context.Context) error {
	if err := v.pruneAliases(ctx, nil); err != nil {
		return err
	}
	if err := v.pruneGroups(ctx, nil); err != nil {
		return err
	}
	if err := v.prunePolicies(ctx, nil); err != nil {
		return err
	}
	mounts, err := v.authMounts(ctx)
	if err != nil {
		return err
	}
	for key, mount := range mounts {
		if mount.Description != vaultMountDescription {
			continue
		}
		if err := v.cleanupMount(ctx, strings.TrimSuffix(key, "/")); err != nil {
			return err
		}
	}
	return nil
}
