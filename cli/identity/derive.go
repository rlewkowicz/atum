package identity

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	seedSize          = 32
	derivedSecretSize = 32
	bootstrapPurpose  = "atum.dev/identity/bootstrap/v1"
	clientPurpose     = "atum.dev/identity/client/v1"
)

type BootstrapProjection struct {
	values map[string]string
	digest string
}

func Derive(contract *Contract, encodedSeed, cluster, domain string) (*BootstrapProjection, error) {
	if contract == nil {
		return nil, errors.New("identity contract is required")
	}
	seed, err := base64.RawStdEncoding.DecodeString(encodedSeed)
	if err != nil || len(seed) != seedSize {
		clear(seed)
		return nil, errors.New("identity seed must be 32 raw-base64 encoded bytes")
	}
	defer clear(seed)
	if cluster == "" || domain == "" || domain != contract.Domain() {
		return nil, errors.New("identity cluster and contract domain are required and must agree")
	}
	values := make(map[string]string, len(contract.clients)+8)
	values["ATUM_IDENTITY_SCHEMA_VERSION"] = contract.SchemaVersion()
	values["ATUM_IDENTITY_CLUSTER"] = cluster
	values["ATUM_IDENTITY_DOMAIN"] = domain
	values["ATUM_IDENTITY_ISSUER"] = contract.Issuer()
	admin := contract.Administrator()
	values["ATUM_IDENTITY_ADMIN_USERNAME"] = admin.Username
	values["ATUM_IDENTITY_ADMIN_PASSWORD"] = admin.Password
	values["ATUM_IDENTITY_ADMIN_GROUP"] = admin.Group
	bootstrap, err := derive(seed, bootstrapPurpose, cluster, domain, "atum-bootstrap")
	if err != nil {
		return nil, err
	}
	values["ATUM_IDENTITY_BOOTSTRAP_PASSWORD"] = base64.RawURLEncoding.EncodeToString(bootstrap)
	clear(bootstrap)
	for _, client := range contract.clients {
		if client.Type != Confidential {
			continue
		}
		secret, err := derive(seed, clientPurpose+"/"+client.SecretPurpose, cluster, domain, client.ID)
		if err != nil {
			clearValues(values)
			return nil, err
		}
		values[clientSecretKey(client.ID)] = base64.RawURLEncoding.EncodeToString(secret)
		clear(secret)
	}
	contractBytes := contract.Canonical()
	hash := sha256.New()
	_, _ = hash.Write(contractBytes)
	clear(contractBytes)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	// Projection hashing is deterministic without retaining a second registry.
	slices.Sort(keys)
	for _, key := range keys {
		if key == "ATUM_IDENTITY_ADMIN_PASSWORD" {
			continue
		}
		sum := sha256.Sum256([]byte(values[key]))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write(sum[:])
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	values["ATUM_IDENTITY_DIGEST"] = digest
	return &BootstrapProjection{values: values, digest: digest}, nil
}

func clientSecretKey(id string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_CLIENT_SECRET"
}

func derive(seed []byte, purpose, cluster, domain, client string) ([]byte, error) {
	info := []byte(purpose + "\x00" + cluster + "\x00" + domain + "\x00" + client)
	output, err := hkdf.Key(sha256.New, seed, nil, string(info), derivedSecretSize)
	clear(info)
	if err != nil {
		return nil, fmt.Errorf("derive identity projection: %w", err)
	}
	return output, nil
}

func (projection *BootstrapProjection) MarshalAnsibleJSON() ([]byte, error) {
	if projection == nil || len(projection.values) == 0 || projection.digest == "" {
		return nil, errors.New("identity projection is unavailable")
	}
	return json.Marshal(struct {
		Identity map[string]string `json:"atum_platform_identity"`
		Digest   string            `json:"atum_platform_identity_digest"`
	}{projection.values, projection.digest})
}

func (projection *BootstrapProjection) Digest() string {
	if projection == nil {
		return ""
	}
	return projection.digest
}

func (projection *BootstrapProjection) Clear() {
	if projection == nil {
		return
	}
	clearValues(projection.values)
	projection.digest = ""
}

func clearValues(values map[string]string) {
	for key := range values {
		values[key] = ""
	}
	clear(values)
}
