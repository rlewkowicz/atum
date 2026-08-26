package identity

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"atum/cli/secretvalue"
)

const (
	seedSize                = 32
	derivedSecretSize       = 32
	identityProjectionLimit = 64 << 10
	bootstrapPurpose        = "atum.dev/identity/bootstrap/v1"
	adminPurpose            = "atum.dev/identity/administrator/v1"
	clientPurpose           = "atum.dev/identity/client/v1"
)

type BootstrapProjection struct {
	values secretvalue.Values
	digest []byte
}

func Derive(contract *Contract, encodedSeed []byte, cluster, domain string) (*BootstrapProjection, error) {
	if contract == nil {
		return nil, errors.New("identity contract is required")
	}
	seed := make([]byte, base64.RawStdEncoding.DecodedLen(len(encodedSeed)))
	size, err := base64.RawStdEncoding.Decode(seed, encodedSeed)
	if err != nil || size != seedSize {
		clear(seed)
		return nil, errors.New("identity seed must be 32 raw-base64 encoded bytes")
	}
	seed = seed[:size]
	defer clear(seed)
	if cluster == "" || domain == "" || domain != contract.Domain() {
		return nil, errors.New("identity cluster and contract domain are required and must agree")
	}
	values := make(secretvalue.Values, len(contract.clients)+9)
	complete := false
	defer func() {
		if !complete {
			values.Clear()
		}
	}()
	values["ATUM_IDENTITY_SCHEMA_VERSION"] = []byte(contract.SchemaVersion())
	values["ATUM_IDENTITY_CLUSTER"] = []byte(cluster)
	values["ATUM_IDENTITY_DOMAIN"] = []byte(domain)
	values["ATUM_IDENTITY_ISSUER"] = []byte(contract.Issuer())
	admin := contract.Administrator()
	values["ATUM_IDENTITY_ADMIN_USERNAME"] = []byte(admin.Username)
	values["ATUM_IDENTITY_ADMIN_GROUP"] = []byte(admin.Group)
	adminPassword, err := derive(seed, adminPurpose, cluster, domain, admin.Username)
	if err != nil {
		return nil, err
	}
	values["ATUM_IDENTITY_ADMIN_PASSWORD"] = encodeRawURL(adminPassword)
	clear(adminPassword)
	bootstrap, err := derive(seed, bootstrapPurpose, cluster, domain, "atum-bootstrap")
	if err != nil {
		return nil, err
	}
	values["ATUM_IDENTITY_BOOTSTRAP_PASSWORD"] = encodeRawURL(bootstrap)
	clear(bootstrap)
	for _, client := range contract.clients {
		if client.Type != Confidential {
			continue
		}
		secret, err := derive(seed, clientPurpose+"/"+client.SecretPurpose, cluster, domain, client.ID)
		if err != nil {
			return nil, err
		}
		values[clientSecretKey(client.ID)] = encodeRawURL(secret)
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
		sum := sha256.Sum256(values[key])
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write(sum[:])
	}
	digestSum := hash.Sum(nil)
	digest := make([]byte, hex.EncodedLen(len(digestSum)))
	hex.Encode(digest, digestSum)
	clear(digestSum)
	values["ATUM_IDENTITY_DIGEST"] = append([]byte(nil), digest...)
	complete = true
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

func encodeRawURL(value []byte) []byte {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(encoded, value)
	return encoded
}

func (projection *BootstrapProjection) MarshalAnsibleJSON() ([]byte, error) {
	if projection == nil || len(projection.values) == 0 || len(projection.digest) == 0 {
		return nil, errors.New("identity projection is unavailable")
	}
	return secretvalue.MarshalProjection(
		"atum_platform_identity",
		projection.values,
		"atum_platform_identity_digest",
		projection.digest,
		identityProjectionLimit,
	)
}

func (projection *BootstrapProjection) MarshalKubernetesSecret() ([]byte, error) {
	if projection == nil || len(projection.values) == 0 || len(projection.digest) == 0 {
		return nil, errors.New("identity projection is unavailable")
	}
	return secretvalue.MarshalKubernetesSecret(
		"atum-platform-identity",
		"flux-system",
		"atum.dev/identity-digest",
		projection.digest,
		projection.values,
		identityProjectionLimit,
	)
}

func (projection *BootstrapProjection) MarshalOperatorSecret() ([]byte, error) {
	if projection == nil || len(projection.values) == 0 || len(projection.digest) == 0 {
		return nil, errors.New("identity projection is unavailable")
	}
	values := make(secretvalue.Values, len(projection.values))
	for key, value := range projection.values {
		if key == "ATUM_IDENTITY_ADMIN_USERNAME" ||
			key == "ATUM_IDENTITY_ADMIN_PASSWORD" ||
			key == "ATUM_IDENTITY_BOOTSTRAP_PASSWORD" ||
			strings.HasSuffix(key, "_CLIENT_SECRET") {
			values[key] = append([]byte(nil), value...)
		}
	}
	defer values.Clear()
	return secretvalue.MarshalKubernetesSecret(
		"atum-provider-credentials",
		"atum-system",
		"atum.dev/identity-digest",
		projection.digest,
		values,
		identityProjectionLimit,
	)
}

func (projection *BootstrapProjection) Digest() string {
	if projection == nil {
		return ""
	}
	return string(projection.digest)
}

// AdministratorPassword crosses the unavoidable final terminal-display
// boundary. The returned Go string cannot be overwritten; callers must keep
// the containing completion result bounded to that display lifecycle.
func (projection *BootstrapProjection) AdministratorPassword() string {
	if projection == nil {
		return ""
	}
	return string(projection.values["ATUM_IDENTITY_ADMIN_PASSWORD"])
}

func (projection *BootstrapProjection) Clear() {
	if projection == nil {
		return
	}
	projection.values.Clear()
	clear(projection.digest)
	projection.digest = nil
}
