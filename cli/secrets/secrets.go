// Package secrets owns Atum's typed runtime credentials. Plaintext is kept in
// memory only: the committed representation is SOPS-encrypted and the optional
// developer override is a mode-0600 ignored file.
package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"encoding/pem"
	"regexp"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/infra"
	"atum/cli/progress"
	"atum/cli/secretvalue"

	"golang.org/x/crypto/hkdf"
)

const (
	SchemaVersion    = "atum.dev/secrets/v4"
	fileLimit        = 1 << 20
	localSecretsLock = ".atum/state/secrets.lock"
)

var (
	ErrNotFound            = errors.New("secrets do not exist")
	forgejoUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?$`)
	harborSecretKeyPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Document is the canonical credential set required to bootstrap the internal
// Forgejo and Harbor control plane and derive bounded platform projections.
type Document struct {
	SchemaVersion string          `json:"schemaVersion" yaml:"schemaVersion"`
	Forgejo       ForgejoSecrets  `json:"forgejo" yaml:"forgejo"`
	Harbor        HarborSecrets   `json:"harbor" yaml:"harbor"`
	Identity      IdentitySecrets `json:"identity" yaml:"identity"`
	Stateful      StatefulSecrets `json:"stateful" yaml:"stateful"`
	RootCA        RootCASecrets    `json:"rootCA" yaml:"rootCA"`
}

type ForgejoSecrets struct {
	Username      string            `json:"username"`
	AdminPassword secretvalue.Value `json:"adminPassword"`
}

type HarborSecrets struct {
	AdminPassword secretvalue.Value `json:"adminPassword"`
	SecretKey     secretvalue.Value `json:"secretKey"`
}

type IdentitySecrets struct {
	Seed secretvalue.Value `json:"seed"`
}

type StatefulSecrets struct {
	Seed secretvalue.Value `json:"seed"`
}

type RootCASecrets struct {
	Certificate secretvalue.Value `json:"certificate"`
	PrivateKey  secretvalue.Value `json:"privateKey"`
}

// Clear overwrites every owned secret byte before releasing the document.
func (document *Document) Clear() {
	if document == nil {
		return
	}
	document.SchemaVersion = ""
	document.Forgejo.Username = ""
	document.Forgejo.AdminPassword.Clear()
	document.Harbor.AdminPassword.Clear()
	document.Harbor.SecretKey.Clear()
	document.Identity.Seed.Clear()
	document.Stateful.Seed.Clear()
	document.RootCA.Certificate.Clear()
	document.RootCA.PrivateKey.Clear()
}

const (
	statefulRedisPasswordKey                   = "ATUM_STATEFUL_REDIS_PASSWORD"
	statefulPostgreSQLPasswordKey              = "ATUM_STATEFUL_POSTGRESQL_PASSWORD"
	statefulGarageAdminTokenKey                = "ATUM_STATEFUL_GARAGE_ADMIN_TOKEN"
	statefulGarageAccessKeyIDKey               = "ATUM_STATEFUL_GARAGE_ACCESS_KEY_ID"
	statefulGarageSecretKeyKey                 = "ATUM_STATEFUL_GARAGE_SECRET_ACCESS_KEY"
	statefulGitLabSecretKeyBaseKey             = "ATUM_STATEFUL_GITLAB_SECRET_KEY_BASE"
	statefulGitLabOTPKeyBaseKey                = "ATUM_STATEFUL_GITLAB_OTP_KEY_BASE"
	statefulGitLabDBKeyBaseKey                 = "ATUM_STATEFUL_GITLAB_DB_KEY_BASE"
	statefulGitLabEncryptedSettingsKeyBaseKey  = "ATUM_STATEFUL_GITLAB_ENCRYPTED_SETTINGS_KEY_BASE"
	statefulGitLabActiveRecordPrimaryKey       = "ATUM_STATEFUL_GITLAB_ACTIVE_RECORD_PRIMARY_KEY"
	statefulGitLabActiveRecordDeterministicKey = "ATUM_STATEFUL_GITLAB_ACTIVE_RECORD_DETERMINISTIC_KEY"
	statefulGitLabActiveRecordSaltKey          = "ATUM_STATEFUL_GITLAB_ACTIVE_RECORD_SALT"
	statefulDigestKey                          = "ATUM_STATEFUL_DIGEST"
	statefulProjectionSchema                   = "atum.dev/platform-stateful/v1"
	statefulProjectionSchemaKey                = "ATUM_STATEFUL_SCHEMA_VERSION"
)

// StatefulProjection is the one clearable in-memory handoff for required
// stateful-service and GitLab inputs. The SOPS document remains their durable
// authority.
type StatefulProjection struct {
	values secretvalue.Values
	digest []byte
}

func (projection *StatefulProjection) MarshalAnsibleJSON() ([]byte, error) {
	if projection == nil || len(projection.values) == 0 || len(projection.digest) == 0 {
		return nil, errors.New("stateful projection is unavailable")
	}
	return secretvalue.MarshalProjection(
		"atum_platform_stateful",
		projection.values,
		"atum_platform_stateful_digest",
		projection.digest,
		fileLimit,
	)
}

func (projection *StatefulProjection) MarshalKubernetesSecret() ([]byte, error) {
	if projection == nil || len(projection.values) == 0 || len(projection.digest) == 0 {
		return nil, errors.New("stateful projection is unavailable")
	}
	return secretvalue.MarshalKubernetesSecret(
		"atum-platform-stateful",
		"flux-system",
		"atum.dev/stateful-digest",
		projection.digest,
		projection.values,
		fileLimit,
	)
}

func (projection *StatefulProjection) Digest() string {
	if projection == nil {
		return ""
	}
	return string(projection.digest)
}

func (projection *StatefulProjection) Clear() {
	if projection == nil {
		return
	}
	projection.values.Clear()
	clear(projection.digest)
	projection.digest = nil
}

func (document Document) DeriveStatefulProjection() (*StatefulProjection, error) {
	encodedSeed := document.Stateful.Seed.Bytes()
	seed := make([]byte, base64.RawStdEncoding.DecodedLen(len(encodedSeed)))
	size, err := base64.RawStdEncoding.Decode(seed, encodedSeed)
	if err != nil || size != 32 {
		clear(seed)
		return nil, errors.New("derive stateful projection: stateful seed is invalid")
	}
	seed = seed[:size]
	defer clear(seed)
	derive := func(label string, size int) ([]byte, error) {
		output := make([]byte, size)
		reader := hkdf.New(sha256.New, seed, nil, []byte("atum.dev/stateful/v1/"+label))
		if _, err := io.ReadFull(reader, output); err != nil {
			clear(output)
			return nil, err
		}
		return output, nil
	}
	redis, err := derive("redis-password", 32)
	if err != nil {
		return nil, err
	}
	defer clear(redis)
	postgresql, err := derive("postgresql-password", 32)
	if err != nil {
		return nil, err
	}
	defer clear(postgresql)
	admin, err := derive("garage-admin-token", 32)
	if err != nil {
		return nil, err
	}
	defer clear(admin)
	access, err := derive("garage-access-key-id", 12)
	if err != nil {
		return nil, err
	}
	defer clear(access)
	secret, err := derive("garage-secret-access-key", 32)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	gitlabSecret, err := derive("gitlab-secret-key-base", 64)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabSecret)
	gitlabOTP, err := derive("gitlab-otp-key-base", 64)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabOTP)
	gitlabDB, err := derive("gitlab-db-key-base", 64)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabDB)
	gitlabSettings, err := derive("gitlab-encrypted-settings-key-base", 64)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabSettings)
	gitlabPrimary, err := derive("gitlab-active-record-primary-key", 24)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabPrimary)
	gitlabDeterministic, err := derive("gitlab-active-record-deterministic-key", 24)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabDeterministic)
	gitlabSalt, err := derive("gitlab-active-record-salt", 24)
	if err != nil {
		return nil, err
	}
	defer clear(gitlabSalt)
	values := secretvalue.Values{
		statefulProjectionSchemaKey:                []byte(statefulProjectionSchema),
		statefulRedisPasswordKey:                   encodeRawURL(redis),
		statefulPostgreSQLPasswordKey:              encodeRawURL(postgresql),
		statefulGarageAdminTokenKey:                encodeHex(admin, ""),
		statefulGarageAccessKeyIDKey:               encodeHex(access, "GK"),
		statefulGarageSecretKeyKey:                 encodeHex(secret, ""),
		statefulGitLabSecretKeyBaseKey:             encodeHex(gitlabSecret, ""),
		statefulGitLabOTPKeyBaseKey:                encodeHex(gitlabOTP, ""),
		statefulGitLabDBKeyBaseKey:                 encodeHex(gitlabDB, ""),
		statefulGitLabEncryptedSettingsKeyBaseKey:  encodeHex(gitlabSettings, ""),
		statefulGitLabActiveRecordPrimaryKey:       encodeRawURL(gitlabPrimary),
		statefulGitLabActiveRecordDeterministicKey: encodeRawURL(gitlabDeterministic),
		statefulGitLabActiveRecordSaltKey:          encodeRawURL(gitlabSalt),
	}
	hash := sha256.New()
	for _, key := range []string{
		statefulProjectionSchemaKey, statefulRedisPasswordKey,
		statefulPostgreSQLPasswordKey,
		statefulGarageAdminTokenKey, statefulGarageAccessKeyIDKey,
		statefulGarageSecretKeyKey,
		statefulGitLabSecretKeyBaseKey, statefulGitLabOTPKeyBaseKey,
		statefulGitLabDBKeyBaseKey, statefulGitLabEncryptedSettingsKeyBaseKey,
		statefulGitLabActiveRecordPrimaryKey,
		statefulGitLabActiveRecordDeterministicKey,
		statefulGitLabActiveRecordSaltKey,
	} {
		_, _ = io.WriteString(hash, key)
		_, _ = hash.Write(values[key])
	}
	digestSum := hash.Sum(nil)
	digest := make([]byte, hex.EncodedLen(len(digestSum)))
	hex.Encode(digest, digestSum)
	clear(digestSum)
	values[statefulDigestKey] = append([]byte(nil), digest...)
	return &StatefulProjection{values: values, digest: digest}, nil
}

func encodeRawURL(value []byte) []byte {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(encoded, value)
	return encoded
}

func encodeHex(value []byte, prefix string) []byte {
	encoded := make([]byte, len(prefix)+hex.EncodedLen(len(value)))
	copy(encoded, prefix)
	hex.Encode(encoded[len(prefix):], value)
	return encoded
}

// InitOptions controls creation of exactly one secrets representation.
type InitOptions struct {
	Local         bool
	AgeRecipients []string
}

func (options InitOptions) Validate() error {
	if options.Local && len(options.AgeRecipients) != 0 {
		return errors.New("--local and --age-recipient are mutually exclusive")
	}
	if !options.Local && len(options.AgeRecipients) == 0 {
		return errors.New("at least one --age-recipient is required for committed SOPS secrets")
	}
	return nil
}

// Init generates a fresh credential set and writes either the committed SOPS
// document or the local mode-0600 override. SOPS receives plaintext only over
// bounded stdin; Atum never uses a shell, plaintext argument, or temporary
// plaintext file.
func Init(
	ctx context.Context,
	project *config.Project,
	sops SOPSAdapter,
	options InitOptions,
) (string, error) {
	if ctx == nil {
		return "", errors.New("secrets context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if project == nil {
		return "", errors.New("project is required")
	}
	if err := options.Validate(); err != nil {
		return "", err
	}
	document, err := generate()
	if err != nil {
		return "", err
	}
	defer document.Clear()
	if options.Local {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := writeLocal(project, document); err != nil {
			return "", fmt.Errorf("write local secrets override: %w", err)
		}
		return project.Desired.Secrets.LocalFile, nil
	}
	data, err := encryptDocument(ctx, sops, document, options.AgeRecipients)
	if err != nil {
		return "", err
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := write(project.Root, project.Desired.Secrets.SOPSFile, data, 0o600); err != nil {
		return "", fmt.Errorf("write SOPS secrets: %w", err)
	}
	return project.Desired.Secrets.SOPSFile, nil
}

// LoadOrCreateLocal loads the configured credentials or atomically creates an
// ignored local credential document when neither representation exists. It
// never replaces an existing, invalid, or undecryptable document.
func LoadOrCreateLocal(
	ctx context.Context,
	project *config.Project,
	sops SOPSAdapter,
) (Document, bool, error) {
	if ctx == nil {
		return Document{}, false, errors.New("secrets context is required")
	}
	if err := ctx.Err(); err != nil {
		return Document{}, false, err
	}
	if project == nil {
		return Document{}, false, errors.New("project is required")
	}
	unlock, err := fssecure.LockContext(
		ctx, project.Root, localSecretsLock, 25*time.Millisecond,
	)
	if err != nil {
		return Document{}, false, fmt.Errorf("lock local secrets: %w", err)
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return Document{}, false, err
	}

	document, err := Load(ctx, project, sops)
	if err == nil {
		return document, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Document{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return Document{}, false, err
	}
	document, err = generate()
	if err != nil {
		return Document{}, false, err
	}
	if err := ctx.Err(); err != nil {
		document.Clear()
		return Document{}, false, err
	}
	if err := writeLocal(project, document); err != nil {
		if errors.Is(err, os.ErrExist) {
			document.Clear()
			document, err = Load(ctx, project, sops)
			return document, false, err
		}
		document.Clear()
		return Document{}, false, fmt.Errorf("write local secrets override: %w", err)
	}
	return document, true, nil
}

// Ensure is the credential entry point for consumers. It loads existing
// credentials or creates the ignored local representation and reports that
// lifecycle without exposing credential values.
func Ensure(
	ctx context.Context,
	project *config.Project,
	sops SOPSAdapter,
	logger *slog.Logger,
) (Document, error) {
	if ctx == nil {
		return Document{}, errors.New("secrets context is required")
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	const (
		id    = "secrets"
		label = "Platform secrets"
	)
	progress.Start(ctx, progress.Credentials, id, label, "loading configured credentials")
	document, created, err := LoadOrCreateLocal(ctx, project, sops)
	if err != nil {
		progress.Fail(ctx, progress.Credentials, id, label, err)
		return Document{}, err
	}
	detail := "configured credentials loaded"
	if created {
		detail = "secrets saved to " + project.Desired.Secrets.LocalFile + " (Git-ignored)"
		if logger != nil {
			logger.InfoContext(ctx, "local secrets saved",
				"path", project.Desired.Secrets.LocalFile,
				"gitIgnored", true)
		}
	}
	progress.Done(ctx, progress.Credentials, id, label, detail)
	return document, nil
}

// Load decrypts the committed file, overlays an optional local document, and
// validates the resulting typed credentials. A local document may be complete
// or may replace only selected non-empty fields.
func Load(
	ctx context.Context,
	project *config.Project,
	sops SOPSAdapter,
) (Document, error) {
	if ctx == nil {
		return Document{}, errors.New("secrets context is required")
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	if project == nil {
		return Document{}, errors.New("project is required")
	}
	var override partialDocument
	defer override.Clear()
	localLoaded := false
	if data, exists, err := readOptional(project.Root, project.Desired.Secrets.LocalFile, true); err != nil {
		return Document{}, fmt.Errorf("read local secrets override: %w", err)
	} else if exists {
		if err := config.DecodeJSON(data, &override); err != nil {
			clear(data)
			return Document{}, fmt.Errorf("decode local secrets override: %w", err)
		}
		clear(data)
		if override.SchemaVersion != SchemaVersion {
			return Document{}, fmt.Errorf(
				"local secrets schemaVersion %q is unsupported; require %s",
				override.SchemaVersion, SchemaVersion,
			)
		}
		localLoaded = true
		var local Document
		applyOverride(&local, override)
		if err := local.Validate(); err == nil {
			if err := ctx.Err(); err != nil {
				local.Clear()
				return Document{}, err
			}
			return local, nil
		}
		local.Clear()
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	var document Document
	loaded := false
	if data, exists, err := readOptional(project.Root, project.Desired.Secrets.SOPSFile, false); err != nil {
		return Document{}, fmt.Errorf("read SOPS secrets: %w", err)
	} else if exists {
		decrypted, err := decryptDocument(ctx, sops, data)
		clear(data)
		if err != nil {
			return Document{}, fmt.Errorf("decrypt SOPS secrets: %w", err)
		}
		document = decrypted
		loaded = true
	}
	if localLoaded {
		applyOverride(&document, override)
	}
	if err := ctx.Err(); err != nil {
		document.Clear()
		return Document{}, err
	}
	if !loaded {
		if localLoaded {
			document.Clear()
			return Document{}, errors.New(
				"local secrets override is incomplete and no committed SOPS document exists",
			)
		}
		return Document{}, fmt.Errorf("%w at %s or %s; run `atum secrets init`",
			ErrNotFound,
			project.Desired.Secrets.SOPSFile, project.Desired.Secrets.LocalFile)
	}
	if err := document.Validate(); err != nil {
		document.Clear()
		return Document{}, err
	}
	return document, nil
}

func (document Document) Validate() error {
	var problems []string
	if document.SchemaVersion != SchemaVersion {
		problems = append(problems, "schemaVersion must be "+SchemaVersion)
	}
	if !forgejoUsernamePattern.MatchString(document.Forgejo.Username) {
		problems = append(problems, "forgejo.username must be 1 through 40 characters using letters, digits, dot, underscore, or hyphen, and start and end with a letter or digit")
	}
	if !safeCredential(document.Forgejo.AdminPassword.Bytes(), 24, 512) {
		problems = append(problems, "forgejo.adminPassword must contain 24 through 512 printable characters")
	}
	if !safeCredential(document.Harbor.AdminPassword.Bytes(), 24, 512) {
		problems = append(problems, "harbor.adminPassword must contain 24 through 512 printable characters")
	}
	if !harborSecretKeyPattern.Match(document.Harbor.SecretKey.Bytes()) {
		problems = append(problems, "harbor.secretKey must be exactly 16 lowercase hexadecimal characters")
	}
	seed := make([]byte, base64.RawStdEncoding.DecodedLen(len(document.Identity.Seed)))
	size, err := base64.RawStdEncoding.Decode(seed, document.Identity.Seed.Bytes())
	if err != nil || size != 32 {
		problems = append(problems, "identity.seed must encode exactly 32 bytes using raw base64")
	}
	clear(seed)
	certificate := document.RootCA.Certificate.Bytes()
	privateKey := document.RootCA.PrivateKey.Bytes()
	if _, err := tls.X509KeyPair(certificate, privateKey); err != nil {
		problems = append(problems, "rootCA certificate and privateKey must be a matching PEM keypair")
	}
	validated, err := infra.ValidateRootCA(certificate, time.Now())
	if err != nil {
		problems = append(problems, "rootCA.certificate: "+err.Error())
	} else {
		validated.Clear()
	}
	seed = make([]byte, base64.RawStdEncoding.DecodedLen(len(document.Stateful.Seed)))
	size, err = base64.RawStdEncoding.Decode(seed, document.Stateful.Seed.Bytes())
	if err != nil || size != 32 {
		problems = append(problems, "stateful.seed must encode exactly 32 bytes using raw base64")
	}
	clear(seed)
	if len(problems) != 0 {
		return fmt.Errorf("secrets validation failed:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}

type partialDocument struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Forgejo       partialForgejoSecrets  `json:"forgejo"`
	Harbor        partialHarborSecrets   `json:"harbor"`
	Identity      partialIdentitySecrets `json:"identity"`
	Stateful      partialStatefulSecrets `json:"stateful"`
	RootCA        partialRootCASecrets   `json:"rootCA"`
}

type partialIdentitySecrets struct {
	Seed *secretvalue.Value `json:"seed,omitempty"`
}

type partialStatefulSecrets struct {
	Seed *secretvalue.Value `json:"seed,omitempty"`
}

type partialRootCASecrets struct {
	Certificate *secretvalue.Value `json:"certificate,omitempty"`
	PrivateKey  *secretvalue.Value `json:"privateKey,omitempty"`
}

type partialForgejoSecrets struct {
	Username      *string            `json:"username,omitempty"`
	AdminPassword *secretvalue.Value `json:"adminPassword,omitempty"`
}

type partialHarborSecrets struct {
	AdminPassword *secretvalue.Value `json:"adminPassword,omitempty"`
	SecretKey     *secretvalue.Value `json:"secretKey,omitempty"`
}

func (document *partialDocument) Clear() {
	if document == nil {
		return
	}
	document.Forgejo.Username = nil
	clearSecretPointer(&document.Forgejo.AdminPassword)
	clearSecretPointer(&document.Harbor.AdminPassword)
	clearSecretPointer(&document.Harbor.SecretKey)
	clearSecretPointer(&document.Identity.Seed)
	clearSecretPointer(&document.Stateful.Seed)
	clearSecretPointer(&document.RootCA.Certificate)
	clearSecretPointer(&document.RootCA.PrivateKey)
	document.SchemaVersion = ""
}

func clearSecretPointer(value **secretvalue.Value) {
	if value == nil || *value == nil {
		return
	}
	(*value).Clear()
	*value = nil
}

func applyOverride(document *Document, override partialDocument) {
	if override.SchemaVersion != "" {
		document.SchemaVersion = override.SchemaVersion
	}
	if override.Forgejo.Username != nil {
		document.Forgejo.Username = *override.Forgejo.Username
	}
	if override.Forgejo.AdminPassword != nil {
		document.Forgejo.AdminPassword.Clear()
		document.Forgejo.AdminPassword = override.Forgejo.AdminPassword.Clone()
	}
	if override.Harbor.AdminPassword != nil {
		document.Harbor.AdminPassword.Clear()
		document.Harbor.AdminPassword = override.Harbor.AdminPassword.Clone()
	}
	if override.Harbor.SecretKey != nil {
		document.Harbor.SecretKey.Clear()
		document.Harbor.SecretKey = override.Harbor.SecretKey.Clone()
	}
	if override.Identity.Seed != nil {
		document.Identity.Seed.Clear()
		document.Identity.Seed = override.Identity.Seed.Clone()
	}
	if override.Stateful.Seed != nil {
		document.Stateful.Seed.Clear()
		document.Stateful.Seed = override.Stateful.Seed.Clone()
	}
	if override.RootCA.Certificate != nil {
		document.RootCA.Certificate.Clear()
		document.RootCA.Certificate = override.RootCA.Certificate.Clone()
	}
	if override.RootCA.PrivateKey != nil {
		document.RootCA.PrivateKey.Clear()
		document.RootCA.PrivateKey = override.RootCA.PrivateKey.Clone()
	}
}

func generate() (Document, error) {
	forgejo, err := randomPassword(36)
	if err != nil {
		return Document{}, fmt.Errorf("generate Forgejo password: %w", err)
	}
	defer clear(forgejo)
	harbor, err := randomPassword(36)
	if err != nil {
		return Document{}, fmt.Errorf("generate Harbor password: %w", err)
	}
	defer clear(harbor)
	key := make([]byte, 8)
	defer clear(key)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return Document{}, fmt.Errorf("generate Harbor secret key: %w", err)
	}
	harborKey := encodeHex(key, "")
	defer clear(harborKey)
	identitySeed, err := randomSeed("identity")
	if err != nil {
		return Document{}, err
	}
	defer clear(identitySeed)
	statefulSeed, err := randomSeed("stateful")
	if err != nil {
		return Document{}, err
	}
	defer clear(statefulSeed)
	rootCertificate, rootPrivateKey, err := generateRootCA()
	if err != nil {
		return Document{}, err
	}
	defer clear(rootCertificate)
	defer clear(rootPrivateKey)

	document := Document{
		SchemaVersion: SchemaVersion,
		Forgejo: ForgejoSecrets{
			Username:      "atum_admin",
			AdminPassword: secretvalue.New(forgejo),
		},
		Harbor: HarborSecrets{
			AdminPassword: secretvalue.New(harbor),
			SecretKey:     secretvalue.New(harborKey),
		},
		Identity: IdentitySecrets{Seed: secretvalue.New(identitySeed)},
		Stateful: StatefulSecrets{Seed: secretvalue.New(statefulSeed)},
		RootCA: RootCASecrets{
			Certificate: secretvalue.New(rootCertificate),
			PrivateKey:  secretvalue.New(rootPrivateKey),
		},
	}
	if err := document.Validate(); err != nil {
		document.Clear()
		return Document{}, err
	}
	return document, nil
}

func generateRootCA() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root CA private key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root CA serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: "atum-test"},
		NotBefore: now.Add(-time.Hour),
		NotAfter: now.AddDate(10, 0, 0),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root CA certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		clear(der)
		return nil, nil, fmt.Errorf("marshal root CA private key: %w", err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	clear(der)
	clear(privateDER)
	return certificate, privateKey, nil
}

func randomSeed(owner string) ([]byte, error) {
	seed := make([]byte, 32)
	defer clear(seed)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("generate %s seed: %w", owner, err)
	}
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(seed)))
	base64.RawStdEncoding.Encode(encoded, seed)
	return encoded, nil
}

func randomPassword(bytesCount int) ([]byte, error) {
	buffer := make([]byte, bytesCount)
	defer clear(buffer)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return nil, err
	}
	value := encodeRawURL(buffer)
	return value, nil
}

func writeLocal(project *config.Project, document Document) error {
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	defer clear(data)
	return write(project.Root, project.Desired.Secrets.LocalFile, data, 0o600)
}

func readOptional(root, relative string, requireMode0600 bool) ([]byte, bool, error) {
	file, err := fssecure.OpenRegular(root, relative)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, false, err
	}
	if requireMode0600 && info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, false, fmt.Errorf("%s mode is %04o, want 0600", relative, info.Mode().Perm())
	}
	if info.Size() <= 0 || info.Size() > fileLimit {
		_ = file.Close()
		return nil, false, fmt.Errorf("%s size %d is outside 1..%d bytes", relative, info.Size(), fileLimit)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, fileLimit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, false, readErr
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	if len(data) > fileLimit {
		clear(data)
		return nil, false, fmt.Errorf("%s exceeds %d bytes", relative, fileLimit)
	}
	return data, true, nil
}

func write(root, relative string, data []byte, mode os.FileMode) error {
	err := fssecure.CreateRegularWith(root, relative, mode, func(destination io.Writer) error {
		_, err := destination.Write(data)
		return err
	})
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; Atum will not rotate live platform credentials during initialization: %w",
			relative, os.ErrExist)
	}
	return err
}

func safeCredential(value []byte, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}
