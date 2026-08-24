// Package secrets owns Atum's typed runtime credentials. Plaintext is kept in
// memory only: the committed representation is SOPS-encrypted and the optional
// developer override is a mode-0600 ignored file.
package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/progress"

	goYAML "go.yaml.in/yaml/v3"
)

const (
	SchemaVersion    = "atum.dev/secrets/v2"
	schemaVersionV1  = "atum.dev/secrets/v1"
	fileLimit        = 1 << 20
	localSecretsLock = ".atum/state/secrets.lock"
)

var (
	ErrNotFound            = errors.New("secrets do not exist")
	ErrMigrationRequired   = errors.New("secrets migration to atum.dev/secrets/v2 is required")
	forgejoUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?$`)
	harborSecretKeyPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Document is the canonical credential set required to bootstrap the internal
// Forgejo and Harbor control plane and derive the platform identity projection.
type Document struct {
	SchemaVersion string          `json:"schemaVersion" yaml:"schemaVersion"`
	Forgejo       ForgejoSecrets  `json:"forgejo" yaml:"forgejo"`
	Harbor        HarborSecrets   `json:"harbor" yaml:"harbor"`
	Identity      IdentitySecrets `json:"identity" yaml:"identity"`
}

type ForgejoSecrets struct {
	Username      string `json:"username" yaml:"username"`
	AdminPassword string `json:"adminPassword" yaml:"adminPassword"`
}

type HarborSecrets struct {
	AdminPassword string `json:"adminPassword" yaml:"adminPassword"`
	SecretKey     string `json:"secretKey" yaml:"secretKey"`
}

type IdentitySecrets struct {
	Seed string `json:"seed" yaml:"seed"`
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
// document or the local mode-0600 override. It never writes plaintext through
// a temporary file or subprocess.
func Init(project *config.Project, options InitOptions) (string, error) {
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
	if options.Local {
		if err := writeLocal(project, document); err != nil {
			return "", fmt.Errorf("write local secrets override: %w", err)
		}
		return project.Desired.Secrets.LocalFile, nil
	}
	data, err := encryptDocument(document, options.AgeRecipients)
	if err != nil {
		return "", err
	}
	defer clear(data)
	if err := write(project.Root, project.Desired.Secrets.SOPSFile, data, 0o600); err != nil {
		return "", fmt.Errorf("write SOPS secrets: %w", err)
	}
	return project.Desired.Secrets.SOPSFile, nil
}

// LoadOrCreateLocal loads the configured credentials or atomically creates an
// ignored local credential document when neither representation exists. It
// never replaces an existing, invalid, or undecryptable document.
func LoadOrCreateLocal(project *config.Project) (Document, bool, error) {
	if project == nil {
		return Document{}, false, errors.New("project is required")
	}
	unlock, err := fssecure.LockContext(
		context.Background(), project.Root, localSecretsLock, 25*time.Millisecond,
	)
	if err != nil {
		return Document{}, false, fmt.Errorf("lock local secrets: %w", err)
	}
	defer unlock()

	document, err := Load(project)
	if err == nil {
		return document, false, nil
	}
	if errors.Is(err, ErrMigrationRequired) {
		document, err = migrateLocal(project)
		return document, false, err
	}
	if !errors.Is(err, ErrNotFound) {
		return Document{}, false, err
	}
	document, err = generate()
	if err != nil {
		return Document{}, false, err
	}
	if err := writeLocal(project, document); err != nil {
		if errors.Is(err, os.ErrExist) {
			document, err = Load(project)
			return document, false, err
		}
		return Document{}, false, fmt.Errorf("write local secrets override: %w", err)
	}
	return document, true, nil
}

// Ensure is the credential entry point for consumers. It loads existing
// credentials or creates the ignored local representation and reports that
// lifecycle without exposing credential values.
func Ensure(ctx context.Context, project *config.Project, logger *slog.Logger) (Document, error) {
	const (
		id    = "secrets"
		label = "Platform secrets"
	)
	progress.Start(ctx, progress.Credentials, id, label, "loading configured credentials")
	document, created, err := LoadOrCreateLocal(project)
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
func Load(project *config.Project) (Document, error) {
	document, migration, _, _, err := load(project)
	if err != nil {
		return Document{}, err
	}
	if migration {
		return Document{}, fmt.Errorf("%w; run a mutating Atum apply or prepare command", ErrMigrationRequired)
	}
	return document, nil
}

func load(project *config.Project) (Document, bool, partialDocument, bool, error) {
	if project == nil {
		return Document{}, false, partialDocument{}, false, errors.New("project is required")
	}
	var override partialDocument
	localLoaded := false
	localV1 := false
	sopsV1 := false
	if data, exists, err := readOptional(project.Root, project.Desired.Secrets.LocalFile, true); err != nil {
		return Document{}, false, override, false, fmt.Errorf("read local secrets override: %w", err)
	} else if exists {
		if err := config.DecodeJSON(data, &override); err != nil {
			clear(data)
			return Document{}, false, override, false, fmt.Errorf("decode local secrets override: %w", err)
		}
		clear(data)
		localLoaded = true
		localV1 = override.SchemaVersion == schemaVersionV1
		var local Document
		applyOverride(&local, override)
		if err := local.Validate(); err == nil {
			return local, false, override, true, nil
		}
	}
	var document Document
	loaded := false
	if data, exists, err := readOptional(project.Root, project.Desired.Secrets.SOPSFile, false); err != nil {
		return Document{}, false, override, localLoaded, fmt.Errorf("read SOPS secrets: %w", err)
	} else if exists {
		decrypted, err := decryptDocument(data)
		clear(data)
		if err != nil {
			return Document{}, false, override, localLoaded, fmt.Errorf("decrypt SOPS secrets: %w", err)
		}
		document = decrypted
		loaded = true
		sopsV1 = document.SchemaVersion == schemaVersionV1
	}
	if localLoaded {
		applyOverride(&document, override)
		loaded = true
	}
	if !loaded {
		return Document{}, false, override, localLoaded, fmt.Errorf("%w at %s or %s; run `atum secrets init`",
			ErrNotFound,
			project.Desired.Secrets.SOPSFile, project.Desired.Secrets.LocalFile)
	}
	migration := localV1 || (sopsV1 &&
		!(localLoaded && override.SchemaVersion == SchemaVersion && override.Identity.Seed != nil))
	if migration {
		document.SchemaVersion = SchemaVersion
		if document.Identity.Seed == "" {
			seed, err := randomSeed()
			if err != nil {
				return Document{}, false, override, localLoaded, err
			}
			document.Identity.Seed = seed
		}
	}
	if err := document.Validate(); err != nil {
		return Document{}, false, override, localLoaded, err
	}
	return document, migration, override, localLoaded, nil
}

func (document Document) Validate() error {
	var problems []string
	if document.SchemaVersion != SchemaVersion {
		problems = append(problems, "schemaVersion must be "+SchemaVersion)
	}
	if !forgejoUsernamePattern.MatchString(document.Forgejo.Username) {
		problems = append(problems, "forgejo.username must be 1 through 40 characters using letters, digits, dot, underscore, or hyphen, and start and end with a letter or digit")
	}
	if !safeCredential(document.Forgejo.AdminPassword, 24, 512) {
		problems = append(problems, "forgejo.adminPassword must contain 24 through 512 printable characters")
	}
	if !safeCredential(document.Harbor.AdminPassword, 24, 512) {
		problems = append(problems, "harbor.adminPassword must contain 24 through 512 printable characters")
	}
	if !harborSecretKeyPattern.MatchString(document.Harbor.SecretKey) {
		problems = append(problems, "harbor.secretKey must be exactly 16 lowercase hexadecimal characters")
	}
	seed, err := base64.RawStdEncoding.DecodeString(document.Identity.Seed)
	if err != nil || len(seed) != 32 {
		problems = append(problems, "identity.seed must encode exactly 32 bytes using raw base64")
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
}

type partialIdentitySecrets struct {
	Seed *string `json:"seed,omitempty"`
}

type partialForgejoSecrets struct {
	Username      *string `json:"username,omitempty"`
	AdminPassword *string `json:"adminPassword,omitempty"`
}

type partialHarborSecrets struct {
	AdminPassword *string `json:"adminPassword,omitempty"`
	SecretKey     *string `json:"secretKey,omitempty"`
}

func applyOverride(document *Document, override partialDocument) {
	if override.SchemaVersion != "" {
		document.SchemaVersion = override.SchemaVersion
	}
	if override.Forgejo.Username != nil {
		document.Forgejo.Username = *override.Forgejo.Username
	}
	if override.Forgejo.AdminPassword != nil {
		document.Forgejo.AdminPassword = *override.Forgejo.AdminPassword
	}
	if override.Harbor.AdminPassword != nil {
		document.Harbor.AdminPassword = *override.Harbor.AdminPassword
	}
	if override.Harbor.SecretKey != nil {
		document.Harbor.SecretKey = *override.Harbor.SecretKey
	}
	if override.Identity.Seed != nil {
		document.Identity.Seed = *override.Identity.Seed
	}
}

func generate() (Document, error) {
	forgejo, err := randomPassword(36)
	if err != nil {
		return Document{}, fmt.Errorf("generate Forgejo password: %w", err)
	}
	harbor, err := randomPassword(36)
	if err != nil {
		return Document{}, fmt.Errorf("generate Harbor password: %w", err)
	}
	key := make([]byte, 8)
	defer clear(key)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return Document{}, fmt.Errorf("generate Harbor secret key: %w", err)
	}
	document := Document{
		SchemaVersion: SchemaVersion,
		Forgejo: ForgejoSecrets{
			Username:      "atum_admin",
			AdminPassword: forgejo,
		},
		Harbor: HarborSecrets{
			AdminPassword: harbor,
			SecretKey:     hex.EncodeToString(key),
		},
	}
	seed, err := randomSeed()
	if err != nil {
		return Document{}, err
	}
	document.Identity.Seed = seed
	return document, document.Validate()
}

func randomSeed() (string, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return "", fmt.Errorf("generate identity seed: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(seed)
	clear(seed)
	return encoded, nil
}

func migrateLocal(project *config.Project) (Document, error) {
	document, migration, override, localLoaded, err := load(project)
	if err != nil {
		return Document{}, err
	}
	if !migration {
		return document, nil
	}
	var data []byte
	if localLoaded {
		override.SchemaVersion = SchemaVersion
		override.Identity.Seed = &document.Identity.Seed
		var local Document
		applyOverride(&local, override)
		if local.Validate() == nil {
			data, err = json.MarshalIndent(document, "", "  ")
		} else {
			data, err = json.MarshalIndent(override, "", "  ")
		}
	} else {
		seed := document.Identity.Seed
		override = partialDocument{SchemaVersion: SchemaVersion, Identity: partialIdentitySecrets{Seed: &seed}}
		data, err = json.MarshalIndent(override, "", "  ")
	}
	if err != nil {
		return Document{}, fmt.Errorf("encode migrated local secrets: %w", err)
	}
	data = append(data, '\n')
	defer clear(data)
	if localLoaded {
		err = fssecure.ReplaceRegular(project.Root, project.Desired.Secrets.LocalFile, data, 0o600)
	} else {
		err = fssecure.WriteRegular(project.Root, project.Desired.Secrets.LocalFile, data, 0o600)
	}
	if err != nil {
		return Document{}, fmt.Errorf("atomically migrate local secrets: %w", err)
	}
	return document, nil
}

func randomPassword(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(buffer)
	clear(buffer)
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

func decodeYAML(data []byte, destination any) error {
	decoder := goYAML.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple YAML documents are not allowed")
		}
		return err
	}
	return nil
}

func safeCredential(value string, minimum, maximum int) bool {
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
