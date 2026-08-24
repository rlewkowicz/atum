package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	filippoage "filippo.io/age"
	"filippo.io/age/armor"
	"github.com/google/shlex"
	goYAML "go.yaml.in/yaml/v3"
)

const (
	sopsAgeKeyEnvironment        = "SOPS_AGE_KEY"
	sopsAgeKeyFileEnvironment    = "SOPS_AGE_KEY_FILE"
	sopsAgeKeyCommandEnvironment = "SOPS_AGE_KEY_CMD"
	sopsAgeRecipientEnvironment  = "SOPS_AGE_RECIPIENT"
	sopsAgeDefaultKeyFile        = "sops/age/keys.txt"
	sopsMetadataVersion          = "3.13.3"
	sopsNonceSize                = 32
	sopsCommandTimeout           = 30 * time.Second
)

type encryptedDocument struct {
	SchemaVersion string                   `yaml:"schemaVersion"`
	Forgejo       encryptedForgejoSecrets  `yaml:"forgejo"`
	Harbor        encryptedHarborSecrets   `yaml:"harbor"`
	Identity      encryptedIdentitySecrets `yaml:"identity"`
	SOPS          ageMetadata              `yaml:"sops"`
}

type encryptedIdentitySecrets struct {
	Seed string `yaml:"seed"`
}

type encryptedForgejoSecrets struct {
	Username      string `yaml:"username"`
	AdminPassword string `yaml:"adminPassword"`
}

type encryptedHarborSecrets struct {
	AdminPassword string `yaml:"adminPassword"`
	SecretKey     string `yaml:"secretKey"`
}

type ageMetadata struct {
	Age               []ageEnvelope `yaml:"age"`
	LastModified      string        `yaml:"lastmodified"`
	MAC               string        `yaml:"mac"`
	UnencryptedSuffix string        `yaml:"unencrypted_suffix,omitempty"`
	Version           string        `yaml:"version"`
}

type ageEnvelope struct {
	EncryptedKey string `yaml:"enc"`
	Recipient    string `yaml:"recipient"`
}

func encryptDocument(document Document, recipientStrings []string) ([]byte, error) {
	recipients := make([]filippoage.Recipient, 0, len(recipientStrings))
	recipientNames := make([]string, 0, len(recipientStrings))
	seen := make(map[string]struct{}, len(recipientStrings))
	for _, name := range recipientStrings {
		name = strings.TrimSpace(name)
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		parsed, err := filippoage.ParseRecipients(strings.NewReader(name + "\n"))
		if err != nil {
			return nil, fmt.Errorf("parse age recipient %q: %w", name, err)
		}
		if len(parsed) != 1 {
			return nil, fmt.Errorf("parse age recipient %q: got %d recipients, want 1", name, len(parsed))
		}
		seen[name] = struct{}{}
		recipients = append(recipients, parsed[0])
		recipientNames = append(recipientNames, name)
	}
	if len(recipients) == 0 {
		return nil, errors.New("no unique age recipients were supplied")
	}

	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, fmt.Errorf("generate SOPS data key: %w", err)
	}
	defer clear(dataKey)
	encrypted := encryptedDocument{}
	fields := []struct {
		plain string
		path  string
		set   func(string)
	}{
		{document.SchemaVersion, "schemaVersion:", func(value string) { encrypted.SchemaVersion = value }},
		{document.Forgejo.Username, "forgejo:username:", func(value string) { encrypted.Forgejo.Username = value }},
		{document.Forgejo.AdminPassword, "forgejo:adminPassword:", func(value string) { encrypted.Forgejo.AdminPassword = value }},
		{document.Harbor.AdminPassword, "harbor:adminPassword:", func(value string) { encrypted.Harbor.AdminPassword = value }},
		{document.Harbor.SecretKey, "harbor:secretKey:", func(value string) { encrypted.Harbor.SecretKey = value }},
		{document.Identity.Seed, "identity:seed:", func(value string) { encrypted.Identity.Seed = value }},
	}
	for _, field := range fields {
		value, err := encryptSOPSString(field.plain, dataKey, field.path)
		if err != nil {
			return nil, fmt.Errorf("encrypt SOPS field %s: %w", field.path, err)
		}
		field.set(value)
	}

	encrypted.SOPS.Age = make([]ageEnvelope, len(recipients))
	for index, recipient := range recipients {
		wrapped, err := encryptAgeDataKey(dataKey, recipient)
		if err != nil {
			return nil, fmt.Errorf("encrypt SOPS data key for %s: %w", recipientNames[index], err)
		}
		encrypted.SOPS.Age[index] = ageEnvelope{EncryptedKey: wrapped, Recipient: recipientNames[index]}
	}
	encrypted.SOPS.LastModified = time.Now().UTC().Format(time.RFC3339)
	encrypted.SOPS.Version = sopsMetadataVersion
	mac, err := encryptSOPSString(documentMAC(document), dataKey, encrypted.SOPS.LastModified)
	if err != nil {
		return nil, fmt.Errorf("encrypt SOPS MAC: %w", err)
	}
	encrypted.SOPS.MAC = mac
	data, err := goYAML.Marshal(encrypted)
	if err != nil {
		return nil, fmt.Errorf("encode age-only SOPS document: %w", err)
	}
	return data, nil
}

func decryptDocument(data []byte) (Document, error) {
	var encrypted encryptedDocument
	if err := decodeYAML(data, &encrypted); err != nil {
		return Document{}, fmt.Errorf("decode age-only SOPS document: %w", err)
	}
	if len(encrypted.SOPS.Age) == 0 {
		return Document{}, errors.New("SOPS document has no age recipients")
	}
	if _, err := time.Parse(time.RFC3339, encrypted.SOPS.LastModified); err != nil {
		return Document{}, fmt.Errorf("parse SOPS lastmodified: %w", err)
	}
	if encrypted.SOPS.MAC == "" || encrypted.SOPS.Version == "" {
		return Document{}, errors.New("SOPS document metadata is incomplete")
	}
	if suffix := encrypted.SOPS.UnencryptedSuffix; suffix != "" && suffix != "_unencrypted" {
		return Document{}, fmt.Errorf("unsupported SOPS unencrypted suffix %q", suffix)
	}
	dataKey, err := decryptAgeDataKey(encrypted.SOPS.Age)
	if err != nil {
		return Document{}, err
	}
	defer clear(dataKey)

	document := Document{}
	fields := []struct {
		encrypted string
		path      string
		set       func(string)
	}{
		{encrypted.SchemaVersion, "schemaVersion:", func(value string) { document.SchemaVersion = value }},
		{encrypted.Forgejo.Username, "forgejo:username:", func(value string) { document.Forgejo.Username = value }},
		{encrypted.Forgejo.AdminPassword, "forgejo:adminPassword:", func(value string) { document.Forgejo.AdminPassword = value }},
		{encrypted.Harbor.AdminPassword, "harbor:adminPassword:", func(value string) { document.Harbor.AdminPassword = value }},
		{encrypted.Harbor.SecretKey, "harbor:secretKey:", func(value string) { document.Harbor.SecretKey = value }},
	}
	if encrypted.Identity.Seed != "" {
		fields = append(fields, struct {
			encrypted string
			path      string
			set       func(string)
		}{encrypted.Identity.Seed, "identity:seed:", func(value string) { document.Identity.Seed = value }})
	}
	for _, field := range fields {
		value, err := decryptSOPSString(field.encrypted, dataKey, field.path)
		if err != nil {
			return Document{}, fmt.Errorf("decrypt SOPS field %s: %w", field.path, err)
		}
		field.set(value)
	}
	storedMAC, err := decryptSOPSString(encrypted.SOPS.MAC, dataKey, encrypted.SOPS.LastModified)
	if err != nil {
		return Document{}, fmt.Errorf("decrypt SOPS MAC: %w", err)
	}
	expectedMAC := documentMAC(document)
	if subtle.ConstantTimeCompare([]byte(storedMAC), []byte(expectedMAC)) != 1 {
		return Document{}, errors.New("SOPS document integrity check failed")
	}
	return document, nil
}

func documentMAC(document Document) string {
	hash := sha512.New()
	_, _ = io.WriteString(hash, document.SchemaVersion)
	_, _ = io.WriteString(hash, document.Forgejo.Username)
	_, _ = io.WriteString(hash, document.Forgejo.AdminPassword)
	_, _ = io.WriteString(hash, document.Harbor.AdminPassword)
	_, _ = io.WriteString(hash, document.Harbor.SecretKey)
	if document.SchemaVersion != schemaVersionV1 {
		_, _ = io.WriteString(hash, document.Identity.Seed)
	}
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
}

func encryptSOPSString(plain string, key []byte, additionalData string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, sopsNonceSize)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, sopsNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plain), []byte(additionalData))
	dataEnd := len(sealed) - gcm.Overhead()
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:str]",
		base64.StdEncoding.EncodeToString(sealed[:dataEnd]),
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(sealed[dataEnd:])), nil
}

func decryptSOPSString(encrypted string, key []byte, additionalData string) (string, error) {
	const prefix = "ENC[AES256_GCM,"
	if !strings.HasPrefix(encrypted, prefix) || !strings.HasSuffix(encrypted, "]") {
		return "", errors.New("value is not AES256_GCM SOPS ciphertext")
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(encrypted, prefix), "]"), ",")
	if len(parts) != 4 || parts[3] != "type:str" || !strings.HasPrefix(parts[0], "data:") ||
		!strings.HasPrefix(parts[1], "iv:") || !strings.HasPrefix(parts[2], "tag:") {
		return "", errors.New("SOPS ciphertext fields are invalid")
	}
	encoded := [...]string{
		strings.TrimPrefix(parts[0], "data:"),
		strings.TrimPrefix(parts[1], "iv:"),
		strings.TrimPrefix(parts[2], "tag:"),
	}
	decoded := [3][]byte{}
	for index := range encoded {
		value, err := base64.StdEncoding.DecodeString(encoded[index])
		if err != nil {
			return "", fmt.Errorf("decode SOPS ciphertext component %d: %w", index, err)
		}
		decoded[index] = value
	}
	if len(decoded[1]) != sopsNonceSize || len(decoded[2]) != aes.BlockSize {
		return "", errors.New("SOPS ciphertext nonce or tag has an invalid size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(decoded[1]))
	if err != nil {
		return "", err
	}
	sealed := make([]byte, len(decoded[0])+len(decoded[2]))
	copy(sealed, decoded[0])
	copy(sealed[len(decoded[0]):], decoded[2])
	plain, err := gcm.Open(nil, decoded[1], sealed, []byte(additionalData))
	if err != nil {
		return "", fmt.Errorf("authenticate SOPS ciphertext: %w", err)
	}
	return string(plain), nil
}

func encryptAgeDataKey(dataKey []byte, recipient filippoage.Recipient) (string, error) {
	var buffer bytes.Buffer
	armored := armor.NewWriter(&buffer)
	writer, err := filippoage.Encrypt(armored, recipient)
	if err != nil {
		_ = armored.Close()
		return "", err
	}
	if _, err := writer.Write(dataKey); err != nil {
		_ = writer.Close()
		_ = armored.Close()
		return "", err
	}
	if err := writer.Close(); err != nil {
		_ = armored.Close()
		return "", err
	}
	if err := armored.Close(); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func decryptAgeDataKey(envelopes []ageEnvelope) ([]byte, error) {
	identities, identityErrors := loadAgeIdentities()
	var attempts []error
	for _, envelope := range envelopes {
		if envelope.Recipient == "" || envelope.EncryptedKey == "" {
			attempts = append(attempts, errors.New("SOPS age recipient metadata is incomplete"))
			continue
		}
		if key, err := openAgeDataKey(envelope.EncryptedKey, identities); err == nil {
			return key, nil
		} else {
			attempts = append(attempts, err)
		}
		commandIdentities, err := loadCommandAgeIdentities(envelope.Recipient)
		if err != nil {
			attempts = append(attempts, err)
			continue
		}
		if key, err := openAgeDataKey(envelope.EncryptedKey, commandIdentities); err == nil {
			return key, nil
		} else {
			attempts = append(attempts, err)
		}
	}
	attempts = append(attempts, identityErrors...)
	if len(attempts) == 0 {
		return nil, errors.New("no age identities are available")
	}
	return nil, fmt.Errorf("no age identity decrypted the SOPS data key: %w", errors.Join(attempts...))
}

func openAgeDataKey(encrypted string, identities []filippoage.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("no age identities loaded")
	}
	reader, err := filippoage.Decrypt(armor.NewReader(strings.NewReader(encrypted)), identities...)
	if err != nil {
		return nil, err
	}
	key, err := io.ReadAll(io.LimitReader(reader, 33))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		clear(key)
		return nil, fmt.Errorf("decrypted SOPS data key is %d bytes, want 32", len(key))
	}
	return key, nil
}

func loadAgeIdentities() ([]filippoage.Identity, []error) {
	identities := make([]filippoage.Identity, 0, 4)
	var problems []error
	if value := strings.TrimSpace(os.Getenv(sopsAgeKeyEnvironment)); value != "" {
		parsed, err := parseAgeIdentities(strings.NewReader(strings.Join(strings.Fields(value), "\n")), sopsAgeKeyEnvironment)
		if err != nil {
			problems = append(problems, err)
		} else {
			identities = append(identities, parsed...)
		}
	}
	if path := strings.TrimSpace(os.Getenv(sopsAgeKeyFileEnvironment)); path != "" {
		parsed, err := readAgeIdentityFile(path, sopsAgeKeyFileEnvironment)
		if err != nil {
			problems = append(problems, err)
		} else {
			identities = append(identities, parsed...)
		}
	}
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		problems = append(problems, fmt.Errorf("resolve user config directory: %w", err))
	} else {
		path := filepath.Join(configDirectory, filepath.FromSlash(sopsAgeDefaultKeyFile))
		parsed, err := readAgeIdentityFile(path, path)
		if err == nil {
			identities = append(identities, parsed...)
		} else if !errors.Is(err, os.ErrNotExist) {
			problems = append(problems, err)
		}
	}
	return identities, problems
}

func loadCommandAgeIdentities(recipient string) ([]filippoage.Identity, error) {
	commandLine := strings.TrimSpace(os.Getenv(sopsAgeKeyCommandEnvironment))
	if commandLine == "" {
		return nil, errors.New("SOPS_AGE_KEY_CMD is not configured")
	}
	arguments, err := shlex.Split(commandLine)
	if err != nil {
		return nil, fmt.Errorf("parse SOPS_AGE_KEY_CMD: %w", err)
	}
	if len(arguments) == 0 {
		return nil, errors.New("SOPS_AGE_KEY_CMD is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sopsCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	command.Env = append(os.Environ(), sopsAgeRecipientEnvironment+"="+recipient)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("run SOPS_AGE_KEY_CMD: %w", err)
	}
	defer clear(output)
	return parseAgeIdentities(bytes.NewReader(output), sopsAgeKeyCommandEnvironment)
}

func readAgeIdentityFile(path, label string) ([]filippoage.Identity, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	return parseAgeIdentities(file, label)
}

func parseAgeIdentities(reader io.Reader, label string) ([]filippoage.Identity, error) {
	identities, err := filippoage.ParseIdentities(reader)
	if err != nil {
		return nil, fmt.Errorf("parse age identities from %s: %w", label, err)
	}
	return identities, nil
}
