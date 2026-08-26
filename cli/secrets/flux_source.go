package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/identity"
)

const fluxSourceEncryptedRegex = "^(data|stringData)$"

var fluxSourceKustomization = []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - operator-namespace.yaml
  - stateful.json
  - identity.json
  - operator.json
`)

var fluxPKIKustomization = []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - cert-manager-namespace.yaml
  - root-ca.json
  - ../../../profiles/local/prep/certificates
  - ../../../profiles/local/access/certificates
`)

var certManagerNamespace = []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager
`)

var operatorNamespace = []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: atum-system
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
`)

type FluxSourceResult struct {
	Paths     []string
	Recipient string
}

type encryptedFluxManifest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels,omitempty"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Type       string            `json:"type"`
	StringData map[string]string `json:"stringData"`
	SOPS       struct {
		Age []struct {
			Recipient string `json:"recipient"`
		} `json:"age"`
		EncryptedRegex string `json:"encrypted_regex"`
		MAC            string `json:"mac"`
	} `json:"sops"`
}

func RenderFluxSource(
	ctx context.Context,
	project *config.Project,
	sops SOPSAdapter,
) (FluxSourceResult, error) {
	if ctx == nil {
		return FluxSourceResult{}, errors.New("Flux secret render context is required")
	}
	if project == nil {
		return FluxSourceResult{}, errors.New("Atum project is required")
	}
	credentials, err := Load(ctx, project, sops)
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer credentials.Clear()
	stateful, err := credentials.DeriveStatefulProjection()
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer stateful.Clear()

	contractPath, found := project.Desired.ActiveIdentityContractPath()
	if !found {
		return FluxSourceResult{}, errors.New("active platform identity contract is required")
	}
	contract, err := identity.Load(project.Root, contractPath)
	if err != nil {
		return FluxSourceResult{}, err
	}
	target, found := project.Desired.ActiveTarget()
	if !found || target.LocalAccess == nil {
		return FluxSourceResult{}, errors.New("active local platform target is required")
	}
	identityProjection, err := identity.Derive(
		contract,
		credentials.Identity.Seed.Bytes(),
		project.Desired.Project.Cluster,
		target.LocalAccess.Domain,
	)
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer identityProjection.Clear()
	ageIdentity, err := EnsureFluxAgeIdentity(ctx, project)
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer ageIdentity.Clear()

	statefulPlaintext, err := stateful.MarshalKubernetesSecret()
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer clear(statefulPlaintext)
	identityPlaintext, err := identityProjection.MarshalKubernetesSecret()
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer clear(identityPlaintext)
	operatorPlaintext, err := identityProjection.MarshalOperatorSecret()
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer clear(operatorPlaintext)
	rootCAPlaintext, _, err := rootCAKubernetesSecret(credentials)
	if err != nil {
		return FluxSourceResult{}, err
	}
	defer clear(rootCAPlaintext)
	statefulEncrypted, err := sops.EncryptKubernetesSecret(
		ctx, statefulPlaintext, ageIdentity.Recipient(),
	)
	if err != nil {
		return FluxSourceResult{}, fmt.Errorf("encrypt stateful Flux Secret: %w", err)
	}
	defer clear(statefulEncrypted)
	identityEncrypted, err := sops.EncryptKubernetesSecret(
		ctx, identityPlaintext, ageIdentity.Recipient(),
	)
	if err != nil {
		return FluxSourceResult{}, fmt.Errorf("encrypt identity Flux Secret: %w", err)
	}
	defer clear(identityEncrypted)
	operatorEncrypted, err := sops.EncryptKubernetesSecret(
		ctx, operatorPlaintext, ageIdentity.Recipient(),
	)
	if err != nil {
		return FluxSourceResult{}, fmt.Errorf("encrypt operator Flux Secret: %w", err)
	}
	defer clear(operatorEncrypted)
	rootCAEncrypted, err := sops.EncryptKubernetesSecret(
		ctx, rootCAPlaintext, ageIdentity.Recipient(),
	)
	if err != nil {
		return FluxSourceResult{}, fmt.Errorf("encrypt root CA Flux Secret: %w", err)
	}
	defer clear(rootCAEncrypted)

	root := fluxSourceRoot(project)
	if _, err := fssecure.EnsureDirectory(project.Root, root, 0o755); err != nil {
		return FluxSourceResult{}, err
	}
	sopsConfiguration := []byte(fmt.Sprintf(`creation_rules:
  - path_regex: .*\.(json|yaml)$
    encrypted_regex: '%s'
    age: %s
`, fluxSourceEncryptedRegex, ageIdentity.Recipient()))
	defer clear(sopsConfiguration)
	dataByName := map[string][]byte{
		".sops.yaml":                   sopsConfiguration,
		"kustomization.yaml":           fluxSourceKustomization,
		"operator-namespace.yaml":       operatorNamespace,
		"stateful.json":                 statefulEncrypted,
		"identity.json":                 identityEncrypted,
		"operator.json":                 operatorEncrypted,
		"pki/kustomization.yaml":        fluxPKIKustomization,
		"pki/cert-manager-namespace.yaml": certManagerNamespace,
		"pki/root-ca.json":              rootCAEncrypted,
	}
	names := config.FluxSecretSourceNames()
	result := FluxSourceResult{
		Paths:     make([]string, 0, len(names)),
		Recipient: ageIdentity.Recipient(),
	}
	for _, name := range names {
		data, exists := dataByName[name]
		if !exists {
			return FluxSourceResult{}, fmt.Errorf(
				"canonical Flux secret source member %s has no rendered bytes",
				name,
			)
		}
		relative := filepath.Join(root, filepath.FromSlash(name))
		if err := fssecure.WriteRegular(project.Root, relative, data, 0o644); err != nil {
			return FluxSourceResult{}, fmt.Errorf("write Flux secret source %s: %w", name, err)
		}
		result.Paths = append(result.Paths, filepath.ToSlash(relative))
	}
	for _, obsolete := range []string{"cert-manager-namespace.yaml", "root-ca.json"} {
		if err := fssecure.RemoveRegular(project.Root, filepath.Join(root, obsolete)); err != nil {
			return FluxSourceResult{}, fmt.Errorf(
				"remove obsolete Flux secret source %s: %w",
				obsolete,
				err,
			)
		}
	}
	return result, nil
}

func rootCAKubernetesSecret(document Document) ([]byte, string, error) {
	certificate := document.RootCA.Certificate.Bytes()
	privateKey := document.RootCA.PrivateKey.Bytes()
	if len(certificate) == 0 || len(privateKey) == 0 {
		return nil, "", errors.New("root CA keypair is unavailable")
	}
	digest, err := document.RootCADigest()
	if err != nil {
		return nil, "", err
	}
	manifest := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      "atum-test-root-ca",
			"namespace": "cert-manager",
			"annotations": map[string]string{
				"atum.dev/root-ca-digest": digest,
			},
		},
		"type": "kubernetes.io/tls",
		"stringData": map[string]string{
			"tls.crt": string(certificate),
			"tls.key": string(privateKey),
		},
	}
	data, err := config.MarshalJSON(manifest)
	if err != nil {
		return nil, "", fmt.Errorf("encode root CA Flux Secret: %w", err)
	}
	return data, digest, nil
}

func (document Document) RootCADigest() (string, error) {
	certificate := document.RootCA.Certificate.Bytes()
	privateKey := document.RootCA.PrivateKey.Bytes()
	if len(certificate) == 0 || len(privateKey) == 0 {
		return "", errors.New("root CA keypair is unavailable")
	}
	hash := sha256.New()
	_, _ = hash.Write(certificate)
	_, _ = hash.Write(privateKey)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ValidateFluxSource(
	project *config.Project,
	sourceRoot string,
	statefulDigest string,
	identityDigest string,
	rootCADigest string,
	recipient string,
) error {
	if project == nil || sourceRoot == "" || statefulDigest == "" || identityDigest == "" ||
		rootCADigest == "" || recipient == "" {
		return errors.New("Flux secret source validation inputs are incomplete")
	}
	root := fluxSourceRoot(project)
	sopsConfiguration, err := readFluxSourceFile(
		sourceRoot, filepath.Join(root, ".sops.yaml"),
	)
	if err != nil {
		return err
	}
	defer clear(sopsConfiguration)
	expectedSOPSConfiguration := []byte(fmt.Sprintf(`creation_rules:
  - path_regex: .*\.(json|yaml)$
    encrypted_regex: '%s'
    age: %s
`, fluxSourceEncryptedRegex, recipient))
	defer clear(expectedSOPSConfiguration)
	if !bytes.Equal(sopsConfiguration, expectedSOPSConfiguration) {
		return errors.New("Flux SOPS configuration is stale; run `atum secrets render`")
	}
	kustomization, err := readFluxSourceFile(
		sourceRoot, filepath.Join(root, "kustomization.yaml"),
	)
	if err != nil {
		return err
	}
	defer clear(kustomization)
	if !bytes.Equal(kustomization, fluxSourceKustomization) {
		return errors.New("Flux secret source Kustomization is stale; run `atum secrets render`")
	}
	pkiKustomization, err := readFluxSourceFile(
		sourceRoot, filepath.Join(root, "pki", "kustomization.yaml"),
	)
	if err != nil {
		return err
	}
	defer clear(pkiKustomization)
	if !bytes.Equal(pkiKustomization, fluxPKIKustomization) {
		return errors.New("Flux PKI source Kustomization is stale; run `atum secrets render`")
	}
	namespace, err := readFluxSourceFile(
		sourceRoot, filepath.Join(root, "pki", "cert-manager-namespace.yaml"),
	)
	if err != nil {
		return err
	}
	defer clear(namespace)
	if !bytes.Equal(namespace, certManagerNamespace) {
		return errors.New("Flux cert-manager namespace source is stale; run `atum secrets render`")
	}
	operatorNS, err := readFluxSourceFile(
		sourceRoot, filepath.Join(root, "operator-namespace.yaml"),
	)
	if err != nil { return err }
	defer clear(operatorNS)
	if !bytes.Equal(operatorNS, operatorNamespace) {
		return errors.New("Flux Atum operator namespace source is stale; run `atum secrets render`")
	}
	for _, expected := range []struct {
		name       string
		secretName string
		namespace  string
		secretType string
		annotation string
		digest     string
	}{
		{
			name: "pki/root-ca.json", secretName: "atum-test-root-ca",
			namespace: "cert-manager", secretType: "kubernetes.io/tls",
			annotation: "atum.dev/root-ca-digest", digest: rootCADigest,
		},
		{
			name: "stateful.json", secretName: "atum-platform-stateful",
			namespace: "flux-system", secretType: "Opaque",
			annotation: "atum.dev/stateful-digest", digest: statefulDigest,
		},
		{
			name: "identity.json", secretName: "atum-platform-identity",
			namespace: "flux-system", secretType: "Opaque",
			annotation: "atum.dev/identity-digest", digest: identityDigest,
		},
		{
			name: "operator.json", secretName: "atum-provider-credentials",
			namespace: "atum-system", secretType: "Opaque",
			annotation: "atum.dev/identity-digest", digest: identityDigest,
		},
	} {
		data, err := readFluxSourceFile(sourceRoot, filepath.Join(root, expected.name))
		if err != nil {
			return err
		}
		if err := validateEncryptedFluxEnvelope(data, expected.name); err != nil {
			clear(data)
			return err
		}
		var manifest encryptedFluxManifest
		decodeErr := json.Unmarshal(data, &manifest)
		clear(data)
		if decodeErr != nil {
			return fmt.Errorf("decode encrypted Flux source %s: %w", expected.name, decodeErr)
		}
		if manifest.APIVersion != "v1" ||
			manifest.Kind != "Secret" ||
			manifest.Metadata.Name != expected.secretName ||
			manifest.Metadata.Namespace != expected.namespace ||
			manifest.Type != expected.secretType ||
			len(manifest.Metadata.Annotations) != 1 ||
			manifest.Metadata.Annotations[expected.annotation] != expected.digest ||
			manifest.SOPS.EncryptedRegex != fluxSourceEncryptedRegex ||
			manifest.SOPS.MAC == "" ||
			len(manifest.SOPS.Age) != 1 ||
			manifest.SOPS.Age[0].Recipient != recipient ||
			len(manifest.StringData) == 0 {
			return fmt.Errorf(
				"encrypted Flux source %s is stale; run `atum secrets render`",
				expected.name,
			)
		}
		if expected.namespace == "flux-system" {
			if len(manifest.Metadata.Labels) != 1 ||
				manifest.Metadata.Labels["reconcile.fluxcd.io/watch"] != "Enabled" {
				return fmt.Errorf(
					"encrypted Flux source %s has stale metadata; run `atum secrets render`",
					expected.name,
				)
			}
		} else if len(manifest.Metadata.Labels) != 0 {
			return fmt.Errorf(
				"encrypted Flux source %s has stale metadata; run `atum secrets render`",
				expected.name,
			)
		}
		for key, value := range manifest.StringData {
			if key == "" || !strings.HasPrefix(value, "ENC[") {
				return fmt.Errorf(
					"encrypted Flux source %s contains clear or invalid stringData",
					expected.name,
				)
			}
		}
	}
	expected := make(map[string]struct{}, len(config.FluxSecretSourceNames()))
	for _, name := range config.FluxSecretSourceNames() {
		expected[name] = struct{}{}
	}
	sourceDirectory, err := fssecure.Resolve(sourceRoot, root, false)
	if err != nil {
		return err
	}
	if err := fssecure.WalkRegularFiles(
		sourceDirectory,
		func(_ string, relative string, _ os.FileInfo) error {
			relative = filepath.ToSlash(relative)
			if _, exists := expected[relative]; !exists {
				return fmt.Errorf(
					"Flux secret source contains unknown member %s; run `atum secrets render`",
					relative,
				)
			}
			delete(expected, relative)
			return nil
		},
	); err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("Flux secret source is incomplete; run `atum secrets render`")
	}
	return nil
}

func validateEncryptedFluxEnvelope(data []byte, name string) error {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode encrypted Flux source %s: %w", name, err)
	}
	allowed := map[string]struct{}{
		"apiVersion": {}, "kind": {}, "metadata": {}, "type": {},
		"stringData": {}, "sops": {},
	}
	for field := range envelope {
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf(
				"encrypted Flux source %s contains unrecognized Secret field %s",
				name,
				field,
			)
		}
	}
	for _, field := range []string{"apiVersion", "kind", "metadata", "type", "stringData", "sops"} {
		if _, ok := envelope[field]; !ok {
			return fmt.Errorf(
				"encrypted Flux source %s is missing Secret field %s",
				name,
				field,
			)
		}
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(envelope["metadata"], &metadata); err != nil {
		return fmt.Errorf("decode encrypted Flux source %s metadata: %w", name, err)
	}
	metadataAllowed := map[string]struct{}{
		"name": {}, "namespace": {}, "labels": {}, "annotations": {},
	}
	for field := range metadata {
		if _, ok := metadataAllowed[field]; !ok {
			return fmt.Errorf(
				"encrypted Flux source %s contains unrecognized metadata field %s",
				name,
				field,
			)
		}
	}
	return nil
}

func FluxSourcePaths(project *config.Project) []string {
	root := fluxSourceRoot(project)
	names := config.FluxSecretSourceNames()
	result := make([]string, len(names))
	for index, name := range names {
		result[index] = filepath.ToSlash(filepath.Join(root, filepath.FromSlash(name)))
	}
	return result
}

func fluxSourceRoot(project *config.Project) string {
	return filepath.Join(
		project.Desired.Platform.Directory,
		"secrets",
		project.Desired.Project.Cluster,
	)
}

func readFluxSourceFile(root, relative string) ([]byte, error) {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return nil, fmt.Errorf(
			"read Flux secret source %s (run `atum secrets render`): %w",
			filepath.ToSlash(relative),
			err,
		)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, fileLimit+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > fileLimit {
		clear(data)
		return nil, fmt.Errorf("Flux secret source %s exceeds %d bytes", relative, fileLimit)
	}
	return data, nil
}
