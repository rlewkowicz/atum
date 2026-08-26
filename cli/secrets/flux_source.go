package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
  - stateful.json
  - identity.json
`)

type FluxSourceResult struct {
	Paths     []string
	Recipient string
}

type encryptedFluxManifest struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
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
	files := []struct {
		name string
		data []byte
	}{
		{name: ".sops.yaml", data: sopsConfiguration},
		{name: "kustomization.yaml", data: fluxSourceKustomization},
		{name: "stateful.json", data: statefulEncrypted},
		{name: "identity.json", data: identityEncrypted},
	}
	result := FluxSourceResult{
		Paths:     make([]string, 0, len(files)),
		Recipient: ageIdentity.Recipient(),
	}
	for _, file := range files {
		relative := filepath.Join(root, file.name)
		if err := fssecure.WriteRegular(project.Root, relative, file.data, 0o644); err != nil {
			return FluxSourceResult{}, fmt.Errorf("write Flux secret source %s: %w", file.name, err)
		}
		result.Paths = append(result.Paths, filepath.ToSlash(relative))
	}
	return result, nil
}

func ValidateFluxSource(
	project *config.Project,
	statefulDigest string,
	identityDigest string,
	recipient string,
) error {
	if project == nil || statefulDigest == "" || identityDigest == "" || recipient == "" {
		return errors.New("Flux secret source validation inputs are incomplete")
	}
	root := fluxSourceRoot(project)
	kustomization, err := readFluxSourceFile(
		project.Root, filepath.Join(root, "kustomization.yaml"),
	)
	if err != nil {
		return err
	}
	defer clear(kustomization)
	if !bytes.Equal(kustomization, fluxSourceKustomization) {
		return errors.New("Flux secret source Kustomization is stale; run `atum secrets render`")
	}
	for _, expected := range []struct {
		name       string
		annotation string
		digest     string
	}{
		{name: "stateful.json", annotation: "atum.dev/stateful-digest", digest: statefulDigest},
		{name: "identity.json", annotation: "atum.dev/identity-digest", digest: identityDigest},
	} {
		data, err := readFluxSourceFile(project.Root, filepath.Join(root, expected.name))
		if err != nil {
			return err
		}
		var manifest encryptedFluxManifest
		decodeErr := json.Unmarshal(data, &manifest)
		clear(data)
		if decodeErr != nil {
			return fmt.Errorf("decode encrypted Flux source %s: %w", expected.name, decodeErr)
		}
		if manifest.Metadata.Annotations[expected.annotation] != expected.digest ||
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
		for key, value := range manifest.StringData {
			if key == "" || !strings.HasPrefix(value, "ENC[") {
				return fmt.Errorf(
					"encrypted Flux source %s contains clear or invalid stringData",
					expected.name,
				)
			}
		}
	}
	return nil
}

func FluxSourcePaths(project *config.Project) []string {
	root := fluxSourceRoot(project)
	return []string{
		filepath.ToSlash(filepath.Join(root, ".sops.yaml")),
		filepath.ToSlash(filepath.Join(root, "kustomization.yaml")),
		filepath.ToSlash(filepath.Join(root, "stateful.json")),
		filepath.ToSlash(filepath.Join(root, "identity.json")),
	}
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
