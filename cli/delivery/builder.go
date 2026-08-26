package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/process"
)

type builderIdentity struct {
	BuildKit       string `json:"buildkit"`
	Registry       string `json:"registry"`
	TLSVerify      bool   `json:"tlsVerify"`
	CA256          string `json:"ca256"`
	MaxParallelism int    `json:"maxParallelism"`
}

type dockerSession struct {
	dockerConfig string
	buildxConfig string
}

func (session dockerSession) environment() []string {
	return []string{
		"BUILDX_CONFIG=" + session.buildxConfig,
		"DOCKER_CONFIG=" + session.dockerConfig,
	}
}

func (service *Service) prepareBuilder(
	ctx context.Context,
	project *config.Project,
	session dockerSession,
	maxParallelism int,
) (string, error) {
	commandEnv := session.environment()
	buildkit, err := buildkitReference(project)
	if err != nil {
		return "", err
	}
	ca := []byte(service.env("HARBOR_CA_CRT"))
	caHash := sha256.Sum256(ca)
	identity := builderIdentity{
		BuildKit:       buildkit,
		Registry:       project.Desired.Delivery.Registry.Host,
		TLSVerify:      project.Desired.Delivery.Registry.TLSVerify,
		CA256:          hex.EncodeToString(caHash[:]),
		MaxParallelism: maxParallelism,
	}
	identityData, err := config.CanonicalJSON(identity)
	if err != nil {
		return "", err
	}
	identitySHA := config.SHA256(identityData)
	name := "atum-" + identitySHA[:16]
	stateRelative := filepath.Join(".atum", "state", "builders", identitySHA)
	stateRoot, err := fssecure.EnsureDirectory(project.Root, stateRelative, 0o700)
	if err != nil {
		return "", fmt.Errorf("create Buildx state: %w", err)
	}
	configData := strings.Builder{}
	configData.Grow(256 + len(project.Desired.Delivery.Registry.Host))
	configData.WriteString("[worker.oci]\n  max-parallelism = ")
	configData.WriteString(strconv.Itoa(identity.MaxParallelism))
	configData.WriteString("\n\n[registry.\"")
	configData.WriteString(project.Desired.Delivery.Registry.Host)
	configData.WriteString("\"]\n")
	driverOptions := []string{"image=" + buildkit, "network=host"}
	if len(ca) != 0 {
		caRelative := filepath.Join(stateRelative, "harbor-ca.crt")
		if err := fssecure.WriteRegular(project.Root, caRelative, append(ca, '\n'), 0o644); err != nil {
			return "", fmt.Errorf("write Buildx registry CA: %w", err)
		}
		caPath := filepath.Join(stateRoot, "harbor-ca.crt")
		configData.WriteString("  ca = [\"")
		configData.WriteString(caPath)
		configData.WriteString("\"]\n")
	} else if !project.Desired.Delivery.Registry.TLSVerify {
		configData.WriteString("  insecure = true\n")
	}
	configRelative := filepath.Join(stateRelative, "buildkitd.toml")
	if err := fssecure.WriteRegular(project.Root, configRelative, []byte(configData.String()), 0o600); err != nil {
		return "", fmt.Errorf("write Buildx configuration: %w", err)
	}
	if err := service.runner.Run(ctx, process.Command{
		Name: service.docker, Args: []string{"buildx", "inspect", "--builder", name, "--bootstrap"}, Env: commandEnv,
	}); err == nil {
		return name, nil
	}
	arguments := []string{"buildx", "create", "--name", name, "--driver", "docker-container"}
	_ = service.runner.Run(ctx, process.Command{
		Name: service.docker, Args: []string{"buildx", "rm", "--force", "--keep-state", name}, Env: commandEnv,
	})
	// Forgejo job containers have an ephemeral Buildx client directory while
	// the sibling Docker daemon retains its containers and volumes. Remove an
	// orphaned builder container by its exact derived name so Buildx can
	// recreate the client record and reattach the retained state volume.
	_ = service.runner.Run(ctx, process.Command{
		Name: service.docker, Args: []string{"container", "rm", "--force", "buildx_buildkit_" + name + "0"}, Env: commandEnv,
	})
	for _, option := range driverOptions {
		arguments = append(arguments, "--driver-opt", option)
	}
	arguments = append(arguments,
		"--buildkitd-config", filepath.Join(stateRoot, "buildkitd.toml"),
		"--bootstrap",
	)
	if err := service.runner.Run(ctx, process.Command{Name: service.docker, Args: arguments, Env: commandEnv}); err != nil {
		return "", fmt.Errorf("create persistent Buildx builder %s: %w", name, err)
	}
	return name, nil
}

func buildkitReference(project *config.Project) (string, error) {
	return bootstrapMirrorReference(project, "buildkit")
}

func bootstrapMirrorReference(project *config.Project, id string) (string, error) {
	for _, image := range project.Desired.Delivery.Images {
		if image.ID != id {
			continue
		}
		if image.Delivery.Default.Type != "mirror" || image.Delivery.Default.Source == "" || image.Delivery.Default.Digest == "" {
			return "", fmt.Errorf("%s delivery must be an official digest-pinned mirror", id)
		}
		return image.Delivery.Default.Source + "@" + image.Delivery.Default.Digest, nil
	}
	return "", fmt.Errorf("delivery inventory has no %s image", id)
}

func (service *Service) dockerConfig(project *config.Project, requireCredentials bool) (dockerSession, func(), error) {
	username := service.env("HARBOR_USERNAME")
	password := service.env("HARBOR_PASSWORD")
	if (username == "") != (password == "") || (requireCredentials && username == "") {
		return dockerSession{}, nil, errors.New("HARBOR_USERNAME and HARBOR_PASSWORD are required to build images")
	}
	buildxConfig, err := fssecure.EnsureDirectory(project.Root, filepath.Join(".atum", "state", "buildx"), 0o700)
	if err != nil {
		return dockerSession{}, nil, fmt.Errorf("create persistent Buildx state: %w", err)
	}
	runtimeRoot, err := fssecure.EnsureDirectory(
		project.Root,
		filepath.Join(".atum", "runtime"),
		0o700,
	)
	if err != nil {
		return dockerSession{}, nil, fmt.Errorf("create Docker runtime directory: %w", err)
	}
	directory, err := os.MkdirTemp(runtimeRoot, ".docker-auth-")
	if err != nil {
		return dockerSession{}, nil, fmt.Errorf("create Docker credential directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	auths := make(map[string]struct {
		Auth string `json:"auth"`
	}, 1)
	if username != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		auths[project.Desired.Delivery.Registry.Host] = struct {
			Auth string `json:"auth"`
		}{Auth: encoded}
	}
	data, err := json.Marshal(struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}{Auths: auths})
	if err != nil {
		cleanup()
		return dockerSession{}, nil, err
	}
	path := filepath.Join(directory, "config.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return dockerSession{}, nil, fmt.Errorf("create Docker credential file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		cleanup()
		return dockerSession{}, nil, fmt.Errorf("write Docker credential file: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return dockerSession{}, nil, fmt.Errorf("close Docker credential file: %w", err)
	}
	return dockerSession{dockerConfig: directory, buildxConfig: buildxConfig}, cleanup, nil
}
