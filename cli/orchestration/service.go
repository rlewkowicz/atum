package orchestration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitcache"
	"atum/cli/kube"
	"atum/cli/process"
	"atum/cli/progress"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

const toolLockRetry = 100 * time.Millisecond

type Service struct {
	Project        *config.Project
	Runner         process.Runner
	Logger         *slog.Logger
	Env            func(string) string
	PythonBin      string
	PythonIdentity string
	SSHBin         string
	FirewallBin    string
	RootCAPEM      []byte
}

type Toolchain struct {
	Release        config.ClusterRelease
	Source         string
	AnsibleAdHoc   string
	Ansible        string
	Environment    []string
	IdentitySHA256 string
}

type toolIdentity struct {
	SchemaVersion   string `json:"schemaVersion"`
	KubesprayCommit string `json:"kubesprayCommit"`
	RequirementsSHA string `json:"requirementsSha256"`
	Python          string `json:"python"`
	HostPlatform    string `json:"hostPlatform"`
}

type kubesprayChecksums struct {
	Kubelet map[string]map[string]string `yaml:"kubelet_checksums"`
	Kubeadm map[string]map[string]string `yaml:"kubeadm_checksums"`
	Kubectl map[string]map[string]string `yaml:"kubectl_checksums"`
}

// ClearLocalState removes artifacts derived from a cluster after Terraform
// has successfully destroyed it. Terraform remains the sole owner of the
// infrastructure; these ignored files belong to Atum's orchestration plane.
func (service Service) ClearLocalState() error {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	inventory := service.Project.Desired.Orchestration.Inventory
	if err := fssecure.RemoveRegular(
		service.Project.Root,
		filepath.Join(inventory, "hosts.yaml"),
	); err != nil {
		return err
	}
	return fssecure.RemoveTree(service.Project.Root, filepath.Join(inventory, "artifacts"))
}

func (service Service) Prepare(ctx context.Context) ([]Toolchain, error) {
	if service.Project == nil {
		return nil, errors.New("Atum project is not loaded")
	}
	return service.prepareReleases(ctx, service.Project.Desired.Orchestration.Releases)
}

func (service Service) prepareReleases(ctx context.Context, releases []config.ClusterRelease) ([]Toolchain, error) {
	toolchains := make([]Toolchain, len(releases))
	type preparation struct {
		releases []config.ClusterRelease
		indexes  []int
	}
	preparations := make([]preparation, 0, len(releases))
	byCommit := make(map[string]int, len(releases))
	for index, release := range releases {
		if preparationIndex, exists := byCommit[release.Kubespray.Commit]; exists {
			preparations[preparationIndex].releases = append(preparations[preparationIndex].releases, release)
			preparations[preparationIndex].indexes = append(preparations[preparationIndex].indexes, index)
			continue
		}
		byCommit[release.Kubespray.Commit] = len(preparations)
		preparations = append(preparations, preparation{
			releases: []config.ClusterRelease{release},
			indexes:  []int{index},
		})
	}
	group, groupContext := errgroup.WithContext(ctx)
	limit := min(config.EffectiveWorkLimit(
		0,
		service.Project.Desired.Updates.Parallelism,
		config.DefaultWorkLimit,
	), 2)
	group.SetLimit(limit)
	for index := range preparations {
		index := index
		group.Go(func() error {
			work := preparations[index]
			primary := work.releases[0]
			id := "toolchain:" + primary.Kubespray.Commit
			label := "Kubespray " + primary.Kubespray.Version
			progress.Start(groupContext, progress.Orchestration, id, label, "hydrating exact toolchain")
			toolchain, err := service.prepareRelease(groupContext, primary, work.releases)
			if err != nil {
				progress.Fail(groupContext, progress.Orchestration, id, label, err)
				return fmt.Errorf("prepare Kubernetes %s with Kubespray %s: %w",
					primary.Kubernetes, primary.Kubespray.Version, err)
			}
			for _, releaseIndex := range work.indexes {
				resolved := toolchain
				resolved.Release = releases[releaseIndex]
				toolchains[releaseIndex] = resolved
			}
			progress.Done(groupContext, progress.Orchestration, id, label, "cache ready")
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return toolchains, nil
}

func (service Service) prepareRelease(
	ctx context.Context,
	release config.ClusterRelease,
	checksumReleases []config.ClusterRelease,
) (Toolchain, error) {
	root := service.Project.Root
	id := "toolchain:" + release.Kubespray.Commit
	label := "Kubespray " + release.Kubespray.Version
	cache := gitcache.New(root)
	source, err := cache.Hydrate(ctx, "kubespray", release.Kubespray.URL, gitcache.Release{
		Version: release.Kubespray.Version,
		Commit:  release.Kubespray.Commit,
	})
	if err != nil {
		return Toolchain{}, err
	}
	for _, relative := range []string{"cluster.yml", "upgrade-cluster.yml", "requirements.txt"} {
		info, statErr := os.Lstat(filepath.Join(source, relative))
		if statErr != nil || !info.Mode().IsRegular() {
			return Toolchain{}, fmt.Errorf("locked Kubespray source has no regular %s", relative)
		}
	}
	if err := verifyReleaseChecksums(source, checksumReleases); err != nil {
		return Toolchain{}, err
	}
	for _, locked := range checksumReleases {
		if err := kube.ValidateKubesprayScopedAnonymousLifecycle(
			source,
			locked.Kubernetes,
		); err != nil {
			return Toolchain{}, fmt.Errorf(
				"locked Kubespray %s (%s) for Kubernetes %s fails scoped-anonymous lifecycle admission: %w",
				locked.Kubespray.Version,
				locked.Kubespray.Commit,
				locked.Kubernetes,
				err,
			)
		}
	}
	progress.Update(ctx, progress.Orchestration, id, label, "source and Kubernetes checksums verified", 0, 0)
	python, pythonIdentity, err := service.python()
	if err != nil {
		return Toolchain{}, err
	}
	sourceRequirements, err := readRegularLimit(filepath.Join(source, "requirements.txt"), 4<<20)
	if err != nil {
		return Toolchain{}, err
	}
	overlayRelative := filepath.Join(service.Project.Desired.Orchestration.Directory, "requirements.txt")
	overlay, err := fssecure.OpenRegular(root, overlayRelative)
	if err != nil {
		return Toolchain{}, fmt.Errorf("open orchestration requirements: %w", err)
	}
	overlayRequirements, readErr := io.ReadAll(io.LimitReader(overlay, (1<<20)+1))
	closeErr := overlay.Close()
	if readErr != nil {
		return Toolchain{}, readErr
	}
	if closeErr != nil {
		return Toolchain{}, closeErr
	}
	if len(overlayRequirements) > 1<<20 {
		return Toolchain{}, errors.New("orchestration requirements exceed 1 MiB")
	}
	mitogen, err := pinnedMitogenRequirement(overlayRequirements)
	if err != nil {
		return Toolchain{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write(sourceRequirements)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(overlayRequirements)
	identity := toolIdentity{
		SchemaVersion:   "atum.dev/kubespray-tool/v1",
		KubesprayCommit: release.Kubespray.Commit,
		RequirementsSHA: hex.EncodeToString(hash.Sum(nil)),
		Python:          pythonIdentity,
		HostPlatform:    runtime.GOOS + "/" + runtime.GOARCH,
	}
	identityData, err := json.Marshal(identity)
	if err != nil {
		return Toolchain{}, err
	}
	identityData = append(identityData, '\n')
	toolRelative := filepath.Join(".atum", "cache", "tools", "kubespray", release.Kubespray.Commit)
	unlock, err := fssecure.LockContext(ctx, root, filepath.Join(".atum", "cache", "locks", "tool-"+release.Kubespray.Commit+".lock"), toolLockRetry)
	if err != nil {
		return Toolchain{}, err
	}
	defer unlock()
	if toolchain, current := service.currentToolchain(release, source, toolRelative, identityData); current {
		progress.Update(ctx, progress.Orchestration, id, label, "reusing exact Python package cache", 0, 0)
		return toolchain, nil
	}
	parentRelative := filepath.Dir(toolRelative)
	if _, err := fssecure.EnsureDirectory(root, parentRelative, 0o700); err != nil {
		return Toolchain{}, err
	}
	if err := fssecure.RemoveTree(root, toolRelative); err != nil {
		return Toolchain{}, err
	}
	toolPath, err := fssecure.EnsureDirectory(root, toolRelative, 0o700)
	if err != nil {
		return Toolchain{}, err
	}
	removeIncomplete := true
	defer func() {
		if removeIncomplete {
			_ = fssecure.RemoveTree(root, toolRelative)
		}
	}()
	venv := filepath.Join(toolPath, "venv")
	progress.Update(ctx, progress.Orchestration, id, label, "creating isolated Python environment", 0, 0)
	if err := service.run(ctx, process.Command{Name: python, Args: []string{"-m", "venv", venv}, Dir: root}); err != nil {
		return Toolchain{}, err
	}
	venvPython := filepath.Join(venv, "bin", "python")
	pipCache, err := fssecure.EnsureDirectory(root, filepath.Join(".atum", "cache", "pip"), 0o700)
	if err != nil {
		return Toolchain{}, err
	}
	pipEnv := []string{
		"PIP_CACHE_DIR=" + pipCache,
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
		"PIP_NO_INPUT=1",
		"PYTHONDONTWRITEBYTECODE=1",
	}
	progress.Update(ctx, progress.Orchestration, id, label, "installing pinned Kubespray packages", 0, 0)
	if err := service.run(ctx, process.Command{
		Name: venvPython,
		Args: []string{"-m", "pip", "install", "--no-input", "-r", filepath.Join(source, "requirements.txt")},
		Dir:  root,
		Env:  pipEnv,
	}); err != nil {
		return Toolchain{}, err
	}
	mitogenTarget := filepath.Join(toolPath, "mitogen")
	progress.Update(ctx, progress.Orchestration, id, label, "installing pinned Mitogen strategy", 0, 0)
	if err := service.run(ctx, process.Command{
		Name: venvPython,
		Args: []string{"-m", "pip", "install", "--no-input", "--no-deps", "--target", mitogenTarget, mitogen},
		Dir:  root,
		Env:  pipEnv,
	}); err != nil {
		return Toolchain{}, err
	}
	strategy := filepath.Join(mitogenTarget, "ansible_mitogen", "plugins", "strategy", "mitogen_linear.py")
	if info, err := os.Lstat(strategy); err != nil || !info.Mode().IsRegular() {
		return Toolchain{}, errors.New("Mitogen strategy plugin was not installed")
	}
	if err := fssecure.WriteRegular(root, filepath.Join(toolRelative, "identity.json"), identityData, 0o600); err != nil {
		return Toolchain{}, err
	}
	toolchain, current := service.currentToolchain(release, source, toolRelative, identityData)
	if !current {
		return Toolchain{}, errors.New("published Kubespray tool cache failed identity validation")
	}
	removeIncomplete = false
	return toolchain, nil
}

func verifyReleaseChecksums(source string, releases []config.ClusterRelease) error {
	data, err := readRegularLimit(filepath.Join(source, "roles", "kubespray_defaults", "vars", "main", "checksums.yml"), 32<<20)
	if err != nil {
		return fmt.Errorf("read locked Kubespray checksum matrix: %w", err)
	}
	var matrix kubesprayChecksums
	if err := yaml.Unmarshal(data, &matrix); err != nil {
		return fmt.Errorf("decode locked Kubespray checksum matrix: %w", err)
	}
	for _, release := range releases {
		want := release.Checksums
		actual := config.KubernetesChecksums{
			Kubelet: matrix.Kubelet["amd64"][release.Kubernetes],
			Kubeadm: matrix.Kubeadm["amd64"][release.Kubernetes],
			Kubectl: matrix.Kubectl["amd64"][release.Kubernetes],
		}
		if actual != want {
			return fmt.Errorf("Kubernetes %s checksums do not match Kubespray %s", release.Kubernetes, release.Kubespray.Version)
		}
	}
	return nil
}

func readRegularLimit(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("file %s is not a regular file within %d bytes", path, limit)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, limit)
	}
	return data, nil
}

func (service Service) currentToolchain(
	release config.ClusterRelease,
	source, relative string,
	want []byte,
) (Toolchain, bool) {
	root := service.Project.Root
	identityFile, err := fssecure.OpenRegular(root, filepath.Join(relative, "identity.json"))
	if err != nil {
		return Toolchain{}, false
	}
	current, readErr := io.ReadAll(io.LimitReader(identityFile, 4097))
	closeErr := identityFile.Close()
	if readErr != nil || closeErr != nil || len(current) > 4096 || !bytes.Equal(current, want) {
		return Toolchain{}, false
	}
	toolPath := filepath.Join(root, relative)
	ansibleAdHoc := filepath.Join(toolPath, "venv", "bin", "ansible")
	ansible := filepath.Join(toolPath, "venv", "bin", "ansible-playbook")
	strategy := filepath.Join(toolPath, "mitogen", "ansible_mitogen", "plugins", "strategy")
	for _, required := range []string{ansibleAdHoc, ansible, filepath.Join(strategy, "mitogen_linear.py")} {
		if info, err := os.Lstat(required); err != nil || !info.Mode().IsRegular() {
			return Toolchain{}, false
		}
	}
	cacheRoot := filepath.Join(".atum", "cache", "ansible")
	if _, err := fssecure.EnsureDirectory(root, filepath.Join(cacheRoot, "facts"), 0o700); err != nil {
		return Toolchain{}, false
	}
	ansibleConfig := filepath.Join(root, service.Project.Desired.Orchestration.Directory, "ansible.cfg")
	environment := []string{
		"ANSIBLE_CONFIG=" + ansibleConfig,
		"ANSIBLE_STRATEGY=mitogen_linear",
		"ANSIBLE_STRATEGY_PLUGINS=" + strategy,
		"ANSIBLE_LIBRARY=" + filepath.Join(source, "library") + string(os.PathListSeparator) + filepath.Join(source, "plugins", "modules"),
		"ANSIBLE_ROLES_PATH=" + filepath.Join(source, "roles"),
		"ANSIBLE_CACHE_PLUGIN_CONNECTION=" + filepath.Join(root, cacheRoot, "facts"),
		"PATH=" + prependPath(service.environment("PATH"), filepath.Join(toolPath, "venv", "bin")),
	}
	return Toolchain{
		Release:        release,
		Source:         source,
		AnsibleAdHoc:   ansibleAdHoc,
		Ansible:        ansible,
		Environment:    environment,
		IdentitySHA256: config.SHA256(want),
	}, true
}

func (service Service) python() (string, string, error) {
	if service.PythonBin != "" && service.PythonIdentity != "" {
		return service.PythonBin, service.PythonIdentity, nil
	}
	return "", "", errors.New("validated Python preflight identity is required")
}

func (service Service) run(ctx context.Context, command process.Command) error {
	if service.Runner == nil {
		return errors.New("orchestration command runner is unavailable")
	}
	if service.Logger != nil {
		service.Logger.InfoContext(ctx, "running orchestration preparation command", "name", command.Name)
	}
	if err := service.Runner.Run(ctx, command); err != nil {
		return fmt.Errorf("%s failed: %w", command.Name, err)
	}
	return nil
}

func (service Service) environment(name string) string {
	if service.Env != nil {
		return service.Env(name)
	}
	return os.Getenv(name)
}

func pinnedMitogenRequirement(data []byte) (string, error) {
	var requirement string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "mitogen==") || strings.ContainsAny(line, " \t") {
			return "", fmt.Errorf("unsupported orchestration requirement %q; only one exact Mitogen pin is allowed", line)
		}
		if requirement != "" {
			return "", errors.New("orchestration requirements contain multiple Mitogen pins")
		}
		requirement = line
	}
	if requirement == "" {
		return "", errors.New("orchestration requirements have no exact Mitogen pin")
	}
	return requirement, nil
}

func prependPath(pathValue, directory string) string {
	if pathValue == "" {
		return directory
	}
	for _, existing := range filepath.SplitList(pathValue) {
		if existing == directory {
			return pathValue
		}
	}
	return directory + string(os.PathListSeparator) + pathValue
}
