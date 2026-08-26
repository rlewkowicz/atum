package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/treehash"

	"gopkg.in/yaml.v3"
)

type candidateTree struct {
	root                string
	originals           map[string]managedVersion
	candidates          map[string]managedVersion
	completeDirectories map[string]struct{}
}

func newCandidateTree(root string) *candidateTree {
	return &candidateTree{
		root:                root,
		originals:           make(map[string]managedVersion),
		candidates:          make(map[string]managedVersion),
		completeDirectories: make(map[string]struct{}),
	}
}

func (tree *candidateTree) Track(relative string) (managedVersion, error) {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return managedVersion{}, err
	}
	if current, exists := tree.originals[clean]; exists {
		return current, nil
	}
	current, err := snapshotManagedFile(tree.root, clean)
	if err != nil {
		return managedVersion{}, err
	}
	tree.originals[clean] = current
	tree.candidates[clean] = current
	return current, nil
}

func (tree *candidateTree) Data(relative string) ([]byte, error) {
	current, err := tree.Track(relative)
	if err != nil {
		return nil, err
	}
	if !current.exists {
		return nil, fmt.Errorf("managed file %s does not exist", relative)
	}
	return append([]byte(nil), current.data...), nil
}

func (tree *candidateTree) CandidateData(relative string) ([]byte, error) {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return nil, err
	}
	if _, err := tree.Track(clean); err != nil {
		return nil, err
	}
	candidate := tree.candidates[clean]
	if !candidate.exists {
		return nil, fmt.Errorf("managed candidate file %s does not exist", clean)
	}
	return append([]byte(nil), candidate.data...), nil
}

func (tree *candidateTree) YAML(relative string) (map[string]any, error) {
	data, err := tree.Data(relative)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode managed YAML %s: %w", relative, err)
	}
	if value == nil {
		value = make(map[string]any)
	}
	return value, nil
}

func readManagedYAML(root string, files map[string][]byte, relative string) (map[string]any, error) {
	clean, data, err := fssecure.ReadRegularCandidate(root, relative, files)
	if err != nil {
		return nil, fmt.Errorf("read managed YAML %s: %w", relative, err)
	}
	var value map[string]any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("decode managed YAML %s: %w", clean, err)
	}
	if value == nil {
		value = make(map[string]any)
	}
	return value, nil
}

func (tree *candidateTree) Set(relative string, data []byte) error {
	current, err := tree.Track(relative)
	if err != nil {
		return err
	}
	mode := current.mode
	if !current.exists {
		mode = 0o644
	}
	tree.candidates[filepath.Clean(relative)] = managedVersion{
		exists: true,
		mode:   mode,
		digest: hashBytes(data),
		data:   append([]byte(nil), data...),
	}
	return nil
}

func (tree *candidateTree) SetYAML(relative string, value map[string]any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode managed YAML %s: %w", relative, err)
	}
	return tree.Set(relative, data)
}

func (tree *candidateTree) Delete(relative string) error {
	if _, err := tree.Track(relative); err != nil {
		return err
	}
	tree.candidates[filepath.Clean(relative)] = managedVersion{}
	return nil
}

// filesView returns a point-in-time map over immutable candidate byte slices.
// Update code treats these slices as read-only, avoiding repeated full-tree
// copies while retaining map snapshot semantics as candidates are replaced.
func (tree *candidateTree) filesView() map[string][]byte {
	files := make(map[string][]byte, len(tree.candidates))
	for relative, candidate := range tree.candidates {
		if candidate.exists {
			files[relative] = candidate.data
		}
	}
	return files
}

func (tree *candidateTree) ValidationFiles() config.CandidateFiles {
	files := make(map[string]config.CandidateFile, len(tree.candidates))
	for relative, candidate := range tree.candidates {
		files[relative] = config.CandidateFile{
			Data:   append([]byte(nil), candidate.data...),
			Mode:   os.FileMode(candidate.mode),
			Exists: candidate.exists,
		}
	}
	directories := make(map[string]struct{}, len(tree.completeDirectories))
	for directory := range tree.completeDirectories {
		directories[directory] = struct{}{}
	}
	return config.CandidateFiles{Files: files, CompleteDirectories: directories}
}

func (tree *candidateTree) Transaction() (*fileTransaction, error) {
	transaction := newFileTransaction(tree.root)
	paths := make([]string, 0, len(tree.candidates))
	for relative := range tree.candidates {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		original := tree.originals[relative]
		candidate := tree.candidates[relative]
		var err error
		if candidate.exists {
			err = transaction.AddMode(relative, candidate.data, os.FileMode(candidate.mode), original)
		} else {
			err = transaction.Delete(relative, original)
		}
		if err != nil {
			return nil, err
		}
	}
	for directory := range tree.completeDirectories {
		expected, err := managedDirectoryDigest(directory, tree.originals)
		if err != nil {
			return nil, err
		}
		if err := transaction.GuardDirectory(directory, expected); err != nil {
			return nil, err
		}
	}
	return transaction, nil
}

func (tree *candidateTree) ReplaceDirectory(relative, candidateDirectory string) error {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return err
	}
	tree.completeDirectories[clean] = struct{}{}
	currentRoot, err := fssecure.Resolve(tree.root, clean, false)
	if err != nil {
		return err
	}
	current, err := regularTreeFiles(currentRoot)
	if err != nil {
		return fmt.Errorf("inspect tracked tree %s: %w", clean, err)
	}
	for path := range current {
		managed := filepath.Clean(filepath.Join(clean, path))
		if _, tracked := tree.originals[managed]; !tracked {
			return fmt.Errorf("tracked tree %s gained %s while upstream updates were resolving; retry without discarding the concurrent edit", clean, path)
		}
	}
	candidate, err := regularTreeFiles(candidateDirectory)
	if err != nil {
		return fmt.Errorf("inspect candidate tree %s: %w", clean, err)
	}
	paths := make(map[string]struct{}, len(current)+len(candidate))
	for path := range current {
		paths[path] = struct{}{}
	}
	for path := range candidate {
		paths[path] = struct{}{}
	}
	for path := range paths {
		managed := filepath.Join(clean, path)
		if _, exists := candidate[path]; !exists {
			if err := tree.Delete(managed); err != nil {
				return err
			}
			continue
		}
		if _, err := tree.Track(managed); err != nil {
			return err
		}
		state := candidate[path]
		tree.candidates[filepath.Clean(managed)] = state
	}
	return nil
}

func regularTreeFiles(root string) (map[string]managedVersion, error) {
	result := make(map[string]managedVersion)
	err := fssecure.WalkRegularFiles(root, func(path, relative string, info os.FileInfo) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[filepath.FromSlash(relative)] = managedVersion{
			exists: true,
			mode:   uint32(info.Mode().Perm()),
			digest: hashBytes(data),
			data:   data,
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return result, err
}

func managedDirectoryDigest(directory string, files map[string]managedVersion) (string, error) {
	prefix := filepath.Clean(directory) + string(filepath.Separator)
	entries := make([]treehash.File, 0, 64)
	for relative, file := range files {
		clean := filepath.Clean(relative)
		if !file.exists || !strings.HasPrefix(clean, prefix) {
			continue
		}
		entries = append(entries, treehash.File{
			Path: filepath.ToSlash(strings.TrimPrefix(clean, prefix)),
			Mode: os.FileMode(file.mode),
			Data: file.data,
		})
	}
	return treehash.Sum(entries)
}

func snapshotDirectoryDigest(root, relative string) (string, error) {
	directory, err := fssecure.Resolve(root, relative, false)
	if err != nil {
		return "", err
	}
	files, err := regularTreeFiles(directory)
	if err != nil {
		return "", err
	}
	entries := make([]treehash.File, 0, len(files))
	for relative, file := range files {
		entries = append(entries, treehash.File{
			Path: filepath.ToSlash(relative),
			Mode: os.FileMode(file.mode),
			Data: file.data,
		})
	}
	return treehash.Sum(entries)
}

func trackUpdateInputs(tree *candidateTree, desired config.Document) error {
	clusterRoot := filepath.Join(
		desired.Platform.Directory,
		"clusters",
		desired.Project.Cluster,
	)
	paths := []string{
		config.DesiredFilename,
		config.LockFilename,
		"atum.schema.json",
		"atum.lock.schema.json",
		desired.Platform.Values.Operational,
		desired.Platform.Values.Generated,
		"platform/apps/bigbang/helmrelease.yaml",
		"platform/apps/bigbang/kustomization.yaml",
		"platform/apps/bigbang/source-bigbang.yaml",
		"platform/apps/bigbang/source-opensearch.yaml",
		"platform/apps/bigbang/source-opensearch-operator.yaml",
		"platform/apps/atum-operator/kustomization.yaml",
		"platform/apps/atum-operator/crd.yaml",
		"platform/apps/atum-operator/service-account.yaml",
		"platform/apps/atum-operator/rbac.yaml",
		"platform/apps/atum-operator/certificate.yaml",
		"platform/apps/atum-operator/deployment.yaml",
		"platform/apps/atum-operator/network-policy.yaml",
		"platform/apps/atum-operator/configuration.yaml",
		"platform/apps/prep/kustomization.yaml",
		"platform/apps/prep/namespace.yaml",
		filepath.Join(clusterRoot, "bigbang.yaml"),
		filepath.Join(clusterRoot, "atum-operator.yaml"),
		filepath.Join(clusterRoot, "kustomization.yaml"),
		filepath.Join(clusterRoot, "platform-profile-access.yaml"),
		filepath.Join(clusterRoot, "platform-certificates.yaml"),
		filepath.Join(clusterRoot, "platform-profile-identity.yaml"),
		filepath.Join(clusterRoot, "platform-profile-prep.yaml"),
		filepath.Join(clusterRoot, "platform-secrets.yaml"),
		filepath.Join(clusterRoot, "prep.yaml"),
		filepath.Join(clusterRoot, "flux-system", "platform-profile.yaml"),
		filepath.Join(clusterRoot, "flux-system", "gotk-sync.yaml"),
		"platform/build/.dockerignore",
		"platform/build/docker-bake.hcl",
	}
	for _, profile := range desired.Platform.Values.SortedProfileNames() {
		valuesPath := desired.Platform.Values.Profiles[profile]
		profileRoot := filepath.Dir(filepath.Dir(valuesPath))
		paths = append(paths,
			valuesPath,
			filepath.Join(filepath.Dir(valuesPath), "kustomization.yaml"),
			filepath.Join(filepath.Dir(valuesPath), "stateful-values.yaml"),
			filepath.Join(profileRoot, "access", "kustomization.yaml"),
		)
		if profile == "local" {
			paths = append(paths,
				filepath.Join(profileRoot, "identity", "contract.yaml"),
				filepath.Join(profileRoot, "identity", "kustomization.yaml"),
				filepath.Join(profileRoot, "identity", "credentials.yaml"),
				filepath.Join(profileRoot, "identity", "keycloak-reconcile.yaml"),
				filepath.Join(profileRoot, "identity", "vault-reconcile.yaml"),
				filepath.Join(profileRoot, "identity", "receipt.yaml"),
				filepath.Join(profileRoot, "prep", "identity-values.yaml"),
				filepath.Join(profileRoot, "prep", "certificates", "kustomization.yaml"),
				filepath.Join(profileRoot, "prep", "certificates", "ca-issuer.yaml"),
				filepath.Join(profileRoot, "prep", "certificates", "identity-certificate.yaml"),
				filepath.Join(profileRoot, "access", "certificates", "kustomization.yaml"),
				filepath.Join(profileRoot, "access", "certificates", "harbor-sso-ca.yaml"),
				filepath.Join(profileRoot, "access", "certificates", "keycloak-sso-ca.yaml"),
				filepath.Join(profileRoot, "access", "certificates", "vault-sso-ca.yaml"),
			)
		}
	}
	templateDirectory, err := fssecure.Resolve(tree.root, identityTemplateRoot, false)
	if err != nil {
		return err
	}
	err = fssecure.WalkRegularFiles(templateDirectory, func(_ string, relative string, _ os.FileInfo) error {
		paths = append(paths, filepath.ToSlash(filepath.Join(identityTemplateRoot, relative)))
		return nil
	})
	if err != nil {
		return fmt.Errorf("snapshot identity templates: %w", err)
	}
	secretsTemplateDirectory, err := fssecure.Resolve(tree.root, "platform/templates/secrets", false)
	if err != nil {
		return err
	}
	err = fssecure.WalkRegularFiles(secretsTemplateDirectory, func(_ string, relative string, _ os.FileInfo) error {
		paths = append(paths, filepath.ToSlash(filepath.Join("platform/templates/secrets", relative)))
		return nil
	})
	if err != nil {
		return fmt.Errorf("snapshot secret templates: %w", err)
	}
	for _, asset := range desired.Platform.Flux.Assets {
		paths = append(paths, asset.File, filepath.Join(filepath.Dir(asset.File), "kustomization.yaml"))
	}
	for _, chart := range desired.Platform.Bootstrap.Charts {
		paths = append(paths,
			chart.Values,
			chart.FluxSource,
			filepath.Join(filepath.Dir(chart.Values), "helmrelease.yaml"),
			filepath.Join(filepath.Dir(chart.Values), "kustomization.yaml"),
			filepath.Join(filepath.Dir(chart.Values), "namespace.yaml"),
		)
	}
	for _, source := range projectGitSourcesForUpdate(desired) {
		for _, patch := range source.Patches {
			paths = append(paths, patch)
		}
		for _, asset := range source.Assets {
			paths = append(paths, asset.File)
		}
	}
	for _, vendor := range desired.Platform.Vendors {
		paths = append(paths, vendor.Patches...)
		vendorRoot, err := fssecure.Resolve(tree.root, vendor.Directory, false)
		if err != nil {
			return err
		}
		vendorFiles, err := regularTreeFiles(vendorRoot)
		if err != nil {
			return fmt.Errorf("snapshot vendor tree %s: %w", vendor.ID, err)
		}
		tree.completeDirectories[filepath.Clean(vendor.Directory)] = struct{}{}
		for relative, state := range vendorFiles {
			managed, err := fssecure.Relative(filepath.Join(vendor.Directory, relative))
			if err != nil {
				return err
			}
			if _, tracked := tree.originals[managed]; tracked {
				continue
			}
			tree.originals[managed] = state
			tree.candidates[managed] = state
		}
	}
	dockerDirectory, err := fssecure.Resolve(tree.root, "platform/build/docker", false)
	if err != nil {
		return err
	}
	dockerfiles, err := os.ReadDir(dockerDirectory)
	if err != nil {
		return err
	}
	for _, entry := range dockerfiles {
		if !entry.IsDir() && len(entry.Name()) >= len("Dockerfile") && entry.Name()[:len("Dockerfile")] == "Dockerfile" {
			paths = append(paths, filepath.ToSlash(filepath.Join("platform/build/docker", entry.Name())))
		}
	}
	compatDirectory, err := fssecure.Resolve(tree.root, "platform/build/compat", false)
	if err != nil {
		return err
	}
	err = fssecure.WalkRegularFiles(compatDirectory, func(_ string, relative string, _ os.FileInfo) error {
		paths = append(paths, filepath.ToSlash(filepath.Join("platform/build/compat", relative)))
		return nil
	})
	if err != nil {
		return err
	}
	for _, root := range []string{"cmd/atum-operator", "operator"} {
		directory, err := fssecure.Resolve(tree.root, root, false)
		if err != nil { return err }
		if err := fssecure.WalkRegularFiles(directory, func(_ string, relative string, _ os.FileInfo) error {
			paths = append(paths, filepath.ToSlash(filepath.Join(root, relative)))
			return nil
		}); err != nil {
			return fmt.Errorf("snapshot first-party build source %s: %w", root, err)
		}
	}
	paths = append(paths, "go.mod", "go.sum")
	seen := make(map[string]struct{}, len(paths))
	for _, relative := range paths {
		clean, err := fssecure.Relative(relative)
		if err != nil {
			return err
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		if _, err := tree.Track(clean); err != nil {
			return err
		}
	}
	return nil
}

func projectGitSourcesForUpdate(desired config.Document) []config.GitSource {
	sources := make([]config.GitSource, 0, 2+len(desired.Orchestration.Releases)+len(desired.Platform.Packages)+len(desired.Platform.Vendors))
	for _, release := range desired.Orchestration.Releases {
		sources = append(sources, release.Kubespray)
	}
	sources = append(sources, desired.Platform.BigBang, desired.Platform.Flux)
	for _, pkg := range desired.Platform.Packages {
		sources = append(sources, pkg.Source)
	}
	for _, vendor := range desired.Platform.Vendors {
		sources = append(sources, vendor.Source)
	}
	return sources
}
