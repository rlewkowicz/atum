package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/gitsnapshot"
)

// AtumSourceSHA256 identifies the current tracked Atum handoff. Publication
// receipts live beneath ignored local state, so the tracked root lock can be
// hashed without normalizing mutable delivery results.
func AtumSourceSHA256(project *Project) (string, error) {
	lockData, err := SourceLockData(project)
	if err != nil {
		return "", err
	}
	snapshot, err := gitsnapshot.Load(project.Root)
	if err != nil {
		return "", err
	}
	if err := requireSourceSnapshot(snapshot, project.Desired); err != nil {
		return "", err
	}
	identity, err := snapshot.SHA256(map[string][]byte{LockFilename: lockData})
	if err != nil {
		return "", fmt.Errorf("identify Atum source snapshot: %w", err)
	}
	return identity, nil
}

// RequiredSourceSnapshotMembers is the single inventory of paths that the
// desired platform, orchestration, generated-value, and build handoffs consume.
// Membership is checked read-only against the Git index before delivery side
// effects; the updater may still construct a candidate transaction in memory.
func RequiredSourceSnapshotMembers(desired Document) []string {
	profiles := desired.Platform.Values.SortedProfileNames()
	members := []string{
		DesiredFilename,
		LockFilename,
		"atum.schema.json",
		"atum.lock.schema.json",
		".dockerignore",
		"go.mod",
		"go.sum",
		filepath.Join(desired.Orchestration.Directory, "ansible.cfg"),
		filepath.Join(desired.Orchestration.Directory, "requirements.txt"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "all", "all.yml"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "all", "containerd.yml"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "k8s_cluster", "addons.yml"),
		filepath.Join(desired.Orchestration.Inventory, "group_vars", "k8s_cluster", "k8s-cluster.yml"),
		filepath.Join(desired.Orchestration.Inventory, "hooks", "wait-admin-rbac.yml"),
		filepath.Join(desired.Orchestration.Directory, "playbooks", "platform-secrets.yml"),
		desired.Platform.Values.Operational,
		desired.Platform.Values.Generated,
		filepath.Join(desired.Platform.Directory, "apps", "prep", "namespace.yaml"),
		filepath.Join(desired.Platform.Directory, "apps", "atum-operator")+"/",
		filepath.Join(desired.Platform.Directory, "build", "docker-bake.hcl"),
		filepath.Join(desired.Platform.Directory, "build", "docker", "Dockerfile.delivery"),
		filepath.Join(desired.Platform.Directory, "build", "docker", "Dockerfile.operator"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "bigbang.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "atum-operator.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "kustomization.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "platform-profile-access.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "platform-certificates.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "platform-profile-prep.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "platform-secrets.yaml"),
		filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster, "flux-system", "platform-profile.yaml"),
		filepath.Join(desired.Platform.Directory, "templates", "secrets", "stateful-values.yaml.tmpl"),
	}
	members = append(members, fluxSecretRequiredFiles(desired)...)
	members = append(members, generatedIdentityRequiredFiles(desired, profiles)...)
	for _, profile := range profiles {
		profileRoot := filepath.Join(desired.Platform.Directory, "profiles", profile)
		members = append(members,
			desired.Platform.Values.Profiles[profile],
			filepath.Join(profileRoot, "prep", "kustomization.yaml"),
			filepath.Join(profileRoot, "access", "kustomization.yaml"),
		)
		if profile == "local" {
			members = append(members,
				filepath.Join(profileRoot, "identity", "contract.yaml"),
				filepath.Join(profileRoot, "prep", "stateful-values.yaml"),
			)
		}
	}
	for _, chart := range desired.Platform.Bootstrap.Charts {
		members = append(members, chart.Values, chart.FluxSource)
	}
	for _, source := range projectGitSources(&desired) {
		members = append(members, source.Patches...)
		for _, asset := range source.Assets {
			members = append(members, asset.File)
		}
	}
	hasBuild := false
	for _, image := range desired.Delivery.Images {
		if image.Delivery.Default.Type != "build" {
			continue
		}
		hasBuild = true
		for _, material := range image.Delivery.Default.Materials {
			if strings.Contains(material, "://") || strings.Contains(material, "@") {
				continue
			}
			if material == "go.mod" || material == "go.sum" ||
				filepath.ToSlash(material) == filepath.ToSlash(filepath.Join(
					desired.Platform.Directory, "build", "docker", "Dockerfile.delivery",
				)) ||
				filepath.ToSlash(material) == filepath.ToSlash(filepath.Join(
					desired.Platform.Directory, "build", "docker", "Dockerfile.operator",
				)) {
				members = append(members, material)
				continue
			}
			members = append(members, strings.TrimSuffix(material, "/")+"/")
		}
	}
	if hasBuild {
		members = append(members,
			filepath.Join(desired.Platform.Directory, "build", "compat")+"/",
		)
	}
	for index := range members {
		members[index] = filepath.ToSlash(members[index])
	}
	sort.Strings(members)
	return compactSourceMembers(members)
}

func fluxSecretRequiredFiles(desired Document) []string {
	root := filepath.Join(
		desired.Platform.Directory, "secrets", desired.Project.Cluster,
	)
	names := FluxSecretSourceNames()
	result := make([]string, len(names))
	for index, name := range names {
		result[index] = filepath.Join(root, filepath.FromSlash(name))
	}
	return result
}

// FluxSecretSourceNames is the canonical relative inventory rendered,
// validated, tracked, and published as the Flux SOPS source.
func FluxSecretSourceNames() []string {
	return []string{
		".sops.yaml",
		"kustomization.yaml",
		"operator-namespace.yaml",
		"stateful.json",
		"identity.json",
		"operator.json",
		"pki/kustomization.yaml",
		"pki/cert-manager-namespace.yaml",
		"pki/root-ca.json",
	}
}

func compactSourceMembers(members []string) []string {
	result := members[:0]
	for _, member := range members {
		if member == "" || len(result) != 0 && result[len(result)-1] == member {
			continue
		}
		result = append(result, member)
	}
	return result
}

// RequiredSourceSnapshotRoots is the canonical inventory of complete
// native-tool source boundaries. The active Terraform target comes from
// desired state; native tools continue to own how these admitted files are
// consumed.
func RequiredSourceSnapshotRoots(
	desired Document,
) ([]gitsnapshot.SourceRoot, error) {
	target, exists := desired.ActiveTarget()
	if !exists {
		return nil, fmt.Errorf(
			"active infrastructure target %q is not defined",
			desired.Infrastructure.Active,
		)
	}
	if target.Driver != "terraform" {
		return nil, fmt.Errorf(
			"active infrastructure target %q uses unsupported driver %q",
			desired.Infrastructure.Active,
			target.Driver,
		)
	}
	roots := []gitsnapshot.SourceRoot{
		{Path: target.Directory, Kind: gitsnapshot.TerraformConfiguration},
		{Path: filepath.Join(target.Directory, "scripts"), Kind: gitsnapshot.SourceAssets},
		{Path: filepath.Join(target.Directory, "templates"), Kind: gitsnapshot.SourceAssets},
		{
			Path: filepath.Join(desired.Orchestration.Directory, "playbooks"),
			Kind: gitsnapshot.AnsibleYAML,
		},
		{
			Path: filepath.Join(desired.Orchestration.Inventory, "hooks"),
			Kind: gitsnapshot.AnsibleYAML,
		},
	}
	for index := range roots {
		roots[index].Path = filepath.ToSlash(roots[index].Path)
	}
	sort.Slice(roots, func(left, right int) bool {
		if roots[left].Path == roots[right].Path {
			return roots[left].Kind < roots[right].Kind
		}
		return roots[left].Path < roots[right].Path
	})
	return roots, nil
}

func requireSourceSnapshot(
	snapshot *gitsnapshot.Snapshot,
	desired Document,
) error {
	if err := snapshot.RequireMembers(RequiredSourceSnapshotMembers(desired)); err != nil {
		return err
	}
	roots, err := RequiredSourceSnapshotRoots(desired)
	if err != nil {
		return err
	}
	return snapshot.RequireSourceRoots(roots)
}

// ValidateSourceSnapshot performs the pre-side-effect Git-index handoff check.
func ValidateSourceSnapshot(project *Project) error {
	if project == nil {
		return fmt.Errorf("Atum project is unavailable")
	}
	snapshot, err := gitsnapshot.Load(project.Root)
	if err != nil {
		return err
	}
	return requireSourceSnapshot(snapshot, project.Desired)
}

// SourceLockData returns the exact tracked root lock bytes. Runtime delivery
// resolution lives in ignored publication state and cannot change this identity.
func SourceLockData(project *Project) ([]byte, error) {
	if project == nil || len(project.LockData) == 0 {
		return nil, fmt.Errorf("Atum project has no tracked lock data")
	}
	return append([]byte(nil), project.LockData...), nil
}
