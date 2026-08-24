package delivery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
)

const (
	artifactDirectoryLimit = 4_096
	artifactMemberLimit    = 4_096
	artifactRoot           = ".atum/artifacts"
	materializedBundleRoot = ".atum/cache/deployment-bundles"
)

// pruneBundleArtifacts bounds generated archives and their extracted cache
// trees to the bundle set selected by the caller. Source, image, and build
// caches live elsewhere and are deliberately unaffected.
func pruneBundleArtifacts(project *config.Project, bundles ...*config.Bundle) error {
	keep := make(map[string]map[string]struct{}, len(bundles))
	materialized := make(map[string]struct{}, len(bundles))
	for _, bundle := range bundles {
		if bundle == nil {
			continue
		}
		directory, artifact, err := retainedBundleFiles(bundle)
		if err != nil {
			return err
		}
		files := keep[directory]
		if files == nil {
			files = make(map[string]struct{}, 2)
			keep[directory] = files
		}
		files[artifact] = struct{}{}
		files[strings.TrimSuffix(artifact, ".tar")+".lock.json"] = struct{}{}
		materialized[bundle.SHA256] = struct{}{}
	}

	directories, err := fssecure.ReadDirectoryNames(project.Root, artifactRoot, artifactDirectoryLimit)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect deployment bundle artifacts: %w", err)
	}
	for _, directory := range directories {
		if !validSHA256Text(directory) {
			continue
		}
		files, retained := keep[directory]
		relativeDirectory := filepath.Join(artifactRoot, directory)
		if !retained {
			if err := fssecure.RemoveTree(project.Root, relativeDirectory); err != nil {
				return fmt.Errorf("remove stale deployment bundle directory %s: %w", directory, err)
			}
			continue
		}
		members, err := fssecure.ReadDirectoryNames(project.Root, relativeDirectory, artifactMemberLimit)
		if err != nil {
			return fmt.Errorf("inspect deployment bundle directory %s: %w", directory, err)
		}
		for _, member := range members {
			if _, retained := files[member]; retained {
				continue
			}
			relative := filepath.Join(relativeDirectory, member)
			switch {
			case member == ".atum-bundle.tar", bundleArtifactMember(member):
				if err := fssecure.RemoveRegular(project.Root, relative); err != nil {
					return fmt.Errorf("remove stale deployment bundle artifact %s: %w", member, err)
				}
			case strings.HasPrefix(member, ".bundle-stage-"):
				if err := fssecure.RemoveTree(project.Root, relative); err != nil {
					return fmt.Errorf("remove stale deployment bundle stage %s: %w", member, err)
				}
			}
		}
	}
	return pruneMaterializedBundles(project, materialized)
}

func pruneMaterializedBundles(project *config.Project, keep map[string]struct{}) error {
	directories, err := fssecure.ReadDirectoryNames(project.Root, materializedBundleRoot, artifactDirectoryLimit)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect materialized deployment bundles: %w", err)
	}
	for _, directory := range directories {
		if !validSHA256Text(directory) {
			continue
		}
		if _, retained := keep[directory]; retained {
			continue
		}
		if err := fssecure.RemoveTree(project.Root, filepath.Join(materializedBundleRoot, directory)); err != nil {
			return fmt.Errorf("remove stale materialized deployment bundle %s: %w", directory, err)
		}
	}
	return nil
}

func retainedBundleFiles(bundle *config.Bundle) (string, string, error) {
	clean, err := fssecure.Relative(filepath.FromSlash(bundle.File))
	if err != nil {
		return "", "", fmt.Errorf("validate retained deployment bundle: %w", err)
	}
	parts := strings.Split(filepath.ToSlash(clean), "/")
	if len(parts) != 4 || parts[0] != ".atum" || parts[1] != "artifacts" || !validSHA256Text(parts[2]) {
		return "", "", fmt.Errorf("deployment bundle path %q is outside content-addressed artifact storage", bundle.File)
	}
	expected := "atum-bundle-" + bundle.SHA256 + ".tar"
	if !validSHA256Text(bundle.SHA256) || parts[3] != expected {
		return "", "", fmt.Errorf("deployment bundle path %q does not match SHA-256 %s", bundle.File, bundle.SHA256)
	}
	return parts[2], parts[3], nil
}

func bundleArtifactMember(name string) bool {
	if !strings.HasPrefix(name, "atum-bundle-") {
		return false
	}
	digest := strings.TrimPrefix(name, "atum-bundle-")
	switch {
	case strings.HasSuffix(digest, ".tar"):
		digest = strings.TrimSuffix(digest, ".tar")
	case strings.HasSuffix(digest, ".lock.json"):
		digest = strings.TrimSuffix(digest, ".lock.json")
	default:
		return false
	}
	return validSHA256Text(digest)
}
