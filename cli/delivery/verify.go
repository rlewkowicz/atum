package delivery

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
)

const bundleSidecarLimit = 16 << 20

// VerifiedBundle is the exact cluster-facing identity of a deployment bundle.
// The detailed manifest remains owned by delivery; callers cannot accidentally
// implement a weaker projection of its source, chart, or image contracts.
type VerifiedBundle struct {
	SchemaVersion   string
	ArchiveSHA256   string
	DesiredSHA256   string
	InventorySHA256 string
	GraphSHA256     string
	LockSHA256      string
	SourceCommit    string
}

// VerifyBundle verifies the external sidecar, the complete artifact bytes,
// the embedded manifest, and every desired source/chart/image identity against
// the current project lock in one pass over the potentially large artifact.
func VerifyBundle(project *config.Project, artifactPath, sidecarPath string) (VerifiedBundle, error) {
	if project == nil || project.ExecutionBundle == nil {
		return VerifiedBundle{}, errors.New("local deployment receipt has no bundle")
	}
	expectedArtifact, err := fssecure.Resolve(project.Root, project.ExecutionBundle.File, false)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("resolve locked deployment bundle: %w", err)
	}
	expectedSidecarRelative := strings.TrimSuffix(project.ExecutionBundle.File, ".tar") + ".lock.json"
	expectedSidecar, err := fssecure.Resolve(project.Root, expectedSidecarRelative, false)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("resolve locked deployment bundle sidecar: %w", err)
	}
	artifactAbsolute, err := filepath.Abs(artifactPath)
	if err != nil || filepath.Clean(artifactAbsolute) != expectedArtifact {
		return VerifiedBundle{}, errors.New("deployment bundle artifact path does not match the current root lock")
	}
	sidecarAbsolute, err := filepath.Abs(sidecarPath)
	if err != nil || filepath.Clean(sidecarAbsolute) != expectedSidecar {
		return VerifiedBundle{}, errors.New("deployment bundle sidecar path does not match the current root lock")
	}
	sidecarFile, err := fssecure.OpenRegular(project.Root, expectedSidecarRelative)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("open deployment bundle sidecar: %w", err)
	}
	sidecarInfo, err := sidecarFile.Stat()
	if err != nil {
		_ = sidecarFile.Close()
		return VerifiedBundle{}, err
	}
	if sidecarInfo.Size() <= 0 || sidecarInfo.Size() > bundleSidecarLimit {
		_ = sidecarFile.Close()
		return VerifiedBundle{}, fmt.Errorf("deployment bundle sidecar size %d exceeds its limit", sidecarInfo.Size())
	}
	sidecarData, readErr := io.ReadAll(io.LimitReader(sidecarFile, bundleSidecarLimit+1))
	closeErr := sidecarFile.Close()
	if readErr != nil {
		return VerifiedBundle{}, readErr
	}
	if closeErr != nil {
		return VerifiedBundle{}, closeErr
	}
	if len(sidecarData) > bundleSidecarLimit {
		return VerifiedBundle{}, errors.New("deployment bundle sidecar exceeds its size limit")
	}
	var sidecar bundleSidecar
	if err := config.DecodeJSON(sidecarData, &sidecar); err != nil {
		return VerifiedBundle{}, fmt.Errorf("decode deployment bundle sidecar: %w", err)
	}
	if !sidecarMatchesLock(project, sidecar) {
		return VerifiedBundle{}, errors.New("deployment bundle sidecar does not match the current root lock")
	}
	artifactBase := filepath.Base(artifactPath)
	expectedBase := filepath.Base(sidecar.Artifact.File)
	if artifactBase != expectedBase || filepath.Base(sidecarPath) != strings.TrimSuffix(expectedBase, ".tar")+".lock.json" {
		return VerifiedBundle{}, errors.New("deployment bundle artifact or sidecar filename does not match its identity")
	}
	artifact, err := fssecure.OpenRegular(project.Root, project.ExecutionBundle.File)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("open deployment bundle artifact: %w", err)
	}
	manifest, inspectErr := inspectBundleArchive(artifact, config.Bundle{
		SHA256: sidecar.Artifact.SHA256,
		Size:   sidecar.Artifact.Size,
	})
	closeErr = artifact.Close()
	if inspectErr != nil {
		return VerifiedBundle{}, inspectErr
	}
	if closeErr != nil {
		return VerifiedBundle{}, closeErr
	}
	if !reflect.DeepEqual(manifest, sidecar.Bundle) {
		return VerifiedBundle{}, errors.New("embedded deployment bundle manifest differs from its sidecar")
	}
	if err := validateBundleManifest(project, manifest); err != nil {
		return VerifiedBundle{}, err
	}
	return VerifiedBundle{
		SchemaVersion:   manifest.SchemaVersion,
		ArchiveSHA256:   sidecar.Artifact.SHA256,
		DesiredSHA256:   manifest.DesiredSHA256,
		InventorySHA256: manifest.InventorySHA256,
		GraphSHA256:     manifest.GraphSHA256,
		LockSHA256:      manifest.LockSHA256,
		SourceCommit:    manifest.Source.Atum.Commit,
	}, nil
}

func sidecarMatchesLock(project *config.Project, sidecar bundleSidecar) bool {
	return sidecar.SchemaVersion == bundleLockSchema &&
		sidecar.Artifact.File == project.ExecutionBundle.File &&
		sidecar.Artifact.SHA256 == project.ExecutionBundle.SHA256 &&
		sidecar.Artifact.Size == project.ExecutionBundle.Size &&
		sidecar.Bundle.Source.SnapshotSHA256 == project.ExecutionBundle.AtumSourceSHA256 &&
		validArchive(sidecar.Artifact, project.ExecutionBundle.File)
}
