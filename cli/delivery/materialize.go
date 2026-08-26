package delivery

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/progress"

	"oras.land/oras-go/v2"
)

const materializeMemberLimit = 2_000_000

// MaterializeLockedBundle resolves and verifies the bundle selected by the
// current ignored execution receipt before exposing cache-backed payloads.
func MaterializeLockedBundle(ctx context.Context, project *config.Project) (bundle *DeploymentBundle, err error) {
	const (
		itemID = "bundle-materialization"
		label  = "Bundle materialization"
	)
	progress.Start(ctx, progress.Platform, itemID, label, "verifying canonical archive")
	defer func() {
		if err != nil {
			progress.Fail(ctx, progress.Platform, itemID, label, err)
			return
		}
		progress.Done(ctx, progress.Platform, itemID, label,
			fmt.Sprintf("%d images and %d charts ready", len(bundle.Images), len(bundle.Charts)))
	}()
	if project == nil {
		return nil, errors.New("Atum project is not loaded")
	}
	locked := project.ExecutionBundle
	if locked == nil {
		return nil, errors.New("local deployment receipt has no bundle")
	}
	artifact, err := fssecure.Resolve(project.Root, locked.File, false)
	if err != nil {
		return nil, err
	}
	sidecarRelative := strings.TrimSuffix(locked.File, ".tar") + ".lock.json"
	sidecar, err := fssecure.Resolve(project.Root, sidecarRelative, false)
	if err != nil {
		return nil, err
	}
	return MaterializeBundle(ctx, project, artifact, sidecar)
}

// DeploymentBundle exposes only the verified data required by platform
// bootstrap. Its content-addressed cache is ignored and can be recreated from
// the canonical bundle at any time.
type DeploymentBundle struct {
	Identity      VerifiedBundle
	SourceRoot    string
	Images        []BundleImage
	Charts        []BundleChart
	SeedPayload   BundleFile
	SourceTag     string
	SourceCommit  string
	DesiredSHA256 string
	ArchiveSHA256 string
	imageStore    oras.ReadOnlyTarget
	runtimeImages map[string]map[string]struct{}
}

type BundleImage struct {
	config.LockedImage
	SeedReference string
}

type BundleChart struct {
	ID            string
	Name          string
	Version       string
	Target        string
	ArchiveSHA256 string
	Size          int64
	Path          string
}

type BundleFile struct {
	Path   string
	SHA256 string
	Size   int64
}

// RuntimeImageDigests returns the exact non-layer OCI identities that a CRI
// may report for every bundled image. The materialized layout was verified
// while it was extracted; resolving it again binds pod status to that same
// immutable content rather than only to a mutable registry reference.
func (bundle *DeploymentBundle) RuntimeImageDigests(
	ctx context.Context,
) (map[string]map[string]struct{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if bundle == nil || bundle.imageStore == nil || len(bundle.runtimeImages) != len(bundle.Images) {
		return nil, errors.New("deployment bundle OCI graph was not verified")
	}
	result := make(map[string]map[string]struct{}, len(bundle.runtimeImages))
	for target, digests := range bundle.runtimeImages {
		copy := make(map[string]struct{}, len(digests))
		for digest := range digests {
			copy[digest] = struct{}{}
		}
		result[target] = copy
	}
	return result, nil
}

func (bundle *DeploymentBundle) ImageStore() (oras.ReadOnlyTarget, error) {
	if bundle == nil || bundle.imageStore == nil {
		return nil, errors.New("deployment bundle OCI graph was not verified")
	}
	return bundle.imageStore, nil
}

// MaterializeBundle verifies and streams a deployment bundle into one
// content-addressed cache tree. Large OCI blobs are never collected in memory.
func MaterializeBundle(
	ctx context.Context,
	project *config.Project,
	artifactPath, sidecarPath string,
) (*DeploymentBundle, error) {
	ctx = withDeliveryBudget(
		ctx, effectiveParallelism(0, project.Desired.Updates.Parallelism),
	)
	identity, err := VerifyBundle(project, artifactPath, sidecarPath)
	if err != nil {
		return nil, err
	}
	progress.Update(ctx, progress.Platform, "bundle-materialization", "Bundle materialization",
		"checking content-addressed cache", 0, 0)
	sidecar, err := loadBundleSidecar(project, sidecarPath)
	if err != nil {
		return nil, err
	}
	cacheRelative := filepath.Join(".atum", "cache", "deployment-bundles", identity.ArchiveSHA256)
	unlock, err := fssecure.LockContext(
		ctx,
		project.Root,
		filepath.Join(".atum", "cache", "locks", "deployment-bundle-"+identity.ArchiveSHA256+".lock"),
		250*time.Millisecond,
	)
	if err != nil {
		return nil, fmt.Errorf("lock deployment bundle cache: %w", err)
	}
	defer unlock()
	marker, err := materializeMarker(sidecar)
	if err != nil {
		return nil, err
	}
	if materializedBundleCurrent(project.Root, cacheRelative, marker, sidecar.Bundle) {
		progress.Update(ctx, progress.Platform, "bundle-materialization", "Bundle materialization",
			"verifying cached OCI graph", 0, len(sidecar.Bundle.Images))
		store, runtimeImages, imageErr := validateMaterializedImages(ctx, project.Root, cacheRelative, sidecar.Bundle)
		if imageErr == nil {
			progress.Update(ctx, progress.Platform, "bundle-materialization", "Bundle materialization",
				"refreshing exact main source", 0, 1)
			if err := refreshMaterializedSources(
				project.Root, cacheRelative, sidecar.Bundle,
			); err != nil {
				return nil, fmt.Errorf("refresh materialized deployment sources: %w", err)
			}
			return deploymentBundle(project.Root, cacheRelative, identity, sidecar.Bundle, store, runtimeImages), nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := fssecure.RemoveTree(project.Root, cacheRelative); err != nil {
		return nil, fmt.Errorf("remove incomplete deployment bundle cache: %w", err)
	}
	if _, err := fssecure.EnsureDirectory(project.Root, cacheRelative, 0o700); err != nil {
		return nil, err
	}
	removeIncomplete := true
	defer func() {
		if removeIncomplete {
			_ = fssecure.RemoveTree(project.Root, cacheRelative)
		}
	}()
	progress.Update(ctx, progress.Platform, "bundle-materialization", "Bundle materialization",
		"extracting canonical archive", 0, 0)
	if err := extractOuterBundle(project, artifactPath, cacheRelative, sidecar.Bundle); err != nil {
		return nil, err
	}
	progress.Update(ctx, progress.Platform, "bundle-materialization", "Bundle materialization",
		"extracting exact main source", 0, 1)
	if err := refreshMaterializedSources(
		project.Root, cacheRelative, sidecar.Bundle,
	); err != nil {
		return nil, fmt.Errorf("extract deployment sources: %w", err)
	}
	progress.Update(ctx, progress.Platform, "bundle-materialization", "Bundle materialization",
		"verifying extracted OCI graph", 0, len(sidecar.Bundle.Images))
	store, runtimeImages, err := validateMaterializedImages(ctx, project.Root, cacheRelative, sidecar.Bundle)
	if err != nil {
		return nil, fmt.Errorf("validate materialized OCI images: %w", err)
	}
	if err := fssecure.WriteRegular(project.Root, filepath.Join(cacheRelative, "identity.json"), marker, 0o600); err != nil {
		return nil, err
	}
	removeIncomplete = false
	return deploymentBundle(project.Root, cacheRelative, identity, sidecar.Bundle, store, runtimeImages), nil
}

func loadBundleSidecar(project *config.Project, sidecarPath string) (bundleSidecar, error) {
	if project == nil || project.ExecutionBundle == nil {
		return bundleSidecar{}, errors.New("local deployment receipt has no bundle")
	}
	relative, err := filepath.Rel(project.Root, sidecarPath)
	if err != nil {
		return bundleSidecar{}, fmt.Errorf("resolve deployment bundle sidecar: %w", err)
	}
	file, err := fssecure.OpenRegular(project.Root, relative)
	if err != nil {
		return bundleSidecar{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, bundleSidecarLimit+1))
	closeErr := file.Close()
	if readErr != nil {
		return bundleSidecar{}, readErr
	}
	if closeErr != nil {
		return bundleSidecar{}, closeErr
	}
	if len(data) > bundleSidecarLimit {
		return bundleSidecar{}, errors.New("deployment bundle sidecar exceeds its size limit")
	}
	var sidecar bundleSidecar
	if err := config.DecodeJSON(data, &sidecar); err != nil {
		return bundleSidecar{}, err
	}
	if !sidecarMatchesLock(project, sidecar) {
		return bundleSidecar{}, errors.New("deployment bundle sidecar changed after verification")
	}
	if err := validateBundleManifest(project, sidecar.Bundle); err != nil {
		return bundleSidecar{}, fmt.Errorf("revalidate deployment bundle sidecar: %w", err)
	}
	return sidecar, nil
}

func materializeMarker(sidecar bundleSidecar) ([]byte, error) {
	identity := struct {
		SchemaVersion string `json:"schemaVersion"`
		ArchiveSHA256 string `json:"archiveSha256"`
		ArchiveSize   int64  `json:"archiveSize"`
		DesiredSHA256 string `json:"desiredSha256"`
		LockSHA256    string `json:"lockSha256"`
	}{
		SchemaVersion: "atum.dev/materialized-bundle/v1",
		ArchiveSHA256: sidecar.Artifact.SHA256,
		ArchiveSize:   sidecar.Artifact.Size,
		DesiredSHA256: sidecar.Bundle.DesiredSHA256,
		LockSHA256:    sidecar.Bundle.LockSHA256,
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func materializedBundleCurrent(root, cacheRelative string, marker []byte, manifest bundleManifest) bool {
	file, err := fssecure.OpenRegular(root, filepath.Join(cacheRelative, "identity.json"))
	if err != nil {
		return false
	}
	current, readErr := io.ReadAll(io.LimitReader(file, int64(len(marker)+1)))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(current, marker) {
		return false
	}
	required := []string{
		filepath.Join(cacheRelative, "source", config.DesiredFilename),
		filepath.Join(cacheRelative, "images", "index.json"),
		filepath.Join(cacheRelative, "images", "oci-layout"),
		filepath.Join(cacheRelative, manifest.Seed.Artifact.File),
	}
	for _, chart := range manifest.Charts {
		required = append(required, filepath.Join(cacheRelative, chart.File))
	}
	for _, relative := range required {
		file, err := fssecure.OpenRegular(root, relative)
		if err != nil {
			return false
		}
		if err := file.Close(); err != nil {
			return false
		}
	}
	if !regularFileMatches(
		root,
		filepath.Join(cacheRelative, manifest.Source.Atum.File),
		manifest.Source.Atum.SHA256,
		manifest.Source.Atum.Size,
	) {
		return false
	}
	if !regularFileMatches(
		root,
		filepath.Join(cacheRelative, manifest.Seed.Artifact.File),
		manifest.Seed.Artifact.SHA256,
		manifest.Seed.Artifact.Size,
	) {
		return false
	}
	for _, chart := range manifest.Charts {
		if !regularFileMatches(root, filepath.Join(cacheRelative, chart.File), chart.ArchiveSHA256, chart.Size) {
			return false
		}
	}
	return true
}

func regularFileMatches(root, relative, expectedSHA string, expectedSize int64) bool {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return false
	}
	info, err := file.Stat()
	if err != nil || (expectedSize >= 0 && info.Size() != expectedSize) {
		_ = file.Close()
		return false
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	return copyErr == nil && closeErr == nil && written == info.Size() &&
		hex.EncodeToString(hash.Sum(nil)) == expectedSHA
}

func refreshMaterializedSources(root, cacheRelative string, manifest bundleManifest) error {
	if err := extractTreeArchive(
		root,
		filepath.Join(cacheRelative, manifest.Source.Atum.File),
		filepath.Join(cacheRelative, "source"),
		manifest.Source.Atum.SHA256,
	); err != nil {
		return err
	}
	return nil
}

func deploymentBundle(
	root, cacheRelative string,
	identity VerifiedBundle,
	manifest bundleManifest,
	store *bundleImageStore,
	runtimeImages map[string]map[string]struct{},
) *DeploymentBundle {
	cacheRoot := filepath.Join(root, cacheRelative)
	result := &DeploymentBundle{
		Identity:      identity,
		SourceRoot:    filepath.Join(cacheRoot, "source"),
		SourceTag:     "bundle-sha256-" + identity.ArchiveSHA256,
		SourceCommit:  identity.SourceCommit,
		DesiredSHA256: identity.DesiredSHA256,
		ArchiveSHA256: identity.ArchiveSHA256,
		imageStore:    store,
		runtimeImages: runtimeImages,
		Images:        make([]BundleImage, len(manifest.Images)),
		Charts:        make([]BundleChart, len(manifest.Charts)),
		SeedPayload: BundleFile{
			Path:   filepath.Join(cacheRoot, manifest.Seed.Artifact.File),
			SHA256: manifest.Seed.Artifact.SHA256,
			Size:   manifest.Seed.Artifact.Size,
		},
	}
	for index, image := range manifest.Images {
		result.Images[index] = BundleImage{LockedImage: image.LockedImage, SeedReference: image.SeedReference}
	}
	for index, chart := range manifest.Charts {
		result.Charts[index] = BundleChart{
			ID: chart.ID, Name: chart.Name, Version: chart.Version, Target: chart.Target,
			ArchiveSHA256: chart.ArchiveSHA256, Size: chart.Size, Path: filepath.Join(cacheRoot, chart.File),
		}
	}
	return result
}

type expectedBundleFile struct {
	sha256 string
	size   int64
}

func extractOuterBundle(
	project *config.Project,
	artifactPath, cacheRelative string,
	manifest bundleManifest,
) error {
	expected, err := expectedBundleFiles(project, manifest)
	if err != nil {
		return err
	}
	artifactRelative, err := filepath.Rel(project.Root, artifactPath)
	if err != nil {
		return err
	}
	artifact, err := fssecure.OpenRegular(project.Root, artifactRelative)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = artifact.Close()
		}
	}()
	info, err := artifact.Stat()
	if err != nil {
		return err
	}
	if project.ExecutionBundle == nil || !info.Mode().IsRegular() || info.Size() != project.ExecutionBundle.Size || info.Size() <= 0 {
		return errors.New("deployment bundle changed before materialization")
	}
	archiveHash := sha256.New()
	stream := io.TeeReader(artifact, archiveHash)
	reader := tar.NewReader(stream)
	seen := make(map[string]struct{}, len(expected))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read deployment bundle: %w", err)
		}
		name, err := cleanArchiveName(header.Name)
		if err != nil {
			return err
		}
		identity, allowed := expected[name]
		if !allowed || header.Typeflag != tar.TypeReg || header.Size < 0 {
			return fmt.Errorf("deployment bundle contains unexpected member %s", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("deployment bundle repeats member %s", name)
		}
		seen[name] = struct{}{}
		hash := sha256.New()
		counter := &countWriter{writer: hash}
		limited := &io.LimitedReader{R: reader, N: header.Size}
		memberStream := io.TeeReader(limited, counter)
		if name == "images.oci.tar" {
			if err := extractTreeStream(
				project.Root,
				filepath.Join(cacheRelative, "images"),
				memberStream,
				header.Size,
				name,
			); err != nil {
				return fmt.Errorf("extract OCI image layout: %w", err)
			}
		} else {
			written, err := fssecure.WriteRegularFrom(
				project.Root,
				filepath.Join(cacheRelative, filepath.FromSlash(name)),
				memberStream,
				0o600,
			)
			if err != nil {
				return fmt.Errorf("extract deployment bundle member %s: %w", name, err)
			}
			if written != header.Size {
				return fmt.Errorf("deployment bundle member %s yielded %d bytes, want %d", name, written, header.Size)
			}
		}
		actual := hex.EncodeToString(hash.Sum(nil))
		if limited.N != 0 || counter.size != header.Size ||
			(identity.size >= 0 && counter.size != identity.size) || actual != identity.sha256 {
			return fmt.Errorf("deployment bundle member %s is %s/%d, want %s/%d",
				name, actual, counter.size, identity.sha256, identity.size)
		}
	}
	if len(seen) != len(expected) {
		missing := make([]string, 0, len(expected)-len(seen))
		for name := range expected {
			if _, found := seen[name]; !found {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("deployment bundle is missing %s", strings.Join(missing, ", "))
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return fmt.Errorf("finish reading deployment bundle: %w", err)
	}
	if err := artifact.Close(); err != nil {
		return fmt.Errorf("close deployment bundle: %w", err)
	}
	closed = true
	if hex.EncodeToString(archiveHash.Sum(nil)) != project.ExecutionBundle.SHA256 {
		return errors.New("deployment bundle changed while it was materialized")
	}
	return nil
}

func expectedBundleFiles(project *config.Project, manifest bundleManifest) (map[string]expectedBundleFile, error) {
	bundleData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	bundleData = append(bundleData, '\n')
	expected := map[string]expectedBundleFile{
		"bundle.json": {
			sha256: config.SHA256(bundleData),
			size:   int64(len(bundleData)),
		},
		config.DesiredFilename: {
			sha256: config.SHA256(project.DesiredData),
			size:   int64(len(project.DesiredData)),
		},
		config.LockFilename: {
			sha256: manifest.LockSHA256,
			size:   -1,
		},
		"images.oci.tar": {
			sha256: manifest.ImagesOCISHA256,
			size:   -1,
		},
	}
	add := func(identity archiveIdentity) error {
		name, err := cleanArchiveName(identity.File)
		if err != nil {
			return err
		}
		if _, duplicate := expected[name]; duplicate {
			return fmt.Errorf("deployment bundle member %s is duplicated in its manifest", name)
		}
		expected[name] = expectedBundleFile{sha256: identity.SHA256, size: identity.Size}
		return nil
	}
	if err := add(manifest.Source.Atum.archiveIdentity); err != nil {
		return nil, err
	}
	if err := add(manifest.Seed.Artifact); err != nil {
		return nil, err
	}
	for _, chart := range manifest.Charts {
		if err := add(archiveIdentity{File: chart.File, SHA256: chart.ArchiveSHA256, Size: chart.Size}); err != nil {
			return nil, err
		}
	}
	return expected, nil
}

func extractTreeArchive(root, archiveRelative, destinationRelative, expectedSHA string) error {
	file, err := fssecure.OpenRegular(root, archiveRelative)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	hash := sha256.New()
	counter := &countWriter{writer: hash}
	stream := io.TeeReader(file, counter)
	if err := extractTreeStream(root, destinationRelative, stream, info.Size(), archiveRelative); err != nil {
		_ = file.Close()
		return err
	}
	closeErr := file.Close()
	actualSHA := hex.EncodeToString(hash.Sum(nil))
	if closeErr != nil || counter.size != info.Size() || actualSHA != expectedSHA {
		_ = fssecure.RemoveTree(root, destinationRelative)
		if closeErr != nil {
			return closeErr
		}
		return fmt.Errorf("archive %s is %s/%d, want %s/%d",
			archiveRelative, actualSHA, counter.size, expectedSHA, info.Size())
	}
	return nil
}

func extractTreeStream(root, destinationRelative string, stream io.Reader, maxSize int64, label string) error {
	if stream == nil || maxSize <= 0 {
		return fmt.Errorf("archive %s has an invalid input size", label)
	}
	if err := fssecure.RemoveTree(root, destinationRelative); err != nil {
		return err
	}
	if _, err := fssecure.EnsureDirectory(root, destinationRelative, 0o700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = fssecure.RemoveTree(root, destinationRelative)
		}
	}()
	reader := tar.NewReader(stream)
	seen := make(map[string]struct{}, 1024)
	symlinks := make(map[string]struct{}, 64)
	var total int64
	for members := 0; ; members++ {
		if members >= materializeMemberLimit {
			return fmt.Errorf("archive %s exceeds %d members", label, materializeMemberLimit)
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name, err := cleanArchiveName(header.Name)
		if err != nil {
			return err
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("archive %s repeats %s", label, name)
		}
		if archiveParentIsLink(name, symlinks) {
			return fmt.Errorf("archive %s places %s beneath a symlink", label, name)
		}
		seen[name] = struct{}{}
		destination := filepath.Join(destinationRelative, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := fssecure.EnsureDirectory(root, destination, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxSize || total > maxSize-header.Size {
				return fmt.Errorf("archive %s has invalid member size for %s", label, name)
			}
			total += header.Size
			mode := os.FileMode(header.Mode).Perm()
			if mode&0o111 != 0 {
				mode = 0o700
			} else {
				mode = 0o600
			}
			written, err := fssecure.CreateRegularFrom(root, destination, io.LimitReader(reader, header.Size), mode)
			if err != nil {
				return err
			}
			if written != header.Size {
				return fmt.Errorf("archive member %s yielded %d bytes, want %d", name, written, header.Size)
			}
		case tar.TypeSymlink:
			if !containedLink(name, header.Linkname) {
				return fmt.Errorf("archive symlink %s escapes through %s", name, header.Linkname)
			}
			if err := fssecure.CreateSymlink(root, destination, header.Linkname); err != nil {
				return err
			}
			symlinks[name] = struct{}{}
		default:
			return fmt.Errorf("archive %s contains unsupported member %s with type %d", label, name, header.Typeflag)
		}
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return fmt.Errorf("finish reading archive %s: %w", label, err)
	}
	complete = true
	return nil
}

func archiveParentIsLink(name string, symlinks map[string]struct{}) bool {
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		if _, found := symlinks[parent]; found {
			return true
		}
	}
	return false
}
