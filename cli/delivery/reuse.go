package delivery

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
)

const bundleManifestLimit = 16 << 20

func reuseExistingBundle(project *config.Project) (BundleResult, bool, error) {
	if project.ExecutionBundle == nil {
		return BundleResult{}, false, nil
	}
	bundle := *project.ExecutionBundle
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return BundleResult{}, false, err
	}
	if sourceSHA != bundle.AtumSourceSHA256 {
		return BundleResult{}, false, nil
	}
	file, err := fssecure.OpenRegular(project.Root, bundle.File)
	if errors.Is(err, os.ErrNotExist) {
		return BundleResult{}, false, nil
	}
	if err != nil {
		return BundleResult{}, false, fmt.Errorf("open existing deployment bundle: %w", err)
	}
	manifest, err := inspectBundleArchive(file, bundle)
	closeErr := file.Close()
	if err != nil {
		return BundleResult{}, false, err
	}
	if closeErr != nil {
		return BundleResult{}, false, closeErr
	}
	if err := validateBundleManifest(project, manifest); err != nil {
		return BundleResult{}, false, err
	}
	sidecar := bundleSidecar{
		SchemaVersion: bundleLockSchema,
		Artifact: archiveIdentity{
			File: bundle.File, SHA256: bundle.SHA256, Size: bundle.Size,
		},
		Bundle: manifest,
	}
	data, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return BundleResult{}, false, err
	}
	data = append(data, '\n')
	sidecarRelative := strings.TrimSuffix(bundle.File, ".tar") + ".lock.json"
	if err := writeBundleSidecar(project.Root, sidecarRelative, data); err != nil {
		return BundleResult{}, false, fmt.Errorf("refresh deployment bundle sidecar: %w", err)
	}
	path, err := fssecure.Resolve(project.Root, bundle.File, false)
	if err != nil {
		return BundleResult{}, false, err
	}
	return BundleResult{Bundle: bundle, Path: path}, true, nil
}

func writeBundleSidecar(root, relative string, data []byte) error {
	file, err := fssecure.OpenRegular(root, relative)
	if err == nil {
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return statErr
		}
		if info.Size() == int64(len(data)) {
			current, readErr := io.ReadAll(io.LimitReader(file, int64(len(data))+1))
			closeErr := file.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if bytes.Equal(current, data) {
				return nil
			}
		} else {
			if err := file.Close(); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fssecure.WriteRegular(root, relative, data, 0o644)
}

func inspectBundleArchive(file *os.File, expected config.Bundle) (bundleManifest, error) {
	info, err := file.Stat()
	if err != nil {
		return bundleManifest{}, err
	}
	if !info.Mode().IsRegular() || info.Size() != expected.Size || expected.Size <= 0 {
		return bundleManifest{}, fmt.Errorf("existing deployment bundle has size %d, want %d", info.Size(), expected.Size)
	}
	hash := sha256.New()
	stream := io.TeeReader(file, hash)
	reader := tar.NewReader(stream)
	var manifest bundleManifest
	found := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return bundleManifest{}, fmt.Errorf("read existing deployment bundle: %w", err)
		}
		name, err := cleanArchiveName(header.Name)
		if err != nil {
			return bundleManifest{}, err
		}
		if name != "bundle.json" {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > bundleManifestLimit {
			return bundleManifest{}, errors.New("existing deployment bundle has an invalid manifest entry")
		}
		data, err := io.ReadAll(io.LimitReader(reader, bundleManifestLimit+1))
		if err != nil || len(data) > bundleManifestLimit {
			if err != nil {
				return bundleManifest{}, err
			}
			return bundleManifest{}, errors.New("existing deployment bundle manifest exceeds its size limit")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return bundleManifest{}, fmt.Errorf("decode existing deployment bundle manifest: %w", err)
		}
		if decoder.Decode(new(any)) != io.EOF {
			return bundleManifest{}, errors.New("existing deployment bundle manifest contains multiple JSON values")
		}
		found = true
	}
	if !found {
		return bundleManifest{}, errors.New("existing deployment bundle has no manifest")
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return bundleManifest{}, err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected.SHA256 {
		return bundleManifest{}, fmt.Errorf("existing deployment bundle has checksum %s, want %s", actual, expected.SHA256)
	}
	return manifest, nil
}

func validateBundleManifest(project *config.Project, manifest bundleManifest) error {
	snapshot := project.Lock
	lockData, err := config.MarshalJSON(snapshot)
	if err != nil {
		return err
	}
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return err
	}
	if manifest.SchemaVersion != bundleSchema || manifest.Platform != project.Lock.Delivery.Platform ||
		manifest.DesiredSHA256 != project.DesiredSHA256 ||
		manifest.InventorySHA256 != project.Lock.Delivery.InventorySHA256 ||
		manifest.GraphSHA256 != project.Lock.Delivery.GraphSHA256 ||
		manifest.LockSHA256 != config.SHA256(lockData) || !validSHA256Text(manifest.ImagesOCISHA256) ||
		manifest.Source.SnapshotSHA256 != sourceSHA ||
		!validArchive(manifest.Source.Atum.archiveIdentity, "sources/atum.tar") ||
		!validCommit(manifest.Source.Atum.Commit) {
		return errors.New("existing deployment bundle manifest does not match the current lock")
	}
	if err := validateBundleSeed(project, manifest.Seed); err != nil {
		return err
	}
	if len(manifest.Images) != len(project.Lock.Delivery.Images) {
		return errors.New("existing deployment bundle image inventory is incomplete")
	}
	for index, image := range manifest.Images {
		expected := project.Lock.Delivery.Images[index]
		if !reflect.DeepEqual(image.LockedImage, expected) || image.SeedReference != "atum-seed.local/"+expected.ID+":seed" {
			return fmt.Errorf("existing deployment bundle image %d does not match %s", index, expected.ID)
		}
	}
	if len(manifest.Charts) != len(project.Lock.Resolved.Artifacts) {
		return errors.New("existing deployment bundle chart inventory is incomplete")
	}
	for index, chart := range manifest.Charts {
		expected := project.Lock.Resolved.Artifacts[index]
		if chart.ID != expected.ID || chart.Name != expected.Name || chart.Version != expected.Version ||
			chart.Target != expected.Target || chart.ArchiveSHA256 != expected.ArchiveSHA256 ||
			chart.Size != expected.Size || chart.Size > config.ChartArchiveLimit ||
			chart.File != "charts/"+filepath.Base(expected.File) {
			return fmt.Errorf("existing deployment bundle chart %d does not match %s", index, expected.ID)
		}
	}
	return nil
}

func validArchive(identity archiveIdentity, expectedFile string) bool {
	return identity.File == expectedFile && identity.Size > 0 && validSHA256Text(identity.SHA256)
}

func validSHA256Text(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validCommit(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
