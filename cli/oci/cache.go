package oci

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/fssecure"
)

const layoutEntryLimit = 10_000

// OfficialMirrorCacheRelative is the single path authority for one exact
// official-image cache. The digest remains part of the directory identity so
// an upstream tag retarget cannot mutate or alias previously verified content.
func OfficialMirrorCacheRelative(imageID, digest string) (string, error) {
	encoded, found := strings.CutPrefix(digest, "sha256:")
	decoded, decodeErr := hex.DecodeString(encoded)
	if !found || decodeErr != nil || !fssecure.ValidName(imageID) ||
		len(decoded) != 32 || hex.EncodeToString(decoded) != encoded {
		return "", fmt.Errorf("official image %s has an invalid cache identity", imageID)
	}
	return filepath.Join(
		".atum",
		"cache",
		"oci",
		"mirrors",
		imageID+"-"+encoded,
	), nil
}

// ValidateLayoutTree rejects aliases and non-regular content before an OCI
// consumer opens a repository-local layout.
func ValidateLayoutTree(directory string) error {
	root, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if root.Mode()&os.ModeSymlink != 0 || !root.IsDir() {
		return fmt.Errorf("OCI output is not a real directory")
	}
	entries := 0
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > layoutEntryLimit {
			return fmt.Errorf("OCI output exceeds %d filesystem entries", layoutEntryLimit)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("OCI output contains unsupported path %s", path)
		}
		return nil
	})
}
