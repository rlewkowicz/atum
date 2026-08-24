package update

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/treehash"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
)

const vendorFileLimit = 32 << 20

func reconstructVendor(root, checkout string, vendor config.Vendor) (string, string, error) {
	source := filepath.Join(checkout, filepath.FromSlash(vendor.Subpath))
	temporaryRoot, err := fssecure.EnsureDirectory(root, filepath.Join(".atum", "cache", "vendors", vendor.ID), 0o700)
	if err != nil {
		return "", "", fmt.Errorf("create vendor cache: %w", err)
	}
	temporary, err := os.MkdirTemp(temporaryRoot, ".vendor-")
	if err != nil {
		return "", "", fmt.Errorf("create vendor candidate directory: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := copyTree(source, temporary); err != nil {
		return "", "", fmt.Errorf("copy upstream vendor %s: %w", vendor.ID, err)
	}
	for _, patch := range vendor.Patches {
		patchPath, err := fssecure.Resolve(root, patch, false)
		if err != nil {
			return "", "", fmt.Errorf("resolve vendor %s patch %s: %w", vendor.ID, patch, err)
		}
		if err := applyPatch(temporary, patchPath); err != nil {
			return "", "", fmt.Errorf("apply vendor %s patch %s: %w", vendor.ID, patch, err)
		}
	}
	patchedSHA, err := hashTree(temporary)
	if err != nil {
		return "", "", fmt.Errorf("hash reconstructed vendor %s: %w", vendor.ID, err)
	}
	commitRoot, err := fssecure.EnsureDirectory(root, filepath.Join(".atum", "cache", "vendors", vendor.ID, vendor.Source.Commit), 0o700)
	if err != nil {
		return "", "", fmt.Errorf("secure vendor commit cache: %w", err)
	}
	destination := filepath.Join(commitRoot, patchedSHA)
	if existingSHA, hashErr := hashTree(destination); hashErr == nil {
		if existingSHA != patchedSHA {
			return "", "", fmt.Errorf("immutable vendor cache %s has tree %s, want %s", destination, existingSHA, patchedSHA)
		}
		return destination, patchedSHA, nil
	} else if !os.IsNotExist(hashErr) {
		return "", "", hashErr
	}
	if err := os.Rename(temporary, destination); err != nil {
		if existingSHA, hashErr := hashTree(destination); hashErr != nil || existingSHA != patchedSHA {
			return "", "", fmt.Errorf("publish vendor cache %s: %w", destination, err)
		}
	}
	removeTemporary = false
	return destination, patchedSHA, nil
}

func verifyTrackedVendor(root string, vendor config.Vendor, candidateDirectory, candidateSHA string) error {
	trackedPath, err := fssecure.Resolve(root, vendor.Directory, false)
	if err != nil {
		return fmt.Errorf("resolve tracked vendor %s: %w", vendor.ID, err)
	}
	trackedSHA, err := hashTree(trackedPath)
	if err != nil {
		return fmt.Errorf("hash tracked vendor %s: %w", vendor.ID, err)
	}
	if candidateSHA != vendor.TreeSHA256 || trackedSHA != vendor.TreeSHA256 {
		return fmt.Errorf("vendor %s delta does not reproduce tree %s (upstream+patches=%s, tracked=%s, candidate=%s)",
			vendor.ID, vendor.TreeSHA256, candidateSHA, trackedSHA, candidateDirectory)
	}
	return nil
}

func copyTree(source, destination string) error {
	return fssecure.WalkTree(source, func(path, relative string, entry fs.DirEntry, info fs.FileInfo) error {
		target := filepath.Join(destination, filepath.FromSlash(relative))
		switch {
		case entry.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			data, err := readBounded(path, vendorFileLimit)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, info.Mode().Perm())
		default:
			return fmt.Errorf("vendor tree contains unsupported file %s with mode %s", path, info.Mode())
		}
	})
}

func applyPatch(root, patchPath string) error {
	patch, err := readBounded(patchPath, vendorFileLimit)
	if err != nil {
		return err
	}
	files, _, err := gitdiff.Parse(bytes.NewReader(patch))
	if err != nil {
		return err
	}
	for _, file := range files {
		oldPath, err := patchPathWithin(root, file.OldName)
		if err != nil && !file.IsNew {
			return err
		}
		newPath, err := patchPathWithin(root, file.NewName)
		if err != nil && !file.IsDelete {
			return err
		}
		var original []byte
		if !file.IsNew {
			original, err = readBounded(oldPath, vendorFileLimit)
			if err != nil {
				return err
			}
		}
		result := boundedBuffer{remaining: vendorFileLimit}
		if err := gitdiff.Apply(&result, bytes.NewReader(original), file); err != nil {
			return err
		}
		if file.IsDelete {
			if err := os.Remove(oldPath); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(newPath), 0o755); err != nil {
			return err
		}
		mode := file.NewMode.Perm()
		if mode == 0 {
			if !file.IsNew {
				info, statErr := os.Stat(oldPath)
				if statErr != nil {
					return statErr
				}
				mode = info.Mode().Perm()
			} else {
				mode = 0o644
			}
		}
		if err := os.WriteFile(newPath, result.buffer.Bytes(), mode); err != nil {
			return err
		}
		if file.IsRename && oldPath != newPath {
			if err := os.Remove(oldPath); err != nil {
				return err
			}
		}
	}
	return nil
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int64
}

func (writer *boundedBuffer) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.remaining {
		return 0, fmt.Errorf("patched file exceeds %d bytes", vendorFileLimit)
	}
	written, err := writer.buffer.Write(data)
	writer.remaining -= int64(written)
	return written, err
}

func patchPathWithin(root, name string) (string, error) {
	if strings.HasPrefix(name, "a/") || strings.HasPrefix(name, "b/") {
		name = name[2:]
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if name == "/dev/null" || clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("patch path %q escapes vendor root", name)
	}
	return filepath.Join(root, clean), nil
}

func hashTree(root string) (string, error) {
	entries := make([]treehash.File, 0, 64)
	err := fssecure.WalkRegularFiles(root, func(path, relative string, info os.FileInfo) error {
		data, err := readBounded(path, vendorFileLimit)
		if err != nil {
			return err
		}
		entries = append(entries, treehash.File{
			Path: relative,
			Mode: info.Mode(),
			Data: data,
		})
		return nil
	})
	if err != nil {
		return "", err
	}
	return treehash.Sum(entries)
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, limit)
	}
	return data, nil
}
