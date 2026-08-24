package fssecure

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyphar/filepath-securejoin/pathrs-lite"
	"golang.org/x/sys/unix"
)

// Root resolves a project root once and rejects a symlink at the ownership
// boundary. Managed paths can then be checked component-by-component without
// a time-of-check ambiguity caused by an aliased root.
func Root(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve project root %s: %w", path, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect project root %s: %w", absolute, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("project root %s must be a real directory", absolute)
	}
	return filepath.Clean(absolute), nil
}

// Relative normalizes a project-relative path without touching the file
// system.
func Relative(path string) (string, error) {
	clean := filepath.Clean(path)
	if path == "" || filepath.IsAbs(clean) || clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is not project-relative", path)
	}
	return clean, nil
}

// ValidName reports whether value is one portable lowercase path component.
func ValidName(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

// Resolve returns a path beneath root after proving that every existing
// component is non-symlinked. Missing final components are accepted only when
// allowMissing is true; all existing ancestors must be directories.
func Resolve(root, relative string, allowMissing bool) (string, error) {
	clean, err := Relative(relative)
	if err != nil {
		return "", err
	}
	root, err = Root(root)
	if err != nil {
		return "", err
	}
	components := strings.Split(clean, string(filepath.Separator))
	current := root
	for index, component := range components {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if !allowMissing {
				return "", fmt.Errorf("managed path %s does not exist: %w", clean, os.ErrNotExist)
			}
			return filepath.Join(root, clean), nil
		}
		if statErr != nil {
			return "", fmt.Errorf("inspect managed path %s: %w", clean, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("managed path %s traverses symlink %s", clean, strings.Join(components[:index+1], string(filepath.Separator)))
		}
		if index != len(components)-1 && !info.IsDir() {
			return "", fmt.Errorf("managed path %s has non-directory ancestor %s", clean, strings.Join(components[:index+1], string(filepath.Separator)))
		}
	}
	return filepath.Join(root, clean), nil
}

// EnsureDirectory creates a directory tree beneath root without following any
// existing symlink. Every newly created component receives mode; existing
// components must be real directories.
func EnsureDirectory(root, relative string, mode os.FileMode) (string, error) {
	clean, err := Relative(relative)
	if err != nil {
		return "", err
	}
	if mode.Perm() == 0 || mode&^os.ModePerm != 0 {
		return "", fmt.Errorf("directory %s has invalid mode %s", clean, mode)
	}
	root, err = Root(root)
	if err != nil {
		return "", err
	}
	rootDirectory, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open project root for directory %s: %w", clean, err)
	}
	defer rootDirectory.Close()
	handle, err := pathrs.MkdirAllHandle(rootDirectory, clean, mode.Perm())
	if err != nil {
		return "", fmt.Errorf("create directory %s: %w", clean, err)
	}
	defer handle.Close()
	handleInfo, err := handle.Stat()
	if err != nil || !handleInfo.IsDir() {
		if err != nil {
			return "", fmt.Errorf("inspect directory %s: %w", clean, err)
		}
		return "", fmt.Errorf("managed directory %s is not a directory", clean)
	}
	path, err := Resolve(root, clean, false)
	if err != nil {
		return "", err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.IsDir() || !os.SameFile(handleInfo, pathInfo) {
		if err != nil {
			return "", fmt.Errorf("inspect managed directory %s: %w", clean, err)
		}
		return "", fmt.Errorf("managed directory %s changed while it was created", clean)
	}
	return path, nil
}
