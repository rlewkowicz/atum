package fssecure

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cyphar/filepath-securejoin/pathrs-lite"
	"golang.org/x/sys/unix"
)

const removeBatchSize = 128

// WalkRegularFiles visits every regular file beneath root exactly once. The
// relative path is slash-normalized for stable manifests and hashes.
func WalkRegularFiles(root string, visit func(path, relative string, info fs.FileInfo) error) error {
	if visit == nil {
		return errors.New("regular file visitor is nil")
	}
	return WalkTree(root, func(path, relative string, entry fs.DirEntry, info fs.FileInfo) error {
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("tree contains unsupported file %s with mode %s", path, info.Mode())
		}
		return visit(path, relative, info)
	})
}

// WalkTree visits every entry beneath root with one normalized relative path.
func WalkTree(root string, visit func(path, relative string, entry fs.DirEntry, info fs.FileInfo) error) error {
	if visit == nil {
		return errors.New("tree visitor is nil")
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return visit(path, filepath.ToSlash(relative), entry, info)
	})
}

// ReadDirectoryNames returns one bounded snapshot of a real directory beneath
// root without following symlinks. Callers that subsequently remove entries
// must still use descriptor-relative mutation helpers such as RemoveTree or
// RemoveRegular so a concurrent replacement remains contained.
func ReadDirectoryNames(root, relative string, limit int) ([]string, error) {
	if limit < 1 {
		return nil, errors.New("directory entry limit must be positive")
	}
	clean, err := Relative(relative)
	if err != nil {
		return nil, err
	}
	root, err = Root(root)
	if err != nil {
		return nil, err
	}
	handle, err := pathrs.OpenInRoot(root, clean)
	if err != nil {
		return nil, fmt.Errorf("open managed directory %s: %w", clean, err)
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || !info.IsDir() {
		if err != nil {
			return nil, fmt.Errorf("inspect managed directory %s: %w", clean, err)
		}
		return nil, fmt.Errorf("managed path %s is not a directory", clean)
	}
	directory, err := pathrs.Reopen(handle, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("reopen managed directory %s: %w", clean, err)
	}
	defer directory.Close()
	names := make([]string, 0, min(limit, removeBatchSize))
	for {
		batch, readErr := directory.Readdirnames(removeBatchSize)
		for _, name := range batch {
			if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
				return nil, fmt.Errorf("managed directory %s contains invalid entry %q", clean, name)
			}
			names = append(names, name)
			if len(names) > limit {
				return nil, fmt.Errorf("managed directory %s exceeds %d entries", clean, limit)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return names, nil
		}
		if readErr != nil {
			return nil, fmt.Errorf("read managed directory %s: %w", clean, readErr)
		}
	}
}

// RemoveTree removes one directory tree beneath root without following any
// symlink or crossing a nested mount. Every traversal step is relative to an
// already-open directory descriptor, so replacing a path component cannot
// redirect deletion outside the project boundary.
func RemoveTree(root, relative string) error {
	clean, err := Relative(relative)
	if err != nil {
		return err
	}
	root, err = Root(root)
	if err != nil {
		return err
	}
	parentRelative := filepath.Dir(clean)
	parentHandle, err := pathrs.OpenInRoot(root, parentRelative)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open parent for directory %s: %w", clean, err)
	}
	defer parentHandle.Close()
	parent, err := pathrs.Reopen(parentHandle, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("reopen parent for directory %s: %w", clean, err)
	}
	defer parent.Close()

	name := filepath.Base(clean)
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open directory %s for removal: %w", clean, err)
	}
	directory := os.NewFile(uintptr(fd), clean)
	if directory == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open directory %s for removal: invalid descriptor", clean)
	}
	defer directory.Close()
	if err := removeDirectoryContents(directory); err != nil {
		return fmt.Errorf("remove directory %s contents: %w", clean, err)
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove directory %s: %w", clean, err)
	}
	if err := unix.Fsync(int(parent.Fd())); err != nil {
		return fmt.Errorf("sync parent after removing directory %s: %w", clean, err)
	}
	return nil
}

func removeDirectoryContents(directory *os.File) error {
	duplicate, err := unix.Dup(int(directory.Fd()))
	if err != nil {
		return err
	}
	reader := os.NewFile(uintptr(duplicate), directory.Name())
	if reader == nil {
		_ = unix.Close(duplicate)
		return errors.New("duplicate directory descriptor is invalid")
	}
	defer reader.Close()
	for {
		names, readErr := reader.Readdirnames(removeBatchSize)
		for _, name := range names {
			if err := removeDirectoryEntry(directory, name); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func removeDirectoryEntry(parent *os.File, name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("directory contains invalid entry %q", name)
	}
	var status unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &status, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect entry %s: %w", name, err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove entry %s: %w", name, err)
		}
		return nil
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return fmt.Errorf("open child directory %s: %w", name, err)
	}
	child := os.NewFile(uintptr(fd), "/proc/self/fd/"+strconv.Itoa(fd))
	if child == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open child directory %s: invalid descriptor", name)
	}
	removeErr := removeDirectoryContents(child)
	closeErr := child.Close()
	if removeErr != nil {
		return removeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove child directory %s: %w", name, err)
	}
	return nil
}
