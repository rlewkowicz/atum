package fssecure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyphar/filepath-securejoin/pathrs-lite"
	"github.com/gofrs/flock"
	"golang.org/x/sys/unix"
)

const streamBufferSize = 128 << 10

type destinationPolicy uint8

const (
	destinationAny destinationPolicy = iota
	destinationExisting
	destinationAbsent
)

var streamBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, streamBufferSize)
	return &buffer
}}

// OpenRegular opens a real regular file beneath root without permitting a
// symlink to escape the ownership boundary. Resolve rejects stable symlinks;
// pathrs keeps a concurrent replacement contained beneath root; and the final
// identity check rejects an in-root replacement before bytes are consumed.
func OpenRegular(root, relative string) (*os.File, error) {
	return openRegular(root, relative, unix.O_RDONLY|unix.O_CLOEXEC)
}

// ReadRegularCandidate returns the in-memory candidate for a managed path when
// present, otherwise it reads the current regular file through the same
// no-follow project boundary as OpenRegular.
func ReadRegularCandidate(
	root, relative string,
	candidates map[string][]byte,
) (string, []byte, error) {
	clean, err := Relative(relative)
	if err != nil {
		return "", nil, err
	}
	if data, exists := candidates[clean]; exists {
		return clean, data, nil
	}
	file, err := OpenRegular(root, clean)
	if err != nil {
		return clean, nil, err
	}
	data, readErr := io.ReadAll(file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return clean, nil, err
	}
	return clean, data, nil
}

// WriteRegular creates or atomically replaces a regular file beneath root.
func WriteRegular(root, relative string, data []byte, mode os.FileMode) error {
	return writeRegular(root, relative, data, mode, false)
}

// ReplaceRegular atomically replaces an existing regular file beneath root.
// The parent directory is held by file descriptor from temporary creation
// through rename, so a concurrent path substitution cannot redirect the
// write outside the project.
func ReplaceRegular(root, relative string, data []byte, mode os.FileMode) error {
	return writeRegular(root, relative, data, mode, true)
}

// WriteRegularFrom streams a reader into an atomically replaced regular file.
// It preserves the same path and durability guarantees as WriteRegular without
// materializing large publication or backup payloads in memory.
func WriteRegularFrom(root, relative string, reader io.Reader, mode os.FileMode) (int64, error) {
	if reader == nil {
		return 0, errors.New("managed file reader is nil")
	}
	var written int64
	err := replaceRegular(root, relative, mode, destinationAny, func(file *os.File) error {
		buffer := streamBufferPool.Get().(*[]byte)
		defer streamBufferPool.Put(buffer)
		var err error
		written, err = io.CopyBuffer(file, reader, *buffer)
		return err
	})
	return written, err
}

// CreateRegularFrom streams one immutable cache member directly into a new
// file. The caller owns an unpublished cache tree, so per-member fsync and
// rename provide no additional crash guarantee: the tree's final identity
// marker is the publication boundary. O_EXCL plus descriptor-relative parent
// resolution retains the no-follow and no-replacement guarantees.
func CreateRegularFrom(root, relative string, reader io.Reader, mode os.FileMode) (int64, error) {
	if reader == nil {
		return 0, errors.New("managed file reader is nil")
	}
	file, err := CreateRegularExclusive(root, relative, mode)
	if err != nil {
		return 0, err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = RemoveRegular(root, relative)
		}
	}()
	buffer := streamBufferPool.Get().(*[]byte)
	written, copyErr := io.CopyBuffer(file, reader, *buffer)
	streamBufferPool.Put(buffer)
	if copyErr != nil {
		return written, fmt.Errorf("write managed file %s: %w", relative, copyErr)
	}
	if err := file.Close(); err != nil {
		return written, fmt.Errorf("close managed file %s: %w", relative, err)
	}
	complete = true
	return written, nil
}

// CreateRegularExclusive opens a new regular file beneath root for streaming
// writes and refuses to replace an existing entry. The returned descriptor is
// opened relative to a protected parent directory with O_NOFOLLOW; the caller
// owns synchronization and close.
func CreateRegularExclusive(root, relative string, mode os.FileMode) (*os.File, error) {
	if mode.Perm() == 0 || mode&^os.ModePerm != 0 {
		return nil, fmt.Errorf("managed file %s has invalid mode %s", relative, mode)
	}
	parent, err := openManagedParent(root, relative)
	if err != nil {
		return nil, err
	}
	defer parent.directory.Close()
	fd, err := unix.Openat(
		int(parent.directory.Fd()),
		parent.name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		uint32(mode.Perm()),
	)
	if errors.Is(err, unix.EEXIST) {
		return nil, os.ErrExist
	}
	if err != nil {
		return nil, fmt.Errorf("create managed file %s: %w", parent.clean, err)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(parent.directory.Fd()), parent.name, 0)
		return nil, fmt.Errorf("set managed file %s mode: %w", parent.clean, err)
	}
	file := os.NewFile(uintptr(fd), parent.clean)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(parent.directory.Fd()), parent.name, 0)
		return nil, fmt.Errorf("create managed file %s: invalid descriptor", parent.clean)
	}
	return file, nil
}

// WriteRegularWith atomically replaces a regular file while allowing a
// streaming encoder to write directly into the protected destination. The
// callback must not retain the writer after it returns.
func WriteRegularWith(root, relative string, mode os.FileMode, write func(io.Writer) error) error {
	if write == nil {
		return errors.New("managed file writer is nil")
	}
	return replaceRegular(root, relative, mode, destinationAny, func(file *os.File) error {
		return write(file)
	})
}

// ReplaceRegularWith atomically replaces an existing regular file while
// allowing a streaming encoder to write directly into the protected target.
func ReplaceRegularWith(root, relative string, mode os.FileMode, write func(io.Writer) error) error {
	if write == nil {
		return errors.New("managed file writer is nil")
	}
	return replaceRegular(root, relative, mode, destinationExisting, func(file *os.File) error {
		return write(file)
	})
}

// CreateRegularWith atomically creates a new regular file and refuses to
// replace an existing destination. It is intended for unique state artifacts
// whose accidental overwrite would destroy recovery material.
func CreateRegularWith(root, relative string, mode os.FileMode, write func(io.Writer) error) error {
	if write == nil {
		return errors.New("managed file writer is nil")
	}
	return replaceRegular(root, relative, mode, destinationAbsent, func(file *os.File) error {
		return write(file)
	})
}

// CreateSymlink creates one symlink beneath root without following a mutable
// parent path or replacing an existing entry. Callers remain responsible for
// validating that target has the domain-specific containment they require.
func CreateSymlink(root, relative, target string) error {
	if target == "" || strings.ContainsRune(target, 0) {
		return fmt.Errorf("managed symlink %s has an invalid target", relative)
	}
	parent, err := openManagedParent(root, relative)
	if err != nil {
		return err
	}
	defer parent.directory.Close()
	if err := validateDestinationAt(parent.directory, parent.name, destinationAbsent); err != nil {
		return fmt.Errorf("inspect managed symlink %s: %w", parent.clean, err)
	}
	if err := unix.Symlinkat(target, int(parent.directory.Fd()), parent.name); err != nil {
		return fmt.Errorf("create managed symlink %s: %w", parent.clean, err)
	}
	if err := unix.Fsync(int(parent.directory.Fd())); err != nil {
		_ = unix.Unlinkat(int(parent.directory.Fd()), parent.name, 0)
		return fmt.Errorf("sync parent for managed symlink %s: %w", parent.clean, err)
	}
	return nil
}

// RemoveRegular unlinks one real regular file beneath root and synchronizes
// its parent directory. A missing file is already in the requested state.
func RemoveRegular(root, relative string) error {
	clean, err := Relative(relative)
	if err != nil {
		return err
	}
	root, err = Root(root)
	if err != nil {
		return err
	}
	parentHandle, err := pathrs.OpenInRoot(root, filepath.Dir(clean))
	if err != nil {
		return fmt.Errorf("open parent for %s: %w", clean, err)
	}
	defer parentHandle.Close()
	parent, err := pathrs.Reopen(parentHandle, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("reopen parent for %s: %w", clean, err)
	}
	defer parent.Close()
	name := filepath.Base(clean)
	var status unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &status, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect managed file %s: %w", clean, err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("managed file %s is not regular", clean)
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
		return fmt.Errorf("remove managed file %s: %w", clean, err)
	}
	if err := unix.Fsync(int(parent.Fd())); err != nil {
		return fmt.Errorf("sync parent after removing %s: %w", clean, err)
	}
	return nil
}

func writeRegular(root, relative string, data []byte, mode os.FileMode, requireExisting bool) error {
	_, err := writeRegularBytes(root, relative, data, mode, requireExisting)
	return err
}

func writeRegularBytes(root, relative string, data []byte, mode os.FileMode, requireExisting bool) (int64, error) {
	var written int64
	policy := destinationAny
	if requireExisting {
		policy = destinationExisting
	}
	err := replaceRegular(root, relative, mode, policy, func(file *os.File) error {
		count, err := file.Write(data)
		written = int64(count)
		if err == nil && count != len(data) {
			return io.ErrShortWrite
		}
		return err
	})
	return written, err
}

func replaceRegular(
	root, relative string,
	mode os.FileMode,
	policy destinationPolicy,
	write func(*os.File) error,
) error {
	if mode.Perm() == 0 || mode&^os.ModePerm != 0 {
		return fmt.Errorf("managed file %s has invalid mode %s", relative, mode)
	}
	parent, err := openManagedParent(root, relative)
	if err != nil {
		return err
	}
	defer parent.directory.Close()
	if err := validateDestinationAt(parent.directory, parent.name, policy); err != nil {
		return fmt.Errorf("inspect managed file %s: %w", parent.clean, err)
	}
	temporary, err := os.CreateTemp("/proc/self/fd/"+strconv.FormatUint(uint64(parent.directory.Fd()), 10), ".atum-replace-")
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", parent.clean, err)
	}
	temporaryName := filepath.Base(temporary.Name())
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = unix.Unlinkat(int(parent.directory.Fd()), temporaryName, 0)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary %s mode: %w", parent.clean, err)
	}
	if err := write(temporary); err != nil {
		return fmt.Errorf("write temporary %s: %w", parent.clean, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary %s: %w", parent.clean, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary %s: %w", parent.clean, err)
	}
	if err := validateDestinationAt(parent.directory, parent.name, policy); err != nil {
		return fmt.Errorf("reinspect managed file %s: %w", parent.clean, err)
	}
	if err := renameTemporary(parent.directory, temporaryName, parent.name, policy); err != nil {
		return fmt.Errorf("replace %s: %w", parent.clean, err)
	}
	remove = false
	if err := unix.Fsync(int(parent.directory.Fd())); err != nil {
		return fmt.Errorf("sync parent for %s: %w", parent.clean, err)
	}
	return nil
}

type managedParent struct {
	clean     string
	name      string
	directory *os.File
}

func openManagedParent(root, relative string) (*managedParent, error) {
	clean, err := Relative(relative)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(clean)
	if parent != "." {
		if _, err := EnsureDirectory(root, parent, 0o700); err != nil {
			return nil, err
		}
	}
	directory, err := openParentDirectory(root, clean)
	if err != nil {
		return nil, err
	}
	return &managedParent{clean: clean, name: filepath.Base(clean), directory: directory}, nil
}

func openParentDirectory(root, clean string) (*os.File, error) {
	root, err := Root(root)
	if err != nil {
		return nil, err
	}
	parentHandle, err := pathrs.OpenInRoot(root, filepath.Dir(clean))
	if err != nil {
		return nil, fmt.Errorf("open parent for %s: %w", clean, err)
	}
	defer parentHandle.Close()
	parentInfo, err := parentHandle.Stat()
	if err != nil || !parentInfo.IsDir() {
		if err != nil {
			return nil, fmt.Errorf("inspect parent for %s: %w", clean, err)
		}
		return nil, fmt.Errorf("parent for %s is not a directory", clean)
	}
	parentDirectory, err := pathrs.Reopen(parentHandle, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("reopen parent for %s: %w", clean, err)
	}
	return parentDirectory, nil
}

func renameTemporary(parent *os.File, temporary, destination string, policy destinationPolicy) error {
	if policy == destinationAbsent {
		err := unix.Renameat2(
			int(parent.Fd()), temporary,
			int(parent.Fd()), destination,
			unix.RENAME_NOREPLACE,
		)
		if errors.Is(err, unix.EEXIST) {
			return os.ErrExist
		}
		return err
	}
	return unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), destination)
}

func validateDestinationAt(parent *os.File, name string, policy destinationPolicy) error {
	if policy == destinationAbsent {
		var status unix.Stat_t
		err := unix.Fstatat(int(parent.Fd()), name, &status, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		return os.ErrExist
	}
	return requireRegularAt(parent, name, policy == destinationExisting)
}

func requireRegularAt(parent *os.File, name string, required bool) error {
	var status unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &status, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if required {
			return os.ErrNotExist
		}
		return nil
	}
	if err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("destination is not a regular file")
	}
	return nil
}

// RenameRegularNoReplace atomically publishes a regular file between managed
// directories on one filesystem. It never replaces an existing destination
// and proves that the published name still identifies the opened source inode.
func RenameRegularNoReplace(root, sourceRelative, destinationRelative string) (bool, error) {
	source, err := Relative(sourceRelative)
	if err != nil {
		return false, err
	}
	destination, err := Relative(destinationRelative)
	if err != nil {
		return false, err
	}
	sourceFile, err := OpenRegular(root, source)
	if err != nil {
		return false, err
	}
	defer sourceFile.Close()
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return false, err
	}
	root, err = Root(root)
	if err != nil {
		return false, err
	}
	sourceParent, err := openParentDirectory(root, source)
	if err != nil {
		return false, err
	}
	defer sourceParent.Close()
	destinationParent, err := openManagedParent(root, destination)
	if err != nil {
		return false, err
	}
	defer destinationParent.directory.Close()
	if err := unix.Renameat2(
		int(sourceParent.Fd()), filepath.Base(source),
		int(destinationParent.directory.Fd()), destinationParent.name,
		unix.RENAME_NOREPLACE,
	); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, fmt.Errorf("publish managed file %s: %w", destination, err)
	}
	published, err := OpenRegular(root, destination)
	if err != nil {
		return false, err
	}
	publishedInfo, statErr := published.Stat()
	closeErr := published.Close()
	if statErr != nil {
		return false, statErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if !os.SameFile(sourceInfo, publishedInfo) {
		return false, fmt.Errorf("managed file %s changed while it was published", destination)
	}
	if err := unix.Fsync(int(destinationParent.directory.Fd())); err != nil {
		return false, fmt.Errorf("sync destination parent for %s: %w", destination, err)
	}
	if filepath.Dir(source) != filepath.Dir(destination) {
		if err := unix.Fsync(int(sourceParent.Fd())); err != nil {
			return false, fmt.Errorf("sync source parent for %s: %w", source, err)
		}
	}
	return true, nil
}

// LockContext serializes cooperating project readers and writers on a
// non-symlinked, mode-0600 regular file beneath root.
func LockContext(ctx context.Context, root, relative string, retry time.Duration) (func(), error) {
	if retry <= 0 {
		return nil, errors.New("lock retry interval must be positive")
	}
	path, err := ensureRegular(root, relative, 0o600)
	if err != nil {
		return nil, err
	}
	lock := flock.New(path, flock.SetFlag(os.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW), flock.SetPermissions(0o600))
	locked, err := lock.TryLockContext(ctx, retry)
	if err != nil {
		return nil, err
	}
	if !locked {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("lock %s was not acquired", relative)
	}
	unlock := func() { _ = lock.Unlock() }
	lockedInfo, err := lock.Stat()
	if err != nil {
		unlock()
		return nil, fmt.Errorf("inspect locked file %s: %w", relative, err)
	}
	resolved, err := Resolve(root, relative, false)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("validate locked path %s: %w", relative, err)
	}
	pathInfo, err := os.Lstat(resolved)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(pathInfo, lockedInfo) {
		unlock()
		if err != nil {
			return nil, fmt.Errorf("inspect lock path %s: %w", relative, err)
		}
		return nil, fmt.Errorf("lock path %s changed or is not a real regular file", relative)
	}
	return unlock, nil
}

func ensureRegular(root, relative string, mode os.FileMode) (string, error) {
	clean, err := Relative(relative)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(clean)
	if parent != "." {
		if _, err := EnsureDirectory(root, parent, 0o700); err != nil {
			return "", err
		}
	}
	root, err = Root(root)
	if err != nil {
		return "", err
	}
	path, err := Resolve(root, clean, true)
	if err != nil {
		return "", err
	}
	rootHandle, err := os.OpenFile(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open project root for %s: %w", clean, err)
	}
	defer rootHandle.Close()
	fd, err := unix.Openat2(int(rootHandle.Fd()), clean, &unix.OpenHow{
		Flags:   uint64(unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC),
		Mode:    uint64(mode.Perm()),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err == nil {
		created := os.NewFile(uintptr(fd), path)
		if created == nil {
			_ = unix.Close(fd)
			return "", fmt.Errorf("create managed file %s: invalid file descriptor", clean)
		}
		if chmodErr := created.Chmod(mode); chmodErr != nil {
			_ = created.Close()
			return "", fmt.Errorf("secure managed file %s: %w", clean, chmodErr)
		}
		if closeErr := created.Close(); closeErr != nil {
			return "", fmt.Errorf("close managed file %s: %w", clean, closeErr)
		}
		return path, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return "", fmt.Errorf("create managed file %s: %w", clean, err)
	}
	file, err := openRegular(root, clean, unix.O_RDWR|unix.O_CLOEXEC)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return "", fmt.Errorf("secure managed file %s: %w", clean, err)
	}
	return path, nil
}

func openRegular(root, relative string, flags int) (*os.File, error) {
	clean, err := Relative(relative)
	if err != nil {
		return nil, err
	}
	root, err = Root(root)
	if err != nil {
		return nil, err
	}
	path, err := Resolve(root, clean, false)
	if err != nil {
		return nil, err
	}
	handle, err := pathrs.OpenInRoot(root, clean)
	if err != nil {
		return nil, fmt.Errorf("open managed file %s: %w", clean, err)
	}
	defer handle.Close()
	handleInfo, err := handle.Stat()
	if err != nil || !handleInfo.Mode().IsRegular() {
		if err != nil {
			return nil, fmt.Errorf("inspect managed file %s: %w", clean, err)
		}
		return nil, fmt.Errorf("managed file %s is not regular", clean)
	}
	file, err := pathrs.Reopen(handle, flags)
	if err != nil {
		return nil, fmt.Errorf("reopen managed file %s: %w", clean, err)
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(handleInfo, openedInfo) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect opened managed file %s: %w", clean, err)
		}
		return nil, fmt.Errorf("managed file %s changed while it was opened", clean)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect managed path %s: %w", clean, err)
		}
		return nil, fmt.Errorf("managed path %s changed or is not a real regular file", clean)
	}
	return file, nil
}
