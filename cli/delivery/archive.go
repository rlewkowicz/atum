package delivery

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"atum/cli/fssecure"
	"atum/cli/gitsnapshot"

	"github.com/go-git/go-git/v5/plumbing/filemode"
)

const copyBufferSize = 128 << 10

var copyBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, copyBufferSize)
	return &buffer
}}

type archiveIdentity struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func materializeBuildWorkspace(root string) (string, func(), error) {
	snapshot, err := gitsnapshot.Load(root)
	if err != nil {
		return "", nil, err
	}
	workspaceRoot, err := fssecure.EnsureDirectory(root, filepath.Join(".atum", "cache", "workspaces"), 0o700)
	if err != nil {
		return "", nil, err
	}
	destination, err := os.MkdirTemp(workspaceRoot, ".build-source-")
	if err != nil {
		return "", nil, err
	}
	destinationRelative, err := filepath.Rel(root, destination)
	if err != nil {
		_ = os.Remove(destination)
		return "", nil, err
	}
	cleanup := func() { _ = fssecure.RemoveTree(root, destinationRelative) }
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	for _, entry := range snapshot.Files {
		name := filepath.ToSlash(entry.Name)
		if !buildSnapshotPath(name) {
			continue
		}
		clean, err := cleanArchiveName(name)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		path := filepath.Join(destination, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			cleanup()
			return "", nil, err
		}
		switch entry.Mode {
		case filemode.Regular, filemode.Deprecated, filemode.Executable:
			mode := os.FileMode(0o644)
			if entry.Mode == filemode.Executable {
				mode = 0o755
			}
			if err := materializeGitFile(entry, path, mode, *buffer); err != nil {
				cleanup()
				return "", nil, err
			}
		case filemode.Symlink:
			target, err := entry.Contents()
			if err != nil || !containedLink(clean, target) {
				cleanup()
				if err != nil {
					return "", nil, err
				}
				return "", nil, fmt.Errorf("Git symlink %s escapes through %s", clean, target)
			}
			if err := os.Symlink(target, path); err != nil {
				cleanup()
				return "", nil, err
			}
		case filemode.Submodule:
			cleanup()
			return "", nil, fmt.Errorf("build source contains unsupported submodule %s", clean)
		default:
			cleanup()
			return "", nil, fmt.Errorf("build source contains unsupported mode %s at %s", entry.Mode, clean)
		}
	}
	return destination, cleanup, nil
}

func buildSnapshotPath(name string) bool {
	return name == ".dockerignore" || name == "go.mod" || name == "go.sum" ||
		strings.HasPrefix(name, "cli/") || strings.HasPrefix(name, "cmd/atum-operator/") ||
		strings.HasPrefix(name, "operator/") || strings.HasPrefix(name, "platform/build/")
}

func materializeGitFile(entry gitsnapshot.File, path string, mode os.FileMode, buffer []byte) error {
	reader, err := entry.Reader()
	if err != nil {
		return err
	}
	defer reader.Close()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	written, copyErr := io.CopyBuffer(file, reader, buffer)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != entry.Size {
		return fmt.Errorf("Git source %s yielded %d bytes, want %d", entry.Name, written, entry.Size)
	}
	return nil
}

func writeRegular(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	written, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func writeReaderEntry(writer *tar.Writer, buffer []byte, reader io.Reader, name string, mode, size int64) error {
	if err := writer.WriteHeader(normalizedHeader(name, mode, size, tar.TypeReg, "")); err != nil {
		return err
	}
	written, err := io.CopyBuffer(writer, reader, buffer)
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("archive input %s yielded %d bytes, want %d", name, written, size)
	}
	return nil
}

func writeDirectoryArchive(destination, root, artifactPath string) (archiveIdentity, error) {
	return writeArchive(destination, artifactPath, func(writer *tar.Writer, buffer []byte) error {
		return filepath.WalkDir(root, func(currentPath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if currentPath == root || entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, currentPath)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			name, err := cleanArchiveName(relative)
			if err != nil {
				return err
			}
			entryPath := filepath.Join(root, filepath.FromSlash(relative))
			info, err := os.Lstat(entryPath)
			if err != nil {
				return err
			}
			switch {
			case info.Mode().IsRegular():
				// The generated seed payload files are not executable;
				// normalizing their mode makes the archive independent of the
				// host umask and cache implementation.
				if err := writeFileEntry(writer, buffer, entryPath, name, 0o644); err != nil {
					return err
				}
			case info.Mode()&os.ModeSymlink != 0:
				target, err := os.Readlink(entryPath)
				if err != nil {
					return err
				}
				if !containedLink(name, target) {
					return fmt.Errorf("archive symlink %s escapes through %s", name, target)
				}
				if err := writer.WriteHeader(normalizedHeader(name, 0o777, 0, tar.TypeSymlink, target)); err != nil {
					return err
				}
			default:
				return fmt.Errorf("archive tree contains unsupported path %s", relative)
			}
			return nil
		})
	})
}

func writeArchive(destination, artifactPath string, populate func(*tar.Writer, []byte) error) (archiveIdentity, error) {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return archiveIdentity{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".archive-")
	if err != nil {
		return archiveIdentity{}, err
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return archiveIdentity{}, err
	}
	hash := sha256.New()
	counting := &countWriter{writer: io.MultiWriter(temporary, hash)}
	tarWriter := tar.NewWriter(counting)
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	if err := populate(tarWriter, *buffer); err != nil {
		_ = tarWriter.Close()
		return archiveIdentity{}, err
	}
	if err := tarWriter.Close(); err != nil {
		return archiveIdentity{}, err
	}
	if err := temporary.Sync(); err != nil {
		return archiveIdentity{}, err
	}
	if err := temporary.Close(); err != nil {
		return archiveIdentity{}, err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return archiveIdentity{}, err
	}
	remove = false
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return archiveIdentity{}, err
	}
	return archiveIdentity{File: artifactPath, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: counting.size}, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writeFileEntry(writer *tar.Writer, buffer []byte, path, name string, mode int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("archive input %s is not a regular file", path)
	}
	if err := writer.WriteHeader(normalizedHeader(name, mode, info.Size(), tar.TypeReg, "")); err != nil {
		return err
	}
	written, err := io.CopyBuffer(writer, file, buffer)
	if err != nil {
		return err
	}
	if written != info.Size() {
		return fmt.Errorf("archive input %s yielded %d bytes, want %d", name, written, info.Size())
	}
	return nil
}

func writeBytesEntry(writer *tar.Writer, name string, data []byte, mode int64) error {
	if err := writer.WriteHeader(normalizedHeader(name, mode, int64(len(data)), tar.TypeReg, "")); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

func normalizedHeader(name string, mode, size int64, typeFlag byte, link string) *tar.Header {
	epoch := time.Unix(0, 0).UTC()
	return &tar.Header{
		Name:       name,
		Linkname:   link,
		Size:       size,
		Mode:       mode,
		Typeflag:   typeFlag,
		ModTime:    epoch,
		AccessTime: epoch,
		ChangeTime: epoch,
		Uid:        0,
		Gid:        0,
		Format:     tar.FormatPAX,
	}
}

func cleanArchiveName(name string) (string, error) {
	name = filepath.ToSlash(filepath.Clean(name))
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return name, nil
}

func containedLink(name, target string) bool {
	if target == "" || filepath.IsAbs(target) {
		return false
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(filepath.FromSlash(name)), target))
	return resolved != ".." && !strings.HasPrefix(resolved, ".."+string(filepath.Separator))
}

type countWriter struct {
	writer io.Writer
	size   int64
}

func (writer *countWriter) Write(data []byte) (int, error) {
	written, err := writer.writer.Write(data)
	writer.size += int64(written)
	return written, err
}

func readerSHA256(reader io.Reader) (string, int64, error) {
	hash := sha256.New()
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	size, err := io.CopyBuffer(hash, reader, *buffer)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func acquireCopyBuffer() *[]byte {
	return copyBufferPool.Get().(*[]byte)
}

func releaseCopyBuffer(buffer *[]byte) {
	copyBufferPool.Put(buffer)
}
