package gitsnapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"atum/cli/fssecure"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const identityBufferSize = 128 << 10

var identityBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, identityBufferSize)
	return &buffer
}}

// Snapshot is the sorted current tree used for an exact source handoff. Its
// membership comes from the Git index, while regular-file bytes and modes come
// from the working tree. This includes pull-generated and user-reviewed tracked
// changes without ever admitting ignored credentials or cache artifacts.
type Snapshot struct {
	Files []File
}

// File is one bounded, project-contained source entry. Regular contents are
// reopened on demand so large trees are streamed rather than retained in
// memory. Symlink targets are small and captured during snapshot discovery.
type File struct {
	Name    string
	Mode    filemode.FileMode
	Size    int64
	root    string
	symlink string
}

type Identity struct {
	SHA256 string
	Commit string
}

type treeNode struct {
	directories map[string]*treeNode
	entries     []object.TreeEntry
}

func Load(root string) (*Snapshot, error) {
	root, err := fssecure.Root(root)
	if err != nil {
		return nil, err
	}
	repository, err := git.PlainOpen(root)
	if err != nil {
		return nil, fmt.Errorf("open Git repository %s: %w", root, err)
	}
	index, err := repository.Storer.Index()
	if err != nil {
		return nil, fmt.Errorf("read Git index %s: %w", root, err)
	}
	files := make([]File, 0, len(index.Entries))
	seen := make(map[string]struct{}, len(index.Entries))
	for _, indexed := range index.Entries {
		if indexed.Stage != 0 {
			return nil, fmt.Errorf("Git index contains an unresolved entry for %s", indexed.Name)
		}
		clean, err := fssecure.Relative(filepath.FromSlash(indexed.Name))
		if err != nil {
			return nil, fmt.Errorf("Git index path %q is invalid: %w", indexed.Name, err)
		}
		name := filepath.ToSlash(clean)
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("Git index path %s is duplicated", name)
		}
		seen[name] = struct{}{}
		path, err := trackedPath(root, clean)
		if errors.Is(err, os.ErrNotExist) {
			// An unstaged deletion can remove the last tracked file and its
			// now-empty parent directory. Treat that exactly like a missing leaf.
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			// A tracked working-tree deletion is part of the current source
			// snapshot, just as an index deletion is.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect tracked source %s: %w", name, err)
		}
		entry := File{Name: name, Size: info.Size(), root: root}
		switch {
		case info.Mode().IsRegular():
			entry.Mode = filemode.Regular
			if info.Mode().Perm()&0o111 != 0 {
				entry.Mode = filemode.Executable
			}
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return nil, fmt.Errorf("read tracked symlink %s: %w", name, err)
			}
			entry.Mode = filemode.Symlink
			entry.Size = int64(len(target))
			entry.symlink = target
		default:
			return nil, fmt.Errorf("tracked source %s has unsupported mode %s", name, info.Mode())
		}
		files = append(files, entry)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return &Snapshot{Files: files}, nil
}

func trackedPath(root, relative string) (string, error) {
	parent := filepath.Dir(relative)
	if parent == "." {
		return filepath.Join(root, relative), nil
	}
	resolved, err := fssecure.Resolve(root, parent, false)
	if err != nil {
		return "", fmt.Errorf("resolve tracked source parent %s: %w", parent, err)
	}
	return filepath.Join(resolved, filepath.Base(relative)), nil
}

// Reader opens an exact regular entry without following a project-boundary
// symlink. The captured size is checked again by each streaming consumer.
func (file File) Reader() (io.ReadCloser, error) {
	if file.Mode != filemode.Regular && file.Mode != filemode.Executable && file.Mode != filemode.Deprecated {
		return nil, fmt.Errorf("tracked source %s is not a regular file", file.Name)
	}
	return fssecure.OpenRegular(file.root, filepath.FromSlash(file.Name))
}

// Contents returns the captured target of a tracked symlink.
func (file File) Contents() (string, error) {
	if file.Mode != filemode.Symlink {
		return "", fmt.Errorf("tracked source %s is not a symlink", file.Name)
	}
	return file.symlink, nil
}

// SHA256 identifies normalized paths, modes, and bytes. Overrides replace
// committed regular-file content before hashing, preventing the generated
// bundle field in atum.lock.json from making the source identity recursive.
func (snapshot *Snapshot) SHA256(overrides map[string][]byte) (string, error) {
	identity, err := snapshot.Identity(overrides)
	return identity.SHA256, err
}

// SHA256Prefix identifies the tracked working-tree entries rooted at one
// repository-relative path. Keeping subset membership tied to the Git index
// excludes ignored runtime artifacts while still including reviewed
// modifications to tracked inputs.
func (snapshot *Snapshot) SHA256Prefix(prefix string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(prefix))
	if clean == "." || clean == "" || filepath.IsAbs(prefix) ||
		clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("Git snapshot prefix %q is invalid", prefix)
	}
	withSeparator := clean + "/"
	files := make([]File, 0, len(snapshot.Files))
	for _, file := range snapshot.Files {
		if file.Name == clean || strings.HasPrefix(file.Name, withSeparator) {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("Git snapshot prefix %s has no tracked files", clean)
	}
	return (&Snapshot{Files: files}).SHA256(nil)
}

// Identity binds the normalized source bytes to the deterministic Git commit
// that Forgejo exposes to Flux. Computing both identities in one traversal
// avoids a second read of every tracked file.
func (snapshot *Snapshot) Identity(overrides map[string][]byte) (Identity, error) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "atum-git-snapshot-v1\x00")
	remaining := make(map[string]struct{}, len(overrides))
	for name := range overrides {
		remaining[filepath.ToSlash(name)] = struct{}{}
	}
	root := &treeNode{directories: make(map[string]*treeNode)}
	buffer := identityBufferPool.Get().(*[]byte)
	defer identityBufferPool.Put(buffer)
	for _, entry := range snapshot.Files {
		name := filepath.ToSlash(entry.Name)
		var mode int64
		var gitMode filemode.FileMode
		switch entry.Mode {
		case filemode.Regular, filemode.Deprecated:
			mode = 0o644
			gitMode = filemode.Regular
		case filemode.Executable:
			mode = 0o755
			gitMode = filemode.Executable
		case filemode.Symlink:
			mode = 0o777
			gitMode = filemode.Symlink
		case filemode.Submodule:
			return Identity{}, fmt.Errorf("Git snapshot contains unsupported submodule %s", name)
		default:
			return Identity{}, fmt.Errorf("Git snapshot contains unsupported mode %s at %s", entry.Mode, name)
		}
		var blobHash plumbing.Hash
		if replacement, exists := overrides[name]; exists {
			if entry.Mode != filemode.Regular && entry.Mode != filemode.Deprecated {
				return Identity{}, fmt.Errorf("Git snapshot replacement %s is not a regular file", name)
			}
			_, _ = fmt.Fprintf(hash, "%s\x00%o\x00%d\x00", name, mode, len(replacement))
			_, _ = hash.Write(replacement)
			_, _ = hash.Write([]byte{0})
			blobHash = plumbing.ComputeHash(plumbing.BlobObject, replacement)
			delete(remaining, name)
		} else if entry.Mode == filemode.Symlink {
			target, err := entry.Contents()
			if err != nil {
				return Identity{}, err
			}
			_, _ = fmt.Fprintf(hash, "%s\x00%o\x00%d\x00", name, mode, len(target))
			_, _ = io.WriteString(hash, target)
			_, _ = hash.Write([]byte{0})
			blobHash = plumbing.ComputeHash(plumbing.BlobObject, []byte(target))
		} else {
			_, _ = fmt.Fprintf(hash, "%s\x00%o\x00%d\x00", name, mode, entry.Size)
			reader, err := entry.Reader()
			if err != nil {
				return Identity{}, fmt.Errorf("open Git snapshot file %s: %w", name, err)
			}
			blobHasher := plumbing.NewHasher(plumbing.BlobObject, entry.Size)
			written, copyErr := io.CopyBuffer(io.MultiWriter(hash, &blobHasher), reader, *buffer)
			closeErr := reader.Close()
			if copyErr != nil {
				return Identity{}, fmt.Errorf("hash Git snapshot file %s: %w", name, copyErr)
			}
			if closeErr != nil {
				return Identity{}, fmt.Errorf("close Git snapshot file %s: %w", name, closeErr)
			}
			if written != entry.Size {
				return Identity{}, fmt.Errorf("Git snapshot file %s yielded %d bytes, want %d", name, written, entry.Size)
			}
			_, _ = hash.Write([]byte{0})
			blobHash = blobHasher.Sum()
		}
		if err := root.add(name, gitMode, blobHash); err != nil {
			return Identity{}, err
		}
	}
	if len(remaining) != 0 {
		names := make([]string, 0, len(remaining))
		for name := range remaining {
			names = append(names, name)
		}
		sort.Strings(names)
		return Identity{}, fmt.Errorf("Git snapshot replacements are absent from the Git index: %v", names)
	}
	treeHash, err := root.hash()
	if err != nil {
		return Identity{}, err
	}
	signature := object.Signature{
		Name:  "Atum Genesis",
		Email: "atum@localhost",
		When:  time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	commit := &object.Commit{
		Author:    signature,
		Committer: signature,
		TreeHash:  treeHash,
		Message:   "Seed exact Atum deployment source\n",
	}
	encoded := &plumbing.MemoryObject{}
	if err := commit.Encode(encoded); err != nil {
		return Identity{}, fmt.Errorf("encode deterministic Atum source commit: %w", err)
	}
	return Identity{SHA256: hex.EncodeToString(hash.Sum(nil)), Commit: encoded.Hash().String()}, nil
}

func (node *treeNode) add(name string, mode filemode.FileMode, hash plumbing.Hash) error {
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return fmt.Errorf("Git snapshot path %q is empty", name)
	}
	current := node
	for _, component := range parts[:len(parts)-1] {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("Git snapshot path %q is invalid", name)
		}
		if current.directories == nil {
			current.directories = make(map[string]*treeNode)
		}
		child := current.directories[component]
		if child == nil {
			child = &treeNode{directories: make(map[string]*treeNode)}
			current.directories[component] = child
		}
		current = child
	}
	leaf := parts[len(parts)-1]
	if leaf == "" || leaf == "." || leaf == ".." {
		return fmt.Errorf("Git snapshot path %q is invalid", name)
	}
	current.entries = append(current.entries, object.TreeEntry{Name: leaf, Mode: mode, Hash: hash})
	return nil
}

func (node *treeNode) hash() (plumbing.Hash, error) {
	entries := make([]object.TreeEntry, 0, len(node.entries)+len(node.directories))
	entries = append(entries, node.entries...)
	for name, child := range node.directories {
		hash, err := child.hash()
		if err != nil {
			return plumbing.ZeroHash, err
		}
		entries = append(entries, object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: hash})
	}
	sort.Sort(object.TreeEntrySorter(entries))
	encoded := &plumbing.MemoryObject{}
	if err := (&object.Tree{Entries: entries}).Encode(encoded); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("encode deterministic Atum source tree: %w", err)
	}
	return encoded.Hash(), nil
}
