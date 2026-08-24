package gitcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"atum/cli/fssecure"

	"github.com/Masterminds/semver/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

const lockRetry = 100 * time.Millisecond

type Manager struct {
	root string
}

type Release struct {
	Version string
	Commit  string
}

func New(root string) *Manager {
	return &Manager{root: root}
}

func (m *Manager) Path(name, commit string) (string, error) {
	if err := validateIdentity(name, commit); err != nil {
		return "", err
	}
	return fssecure.Resolve(m.root, filepath.Join(".atum", "cache", "upstreams", "full", name, commit), true)
}

func (m *Manager) Releases(ctx context.Context, url string) ([]Release, error) {
	commits, err := m.tagCommits(ctx, url)
	if err != nil {
		return nil, err
	}

	type versionedRelease struct {
		Release
		semantic *semver.Version
	}
	releases := make([]versionedRelease, 0, len(commits))
	for version, commit := range commits {
		semantic, parseErr := semver.NewVersion(strings.TrimPrefix(version, "v"))
		if parseErr != nil || semantic.Prerelease() != "" {
			continue
		}
		releases = append(releases, versionedRelease{
			Release:  Release{Version: version, Commit: commit},
			semantic: semantic,
		})
	}
	sort.Slice(releases, func(i, j int) bool {
		if comparison := releases[i].semantic.Compare(releases[j].semantic); comparison != 0 {
			return comparison > 0
		}
		return releases[i].Version < releases[j].Version
	})
	result := make([]Release, len(releases))
	for i := range releases {
		result[i] = releases[i].Release
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("Git source %s has no stable semantic-version tags", url)
	}
	return result, nil
}

func (m *Manager) tagCommits(ctx context.Context, url string) (map[string]string, error) {
	commits, _, err := m.references(ctx, url)
	return commits, err
}

func (m *Manager) references(ctx context.Context, url string) (map[string]string, string, error) {
	if strings.TrimSpace(url) == "" {
		return nil, "", errors.New("Git source URL is empty")
	}
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: git.DefaultRemoteName,
		URLs: []string{url},
	})
	refs, err := remote.ListContext(ctx, &git.ListOptions{PeelingOption: git.AppendPeeled})
	if err != nil {
		return nil, "", fmt.Errorf("list Git references from %s: %w", url, err)
	}

	commits := make(map[string]string, len(refs))
	defaultBranch := ""
	for _, ref := range refs {
		if ref.Name() == plumbing.HEAD && ref.Type() == plumbing.SymbolicReference {
			defaultBranch = strings.TrimPrefix(ref.Target().String(), "refs/heads/")
			continue
		}
		name := ref.Name().String()
		if !strings.HasPrefix(name, "refs/tags/") {
			continue
		}
		name = strings.TrimPrefix(name, "refs/tags/")
		if strings.HasSuffix(name, "^{}") {
			commits[strings.TrimSuffix(name, "^{}")] = ref.Hash().String()
			continue
		}
		if _, exists := commits[name]; !exists {
			commits[name] = ref.Hash().String()
		}
	}

	return commits, defaultBranch, nil
}

func (m *Manager) Resolve(ctx context.Context, url, version string) (Release, error) {
	semantic, err := semver.NewVersion(strings.TrimPrefix(version, "v"))
	if err != nil || semantic.Prerelease() != "" {
		return Release{}, fmt.Errorf("Git tag %q is not a stable semantic version", version)
	}
	return m.ResolveTag(ctx, url, version)
}

func (m *Manager) ResolveTag(ctx context.Context, url, version string) (Release, error) {
	commits, err := m.tagCommits(ctx, url)
	if err != nil {
		return Release{}, err
	}
	if commit, exists := commits[version]; exists {
		return Release{Version: version, Commit: commit}, nil
	}
	return Release{}, fmt.Errorf("Git source %s has no tag %q", url, version)
}

func (m *Manager) ResolveTagWithDefaultBranch(ctx context.Context, url, version string) (Release, string, error) {
	commits, branch, err := m.references(ctx, url)
	if err != nil {
		return Release{}, "", err
	}
	if branch == "" {
		return Release{}, "", fmt.Errorf("Git source %s does not advertise a default branch", url)
	}
	commit, exists := commits[version]
	if !exists {
		return Release{}, "", fmt.Errorf("Git source %s has no tag %q", url, version)
	}
	return Release{Version: version, Commit: commit}, branch, nil
}

func (m *Manager) Hydrate(ctx context.Context, name, url string, release Release) (string, error) {
	destination, err := m.Path(name, release.Commit)
	if err != nil {
		return "", err
	}
	unlock, err := fssecure.LockContext(
		ctx,
		m.root,
		filepath.Join(".atum", "cache", "locks", name+"-"+release.Commit+".lock"),
		lockRetry,
	)
	if err != nil {
		return "", fmt.Errorf("lock Git cache %s: %w", name, err)
	}
	defer unlock()

	if info, statErr := os.Lstat(destination); statErr == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("Git cache path %s is not a directory", destination)
		}
		if verifyErr := verifyCheckout(destination, url, release.Commit); verifyErr != nil {
			return "", verifyErr
		}
		return destination, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect Git cache %s: %w", destination, statErr)
	}

	parent, err := fssecure.EnsureDirectory(m.root, filepath.Join(".atum", "cache", "upstreams", "full", name), 0o700)
	if err != nil {
		return "", fmt.Errorf("create Git cache directory: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".hydrate-")
	if err != nil {
		return "", fmt.Errorf("create temporary Git cache: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()

	_, err = git.PlainCloneContext(ctx, temporary, false, &git.CloneOptions{
		URL:           url,
		ReferenceName: plumbing.NewTagReferenceName(release.Version),
		SingleBranch:  true,
		Tags:          git.NoTags,
	})
	if err != nil {
		return "", fmt.Errorf("hydrate %s at %s: %w", name, release.Version, err)
	}
	if err := verifyCheckout(temporary, url, release.Commit); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", fmt.Errorf("publish Git cache %s: %w", destination, err)
	}
	removeTemporary = false
	return destination, nil
}

func verifyCheckout(path, expectedURL, expectedCommit string) error {
	repository, err := git.PlainOpen(path)
	if err != nil {
		return fmt.Errorf("open Git cache %s: %w", path, err)
	}
	head, err := repository.Head()
	if err != nil {
		return fmt.Errorf("read Git cache HEAD %s: %w", path, err)
	}
	if head.Hash().String() != expectedCommit {
		return fmt.Errorf("Git cache %s is at %s, want %s", path, head.Hash(), expectedCommit)
	}
	shallow, err := repository.Storer.Shallow()
	if err != nil {
		return fmt.Errorf("inspect Git cache history %s: %w", path, err)
	}
	if len(shallow) != 0 {
		return fmt.Errorf("Git cache %s is shallow and cannot seed an exact disconnected repository", path)
	}
	remote, err := repository.Remote(git.DefaultRemoteName)
	if err != nil {
		return fmt.Errorf("read Git cache origin %s: %w", path, err)
	}
	urls := remote.Config().URLs
	if len(urls) != 1 || urls[0] != expectedURL {
		return fmt.Errorf("Git cache %s origin does not match %s", path, expectedURL)
	}
	if err := verifyCheckoutTree(repository, path, head.Hash()); err != nil {
		return err
	}
	return nil
}

type checkoutEntry struct {
	hash plumbing.Hash
	mode filemode.FileMode
}

func verifyCheckoutTree(repository *git.Repository, root string, commitHash plumbing.Hash) error {
	commit, err := repository.CommitObject(commitHash)
	if err != nil {
		return fmt.Errorf("read Git cache commit %s: %w", root, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("read Git cache tree %s: %w", root, err)
	}
	expected := make(map[string]checkoutEntry)
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		name, entry, nextErr := walker.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("walk Git cache tree %s: %w", root, nextErr)
		}
		switch entry.Mode {
		case filemode.Dir:
			continue
		case filemode.Submodule:
			return fmt.Errorf("Git cache %s contains unsupported submodule %s", root, name)
		case filemode.Regular, filemode.Deprecated, filemode.Executable, filemode.Symlink:
			expected[name] = checkoutEntry{hash: entry.Hash, mode: entry.Mode}
		default:
			return fmt.Errorf("Git cache %s contains unsupported mode %s at %s", root, entry.Mode, name)
		}
	}

	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		if relative == ".git" {
			return fmt.Errorf("Git cache %s metadata is not a directory", root)
		}
		if entry.IsDir() {
			return nil
		}
		relative = filepath.ToSlash(relative)
		want, exists := expected[relative]
		if !exists {
			return fmt.Errorf("immutable Git cache %s has untracked file %s", root, relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		actualMode, err := filemode.NewFromOSFileMode(info.Mode())
		if err != nil {
			return fmt.Errorf("inspect Git cache mode %s: %w", path, err)
		}
		if want.mode == filemode.Deprecated {
			want.mode = filemode.Regular
		}
		if actualMode != want.mode {
			return fmt.Errorf("immutable Git cache %s mode for %s is %s, want %s", root, relative, actualMode, want.mode)
		}
		if actualMode == filemode.Symlink {
			if err := verifyContainedSymlink(root, path, relative); err != nil {
				return err
			}
		}
		actualHash, err := checkoutBlobHash(path, info, actualMode)
		if err != nil {
			return err
		}
		if actualHash != want.hash {
			return fmt.Errorf("immutable Git cache %s content changed at %s", root, relative)
		}
		delete(expected, relative)
		return nil
	})
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		missing := make([]string, 0, len(expected))
		for name := range expected {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		shown := min(len(missing), 8)
		return fmt.Errorf("immutable Git cache %s is missing %d paths (first %d: %s)", root, len(missing), shown, strings.Join(missing[:shown], ", "))
	}
	return nil
}

func verifyContainedSymlink(root, path, relative string) error {
	target, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("read Git cache symlink %s: %w", path, err)
	}
	if filepath.IsAbs(target) {
		return fmt.Errorf("immutable Git cache %s symlink %s has absolute target %s", root, relative, target)
	}
	joined := filepath.Clean(filepath.Join(filepath.Dir(path), target))
	contained, err := filepath.Rel(root, joined)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return fmt.Errorf("immutable Git cache %s symlink %s escapes through %s", root, relative, target)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve Git cache symlink %s: %w", relative, err)
	}
	contained, err = filepath.Rel(root, resolved)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return fmt.Errorf("immutable Git cache %s symlink %s resolves outside the checkout", root, relative)
	}
	return nil
}

func checkoutBlobHash(path string, info os.FileInfo, mode filemode.FileMode) (plumbing.Hash, error) {
	if mode == filemode.Symlink {
		target, err := os.Readlink(path)
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("read Git cache symlink %s: %w", path, err)
		}
		return plumbing.ComputeHash(plumbing.BlobObject, []byte(target)), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("open Git cache file %s: %w", path, err)
	}
	defer file.Close()
	hasher := plumbing.NewHasher(plumbing.BlobObject, info.Size())
	if _, err := io.Copy(&hasher, file); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("hash Git cache file %s: %w", path, err)
	}
	return hasher.Sum(), nil
}

func validateIdentity(name, commit string) error {
	if name == "" || strings.ContainsAny(name, `/\\`) || name == "." || name == ".." {
		return fmt.Errorf("invalid Git cache name %q", name)
	}
	if len(commit) != 40 {
		return fmt.Errorf("invalid Git commit %q", commit)
	}
	for _, character := range commit {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return fmt.Errorf("invalid Git commit %q", commit)
		}
	}
	return nil
}
