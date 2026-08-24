package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"atum/cli/delivery"
	"atum/cli/fssecure"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"

	forgejo "codeberg.org/mvdkleijn/forgejo-sdk/forgejo/v2"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"golang.org/x/sync/errgroup"
)

const (
	gitCopyBufferSize = 128 << 10
	forgejoPushRemote = "atum-publish"
	forgejoRefTimeout = 30 * time.Second
	forgejoRefPoll    = 250 * time.Millisecond
	deployedBranch    = "deployed"
	fluxTokenName     = "atum-flux-read"
)

type forgejoControl struct {
	api       *forgejo.Client
	url       string
	username  string
	fluxToken string
	auth      *githttp.BasicAuth
	root      string
}

func (service Service) configureForgejo(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	credentials atumsecrets.Document,
) (*forgejoControl, error) {
	sources := service.Project.Desired.Platform.Sources
	endpoint := strings.TrimSuffix(sources.ExternalURL, "/")
	api, err := forgejo.NewClient(endpoint,
		forgejo.SetHTTPClient(&http.Client{Timeout: 60 * time.Second}),
		forgejo.SetContext(ctx),
		forgejo.SetBasicAuth(credentials.Forgejo.Username, credentials.Forgejo.AdminPassword),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Forgejo API client: %w", err)
	}
	if _, _, err := api.GetMyUserInfo(); err != nil {
		return nil, fmt.Errorf("authenticate Forgejo administrator: %w", err)
	}
	control := &forgejoControl{
		api: api, url: endpoint, username: credentials.Forgejo.Username,
		auth: &githttp.BasicAuth{
			Username: credentials.Forgejo.Username,
			Password: credentials.Forgejo.AdminPassword,
		},
		root: service.Project.Root,
	}
	if err := control.ensureOrganization(sources.Organization, "Atum Platform", forgejo.VisibleTypePrivate); err != nil {
		return nil, err
	}
	if err := control.ensureOrganization(sources.UpstreamOrganization, "Atum Immutable Upstreams", forgejo.VisibleTypePublic); err != nil {
		return nil, err
	}
	if err := control.ensureRepository(sources.Organization, sources.Repository, "Exact Atum deployment source", true); err != nil {
		return nil, err
	}
	if err := control.publishAtumSource(ctx, bundle, sources.Organization, sources.Repository); err != nil {
		return nil, err
	}
	total := len(bundle.Repositories) + 1
	var published atomic.Int64
	published.Store(1)
	progress.Update(ctx, progress.Platform, "forgejo", "Forgejo sources",
		"published exact Atum source", 1, total)

	parallelism := min(max(service.Project.Desired.Updates.Parallelism, 1), 16)
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for _, repository := range bundle.Repositories {
		repository := repository
		group.Go(func() error {
			if err := control.ensureRepository(
				sources.UpstreamOrganization,
				repository.ID,
				"Immutable upstream snapshot for "+repository.ID,
				false,
			); err != nil {
				return err
			}
			if err := control.publishUpstream(groupContext, repository, sources.UpstreamOrganization); err != nil {
				return err
			}
			current := int(published.Add(1))
			progress.Update(groupContext, progress.Platform, "forgejo", "Forgejo sources",
				"published immutable source "+repository.ID, current, total)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return control, nil
}

func (control *forgejoControl) rotateFluxToken() (string, error) {
	if response, err := control.api.DeleteAccessToken(fluxTokenName); err != nil && forgejoStatus(response) != http.StatusNotFound {
		return "", fmt.Errorf("remove previous Flux read token: %w", err)
	}
	token, _, err := control.api.CreateAccessToken(forgejo.CreateAccessTokenOption{
		Name: fluxTokenName,
		Scopes: []forgejo.AccessTokenScope{
			forgejo.AccessTokenScopeRepositoryRead,
		},
	})
	if err != nil {
		return "", fmt.Errorf("create Flux read token: %w", err)
	}
	if token == nil || token.Token == "" {
		return "", errors.New("Forgejo returned no Flux read token")
	}
	return token.Token, nil
}

func forgejoStatus(response *forgejo.Response) int {
	if response == nil || response.Response == nil {
		return 0
	}
	return response.StatusCode
}

func (control *forgejoControl) ensureOrganization(name, fullName string, visibility forgejo.VisibleType) error {
	current, response, err := control.api.GetOrg(name)
	if err == nil {
		if current == nil {
			return fmt.Errorf("Forgejo organization %s returned no state", name)
		}
		if current.Visibility == string(visibility) && current.FullName == fullName {
			return nil
		}
		if _, err := control.api.EditOrg(name, forgejo.EditOrgOption{
			FullName: fullName, Visibility: visibility,
		}); err != nil {
			return fmt.Errorf("update Forgejo organization %s: %w", name, err)
		}
		return nil
	}
	if forgejoStatus(response) != http.StatusNotFound {
		return fmt.Errorf("inspect Forgejo organization %s: %w", name, err)
	}
	_, _, err = control.api.CreateOrg(forgejo.CreateOrgOption{Name: name, FullName: fullName, Visibility: visibility})
	if err != nil {
		return fmt.Errorf("create Forgejo organization %s: %w", name, err)
	}
	return nil
}

func (control *forgejoControl) ensureRepository(owner, name, description string, private bool) error {
	current, response, err := control.api.GetRepo(owner, name)
	if err == nil {
		if current == nil {
			return fmt.Errorf("Forgejo repository %s/%s returned no state", owner, name)
		}
		if current.Private == private && current.Description == description {
			return nil
		}
		if _, _, err := control.api.EditRepo(owner, name, forgejo.EditRepoOption{
			Description: &description, Private: &private,
		}); err != nil {
			return fmt.Errorf("update Forgejo repository %s/%s: %w", owner, name, err)
		}
		return nil
	}
	if forgejoStatus(response) != http.StatusNotFound {
		return fmt.Errorf("inspect Forgejo repository %s/%s: %w", owner, name, err)
	}
	_, _, err = control.api.CreateOrgRepo(owner, forgejo.CreateRepoOption{
		Name: name, Description: description, Private: private, AutoInit: false, DefaultBranch: "main",
	})
	if err != nil {
		return fmt.Errorf("create Forgejo repository %s/%s: %w", owner, name, err)
	}
	return nil
}

func (control *forgejoControl) publishAtumSource(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	owner, name string,
) error {
	return control.withAtumRepository(bundle, func(repository *git.Repository, commit plumbing.Hash) error {
		for _, reference := range []plumbing.ReferenceName{
			plumbing.NewBranchReferenceName("main"),
			plumbing.NewTagReferenceName(bundle.SourceTag),
		} {
			if err := repository.Storer.SetReference(plumbing.NewHashReference(reference, commit)); err != nil {
				return err
			}
		}
		if err := control.pushImmutable(ctx, repository, owner, name, bundle.SourceTag, bundle.SourceCommit); err != nil {
			return err
		}
		return control.advanceBranch(ctx, repository, owner, name, "main", bundle.SourceCommit)
	})
}

// activateAtumSource is the sole deployed-branch handoff. Immutable source
// publication happens before Kubespray so a fresh cluster has everything it
// needs, while this ref update is delayed until the compatibility planner has
// selected the platform side of the transition.
func (control *forgejoControl) activateAtumSource(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	owner, name string,
) error {
	return control.withAtumRepository(bundle, func(repository *git.Repository, commit plumbing.Hash) error {
		deployed := plumbing.NewBranchReferenceName(deployedBranch)
		if err := repository.Storer.SetReference(plumbing.NewHashReference(deployed, commit)); err != nil {
			return err
		}
		return control.advanceBranch(ctx, repository, owner, name, deployedBranch, bundle.SourceCommit)
	})
}

func (control *forgejoControl) withAtumRepository(
	bundle *delivery.DeploymentBundle,
	operation func(*git.Repository, plumbing.Hash) error,
) error {
	stageParent, err := fssecure.EnsureDirectory(control.root, filepath.Join(".atum", "state", "forgejo-stage"), 0o700)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(stageParent, "source-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyVerifiedTree(bundle.SourceRoot, stage); err != nil {
		return err
	}
	repository, err := git.PlainInit(stage, false)
	if err != nil {
		return fmt.Errorf("initialize Atum source repository: %w", err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return err
	}
	if err := worktree.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		return fmt.Errorf("index Atum source repository: %w", err)
	}
	signature := &object.Signature{
		Name: "Atum Genesis", Email: "atum@localhost",
		When: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	commit, err := worktree.Commit("Seed exact Atum deployment source\n", &git.CommitOptions{
		Author: signature, Committer: signature,
	})
	if err != nil {
		return fmt.Errorf("commit Atum source repository: %w", err)
	}
	if commit.String() != bundle.SourceCommit {
		return fmt.Errorf("materialized Atum source commit is %s, want %s", commit, bundle.SourceCommit)
	}
	return operation(repository, commit)
}

func (control *forgejoControl) publishUpstream(
	ctx context.Context,
	source delivery.BundleRepository,
	owner string,
) error {
	repository, head, err := openBundledUpstream(source)
	if err != nil {
		return err
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(
		plumbing.NewTagReferenceName(source.Version), head,
	)); err != nil {
		return err
	}
	return control.pushImmutable(ctx, repository, owner, source.ID, source.Version, source.Commit)
}

func (control *forgejoControl) activateUpstreams(
	ctx context.Context,
	sources []delivery.BundleRepository,
	owner string,
	parallelism int,
) error {
	var activated atomic.Int64
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(min(max(parallelism, 1), 16))
	for _, source := range sources {
		source := source
		group.Go(func() error {
			repository, head, err := openBundledUpstream(source)
			if err != nil {
				return err
			}
			if err := repository.Storer.SetReference(plumbing.NewHashReference(
				plumbing.NewBranchReferenceName("main"), head,
			)); err != nil {
				return err
			}
			if err := control.advanceBranch(groupContext, repository, owner, source.ID, "main", source.Commit); err != nil {
				return err
			}
			current := int(activated.Add(1))
			progress.Update(groupContext, progress.Platform, "forgejo", "Forgejo sources",
				"advanced upstream source "+source.ID, current+1, len(sources)+1)
			return nil
		})
	}
	return group.Wait()
}

func openBundledUpstream(source delivery.BundleRepository) (*git.Repository, plumbing.Hash, error) {
	repository, err := git.PlainOpen(source.Path)
	if err != nil {
		return nil, plumbing.ZeroHash, fmt.Errorf("open bundled repository %s: %w", source.ID, err)
	}
	head, err := repository.Head()
	if err != nil {
		return nil, plumbing.ZeroHash, err
	}
	if head.Hash().String() != source.Commit {
		return nil, plumbing.ZeroHash, fmt.Errorf(
			"bundled repository %s is at %s, want %s", source.ID, head.Hash(), source.Commit,
		)
	}
	return repository, head.Hash(), nil
}

func (control *forgejoControl) remote(repository *git.Repository, owner, name string) *git.Remote {
	return git.NewRemote(repository.Storer, &gitconfig.RemoteConfig{
		Name: forgejoPushRemote, URLs: []string{control.url + "/" + owner + "/" + name + ".git"},
	})
}

func (control *forgejoControl) pushImmutable(
	ctx context.Context,
	repository *git.Repository,
	owner, name, tag, commit string,
) error {
	existing, found, err := control.exactTag(owner, name, tag)
	if err != nil {
		return err
	}
	if found {
		if existing != commit {
			return fmt.Errorf("immutable Forgejo tag %s/%s:%s resolves to %s, want %s", owner, name, tag, existing, commit)
		}
		return nil
	}
	ref := plumbing.NewTagReferenceName(tag).String()
	err = control.remote(repository, owner, name).PushContext(ctx, &git.PushOptions{
		Auth: control.auth, RemoteName: forgejoPushRemote,
		RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec(ref + ":" + ref)},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("publish Forgejo tag %s/%s:%s: %w", owner, name, tag, err)
	}
	existing, found, err = control.exactTag(owner, name, tag)
	if err != nil {
		return err
	}
	if !found || existing != commit {
		return fmt.Errorf("published Forgejo tag %s/%s:%s resolves to %s, want %s", owner, name, tag, existing, commit)
	}
	return nil
}

func (control *forgejoControl) advanceBranch(
	ctx context.Context,
	repository *git.Repository,
	owner, name, branchName, commit string,
) error {
	current, found, err := control.exactBranch(owner, name, branchName)
	if err != nil {
		return err
	}
	if found && current == commit {
		return nil
	}
	local := plumbing.NewBranchReferenceName(branchName)
	remote := local
	options := &git.PushOptions{
		Auth: control.auth, RemoteName: forgejoPushRemote,
		RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec(local.String() + ":" + remote.String())},
	}
	if found {
		expected := plumbing.NewHash(current)
		tracking := plumbing.NewRemoteReferenceName(forgejoPushRemote, branchName)
		if err := repository.Storer.SetReference(plumbing.NewHashReference(tracking, expected)); err != nil {
			return fmt.Errorf("record Forgejo branch lease %s/%s:%s: %w", owner, name, branchName, err)
		}
		options.ForceWithLease = &git.ForceWithLease{RefName: remote, Hash: expected}
	}
	err = control.remote(repository, owner, name).PushContext(ctx, options)
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		latest, latestFound, latestErr := control.exactBranch(owner, name, branchName)
		if latestErr == nil && latestFound && latest == commit {
			return nil
		}
		return fmt.Errorf("advance Forgejo branch %s/%s:%s with lease: %w", owner, name, branchName, err)
	}
	return control.waitExactRemoteBranch(ctx, repository, owner, name, branchName, commit)
}

func (control *forgejoControl) waitExactRemoteBranch(
	ctx context.Context,
	repository *git.Repository,
	owner, name, branchName, commit string,
) error {
	return control.waitForExactBranch(ctx, owner, name, branchName, commit,
		func(ctx context.Context) (string, bool, error) {
			return control.exactRemoteBranch(ctx, repository, owner, name, branchName)
		})
}

func (control *forgejoControl) waitExactBranch(ctx context.Context, owner, name, branchName, commit string) error {
	return control.waitForExactBranch(ctx, owner, name, branchName, commit,
		func(context.Context) (string, bool, error) {
			return control.exactBranch(owner, name, branchName)
		})
}

func (control *forgejoControl) waitForExactBranch(
	ctx context.Context,
	owner, name, branchName, commit string,
	lookup func(context.Context) (string, bool, error),
) error {
	waitContext, cancel := context.WithTimeout(ctx, forgejoRefTimeout)
	defer cancel()
	ticker := time.NewTicker(forgejoRefPoll)
	defer ticker.Stop()
	var lastErr error
	for {
		current, found, err := lookup(waitContext)
		if err == nil && found {
			if current != commit {
				return fmt.Errorf("verify Forgejo branch %s/%s:%s: resolves to %s, want %s",
					owner, name, branchName, current, commit)
			}
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("branch is absent")
		}
		select {
		case <-waitContext.Done():
			return fmt.Errorf("verify Forgejo branch %s/%s:%s: %w: %v",
				owner, name, branchName, waitContext.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func (control *forgejoControl) exactRemoteBranch(
	ctx context.Context,
	repository *git.Repository,
	owner, name, branchName string,
) (string, bool, error) {
	references, err := control.remote(repository, owner, name).ListContext(ctx, &git.ListOptions{Auth: control.auth})
	if err != nil {
		return "", false, fmt.Errorf("list Forgejo references %s/%s: %w", owner, name, err)
	}
	wanted := plumbing.NewBranchReferenceName(branchName)
	for _, reference := range references {
		if reference.Name() == wanted {
			return reference.Hash().String(), true, nil
		}
	}
	return "", false, nil
}

func (control *forgejoControl) exactBranch(owner, name, branchName string) (string, bool, error) {
	branch, response, err := control.api.GetRepoBranch(owner, name, branchName)
	if err != nil {
		if forgejoStatus(response) == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, fmt.Errorf("inspect Forgejo branch %s/%s:%s: %w", owner, name, branchName, err)
	}
	if branch == nil || branch.Commit == nil || !plumbing.IsHash(branch.Commit.ID) {
		return "", false, errors.New("Forgejo returned an empty branch")
	}
	return branch.Commit.ID, true, nil
}

func (control *forgejoControl) exactTag(owner, name, tag string) (string, bool, error) {
	current, response, err := control.api.GetTag(owner, name, tag)
	if err != nil {
		if forgejoStatus(response) == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, fmt.Errorf("inspect Forgejo tag %s/%s:%s: %w", owner, name, tag, err)
	}
	if current == nil {
		return "", false, errors.New("Forgejo returned an empty tag")
	}
	commit := current.ID
	if current.Commit != nil && current.Commit.SHA != "" {
		commit = current.Commit.SHA
	}
	if !plumbing.IsHash(commit) {
		return "", false, errors.New("Forgejo returned an invalid tag commit")
	}
	return commit, true, nil
}

func copyVerifiedTree(source, destination string) error {
	buffer := make([]byte, gitCopyBufferSize)
	return fssecure.WalkTree(source, func(path, relative string, entry os.DirEntry, info os.FileInfo) error {
		if relative == "." {
			return nil
		}
		target := filepath.Join(destination, filepath.FromSlash(relative))
		switch {
		case entry.IsDir():
			return os.Mkdir(target, 0o700)
		case info.Mode().IsRegular():
			input, err := os.Open(path)
			if err != nil {
				return err
			}
			mode := os.FileMode(0o600)
			if info.Mode().Perm()&0o111 != 0 {
				mode = 0o700
			}
			output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				_ = input.Close()
				return err
			}
			written, copyErr := io.CopyBuffer(output, input, buffer)
			closeInputErr := input.Close()
			closeOutputErr := output.Close()
			if copyErr != nil || closeInputErr != nil || closeOutputErr != nil {
				return errors.Join(copyErr, closeInputErr, closeOutputErr)
			}
			if written != info.Size() {
				return fmt.Errorf("copy %s wrote %d bytes, want %d", relative, written, info.Size())
			}
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), link))
			if !strings.HasPrefix(resolved+string(os.PathSeparator), filepath.Clean(source)+string(os.PathSeparator)) {
				return fmt.Errorf("source symlink %s escapes through %s", relative, link)
			}
			return os.Symlink(link, target)
		default:
			return fmt.Errorf("source tree contains unsupported mode %s at %s", info.Mode(), relative)
		}
	})
}
