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
	"time"

	"atum/cli/delivery"
	"atum/cli/fssecure"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
	"atum/cli/secretvalue"

	forgejo "codeberg.org/mvdkleijn/forgejo-sdk/forgejo/v2"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const (
	gitCopyBufferSize = 128 << 10
	forgejoPushRemote = "atum-publish"
	forgejoRefTimeout = 30 * time.Second
	forgejoRefPoll    = 250 * time.Millisecond
	fluxTokenName     = "atum-flux-read"
)

type forgejoControl struct {
	url           string
	username      string
	adminPassword secretvalue.Value
	fluxToken     secretvalue.Value
	root          string
}

func (control *forgejoControl) clear() {
	if control == nil {
		return
	}
	control.url = ""
	control.username = ""
	control.adminPassword.Clear()
	control.fluxToken.Clear()
	control.root = ""
}

func (service Service) configureForgejo(
	ctx context.Context,
	publication *delivery.Publication,
	credentials atumsecrets.Document,
) (*forgejoControl, error) {
	sources := service.Project.Desired.Platform.Sources
	endpoint := strings.TrimSuffix(sources.ExternalURL, "/")
	control := &forgejoControl{
		url: endpoint, username: credentials.Forgejo.Username,
		adminPassword: credentials.Forgejo.AdminPassword.Clone(),
		root:          service.Project.Root,
	}
	succeeded := false
	defer func() {
		if !succeeded {
			control.clear()
		}
	}()
	api, err := control.apiClient(ctx)
	if err != nil {
		return nil, err
	}
	if _, _, err := api.GetMyUserInfo(); err != nil {
		return nil, fmt.Errorf("authenticate Forgejo administrator: %w", err)
	}
	api = nil
	if err := control.ensureOrganization(
		ctx, sources.Organization, "Atum Platform", forgejo.VisibleTypePrivate,
	); err != nil {
		return nil, err
	}
	if err := control.ensureRepository(
		ctx,
		sources.Organization,
		sources.Repository,
		"Exact Atum deployment source",
		true,
	); err != nil {
		return nil, err
	}
	if err := control.publishAtumSource(ctx, publication, sources.Organization, sources.Repository); err != nil {
		return nil, err
	}
	progress.Update(ctx, progress.Platform, "forgejo", "Forgejo sources",
		"published exact Atum main source", 1, 1)
	succeeded = true
	return control, nil
}

func (control *forgejoControl) apiClient(ctx context.Context) (*forgejo.Client, error) {
	password := string(control.adminPassword.Bytes())
	api, err := forgejo.NewClient(
		control.url,
		forgejo.SetHTTPClient(&http.Client{Timeout: 60 * time.Second}),
		forgejo.SetContext(ctx),
		forgejo.SetBasicAuth(control.username, password),
	)
	password = ""
	if err != nil {
		return nil, fmt.Errorf("initialize Forgejo API client: %w", err)
	}
	return api, nil
}

func (control *forgejoControl) gitAuth() (*githttp.BasicAuth, func()) {
	auth := &githttp.BasicAuth{
		Username: control.username,
		Password: string(control.adminPassword.Bytes()),
	}
	return auth, func() {
		auth.Username = ""
		auth.Password = ""
	}
}

func (control *forgejoControl) rotateFluxToken(ctx context.Context) (secretvalue.Value, error) {
	api, err := control.apiClient(ctx)
	if err != nil {
		return nil, err
	}
	if response, err := api.DeleteAccessToken(fluxTokenName); err != nil &&
		forgejoStatus(response) != http.StatusNotFound {
		return nil, fmt.Errorf("remove previous Flux read token: %w", err)
	}
	token, _, err := api.CreateAccessToken(forgejo.CreateAccessTokenOption{
		Name: fluxTokenName,
		Scopes: []forgejo.AccessTokenScope{
			forgejo.AccessTokenScopeRepositoryRead,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create Flux read token: %w", err)
	}
	if token == nil || token.Token == "" {
		return nil, errors.New("Forgejo returned no Flux read token")
	}
	result := secretvalue.New([]byte(token.Token))
	token.Token = ""
	return result, nil
}

func forgejoStatus(response *forgejo.Response) int {
	if response == nil || response.Response == nil {
		return 0
	}
	return response.StatusCode
}

func (control *forgejoControl) ensureOrganization(
	ctx context.Context,
	name, fullName string,
	visibility forgejo.VisibleType,
) error {
	api, err := control.apiClient(ctx)
	if err != nil {
		return err
	}
	current, response, err := api.GetOrg(name)
	if err == nil {
		if current == nil {
			return fmt.Errorf("Forgejo organization %s returned no state", name)
		}
		if current.Visibility == string(visibility) && current.FullName == fullName {
			return nil
		}
		if _, err := api.EditOrg(name, forgejo.EditOrgOption{
			FullName: fullName, Visibility: visibility,
		}); err != nil {
			return fmt.Errorf("update Forgejo organization %s: %w", name, err)
		}
		return nil
	}
	if forgejoStatus(response) != http.StatusNotFound {
		return fmt.Errorf("inspect Forgejo organization %s: %w", name, err)
	}
	_, _, err = api.CreateOrg(forgejo.CreateOrgOption{
		Name: name, FullName: fullName, Visibility: visibility,
	})
	if err != nil {
		return fmt.Errorf("create Forgejo organization %s: %w", name, err)
	}
	return nil
}

func (control *forgejoControl) ensureRepository(
	ctx context.Context,
	owner, name, description string,
	private bool,
) error {
	api, err := control.apiClient(ctx)
	if err != nil {
		return err
	}
	current, response, err := api.GetRepo(owner, name)
	if err == nil {
		if current == nil {
			return fmt.Errorf("Forgejo repository %s/%s returned no state", owner, name)
		}
		if current.Private == private && current.Description == description {
			return nil
		}
		if _, _, err := api.EditRepo(owner, name, forgejo.EditRepoOption{
			Description: &description, Private: &private,
		}); err != nil {
			return fmt.Errorf("update Forgejo repository %s/%s: %w", owner, name, err)
		}
		return nil
	}
	if forgejoStatus(response) != http.StatusNotFound {
		return fmt.Errorf("inspect Forgejo repository %s/%s: %w", owner, name, err)
	}
	_, _, err = api.CreateOrgRepo(owner, forgejo.CreateRepoOption{
		Name: name, Description: description, Private: private, AutoInit: false, DefaultBranch: "main",
	})
	if err != nil {
		return fmt.Errorf("create Forgejo repository %s/%s: %w", owner, name, err)
	}
	return nil
}

func (control *forgejoControl) publishAtumSource(
	ctx context.Context,
	publication *delivery.Publication,
	owner, name string,
) error {
	return control.withAtumRepository(publication, func(repository *git.Repository, commit plumbing.Hash) error {
		for _, reference := range []plumbing.ReferenceName{
			plumbing.NewBranchReferenceName("main"),
			plumbing.NewTagReferenceName(publication.SourceTag),
		} {
			if err := repository.Storer.SetReference(plumbing.NewHashReference(reference, commit)); err != nil {
				return err
			}
		}
		if err := control.pushImmutable(ctx, repository, owner, name, publication.SourceTag, publication.SourceCommit); err != nil {
			return err
		}
		return control.advanceBranch(ctx, repository, owner, name, "main", publication.SourceCommit)
	})
}

func (control *forgejoControl) withAtumRepository(
	publication *delivery.Publication,
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
	if err := copyVerifiedTree(publication.SourceRoot, stage); err != nil {
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
	if commit.String() != publication.SourceCommit {
		return fmt.Errorf("materialized Atum source commit is %s, want %s", commit, publication.SourceCommit)
	}
	return operation(repository, commit)
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
	existing, found, err := control.exactTag(ctx, owner, name, tag)
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
	auth, clearAuth := control.gitAuth()
	defer clearAuth()
	err = control.remote(repository, owner, name).PushContext(ctx, &git.PushOptions{
		Auth: auth, RemoteName: forgejoPushRemote,
		RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec(ref + ":" + ref)},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("publish Forgejo tag %s/%s:%s: %w", owner, name, tag, err)
	}
	existing, found, err = control.exactTag(ctx, owner, name, tag)
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
	current, found, err := control.exactBranch(ctx, owner, name, branchName)
	if err != nil {
		return err
	}
	if found && current == commit {
		return nil
	}
	local := plumbing.NewBranchReferenceName(branchName)
	remote := local
	auth, clearAuth := control.gitAuth()
	defer clearAuth()
	options := &git.PushOptions{
		Auth: auth, RemoteName: forgejoPushRemote,
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
		latest, latestFound, latestErr := control.exactBranch(ctx, owner, name, branchName)
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
		func(ctx context.Context) (string, bool, error) {
			return control.exactBranch(ctx, owner, name, branchName)
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
	auth, clearAuth := control.gitAuth()
	defer clearAuth()
	references, err := control.remote(repository, owner, name).ListContext(
		ctx,
		&git.ListOptions{Auth: auth},
	)
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

func (control *forgejoControl) exactBranch(
	ctx context.Context,
	owner, name, branchName string,
) (string, bool, error) {
	api, err := control.apiClient(ctx)
	if err != nil {
		return "", false, err
	}
	branch, response, err := api.GetRepoBranch(owner, name, branchName)
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

func (control *forgejoControl) exactTag(
	ctx context.Context,
	owner, name, tag string,
) (string, bool, error) {
	api, err := control.apiClient(ctx)
	if err != nil {
		return "", false, err
	}
	current, response, err := api.GetTag(owner, name, tag)
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
