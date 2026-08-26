package gitsnapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
)

func TestRequireMembersUsesExactIndexMembership(t *testing.T) {
	t.Parallel()
	snapshot := &Snapshot{Files: []File{
		{Name: "atum.json"},
		{Name: "platform/build/compat/redis/run.sh"},
		{Name: "platform/build/docker/Dockerfile.delivery"},
	}}
	if err := snapshot.RequireMembers([]string{
		"atum.json",
		"platform/build/compat/",
	}); err != nil {
		t.Fatal(err)
	}
	err := snapshot.RequireMembers([]string{
		"platform/build/compat/postgresql/",
		"platform/profiles/local/prep/stateful-values.yaml",
	})
	if err == nil {
		t.Fatal("missing exact snapshot members were accepted")
	}
	message := err.Error()
	for _, missing := range []string{
		"platform/build/compat/postgresql/",
		"platform/profiles/local/prep/stateful-values.yaml",
	} {
		if !strings.Contains(message, missing) {
			t.Fatalf("membership error %q omits %s", message, missing)
		}
	}
}

func TestRequireSourceRootsAdmitsOnlyTrackedOrIgnoredEligibleInputs(t *testing.T) {
	root := sourceRootTestRepository(t)
	repository, err := git.PlainInit(root, false)
	if err != nil {
		t.Fatalf("initialize Git fixture: %v", err)
	}
	writeSourceRootFixture(t, root, ".gitignore", "infra/local/ignored.tf\n")
	writeSourceRootFixture(t, root, "infra/local/main.tf", "terraform {}\n")
	writeSourceRootFixture(t, root, "infra/local/ignored.tf", "terraform {}\n")
	writeSourceRootFixture(t, root, "infra/local/terraform.tfstate", "{}\n")
	writeSourceRootFixture(t, root, "infra/local/notes.txt", "not a native input\n")
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatalf("open Git fixture worktree: %v", err)
	}
	for _, tracked := range []string{".gitignore", "infra/local/main.tf"} {
		if _, err := worktree.Add(tracked); err != nil {
			t.Fatalf("index fixture source %s: %v", tracked, err)
		}
	}
	snapshot, err := Load(root)
	if err != nil {
		t.Fatalf("load Git fixture: %v", err)
	}
	requirement := []SourceRoot{{
		Path: "infra/local", Kind: TerraformConfiguration,
	}}
	if err := snapshot.RequireSourceRoots(requirement); err != nil {
		t.Fatalf("ignored and ineligible runtime files affected admission: %v", err)
	}

	const untracked = "infra/local/extra.tf.json"
	writeSourceRootFixture(t, root, untracked, "{}\n")
	err = snapshot.RequireSourceRoots(requirement)
	if err == nil || !strings.Contains(err.Error(), untracked) {
		t.Fatalf("untracked Terraform source error = %v", err)
	}

	if _, err := worktree.Add(untracked); err != nil {
		t.Fatalf("index eligible Terraform source: %v", err)
	}
	snapshot, err = Load(root)
	if err != nil {
		t.Fatalf("reload Git fixture: %v", err)
	}
	if err := snapshot.RequireSourceRoots(requirement); err != nil {
		t.Fatalf("tracked Terraform source was rejected: %v", err)
	}

	const asset = "infra/local/scripts/bootstrap.sh"
	writeSourceRootFixture(t, root, asset, "#!/bin/sh\n")
	assetRequirement := []SourceRoot{{
		Path: "infra/local/scripts", Kind: SourceAssets,
	}}
	err = snapshot.RequireSourceRoots(assetRequirement)
	if err == nil || !strings.Contains(err.Error(), asset) {
		t.Fatalf("untracked Terraform asset error = %v", err)
	}
	if _, err := worktree.Add(asset); err != nil {
		t.Fatalf("index Terraform asset: %v", err)
	}
	snapshot, err = Load(root)
	if err != nil {
		t.Fatalf("reload Git fixture after asset: %v", err)
	}
	if err := snapshot.RequireSourceRoots(assetRequirement); err != nil {
		t.Fatalf("tracked Terraform asset was rejected: %v", err)
	}
}

func sourceRootTestRepository(t *testing.T) string {
	t.Helper()

	repositoryRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	root, err := os.MkdirTemp(
		filepath.Join(repositoryRoot, ".atum"),
		"gitsnapshot-source-root-",
	)
	if err != nil {
		t.Fatalf("create Git fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove Git fixture: %v", err)
		}
	})
	return root
}

func writeSourceRootFixture(t *testing.T, root, relative, data string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture parent %s: %v", relative, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", relative, err)
	}
}
