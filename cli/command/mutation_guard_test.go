package command

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"atum/cli/config"

	git "github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
)

func TestMutationCommandStopsBeforeEffectWhenSourceMemberIsUntracked(t *testing.T) {
	project := projectWithSourceAdmissionFailure(t, "atum.schema.json", "")
	application := &app{project: project}
	effects := 0
	root := mutationGuardFixture(application, nil, func() {
		effects++
	})

	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "absent from the Git-index snapshot") {
		t.Fatalf("execute error = %v, want missing Git-index member", err)
	}
	if effects != 0 {
		t.Fatalf("downstream effects = %d, want 0", effects)
	}
}

func TestMutationCommandStopsBeforeUntrackedNativeToolInputs(t *testing.T) {
	for _, relative := range []string{
		"infra/libvirt/extra.tf",
		"orchestration/playbooks/extra.yml",
	} {
		relative := relative
		t.Run(relative, func(t *testing.T) {
			project := projectWithSourceAdmissionFailure(t, "", relative)
			application := &app{project: project}
			effects := 0
			root := mutationGuardFixture(application, nil, func() {
				effects++
			})

			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), relative) {
				t.Fatalf("execute error = %v, want untracked source %s", err, relative)
			}
			if effects != 0 {
				t.Fatalf("downstream effects = %d, want 0", effects)
			}
		})
	}
}

func TestReadOnlyCommandExplicitlyBypassesMutationGate(t *testing.T) {
	project := projectWithSourceAdmissionFailure(t, "atum.schema.json", "")
	application := &app{project: project}
	effects := 0
	root := mutationGuardFixture(
		application,
		map[string]string{"atum.dev/read-only": "true"},
		func() {
			effects++
		},
	)

	if err := root.Execute(); err != nil {
		t.Fatalf("execute read-only fixture: %v", err)
	}
	if effects != 1 {
		t.Fatalf("read-only callback count = %d, want 1", effects)
	}
}

func TestCommandMutationExceptionsAreExplicit(t *testing.T) {
	t.Parallel()

	root := New(Options{})
	for _, test := range []struct {
		path       []string
		annotation string
		value      string
	}{
		{path: []string{"validate"}, annotation: "atum.dev/read-only", value: "true"},
		{path: []string{"orchestration", "plan"}, annotation: "atum.dev/read-only", value: "true"},
		{path: []string{"platform", "status"}, annotation: "atum.dev/read-only", value: "true"},
		{path: []string{"infra", "access", "status"}, annotation: "atum.dev/read-only", value: "true"},
		{path: []string{"pull", "updates"}, annotation: "atum.dev/update-writer", value: "true"},
		{path: []string{"destroy"}, annotation: projectLockBypassAnnotation, value: "true"},
		{path: []string{"__host-access"}, annotation: "atum.dev/internal-process", value: internalRootProcess},
		{path: []string{"__verify-host-access"}, annotation: "atum.dev/internal-process", value: internalVerifyProcess},
	} {
		command, _, err := root.Find(test.path)
		if err != nil {
			t.Fatalf("find %v: %v", test.path, err)
		}
		if actual := commandAnnotation(command, test.annotation); actual != test.value {
			t.Errorf("%v annotation %s = %q, want %q",
				test.path, test.annotation, actual, test.value)
		}
	}
}

func mutationGuardFixture(
	application *app,
	annotations map[string]string,
	effect func(),
) *cobra.Command {
	root := &cobra.Command{
		Use: "fixture",
		PersistentPreRunE: func(command *cobra.Command, _ []string) error {
			return application.ensureCommandAllowed(command)
		},
	}
	root.AddCommand(&cobra.Command{
		Use:         "mutate",
		Annotations: annotations,
		RunE: func(*cobra.Command, []string) error {
			effect()
			return nil
		},
	})
	root.SetArgs([]string{"mutate"})
	root.SilenceErrors = true
	root.SilenceUsage = true
	return root
}

func projectWithSourceAdmissionFailure(
	t *testing.T,
	omittedExact string,
	untrackedNative string,
) *config.Project {
	t.Helper()

	root, err := config.Discover("")
	if err != nil {
		t.Fatalf("discover project: %v", err)
	}
	project, err := config.Load(root)
	if err != nil {
		t.Fatalf("load project: %v", err)
	}
	fixtureRoot, err := os.MkdirTemp(filepath.Join(root, ".atum"), "mutation-guard-")
	if err != nil {
		t.Fatalf("create ignored fixture repository: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixtureRoot); err != nil {
			t.Errorf("remove ignored fixture repository: %v", err)
		}
	})
	if err := mirrorProjectFixture(root, fixtureRoot); err != nil {
		t.Fatalf("mirror project fixture: %v", err)
	}
	if err := mirrorResolvedChartArtifacts(
		root,
		fixtureRoot,
		project.Lock.Resolved.Artifacts,
	); err != nil {
		t.Fatalf("mirror resolved chart artifacts: %v", err)
	}
	repository, err := git.PlainInit(fixtureRoot, false)
	if err != nil {
		t.Fatalf("initialize fixture Git index: %v", err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatalf("open fixture Git worktree: %v", err)
	}
	members := requiredFixtureFiles(t, fixtureRoot, project.Desired)
	for _, member := range members {
		if member == omittedExact {
			continue
		}
		if _, err := worktree.Add(member); err != nil {
			t.Fatalf("index fixture source %s: %v", member, err)
		}
	}
	roots, err := config.RequiredSourceSnapshotRoots(project.Desired)
	if err != nil {
		t.Fatalf("derive fixture source roots: %v", err)
	}
	for _, root := range roots {
		if _, err := worktree.Add(root.Path); err != nil {
			t.Fatalf("index fixture source root %s: %v", root.Path, err)
		}
	}
	if untrackedNative != "" {
		path := filepath.Join(fixtureRoot, filepath.FromSlash(untrackedNative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create untracked native source parent: %v", err)
		}
		if err := os.WriteFile(path, []byte("# untracked native source\n"), 0o600); err != nil {
			t.Fatalf("write untracked native source: %v", err)
		}
	}
	project.Root = fixtureRoot
	if err := project.Validate(); err != nil {
		t.Fatalf("fixture project should remain semantically valid: %v", err)
	}
	return project
}

func mirrorProjectFixture(sourceRoot, fixtureRoot string) error {
	return filepath.WalkDir(sourceRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.IsDir() && (relative == ".git" || relative == ".atum" ||
			entry.Name() == ".terraform") {
			return filepath.SkipDir
		}
		if relative == "atum" {
			return nil
		}
		target := filepath.Join(fixtureRoot, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return mirrorRegularFile(path, target, info.Mode().Perm())
	})
}

func mirrorResolvedChartArtifacts(
	sourceRoot string,
	fixtureRoot string,
	artifacts []config.ChartArtifact,
) error {
	for _, artifact := range artifacts {
		source := filepath.Join(sourceRoot, filepath.FromSlash(artifact.File))
		target := filepath.Join(fixtureRoot, filepath.FromSlash(artifact.File))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		info, err := os.Stat(source)
		if err != nil {
			return err
		}
		if err := mirrorRegularFile(source, target, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func mirrorRegularFile(sourcePath, targetPath string, mode os.FileMode) error {
	if err := os.Link(sourcePath, targetPath); err == nil {
		return nil
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	destination, err := os.OpenFile(
		targetPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		mode,
	)
	if err != nil {
		_ = source.Close()
		return err
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	sourceCloseErr := source.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return sourceCloseErr
}

func requiredFixtureFiles(
	t *testing.T,
	root string,
	desired config.Document,
) []string {
	t.Helper()

	files := make(map[string]struct{})
	for _, member := range config.RequiredSourceSnapshotMembers(desired) {
		if !strings.HasSuffix(member, "/") {
			files[member] = struct{}{}
			continue
		}
		directory := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(member, "/")))
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(relative)] = struct{}{}
			return nil
		})
		if err != nil {
			t.Fatalf("enumerate fixture source directory %s: %v", member, err)
		}
	}
	result := make([]string, 0, len(files))
	for file := range files {
		result = append(result, file)
	}
	return result
}
