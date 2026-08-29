package delivery

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"atum/cli/config"
	"atum/cli/process"
)

type filePublicationRunner struct {
	mu            sync.Mutex
	missing       string
	failReport    bool
	commands      []process.Command
	uploadedBytes int64
}

func (runner *filePublicationRunner) Run(
	_ context.Context,
	command process.Command,
) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	copied := command
	copied.Args = append([]string(nil), command.Args...)
	runner.commands = append(runner.commands, copied)
	operation := ""
	for index, argument := range command.Args {
		if argument == "/usr/local/sbin/atum-kubespray-files" &&
			index+1 < len(command.Args) {
			operation = command.Args[index+1]
			break
		}
	}
	switch operation {
	case "report":
		if runner.failReport {
			return errors.New("report failed")
		}
		_, err := io.WriteString(command.Stdout, runner.missing)
		return err
	case "put":
		size, err := io.Copy(io.Discard, command.Stdin)
		runner.uploadedBytes += size
		return err
	case "activate":
		return nil
	default:
		return errors.New("unexpected helper operation")
	}
}

func TestFileManifestDeduplicatesSortedLadderUnion(t *testing.T) {
	t.Parallel()

	project, manifest := fileManifestFixture(t)
	second, err := MaterializeFileManifest(project)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Identity != second.Identity ||
		string(manifest.Data) != string(second.Data) {
		t.Fatal("manifest materialization is not deterministic")
	}
	if manifest.Identity.Count != 1 ||
		manifest.Identity.Bytes != 4 ||
		len(manifest.Blobs) != 1 ||
		!slices.Equal(
			manifest.Blobs[0].Paths,
			[]string{"dl.k8s.io/a", "github.com/b"},
		) {
		t.Fatalf("deduplicated manifest = %#v", manifest)
	}
}

func TestFilePublicationIsolatesTrustAndReusesRetainedBlobs(t *testing.T) {
	t.Parallel()

	project, manifest := fileManifestFixture(t)
	privateKey := filepath.Join(project.Root, "identity")
	if err := os.WriteFile(privateKey, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTrust := filepath.Join(
		project.Root,
		".atum",
		"state",
		"ssh",
		"bastion",
		strings.Repeat("f", 64),
	)
	if err := os.MkdirAll(oldTrust, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &filePublicationRunner{
		missing: manifest.Blobs[0].SHA256 + "\n",
	}
	var uploaded, reused int64
	if err := PublishFileManifest(
		t.Context(),
		runner,
		"/usr/bin/ssh",
		privateKey,
		project,
		manifest,
		"terraform-bastion-a",
		2,
		func(_ string, size int64, wasReused bool) {
			uploaded += size
			if wasReused {
				reused++
			}
		},
	); err != nil {
		t.Fatal(err)
	}
	if runner.uploadedBytes != 4 || uploaded != 4 || reused != 0 {
		t.Fatalf("first publication bytes = %d/%d, reused = %d", runner.uploadedBytes, uploaded, reused)
	}
	if _, err := os.Stat(oldTrust); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired trust was not cleaned after connection: %v", err)
	}
	assertIsolatedSSHArguments(t, runner.commands, privateKey, "terraform-bastion-a")

	reuseRunner := &filePublicationRunner{}
	uploaded, reused = 0, 0
	if err := PublishFileManifest(
		t.Context(),
		reuseRunner,
		"/usr/bin/ssh",
		privateKey,
		project,
		manifest,
		"terraform-bastion-a",
		2,
		func(_ string, size int64, wasReused bool) {
			uploaded += size
			if wasReused {
				reused++
			}
		},
	); err != nil {
		t.Fatal(err)
	}
	if reuseRunner.uploadedBytes != 0 || uploaded != 0 || reused != 1 ||
		len(reuseRunner.commands) != 2 {
		t.Fatalf(
			"retained publication uploaded=%d/%d reused=%d commands=%d",
			reuseRunner.uploadedBytes,
			uploaded,
			reused,
			len(reuseRunner.commands),
		)
	}
}

func TestFailedNewBastionConnectionPreservesRetiredTrust(t *testing.T) {
	t.Parallel()

	project, manifest := fileManifestFixture(t)
	privateKey := filepath.Join(project.Root, "identity")
	if err := os.WriteFile(privateKey, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTrust := filepath.Join(
		project.Root,
		".atum",
		"state",
		"ssh",
		"bastion",
		strings.Repeat("e", 64),
	)
	if err := os.MkdirAll(oldTrust, 0o700); err != nil {
		t.Fatal(err)
	}
	err := PublishFileManifest(
		t.Context(),
		&filePublicationRunner{failReport: true},
		"/usr/bin/ssh",
		privateKey,
		project,
		manifest,
		"terraform-bastion-b",
		1,
		nil,
	)
	if err == nil {
		t.Fatal("failed bastion connection was accepted")
	}
	if _, err := os.Stat(oldTrust); err != nil {
		t.Fatalf("retired trust changed before successful connection: %v", err)
	}
	err = PublishFileManifest(
		t.Context(),
		&filePublicationRunner{missing: strings.Repeat("0", 64)},
		"/usr/bin/ssh",
		privateKey,
		project,
		manifest,
		"terraform-bastion-b",
		1,
		nil,
	)
	if err == nil {
		t.Fatal("corrupt helper report was accepted")
	}
	if _, err := os.Stat(oldTrust); err != nil {
		t.Fatalf("retired trust changed before successful activation: %v", err)
	}
}

func TestManifestReportAndReceiptRejectUnknownOrStaleIdentity(t *testing.T) {
	t.Parallel()

	_, manifest := fileManifestFixture(t)
	if _, err := parseMissingDigests(strings.Repeat("f", 64), manifest); err == nil {
		t.Fatal("unknown helper digest was accepted")
	}
	if !validFileManifestReceipt(manifest.Identity, manifest.Identity) {
		t.Fatal("exact v2 file-manifest receipt was rejected")
	}
	stale := manifest.Identity
	stale.Bytes++
	if validFileManifestReceipt(stale, manifest.Identity) {
		t.Fatal("stale v2 file-manifest receipt was accepted")
	}
}

func fileManifestFixture(t *testing.T) (*config.Project, FileManifest) {
	t.Helper()

	root := t.TempDir()
	cache := filepath.Join(".atum", "cache", "kubespray-offline", "sha256")
	content := []byte("blob")
	digest := config.SHA256(content)
	cacheFile := filepath.Join(cache, digest)
	if err := os.MkdirAll(filepath.Join(root, cache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, cacheFile), content, 0o600); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{
		Root: root,
		Desired: config.Document{
			Updates: config.UpdatePolicy{Parallelism: 2},
			Delivery: config.Delivery{
				Kubespray: []config.KubesprayArtifactInventory{
					{Files: []config.KubesprayFile{{
						RepositoryPath: "github.com/b",
						CacheFile: cacheFile,
						SHA256: digest,
						Size: int64(len(content)),
					}}},
					{Files: []config.KubesprayFile{{
						RepositoryPath: "dl.k8s.io/a",
						CacheFile: cacheFile,
						SHA256: digest,
						Size: int64(len(content)),
					}}},
				},
			},
		},
	}
	manifest, err := MaterializeFileManifest(project)
	if err != nil {
		t.Fatal(err)
	}
	return project, manifest
}

func assertIsolatedSSHArguments(
	t *testing.T,
	commands []process.Command,
	privateKey string,
	bastionIdentity string,
) {
	t.Helper()

	if len(commands) != 3 {
		t.Fatalf("SSH command count = %d, want report, put, activate", len(commands))
	}
	wantTrust := filepath.Join(
		".atum",
		"state",
		"ssh",
		"bastion",
		config.SHA256([]byte(bastionIdentity)),
		"known_hosts",
	)
	for _, command := range commands {
		joined := strings.Join(command.Args, "\n")
		if command.Name != "/usr/bin/ssh" ||
			!strings.Contains(joined, privateKey) ||
			!strings.Contains(joined, wantTrust) ||
			!strings.Contains(joined, "StrictHostKeyChecking=accept-new") ||
			!strings.Contains(joined, "GlobalKnownHostsFile=/dev/null") ||
			!strings.Contains(joined, "/usr/local/sbin/atum-kubespray-files") {
			t.Fatalf("SSH helper boundary = %#v", command)
		}
	}
}
