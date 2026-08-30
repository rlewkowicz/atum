package delivery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func fileHelperOperation(command process.Command) string {
	for index, argument := range command.Args {
		if argument == "/usr/local/sbin/atum-kubespray-files" &&
			index+1 < len(command.Args) {
			return command.Args[index+1]
		}
	}
	return ""
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
	switch fileHelperOperation(command) {
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

type concurrentFilePublicationRunner struct {
	missing string
	started chan struct{}
	release chan struct{}
	current atomic.Int64
	maximum atomic.Int64
}

func (runner *concurrentFilePublicationRunner) Run(
	ctx context.Context,
	command process.Command,
) error {
	switch fileHelperOperation(command) {
	case "report":
		_, err := io.WriteString(command.Stdout, runner.missing)
		return err
	case "put":
		current := runner.current.Add(1)
		defer runner.current.Add(-1)
		for maximum := runner.maximum.Load(); current > maximum; {
			if runner.maximum.CompareAndSwap(maximum, current) {
				break
			}
			maximum = runner.maximum.Load()
		}
		select {
		case runner.started <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-runner.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		_, err := io.Copy(io.Discard, command.Stdin)
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

func TestFilePublicationCapsConcurrentBastionSSHTransfers(t *testing.T) {
	t.Parallel()

	const blobCount = maxConcurrentBastionFileSSHTransfers + 3
	root := t.TempDir()
	cache := filepath.Join(".atum", "cache", "kubespray-offline", "sha256")
	if err := os.MkdirAll(filepath.Join(root, cache), 0o700); err != nil {
		t.Fatal(err)
	}
	files := make([]config.KubesprayFile, 0, blobCount)
	for index := range blobCount {
		content := []byte("blob-" + strconv.Itoa(index))
		digest := config.SHA256(content)
		cacheFile := filepath.Join(cache, digest)
		if err := os.WriteFile(
			filepath.Join(root, cacheFile),
			content,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		files = append(files, config.KubesprayFile{
			ID:             "file-" + strconv.Itoa(index),
			RepositoryPath: "example.com/file-" + strconv.Itoa(index),
			CacheFile:      cacheFile,
			SHA256:         digest,
			Size:           int64(len(content)),
		})
	}
	project := &config.Project{
		Root: root,
		Desired: config.Document{
			Updates: config.UpdatePolicy{Parallelism: blobCount},
			Delivery: config.Delivery{
				Kubespray: []config.KubesprayArtifactInventory{{
					Files: files,
				}},
			},
		},
	}
	manifest, err := MaterializeFileManifest(project)
	if err != nil {
		t.Fatal(err)
	}
	var missing strings.Builder
	for _, blob := range manifest.Blobs {
		missing.WriteString(blob.SHA256)
		missing.WriteByte('\n')
	}
	privateKey := filepath.Join(root, "identity")
	if err := os.WriteFile(privateKey, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &concurrentFilePublicationRunner{
		missing: missing.String(),
		started: make(chan struct{}, blobCount),
		release: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		done <- PublishFileManifest(
			t.Context(),
			runner,
			"/usr/bin/ssh",
			privateKey,
			project,
			manifest,
			"terraform-bastion-limit",
			blobCount,
			nil,
		)
	}()
	expected := min(
		config.EffectiveWorkLimit(blobCount, blobCount, defaultParallelism),
		maxConcurrentBastionFileSSHTransfers,
	)
	for range expected {
		select {
		case <-runner.started:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent SSH transfers")
		}
	}
	if maximum := runner.maximum.Load(); maximum != int64(expected) {
		t.Fatalf("maximum concurrent SSH transfers = %d, want %d", maximum, expected)
	}
	close(runner.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out completing SSH transfers")
	}
	if maximum := runner.maximum.Load(); maximum > maxConcurrentBastionFileSSHTransfers {
		t.Fatalf(
			"maximum concurrent SSH transfers = %d, limit %d",
			maximum,
			maxConcurrentBastionFileSSHTransfers,
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

func TestKubesprayFileObserverUsesOneDirectExactContentContract(t *testing.T) {
	content := []byte("blob")
	projection, err := SelectedKubesprayFileProjection(
		[]config.KubesprayFile{{
			ID:             "kubeadm",
			RepositoryPath: "dl.k8s.io/release/kubeadm",
			SHA256:         config.SHA256(content),
			Size:           int64(len(content)),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	var proxyRequests atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		proxyRequests.Add(1)
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)

	tests := []struct {
		name    string
		status  int
		body    []byte
		wantErr string
	}{
		{name: "exact", status: http.StatusOK, body: content},
		{name: "status", status: http.StatusNotFound, body: content, wantErr: "HTTP 404"},
		{name: "stale size", status: http.StatusOK, body: []byte("blo"), wantErr: "Content-Length"},
		{name: "wrong digest", status: http.StatusOK, body: []byte("clob"), wantErr: "identity differs"},
		{name: "oversized", status: http.StatusOK, body: []byte("blob-extra"), wantErr: "Content-Length"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				if request.URL.Path != "/dl.k8s.io/release/kubeadm" {
					t.Errorf("path = %q", request.URL.Path)
				}
				writer.Header().Set(
					"Content-Length",
					strconv.Itoa(len(test.body)),
				)
				writer.WriteHeader(test.status)
				_, _ = writer.Write(test.body)
			}))
			defer server.Close()
			client, transport := directKubesprayFilesClient(1)
			defer transport.CloseIdleConnections()
			if transport.Proxy != nil {
				t.Fatal("direct files transport inherited a proxy function")
			}
			err := observeKubesprayFileProjection(
				t.Context(),
				client,
				server.URL,
				projection,
				1,
			)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("observation error = %v, want %q", err, test.wantErr)
			}
		})
	}
	if proxyRequests.Load() != 0 {
		t.Fatal("direct files observation used the environment proxy")
	}
}

func TestKubesprayFileObserverRejectsRedirectAndCancellation(t *testing.T) {
	content := []byte("blob")
	projection, err := SelectedKubesprayFileProjection(
		[]config.KubesprayFile{{
			ID:             "kubeadm",
			RepositoryPath: "dl.k8s.io/release/kubeadm",
			SHA256:         config.SHA256(content),
			Size:           int64(len(content)),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	destination := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		_, _ = writer.Write(content)
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.RedirectHandler(
		destination.URL,
		http.StatusFound,
	))
	defer redirect.Close()
	client, transport := directKubesprayFilesClient(1)
	defer transport.CloseIdleConnections()
	if err := observeKubesprayFileProjection(
		t.Context(),
		client,
		redirect.URL,
		projection,
		1,
	); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect observation error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := observeKubesprayFileProjection(
		ctx,
		client,
		destination.URL,
		projection,
		1,
	); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observation error = %v", err)
	}
}

func TestManifestKubesprayFileProjectionObservesLadderUnion(t *testing.T) {
	content := []byte("blob")
	digest := config.SHA256(content)
	projection, err := ManifestKubesprayFileProjection(FileManifest{
		Blobs: []FileBlob{{
			SHA256: digest,
			Size:   int64(len(content)),
			Paths:  []string{"dl.k8s.io/a", "github.com/b"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if projection.Count() != 2 {
		t.Fatalf("union projection count = %d, want 2", projection.Count())
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/dl.k8s.io/a" &&
			request.URL.Path != "/github.com/b" {
			t.Errorf("path = %q", request.URL.Path)
		}
		requests.Add(1)
		_, _ = writer.Write(content)
	}))
	defer server.Close()
	client, transport := directKubesprayFilesClient(2)
	defer transport.CloseIdleConnections()
	if err := observeKubesprayFileProjection(
		t.Context(),
		client,
		server.URL,
		projection,
		2,
	); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("union requests = %d, want 2", requests.Load())
	}
}

func TestKubesprayFileProjectionRejectsUnsupportedPathAndEndpoint(t *testing.T) {
	content := []byte("blob")
	if _, err := SelectedKubesprayFileProjection(
		[]config.KubesprayFile{{
			ID:             "escape",
			RepositoryPath: "../outside",
			SHA256:         config.SHA256(content),
			Size:           int64(len(content)),
		}},
	); err == nil {
		t.Fatal("unsupported projection path was accepted")
	}
	projection, err := SelectedKubesprayFileProjection(
		[]config.KubesprayFile{{
			ID:             "kubeadm",
			RepositoryPath: "dl.k8s.io/release/kubeadm",
			SHA256:         config.SHA256(content),
			Size:           int64(len(content)),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ObserveKubesprayFileProjection(
		t.Context(),
		"http://proxy.invalid",
		projection,
		1,
	); err == nil || !strings.Contains(err.Error(), "fixed private bastion") {
		t.Fatalf("unsupported endpoint error = %v", err)
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
						CacheFile:      cacheFile,
						SHA256:         digest,
						Size:           int64(len(content)),
					}}},
					{Files: []config.KubesprayFile{{
						RepositoryPath: "dl.k8s.io/a",
						CacheFile:      cacheFile,
						SHA256:         digest,
						Size:           int64(len(content)),
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
