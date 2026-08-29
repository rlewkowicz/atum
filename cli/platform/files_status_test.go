package platform

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"atum/cli/config"
	"atum/cli/delivery"
)

func TestDirectKubesprayFilesClientDisablesProxyAndRedirects(t *testing.T) {
	var proxyRequests atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		proxyRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)

	client, transport := directKubesprayFilesClient()
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("direct files transport inherited a proxy function")
	}
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://files.invalid/content",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Do(request)
	if proxyRequests.Load() != 0 {
		t.Fatal("direct files observation used the environment proxy")
	}

	content := []byte("blob")
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
	err = observeFileProjection(
		t.Context(),
		client,
		redirect.URL,
		fileObservationManifest(content),
		1,
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect observation error = %v", err)
	}
}

func TestFileProjectionObservationRequiresExactHTTPContent(t *testing.T) {
	t.Parallel()

	content := []byte("blob")
	tests := []struct {
		name    string
		status  int
		body    []byte
		wantErr string
	}{
		{name: "exact", status: http.StatusOK, body: content},
		{name: "not found", status: http.StatusNotFound, body: content, wantErr: "HTTP 404"},
		{name: "oversized", status: http.StatusOK, body: []byte("blob-extra"), wantErr: "identity differs"},
		{name: "wrong digest", status: http.StatusOK, body: []byte("clob"), wantErr: "identity differs"},
		{name: "short", status: http.StatusOK, body: []byte("blo"), wantErr: "identity differs"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				if request.URL.Path != "/dl.k8s.io/release" {
					t.Errorf("path = %q", request.URL.Path)
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write(test.body)
			}))
			defer server.Close()
			client, transport := directKubesprayFilesClient()
			defer transport.CloseIdleConnections()
			err := observeFileProjection(
				t.Context(),
				client,
				server.URL,
				fileObservationManifest(content),
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
}

func TestFileProjectionObserverRejectsNonBastionEndpoint(t *testing.T) {
	t.Parallel()

	project := &config.Project{
		Root: t.TempDir(),
		Desired: config.Document{
			Delivery: config.Delivery{
				Seed: config.SeedPlane{
					KubesprayFiles: config.SeedKubesprayFiles{
						URL: "http://proxy.invalid",
					},
				},
				Kubespray: []config.KubesprayArtifactInventory{{
					Files: []config.KubesprayFile{{
						RepositoryPath: "dl.k8s.io/release",
						SHA256: config.SHA256([]byte("blob")),
						Size: 4,
					}},
				}},
			},
		},
	}
	project.Desired.Delivery.Kubespray[0].Files[0].CacheFile = filepath.Join(
		".atum",
		"cache",
		"kubespray-offline",
		"sha256",
		project.Desired.Delivery.Kubespray[0].Files[0].SHA256,
	)
	cache := filepath.Join(
		project.Root,
		project.Desired.Delivery.Kubespray[0].Files[0].CacheFile,
	)
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := delivery.MaterializeFileManifest(project)
	if err != nil {
		t.Fatal(err)
	}
	service := Service{Project: project}
	receipt := delivery.Receipt{KubesprayFiles: manifest.Identity}
	err = service.observeKubesprayFiles(t.Context(), receipt)
	if err == nil {
		t.Fatal("non-bastion files endpoint was accepted")
	}
}

func TestFileProjectionFailureRemainsAttributedAndNoncompliant(t *testing.T) {
	t.Parallel()

	compliance := DeliveryComplianceStatus{KubesprayFilesExact: true}
	recordKubesprayFilesObservation(
		&compliance,
		fmt.Errorf("dl.k8s.io/release content identity differs"),
	)
	if compliance.KubesprayFilesExact ||
		len(compliance.Issues) != 1 ||
		!strings.Contains(compliance.Issues[0], "dl.k8s.io/release") {
		t.Fatalf("file compliance failure = %#v", compliance)
	}
}

func fileObservationManifest(content []byte) delivery.FileManifest {
	digest := config.SHA256(content)
	return delivery.FileManifest{
		Identity: delivery.FileManifestIdentity{
			SHA256: digest,
			Count:  1,
			Bytes:  int64(len(content)),
		},
		Blobs: []delivery.FileBlob{{
			SHA256: digest,
			Size:   int64(len(content)),
			Paths:  []string{"dl.k8s.io/release"},
		}},
		Data: []byte(fmt.Sprintf("%s\n", digest)),
	}
}
