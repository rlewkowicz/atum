package orchestration

import (
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestKubesprayFileRepositoryInputsUseDocumentedDomainRoots(t *testing.T) {
	t.Parallel()

	digest := config.SHA256([]byte("blob"))
	files := []config.KubesprayFile{
		{
			ID:             "containerd",
			Source:         "https://github.com/containerd/containerd/releases/download/v2.2.3/containerd.tar.gz",
			RepositoryPath: "github.com/containerd/containerd/releases/download/v2.2.3/containerd.tar.gz",
			SHA256:         digest,
			Size:           4,
		},
		{
			ID:             "kubeadm",
			Source:         "https://dl.k8s.io/release/v1.35.4/bin/linux/amd64/kubeadm",
			RepositoryPath: "dl.k8s.io/release/v1.35.4/bin/linux/amd64/kubeadm",
			SHA256:         digest,
			Size:           4,
		},
	}
	variables, remote, err := kubesprayFileRepositoryInputs(
		config.SeedKubesprayFilesURL,
		files,
	)
	if err != nil {
		t.Fatalf("repository inputs: %v", err)
	}
	wantVariables := map[string]any{
		"files_repo":    config.SeedKubesprayFilesURL,
		"github_url":    config.SeedKubesprayFilesURL + "/github.com",
		"dl_k8s_io_url": config.SeedKubesprayFilesURL + "/dl.k8s.io",
	}
	if !reflect.DeepEqual(variables, wantVariables) {
		t.Fatalf("variables = %#v, want %#v", variables, wantVariables)
	}
	if remote.Count() != len(files) {
		t.Fatalf("projected files = %d, want %d", remote.Count(), len(files))
	}
}

func TestKubesprayFileRepositoryInputsRejectUnsupportedRoot(t *testing.T) {
	t.Parallel()

	_, _, err := kubesprayFileRepositoryInputs(
		config.SeedKubesprayFilesURL,
		[]config.KubesprayFile{{
			ID:             "manifest",
			Source:         "https://raw.githubusercontent.com/example/project/main/install.yaml",
			RepositoryPath: "raw.githubusercontent.com/example/project/main/install.yaml",
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid repository path") {
		t.Fatalf("unsupported root error = %v", err)
	}
}
