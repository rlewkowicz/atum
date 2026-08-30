package update

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/kubespray"
)

func TestKubespraySelectedRuntimeFixture(t *testing.T) {
	t.Parallel()
	const (
		// The fixture is the evaluated selection for Kubespray v2.31.0 at
		// this commit and the terminal supported Kubernetes patch.
		kubernetesVersion = "1.35.4"
		kubesprayCommit   = "1c9add48975060f45396b34d8e022c30d7f80dab"
	)
	if len(kubesprayCommit) != 40 ||
		strings.Trim(kubesprayCommit, "0123456789abcdef") != "" {
		t.Fatal("fixture Kubespray commit is not a pinned Git identity")
	}
	if groups := kubespray.LocalNodeGroups(); groups != ([4]string{
		"kube_control_plane", "etcd", "kube_node", "k8s_cluster",
	}) {
		t.Fatalf("fixture canonical host groups = %#v", groups)
	}
	downloads := map[string]kubesprayEvaluatedDownload{}
	wantFiles := []discoveredKubesprayFile{
		{
			id:        "calico_crds",
			source:    "https://github.com/projectcalico/calico/raw/v3.31.5/manifests/crds.yaml",
			localPath: "github.com/projectcalico/calico/raw/v3.31.5/manifests/crds.yaml",
			checksum:  "1d6d5e523f92ee1e8227a48c016229c668f94035431b82f19139affeb45dbeff",
		},
		{
			id:        "calicoctl",
			source:    "https://github.com/projectcalico/calico/releases/download/v3.31.5/calicoctl-linux-amd64",
			localPath: "github.com/projectcalico/calico/releases/download/v3.31.5/calicoctl-linux-amd64",
			checksum:  "d1dd3a3fb2f5640987eab589dc1dcb03c47c11b32bc19a65c45c39421cd887d2",
		},
		{
			id:        "cni",
			source:    "https://github.com/containernetworking/plugins/releases/download/v1.9.1/cni-plugins-linux-amd64-v1.9.1.tgz",
			localPath: "github.com/containernetworking/plugins/releases/download/v1.9.1/cni-plugins-linux-amd64-v1.9.1.tgz",
			checksum:  "b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303",
		},
		{
			id:        "containerd",
			source:    "https://github.com/containerd/containerd/releases/download/v2.2.3/containerd-2.2.3-linux-amd64.tar.gz",
			localPath: "github.com/containerd/containerd/releases/download/v2.2.3/containerd-2.2.3-linux-amd64.tar.gz",
			checksum:  "ca26ef5138f17b847bbeeec36d4bf5e002b54d25858197a870c125d57f44d32f",
		},
		{
			id:        "crictl",
			source:    "https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.35.0/crictl-v1.35.0-linux-amd64.tar.gz",
			localPath: "github.com/kubernetes-sigs/cri-tools/releases/download/v1.35.0/crictl-v1.35.0-linux-amd64.tar.gz",
			checksum:  "2e141e5b22cb189c40365a11807d69b76b9b3caced89fac2f4ec879408ce2177",
		},
		{
			id:        "etcd",
			source:    "https://github.com/etcd-io/etcd/releases/download/v3.6.10/etcd-v3.6.10-linux-amd64.tar.gz",
			localPath: "github.com/etcd-io/etcd/releases/download/v3.6.10/etcd-v3.6.10-linux-amd64.tar.gz",
			checksum:  "ed579fafab5701e3aaa95509969e7bc74776a4ae5269d32e3928408b406456ec",
		},
		{
			id:        "kubeadm",
			source:    "https://dl.k8s.io/release/v" + kubernetesVersion + "/bin/linux/amd64/kubeadm",
			localPath: "dl.k8s.io/release/v" + kubernetesVersion + "/bin/linux/amd64/kubeadm",
			checksum:  "0c0497da793f8897c14e45340da919534b615294a1aab69dc1998896c0f11145",
		},
		{
			id:        "kubectl",
			source:    "https://dl.k8s.io/release/v" + kubernetesVersion + "/bin/linux/amd64/kubectl",
			localPath: "dl.k8s.io/release/v" + kubernetesVersion + "/bin/linux/amd64/kubectl",
			checksum:  "b529430df69a688fd61b64ad2299edb5fd71cb58be2a4779dba624c7d3510efd",
		},
		{
			id:        "kubelet",
			source:    "https://dl.k8s.io/release/v" + kubernetesVersion + "/bin/linux/amd64/kubelet",
			localPath: "dl.k8s.io/release/v" + kubernetesVersion + "/bin/linux/amd64/kubelet",
			checksum:  "983a6ba5a49823dcdd745c674e5e2416377dd27d6ad1b42d2befa0fb961a19f6",
		},
		{
			id:        "nerdctl",
			source:    "https://github.com/containerd/nerdctl/releases/download/v2.2.2/nerdctl-2.2.2-linux-amd64.tar.gz",
			localPath: "github.com/containerd/nerdctl/releases/download/v2.2.2/nerdctl-2.2.2-linux-amd64.tar.gz",
			checksum:  "6f637760fb2875e3454e97c3de7438fd17281b5996908cbd8ee1c872b0653cc8",
		},
		{
			id:        "runc",
			source:    "https://github.com/opencontainers/runc/releases/download/v1.4.2/runc.amd64",
			localPath: "github.com/opencontainers/runc/releases/download/v1.4.2/runc.amd64",
			checksum:  "ac8a90f9e225bb9322189937b230cdc5478d5753f0e31e1bda98a5cf06bd9539",
		},
	}
	for _, file := range wantFiles {
		source, checksum := file.source, file.checksum
		downloads[file.id] = kubesprayEvaluatedDownload{
			Enabled: true, File: true, URL: &source, Checksum: &checksum,
			Groups: []string{"k8s_cluster"},
		}
	}
	wantDownloadImages := []string{
		"quay.io/calico/cni:v3.31.5",
		"quay.io/calico/node:v3.31.5",
		"quay.io/calico/kube-controllers:v3.31.5",
		"registry.k8s.io/coredns/coredns:v1.12.4",
		"registry.k8s.io/cpa/cluster-proportional-autoscaler:v1.8.8",
		"registry.k8s.io/pause:3.10.1",
	}
	for index, image := range []struct {
		id, repo, tag string
	}{
		{"calico_cni", "quay.io/calico/cni", "v3.31.5"},
		{"calico_node", "quay.io/calico/node", "v3.31.5"},
		{"calico_policy", "quay.io/calico/kube-controllers", "v3.31.5"},
		{"coredns", "registry.k8s.io/coredns/coredns", "v1.12.4"},
		{"dnsautoscaler", "registry.k8s.io/cpa/cluster-proportional-autoscaler", "v1.8.8"},
		{"pod_infra", "registry.k8s.io/pause", "3.10.1"},
	} {
		if image.repo+":"+image.tag != wantDownloadImages[index] {
			t.Fatal("selected image fixture order is inconsistent")
		}
		repo, tag := image.repo, image.tag
		downloads[image.id] = kubesprayEvaluatedDownload{
			Enabled: true, Container: true, Repo: &repo, Tag: &tag,
			Groups: []string{"k8s_cluster"},
		}
	}
	excludedImages := []struct {
		id, repo, tag string
	}{
		{"cilium", "quay.io/cilium/cilium", "v1.19.4"},
		{"flannel", "docker.io/flannel/flannel", "v0.28.4"},
		{"external_openstack", "registry.k8s.io/provider-os/openstack", "v1.35.0"},
		{"metrics_server", "registry.k8s.io/metrics-server/metrics-server", "v0.8.1"},
	}
	for _, item := range excludedImages {
		repo, tag := item.repo, item.tag
		downloads[item.id] = kubesprayEvaluatedDownload{
			Container: true, Repo: &repo, Tag: &tag,
			Groups: []string{"k8s_cluster"},
		}
	}
	excludedFiles := []discoveredKubesprayFile{
		{
			id:        "crio",
			source:    "https://storage.googleapis.com/cri-o/artifacts/cri-o.amd64.v1.35.0.tar.gz",
			localPath: "storage.googleapis.com/cri-o/artifacts/cri-o.amd64.v1.35.0.tar.gz",
			checksum:  "55b6d3e9fc9a5864ab5cdf0b24d54b1dcbaf6d4919274b3b9eb37bfc4b0b8cb5",
		},
		{
			id:        "gvisor_runsc",
			source:    "https://storage.googleapis.com/gvisor/releases/release/20260323.0/x86_64/runsc",
			localPath: "storage.googleapis.com/gvisor/releases/release/20260323.0/x86_64/runsc",
			checksum:  "df61fefa05237aa7aa549e776071abfa947b19fbe5908393f5902257a2961ca9",
		},
		{
			id:        "kata_containers",
			source:    "https://github.com/kata-containers/kata-containers/releases/download/3.7.0/kata-static-3.7.0-amd64.tar.xz",
			localPath: "github.com/kata-containers/kata-containers/releases/download/3.7.0/kata-static-3.7.0-amd64.tar.xz",
			checksum:  "bebf218cafdc082476c7dabbcc5439aee6a41d6dda24dd3cfffbe0a6ae94e23d",
		},
	}
	for _, file := range excludedFiles {
		source, checksum := file.source, file.checksum
		downloads[file.id] = kubesprayEvaluatedDownload{
			File: true, URL: &source, Checksum: &checksum,
			Groups: []string{"k8s_cluster"},
		}
	}

	files, images, err := selectKubesprayDownloads(downloads)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, wantFiles) {
		t.Fatalf("selected files = %#v, want %#v", files, wantFiles)
	}
	if !reflect.DeepEqual(images, wantDownloadImages) {
		t.Fatalf("download-selected images = %#v, want %#v", images, wantDownloadImages)
	}
	images, err = mergeKubespraySelectedImages(images, []string{
		"registry.k8s.io/kube-apiserver:v1.35.4",
		"registry.k8s.io/kube-controller-manager:v1.35.4",
		"registry.k8s.io/kube-proxy:v1.35.4",
		"registry.k8s.io/kube-scheduler:v1.35.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantImages := []string{
		"quay.io/calico/cni:v3.31.5",
		"quay.io/calico/kube-controllers:v3.31.5",
		"quay.io/calico/node:v3.31.5",
		"registry.k8s.io/coredns/coredns:v1.12.4",
		"registry.k8s.io/cpa/cluster-proportional-autoscaler:v1.8.8",
		"registry.k8s.io/kube-apiserver:v1.35.4",
		"registry.k8s.io/kube-controller-manager:v1.35.4",
		"registry.k8s.io/kube-proxy:v1.35.4",
		"registry.k8s.io/kube-scheduler:v1.35.4",
		"registry.k8s.io/pause:3.10.1",
	}
	if !reflect.DeepEqual(images, wantImages) {
		t.Fatalf("selected images = %#v, want %#v", images, wantImages)
	}
	for _, item := range excludedImages {
		for _, source := range images {
			if strings.Contains(source, item.repo) {
				t.Fatalf("evaluated disabled payload %q was selected from %#v", item.id, images)
			}
		}
	}
	for _, item := range excludedFiles {
		for _, file := range files {
			if file.id == item.id {
				t.Fatalf("evaluated disabled file %q was selected from %#v", item.id, files)
			}
		}
	}
}

func TestKubespraySelectionInputIdentityUsesOnlySemanticSnapshots(t *testing.T) {
	t.Parallel()
	firstVars, err := json.Marshal(kubespraySelectionVars{
		ProjectionPath: "/workspace/.atum/invocations/kubespray-selection/first/projection.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondVars, err := json.Marshal(kubespraySelectionVars{
		ProjectionPath: "/workspace/.atum/invocations/kubespray-selection/second/projection.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(firstVars, secondVars) {
		t.Fatal("fixture invocation paths are not distinct")
	}
	selectionPaths := config.KubespraySelectionGroupVarPaths(config.Document{
		Orchestration: config.Orchestration{Inventory: "inventory"},
	})
	if len(selectionPaths) != 3 {
		t.Fatalf("selection inputs = %#v, want three authoritative group variables", selectionPaths)
	}
	inputs := map[string]string{
		selectionPaths[0]: strings.Repeat("a", 64),
		selectionPaths[1]: strings.Repeat("b", 64),
		selectionPaths[2]: strings.Repeat("c", 64),
	}
	overrides := kubespraySourceOverrides{KubeImageRepo: "registry.k8s.io"}
	first, err := kubespraySelectionInputSHA256(
		"1.35.4",
		"1c9add48975060f45396b34d8e022c30d7f80dab",
		kubespray.SelectionInventory(),
		[]byte("semantic playbook"),
		overrides,
		[]byte("semantic kubeadm template"),
		inputs,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := kubespraySelectionInputSHA256(
		"1.35.4",
		"1c9add48975060f45396b34d8e022c30d7f80dab",
		kubespray.SelectionInventory(),
		[]byte("semantic playbook"),
		overrides,
		[]byte("semantic kubeadm template"),
		map[string]string{
			selectionPaths[2]: strings.Repeat("c", 64),
			selectionPaths[0]: strings.Repeat("a", 64),
			selectionPaths[1]: strings.Repeat("b", 64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("invocation-private path-independent identities differ: %s != %s", first, second)
	}
	inputs[selectionPaths[1]] = strings.Repeat("d", 64)
	changed, err := kubespraySelectionInputSHA256(
		"1.35.4",
		"1c9add48975060f45396b34d8e022c30d7f80dab",
		kubespray.SelectionInventory(),
		[]byte("semantic playbook"),
		overrides,
		[]byte("semantic kubeadm template"),
		inputs,
	)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("changed snapshotted group variables retained the selection identity")
	}
}

func TestKubespraySelectionFailsClosed(t *testing.T) {
	t.Parallel()
	checksum := strings.Repeat("a", 64)
	source := "https://dl.k8s.io/release/kubeadm"
	downloads := map[string]kubesprayEvaluatedDownload{
		"kubeadm": {
			Enabled: true, File: true, URL: &source, Checksum: &checksum,
			Groups: []string{"k8s_cluster"},
		},
		"duplicate": {
			Enabled: true, File: true, URL: &source, Checksum: &checksum,
			Groups: []string{"k8s_cluster"},
		},
	}
	if _, _, err := selectKubesprayDownloads(downloads); err == nil ||
		!strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate source error = %v", err)
	}

	invalidSource := "https://dl.k8s.io/release/kubectl"
	invalidDownloads := map[string]kubesprayEvaluatedDownload{
		"Invalid": {
			Enabled: true, File: true, URL: &invalidSource, Checksum: &checksum,
			Groups: []string{"k8s_cluster"},
		},
	}
	if config.ValidKubesprayDownloadID("Invalid") {
		t.Fatal("shared Kubespray download-ID admission accepted an uppercase-leading ID")
	}
	if _, _, err := selectKubesprayDownloads(invalidDownloads); err == nil ||
		!strings.Contains(err.Error(), `download id "Invalid" is invalid`) {
		t.Fatalf("invalid evaluated ID error = %v", err)
	}
}
