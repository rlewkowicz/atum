package orchestration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atum/cli/config"
	"atum/cli/process"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type preparationRunner struct {
	calls int
}

func (runner *preparationRunner) Run(context.Context, process.Command) error {
	runner.calls++
	return nil
}

func TestPrepareReleaseRejectsUncredentialedLockedKubesprayBeforeToolMutation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	source := filepath.Join(root, "locked-source")
	files := map[string]string{
		"cluster.yml":         "---\n",
		"upgrade-cluster.yml": "---\n",
		"requirements.txt":    "ansible==11.1.0\n",
		filepath.Join("roles", "kubespray_defaults", "defaults", "main", "main.yml"): `
kube_config_dir: /etc/kubernetes
kube_apiserver_use_authentication_config_file: false
kube_apiserver_authentication_config_api_version: "{{ 'v1beta1' if kube_version is version('1.34.0', '<') else 'v1' }}"
kube_apiserver_authentication_config_anonymous:
  enabled: true
kube_apiserver_authentication_config_jwt: []
`,
		filepath.Join("roles", "kubespray_defaults", "vars", "main", "checksums.yml"): `
kubelet_checksums:
  amd64:
    1.35.4: kubelet-sha
kubeadm_checksums:
  amd64:
    1.35.4: kubeadm-sha
kubectl_checksums:
  amd64:
    1.35.4: kubectl-sha
`,
		filepath.Join("roles", "kubernetes", "control-plane", "tasks", "main.yml"): `
- name: Create structured AuthenticationConfiguration file
  copy:
    dest: "{{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml"
    mode: "0640"
    content:
      apiVersion: apiserver.config.k8s.io/{{ kube_apiserver_authentication_config_api_version }}
      jwt: "{{ kube_apiserver_authentication_config_jwt }}"
      anonymous: "{{ kube_apiserver_authentication_config_anonymous }}"
  when: kube_apiserver_use_authentication_config_file
`,
		filepath.Join("roles", "kubernetes", "control-plane", "templates", "kubeadm-config.v1beta4.yaml.j2"): `
{% if kube_oidc_auth and kube_oidc_url is defined and kube_oidc_client_id is defined and not kube_apiserver_use_authentication_config_file %}
{% endif %}
{% if kube_api_anonymous_auth is defined and not kube_apiserver_use_authentication_config_file %}
{% endif %}
- name: authentication-config
  value: "{{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml"
  hostPath: {{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml
  mountPath: {{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml
`,
		filepath.Join("playbooks", "cluster.yml"): `
- { role: kubernetes/preinstall, when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'", tags: resolvconf, dns_late: true }
`,
		filepath.Join("playbooks", "scale.yml"): `
- { role: kubernetes/preinstall, when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'", tags: resolvconf, dns_late: true }
`,
		filepath.Join("playbooks", "upgrade_cluster.yml"): `
- { role: kubernetes/control-plane, tags: control-plane, upgrade_cluster_setup: true }
- { role: kubernetes/preinstall, when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'", tags: resolvconf, dns_late: true }
`,
		filepath.Join("roles", "kubernetes", "preinstall", "handlers", "main.yml"): `
- name: Preinstall | wait for the apiserver to be running
  uri:
    url: "{{ kube_apiserver_endpoint }}/healthz"
  when:
    - dns_late
    - dns_mode != 'none'
    - resolvconf_mode == 'host_resolvconf'
`,
		filepath.Join("roles", "kubernetes", "node-label", "tasks", "main.yml"): `
- name: Kubernetes Apps | Wait for kube-apiserver
  uri:
    url: "{{ kube_apiserver_endpoint }}/healthz"
    client_cert: "{{ kube_apiserver_client_cert }}"
    client_key: "{{ kube_apiserver_client_key }}"
`,
		filepath.Join("roles", "kubernetes", "control-plane", "handlers", "main.yml"): `
- name: Control plane | wait for the apiserver to be running
  uri:
    url: "{{ kube_apiserver_endpoint }}/healthz"
  listen:
    - Control plane | restart kubelet
    - Control plane | Restart apiserver
`,
	}
	for relative, data := range files {
		path := filepath.Join(source, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repository, err := git.PlainInit(source, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateRemote(&gitconfig.RemoteConfig{
		Name: git.DefaultRemoteName,
		URLs: []string{source},
	}); err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("."); err != nil {
		t.Fatal(err)
	}
	commit, err := worktree.Commit("locked Kubespray fixture", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Atum Test",
			Email: "atum@example.invalid",
			When:  time.Unix(1, 0),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const version = "v2.99.0"
	if _, err := repository.CreateTag(version, commit, nil); err != nil {
		t.Fatal(err)
	}

	release := config.ClusterRelease{
		Kubernetes: "1.35.4",
		Kubespray: config.GitSource{
			URL:     source,
			Version: version,
			Commit:  commit.String(),
		},
		Checksums: config.KubernetesChecksums{
			Kubelet: "kubelet-sha",
			Kubeadm: "kubeadm-sha",
			Kubectl: "kubectl-sha",
		},
	}
	runner := &preparationRunner{}
	service := Service{
		Project: &config.Project{
			Root: root,
			Desired: config.Document{
				Orchestration: config.Orchestration{Directory: "orchestration"},
			},
		},
		Runner: runner,
	}
	_, err = service.prepareRelease(context.Background(), release, []config.ClusterRelease{release})
	if err == nil ||
		!strings.Contains(err.Error(), "locked Kubespray "+version+" ("+commit.String()+") for Kubernetes 1.35.4") ||
		!strings.Contains(err.Error(), "authenticated control-plane restart API probe") ||
		!strings.Contains(err.Error(), "client_cert") {
		t.Fatalf("locked source admission error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("preparation runner calls = %d, want 0", runner.calls)
	}
	if _, err := os.Lstat(filepath.Join(root, ".atum", "cache", "tools")); !os.IsNotExist(err) {
		t.Fatalf("Kubespray tool cache exists before admission: %v", err)
	}
}
