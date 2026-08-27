package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubesprayOIDCLifecycleCompatibility(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		filepath.Join("roles", "kubespray_defaults", "defaults", "main", "main.yml"): `
kube_config_dir: /etc/kubernetes
kube_apiserver_use_authentication_config_file: false
kube_apiserver_authentication_config_api_version: "{{ 'v1beta1' if kube_version is version('1.34.0', '<') else 'v1' }}"
kube_apiserver_authentication_config_anonymous:
  enabled: true
kube_apiserver_authentication_config_jwt: []
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
- name: anonymous-auth
  value: "{{ kube_api_anonymous_auth }}"
{% endif %}
- name: authentication-config
  value: "{{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml"
  hostPath: {{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml
  mountPath: {{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml
`,
	}
	for relative, data := range files {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.35.4"); err != nil {
		t.Fatalf("exact lifecycle rejected: %v", err)
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.33.5"); err == nil ||
		!strings.Contains(err.Error(), "lacks the required v1 AuthenticationConfiguration API") {
		t.Fatalf("unsupported final observation boundary error = %v", err)
	}
	defaults := filepath.Join(
		root, "roles", "kubespray_defaults", "defaults", "main", "main.yml")
	defaultData, err := os.ReadFile(defaults)
	if err != nil {
		t.Fatal(err)
	}
	withoutBootstrapBeta := strings.Replace(
		string(defaultData),
		"'v1beta1' if kube_version is version('1.34.0', '<') else 'v1'",
		"'v1'",
		1,
	)
	if err := os.WriteFile(defaults, []byte(withoutBootstrapBeta), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "structured authentication defaults") {
		t.Fatalf("missing CA-less bootstrap API evidence error = %v", err)
	}
	if err := os.WriteFile(defaults, defaultData, 0o600); err != nil {
		t.Fatal(err)
	}
	changedDefault := strings.Replace(
		string(defaultData),
		"kube_config_dir: /etc/kubernetes",
		"kube_config_dir: /var/lib/kubernetes",
		1,
	)
	if err := os.WriteFile(defaults, []byte(changedDefault), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "structured authentication defaults") {
		t.Fatalf("changed kube_config_dir error = %v", err)
	}
	if err := os.WriteFile(defaults, defaultData, 0o600); err != nil {
		t.Fatal(err)
	}
	task := filepath.Join(
		root, "roles", "kubernetes", "control-plane", "tasks", "main.yml")
	taskData, err := os.ReadFile(task)
	if err != nil {
		t.Fatal(err)
	}
	withoutAnonymousProjection := strings.Replace(
		string(taskData),
		`      anonymous: "{{ kube_apiserver_authentication_config_anonymous }}"`,
		"",
		1,
	)
	if err := os.WriteFile(task, []byte(withoutAnonymousProjection), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "structured authentication task") {
		t.Fatalf("missing anonymous projection evidence error = %v", err)
	}
	if err := os.WriteFile(task, taskData, 0o600); err != nil {
		t.Fatal(err)
	}
	template := filepath.Join(
		root, "roles", "kubernetes", "control-plane", "templates", "kubeadm-config.v1beta4.yaml.j2")
	templateData, err := os.ReadFile(template)
	if err != nil {
		t.Fatal(err)
	}
	withoutLegacyGuard := strings.Replace(
		string(templateData),
		"{% if kube_api_anonymous_auth is defined and not kube_apiserver_use_authentication_config_file %}",
		"{% if kube_api_anonymous_auth is defined %}",
		1,
	)
	if err := os.WriteFile(template, []byte(withoutLegacyGuard), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "kubeadm authentication mount") {
		t.Fatalf("missing legacy anonymous-auth guard error = %v", err)
	}
	if err := os.WriteFile(template, templateData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(template, []byte("authentication-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateKubesprayOIDCLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "kubeadm authentication mount") {
		t.Fatalf("missing mount evidence error = %v", err)
	}
}
