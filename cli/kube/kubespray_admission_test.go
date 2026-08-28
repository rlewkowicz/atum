package kube

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubesprayScopedAnonymousLifecycleCompatibility(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		filepath.Join("roles", "kubespray_defaults", "defaults", "main", "main.yml"): `
kube_config_dir: /etc/kubernetes
kube_apiserver_use_authentication_config_file: false
kube_apiserver_authentication_config_api_version: "{{ 'v1beta1' if kube_version is version('1.34.0', '<') else 'v1' }}"
kube_apiserver_authentication_config_anonymous:
  enabled: true
  conditions: []
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
		filepath.Join("roles", "kubernetes", "control-plane", "handlers", "main.yml"): `
- name: Control plane | wait for the apiserver to be running
  uri:
    url: "{{ kube_apiserver_endpoint }}/healthz"
  listen:
    - Control plane | restart kubelet
    - Control plane | Restart apiserver
`,
		filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-setup.yml"): `
- name: Kubeadm | Initialize first control plane node
  notify: Control plane | restart kubelet
`,
		filepath.Join("roles", "kubernetes", "control-plane", "tasks", "check-api.yml"): `
- name: Kubeadm | Check api is up
  uri:
    url: "https://{{ main_ip }}:{{ kube_apiserver_port }}/healthz"
`,
		filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"): `
- name: Ensure kube-apiserver is up before upgrade
  import_tasks: check-api.yml
- name: Ensure kube-apiserver is up after upgrade and control plane configuration updates
  import_tasks: check-api.yml
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
		filepath.Join("roles", "kubernetes", "node", "templates", "kubelet-config.v1beta1.yaml.j2"): `
{% elif dns_mode in ['coredns'] %}
{% set kubelet_cluster_dns = [skydns_server] %}
clusterDNS:
`,
		filepath.Join("roles", "kubernetes", "node", "tasks", "main.yml"): `
- name: Install haproxy
  import_tasks: loadbalancer/haproxy.yml
  when:
    - loadbalancer_apiserver_localhost
    - loadbalancer_apiserver_type == 'haproxy'
`,
		filepath.Join("roles", "kubernetes", "node", "templates", "loadbalancer", "haproxy.cfg.j2"): `
backend kube_api_backend
  option httpchk GET /healthz
  server control-plane 127.0.0.1:6443 check check-ssl verify none
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
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err != nil {
		t.Fatalf("exact lifecycle rejected: %v", err)
	}
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.33.5"); err == nil ||
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
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
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
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
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
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
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
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "kubeadm authentication mount") {
		t.Fatalf("missing legacy anonymous-auth guard error = %v", err)
	}
	if err := os.WriteFile(template, templateData, 0o600); err != nil {
		t.Fatal(err)
	}
	lifecycleCases := []struct {
		name        string
		relative    string
		remove      string
		replacement string
		decoy       string
		want        string
	}{
		{
			name:     "cluster resolver gate",
			relative: filepath.Join("playbooks", "cluster.yml"),
			remove:   `when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'"`,
			want:     "cluster resolver lifecycle",
		},
		{
			name:     "scale resolver gate",
			relative: filepath.Join("playbooks", "scale.yml"),
			remove:   `when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'"`,
			want:     "scale resolver lifecycle",
		},
		{
			name:     "upgrade resolver gate",
			relative: filepath.Join("playbooks", "upgrade_cluster.yml"),
			remove:   `when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'"`,
			want:     "upgrade resolver lifecycle",
		},
		{
			name:     "active control-plane upgrade role",
			relative: filepath.Join("playbooks", "upgrade_cluster.yml"),
			remove:   "{ role: kubernetes/control-plane, tags: control-plane, upgrade_cluster_setup: true }",
			want:     "active control-plane upgrade role",
		},
		{
			name:     "late probe resolver gate",
			relative: filepath.Join("roles", "kubernetes", "preinstall", "handlers", "main.yml"),
			remove:   "- resolvconf_mode == 'host_resolvconf'",
			want:     "late resolver API probe",
		},
		{
			name:     "late probe DNS gate",
			relative: filepath.Join("roles", "kubernetes", "preinstall", "handlers", "main.yml"),
			remove:   "- dns_mode != 'none'",
			want:     "late resolver API probe",
		},
		{
			name:     "late probe lifecycle gate",
			relative: filepath.Join("roles", "kubernetes", "preinstall", "handlers", "main.yml"),
			remove:   "- dns_late",
			want:     "late resolver API probe",
		},
		{
			name:     "node-label client certificate",
			relative: filepath.Join("roles", "kubernetes", "node-label", "tasks", "main.yml"),
			remove:   `client_cert: "{{ kube_apiserver_client_cert }}"`,
			want:     "authenticated node-label API probe",
		},
		{
			name:     "node-label client key",
			relative: filepath.Join("roles", "kubernetes", "node-label", "tasks", "main.yml"),
			remove:   `client_key: "{{ kube_apiserver_client_key }}"`,
			want:     "authenticated node-label API probe",
		},
		{
			name:     "initial control-plane notification",
			relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-setup.yml"),
			remove:   "notify: Control plane | restart kubelet",
			want:     "initial control-plane restart notification",
		},
		{
			name:     "before-upgrade probe import",
			relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
			remove: "- name: Ensure kube-apiserver is up before upgrade\n" +
				"  import_tasks: check-api.yml",
			want: "before-upgrade API probe caller",
		},
		{
			name:     "after-upgrade probe import",
			relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
			remove: "- name: Ensure kube-apiserver is up after upgrade and control plane configuration updates\n" +
				"  import_tasks: check-api.yml",
			want: "after-upgrade API probe caller",
		},
		{
			name:     "node-label decoy client certificate",
			relative: filepath.Join("roles", "kubernetes", "node-label", "tasks", "main.yml"),
			remove:   `client_cert: "{{ kube_apiserver_client_cert }}"`,
			decoy: `
- name: Decoy node-label certificate
  uri:
    client_cert: "{{ kube_apiserver_client_cert }}"
`,
			want: "authenticated node-label API probe",
		},
		{
			name:     "node-label decoy client key",
			relative: filepath.Join("roles", "kubernetes", "node-label", "tasks", "main.yml"),
			remove:   `client_key: "{{ kube_apiserver_client_key }}"`,
			decoy: `
- name: Decoy node-label key
  uri:
    client_key: "{{ kube_apiserver_client_key }}"
`,
			want: "authenticated node-label API probe",
		},
		{
			name:     "late resolver decoy gate",
			relative: filepath.Join("roles", "kubernetes", "preinstall", "handlers", "main.yml"),
			remove:   "- resolvconf_mode == 'host_resolvconf'",
			decoy: `
- name: Decoy resolver gate
  when:
    - resolvconf_mode == 'host_resolvconf'
`,
			want: "late resolver API probe",
		},
		{
			name:     "initial notification decoy",
			relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-setup.yml"),
			remove:   "notify: Control plane | restart kubelet",
			decoy: `
- name: Decoy initial notification
  notify: Control plane | restart kubelet
`,
			want: "initial control-plane restart notification",
		},
		{
			name:     "before-upgrade import decoy",
			relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
			remove:   "  import_tasks: check-api.yml",
			decoy: `
- name: Decoy before-upgrade import
  import_tasks: check-api.yml
`,
			want: "before-upgrade API probe caller",
		},
		{
			name:     "after-upgrade import decoy",
			relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
			remove: "- name: Ensure kube-apiserver is up after upgrade and control plane configuration updates\n" +
				"  import_tasks: check-api.yml",
			replacement: "- name: Ensure kube-apiserver is up after upgrade and control plane configuration updates",
			decoy: `
- name: Decoy after-upgrade import
  import_tasks: check-api.yml
`,
			want: "after-upgrade API probe caller",
		},
		{
			name:     "local load balancer decoy gate",
			relative: filepath.Join("roles", "kubernetes", "node", "tasks", "main.yml"),
			remove:   "- loadbalancer_apiserver_localhost",
			decoy: `
- name: Decoy local load balancer gate
  when:
    - loadbalancer_apiserver_localhost
`,
			want: "optional local API load balancer gate",
		},
		{
			name:     "CoreDNS kubelet projection",
			relative: filepath.Join("roles", "kubernetes", "node", "templates", "kubelet-config.v1beta1.yaml.j2"),
			remove:   "{% set kubelet_cluster_dns = [skydns_server] %}",
			want:     "CoreDNS kubelet projection",
		},
		{
			name:     "local load balancer inventory gate",
			relative: filepath.Join("roles", "kubernetes", "node", "tasks", "main.yml"),
			remove:   "- loadbalancer_apiserver_localhost",
			want:     "optional local API load balancer gate",
		},
		{
			name:     "local load balancer health probe",
			relative: filepath.Join("roles", "kubernetes", "node", "templates", "loadbalancer", "haproxy.cfg.j2"),
			remove:   "option httpchk GET /healthz",
			want:     "optional local API load balancer",
		},
	}
	for _, testCase := range lifecycleCases {
		path := filepath.Join(root, testCase.relative)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.Replace(
			string(original), testCase.remove, testCase.replacement, 1,
		)
		if changed == string(original) {
			t.Fatalf("%s fixture lacks %q", testCase.name, testCase.remove)
		}
		changed += testCase.decoy
		if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
			!strings.Contains(err.Error(), testCase.want) {
			t.Fatalf("%s error = %v", testCase.name, err)
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	handler := filepath.Join(
		root, "roles", "kubernetes", "control-plane", "handlers", "main.yml",
	)
	handlerData, err := os.ReadFile(handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(handler, append(handlerData, handlerData...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "duplicate task") ||
		!strings.Contains(err.Error(), "scoped-anonymous control-plane restart API probe") {
		t.Fatalf("duplicate control-plane handler error = %v", err)
	}
	if err := os.WriteFile(handler, handlerData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(template, []byte("authentication-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKubesprayScopedAnonymousLifecycle(root, "1.35.4"); err == nil ||
		!strings.Contains(err.Error(), "kubeadm authentication mount") {
		t.Fatalf("missing mount evidence error = %v", err)
	}
}

func TestAtumKubesprayInventoryScopesAnonymousAPI(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	assertInventoryEvidence := func(relative string, required, prohibited []string) {
		t.Helper()

		data, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, evidence := range required {
			if !strings.Contains(text, evidence) {
				t.Fatalf("%s lacks %q", relative, evidence)
			}
		}
		for _, evidence := range prohibited {
			if strings.Contains(text, evidence) {
				t.Fatalf("%s retains %q", relative, evidence)
			}
		}
	}
	assertInventoryEvidence(
		filepath.Join("orchestration", "inventory", "atum", "group_vars", "all", "all.yml"),
		[]string{
			"loadbalancer_apiserver_localhost: false",
			"resolvconf_mode: none",
		},
		nil,
	)
	assertInventoryEvidence(
		filepath.Join("orchestration", "inventory", "atum", "group_vars", "k8s_cluster", "k8s-cluster.yml"),
		[]string{
			"enable_nodelocaldns: false",
			"dns_mode: coredns",
			"upstream_dns_servers:",
			`- "{{ atum_dns_server }}"`,
			"dns_upstream_forward_extra_opts:",
			`force_tcp: ""`,
			"kube_api_anonymous_auth: false",
			"default({'enabled': false})",
			"/healthz, /livez, and",
			"/readyz",
			"kube-public/cluster-info",
		},
		[]string{
			"dns_min_replicas: 1",
			"coredns_replicas: 1",
			"'conditions'",
			"default({'enabled': true})",
		},
	)
	assertInventoryEvidence(
		filepath.Join("infra", "libvirt", "cloud-init.tf"),
		[]string{
			"mode tcp",
			`format("    server %s %s:6443 check"`,
		},
		[]string{
			"/healthz",
			"option httpchk",
		},
	)
}
