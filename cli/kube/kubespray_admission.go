package kube

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubesprayContractFile struct {
	name     string
	relative string
	task     string
	evidence []string
	counts   map[string]int
}

var kubesprayScopedAnonymousContract = [...]kubesprayContractFile{
	{
		name:     "structured authentication defaults",
		relative: filepath.Join("roles", "kubespray_defaults", "defaults", "main", "main.yml"),
		evidence: []string{
			"kube_apiserver_use_authentication_config_file: false",
			"kube_apiserver_authentication_config_api_version:",
			// This is upstream bootstrap evidence, not an accepted final Atum API.
			"'v1beta1' if kube_version is version('1.34.0', '<') else 'v1'",
			"kube_apiserver_authentication_config_jwt: []",
			"kube_apiserver_authentication_config_anonymous:",
			"conditions: []",
		},
	},
	{
		name:     "structured authentication task",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "main.yml"),
		evidence: []string{
			"Create structured AuthenticationConfiguration file",
			"apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml",
			`mode: "0640"`,
			"apiVersion: apiserver.config.k8s.io/{{ kube_apiserver_authentication_config_api_version }}",
			`jwt: "{{ kube_apiserver_authentication_config_jwt }}"`,
			`anonymous: "{{ kube_apiserver_authentication_config_anonymous }}"`,
			"when: kube_apiserver_use_authentication_config_file",
		},
	},
	{
		name:     "kubeadm authentication mount",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "templates", "kubeadm-config.v1beta4.yaml.j2"),
		evidence: []string{
			"{% if kube_oidc_auth and kube_oidc_url is defined and kube_oidc_client_id is defined and not kube_apiserver_use_authentication_config_file %}",
			"{% if kube_api_anonymous_auth is defined and not kube_apiserver_use_authentication_config_file %}",
			"- name: authentication-config",
			`value: "{{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml"`,
			"hostPath: {{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml",
			"mountPath: {{ kube_config_dir }}/apiserver-authentication-config-{{ kube_apiserver_authentication_config_api_version }}.yaml",
		},
	},
	{
		name:     "cluster resolver lifecycle",
		relative: filepath.Join("playbooks", "cluster.yml"),
		evidence: []string{
			`when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'"`,
			"dns_late: true",
		},
	},
	{
		name:     "scale resolver lifecycle",
		relative: filepath.Join("playbooks", "scale.yml"),
		evidence: []string{
			`when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'"`,
			"dns_late: true",
		},
	},
	{
		name:     "upgrade resolver lifecycle",
		relative: filepath.Join("playbooks", "upgrade_cluster.yml"),
		evidence: []string{
			`when: "dns_mode != 'none' and resolvconf_mode == 'host_resolvconf'"`,
			"dns_late: true",
		},
	},
	{
		name:     "active control-plane upgrade role",
		relative: filepath.Join("playbooks", "upgrade_cluster.yml"),
		evidence: []string{
			"{ role: kubernetes/control-plane, tags: control-plane, upgrade_cluster_setup: true }",
		},
	},
	{
		name:     "late resolver API probe",
		relative: filepath.Join("roles", "kubernetes", "preinstall", "handlers", "main.yml"),
		task:     "Preinstall | wait for the apiserver to be running",
		evidence: []string{
			`url: "{{ kube_apiserver_endpoint }}/healthz"`,
			"- dns_late",
			"- dns_mode != 'none'",
			"- resolvconf_mode == 'host_resolvconf'",
		},
	},
	{
		name:     "authenticated node-label API probe",
		relative: filepath.Join("roles", "kubernetes", "node-label", "tasks", "main.yml"),
		task:     "Kubernetes Apps | Wait for kube-apiserver",
		evidence: []string{
			`url: "{{ kube_apiserver_endpoint }}/healthz"`,
			`client_cert: "{{ kube_apiserver_client_cert }}"`,
			`client_key: "{{ kube_apiserver_client_key }}"`,
		},
	},
	{
		name:     "scoped-anonymous control-plane restart API probe",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "handlers", "main.yml"),
		task:     "Control plane | wait for the apiserver to be running",
		evidence: []string{
			`url: "{{ kube_apiserver_endpoint }}/healthz"`,
			"- Control plane | restart kubelet",
			"- Control plane | Restart apiserver",
		},
	},
	{
		name:     "initial control-plane restart notification",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-setup.yml"),
		task:     "Kubeadm | Initialize first control plane node",
		evidence: []string{
			"notify: Control plane | restart kubelet",
		},
	},
	{
		name:     "scoped-anonymous upgrade API probe",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "check-api.yml"),
		task:     "Kubeadm | Check api is up",
		evidence: []string{
			"/healthz",
		},
	},
	{
		name:     "before-upgrade API probe caller",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
		task:     "Ensure kube-apiserver is up before upgrade",
		evidence: []string{
			"import_tasks: check-api.yml",
		},
	},
	{
		name:     "after-upgrade API probe caller",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
		task:     "Ensure kube-apiserver is up after upgrade and control plane configuration updates",
		evidence: []string{
			"import_tasks: check-api.yml",
		},
	},
	{
		name:     "upgrade API probe import cardinality",
		relative: filepath.Join("roles", "kubernetes", "control-plane", "tasks", "kubeadm-upgrade.yml"),
		counts: map[string]int{
			"import_tasks: check-api.yml": 2,
		},
	},
	{
		name:     "CoreDNS kubelet projection",
		relative: filepath.Join("roles", "kubernetes", "node", "templates", "kubelet-config.v1beta1.yaml.j2"),
		evidence: []string{
			"{% elif dns_mode in ['coredns'] %}",
			"{% set kubelet_cluster_dns = [skydns_server] %}",
			"clusterDNS:",
		},
	},
	{
		name:     "optional local API load balancer gate",
		relative: filepath.Join("roles", "kubernetes", "node", "tasks", "main.yml"),
		task:     "Install haproxy",
		evidence: []string{
			"import_tasks: loadbalancer/haproxy.yml",
			"- loadbalancer_apiserver_localhost",
			"- loadbalancer_apiserver_type == 'haproxy'",
		},
	},
	{
		name:     "optional local API load balancer",
		relative: filepath.Join("roles", "kubernetes", "node", "templates", "loadbalancer", "haproxy.cfg.j2"),
		evidence: []string{
			"backend kube_api_backend",
			"option httpchk GET /healthz",
			"check check-ssl verify none",
		},
	},
}

// ScopedAnonymousPaths returns the complete anonymous API path allowlist
// required by kubeadm bootstrap and static-pod probes and by Kubespray's
// lifecycle checks.
func ScopedAnonymousPaths() [4]string {
	return [4]string{
		"/healthz",
		"/livez",
		"/readyz",
		"/api/v1/namespaces/kube-public/configmaps/cluster-info",
	}
}

// ValidateKubesprayScopedAnonymousLifecycle verifies that an immutable
// Kubespray source uses only the selected Kubernetes health allowlist for
// lifecycle checks that do not carry a client identity.
func ValidateKubesprayScopedAnonymousLifecycle(checkout, kubernetes string) error {
	if _, err := AuthenticationConfigAPIVersion(kubernetes); err != nil {
		return err
	}
	for _, file := range kubesprayScopedAnonymousContract {
		data, err := readKubesprayEvidence(filepath.Join(checkout, file.relative))
		if err != nil {
			return fmt.Errorf("inspect Kubespray %s: %w", file.name, err)
		}
		text := string(data)
		if file.name == "structured authentication defaults" {
			var defaults struct {
				KubeConfigDir string `yaml:"kube_config_dir"`
			}
			if err := yaml.Unmarshal(data, &defaults); err != nil {
				return fmt.Errorf("decode Kubespray structured authentication defaults: %w", err)
			}
			if defaults.KubeConfigDir != "/etc/kubernetes" {
				return fmt.Errorf(
					"Kubespray structured authentication defaults select kube_config_dir %q, want /etc/kubernetes",
					defaults.KubeConfigDir,
				)
			}
		}
		if file.task != "" {
			if err := validateKubesprayTaskEvidence(text, file.name, file.task, file.evidence); err != nil {
				return err
			}
		} else {
			for _, evidence := range file.evidence {
				if !strings.Contains(text, evidence) {
					return fmt.Errorf(
						"Kubespray %s does not preserve required evidence %q",
						file.name, evidence,
					)
				}
			}
		}
		for evidence, count := range file.counts {
			if actual := strings.Count(text, evidence); actual != count {
				return fmt.Errorf(
					"Kubespray %s preserves %d instances of required evidence %q, want %d",
					file.name, actual, evidence, count,
				)
			}
		}
	}
	return nil
}

func validateKubesprayTaskEvidence(text, source, task string, evidence []string) error {
	marker := "- name: " + task
	start := -1
	for offset := 0; offset < len(text); {
		found := strings.Index(text[offset:], marker)
		if found < 0 {
			break
		}
		found += offset
		lineStart := found == 0 || text[found-1] == '\n'
		lineEnd := found+len(marker) == len(text) || text[found+len(marker)] == '\n'
		if lineStart && lineEnd {
			if start >= 0 {
				return fmt.Errorf("Kubespray %s preserves duplicate task %q", source, task)
			}
			start = found
		}
		offset = found + len(marker)
	}
	if start < 0 {
		return fmt.Errorf("Kubespray %s does not preserve required task %q", source, task)
	}
	end := len(text)
	if next := strings.Index(text[start+len(marker):], "\n- "); next >= 0 {
		end = start + len(marker) + next
	}
	segment := text[start:end]
	for _, fragment := range evidence {
		if !strings.Contains(segment, fragment) {
			return fmt.Errorf(
				"Kubespray %s task %q does not preserve required evidence %q",
				source, task, fragment,
			)
		}
	}
	return nil
}

func readKubesprayEvidence(path string) ([]byte, error) {
	const limit = 4 << 20
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > limit {
		return nil, errors.New("compatibility evidence exceeds 4 MiB")
	}
	return data, nil
}
