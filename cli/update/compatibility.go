package update

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/kube"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

type kubernetesRelease struct {
	Version   string
	Checksums config.KubernetesChecksums
}

type kubesprayChecksums struct {
	Kubelet map[string]map[string]string `yaml:"kubelet_checksums"`
	Kubeadm map[string]map[string]string `yaml:"kubeadm_checksums"`
	Kubectl map[string]map[string]string `yaml:"kubectl_checksums"`
}

type versionConstraint struct {
	ID    string
	Value string
}

var errNoCompatibleKubernetes = errors.New("no compatible Kubernetes release")

func validateKubesprayOIDCLifecycle(checkout, kubernetes string) error {
	if _, err := kube.AuthenticationConfigAPIVersion(kubernetes); err != nil {
		return err
	}
	return validateKubesprayOIDCImplementation(checkout)
}

func validateKubesprayOIDCImplementation(checkout string) error {
	type contractFile struct {
		name     string
		relative string
		evidence []string
	}
	files := [...]contractFile{
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
	}
	for _, file := range files {
		data, err := readCompatibilityEvidence(filepath.Join(checkout, file.relative))
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
					defaults.KubeConfigDir)
			}
		}
		for _, evidence := range file.evidence {
			if !strings.Contains(text, evidence) {
				return fmt.Errorf("Kubespray %s does not preserve required evidence %q", file.name, evidence)
			}
		}
	}
	return nil
}

func readCompatibilityEvidence(path string) ([]byte, error) {
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

func readKubesprayMatrix(checkout string) ([]kubernetesRelease, error) {
	path := filepath.Join(checkout, "roles", "kubespray_defaults", "vars", "main", "checksums.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Kubespray checksum matrix: %w", err)
	}
	var checksums kubesprayChecksums
	if err := yaml.Unmarshal(data, &checksums); err != nil {
		return nil, fmt.Errorf("decode Kubespray checksum matrix: %w", err)
	}
	kubelet := checksums.Kubelet["amd64"]
	kubeadm := checksums.Kubeadm["amd64"]
	kubectl := checksums.Kubectl["amd64"]
	if len(kubelet) == 0 || len(kubeadm) == 0 || len(kubectl) == 0 {
		return nil, errors.New("invalid Kubespray checksum matrix: incomplete amd64 Kubernetes checksums")
	}
	releases := make([]kubernetesRelease, 0, len(kubelet))
	semanticVersions := make(map[string]*semver.Version, len(kubelet))
	for version, kubeletSHA := range kubelet {
		semantic, parseErr := semver.NewVersion(strings.TrimPrefix(version, "v"))
		if parseErr != nil || semantic.Prerelease() != "" {
			continue
		}
		kubeadmSHA, hasKubeadm := kubeadm[version]
		kubectlSHA, hasKubectl := kubectl[version]
		if !hasKubeadm || !hasKubectl || !validChecksum(kubeletSHA) || !validChecksum(kubeadmSHA) || !validChecksum(kubectlSHA) {
			continue
		}
		release := kubernetesRelease{
			Version: strings.TrimPrefix(version, "v"),
			Checksums: config.KubernetesChecksums{
				Kubelet: kubeletSHA,
				Kubeadm: kubeadmSHA,
				Kubectl: kubectlSHA,
			},
		}
		releases = append(releases, release)
		semanticVersions[release.Version] = semantic
	}
	sort.Slice(releases, func(i, j int) bool {
		return semanticVersions[releases[i].Version].GreaterThan(
			semanticVersions[releases[j].Version],
		)
	})
	if len(releases) == 0 {
		return nil, errors.New("invalid Kubespray checksum matrix: no complete stable amd64 Kubernetes release")
	}
	return releases, nil
}

func compatibleKubernetes(releases []kubernetesRelease, constraints []versionConstraint) ([]kubernetesRelease, error) {
	parsed := make([]*semver.Constraints, len(constraints))
	for i, constraint := range constraints {
		value, err := semver.NewConstraint(normalizeConstraint(constraint.Value))
		if err != nil {
			return nil, fmt.Errorf("parse Kubernetes constraint %s for %s: %w", constraint.Value, constraint.ID, err)
		}
		parsed[i] = value
	}
	compatible := make([]kubernetesRelease, 0, len(releases))
	for _, release := range releases {
		version, _ := semver.NewVersion(release.Version)
		matches := true
		for _, constraint := range parsed {
			if !constraint.Check(version) {
				matches = false
				break
			}
		}
		if matches {
			compatible = append(compatible, release)
		}
	}
	if len(compatible) == 0 {
		labels := make([]string, len(constraints))
		for i, constraint := range constraints {
			labels[i] = constraint.ID + "=" + constraint.Value
		}
		return nil, fmt.Errorf("%w: Kubespray supports no release satisfying %s", errNoCompatibleKubernetes, strings.Join(labels, ", "))
	}
	return compatible, nil
}

func requireKubernetesFloor(releases []kubernetesRelease, minimum string) ([]kubernetesRelease, error) {
	floor, err := semver.NewVersion(strings.TrimPrefix(minimum, "v"))
	if err != nil {
		return nil, fmt.Errorf("parse current Kubernetes version %s: %w", minimum, err)
	}
	result := make([]kubernetesRelease, 0, len(releases))
	for _, release := range releases {
		version, err := semver.NewVersion(release.Version)
		if err != nil {
			return nil, fmt.Errorf("parse supported Kubernetes version %s: %w", release.Version, err)
		}
		if !version.LessThan(floor) {
			result = append(result, release)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%w: no release is at least current Kubernetes %s", errNoCompatibleKubernetes, minimum)
	}
	return result, nil
}

func validChecksum(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validHexSHA256(strings.TrimPrefix(value, "sha256:"))
}
