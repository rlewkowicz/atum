package update

import (
	"reflect"
	"testing"

	"atum/cli/config"
)

func TestBuildReleaseLadderReplacesTerminalPatch(t *testing.T) {
	t.Parallel()

	current := []config.ClusterRelease{
		testClusterRelease("1.34.3", "v2.30.0", "a"),
		testClusterRelease("1.35.0", "v2.31.0", "b"),
	}
	selected := testKubernetesCandidate("1.35.4", "v2.31.0", "c")
	got, err := buildReleaseLadder(current, []kubernetesCandidate{selected}, selected)
	if err != nil {
		t.Fatalf("build release ladder: %v", err)
	}
	want := []config.ClusterRelease{
		current[0],
		{
			Kubernetes: selected.kubernetes.Version,
			Kubespray:  selected.kubespray.Source,
			Checksums:  selected.kubernetes.Checksums,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("release ladder = %#v, want %#v", got, want)
	}
}

func TestRetireCompletedReleaseSteps(t *testing.T) {
	t.Parallel()

	releases := []config.ClusterRelease{
		testClusterRelease("1.33.5", "v2.29.1", "a"),
		testClusterRelease("1.34.3", "v2.30.0", "b"),
		testClusterRelease("1.35.4", "v2.31.0", "c"),
	}
	got, err := retireCompletedReleaseSteps(releases, "v1.35.4")
	if err != nil {
		t.Fatalf("retire completed release steps: %v", err)
	}
	want := releases[2:]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active release plan = %#v, want %#v", got, want)
	}
}

func TestRetireCompletedReleaseStepsKeepsRequiredUpgrade(t *testing.T) {
	t.Parallel()

	releases := []config.ClusterRelease{
		testClusterRelease("1.34.3", "v2.30.0", "a"),
		testClusterRelease("1.35.4", "v2.31.0", "b"),
	}
	got, err := retireCompletedReleaseSteps(releases, "1.34.3")
	if err != nil {
		t.Fatalf("retain required release steps: %v", err)
	}
	if !reflect.DeepEqual(got, releases) {
		t.Fatalf("active release plan = %#v, want %#v", got, releases)
	}
}

func testKubernetesCandidate(
	kubernetesVersion string,
	kubesprayVersion string,
	commitCharacter string,
) kubernetesCandidate {
	release := testClusterRelease(
		kubernetesVersion,
		kubesprayVersion,
		commitCharacter,
	)
	return kubernetesCandidate{
		kubespray: resolvedGit{Source: release.Kubespray},
		kubernetes: kubernetesRelease{
			Version:   release.Kubernetes,
			Checksums: release.Checksums,
		},
	}
}

func testClusterRelease(
	kubernetesVersion string,
	kubesprayVersion string,
	commitCharacter string,
) config.ClusterRelease {
	return config.ClusterRelease{
		Kubernetes: kubernetesVersion,
		Kubespray: config.GitSource{
			URL:     "https://example.invalid/kubespray.git",
			Version: kubesprayVersion,
			Commit:  repeatTestCharacter(commitCharacter, 40),
		},
		Checksums: config.KubernetesChecksums{
			Kubelet: "sha256:" + repeatTestCharacter("1", 64),
			Kubeadm: "sha256:" + repeatTestCharacter("2", 64),
			Kubectl: "sha256:" + repeatTestCharacter("3", 64),
		},
	}
}

func repeatTestCharacter(character string, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = character[0]
	}
	return string(result)
}
