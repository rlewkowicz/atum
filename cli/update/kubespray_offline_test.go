package update

import (
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestKubesprayFullOfflineImageOutputIsNotFiltered(t *testing.T) {
	t.Parallel()
	official := []string{
		"quay.io/calico/node:v3.31.4",
		"docker.io/flannel/flannel:v0.27.4",
		"quay.io/metallb/controller:v0.15.3",
		"quay.io/cilium/hubble-relay:v1.19.1",
		"quay.io/cilium/operator:v1.19.1",
	}
	wantOfficial := append([]string(nil), official...)
	runtime := []kubesprayRuntimeImage{
		{
			source: "quay.io/cilium/cilium-envoy:v1.36.6",
			digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			source: "quay.io/cilium/operator-generic:v1.19.1",
			digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	expanded := mergeKubesprayRuntimeImages(official, runtime)
	if !reflect.DeepEqual(official, wantOfficial) {
		t.Fatalf("official generate_list.sh output was mutated: got %#v want %#v", official, wantOfficial)
	}
	for _, upstream := range wantOfficial {
		if !containsString(expanded, upstream) {
			t.Errorf("full upstream offline image %q was filtered: %#v", upstream, expanded)
		}
	}
	if !containsString(expanded, "quay.io/cilium/operator-generic:v1.19.1") {
		t.Fatalf("chart-derived Cilium runtime image is absent: %#v", expanded)
	}
	if !containsString(expanded, "quay.io/cilium/cilium-envoy:v1.36.6") {
		t.Fatalf("chart-selected Envoy runtime image is absent: %#v", expanded)
	}
}

func TestKubesprayCiliumRuntimeTagsUseExactChartCoordinates(t *testing.T) {
	t.Parallel()

	inventory := config.KubesprayArtifactInventory{
		RuntimeImages: []string{
			"quay.io/cilium/cilium:v1.19.4",
			"quay.io/cilium/cilium-envoy:v1.36.6-1778235340-b87d1e32f522b33bd51701c6476d199326f01496",
			"quay.io/cilium/operator-generic:v1.19.4",
		},
	}
	tags, err := kubesprayCiliumRuntimeTags(inventory)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"cilium_image_tag":              "v1.19.4",
		"cilium_hubble_envoy_image_tag": "v1.36.6-1778235340-b87d1e32f522b33bd51701c6476d199326f01496",
		"cilium_operator_image_tag":     "v1.19.4",
	}
	if !reflect.DeepEqual(tags, expected) {
		t.Fatalf("runtime tags = %#v, want %#v", tags, expected)
	}

	inventory.RuntimeImages = inventory.RuntimeImages[:2]
	if _, err := kubesprayCiliumRuntimeTags(inventory); err == nil ||
		!strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete runtime graph error = %v", err)
	}
}

func TestKubesprayRuntimeDiscoveryUsesExactChartTags(t *testing.T) {
	t.Parallel()

	runtime := []kubesprayRuntimeImage{
		{
			source:              "quay.io/cilium/cilium:v1.19.4",
			discoveryRepository: "quay.io/cilium/cilium",
		},
		{
			source:              "quay.io/cilium/cilium-envoy:v1.36.6",
			discoveryRepository: "quay.io/cilium/cilium-envoy",
		},
		{
			source:              "quay.io/cilium/operator-generic:v1.19.4",
			discoveryRepository: "quay.io/cilium/operator",
		},
	}
	sources := []string{
		"quay.io/cilium/cilium:v1.19.4",
		"quay.io/cilium/cilium-envoy:v1.36.6",
		"quay.io/cilium/operator:v1.19.4",
	}
	if err := validateKubesprayRuntimeDiscovery(sources, runtime); err != nil {
		t.Fatal(err)
	}
	sources[1] = "quay.io/cilium/cilium-envoy:v1.34.10"
	if err := validateKubesprayRuntimeDiscovery(sources, runtime); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched runtime discovery error = %v", err)
	}
}
