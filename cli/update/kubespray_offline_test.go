package update

import (
	"reflect"
	"testing"
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
	expanded, err := includeKubesprayChartRuntimeImages(official)
	if err != nil {
		t.Fatal(err)
	}
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
}
