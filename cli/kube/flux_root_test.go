package kube

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestObserveFluxHelmRootUsesCanonicalReadiness(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name          string
		deleteSource  bool
		deleteRelease bool
		staleStatus   bool
		wantComplete  bool
	}{
		{name: "source deleting", deleteSource: true},
		{name: "release deleting", deleteRelease: true},
		{name: "stale status generation", staleStatus: true},
		{name: "healthy current", wantComplete: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			source := fluxRootTestObject(
				"source.toolkit.fluxcd.io/v1",
				"OCIRepository",
			)
			release := fluxRootTestObject(
				"helm.toolkit.fluxcd.io/v2",
				"HelmRelease",
			)
			source.Object["spec"] = map[string]any{
				"url": "oci://harbor.test/charts/bigbang",
				"ref": map[string]any{"tag": "3.0.0"},
			}
			release.Object["spec"] = map[string]any{
				"chartRef": map[string]any{
					"kind":      "OCIRepository",
					"name":      "bigbang",
					"namespace": "bigbang",
				},
			}
			if test.deleteSource {
				source.SetFinalizers([]string{"test.atum.dev/observe"})
				source.SetDeletionTimestamp(&metav1.Time{Time: time.Unix(1, 0)})
			}
			if test.deleteRelease {
				release.SetFinalizers([]string{"test.atum.dev/observe"})
				release.SetDeletionTimestamp(&metav1.Time{Time: time.Unix(1, 0)})
			}
			if test.staleStatus {
				source.Object["status"].(map[string]any)["observedGeneration"] = int64(1)
			}
			observer := &Observer{dynamic: dynamicfake.NewSimpleDynamicClient(
				runtime.NewScheme(),
				source,
				release,
			)}
			observation, err := observer.ObserveFluxHelmRoot(
				context.Background(),
				"bigbang",
				"bigbang",
				FluxRootTarget{
					URL: "oci://harbor.test/charts/bigbang",
					Tag: "3.0.0",
				},
			)
			if err != nil {
				t.Fatalf("observe Flux root: %v", err)
			}
			if !observation.Found || !observation.TargetCurrent {
				t.Fatalf("observation lost current root identity: %#v", observation)
			}
			if got := observation.Complete(); got != test.wantComplete {
				t.Fatalf("complete = %t, want %t: %#v", got, test.wantComplete, observation)
			}
		})
	}
}

func fluxRootTestObject(apiVersion, kind string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":       "bigbang",
			"namespace":  "bigbang",
			"generation": int64(2),
		},
		"status": map[string]any{
			"observedGeneration": int64(2),
			"conditions": []any{
				map[string]any{
					"type":               "Ready",
					"status":             "True",
					"observedGeneration": int64(2),
				},
			},
		},
	}}
	return object
}
