package update

import (
	"errors"
	"strings"
	"testing"
)

func TestFormerWaitResourceAbsenceAdmission(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		artifact string
		manifest string
		rejected bool
	}{
		{
			name:     "selected wait Job",
			artifact: "package/headlamp",
			manifest: `
apiVersion: batch/v1
kind: Job
metadata:
  name: headlamp-wait-job
  namespace: headlamp
`,
			rejected: true,
		},
		{
			name:     "selected wait NetworkPolicy",
			artifact: "package/kiali",
			manifest: `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-from-kiali-wait-job-to-anywhere-any-port
  namespace: kiali
`,
			rejected: true,
		},
		{
			name:     "unrelated artifact",
			artifact: "package/grafana",
			manifest: `
apiVersion: batch/v1
kind: Job
metadata:
  name: grafana-wait-job
  namespace: grafana
`,
		},
		{
			name:     "unrelated selected Job",
			artifact: "package/kyverno-policies",
			manifest: `
apiVersion: batch/v1
kind: Job
metadata:
  name: policy-migration
  namespace: kyverno-policies
`,
		},
		{
			name:     "unrelated selected NetworkPolicy",
			artifact: "package/istio-gateway",
			manifest: `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-gateway-egress
  namespace: istio-gateway
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspection, err := inspectManifestData("selected.yaml", []byte(test.manifest))
			if err != nil {
				t.Fatal(err)
			}
			err = validateFormerWaitResourceAbsence(map[string]chartInspection{
				test.artifact: inspection,
			})
			if test.rejected {
				var renderError *artifactRenderError
				if !errors.As(err, &renderError) ||
					renderError.id != test.artifact ||
					!strings.Contains(err.Error(), "selected.yaml#0") {
					t.Fatalf("wait-resource error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFormerWaitResourceMergeIsBounded(t *testing.T) {
	t.Parallel()
	source := formerWaitObservation{
		Resources: make([]renderedResource, maxFormerWaitResources),
	}
	for index := range source.Resources {
		source.Resources[index] = renderedResource{
			APIVersion: "batch/v1",
			Kind:       "Job",
			Name:       "headlamp-wait-job",
			Path:       "rendered.yaml#0",
		}
	}
	var combined formerWaitObservation
	mergeFormerWaitObservation(&combined, source, "headlamp/first/")
	mergeFormerWaitObservation(
		&combined,
		formerWaitObservation{Resources: []renderedResource{{
			APIVersion: "batch/v1",
			Kind:       "Job",
			Name:       "headlamp-wait-job",
			Path:       "rendered.yaml#0",
		}}},
		"headlamp/second/",
	)
	if combined.Overflow == nil ||
		!strings.Contains(combined.Overflow.Path, "headlamp/second/") {
		t.Fatal("multi-instance former wait-resource observation did not fail closed")
	}
}
