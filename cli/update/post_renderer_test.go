package update

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHelmPostRendererReplacesOnlyNamedInitContainerImage(t *testing.T) {
	t.Parallel()
	const applicationImage = "registry.test/authservice:1.1.5"
	const utilityImage = "registry.test/ubi9:9.8"
	rendered := map[string]string{
		"authservice/templates/deployment.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: authservice
spec:
  template:
    spec:
      initContainers:
        - name: update-ca-bundle
          image: registry.test/authservice:1.1.5
          command: [sh, -c, "cat /etc/pki/tls/certs/* > /mnt/ca-bundle/ca-bundle.crt"]
        - name: unrelated
          image: registry.test/unrelated:1
      containers:
        - name: authservice
          image: registry.test/authservice:1.1.5
`,
	}
	postRenderers := []any{map[string]any{
		"kustomize": map[string]any{
			"patches": []any{map[string]any{
				"target": map[string]any{
					"group": "apps", "version": "v1",
					"kind": "Deployment", "name": "authservice",
				},
				"patch": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: authservice
spec:
  template:
    spec:
      initContainers:
        - name: update-ca-bundle
          image: registry.test/ubi9:9.8
`,
			}},
		},
	}}
	result, err := applyHelmPostRenderers(rendered, postRenderers)
	if err != nil {
		t.Fatal(err)
	}
	var deployment map[string]any
	if err := yaml.Unmarshal(
		[]byte(result["post-rendered/resources.yaml"]),
		&deployment,
	); err != nil {
		t.Fatal(err)
	}
	podSpec := mapAt(deployment, "spec", "template", "spec")
	initContainers, _ := podSpec["initContainers"].([]any)
	if len(initContainers) != 2 {
		t.Fatalf("init containers = %#v", initContainers)
	}
	first, _ := initContainers[0].(map[string]any)
	second, _ := initContainers[1].(map[string]any)
	if first["name"] != "update-ca-bundle" ||
		first["image"] != utilityImage ||
		second["name"] != "unrelated" ||
		second["image"] != "registry.test/unrelated:1" {
		t.Fatalf("post-rendered init containers = %#v", initContainers)
	}
	containers, _ := podSpec["containers"].([]any)
	application, _ := containers[0].(map[string]any)
	if application["image"] != applicationImage {
		t.Fatalf("application image = %#v", application["image"])
	}
}

func TestHelmPostRendererRejectsUnsupportedFluxField(t *testing.T) {
	t.Parallel()
	_, err := applyHelmPostRenderers(
		map[string]string{
			"templates/configmap.yaml": `apiVersion: v1
kind: ConfigMap
metadata:
  name: example
`,
		},
		[]any{map[string]any{
			"kustomize": map[string]any{"patchesStrategicMerge": []any{}},
		}},
	)
	if err == nil {
		t.Fatal("unsupported selected Flux post-render field was accepted")
	}
}
