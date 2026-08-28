package update

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	fluxkustomize "github.com/fluxcd/pkg/kustomize"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

const postRendererRoot = "/atum-helm-post-renderer"

// applyHelmPostRenderers models the Helm controller's combined post-render
// stream. Big Bang owns the child HelmRelease and passes the typed Kustomize
// configuration through unchanged; this inspection applies the same ordered
// transformations before image and invocation admission.
func applyHelmPostRenderers(
	rendered map[string]string,
	postRenderers []any,
) (map[string]string, error) {
	if len(postRenderers) == 0 {
		return rendered, nil
	}
	resources := combinedRenderedResources(rendered)
	if len(bytes.TrimSpace(resources)) == 0 {
		return nil, errors.New("post-render stream has no Kubernetes resources")
	}
	for index, raw := range postRenderers {
		renderer, ok := raw.(map[string]any)
		if !ok || len(renderer) != 1 {
			return nil, fmt.Errorf(
				"postRenderer[%d] must contain exactly one kustomize renderer",
				index,
			)
		}
		kustomizeRaw, exists := renderer["kustomize"]
		if !exists {
			return nil, fmt.Errorf(
				"postRenderer[%d] has no kustomize renderer",
				index,
			)
		}
		kustomize, ok := kustomizeRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf(
				"postRenderer[%d].kustomize is not an object",
				index,
			)
		}
		kustomization := map[string]any{
			"apiVersion": "kustomize.config.k8s.io/v1beta1",
			"kind":       "Kustomization",
			"resources":  []any{"resources.yaml"},
		}
		for field, value := range kustomize {
			if field != "images" && field != "patches" {
				return nil, fmt.Errorf(
					"postRenderer[%d].kustomize.%s is unsupported by the selected Flux API",
					index,
					field,
				)
			}
			kustomization[field] = cloneValue(value)
		}
		encoded, err := yaml.Marshal(kustomization)
		if err != nil {
			return nil, fmt.Errorf(
				"encode postRenderer[%d] Kustomization: %w",
				index,
				err,
			)
		}
		filesystem := filesys.MakeFsInMemory()
		if err := filesystem.MkdirAll(postRendererRoot); err != nil {
			return nil, fmt.Errorf(
				"create postRenderer[%d] in-memory root: %w",
				index,
				err,
			)
		}
		if err := filesystem.WriteFile(
			postRendererRoot+"/kustomization.yaml",
			encoded,
		); err != nil {
			return nil, fmt.Errorf(
				"write postRenderer[%d] Kustomization: %w",
				index,
				err,
			)
		}
		if err := filesystem.WriteFile(
			postRendererRoot+"/resources.yaml",
			resources,
		); err != nil {
			return nil, fmt.Errorf(
				"write postRenderer[%d] resources: %w",
				index,
				err,
			)
		}
		result, err := fluxkustomize.Build(filesystem, postRendererRoot)
		if err != nil {
			return nil, fmt.Errorf("apply postRenderer[%d]: %w", index, err)
		}
		resources, err = result.AsYaml()
		if err != nil {
			return nil, fmt.Errorf(
				"encode postRenderer[%d] result: %w",
				index,
				err,
			)
		}
	}
	return map[string]string{
		"post-rendered/resources.yaml": string(resources),
	}, nil
}

func combinedRenderedResources(rendered map[string]string) []byte {
	names := make([]string, 0, len(rendered))
	for name, content := range rendered {
		if strings.HasSuffix(name, "NOTES.txt") ||
			len(strings.TrimSpace(content)) == 0 {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var combined bytes.Buffer
	for _, name := range names {
		combined.WriteString("---\n")
		combined.WriteString(rendered[name])
		if !strings.HasSuffix(rendered[name], "\n") {
			combined.WriteByte('\n')
		}
	}
	return combined.Bytes()
}
