package update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	fluxkustomize "github.com/fluxcd/pkg/apis/kustomize"
	"sigs.k8s.io/kustomize/api/krusty"
	kustypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

type releasePostRenderer struct {
	Kustomize *releaseKustomize `json:"kustomize"`
}

type releaseKustomize struct {
	Patches []fluxkustomize.Patch `json:"patches,omitempty"`
	Images  []fluxkustomize.Image `json:"images,omitempty"`
}

func postRenderersWithoutImages(renderers []releasePostRenderer) ([]releasePostRenderer, bool) {
	for i := range renderers {
		if renderers[i].Kustomize != nil && len(renderers[i].Kustomize.Images) != 0 {
			result := make([]releasePostRenderer, len(renderers))
			copy(result, renderers)
			for j := range result {
				if result[j].Kustomize == nil {
					continue
				}
				kustomize := *result[j].Kustomize
				kustomize.Images = nil
				result[j].Kustomize = &kustomize
			}
			return result, true
		}
	}
	return renderers, false
}

func decodePostRenderers(value any) ([]releasePostRenderer, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var renderers []releasePostRenderer
	if err := decoder.Decode(&renderers); err != nil {
		return nil, err
	}
	return renderers, nil
}

func applyPostRenderers(rendered map[string]string, renderers []releasePostRenderer) (map[string]string, error) {
	filenames := make([]string, 0, len(rendered))
	size := 0
	for filename, manifest := range rendered {
		if strings.HasSuffix(filename, "NOTES.txt") {
			continue
		}
		filenames = append(filenames, filename)
		size += len(manifest) + len("---\n")
	}
	sort.Strings(filenames)
	var combined bytes.Buffer
	combined.Grow(size)
	for _, filename := range filenames {
		combined.WriteString("---\n")
		combined.WriteString(rendered[filename])
		if !strings.HasSuffix(rendered[filename], "\n") {
			combined.WriteByte('\n')
		}
	}
	manifest := combined.Bytes()
	for i := range renderers {
		if renderers[i].Kustomize == nil {
			continue
		}
		var err error
		manifest, err = applyKustomizeRenderer(manifest, renderers[i].Kustomize)
		if err != nil {
			return nil, fmt.Errorf("apply postRenderer %d: %w", i, err)
		}
	}
	return map[string]string{"post-rendered.yaml": string(manifest)}, nil
}

var kustomizeRenderMutex sync.Mutex

func applyKustomizeRenderer(manifest []byte, renderer *releaseKustomize) ([]byte, error) {
	filesystem := filesys.MakeFsInMemory()
	configuration := kustypes.Kustomization{
		TypeMeta:  kustypes.TypeMeta{APIVersion: kustypes.KustomizationVersion, Kind: kustypes.KustomizationKind},
		Resources: []string{"helm-output.yaml"},
		Patches:   make([]kustypes.Patch, len(renderer.Patches)),
		Images:    make([]kustypes.Image, len(renderer.Images)),
	}
	for i := range renderer.Patches {
		configuration.Patches[i] = kustypes.Patch{
			Patch:  renderer.Patches[i].Patch,
			Target: adaptPostRendererSelector(renderer.Patches[i].Target),
		}
	}
	for i := range renderer.Images {
		configuration.Images[i] = kustypes.Image{
			Name:    renderer.Images[i].Name,
			NewName: renderer.Images[i].NewName,
			NewTag:  renderer.Images[i].NewTag,
			Digest:  renderer.Images[i].Digest,
		}
	}
	kustomization, err := json.Marshal(configuration)
	if err != nil {
		return nil, err
	}
	if err := filesystem.WriteFile("helm-output.yaml", manifest); err != nil {
		return nil, err
	}
	if err := filesystem.WriteFile("kustomization.yaml", kustomization); err != nil {
		return nil, err
	}

	kustomizeRenderMutex.Lock()
	defer kustomizeRenderMutex.Unlock()
	builder := krusty.MakeKustomizer(&krusty.Options{
		LoadRestrictions: kustypes.LoadRestrictionsNone,
		PluginConfig:     kustypes.DisabledPluginConfig(),
	})
	resources, err := builder.Run(filesystem, ".")
	if err != nil {
		return nil, err
	}
	return resources.AsYaml()
}

func adaptPostRendererSelector(selector *fluxkustomize.Selector) *kustypes.Selector {
	if selector == nil {
		return nil
	}
	adapted := &kustypes.Selector{
		AnnotationSelector: selector.AnnotationSelector,
		LabelSelector:      selector.LabelSelector,
	}
	adapted.Gvk.Group = selector.Group
	adapted.Gvk.Version = selector.Version
	adapted.Gvk.Kind = selector.Kind
	adapted.Name = selector.Name
	adapted.Namespace = selector.Namespace
	return adapted
}
