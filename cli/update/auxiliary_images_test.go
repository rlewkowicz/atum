package update

import (
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"

	fluxkustomize "github.com/fluxcd/pkg/apis/kustomize"
)

func TestProjectTrackedChartAuxiliaryImages(t *testing.T) {
	t.Parallel()

	inspection := auxiliaryRenderedInspection(t, "v0.15.0", false)
	current := auxiliaryGeneratedValues(nil)
	candidate := cloneMap(current)
	changes, err := projectTrackedChartAuxiliaryImages(
		current,
		candidate,
		auxiliaryTrackedCharts(),
		auxiliaryArtifacts(),
		[]chartInspection{inspection},
		auxiliaryInventory(),
	)
	if err != nil {
		t.Fatalf("project auxiliary images: %v", err)
	}
	if len(changes) != 1 ||
		!reflect.DeepEqual(changes[0].Added, []string{
			"gcr.io/kubebuilder/kube-rbac-proxy -> registry.example/atum/kube-rbac-proxy:v0.15.0",
		}) ||
		len(changes[0].Removed) != 0 {
		t.Fatalf("changes = %#v", changes)
	}
	images, err := generatedPostRendererImages(candidate, "packages.operator")
	if err != nil {
		t.Fatalf("read projected images: %v", err)
	}
	want := []map[string]any{{
		"name":    "gcr.io/kubebuilder/kube-rbac-proxy",
		"newName": "registry.example/atum/kube-rbac-proxy",
		"newTag":  "v0.15.0",
	}}
	if !reflect.DeepEqual(images, want) {
		t.Fatalf("images = %#v, want %#v", images, want)
	}
	assertAuxiliaryPatchPreserved(t, candidate)
}

func TestProjectTrackedChartAuxiliaryImagesRemovesAbsentProjection(t *testing.T) {
	t.Parallel()

	existing := []map[string]any{{
		"name":    "gcr.io/kubebuilder/kube-rbac-proxy",
		"newName": "registry.example/atum/kube-rbac-proxy",
		"newTag":  "v0.15.0",
	}}
	current := auxiliaryGeneratedValues(existing)
	candidate := cloneMap(current)
	changes, err := projectTrackedChartAuxiliaryImages(
		current,
		candidate,
		auxiliaryTrackedCharts(),
		auxiliaryArtifacts(),
		[]chartInspection{auxiliaryRenderedInspection(t, "", true)},
		auxiliaryInventory(),
	)
	if err != nil {
		t.Fatalf("remove auxiliary images: %v", err)
	}
	if len(changes) != 1 || len(changes[0].Added) != 0 ||
		!reflect.DeepEqual(changes[0].Removed, []string{
			"gcr.io/kubebuilder/kube-rbac-proxy -> registry.example/atum/kube-rbac-proxy:v0.15.0",
		}) {
		t.Fatalf("changes = %#v", changes)
	}
	images, err := generatedPostRendererImages(candidate, "packages.operator")
	if err != nil {
		t.Fatalf("read removed projection: %v", err)
	}
	if len(images) != 0 {
		t.Fatalf("images = %#v, want none", images)
	}
	assertAuxiliaryPatchPreserved(t, candidate)
}

func TestProjectTrackedChartAuxiliaryImagesStableSecondPass(t *testing.T) {
	t.Parallel()

	existing := []map[string]any{{
		"name":    "gcr.io/kubebuilder/kube-rbac-proxy",
		"newName": "registry.example/atum/kube-rbac-proxy",
		"newTag":  "v0.15.0",
	}}
	current := auxiliaryGeneratedValues(existing)
	candidate := cloneMap(current)
	inspection := auxiliaryRenderedInspection(t, "v0.15.0", true)
	changes, err := projectTrackedChartAuxiliaryImages(
		current,
		candidate,
		auxiliaryTrackedCharts(),
		auxiliaryArtifacts(),
		[]chartInspection{inspection},
		auxiliaryInventory(),
	)
	if err != nil {
		t.Fatalf("stable auxiliary projection: %v", err)
	}
	if len(changes) != 0 || !reflect.DeepEqual(candidate, current) {
		t.Fatalf("changes = %#v, candidate changed = %t", changes, !reflect.DeepEqual(candidate, current))
	}
}

func TestProjectTrackedChartAuxiliaryImagesOwnsEachRolloutProjection(t *testing.T) {
	t.Parallel()

	candidate := map[string]any{
		"packages": map[string]any{
			"operator":    map[string]any{},
			"application": map[string]any{},
		},
	}
	if err := pinIstioWorkloadRollouts(
		candidate,
		"1.30.3-bb.0",
		"registry.example/atum/proxyv2:1.30.3",
		[]string{"packages.operator", "packages.application"},
	); err != nil {
		t.Fatalf("pin workload rollouts: %v", err)
	}
	current := cloneMap(candidate)
	charts := []resolvedTrackedChart{
		{Chart: config.TrackedChart{ID: "operator", ValuesPath: "packages.operator"}},
		{Chart: config.TrackedChart{ID: "application", ValuesPath: "packages.application"}},
	}
	artifacts := []chartArtifact{
		{ID: "chart/operator"},
		{ID: "chart/application"},
	}
	_, err := projectTrackedChartAuxiliaryImages(
		current,
		candidate,
		charts,
		artifacts,
		[]chartInspection{
			auxiliaryRenderedInspection(t, "v0.15.0", false),
			{},
		},
		auxiliaryInventory(),
	)
	if err != nil {
		t.Fatalf("project auxiliary images: %v", err)
	}
	operatorImages, err := generatedPostRendererImages(candidate, "packages.operator")
	if err != nil {
		t.Fatalf("read operator images: %v", err)
	}
	if len(operatorImages) != 1 {
		t.Fatalf("operator images = %#v, want one", operatorImages)
	}
	applicationImages, err := generatedPostRendererImages(candidate, "packages.application")
	if err != nil {
		t.Fatalf("read application images: %v", err)
	}
	if len(applicationImages) != 0 {
		t.Fatalf("application images = %#v, want none", applicationImages)
	}
}

func TestAuxiliarySourceTagChangeReachesCompatibilityMapping(t *testing.T) {
	t.Parallel()

	current := auxiliaryRenderedInspection(t, "v0.15.0", true)
	candidate := auxiliaryRenderedInspection(t, "v0.16.0", true)
	desired := config.Document{
		Delivery: config.Delivery{
			Images: auxiliaryInventory(),
		},
	}
	replacements, err := reconcileImageContract(
		nil,
		nil,
		nil,
		&desired,
		nil,
		"chart/operator",
		current,
		candidate,
		map[string]struct{}{"operator": {}, "kube-rbac-proxy": {}},
		false,
		false,
	)
	if err != nil {
		t.Fatalf("reconcile changed source tag: %v", err)
	}
	want := []imageReplacement{{
		Old: "registry.example/atum/kube-rbac-proxy:v0.15.0",
		New: "registry.example/atum/kube-rbac-proxy:v0.16.0",
	}}
	if !reflect.DeepEqual(replacements, want) {
		t.Fatalf("replacements = %#v, want %#v", replacements, want)
	}
}

func TestProjectTrackedChartAuxiliaryImagesRejectsUnknownRepository(t *testing.T) {
	t.Parallel()

	current := auxiliaryGeneratedValues(nil)
	candidate := cloneMap(current)
	_, err := projectTrackedChartAuxiliaryImages(
		current,
		candidate,
		auxiliaryTrackedCharts(),
		auxiliaryArtifacts(),
		[]chartInspection{{Images: []string{"gcr.io/unknown/helper:v1.0.0"}}},
		auxiliaryInventory(),
	)
	if err == nil || !strings.Contains(err.Error(), "renders unknown image repository gcr.io/unknown/helper") {
		t.Fatalf("error = %v", err)
	}
}

func auxiliaryRenderedInspection(t *testing.T, sourceTag string, projected bool) chartInspection {
	t.Helper()

	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: operator
spec:
  selector:
    matchLabels:
      app: operator
  template:
    metadata:
      labels:
        app: operator
    spec:
      containers:
      - name: operator
        image: docker.io/example/operator:2.8.0
`
	if sourceTag != "" {
		manifest += `      - name: proxy
        image: gcr.io/kubebuilder/kube-rbac-proxy:` + sourceTag + `
`
	}
	rendered := map[string]string{
		"templates/deployment.yaml": manifest,
	}
	renderers := []releasePostRenderer{{
		Kustomize: &releaseKustomize{
			Patches: []fluxkustomize.Patch{{
				Patch: `- op: add
  path: /metadata/labels
  value:
    post-rendered: "true"
`,
				Target: &fluxkustomize.Selector{
					Kind: "Deployment",
					Name: "operator",
				},
			}},
		},
	}}
	if projected {
		renderers[0].Kustomize.Images = []fluxkustomize.Image{{
			Name:    "gcr.io/kubebuilder/kube-rbac-proxy",
			NewName: "registry.example/atum/kube-rbac-proxy",
			NewTag:  "v0.15.0",
		}}
	}
	sourceImages, distinct, err := inspectSourceImages(rendered, nil, renderers)
	if err != nil {
		t.Fatalf("inspect source render: %v", err)
	}
	if projected && !distinct {
		t.Fatal("source render was not separated from image projection")
	}
	if !distinct {
		sourceImages, _, _, err = inspectRenderedResources(rendered, nil, nil, nil)
		if err != nil {
			t.Fatalf("inspect unprojected source render: %v", err)
		}
	}
	sourceRenderers, changed := postRenderersWithoutImages(renderers)
	if changed != projected || len(sourceRenderers[0].Kustomize.Patches) != 1 {
		t.Fatalf("source renderers lost patches: %#v", sourceRenderers)
	}
	applied, err := applyPostRenderers(rendered, renderers)
	if err != nil {
		t.Fatalf("apply image projection: %v", err)
	}
	appliedImages, _, _, err := inspectRenderedResources(applied, nil, nil, nil)
	if err != nil {
		t.Fatalf("inspect applied render: %v", err)
	}
	return chartInspection{
		Name:         "operator",
		Version:      "2.8.0",
		AppVersion:   "2.8.0",
		Images:       appliedImages,
		SourceImages: sourceImages,
	}
}

func TestReconcileDeliveryEvidenceOwnsInventoryCoverage(t *testing.T) {
	t.Parallel()

	images := auxiliaryInventory()
	images[0].Family = "operator"
	images[0].Scopes = []string{"bigbang"}
	images[0].Consumers = []string{"Operator"}
	images[0].Delivery.Default = config.DeliveryChoice{
		Type:   "mirror",
		Source: "docker.io/example/operator:2.8.0",
		Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	images[1].Family = "operator"
	images[1].Scopes = []string{"bigbang"}
	images[1].Consumers = []string{"Operator proxy"}
	images[1].Delivery.Default.Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	desired := config.Document{
		Delivery: config.Delivery{
			Images: images,
			RenderedBaseline: config.RenderedBaseline{
				Entries: []config.RenderedBaselineEntry{{
					ImageID:  "operator",
					Evidence: "configuration",
				}},
			},
		},
	}

	reconcileDeliveryEvidence(&desired)

	if len(desired.Delivery.RenderedBaseline.Entries) != 2 ||
		desired.Delivery.RenderedBaseline.Entries[0].Evidence != "configuration" ||
		desired.Delivery.RenderedBaseline.Entries[1].Evidence != "rendered" ||
		len(desired.Delivery.LegacyCrosswalk.Entries) != 2 ||
		desired.Delivery.LegacyCrosswalk.Entries[1].OfficialSource == nil ||
		desired.Delivery.LegacyCrosswalk.Entries[1].OfficialSource.Reference !=
			"registry.k8s.io/kubebuilder/kube-rbac-proxy:v0.15.0" {
		t.Fatalf("reconciled delivery evidence = %#v / %#v",
			desired.Delivery.RenderedBaseline, desired.Delivery.LegacyCrosswalk)
	}
}

func TestReconcileDeliveryEvidenceKeepsRequiredArraysNonNil(t *testing.T) {
	t.Parallel()

	desired := config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:          "built",
				Scopes:      []string{},
				Consumers:   []string{},
				BigBangRefs: []string{},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:      "build",
						Materials: []string{},
					},
				},
			}},
		},
	}
	reconcileDeliveryEvidence(&desired)

	baseline := desired.Delivery.RenderedBaseline.Entries[0]
	entry := desired.Delivery.LegacyCrosswalk.Entries[0]
	if baseline.Scopes == nil ||
		entry.Scopes == nil ||
		entry.Consumers == nil ||
		entry.BigBangRefs == nil ||
		entry.CompatibilityBuild == nil ||
		entry.CompatibilityBuild.Materials == nil {
		t.Fatalf("required arrays contain nil: baseline=%#v crosswalk=%#v", baseline, entry)
	}
}

func TestApproveAuxiliaryImageCreatesCanonicalPendingMirror(t *testing.T) {
	t.Parallel()

	desired := config.Document{
		Platform: config.Platform{
			Charts: []config.TrackedChart{{ID: "operator"}},
		},
		Delivery: config.Delivery{
			Policy: config.DeliveryPolicy{
				RuntimeRegistryPrefix: "registry.example/atum/",
			},
		},
	}
	err := approveAuxiliaryImages(
		&desired,
		[]string{
			"chart/operator=kube-rbac-proxy,Apache-2.0,gcr.io/kubebuilder/kube-rbac-proxy:v0.15.0",
		},
	)
	if err != nil {
		t.Fatalf("approve auxiliary image: %v", err)
	}
	if len(desired.Delivery.Images) != 1 {
		t.Fatalf("images = %#v", desired.Delivery.Images)
	}
	image := desired.Delivery.Images[0]
	if image.ID != "kube-rbac-proxy" || image.Version != "0.15.0" ||
		image.Target != "registry.example/atum/kube-rbac-proxy:v0.15.0" ||
		!reflect.DeepEqual(
			image.BigBangRefs,
			[]string{"gcr.io/kubebuilder/kube-rbac-proxy:v0.15.0"},
		) ||
		image.Delivery.Default.Source !=
			"registry.k8s.io/kubebuilder/kube-rbac-proxy:v0.15.0" ||
		image.Delivery.Default.Digest !=
			"sha256:0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("approved image = %#v", image)
	}
}

func TestApproveAuxiliaryImageRejectsMalformedTuple(t *testing.T) {
	t.Parallel()

	desired := config.Document{
		Platform: config.Platform{
			Charts: []config.TrackedChart{{ID: "operator"}},
		},
	}
	err := approveAuxiliaryImages(
		&desired,
		[]string{"chart/operator=kube-rbac-proxy,Apache-2.0"},
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"must be chart/<id>=<image-id>,<license>,<official-reference>",
	) {
		t.Fatalf("error = %v", err)
	}
}

func auxiliaryGeneratedValues(images []map[string]any) map[string]any {
	kustomize := map[string]any{
		"patches": []any{map[string]any{
			"patch": "kind: Deployment\nmetadata:\n  name: rollout\n",
		}},
	}
	if len(images) != 0 {
		raw := make([]any, len(images))
		for i := range images {
			raw[i] = cloneMap(images[i])
		}
		kustomize["images"] = raw
	}
	return map[string]any{
		"packages": map[string]any{
			"operator": map[string]any{
				"postRenderers": []any{map[string]any{
					"kustomize": kustomize,
				}},
			},
		},
	}
}

func auxiliaryTrackedCharts() []resolvedTrackedChart {
	return []resolvedTrackedChart{{
		Chart: config.TrackedChart{
			ID:         "operator",
			ValuesPath: "packages.operator",
		},
	}}
}

func auxiliaryArtifacts() []chartArtifact {
	return []chartArtifact{{ID: "chart/operator"}}
}

func auxiliaryInventory() []config.Image {
	return []config.Image{
		{
			ID:          "operator",
			Version:     "2.8.0",
			Target:      "registry.example/atum/operator:2.8.0",
			BigBangRefs: []string{"docker.io/example/operator:2.8.0"},
			VersionMapping: &config.ImageVersionMapping{
				Artifact: "chart/operator",
				Source:   "chartAppVersion",
			},
			Delivery: config.ImageDelivery{
				Default: config.DeliveryChoice{
					Type:   "mirror",
					Source: "docker.io/example/operator:2.8.0",
				},
			},
		},
		{
			ID:     "kube-rbac-proxy",
			Target: "registry.example/atum/kube-rbac-proxy:v0.15.0",
			BigBangRefs: []string{
				"gcr.io/kubebuilder/kube-rbac-proxy:v0.15.0",
			},
			Delivery: config.ImageDelivery{
				Default: config.DeliveryChoice{
					Type:   "mirror",
					Source: "registry.k8s.io/kubebuilder/kube-rbac-proxy:v0.15.0",
				},
			},
		},
	}
}

func assertAuxiliaryPatchPreserved(t *testing.T, generated map[string]any) {
	t.Helper()

	values, err := valuesAt(generated, "packages.operator")
	if err != nil {
		t.Fatalf("read generated operator values: %v", err)
	}
	renderers, _ := values["postRenderers"].([]any)
	renderer, _ := renderers[0].(map[string]any)
	kustomize, _ := renderer["kustomize"].(map[string]any)
	patches, _ := kustomize["patches"].([]any)
	if len(patches) != 1 {
		t.Fatalf("patches = %#v", patches)
	}
}
