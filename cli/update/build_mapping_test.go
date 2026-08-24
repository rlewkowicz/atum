package update

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/gitcache"
)

const testBuildRevision = "0123456789abcdef0123456789abcdef01234567"

func matchingTagResolver(_ context.Context, _, tag string) (gitcache.Release, error) {
	return gitcache.Release{Version: tag, Commit: testBuildRevision}, nil
}

const concreteOperatorGraph = `
target "operator" {
  tags = ["registry.test/atum/operator:3.0.0-alpha-debian13-r1"]
  contexts = {
    operator_source = "https://github.com/example/operator.git?tag=v3.0.0-alpha&checksum=0123456789abcdef0123456789abcdef01234567"
  }
  args = {
    ATUM_IMAGE_VERSION = "3.0.0-alpha"
    ATUM_IMAGE_REVISION = "0123456789abcdef0123456789abcdef01234567"
  }
}
`

func operatorInferenceImage() config.Image {
	return config.Image{
		ID:      "operator",
		Version: "3.0.0-alpha",
		Target:  "registry.test/atum/operator:3.0.0-alpha",
		Delivery: config.ImageDelivery{
			Default: config.DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/example/operator:3.0.0-alpha",
			},
			FullBuildTarget: "operator",
		},
	}
}

func TestInferChartAppBuildMapping(t *testing.T) {
	t.Parallel()

	mapping, err := inferChartAppBuildMapping(
		context.Background(),
		matchingTagResolver,
		[]byte(concreteOperatorGraph),
		"chart/operator",
		"docker.io/example/operator:2.8.0",
		operatorInferenceImage(),
	)
	if err != nil {
		t.Fatalf("infer mapping: %v", err)
	}
	if mapping.Artifact != "chart/operator" || mapping.Source != "chartAppVersion" ||
		mapping.Build == nil || mapping.Build.GitTagPrefix != "v" ||
		mapping.Build.ImageRepository != "docker.io/example/operator" ||
		mapping.Build.GitContext != "operator_source" ||
		mapping.Build.FullTagSuffix != "-debian13-r1" {
		t.Fatalf("mapping = %#v", mapping)
	}
}

func TestInferChartInspectionVersionMappingsOwnership(t *testing.T) {
	t.Parallel()

	inspection := chartInspection{
		AppVersion: "2.8.0",
		Images:     []string{"docker.io/example/operator:2.8.0"},
	}
	tests := []struct {
		name         string
		graph        string
		images       []config.Image
		resolveTag   exactTagResolver
		want         string
		wantCount    int
		wantRendered string
	}{
		{
			name:       "complete proof",
			graph:      concreteOperatorGraph,
			images:     []config.Image{operatorInferenceImage()},
			resolveTag: matchingTagResolver,
			wantCount:  1,
		},
		{
			name:  "aligned inventory proves current rendered evidence",
			graph: strings.ReplaceAll(concreteOperatorGraph, "3.0.0-alpha", "2.8.0"),
			images: []config.Image{func() config.Image {
				image := operatorInferenceImage()
				image.Version = "2.8.0"
				image.Target = "registry.test/atum/operator:2.8.0"
				image.Delivery.Default.Source = "docker.io/example/operator:2.8.0"
				return image
			}()},
			resolveTag:   matchingTagResolver,
			wantCount:    1,
			wantRendered: "docker.io/example/operator:2.8.0",
		},
		{
			name:  "duplicate delivery owners",
			graph: concreteOperatorGraph,
			images: []config.Image{
				operatorInferenceImage(),
				func() config.Image {
					image := operatorInferenceImage()
					image.ID = "operator-copy"
					image.Target = "registry.test/atum/operator-copy:3.0.0-alpha"
					return image
				}(),
			},
			resolveTag: matchingTagResolver,
			want:       "maps ambiguously",
		},
		{
			name:  "different-version direct owner is ignored",
			graph: concreteOperatorGraph,
			images: []config.Image{
				operatorInferenceImage(),
				func() config.Image {
					image := operatorInferenceImage()
					image.ID = "operator-old"
					image.Version = "1.0.0"
					image.Target = "registry.test/atum/operator-old:1.0.0"
					image.Delivery.Default.Source = "docker.io/example/operator:1.0.0"
					image.Delivery.FullBuildTarget = "operator-old"
					return image
				}(),
			},
			resolveTag: matchingTagResolver,
			wantCount:  1,
		},
		{
			name:  "different-version historical owner is ignored",
			graph: concreteOperatorGraph,
			images: []config.Image{
				operatorInferenceImage(),
				func() config.Image {
					image := operatorInferenceImage()
					image.ID = "operator-old"
					image.Target = "registry.test/atum/operator-old:3.0.0-alpha"
					image.Delivery.Default.Source = "docker.io/other/operator:3.0.0-alpha"
					image.Delivery.FullBuildTarget = "operator-old"
					image.BigBangRefs = []string{"docker.io/example/operator:1.0.0"}
					return image
				}(),
			},
			resolveTag: matchingTagResolver,
			wantCount:  1,
		},
		{
			name:  "historical reference is not mirror ownership",
			graph: concreteOperatorGraph,
			images: []config.Image{func() config.Image {
				image := operatorInferenceImage()
				image.Delivery.Default.Source = "docker.io/other/operator:3.0.0-alpha"
				image.BigBangRefs = []string{"docker.io/example/operator:3.0.0-alpha"}
				return image
			}()},
			resolveTag: matchingTagResolver,
			want:       "only through a runtime target or historical reference",
		},
		{
			name:  "existing mapping owns historical reference",
			graph: concreteOperatorGraph,
			images: []config.Image{func() config.Image {
				image := operatorInferenceImage()
				image.Delivery.Default.Source = "docker.io/other/operator:3.0.0-alpha"
				image.BigBangRefs = []string{"docker.io/example/operator:3.0.0-alpha"}
				image.VersionMapping = &config.ImageVersionMapping{
					Artifact: "package/operator",
					Source:   "upstreamImageTag",
				}
				return image
			}()},
			resolveTag: matchingTagResolver,
		},
		{
			name:  "mirror-only entry owns historical reference",
			graph: concreteOperatorGraph,
			images: []config.Image{func() config.Image {
				image := operatorInferenceImage()
				image.Delivery.Default.Source = "docker.io/other/operator:3.0.0-alpha"
				image.BigBangRefs = []string{"docker.io/example/operator:3.0.0-alpha"}
				image.Delivery.FullBuildTarget = ""
				return image
			}()},
			resolveTag: matchingTagResolver,
		},
		{
			name: "matrix target",
			graph: `
target "operator" {
  name = item.name
  matrix = { item = [{ name = "operator" }] }
  tags = ["registry.test/atum/operator:3.0.0-alpha-debian13-r1"]
  contexts = {
    operator_source = "https://github.com/example/operator.git?tag=v3.0.0-alpha&checksum=0123456789abcdef0123456789abcdef01234567"
  }
  args = {
    ATUM_IMAGE_VERSION = "3.0.0-alpha"
    ATUM_IMAGE_REVISION = "0123456789abcdef0123456789abcdef01234567"
  }
}`,
			images:     []config.Image{operatorInferenceImage()},
			resolveTag: matchingTagResolver,
			want:       "matrix template",
		},
		{
			name:   "missing exact Git tag",
			graph:  concreteOperatorGraph,
			images: []config.Image{operatorInferenceImage()},
			resolveTag: func(context.Context, string, string) (gitcache.Release, error) {
				return gitcache.Release{}, errors.New("tag is missing")
			},
			want: "tag is missing",
		},
		{
			name:   "peeled commit mismatch",
			graph:  concreteOperatorGraph,
			images: []config.Image{operatorInferenceImage()},
			resolveTag: func(_ context.Context, _, tag string) (gitcache.Release, error) {
				return gitcache.Release{
					Version: tag,
					Commit:  "89abcdef0123456789abcdef0123456789abcdef",
				}, nil
			},
			want: "want exact tag",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mappings, err := inferChartInspectionVersionMappings(
				context.Background(),
				test.resolveTag,
				[]byte(test.graph),
				"chart/operator",
				inspection,
				test.images,
			)
			if test.want == "" {
				if err != nil {
					t.Fatalf("infer mappings: %v", err)
				}
				if len(mappings) != test.wantCount {
					t.Fatalf("mappings = %#v", mappings)
				}
				if test.wantCount == 1 && mappings[0].mapping.Artifact != "chart/operator" {
					t.Fatalf("mapping = %#v", mappings[0])
				}
				if test.wantCount == 1 && mappings[0].renderedReference != test.wantRendered {
					t.Fatalf("rendered reference = %q, want %q", mappings[0].renderedReference, test.wantRendered)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestApplyInferredVersionMappingsSeedsOnlyAlignedEvidence(t *testing.T) {
	t.Parallel()

	const (
		alignedReference = "docker.io/example/aligned:2.8.0"
		repairReference  = "docker.io/example/repair:2.8.0"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{
				{ID: "aligned"},
				{ID: "repair"},
			},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{
					{ImageID: "aligned"},
					{ImageID: "repair"},
				},
			},
		},
	}
	mapping := config.ImageVersionMapping{
		Artifact: "chart/operator",
		Source:   "chartAppVersion",
	}
	count, err := applyInferredVersionMappings(
		desired,
		[][]inferredVersionMapping{{
			{imageIndex: 0, mapping: mapping, renderedReference: alignedReference},
			{imageIndex: 1, mapping: mapping},
		}},
	)
	if err != nil {
		t.Fatalf("apply inferred mappings: %v", err)
	}
	if count != 2 {
		t.Fatalf("mapping count = %d, want 2", count)
	}
	if !containsString(desired.Delivery.Images[0].BigBangRefs, alignedReference) ||
		!containsString(desired.Delivery.LegacyCrosswalk.Entries[0].BigBangRefs, alignedReference) {
		t.Fatalf("aligned evidence was not seeded: %#v", desired.Delivery)
	}
	if containsString(desired.Delivery.Images[1].BigBangRefs, repairReference) ||
		containsString(desired.Delivery.LegacyCrosswalk.Entries[1].BigBangRefs, repairReference) ||
		len(desired.Delivery.Images[1].BigBangRefs) != 0 ||
		len(desired.Delivery.LegacyCrosswalk.Entries[1].BigBangRefs) != 0 {
		t.Fatalf("bounded repair evidence was seeded early: %#v", desired.Delivery)
	}
}

func TestInferChartAppBuildMappingRejectsAmbiguousGitInput(t *testing.T) {
	t.Parallel()

	const graph = `
target "operator" {
  tags = ["registry.test/atum/operator:3.0.0-alpha-debian13-r1"]
  contexts = {
    first = "https://github.com/example/operator.git?tag=v3.0.0-alpha&checksum=0123456789abcdef0123456789abcdef01234567"
    second = "https://github.com/example/fork.git?tag=v3.0.0-alpha&checksum=0123456789abcdef0123456789abcdef01234567"
  }
  args = {
    ATUM_IMAGE_VERSION = "3.0.0-alpha"
    ATUM_IMAGE_REVISION = "0123456789abcdef0123456789abcdef01234567"
  }
}
`
	image := config.Image{
		Version: "3.0.0-alpha",
		Target:  "registry.test/atum/operator:3.0.0-alpha",
		Delivery: config.ImageDelivery{
			Default: config.DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/example/operator:3.0.0-alpha",
			},
			FullBuildTarget: "operator",
		},
	}
	_, err := inferChartAppBuildMapping(
		context.Background(),
		matchingTagResolver,
		[]byte(graph),
		"chart/operator",
		"docker.io/example/operator:2.8.0",
		image,
	)
	if err == nil || !strings.Contains(err.Error(), "multiple versioned Git inputs") {
		t.Fatalf("error = %v", err)
	}
}

func TestMappedBuildGitTagAdmission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		source       string
		oldVersion   string
		newVersion   string
		gitTagPrefix string
		wantError    bool
	}{
		{
			name:         "stable upstream image rejects semantic prerelease tag",
			source:       "upstreamImageTag",
			oldVersion:   "2.8.0",
			newVersion:   "2.9.0",
			gitTagPrefix: "1.0.0-alpha+",
			wantError:    true,
		},
		{
			name:         "stable chart application rejects semantic prerelease tag",
			source:       "chartAppVersion",
			oldVersion:   "2.8.0",
			newVersion:   "2.9.0",
			gitTagPrefix: "1.0.0-alpha+",
			wantError:    true,
		},
		{
			name:         "nonsemantic artifact rejects semantic prerelease tag",
			source:       "chartAppVersion",
			oldVersion:   "opaque",
			newVersion:   "opaque-next",
			gitTagPrefix: "1.0.0-alpha+",
			wantError:    true,
		},
		{
			name:         "authoritative prerelease artifact permits prerelease tag",
			source:       "upstreamImageTag",
			oldVersion:   "3.0.0-alpha",
			newVersion:   "3.0.0-beta",
			gitTagPrefix: "v",
		},
		{
			name:         "nonsemantic Git spelling remains admissible",
			source:       "chartAppVersion",
			oldVersion:   "2.8.0",
			newVersion:   "2.9.0",
			gitTagPrefix: "release-",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			oldSource := "docker.io/example/operator:" + test.oldVersion
			newSource := "docker.io/example/operator:" + test.newVersion
			image := config.Image{
				ID:      "operator",
				Version: test.oldVersion,
				Target:  "registry.test/atum/operator:" + test.oldVersion,
				BigBangRefs: []string{
					oldSource,
				},
				VersionMapping: &config.ImageVersionMapping{
					Artifact: "chart/operator",
					Source:   test.source,
					Build: &config.ImageBuildVersionMapping{
						ImageRepository: "docker.io/example/operator",
						GitURL:          "https://github.com/example/operator.git",
						GitTagPrefix:    test.gitTagPrefix,
						GitContext:      "operator_source",
						FullTagSuffix:   "-debian13-r1",
					},
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: oldSource,
					},
					FullBuildTarget: "operator",
				},
			}
			resolverCalls := 0
			var tree *candidateTree
			if test.wantError {
				tree = newCandidateTree(".")
			}
			replacement, changed, err := reconcileMappedBuildVersionWithResolver(
				context.Background(),
				func(context.Context, string, string) (gitcache.Release, error) {
					resolverCalls++
					return gitcache.Release{}, errors.New("resolver must not run in check mode")
				},
				tree,
				nil,
				nil,
				&image,
				test.oldVersion,
				test.newVersion,
				renderedEvidenceTransition{
					prior:     oldSource,
					candidate: newSource,
				},
				test.wantError,
			)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "semantic prerelease") {
					t.Fatalf("error = %v", err)
				}
				if changed || resolverCalls != 0 {
					t.Fatalf("changed = %t, resolver calls = %d", changed, resolverCalls)
				}
				return
			}
			if err != nil {
				t.Fatalf("reconcile mapped build: %v", err)
			}
			want := imageReplacement{
				Old: "registry.test/atum/operator:" + test.oldVersion,
				New: "registry.test/atum/operator:" + test.newVersion,
			}
			if !changed || replacement != want || resolverCalls != 0 {
				t.Fatalf("replacement = %#v, changed = %t, resolver calls = %d", replacement, changed, resolverCalls)
			}
		})
	}
}

func TestUpstreamImageMappedBuildAllowsEmptyBigBangEvidence(t *testing.T) {
	t.Parallel()

	const (
		oldRevision = "0123456789abcdef0123456789abcdef01234567"
		newRevision = "89abcdef0123456789abcdef0123456789abcdef"
		oldSource   = "docker.io/example/operator:2.8.0"
		newSource   = "docker.io/example/operator:2.9.0"
		oldTarget   = "registry.test/atum/operator:2.8.0"
		newTarget   = "registry.test/atum/operator:2.9.0"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "operator",
				Version: "2.8.0",
				Target:  oldTarget,
				VersionMapping: &config.ImageVersionMapping{
					Artifact: "package/opensearch",
					Source:   "upstreamImageTag",
					Build: &config.ImageBuildVersionMapping{
						ImageRepository: "docker.io/example/operator",
						GitURL:          "https://github.com/example/operator.git",
						GitTagPrefix:    "v",
						GitContext:      "operator_source",
						FullTagSuffix:   "-debian13-r1",
					},
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: oldSource,
					},
					FullBuildTarget: "operator",
				},
			}},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{{
					ImageID:     "operator",
					Replacement: oldTarget,
					OfficialSource: &config.OfficialSource{
						Reference: oldSource,
					},
				}},
			},
		},
	}
	lock := &config.Lock{
		Delivery: config.ImageLock{
			Images: []config.LockedImage{{
				ID:     "operator",
				Target: oldTarget,
				Delivery: config.LockedDelivery{
					Type:   "mirror",
					Source: oldSource,
				},
			}},
		},
	}
	graphData := []byte(strings.ReplaceAll(concreteOperatorGraph, "3.0.0-alpha", "2.8.0"))
	tree := newCandidateTree(".")
	graphVersion := managedVersion{
		exists: true,
		mode:   0o644,
		digest: hashBytes(graphData),
		data:   graphData,
	}
	tree.originals[buildGraphFile] = graphVersion
	tree.candidates[buildGraphFile] = graphVersion
	resolveTag := func(_ context.Context, _, tag string) (gitcache.Release, error) {
		commit := newRevision
		if tag == "v2.8.0" {
			commit = oldRevision
		}
		return gitcache.Release{Version: tag, Commit: commit}, nil
	}
	replacement, changed, err := reconcileMappedBuildVersionWithResolver(
		context.Background(),
		resolveTag,
		tree,
		desired,
		lock,
		&desired.Delivery.Images[0],
		"2.8.0",
		"2.9.0",
		renderedEvidenceTransition{prior: oldSource, candidate: newSource},
		true,
	)
	if err != nil {
		t.Fatalf("reconcile upstream image build: %v", err)
	}
	if !changed || replacement != (imageReplacement{Old: oldTarget, New: newTarget}) {
		t.Fatalf("replacement = %#v, changed = %t", replacement, changed)
	}
	image := desired.Delivery.Images[0]
	crosswalk := desired.Delivery.LegacyCrosswalk.Entries[0]
	if image.Target != newTarget || image.Delivery.Default.Source != newSource ||
		crosswalk.Replacement != newTarget || crosswalk.OfficialSource.Reference != newSource ||
		len(image.BigBangRefs) != 0 || len(crosswalk.BigBangRefs) != 0 {
		t.Fatalf("mapped build state = %#v / %#v", image, crosswalk)
	}
	updatedGraph, err := tree.CandidateData(buildGraphFile)
	if err != nil {
		t.Fatalf("read candidate graph: %v", err)
	}
	if !strings.Contains(string(updatedGraph), "tag=v2.9.0&checksum="+newRevision) {
		t.Fatalf("candidate graph did not advance:\n%s", updatedGraph)
	}
}

func TestMappedBuildSameVersionEvidenceRolloverAndNoOp(t *testing.T) {
	t.Parallel()

	const (
		prior     = "docker.io/example/operator:2.8.0"
		candidate = "docker.io/example/operator:v2.8.0"
		target    = "registry.test/atum/operator:2.8.0"
		source    = "docker.io/example/operator:release-2.8.0"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:          "operator",
				Version:     "2.8.0",
				Target:      target,
				BigBangRefs: []string{prior},
				VersionMapping: &config.ImageVersionMapping{
					Artifact: "chart/operator",
					Source:   "chartAppVersion",
					Build: &config.ImageBuildVersionMapping{
						ImageRepository: "docker.io/example/operator",
						ImageTagPrefix:  "release-",
						GitURL:          "https://github.com/example/operator.git",
						GitTagPrefix:    "v",
						GitContext:      "operator_source",
						FullTagSuffix:   "-debian13-r1",
					},
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: source,
					},
					FullBuildTarget: "operator",
				},
			}},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{{
					ImageID:     "operator",
					Replacement: target,
					BigBangRefs: []string{prior},
				}},
			},
		},
	}
	lock := &config.Lock{
		Delivery: config.ImageLock{
			Images: []config.LockedImage{{
				ID:     "operator",
				Target: target,
				Delivery: config.LockedDelivery{
					Type:   "mirror",
					Source: source,
				},
			}},
		},
	}
	tree := newCandidateTree(".")
	graphData := []byte(concreteOperatorGraph)
	graphVersion := managedVersion{
		exists: true,
		mode:   0o644,
		digest: hashBytes(graphData),
		data:   graphData,
	}
	tree.originals[buildGraphFile] = graphVersion
	tree.candidates[buildGraphFile] = graphVersion
	resolverCalls := 0
	replacement, changed, err := reconcileMappedBuildVersionWithResolver(
		context.Background(),
		func(context.Context, string, string) (gitcache.Release, error) {
			resolverCalls++
			return gitcache.Release{}, nil
		},
		tree,
		desired,
		lock,
		&desired.Delivery.Images[0],
		"2.8.0",
		"2.8.0",
		renderedEvidenceTransition{prior: prior, candidate: candidate},
		true,
	)
	if err != nil {
		t.Fatalf("roll over rendered evidence: %v", err)
	}
	if changed || replacement != (imageReplacement{}) || resolverCalls != 0 {
		t.Fatalf("replacement = %#v, changed = %t, resolver calls = %d", replacement, changed, resolverCalls)
	}
	if !containsString(desired.Delivery.Images[0].BigBangRefs, candidate) ||
		!containsString(desired.Delivery.LegacyCrosswalk.Entries[0].BigBangRefs, candidate) {
		t.Fatalf("candidate evidence was not recorded: %#v", desired.Delivery)
	}
	if desired.Delivery.Images[0].Target != target ||
		desired.Delivery.Images[0].Delivery.Default.Source != source {
		t.Fatalf("evidence rollover changed delivery state: %#v", desired.Delivery.Images[0])
	}
	updatedGraph, err := tree.CandidateData(buildGraphFile)
	if err != nil {
		t.Fatalf("read candidate graph: %v", err)
	}
	if string(updatedGraph) != string(graphData) {
		t.Fatalf("evidence rollover changed candidate graph:\n%s", updatedGraph)
	}

	convergedDesired, convergedLock, err := cloneState(*desired, *lock)
	if err != nil {
		t.Fatalf("clone converged state: %v", err)
	}
	replacement, changed, err = reconcileMappedBuildVersionWithResolver(
		context.Background(),
		nil,
		tree,
		desired,
		lock,
		&desired.Delivery.Images[0],
		"2.8.0",
		"2.8.0",
		renderedEvidenceTransition{prior: candidate, candidate: candidate},
		true,
	)
	if err != nil {
		t.Fatalf("reconcile exact evidence: %v", err)
	}
	if changed || replacement != (imageReplacement{}) ||
		!reflect.DeepEqual(*desired, convergedDesired) ||
		!reflect.DeepEqual(*lock, convergedLock) {
		t.Fatalf("exact evidence transition mutated state: %#v, %t", replacement, changed)
	}
}

func TestUpdateSourceBakeTargetAcceptsExactPrereleaseTag(t *testing.T) {
	t.Parallel()

	const graph = `
target "operator" {
  tags = ["registry.test/atum/operator:3.0.0-alpha-debian13-r1"]
  contexts = {
    operator_source = "https://github.com/example/operator.git?tag=v3.0.0-alpha&checksum=0123456789abcdef0123456789abcdef01234567"
  }
  args = {
    ATUM_IMAGE_VERSION = "3.0.0-alpha"
    ATUM_IMAGE_REVISION = "0123456789abcdef0123456789abcdef01234567"
  }
}
`
	build := &config.ImageBuildVersionMapping{
		GitURL:        "https://github.com/example/operator.git",
		GitTagPrefix:  "v",
		GitContext:    "operator_source",
		FullTagSuffix: "-debian13-r1",
	}
	updated, err := updateSourceBakeTarget(
		[]byte(graph),
		"operator",
		build,
		"registry.test/atum/operator",
		"",
		"3.0.0-alpha",
		"3.0.0",
		"0123456789abcdef0123456789abcdef01234567",
		"89abcdef0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("update source target: %v", err)
	}
	target, err := loadStaticBakeTarget(updated, "operator")
	if err != nil {
		t.Fatalf("load updated target: %v", err)
	}
	if target.tags[0] != "registry.test/atum/operator:3.0.0-debian13-r1" ||
		target.args["ATUM_IMAGE_VERSION"] != "3.0.0" ||
		!strings.Contains(target.contexts["operator_source"], "tag=v3.0.0&checksum=89abcdef") {
		t.Fatalf("updated target = %#v", target)
	}
}
