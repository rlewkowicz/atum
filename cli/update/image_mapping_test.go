package update

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/gitcache"
)

func TestReconcileImageContractSkipsIdenticalContract(t *testing.T) {
	t.Parallel()

	contract := chartInspection{
		Name:       "grafana",
		Version:    "10.5.15-bb.6",
		AppVersion: "13.0.1",
		Images: []string{
			"registry.test/atum/grafana-plugins:13.0.1-atum1",
		},
		Declared: []string{
			"registry.example/grafana/grafana-plugins:13.0.1",
		},
		ContractSHA: "same",
	}
	replacements, err := reconcileImageContract(
		nil, nil, nil, nil, nil, "package/grafana",
		contract, contract, nil, false, false,
	)
	if err != nil {
		t.Fatalf("reconcile identical contract: %v", err)
	}
	if replacements != nil {
		t.Fatalf("replacements = %#v, want nil", replacements)
	}
}

func TestIdenticalMappedChartRejectsDifferentOfficialRepository(t *testing.T) {
	t.Parallel()

	const renderedReference = "docker.io/rendered/operator:v2.8.0"
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "operator",
				Version: "2.8.0",
				Target:  "registry.test/atum/operator:v2.8.0",
				BigBangRefs: []string{
					renderedReference,
				},
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "chart/operator",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/unrelated/operator:v2.8.0",
						Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				},
			}},
		},
	}
	lock := &config.Lock{
		Delivery: config.ImageLock{
			Images: []config.LockedImage{{
				ID:     "operator",
				Target: "registry.test/atum/operator:v2.8.0",
				Delivery: config.LockedDelivery{
					Type:   "mirror",
					Source: "docker.io/unrelated/operator:v2.8.0",
					Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			}},
		},
	}
	originalDesired, originalLock, err := cloneState(*desired, *lock)
	if err != nil {
		t.Fatalf("clone state: %v", err)
	}
	contract := chartInspection{
		AppVersion:  "2.8.0",
		Images:      []string{renderedReference},
		ContractSHA: "same",
	}
	replacements, err := reconcileImageContract(
		context.Background(),
		nil,
		nil,
		desired,
		lock,
		"chart/operator",
		contract,
		contract,
		nil,
		true,
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match official mirror repository") {
		t.Fatalf("error = %v", err)
	}
	if replacements != nil {
		t.Fatalf("replacements = %#v, want nil", replacements)
	}
	if !reflect.DeepEqual(*desired, originalDesired) || !reflect.DeepEqual(*lock, originalLock) {
		t.Fatal("repository mismatch mutated desired or lock state")
	}
}

func TestIdenticalPackageChartMappingKeepsCrossRepositoryFastPath(t *testing.T) {
	t.Parallel()

	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "harbor-nginx",
				Version: "v2.15.2",
				Target:  "registry.test/atum/harbor-nginx:v2.15.2",
				BigBangRefs: []string{
					"registry.example/ironbank/nginx:v2.15.2",
				},
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "package/harbor",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/goharbor/nginx-photon:v2.15.2",
					},
				},
			}},
		},
	}
	originalDesired, _, err := cloneState(*desired, config.Lock{})
	if err != nil {
		t.Fatalf("clone state: %v", err)
	}
	contract := chartInspection{
		AppVersion:  "v2.15.2",
		Images:      []string{"registry.example/ironbank/nginx:v2.15.2"},
		ContractSHA: "same",
	}
	replacements, err := reconcileImageContract(
		context.Background(), nil, nil, desired, nil, "package/harbor",
		contract, contract, nil, true, false,
	)
	if err != nil {
		t.Fatalf("reconcile identical package: %v", err)
	}
	if replacements != nil || !reflect.DeepEqual(*desired, originalDesired) {
		t.Fatalf("replacements = %#v, desired mutated = %t", replacements, !reflect.DeepEqual(*desired, originalDesired))
	}
}

func TestChangedPackageChartMappingRetainsRenderedEvidence(t *testing.T) {
	t.Parallel()

	const (
		oldRendered = "registry.example/ironbank/nginx:v2.15.2"
		newRendered = "registry.example/ironbank/nginx:v2.16.0"
		oldTarget   = "registry.test/atum/harbor-nginx:v2.15.2"
		newTarget   = "registry.test/atum/harbor-nginx:v2.16.0"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:          "harbor-nginx",
				Version:     "2.15.2",
				Target:      oldTarget,
				BigBangRefs: []string{oldRendered},
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "package/harbor",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/goharbor/nginx-photon:v2.15.2",
					},
				},
			}},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{{
					ImageID:     "harbor-nginx",
					Replacement: oldTarget,
					BigBangRefs: []string{oldRendered},
					OfficialSource: &config.OfficialSource{
						Reference: "docker.io/goharbor/nginx-photon:v2.15.2",
					},
				}},
			},
		},
	}
	lock := &config.Lock{
		Delivery: config.ImageLock{
			Images: []config.LockedImage{{
				ID:     "harbor-nginx",
				Target: oldTarget,
				Delivery: config.LockedDelivery{
					Type:   "mirror",
					Source: "docker.io/goharbor/nginx-photon:v2.15.2",
				},
			}},
		},
	}
	current := chartInspection{AppVersion: "2.15.2", Images: []string{oldRendered}}
	candidate := chartInspection{AppVersion: "2.16.0", Images: []string{newRendered}}
	replacements, err := reconcileImageContract(
		context.Background(), nil, nil, desired, lock, "package/harbor",
		current, candidate, nil, true, false,
	)
	if err != nil {
		t.Fatalf("reconcile changed package mapping: %v", err)
	}
	want := imageReplacement{Old: oldTarget, New: newTarget}
	if len(replacements) != 1 || replacements[0] != want {
		t.Fatalf("replacements = %#v, want %#v", replacements, want)
	}
	image := desired.Delivery.Images[0]
	crosswalk := desired.Delivery.LegacyCrosswalk.Entries[0]
	if !containsString(image.BigBangRefs, oldRendered) || !containsString(image.BigBangRefs, newRendered) ||
		image.Delivery.Default.Source != "docker.io/goharbor/nginx-photon:v2.16.0" ||
		!containsString(crosswalk.BigBangRefs, newRendered) ||
		crosswalk.OfficialSource.Reference != "docker.io/goharbor/nginx-photon:v2.16.0" {
		t.Fatalf("image evidence = %#v / %#v", image, crosswalk)
	}
}

func TestPackageChartMappingAllowsEmptyCrossRepositoryEvidence(t *testing.T) {
	t.Parallel()

	const (
		oldRendered = "registry.example/ironbank/nginx:v2.15.2"
		newRendered = "registry.example/ironbank/nginx:v2.16.0"
		oldSource   = "docker.io/goharbor/nginx-photon:v2.15.2"
		newSource   = "docker.io/goharbor/nginx-photon:v2.16.0"
		oldTarget   = "registry.test/atum/harbor-nginx:v2.15.2"
		newTarget   = "registry.test/atum/harbor-nginx:v2.16.0"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "harbor-nginx",
				Version: "2.15.2",
				Target:  oldTarget,
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "package/harbor",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: oldSource,
					},
				},
			}},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{{
					ImageID:     "harbor-nginx",
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
				ID:     "harbor-nginx",
				Target: oldTarget,
				Delivery: config.LockedDelivery{
					Type:   "mirror",
					Source: oldSource,
				},
			}},
		},
	}
	current := chartInspection{AppVersion: "2.15.2", Images: []string{oldRendered}}
	candidate := chartInspection{AppVersion: "2.16.0", Images: []string{newRendered}}
	replacement, changed, err := reconcileVersionMappedImage(
		context.Background(), nil, nil, desired, lock, &desired.Delivery.Images[0],
		current, candidate, oldRendered, newRendered, true,
	)
	if err != nil {
		t.Fatalf("reconcile package mapping: %v", err)
	}
	if !changed || replacement != (imageReplacement{Old: oldTarget, New: newTarget}) {
		t.Fatalf("replacement = %#v, changed = %t", replacement, changed)
	}
	image := desired.Delivery.Images[0]
	crosswalk := desired.Delivery.LegacyCrosswalk.Entries[0]
	locked := lock.Delivery.Images[0]
	if image.Target != newTarget || image.Delivery.Default.Source != newSource ||
		crosswalk.Replacement != newTarget || crosswalk.OfficialSource.Reference != newSource ||
		locked.Target != newTarget || locked.Delivery.Source != newSource {
		t.Fatalf("package state = %#v / %#v / %#v", image, crosswalk, locked)
	}
	if len(image.BigBangRefs) != 0 || len(crosswalk.BigBangRefs) != 0 {
		t.Fatalf("package transition invented rendered evidence: %#v / %#v", image.BigBangRefs, crosswalk.BigBangRefs)
	}
}

func TestDirectChartMappingsRejectMissingRenderedPrior(t *testing.T) {
	t.Parallel()

	const (
		oldRendered = "docker.io/example/operator:2.8.0"
		newRendered = "docker.io/example/operator:2.9.0"
		oldTarget   = "registry.test/atum/operator:2.8.0"
	)
	for _, fullBuild := range []bool{false, true} {
		fullBuild := fullBuild
		name := "mirror-only"
		if fullBuild {
			name = "mapped-build"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mapping := &config.ImageVersionMapping{
				Artifact: "chart/operator",
				Source:   "chartAppVersion",
			}
			delivery := config.ImageDelivery{
				Default: config.DeliveryChoice{
					Type:   "mirror",
					Source: oldRendered,
					Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			}
			if fullBuild {
				mapping.Build = &config.ImageBuildVersionMapping{
					ImageRepository: "docker.io/example/operator",
					GitURL:          "https://github.com/example/operator.git",
					GitTagPrefix:    "v",
					GitContext:      "operator_source",
					FullTagSuffix:   "-debian13-r1",
				}
				delivery.FullBuildTarget = "operator"
			}
			desired := &config.Document{
				Delivery: config.Delivery{
					Images: []config.Image{{
						ID:             "operator",
						Version:        "2.8.0",
						Target:         oldTarget,
						VersionMapping: mapping,
						Delivery:       delivery,
					}},
					RenderedBaseline: config.RenderedBaseline{
						Entries: []config.RenderedBaselineEntry{{
							ImageID: "operator",
							Target:  oldTarget,
						}},
					},
					LegacyCrosswalk: config.LegacyCrosswalk{
						Entries: []config.LegacyCrosswalkEntry{{
							ImageID:     "operator",
							Replacement: oldTarget,
							OfficialSource: &config.OfficialSource{
								Reference: oldRendered,
								Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
							Source: oldRendered,
							Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						},
					}},
				},
			}
			originalDesired, originalLock, err := cloneState(*desired, *lock)
			if err != nil {
				t.Fatalf("clone state: %v", err)
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
			current := chartInspection{AppVersion: "2.8.0", Images: []string{oldRendered}}
			candidate := chartInspection{AppVersion: "2.9.0", Images: []string{newRendered}}
			replacement, changed, err := reconcileVersionMappedImageWithResolver(
				context.Background(),
				nil,
				func(context.Context, string, string) (gitcache.Release, error) {
					resolverCalls++
					return gitcache.Release{}, nil
				},
				tree,
				desired,
				lock,
				&desired.Delivery.Images[0],
				current,
				candidate,
				oldRendered,
				newRendered,
				true,
			)
			if err == nil || !strings.Contains(err.Error(), "prior rendered reference") {
				t.Fatalf("error = %v", err)
			}
			if changed || replacement != (imageReplacement{}) || resolverCalls != 0 {
				t.Fatalf("replacement = %#v, changed = %t, resolver calls = %d", replacement, changed, resolverCalls)
			}
			if !reflect.DeepEqual(*desired, originalDesired) ||
				!reflect.DeepEqual(*lock, originalLock) {
				t.Fatal("missing evidence mutated desired or lock state")
			}
			candidateGraph, graphErr := tree.CandidateData(buildGraphFile)
			if graphErr != nil {
				t.Fatalf("read candidate graph: %v", graphErr)
			}
			if !bytes.Equal(candidateGraph, graphData) {
				t.Fatalf("missing evidence mutated candidate graph:\n%s", candidateGraph)
			}
		})
	}
}

func TestReconcileImageContractRepairsPrereleaseChartMapping(t *testing.T) {
	t.Parallel()

	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "opensearch-operator",
				Version: "3.0.0-alpha",
				Target:  "registry.test/atum/opensearch-operator:3.0.0-alpha",
				VersionMapping: &config.ImageVersionMapping{
					Artifact: "chart/opensearch-operator",
					Source:   "chartAppVersion",
					Build: &config.ImageBuildVersionMapping{
						ImageRepository: "docker.io/example/operator",
						GitURL:          "https://example.test/operator.git",
						GitTagPrefix:    "v",
						GitContext:      "operator_source",
						FullTagSuffix:   "-debian13-r1",
					},
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/example/operator:3.0.0-alpha",
					},
					FullBuildTarget: "opensearch-operator",
				},
			}},
		},
	}
	contract := chartInspection{
		Name:        "opensearch-operator",
		Version:     "2.8.2",
		AppVersion:  "2.8.0",
		Images:      []string{"docker.io/example/operator:2.8.0"},
		ContractSHA: "same",
	}
	replacements, err := reconcileImageContract(
		nil, nil, nil, desired, nil, "chart/opensearch-operator",
		contract, contract, nil, false, false,
	)
	if err != nil {
		t.Fatalf("repair prerelease mapping: %v", err)
	}
	want := imageReplacement{
		Old: "registry.test/atum/opensearch-operator:3.0.0-alpha",
		New: "registry.test/atum/opensearch-operator:2.8.0",
	}
	if len(replacements) != 1 || replacements[0] != want {
		t.Fatalf("replacements = %#v, want %#v", replacements, want)
	}
}

func TestMappedOfficialSourceTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mapping config.ImageVersionMapping
		want    string
	}{
		{
			name:    "mirror only",
			mapping: config.ImageVersionMapping{TagPrefix: "v"},
			want:    "v2.8.0",
		},
		{
			name: "source build",
			mapping: config.ImageVersionMapping{
				TagPrefix: "v",
				Build: &config.ImageBuildVersionMapping{
					ImageTagPrefix: "release-",
				},
			},
			want: "release-2.8.0",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := mappedOfficialSourceTag(&test.mapping, "2.8.0"); got != test.want {
				t.Fatalf("mappedOfficialSourceTag = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMirrorOnlyPrereleaseRepairRejectsUnrelatedOfficialSource(t *testing.T) {
	t.Parallel()

	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "operator",
				Version: "3.0.0-alpha",
				Target:  "registry.test/atum/operator:v3.0.0-alpha",
				BigBangRefs: []string{
					"docker.io/example/operator:3.0.0-alpha",
				},
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "chart/operator",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: "docker.io/example/operator:unrelated",
						Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				},
			}},
			RenderedBaseline: config.RenderedBaseline{
				Entries: []config.RenderedBaselineEntry{{
					ImageID: "operator",
					Target:  "registry.test/atum/operator:v3.0.0-alpha",
				}},
			},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{{
					ImageID:     "operator",
					Replacement: "registry.test/atum/operator:v3.0.0-alpha",
					OfficialSource: &config.OfficialSource{
						Reference: "docker.io/example/operator:unrelated",
						Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				}},
			},
		},
	}
	lock := &config.Lock{
		Delivery: config.ImageLock{
			Images: []config.LockedImage{{
				ID:     "operator",
				Target: "registry.test/atum/operator:v3.0.0-alpha",
				Delivery: config.LockedDelivery{
					Type:   "mirror",
					Source: "docker.io/example/operator:unrelated",
					Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			}},
		},
	}
	originalDesired, originalLock, err := cloneState(*desired, *lock)
	if err != nil {
		t.Fatalf("clone state: %v", err)
	}
	stable := chartInspection{
		AppVersion: "2.8.0",
		Images:     []string{"docker.io/example/operator:2.8.0"},
	}
	replacement, changed, err := reconcileVersionMappedImage(
		context.Background(),
		nil,
		nil,
		desired,
		lock,
		&desired.Delivery.Images[0],
		stable,
		stable,
		"docker.io/example/operator:2.8.0",
		"docker.io/example/operator:2.8.0",
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "version mapping is stale") {
		t.Fatalf("error = %v", err)
	}
	if changed || replacement != (imageReplacement{}) {
		t.Fatalf("replacement = %#v, changed = %t", replacement, changed)
	}
	if !reflect.DeepEqual(*desired, originalDesired) || !reflect.DeepEqual(*lock, originalLock) {
		t.Fatal("stale mirror repair mutated desired or lock state")
	}
}

func TestMirrorOnlyPrereleaseRepairRecordsStableRenderedEvidence(t *testing.T) {
	t.Parallel()

	const (
		oldTarget   = "registry.test/atum/operator:v3.0.0-alpha"
		newTarget   = "registry.test/atum/operator:v2.8.0"
		oldSource   = "docker.io/example/operator:v3.0.0-alpha"
		newRendered = "docker.io/example/operator:v2.8.0"
		digest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:      "operator",
				Version: "3.0.0-alpha",
				Target:  oldTarget,
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "chart/operator",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: oldSource,
						Digest: digest,
					},
				},
			}},
			RenderedBaseline: config.RenderedBaseline{
				Entries: []config.RenderedBaselineEntry{{
					ImageID: "operator",
					Target:  oldTarget,
				}},
			},
			LegacyCrosswalk: config.LegacyCrosswalk{
				Entries: []config.LegacyCrosswalkEntry{{
					ImageID:     "operator",
					Replacement: oldTarget,
					OfficialSource: &config.OfficialSource{
						Reference: oldSource,
						Digest:    digest,
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
					Digest: digest,
				},
			}},
		},
	}
	stable := chartInspection{
		AppVersion: "2.8.0",
		Images:     []string{newRendered},
	}
	replacement, changed, err := reconcileVersionMappedImage(
		context.Background(), nil, nil, desired, lock, &desired.Delivery.Images[0],
		stable, stable, newRendered, newRendered, true,
	)
	if err != nil {
		t.Fatalf("repair mirror-only mapping: %v", err)
	}
	if !changed || replacement != (imageReplacement{Old: oldTarget, New: newTarget}) {
		t.Fatalf("replacement = %#v, changed = %t", replacement, changed)
	}
	image := desired.Delivery.Images[0]
	crosswalk := desired.Delivery.LegacyCrosswalk.Entries[0]
	locked := lock.Delivery.Images[0]
	if image.Version != "2.8.0" || image.Target != newTarget ||
		image.Delivery.Default.Source != newRendered || image.Delivery.Default.Digest != digest {
		t.Fatalf("image = %#v", image)
	}
	if !reflect.DeepEqual(image.BigBangRefs, []string{newRendered}) ||
		!reflect.DeepEqual(crosswalk.BigBangRefs, []string{newRendered}) {
		t.Fatalf("rendered evidence = %#v / %#v", image.BigBangRefs, crosswalk.BigBangRefs)
	}
	if crosswalk.Replacement != newTarget || crosswalk.OfficialSource.Reference != newRendered ||
		crosswalk.OfficialSource.Digest != digest ||
		locked.Target != newTarget || locked.Delivery.Source != newRendered ||
		locked.Delivery.Digest != digest {
		t.Fatalf("projected evidence = %#v / %#v", crosswalk, locked)
	}

	convergedDesired, convergedLock, err := cloneState(*desired, *lock)
	if err != nil {
		t.Fatalf("clone converged state: %v", err)
	}
	replacement, changed, err = reconcileVersionMappedImage(
		context.Background(), nil, nil, desired, lock, &desired.Delivery.Images[0],
		stable, stable, newRendered, newRendered, true,
	)
	if err != nil {
		t.Fatalf("reconcile unchanged mirror-only mapping: %v", err)
	}
	if changed || replacement != (imageReplacement{}) ||
		!reflect.DeepEqual(*desired, convergedDesired) ||
		!reflect.DeepEqual(*lock, convergedLock) {
		t.Fatalf("unchanged reconciliation mutated state: %#v, %t", replacement, changed)
	}
}

func TestMirrorOnlySameVersionEvidenceRolloverAndNoOp(t *testing.T) {
	t.Parallel()

	const (
		prior     = "docker.io/example/operator:2.8.0"
		candidate = "docker.io/example/operator:v2.8.0"
		target    = "registry.test/atum/operator:v2.8.0"
	)
	desired := &config.Document{
		Delivery: config.Delivery{
			Images: []config.Image{{
				ID:          "operator",
				Version:     "2.8.0",
				Target:      target,
				BigBangRefs: []string{prior},
				VersionMapping: &config.ImageVersionMapping{
					Artifact:  "chart/operator",
					Source:    "chartAppVersion",
					TagPrefix: "v",
				},
				Delivery: config.ImageDelivery{
					Default: config.DeliveryChoice{
						Type:   "mirror",
						Source: candidate,
					},
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
	lock := &config.Lock{}
	contract := chartInspection{
		AppVersion: "2.8.0",
		Images:     []string{candidate},
	}
	replacement, changed, err := reconcileVersionMappedImage(
		context.Background(), nil, nil, desired, lock, &desired.Delivery.Images[0],
		contract, contract, prior, candidate, true,
	)
	if err != nil {
		t.Fatalf("roll over mirror-only evidence: %v", err)
	}
	if changed || replacement != (imageReplacement{}) ||
		!containsString(desired.Delivery.Images[0].BigBangRefs, candidate) ||
		!containsString(desired.Delivery.LegacyCrosswalk.Entries[0].BigBangRefs, candidate) {
		t.Fatalf("evidence rollover = %#v, %#v, %t", desired.Delivery, replacement, changed)
	}
	convergedDesired, convergedLock, err := cloneState(*desired, *lock)
	if err != nil {
		t.Fatalf("clone converged state: %v", err)
	}
	replacement, changed, err = reconcileVersionMappedImage(
		context.Background(), nil, nil, desired, lock, &desired.Delivery.Images[0],
		contract, contract, candidate, candidate, true,
	)
	if err != nil {
		t.Fatalf("reconcile exact mirror-only evidence: %v", err)
	}
	if changed || replacement != (imageReplacement{}) ||
		!reflect.DeepEqual(*desired, convergedDesired) ||
		!reflect.DeepEqual(*lock, convergedLock) {
		t.Fatalf("exact mirror-only transition mutated state: %#v, %t", replacement, changed)
	}
}

func TestReconcileChartApplicationBuildConvergesPrereleaseInventory(t *testing.T) {
	t.Parallel()

	const (
		oldRevision   = "0123456789abcdef0123456789abcdef01234567"
		newRevision   = "89abcdef0123456789abcdef0123456789abcdef"
		oldTarget     = "registry.test/atum/operator:v3.0.0-alpha"
		newTarget     = "registry.test/atum/operator:v2.8.0"
		oldRendered   = "docker.io/example/operator:v3.0.0-alpha"
		newRendered   = "docker.io/example/operator:v2.8.0"
		oldSource     = "docker.io/example/operator:release-3.0.0-alpha"
		newSource     = "docker.io/example/operator:release-2.8.0"
		wrongEvidence = "docker.io/example/operator:release-2.8.0"
		graph         = `
target "operator" {
  tags = ["registry.test/atum/operator:v3.0.0-alpha-debian13-r1"]
  contexts = {
    operator_source = "https://github.com/example/operator.git?tag=v3.0.0-alpha&checksum=0123456789abcdef0123456789abcdef01234567"
  }
  args = {
    ATUM_IMAGE_VERSION = "3.0.0-alpha"
    ATUM_IMAGE_REVISION = "0123456789abcdef0123456789abcdef01234567"
  }
}
`
	)
	tests := []struct {
		name         string
		current      chartInspection
		oldChartRef  string
		candidateRef string
		priorRefs    []string
		emptyPrior   bool
	}{
		{
			name: "normal prerelease chart convergence",
			current: chartInspection{
				AppVersion: "3.0.0-alpha",
				Images:     []string{oldRendered},
			},
			oldChartRef: oldRendered,
			priorRefs:   []string{oldRendered},
		},
		{
			name: "bounded stable chart partial-state repair",
			current: chartInspection{
				AppVersion: "2.8.0",
				Images:     []string{newRendered},
			},
			oldChartRef: newRendered,
			emptyPrior:  true,
		},
		{
			name: "bounded repair through rendered runtime target",
			current: chartInspection{
				AppVersion: "2.8.0",
				Images:     []string{oldTarget},
			},
			oldChartRef:  oldTarget,
			candidateRef: oldTarget,
			emptyPrior:   true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			desired := &config.Document{
				Delivery: config.Delivery{
					Images: []config.Image{{
						ID:          "operator",
						Version:     "3.0.0-alpha",
						Target:      oldTarget,
						BigBangRefs: append([]string(nil), test.priorRefs...),
						VersionMapping: &config.ImageVersionMapping{
							Artifact:  "chart/operator",
							Source:    "chartAppVersion",
							TagPrefix: "v",
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
								Source: oldSource,
								Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							},
							FullBuildTarget: "operator",
						},
					}},
					RenderedBaseline: config.RenderedBaseline{
						Entries: []config.RenderedBaselineEntry{{
							ImageID: "operator",
							Target:  oldTarget,
						}},
					},
					LegacyCrosswalk: config.LegacyCrosswalk{
						Entries: []config.LegacyCrosswalkEntry{{
							ImageID:     "operator",
							Replacement: oldTarget,
							BigBangRefs: append([]string(nil), test.priorRefs...),
							OfficialSource: &config.OfficialSource{
								Reference: oldSource,
								Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
							Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						},
					}},
				},
			}
			if test.emptyPrior &&
				(len(desired.Delivery.Images[0].BigBangRefs) != 0 ||
					len(desired.Delivery.LegacyCrosswalk.Entries[0].BigBangRefs) != 0) {
				t.Fatal("bounded repair fixture has prior rendered evidence")
			}
			tree := newCandidateTree(".")
			graphData := []byte(graph)
			version := managedVersion{
				exists: true,
				mode:   0o644,
				digest: hashBytes(graphData),
				data:   graphData,
			}
			tree.originals[buildGraphFile] = version
			tree.candidates[buildGraphFile] = version
			resolveTag := func(_ context.Context, _, tag string) (gitcache.Release, error) {
				commit := newRevision
				if tag == "v3.0.0-alpha" {
					commit = oldRevision
				}
				return gitcache.Release{Version: tag, Commit: commit}, nil
			}
			candidate := chartInspection{
				AppVersion: "2.8.0",
				Images:     []string{newRendered},
			}
			candidateRef := test.candidateRef
			if candidateRef == "" {
				candidateRef = newRendered
			}
			replacement, changed, err := reconcileVersionMappedImageWithResolver(
				context.Background(),
				nil,
				resolveTag,
				tree,
				desired,
				lock,
				&desired.Delivery.Images[0],
				test.current,
				candidate,
				test.oldChartRef,
				candidateRef,
				true,
			)
			if err != nil {
				t.Fatalf("reconcile mapping: %v", err)
			}
			if !changed || replacement != (imageReplacement{Old: oldTarget, New: newTarget}) {
				t.Fatalf("replacement = %#v, changed = %t", replacement, changed)
			}
			image := desired.Delivery.Images[0]
			if image.Version != "2.8.0" || image.Target != newTarget ||
				image.Delivery.Default.Source != newSource {
				t.Fatalf("image = %#v", image)
			}
			if !containsString(image.BigBangRefs, newRendered) ||
				containsString(image.BigBangRefs, wrongEvidence) {
				t.Fatalf("rendered evidence = %#v", image.BigBangRefs)
			}
			crosswalkRefs := desired.Delivery.LegacyCrosswalk.Entries[0].BigBangRefs
			if !containsString(crosswalkRefs, newRendered) ||
				containsString(crosswalkRefs, wrongEvidence) {
				t.Fatalf("legacy rendered evidence = %#v", crosswalkRefs)
			}
			updatedGraph, err := tree.CandidateData(buildGraphFile)
			if err != nil {
				t.Fatalf("read candidate graph: %v", err)
			}
			if !strings.Contains(string(updatedGraph), "tag=v2.8.0&checksum="+newRevision) ||
				!strings.Contains(string(updatedGraph), "ATUM_IMAGE_REVISION") ||
				!strings.Contains(string(updatedGraph), newRevision) {
				t.Fatalf("candidate graph did not converge source tag and revision:\n%s", updatedGraph)
			}
			if desired.Delivery.RenderedBaseline.Entries[0].Target != newTarget ||
				desired.Delivery.LegacyCrosswalk.Entries[0].Replacement != newTarget ||
				desired.Delivery.LegacyCrosswalk.Entries[0].OfficialSource.Reference != newSource {
				t.Fatalf("generated evidence did not converge: %#v", desired.Delivery)
			}
			locked := lock.Delivery.Images[0]
			if locked.Target != newTarget || locked.Delivery.Source != newSource {
				t.Fatalf("locked image = %#v", locked)
			}
			if image.Delivery.Default.Digest == "" ||
				desired.Delivery.LegacyCrosswalk.Entries[0].OfficialSource.Digest == "" ||
				locked.Delivery.Digest == "" {
				t.Fatal("mirror digest evidence was discarded before refresh")
			}

			convergedDesired, convergedLock, err := cloneState(*desired, *lock)
			if err != nil {
				t.Fatalf("clone converged state: %v", err)
			}
			replacement, changed, err = reconcileVersionMappedImageWithResolver(
				context.Background(),
				nil,
				nil,
				tree,
				desired,
				lock,
				&desired.Delivery.Images[0],
				candidate,
				candidate,
				newRendered,
				newRendered,
				true,
			)
			if err != nil {
				t.Fatalf("reconcile unchanged mapping: %v", err)
			}
			if changed || replacement != (imageReplacement{}) {
				t.Fatalf("unchanged replacement = %#v, changed = %t", replacement, changed)
			}
			if !reflect.DeepEqual(*desired, convergedDesired) ||
				!reflect.DeepEqual(*lock, convergedLock) {
				t.Fatal("unchanged reconciliation mutated desired or lock state")
			}
			unchangedGraph, err := tree.CandidateData(buildGraphFile)
			if err != nil {
				t.Fatalf("read unchanged candidate graph: %v", err)
			}
			if !bytes.Equal(unchangedGraph, updatedGraph) {
				t.Fatalf("unchanged reconciliation mutated candidate graph:\n%s", unchangedGraph)
			}
		})
	}
}

func TestNormalizedMirrorDigestPreservesPinsAndSelectsManifest(t *testing.T) {
	t.Parallel()

	resolved := resolvedImageDigests{
		manifest: "sha256:manifest",
		tag:      "sha256:index",
	}
	digest, err := normalizedMirrorDigest("sha256:index", resolved)
	if err != nil || digest != "sha256:manifest" {
		t.Fatalf("normalized digest = %q, %v", digest, err)
	}
	digest, err = normalizedMirrorDigest("", resolved)
	if err != nil || digest != "sha256:manifest" {
		t.Fatalf("new-source digest = %q, %v", digest, err)
	}
	if _, err := normalizedMirrorDigest("sha256:other", resolved); err == nil {
		t.Fatal("mismatched pinned root was accepted")
	}
}
