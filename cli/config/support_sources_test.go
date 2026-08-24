package config

import (
	"strings"
	"testing"
)

func TestRepositoryInventoryIncludesResolvedSupportInStableOrder(t *testing.T) {
	t.Parallel()

	source := func(version, commit string) GitSource {
		return GitSource{
			URL: "https://example.test/source.git", Version: version,
			Branch: "main", Commit: commit,
		}
	}
	desired := Document{Platform: Platform{
		BigBang: source("3.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Flux:    source("2.0.0", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Packages: []Package{{
			ID: "z-package", Source: source("1.0.0", "cccccccccccccccccccccccccccccccccccccccc"),
		}},
	}}
	resolved := Resolved{SupportSources: []SupportSource{{
		ID: "wrapper", Source: source("0.4.15", "dddddddddddddddddddddddddddddddddddddddd"),
	}}}
	inventory, err := RepositoryInventory(desired, resolved)
	if err != nil {
		t.Fatalf("repository inventory: %v", err)
	}
	want := []string{"bigbang", "flux", "wrapper", "z-package"}
	if len(inventory) != len(want) {
		t.Fatalf("repository count = %d, want %d", len(inventory), len(want))
	}
	for i := range want {
		if inventory[i].ID != want[i] {
			t.Fatalf("repository %d = %q, want %q", i, inventory[i].ID, want[i])
		}
	}
	if inventory[2].CacheKey != "support-wrapper" {
		t.Fatalf("wrapper cache key = %q", inventory[2].CacheKey)
	}
}

func TestRepositoryInventoryRejectsSupportCollision(t *testing.T) {
	t.Parallel()

	desired := Document{Platform: Platform{
		BigBang: GitSource{}, Flux: GitSource{},
		Packages: []Package{{ID: "wrapper"}},
	}}
	_, err := RepositoryInventory(desired, Resolved{
		SupportSources: []SupportSource{{ID: "wrapper"}},
	})
	if err == nil {
		t.Fatal("duplicate package and support source ID was accepted")
	}
}

func TestRepositoryInventoryKeepsPostgreSQLAndWrapperIdentitiesDistinct(t *testing.T) {
	t.Parallel()

	wrapper := GitSource{
		URL: "https://repo1.dso.mil/big-bang/product/packages/wrapper.git",
		Version: "0.4.15", Branch: "main",
		Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	inventory, err := RepositoryInventory(Document{Platform: Platform{
		Packages: []Package{{ID: "postgresql", Source: wrapper}},
	}}, Resolved{SupportSources: []SupportSource{{ID: "wrapper", Source: wrapper}}})
	if err != nil {
		t.Fatalf("repository inventory: %v", err)
	}
	found := make(map[string]string)
	for _, source := range inventory {
		found[source.ID] = source.CacheKey
	}
	if found["postgresql"] != "package-postgresql" || found["wrapper"] != "support-wrapper" {
		t.Fatalf("distinct wrapper-backed identities = %#v", found)
	}
}

func TestPackageSelectionOwnsIntegratedAndGenericInventory(t *testing.T) {
	t.Parallel()

	operational := map[string]any{
		"integrated": map[string]any{
			"enabled": true, "sourceType": "git",
			"atum": map[string]any{
				"id": "integrated", "fluxName": "integrated",
				"license": "Apache-2.0", "integration": "integrated",
			},
			"git": map[string]any{},
			"values": map[string]any{"atum": map[string]any{
				"id": "application-owned", "license": "application-owned",
				"integration": "application-owned",
			}, "nestedSourceLookalike": map[string]any{
				"enabled": true, "sourceType": "git",
			}},
		},
		"packages": map[string]any{"generic": map[string]any{
			"enabled": true, "sourceType": "git",
			"atum": map[string]any{
				"id": "generic", "fluxName": "generic",
				"license": "MIT", "integration": "generic",
				"source": map[string]any{
					"repo": "https://example.test/generic.git",
					"tag": "1.2.3", "path": "deploy/chart",
				},
			},
			"git": map[string]any{},
		}},
		"disabled": map[string]any{
			"enabled": false, "sourceType": "git",
			"atum": map[string]any{
				"id": "disabled", "fluxName": "disabled",
				"license": "MIT", "integration": "generic",
				"source": map[string]any{
					"repo": "https://example.test/disabled.git",
					"tag": "1.0.0", "path": "chart",
				},
			},
			"values": map[string]any{"atum": map[string]any{
				"id": "application-owned",
			}},
		},
	}
	defaults := map[string]any{"integrated": map[string]any{"git": map[string]any{
		"repo": "https://example.test/integrated.git", "tag": "2.0.0", "path": "./chart",
	}}}
	packages, err := PackageSelection(operational, defaults)
	if err != nil {
		t.Fatalf("derive package selection: %v", err)
	}
	if len(packages) != 2 || packages[0].ID != "generic" || packages[1].ID != "integrated" {
		t.Fatalf("package selection = %#v", packages)
	}
	if packages[0].Integration != "generic" || packages[0].ChartPath != "deploy/chart" ||
		packages[0].Source.Version != "1.2.3" {
		t.Fatalf("generic package = %#v", packages[0])
	}
	if packages[1].Integration != "integrated" ||
		packages[1].Source.URL != "https://example.test/integrated.git" {
		t.Fatalf("integrated package = %#v", packages[1])
	}

	rendered, err := StripPackageSelectionMetadata(operational, nil)
	if err != nil {
		t.Fatalf("strip package selection metadata: %v", err)
	}
	if _, leaked := rendered["integrated"].(map[string]any)["atum"]; leaked {
		t.Fatal("Atum package metadata crossed the render boundary")
	}
	disabledRendered := rendered["disabled"].(map[string]any)
	if _, leaked := disabledRendered["atum"]; leaked {
		t.Fatal("disabled Atum package metadata crossed the render boundary")
	}
	if _, preserved := disabledRendered["values"].(map[string]any)["atum"]; !preserved {
		t.Fatal("disabled package nested chart-owned Atum values were removed")
	}
	nested := rendered["integrated"].(map[string]any)["values"].(map[string]any)
	if _, preserved := nested["atum"]; !preserved {
		t.Fatal("nested chart value resembling selection metadata was removed")
	}
	if _, retained := operational["integrated"].(map[string]any)["atum"]; !retained {
		t.Fatal("render-boundary stripping mutated operational authority")
	}
	if err := ValidatePackageSelectionCoverage(operational, nil, packages, nil); err != nil {
		t.Fatalf("nested chart source lookalike escaped declaration boundary: %v", err)
	}
	current, err := CurrentPackageSelectionValues(
		operational, nil, []Package{{ID: "integrated"}},
	)
	if err != nil {
		t.Fatalf("project current package selection values: %v", err)
	}
	if enabled, _ := current["packages"].(map[string]any)["generic"].(map[string]any)["enabled"].(bool); enabled {
		t.Fatal("candidate-only generic package remained enabled in the historical render")
	}
	nested = current["integrated"].(map[string]any)["values"].(map[string]any)
	if _, preserved := nested["atum"]; !preserved {
		t.Fatal("historical projection removed nested chart-owned Atum values")
	}
	disabledCurrent := current["disabled"].(map[string]any)
	if _, leaked := disabledCurrent["atum"]; leaked {
		t.Fatal("disabled Atum package metadata crossed the historical render boundary")
	}
	if _, preserved := disabledCurrent["values"].(map[string]any)["atum"]; !preserved {
		t.Fatal("historical projection removed disabled nested chart-owned Atum values")
	}
}

func TestPackageSelectionRejectsMissingMetadataAndRepositoryCollision(t *testing.T) {
	t.Parallel()

	missing := map[string]any{"package": map[string]any{
		"enabled": true, "sourceType": "git",
	}}
	if _, err := PackageSelection(missing, nil); err == nil {
		t.Fatal("enabled Git package without selection metadata was accepted")
	}
	declaration := func(id string) map[string]any {
		return map[string]any{
			"enabled": true, "sourceType": "git",
			"atum": map[string]any{
				"id": id, "fluxName": id, "license": "MIT", "integration": "generic",
				"source": map[string]any{
					"repo": "https://example.test/shared.git", "tag": "1.0.0", "path": "chart",
				},
			},
		}
	}
	if _, err := PackageSelection(map[string]any{
		"first": declaration("first"), "second": declaration("second"),
	}, nil); err == nil {
		t.Fatal("duplicate package repository declaration was accepted")
	}
	moving := declaration("moving")
	moving["atum"].(map[string]any)["source"].(map[string]any)["repo"] =
		"https://example.test/moving.git"
	moving["atum"].(map[string]any)["source"].(map[string]any)["tag"] = "latest"
	if _, err := PackageSelection(map[string]any{"moving": moving}, nil); err == nil {
		t.Fatal("non-semantic generic package tag was accepted")
	}
}

func TestPackageDeclarationControlsAreStrictAcrossEveryProjection(t *testing.T) {
	t.Parallel()

	for name, declaration := range map[string]map[string]any{
		"enabled": {
			"enabled": "true", "sourceType": "git",
			"atum": map[string]any{"id": "malformed"},
		},
		"source type": {
			"enabled": true, "sourceType": 7,
			"atum": map[string]any{"id": "malformed"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := map[string]any{"packages": map[string]any{"malformed": declaration}}
			if _, err := PackageSelection(values, nil); err == nil {
				t.Fatal("malformed declaration bypassed package selection")
			}
			if err := ValidatePackageSelectionCoverage(values, nil, nil, nil); err == nil {
				t.Fatal("malformed declaration bypassed package coverage")
			}
			if _, err := StripPackageSelectionMetadata(values, nil); err == nil {
				t.Fatal("malformed declaration crossed the render projection")
			}
			if _, err := CurrentPackageSelectionValues(values, nil, nil); err == nil {
				t.Fatal("malformed declaration crossed the historical render projection")
			}
		})
	}

	nonDeclaration := map[string]any{
		"networkPolicies": map[string]any{
			"enabled": true,
			"atum":    map[string]any{"application-owned": "network-policy"},
		},
		"istio": map[string]any{"ambient": map[string]any{
			"enabled": true,
			"atum":    map[string]any{"application-owned": "ambient"},
		}},
		"wrapper": map[string]any{
			"sourceType": "git",
			"atum":       map[string]any{"application-owned": "wrapper"},
		},
	}
	if packages, err := PackageSelection(nonDeclaration, nil); err != nil || len(packages) != 0 {
		t.Fatalf("ordinary one-control chart values selected packages %#v: %v", packages, err)
	}
	if err := ValidatePackageSelectionCoverage(nonDeclaration, nil, nil, nil); err != nil {
		t.Fatalf("ordinary one-control chart values failed coverage: %v", err)
	}
	projected, err := StripPackageSelectionMetadata(nonDeclaration, nil)
	if err != nil {
		t.Fatalf("one-control-key chart values were classified as a declaration: %v", err)
	}
	current, err := CurrentPackageSelectionValues(nonDeclaration, nil, nil)
	if err != nil {
		t.Fatalf("one-control-key chart values failed historical projection: %v", err)
	}
	paths := [][]string{
		{"networkPolicies"},
		{"istio", "ambient"},
		{"wrapper"},
	}
	for _, path := range paths {
		for _, values := range []map[string]any{projected, current} {
			node := values
			for _, component := range path {
				node = node[component].(map[string]any)
			}
			if _, retained := node["atum"]; !retained {
				t.Fatalf("one-control-key chart-owned Atum values at %s were removed", strings.Join(path, "."))
			}
		}
	}
}

func TestSourceCoverageRequiresEveryEnabledHelmRepositoryDeclaration(t *testing.T) {
	t.Parallel()

	values := map[string]any{"packages": map[string]any{
		"tracked": map[string]any{
			"enabled": true, "sourceType": "helmRepo",
			"values": map[string]any{"lookalike": map[string]any{
				"enabled": true, "sourceType": "helmRepo",
			}},
		},
	}}
	if err := ValidatePackageSelectionCoverage(values, nil, nil, nil); err == nil {
		t.Fatal("enabled HelmRepository declaration without a tracked chart was accepted")
	}
	chart := TrackedChart{ID: "tracked", ValuesPath: "packages.tracked"}
	if err := ValidatePackageSelectionCoverage(values, nil, nil, []TrackedChart{chart}); err != nil {
		t.Fatalf("tracked HelmRepository coverage: %v", err)
	}
	if err := ValidatePackageSelectionCoverage(
		values,
		nil,
		[]Package{{ID: "wrong-kind", ValuesPath: chart.ValuesPath}},
		nil,
	); err == nil {
		t.Fatal("HelmRepository declaration materialized as a Git package was accepted")
	}
	if err := ValidatePackageSelectionCoverage(
		values, nil, nil, []TrackedChart{chart, chart},
	); err == nil {
		t.Fatal("duplicate tracked-chart values path was accepted")
	}
}

func TestPackageSelectionSeparatesRepositoryAndRenderedFluxIdentity(t *testing.T) {
	t.Parallel()

	operational := map[string]any{"fluentbit": map[string]any{
		"enabled": true, "sourceType": "git",
		"atum": map[string]any{
			"id": "fluent-bit", "fluxName": "fluentbit",
			"license": "Apache-2.0", "integration": "integrated",
		},
	}}
	defaults := map[string]any{"fluentbit": map[string]any{"git": map[string]any{
		"repo": "https://example.test/fluent-bit.git",
		"tag": "0.57.9-bb.0", "path": "chart",
	}}}
	packages, err := PackageSelection(operational, defaults)
	if err != nil {
		t.Fatalf("select Fluent Bit package: %v", err)
	}
	if len(packages) != 1 || packages[0].ID != "fluent-bit" ||
		packages[0].FluxName != "fluentbit" {
		t.Fatalf("Fluent Bit identities = %#v", packages)
	}

	generic := map[string]any{"packages": map[string]any{"CamelCase": map[string]any{
		"enabled": true, "sourceType": "git",
		"atum": map[string]any{
			"id": "camel-case", "fluxName": "not-camel-case",
			"license": "MIT", "integration": "generic",
			"source": map[string]any{
				"repo": "https://example.test/camel-case.git",
				"tag": "1.0.0", "path": "chart",
			},
		},
	}}}
	if _, err := PackageSelection(generic, nil); err == nil {
		t.Fatal("generic package with a non-rendered Flux identity was accepted")
	}

	for valuesKey, identity := range map[string]string{
		"istioCRDs": "istio-crds", "kyvernoReporter": "kyverno-reporter",
		"prometheusOperatorCRDs": "prometheus-operator-crds",
	} {
		operational := map[string]any{valuesKey: map[string]any{
			"enabled": true, "sourceType": "git",
			"atum": map[string]any{
				"id": identity, "fluxName": identity,
				"license": "Apache-2.0", "integration": "integrated",
			},
		}}
		defaults := map[string]any{valuesKey: map[string]any{"git": map[string]any{
			"repo": "https://example.test/" + identity + ".git",
			"tag": "1.0.0-bb.0", "path": "chart",
		}}}
		selected, err := PackageSelection(operational, defaults)
		if err != nil || len(selected) != 1 || selected[0].FluxName != identity {
			t.Fatalf("CamelCase package %s projection = %#v, error %v", valuesKey, selected, err)
		}
	}
}

func TestPackageSelectionUsesTemplateEffectiveDirectDefaults(t *testing.T) {
	t.Parallel()

	operational := map[string]any{"packages": map[string]any{
		"garage": map[string]any{"atum": map[string]any{
			"id": "garage", "fluxName": "garage", "license": "AGPL-3.0",
			"integration": "generic",
			"source": map[string]any{
				"repo": "https://example.test/garage.git",
				"tag": "1.2.3", "path": "chart",
			},
		}},
	}}
	packages, err := PackageSelection(operational, nil)
	if err != nil || len(packages) != 1 || packages[0].ID != "garage" {
		t.Fatalf("template-defaulted direct package = %#v, error %v", packages, err)
	}
	if err := ValidatePackageSelectionCoverage(operational, nil, packages, nil); err != nil {
		t.Fatalf("template-defaulted package coverage: %v", err)
	}
	rendered, err := StripPackageSelectionMetadata(operational, nil)
	if err != nil {
		t.Fatalf("strip template-defaulted package metadata: %v", err)
	}
	garage := rendered["packages"].(map[string]any)["garage"].(map[string]any)
	if _, found := garage["atum"]; found {
		t.Fatal("template-defaulted package retained Atum metadata")
	}
}

func TestPackageSelectionUsesIntegratedDefaultControlsAndCoordinates(t *testing.T) {
	t.Parallel()

	operational := map[string]any{"loki": map[string]any{
		"enabled": true,
		"atum": map[string]any{
			"id": "loki", "fluxName": "loki", "license": "AGPL-3.0",
			"integration": "integrated",
		},
	}}
	defaults := map[string]any{"loki": map[string]any{
		"sourceType": "git",
		"git": map[string]any{
			"repo": "https://example.test/loki.git",
			"tag": "6.30.1", "path": "chart",
		},
	}}
	packages, err := PackageSelection(operational, defaults)
	if err != nil || len(packages) != 1 || packages[0].Source.Version != "6.30.1" {
		t.Fatalf("default-controlled integrated package = %#v, error %v", packages, err)
	}
}

func TestPackageSelectionRejectsUnmaterializedDefaultAndGenericKustomization(t *testing.T) {
	t.Parallel()

	defaultOnly := map[string]any{"loki": map[string]any{
		"enabled": true, "sourceType": "git",
	}}
	if _, err := PackageSelection(nil, defaultOnly); err == nil {
		t.Fatal("enabled default-only Git declaration was omitted from admission")
	}
	kustomization := map[string]any{"packages": map[string]any{
		"raw": map[string]any{
			"kustomize": true,
			"atum": map[string]any{
				"id": "raw", "fluxName": "raw", "license": "MIT",
				"integration": "generic",
				"source": map[string]any{
					"repo": "https://example.test/raw.git",
					"tag": "1.0.0", "path": "chart",
				},
			},
		},
	}}
	if _, err := PackageSelection(kustomization, nil); err == nil {
		t.Fatal("generic Kustomization declaration was accepted as a Helm package")
	}
}

func TestPackageSelectionUsesStrictCanonicalSourceCoordinates(t *testing.T) {
	t.Parallel()

	integrated := map[string]any{"integrated": map[string]any{
		"enabled": true, "sourceType": "git",
		"atum": map[string]any{
			"id": "integrated", "fluxName": "integrated",
			"license": "Apache-2.0", "integration": "integrated",
		},
	}}
	latest := map[string]any{"integrated": map[string]any{"git": map[string]any{
		"repo": "https://example.test/integrated.git", "tag": "latest", "path": "chart",
	}}}
	if _, err := PackageSelection(integrated, latest); err == nil {
		t.Fatal("integrated moving tag was accepted")
	}

	genericDeclaration := func(id, repository string, chartPath any) map[string]any {
		return map[string]any{
			"enabled": true, "sourceType": "git",
			"atum": map[string]any{
				"id": id, "fluxName": id, "license": "MIT", "integration": "generic",
				"source": map[string]any{
					"repo": repository, "tag": "1.0.0", "path": chartPath,
				},
			},
		}
	}
	if _, err := PackageSelection(map[string]any{
		"invalid": genericDeclaration("invalid", "https://example.test/invalid.git", 7),
	}, nil); err == nil {
		t.Fatal("non-string generic chart path was accepted")
	}
	emptyQuery := "https://example.test/empty-query.git?"
	if _, err := CanonicalPackageRepositoryURL(emptyQuery); err == nil {
		t.Fatal("repository URL with an explicit empty query was canonicalized")
	}
	if _, err := PackageSelection(map[string]any{
		"empty-query": genericDeclaration("empty-query", emptyQuery, "chart"),
	}, nil); err == nil {
		t.Fatal("generic repository URL with an explicit empty query was selected")
	}
	if _, err := PackageSelection(map[string]any{
		"first": genericDeclaration("first", "https://example.test/Shared.git/", "chart"),
		"second": genericDeclaration("second", "https://example.test/Shared", "chart"),
	}, nil); err == nil {
		t.Fatal("slash-equivalent duplicate repository declarations were accepted")
	}
	first, err := CanonicalPackageRepositoryURL("HTTPS://EXAMPLE.TEST/CaseSensitive.git/")
	if err != nil {
		t.Fatalf("canonical repository URL: %v", err)
	}
	second, err := CanonicalPackageRepositoryURL("https://example.test/CaseSensitive")
	if err != nil || first != second {
		t.Fatalf("equivalent repository URLs = %q and %q, error %v", first, second, err)
	}
	differentCase, err := CanonicalPackageRepositoryURL("https://example.test/casesensitive")
	if err != nil || first == differentCase {
		t.Fatalf("case-sensitive repository paths were conflated: %q and %q", first, differentCase)
	}
}

func TestRenderedGenericSourceReferenceOwnsNamespaceAndCollisionAdmission(t *testing.T) {
	t.Parallel()

	pkg := Package{
		ID: "foo-package", ValuesPath: "packages.Foo",
		Integration: "generic", FluxName: "foo",
	}
	reference, err := RenderedPackageSourceReference(pkg, map[string]any{
		"namespace": map[string]any{"name": "target"},
		"helmRelease": map[string]any{"namespace": "reconciliation"},
	})
	if err != nil || reference != (PackageSourceReference{Name: "foo", Namespace: "reconciliation"}) {
		t.Fatalf("generic source namespace precedence = %#v, error %v", reference, err)
	}
	reference, err = RenderedPackageSourceReference(pkg, map[string]any{
		"namespace": map[string]any{"name": "target"},
	})
	if err != nil || reference.Namespace != "target" {
		t.Fatalf("generic target namespace projection = %#v, error %v", reference, err)
	}
	reference, err = RenderedPackageSourceReference(pkg, map[string]any{
		"namespace":   map[string]any{"name": ""},
		"helmRelease": map[string]any{"namespace": ""},
	})
	if err != nil || reference.Namespace != "foo" {
		t.Fatalf("generic empty namespace fallback = %#v, error %v", reference, err)
	}

	declaration := func(id, key, repository string, namespace map[string]any) (string, map[string]any) {
		return key, map[string]any{
			"enabled": true, "sourceType": "git", "namespace": namespace,
			"atum": map[string]any{
				"id": id, "fluxName": "foo", "license": "MIT", "integration": "generic",
				"source": map[string]any{
					"repo": repository, "tag": "1.0.0", "path": "chart",
				},
			},
		}
	}
	firstKey, first := declaration(
		"foo-upper", "Foo", "https://example.test/foo-upper.git", nil,
	)
	secondKey, second := declaration(
		"foo-lower", "foo", "https://example.test/foo-lower.git", nil,
	)
	values := map[string]any{"packages": map[string]any{
		firstKey: first, secondKey: second,
	}}
	selected, err := PackageSelection(values, nil)
	if err != nil {
		t.Fatalf("select collision fixture: %v", err)
	}
	if err := ValidateRenderedSourceReferences(values, selected, nil); err == nil {
		t.Fatal("duplicate rendered generic GitRepository identity was accepted")
	}
	second["namespace"] = map[string]any{"name": "other"}
	if err := ValidateRenderedSourceReferences(values, selected, nil); err != nil {
		t.Fatalf("disjoint generic source namespaces collided: %v", err)
	}

	wrapperCollision := Package{
		ID: "generic-wrapper-collision", ValuesPath: "packages.bigbang-wrapper",
		Integration: "generic", FluxName: "bigbang-wrapper",
	}
	collisionValues := map[string]any{"packages": map[string]any{
		"bigbang-wrapper": map[string]any{
			"helmRelease": map[string]any{"namespace": "bigbang"},
		},
	}}
	if err := ValidateRenderedSourceReferences(
		collisionValues,
		[]Package{wrapperCollision},
		[]RenderedSourceObligation{{
			Owner: "Big Bang shared wrapper source",
			Reference: BigBangWrapperSourceReference(),
		}},
	); err == nil {
		t.Fatal("generic package collision with the shared wrapper GitRepository was accepted")
	}
	collisionValues["packages"].(map[string]any)["bigbang-wrapper"].(map[string]any)["helmRelease"] =
		map[string]any{"namespace": "generic"}
	if err := ValidateRenderedSourceReferences(
		collisionValues,
		[]Package{wrapperCollision},
		[]RenderedSourceObligation{{
			Owner: "Big Bang shared wrapper source",
			Reference: BigBangWrapperSourceReference(),
		}},
	); err != nil {
		t.Fatalf("disjoint generic and wrapper GitRepositories collided: %v", err)
	}
}

func TestActiveWrapperConsumersUnifiesPackagesAndTrackedCharts(t *testing.T) {
	t.Parallel()

	platform := Platform{
		Packages: []Package{
			{ID: "git-package", ValuesPath: "packages.GitPackage"},
			{ID: "ignored", ValuesPath: "addons.ignored"},
		},
		Charts: []TrackedChart{
			{ID: "opensearch", ValuesPath: "packages.opensearch"},
			{ID: "disabled", ValuesPath: "packages.disabled"},
		},
	}
	values := map[string]any{"packages": map[string]any{
		"opensearch": map[string]any{
			"namespace": map[string]any{"name": "search"},
			"wrapper":   map[string]any{"enabled": true},
		},
		"disabled": map[string]any{
			"enabled": false, "wrapper": map[string]any{"enabled": true},
		},
		"GitPackage": map[string]any{
			"helmRelease": map[string]any{"namespace": "addons-system"},
			"wrapper":     map[string]any{"enabled": true},
		},
	}, "addons": map[string]any{
		"ignored": map[string]any{
			"wrapper": map[string]any{"enabled": true},
		},
	}}
	consumers, err := ActiveWrapperConsumers(platform, values)
	if err != nil {
		t.Fatalf("active wrapper consumers: %v", err)
	}
	if len(consumers) != 2 {
		t.Fatalf("active consumer count = %d, want 2", len(consumers))
	}
	byOwner := make(map[string]WrapperConsumer, len(consumers))
	for _, consumer := range consumers {
		byOwner[consumer.OwnerID] = consumer
	}
	if got := byOwner["opensearch"]; got.PackageKey != "opensearch" ||
		got.ReleaseName != "opensearch-wrapper" || got.Namespace != "search" {
		t.Fatalf("tracked chart wrapper consumer = %#v", got)
	}
	if got := byOwner["git-package"]; got.ReleaseName != "git-package-wrapper" ||
		got.PackageKey != "git-package" || got.Namespace != "addons-system" {
		t.Fatalf("Git package wrapper consumer = %#v", got)
	}
	if _, exists := byOwner["ignored"]; exists {
		t.Fatal("wrapper-shaped values outside .Values.packages created a consumer")
	}
}

func TestActiveWrapperConsumersRejectsOnlyActualResourceCollisions(t *testing.T) {
	t.Parallel()

	outside := map[string]any{
		"TopLevel": map[string]any{"wrapper": map[string]any{"enabled": true}},
		"addons": map[string]any{"ignored": map[string]any{
			"wrapper": map[string]any{"enabled": true},
		}},
	}
	consumers, err := ActiveWrapperConsumers(
		Platform{Packages: []Package{{ID: "ignored", ValuesPath: "addons.ignored"}}},
		outside,
	)
	if err != nil || len(consumers) != 0 {
		t.Fatalf("wrapper-shaped values outside packages projected %#v, error %v", consumers, err)
	}

	undeclared := map[string]any{"packages": map[string]any{
		"unknown": map[string]any{"wrapper": map[string]any{"enabled": true}},
	}}
	if _, err := ActiveWrapperConsumers(Platform{}, undeclared); err == nil {
		t.Fatal("undeclared wrapper consumer was accepted")
	}

	platform := Platform{
		Packages: []Package{{ID: "first", ValuesPath: "packages.MyApp"}},
		Charts:   []TrackedChart{{ID: "second", ValuesPath: "packages.my-app"}},
	}
	disjoint := map[string]any{"packages": map[string]any{
		"MyApp": map[string]any{
			"wrapper": map[string]any{"enabled": true},
		},
		"my-app": map[string]any{
			"namespace": map[string]any{"name": "different"},
			"wrapper":   map[string]any{"enabled": true},
		},
	}}
	consumers, err = ActiveWrapperConsumers(platform, disjoint)
	if err != nil || len(consumers) != 2 ||
		consumers[0].ReleaseKey() == consumers[1].ReleaseKey() {
		t.Fatalf("disjoint same-name wrapper resources = %#v, error %v", consumers, err)
	}
	disjoint["packages"].(map[string]any)["MyApp"].(map[string]any)["namespace"] =
		map[string]any{"name": "different"}
	if _, err := ActiveWrapperConsumers(platform, disjoint); err == nil {
		t.Fatal("colliding namespace-qualified wrapper release was accepted")
	}
}

func TestActiveWrapperConsumersRejectsOrdinaryReleaseCollision(t *testing.T) {
	t.Parallel()

	platform := Platform{Packages: []Package{
		{ID: "foo", ValuesPath: "packages.foo"},
		{ID: "foo-wrapper", ValuesPath: "packages.foo-wrapper"},
	}}
	values := map[string]any{"packages": map[string]any{
		"foo": map[string]any{
			"enabled": true,
			"wrapper": map[string]any{"enabled": true},
		},
		"foo-wrapper": map[string]any{
			"enabled":   true,
			"sourceType": "helmRepo",
			"namespace": map[string]any{"name": "foo"},
		},
	}}
	if _, err := ActiveWrapperConsumers(platform, values); err == nil {
		t.Fatal("wrapper and ordinary package HelmRelease collision was accepted")
	}
	values["packages"].(map[string]any)["foo-wrapper"].(map[string]any)["namespace"] =
		map[string]any{"name": "other"}
	consumers, err := ActiveWrapperConsumers(platform, values)
	if err != nil || len(consumers) != 1 || consumers[0].ReleaseKey() != "foo/foo-wrapper" {
		t.Fatalf("disjoint ordinary and wrapper releases = %#v, error %v", consumers, err)
	}

	values["packages"].(map[string]any)["foo-wrapper"].(map[string]any)["namespace"] =
		map[string]any{"name": "foo"}
	values["packages"].(map[string]any)["foo-wrapper"].(map[string]any)["kustomize"] =
		map[string]any{"path": "overlay"}
	if _, err := ActiveWrapperConsumers(platform, values); err != nil {
		t.Fatalf("kustomize-owned package was admitted as an ordinary HelmRelease: %v", err)
	}
}

func TestWrapperSourceRequirementIsIndependentFromConsumerMembership(t *testing.T) {
	t.Parallel()

	defaults := map[string]any{"wrapper": map[string]any{
		"sourceType": "git",
		"git": map[string]any{
			"repo": "https://example.test/wrapper.git",
			"tag": "0.4.15", "path": "chart",
		},
	}}
	effective := cloneSelectionValue(defaults).(map[string]any)
	effective["packages"] = map[string]any{
		"garage": map[string]any{"enabled": true},
	}
	requirement, err := BigBangWrapperSourceRequirement(defaults, effective, nil)
	if err != nil || !requirement.Required ||
		requirement.Declaration.Tag != "0.4.15" {
		t.Fatalf("consumer-independent wrapper source requirement = %#v, error %v",
			requirement, err)
	}

	effective["wrapper"].(map[string]any)["sourceType"] = "helmRepo"
	if _, err := WrapperSourceRequired(
		effective, []WrapperConsumer{{OwnerID: "garage"}},
	); err == nil {
		t.Fatal("active wrapper consumer with a non-Git wrapper source was accepted")
	}
}

func TestBigBangPackageIdentityMatchesResourceNameContract(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"OpenSearch":  "open-search",
		"HTTPServer":  "http-server",
		"GO_PATH":     "go-path",
		"-Leading":    "leading",
		"punct.value": "punct-value",
	}
	for input, expected := range tests {
		actual, err := bigBangPackageIdentity(input)
		if err != nil {
			t.Fatalf("render package identity %q: %v", input, err)
		}
		if actual != expected {
			t.Fatalf("package identity %q = %q, want %q", input, actual, expected)
		}
	}
	long, err := bigBangPackageIdentity(strings.Repeat("A", 70))
	if err != nil || long != strings.Repeat("a", 63) {
		t.Fatalf("truncated package identity = %q, error %v", long, err)
	}
	longKey := strings.Repeat("A", 70)
	if _, err := ActiveWrapperConsumers(
		Platform{Charts: []TrackedChart{{ID: "long", ValuesPath: "packages." + longKey}}},
		map[string]any{"packages": map[string]any{
			longKey: map[string]any{"wrapper": map[string]any{"enabled": true}},
		}},
	); err == nil {
		t.Fatal("Big Bang identity producing an invalid wrapper release name was accepted")
	}
}

func TestValidateWrapperSupportSourceRequiresImmutableHTTPSIdentity(t *testing.T) {
	t.Parallel()

	valid := SupportSource{
		ID: "wrapper", ValuesPath: "wrapper", ChartPath: "chart",
		Source: GitSource{
			URL: "https://repo.example/wrapper.git", Version: "0.4.15",
			Branch: "main", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	if err := ValidateWrapperSupportSource(valid); err != nil {
		t.Fatalf("valid wrapper support source: %v", err)
	}
	cases := []SupportSource{valid, valid, valid, valid}
	cases[0].Source.URL = "ssh://repo.example/wrapper.git"
	cases[1].Source.Branch = ""
	cases[2].Source.Commit = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases[3].Source.Patches = []string{"patch.diff"}
	for index, source := range cases {
		if err := ValidateWrapperSupportSource(source); err == nil {
			t.Fatalf("invalid wrapper support source %d was accepted", index)
		}
	}
}

func TestStaleLockAllowsMissingSupportProjection(t *testing.T) {
	t.Parallel()

	var problems []string
	validateSupportSources(&problems, &Project{}, true, nil)
	if len(problems) != 0 {
		t.Fatalf("stale support projection problems = %#v", problems)
	}
}

func TestCurrentStateValidatesExactWrapperProjection(t *testing.T) {
	t.Parallel()

	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	project := &Project{
		Root: ".",
		Desired: Document{
			Infrastructure: Infrastructure{
				Active: "local",
				Targets: map[string]InfrastructureTarget{
					"local": {PlatformProfile: "local"},
				},
			},
			Platform: Platform{
				Sources: SourceRegistry{
					ClusterURL: "http://forgejo", UpstreamOrganization: "atum-upstreams",
				},
				Charts: []TrackedChart{{ID: "opensearch", ValuesPath: "packages.opensearch"}},
				Values: PlatformValues{
					Operational: "operational.yaml", Generated: "generated.yaml",
					Profiles: map[string]string{"local": "profile.yaml"},
				},
			},
		},
		Lock: Lock{Resolved: Resolved{SupportSources: []SupportSource{{
			ID: "wrapper", ValuesPath: "wrapper", ChartPath: "chart",
			Source: GitSource{
				URL: "https://repo.example/wrapper.git", Version: "0.4.15",
				Branch: "main", Commit: commit,
			},
		}}}},
	}
	files := map[string][]byte{
		"operational.yaml": []byte(`
wrapper:
  sourceType: git
packages:
  opensearch:
    wrapper:
      enabled: true
`),
		"generated.yaml": []byte(`
wrapper:
  git:
    repo: http://forgejo/atum-upstreams/wrapper.git
    tag: ""
    semver: 0.4.15
    branch: main
    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    path: chart
`),
		"profile.yaml": []byte("{}\n"),
	}
	var problems []string
	validateSupportSources(&problems, project, false, files)
	if len(problems) != 0 {
		t.Fatalf("valid current wrapper projection problems = %#v", problems)
	}
	files["generated.yaml"] = []byte(`
wrapper:
  git:
    repo: http://forgejo/atum-upstreams/wrapper.git
    tag: ""
    semver: 0.4.15
    branch: main
    commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    path: chart
`)
	problems = nil
	validateSupportSources(&problems, project, false, files)
	if len(problems) == 0 {
		t.Fatal("mismatched generated wrapper projection was accepted")
	}
}
