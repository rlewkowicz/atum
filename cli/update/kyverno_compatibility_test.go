package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestKyvernoWebhookCleanupUsesDeclaredReadinessChecker(t *testing.T) {
	t.Parallel()

	observation := renderedImageObservation{
		artifact:  kyvernoArtifact,
		reference: kyvernoWebhookCleanupRepository + ":v1.35.7",
		inspection: chartInspection{Declared: []string{
			kyvernoReadinessCheckerRepository + ":v1.18.2",
		}},
		invocations: []containerInvocation{
			{Location: "pre-delete-remove-webhooks", Args: []any{"delete-webhooks"}},
			{Location: "pre-delete-scale-to-zero", Args: []any{"scale-deploy"}},
		},
	}
	spec, err := officialImageForObservation(
		observation,
		"1.35.4",
		nil,
		"docker.io/library/debian:13-slim",
	)
	if err != nil {
		t.Fatal(err)
	}
	if spec.id != "kyverno-readiness-checker" ||
		spec.source != "ghcr.io/kyverno/readiness-checker:v1.18.2" ||
		spec.family != "policy" {
		t.Fatalf("readiness-checker identity = %#v", spec)
	}
}

func TestKyvernoWebhookCleanupRejectsUnknownCommandContract(t *testing.T) {
	t.Parallel()

	_, err := officialImageForObservation(
		renderedImageObservation{
			artifact:  kyvernoArtifact,
			reference: kyvernoWebhookCleanupRepository + ":v1.35.7",
			inspection: chartInspection{Declared: []string{
				kyvernoReadinessCheckerRepository + ":v1.18.2",
			}},
			invocations: []containerInvocation{{
				Location: "changed-hook",
				Args:     []any{"get"},
			}},
		},
		"1.35.4",
		nil,
		"docker.io/library/debian:13-slim",
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported argument") {
		t.Fatalf("unknown Kyverno hook contract error = %v", err)
	}
}

func TestKyvernoWatchListCompatibilityIsVersionBound(t *testing.T) {
	t.Parallel()

	desired := config.Document{
		Orchestration: config.Orchestration{Releases: []config.ClusterRelease{{
			Kubernetes: "1.35.4",
		}}},
		Platform: config.Platform{Packages: []config.Package{{
			ID: "kyverno",
			Source: config.GitSource{
				Version: kyvernoWatchListPackageVersion,
			},
		}}},
		Delivery: config.Delivery{Images: []config.Image{{
			ID:        "kyverno-admission-controller",
			Version:   kyvernoWatchListApplicationVersion,
			Consumers: []string{kyvernoArtifact},
			BigBangRefs: []string{
				"registry1.dso.mil/ironbank/opensource/kyverno:v1.18.2",
			},
		}}},
	}
	generated := make(map[string]any)
	images := indexSelectedImages(desired.Delivery.Images)
	if err := projectKyvernoWatchListCompatibility(generated, desired, images); err != nil {
		t.Fatal(err)
	}
	vars := mapAt(
		generated,
		"kyverno",
		"values",
		"upstream",
		"global",
	)["extraEnvVars"].([]any)
	if len(vars) != 1 || vars[0].(map[string]any)["name"] != "KUBE_FEATURE_WatchListClient" ||
		vars[0].(map[string]any)["value"] != "false" {
		t.Fatalf("Kyverno compatibility environment = %#v", vars)
	}

	desired.Platform.Packages[0].Source.Version = "3.8.3-bb.0"
	if err := projectKyvernoWatchListCompatibility(
		make(map[string]any),
		desired,
		images,
	); err == nil || !strings.Contains(err.Error(), "requires review") {
		t.Fatalf("unaudited Kyverno package error = %v", err)
	}
}
