package update

import (
	"strings"
	"testing"
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
