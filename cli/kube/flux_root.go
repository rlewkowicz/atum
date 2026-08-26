package kube

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type FluxRootTarget struct {
	URL string
	Tag string
}

type FluxRootObservation struct {
	Found            bool
	TargetCurrent    bool
	ObservedTag      string
	SourceReady      bool
	SourceMessage    string
	HelmReleaseReady bool
	HelmMessage      string
}

func (observation FluxRootObservation) Complete() bool {
	return observation.Found &&
		observation.TargetCurrent &&
		observation.SourceReady &&
		observation.HelmReleaseReady
}

func (observer *Observer) ObserveFluxHelmRoot(
	ctx context.Context,
	namespace, name string,
	target FluxRootTarget,
) (FluxRootObservation, error) {
	if target.URL == "" || target.Tag == "" {
		return FluxRootObservation{}, errors.New("Flux root OCI target is incomplete")
	}
	source, sourceFound, err := observer.GetResource(
		ctx,
		OCIRepository,
		namespace,
		name,
	)
	if err != nil {
		return FluxRootObservation{}, fmt.Errorf("read %s/%s OCIRepository: %w", namespace, name, err)
	}
	release, releaseFound, err := observer.GetResource(
		ctx,
		HelmRelease,
		namespace,
		name,
	)
	if err != nil {
		return FluxRootObservation{}, fmt.Errorf("read %s/%s HelmRelease: %w", namespace, name, err)
	}
	if sourceFound != releaseFound {
		return FluxRootObservation{}, fmt.Errorf(
			"Flux root %s/%s has only one of its OCIRepository and HelmRelease",
			namespace,
			name,
		)
	}
	if !sourceFound {
		return FluxRootObservation{}, nil
	}
	url, found, err := unstructured.NestedString(source.Object, "spec", "url")
	if err != nil || !found || url != target.URL {
		return FluxRootObservation{}, fmt.Errorf(
			"Flux root %s/%s OCIRepository URL %q does not match %s",
			namespace,
			name,
			url,
			target.URL,
		)
	}
	tag, found, err := unstructured.NestedString(source.Object, "spec", "ref", "tag")
	if err != nil || !found || tag == "" {
		return FluxRootObservation{}, fmt.Errorf(
			"Flux root %s/%s OCIRepository has no immutable tag",
			namespace,
			name,
		)
	}
	kind, _, _ := unstructured.NestedString(release.Object, "spec", "chartRef", "kind")
	chartName, _, _ := unstructured.NestedString(release.Object, "spec", "chartRef", "name")
	chartNamespace, _, _ := unstructured.NestedString(
		release.Object,
		"spec",
		"chartRef",
		"namespace",
	)
	if kind != "OCIRepository" || chartName != name ||
		(chartNamespace != "" && chartNamespace != namespace) {
		return FluxRootObservation{}, fmt.Errorf(
			"Flux root %s/%s HelmRelease chartRef is %s %s/%s, want OCIRepository %s/%s",
			namespace,
			name,
			kind,
			chartNamespace,
			chartName,
			namespace,
			name,
		)
	}
	sourceReady := IsReady(source)
	helmReady := IsReady(release)
	return FluxRootObservation{
		Found:            true,
		TargetCurrent:    tag == target.Tag,
		ObservedTag:      tag,
		SourceReady:      sourceReady,
		SourceMessage:    readinessDiagnostic(source, sourceReady),
		HelmReleaseReady: helmReady,
		HelmMessage:      readinessDiagnostic(release, helmReady),
	}, nil
}

func readinessDiagnostic(object *Object, ready bool) string {
	if ready {
		return ""
	}
	if object == nil {
		return "resource is absent"
	}
	if object.DeletionTimestamp != nil {
		return "resource is deleting"
	}
	statusObserved, statusFound, statusErr := unstructured.NestedInt64(
		object.Object,
		"status",
		"observedGeneration",
	)
	if statusErr != nil {
		return "status observedGeneration is invalid"
	}
	if statusFound && statusObserved != object.Generation {
		return "status observedGeneration is stale"
	}
	conditions, found, err := unstructured.NestedSlice(
		object.Object,
		"status",
		"conditions",
	)
	if err != nil || !found {
		return "Ready condition is absent"
	}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok || condition["type"] != "Ready" {
			continue
		}
		reason, _ := condition["reason"].(string)
		message, _ := condition["message"].(string)
		if reason != "" && message != "" {
			return reason + ": " + message
		}
		if message != "" {
			return message
		}
		if reason != "" {
			return reason
		}
		return "Ready condition does not establish current readiness"
	}
	return "Ready condition is absent"
}
