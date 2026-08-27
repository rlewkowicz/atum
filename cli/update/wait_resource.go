package update

import (
	"errors"
	"strings"
)

const maxFormerWaitResources = 16

type formerWaitObservation struct {
	Resources []renderedResource
	Overflow  *renderedResource
}

func observeFormerWaitResource(
	value any,
	path string,
	observation *formerWaitObservation,
) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	apiVersion, _ := object["apiVersion"].(string)
	kind, _ := object["kind"].(string)
	metadata, _ := object["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	resource := renderedResource{
		APIVersion: apiVersion,
		Kind:       kind,
		Namespace:  namespace,
		Name:       name,
		Path:       path,
	}
	if !isFormerWaitIdentity(resource) {
		return
	}
	if !boundedSecurityStrings(apiVersion, kind, namespace, name, path) ||
		len(observation.Resources) >= maxFormerWaitResources {
		if observation.Overflow == nil {
			copy := resource
			observation.Overflow = &copy
		}
		return
	}
	observation.Resources = append(observation.Resources, resource)
}

func isFormerWaitIdentity(resource renderedResource) bool {
	switch {
	case resource.APIVersion == "batch/v1" && resource.Kind == "Job":
		return strings.TrimSuffix(resource.Name, "-wait-job") != resource.Name &&
			strings.TrimSuffix(resource.Name, "-wait-job") != ""
	case resource.APIVersion == "networking.k8s.io/v1" &&
		resource.Kind == "NetworkPolicy":
		const prefix = "allow-egress-from-"
		const suffix = "-wait-job-to-anywhere-any-port"
		return strings.HasPrefix(resource.Name, prefix) &&
			strings.HasSuffix(resource.Name, suffix) &&
			len(resource.Name) > len(prefix)+len(suffix)
	default:
		return false
	}
}

func mergeFormerWaitObservation(
	target *formerWaitObservation,
	source formerWaitObservation,
	pathPrefix string,
) {
	if target.Overflow != nil {
		return
	}
	if source.Overflow != nil {
		copy := *source.Overflow
		copy.Path = pathPrefix + copy.Path
		target.Overflow = &copy
		return
	}
	if len(target.Resources)+len(source.Resources) > maxFormerWaitResources {
		resource := renderedResource{Path: pathPrefix}
		if len(source.Resources) != 0 {
			resource = source.Resources[0]
			resource.Path = pathPrefix + resource.Path
		}
		target.Overflow = &resource
		return
	}
	for _, resource := range source.Resources {
		resource.Path = pathPrefix + resource.Path
		target.Resources = append(target.Resources, resource)
	}
}

func validateFormerWaitResourceAbsence(
	inspections map[string]chartInspection,
) error {
	for _, artifact := range []string{
		"package/kyverno-policies",
		"package/kiali",
		"package/headlamp",
		"package/istio-gateway",
	} {
		inspection, found := inspections[artifact]
		if !found {
			continue
		}
		if inspection.FormerWait.Overflow != nil {
			return candidateRenderError(
				artifact,
				errors.New(
					inspection.FormerWait.Overflow.String()+
						": former wait-resource observation exceeded its hard bound",
				),
			)
		}
		if len(inspection.FormerWait.Resources) != 0 {
			resource := inspection.FormerWait.Resources[0]
			return candidateRenderError(
				artifact,
				errors.New(
					resource.String()+
						": selected production render contains a former Gluon wait resource",
				),
			)
		}
	}
	return nil
}
