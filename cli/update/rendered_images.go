package update

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"atum/cli/config"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type officialImageSpec struct {
	id         string
	targetName string
	family     string
	version    string
	targetTag  string
	license    string
	provenance string
	source     string
}

type renderedImageObservation struct {
	artifact    string
	reference   string
	inspection  chartInspection
	invocations []containerInvocation
}

type renderedImageInventory struct {
	desired  *config.Document
	byID     map[string]int
	byTarget map[string]int
}

func newRenderedImageInventory(desired *config.Document) *renderedImageInventory {
	inventory := &renderedImageInventory{
		desired:  desired,
		byID:     make(map[string]int, len(desired.Delivery.Images)),
		byTarget: make(map[string]int, len(desired.Delivery.Images)),
	}
	for index := range desired.Delivery.Images {
		image := desired.Delivery.Images[index]
		inventory.byID[image.ID] = index
		inventory.byTarget[image.Target] = index
	}
	return inventory
}

// reconstructRenderedImages owns the updater transaction's runtime inventory.
// It consumes only the current selected renders and official vendor mappings;
// no prior rendered references, generated post-renderer, or desired build
// record can admit an image.
func reconstructRenderedImages(
	ctx context.Context,
	desired *config.Document,
	artifacts []chartArtifact,
	inspections []chartInspection,
	kubernetesVersion string,
) (map[string]string, error) {
	if len(artifacts) != len(inspections) {
		return nil, errors.New("current rendered image observation set is incomplete")
	}
	inventory := newRenderedImageInventory(desired)
	observations := currentImageObservations(artifacts, inspections)
	kubectlVersions, err := resolveKubectlMinorTags(ctx, observations, kubernetesVersion)
	if err != nil {
		return nil, err
	}
	var projectedTargets []renderedImageObservation
	for _, renderedObservation := range observations {
		if strings.HasPrefix(
			renderedObservation.reference,
			desired.Delivery.Policy.RuntimeRegistryPrefix,
		) {
			projectedTargets = append(projectedTargets, renderedObservation)
			continue
		}
		if inventory.mergeKnownTargetObservation(renderedObservation) {
			continue
		}
		spec, err := officialImageFor(
			renderedObservation.reference,
			renderedObservation.artifact,
			kubernetesVersion,
			kubectlVersions,
			desired.Delivery.Policy.BuildBase,
		)
		if err != nil {
			return nil, err
		}
		if spec.version == "" {
			spec.version = strings.TrimPrefix(imageTag(spec.source), "v")
		}
		if spec.targetTag == "" {
			spec.targetTag = imageTag(spec.source)
		}
		if spec.targetTag == "" {
			return nil, fmt.Errorf(
				"%s official candidate %s has no internal target tag",
				renderedObservation.artifact,
				spec.source,
			)
		}
		targetName := spec.id
		if spec.targetName != "" {
			targetName = spec.targetName
		}
		candidate := config.Image{
			ID:          spec.id,
			Family:      spec.family,
			Version:     spec.version,
			Target:      desired.Delivery.Policy.RuntimeRegistryPrefix + targetName + ":" + spec.targetTag,
			Scopes:      []string{"bigbang"},
			Runtime:     true,
			License:     spec.license,
			Provenance:  spec.provenance,
			Consumers:   []string{renderedObservation.artifact},
			BigBangRefs: []string{renderedObservation.reference},
			Discovery:   "rendered",
			Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type:   "mirror",
				Source: spec.source,
				Digest: "sha256:" + strings.Repeat("0", 64),
			}},
		}
		inventory.mergeCurrentRenderedImage(
			candidate,
			renderedObservation.artifact != "bigbang",
		)
	}
	for _, observation := range projectedTargets {
		if !inventory.mergeKnownTargetObservation(observation) {
			return nil, fmt.Errorf(
				"%s selected-source render uses projected target %s without an exact current source binding",
				observation.artifact,
				observation.reference,
			)
		}
	}
	sort.Slice(desired.Delivery.Images, func(i, j int) bool {
		return desired.Delivery.Images[i].ID < desired.Delivery.Images[j].ID
	})
	return kubectlVersions, nil
}

func (inventory *renderedImageInventory) mergeKnownTargetObservation(
	observation renderedImageObservation,
) bool {
	index, found := inventory.byTarget[observation.reference]
	if !found {
		return false
	}
	image := &inventory.desired.Delivery.Images[index]
	image.Consumers = compactSorted(append(image.Consumers, observation.artifact))
	return true
}

func currentImageObservations(
	artifacts []chartArtifact,
	inspections []chartInspection,
) []renderedImageObservation {
	observations := make([]renderedImageObservation, 0, len(artifacts)*4)
	for index := range artifacts {
		inspection := inspections[index]
		invocationsByRepository := make(
			map[string][]containerInvocation,
			len(inspection.Invocations),
		)
		for _, invocation := range inspection.Invocations {
			invocationsByRepository[invocation.Repository] = append(
				invocationsByRepository[invocation.Repository],
				invocation,
			)
		}
		for _, reference := range observedSourceImages(inspection) {
			repository := imageRepository(reference)
			observations = append(observations, renderedImageObservation{
				artifact: artifacts[index].ID, reference: reference,
				inspection:  inspection,
				invocations: invocationsByRepository[repository],
			})
		}
	}
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].artifact != observations[j].artifact {
			return observations[i].artifact < observations[j].artifact
		}
		return observations[i].reference < observations[j].reference
	})
	return observations
}

func (inventory *renderedImageInventory) mergeCurrentRenderedImage(
	candidate config.Image,
	preferCandidate bool,
) {
	index, exists := inventory.byID[candidate.ID]
	if exists {
		current := &inventory.desired.Delivery.Images[index]
		current.BigBangRefs = compactSorted(append(current.BigBangRefs, candidate.BigBangRefs...))
		current.Consumers = compactSorted(append(current.Consumers, candidate.Consumers...))
		if current.Discovery != "rendered" {
			return
		}
		if preferCandidate {
			references, consumers := current.BigBangRefs, current.Consumers
			delete(inventory.byTarget, current.Target)
			*current = candidate
			current.BigBangRefs, current.Consumers = references, consumers
			inventory.byTarget[current.Target] = index
		}
		return
	}
	index = len(inventory.desired.Delivery.Images)
	inventory.desired.Delivery.Images = append(inventory.desired.Delivery.Images, candidate)
	inventory.byID[candidate.ID] = index
	inventory.byTarget[candidate.Target] = index
}

func officialImageFor(
	reference string,
	artifact string,
	kubernetesVersion string,
	kubectlVersions map[string]string,
	buildBase string,
) (officialImageSpec, error) {
	repository := imageRepository(reference)
	tag := imageTag(reference)
	if repository == "" || tag == "" {
		return officialImageSpec{}, fmt.Errorf("%s renders invalid image %q", artifact, reference)
	}
	switch repository {
	case "registry1.dso.mil/ironbank/big-bang/base":
		return officialImageSpec{
			id: "garage-init-helper", family: "data", version: strings.TrimPrefix(tag, "v"),
			targetTag: tag, license: "Debian",
			provenance: "https://www.debian.org/",
			source:     buildBase,
		}, nil
	case "registry1.dso.mil/ironbank/big-bang/grafana/grafana-plugins":
		version := strings.TrimPrefix(tag, "v")
		return officialImageSpec{
			id: "grafana-plugins", family: "observability", version: version,
			targetTag: tag, license: "AGPL-3.0-only",
			provenance: "https://github.com/grafana/grafana",
			source:     "docker.io/grafana/grafana:" + version,
		}, nil
	case "registry1.dso.mil/ironbank/opensource/postgres/postgresql":
		version := strings.TrimPrefix(tag, "v")
		return officialImageSpec{
			id: "postgresql-" + strings.Split(version, ".")[0], family: "data",
			version: version, targetTag: version, license: "PostgreSQL",
			provenance: "https://github.com/docker-library/postgres",
			source:     "docker.io/library/postgres:" + version,
		}, nil
	case "registry1.dso.mil/ironbank/opensource/redis/redis8-slim":
		version := strings.TrimPrefix(tag, "v")
		versionID := strings.NewReplacer(".", "-", "_", "-").Replace(version)
		return officialImageSpec{
			id: "redis-" + versionID, family: "data", version: version,
			targetTag: version, license: "RSALv2 OR SSPLv1 OR AGPLv3",
			provenance: "https://github.com/redis/redis",
			source:     "docker.io/library/redis:" + version,
		}, nil
	case "registry1.dso.mil/ironbank/opensource/kubernetes/kubectl":
		spec, err := officialKubectlImage(reference, kubernetesVersion, kubectlVersions)
		if err != nil {
			return officialImageSpec{}, err
		}
		version := strings.TrimPrefix(imageTag(spec.source), "v")
		versionID := strings.NewReplacer(".", "-", "_", "-").Replace(version)
		spec.id = "kubectl-helper-" + versionID
		if version == kubernetesVersion {
			spec.id = "kubectl"
		}
		spec.version = version
		spec.targetTag = "v" + version
		spec.provenance = "https://github.com/kubernetes/kubernetes"
		return spec, nil
	}
	if strings.HasPrefix(repository, "registry1.dso.mil/gitlab/gitlab-org/build/cng/") {
		name := strings.TrimPrefix(repository, "registry1.dso.mil/gitlab/gitlab-org/build/cng/")
		sourceTag := strings.TrimSuffix(tag, "-ubi")
		sourceTag = strings.TrimSuffix(sourceTag, "-gitlab")
		if strings.Contains(tag, "-gitlab-ubi") {
			sourceTag += "-gitlab"
		}
		id := strings.TrimSuffix(name, "-ee")
		if id == "kubectl" {
			id = "gitlab-kubectl"
		}
		return officialImageSpec{
			id: id, family: "gitlab",
			license: "MIT", provenance: "https://gitlab.com/gitlab-org/build/CNG @ " + sourceTag,
			source: "registry.gitlab.com/gitlab-org/build/cng/" + name + ":" + sourceTag,
		}, nil
	}
	if !strings.HasPrefix(repository, "registry1.dso.mil/") {
		return directOfficialImage(repository, tag)
	}

	const ironbank = "registry1.dso.mil/ironbank/"
	path := strings.TrimPrefix(repository, ironbank)
	spec := officialImageSpec{family: artifactFamily(artifact)}
	switch {
	case strings.HasPrefix(path, "fluxcd/"):
		name := strings.TrimPrefix(path, "fluxcd/")
		spec.id, spec.targetName, spec.family, spec.license =
			"flux-"+name, name, "flux", "Apache-2.0"
		spec.source = "ghcr.io/fluxcd/" + name + ":" + tag
	case strings.HasPrefix(path, "opensource/goharbor/"):
		name := strings.TrimPrefix(path, "opensource/goharbor/")
		spec.id, spec.family, spec.license = "harbor-"+name, "harbor", "Apache-2.0"
		sourceName := name
		if name == "registry" {
			sourceName = "registry-photon"
		}
		if name == "trivy-adapter" {
			sourceName = "trivy-adapter-photon"
		}
		spec.source = "docker.io/goharbor/" + sourceName + ":" + tag
	case path == "afdco/docker/busybox" ||
		path == "frontiertechnology/cortex/busybox":
		spec.id, spec.family, spec.license = "busybox", "foundation", "GPL-2.0-only"
		spec.source = "docker.io/library/busybox:" + strings.TrimPrefix(tag, "v")
	case path == "opensource/istio/pilot":
		spec.id, spec.family, spec.license = "pilot", "mesh", "Apache-2.0"
		spec.source = "docker.io/istio/pilot:" + tag
	case path == "opensource/istio/proxyv2":
		spec.id, spec.family, spec.license = "proxyv2", "mesh", "Apache-2.0"
		spec.source = "docker.io/istio/proxyv2:" + tag
	case path == "opensource/kiali/kiali-operator":
		spec.id, spec.family, spec.license = "kiali-operator", "mesh", "Apache-2.0"
		spec.source = "quay.io/kiali/kiali-operator:" + tag
	case path == "opensource/kiali/kiali":
		spec.id, spec.family, spec.license = "kiali", "mesh", "Apache-2.0"
		spec.source = "quay.io/kiali/kiali:" + tag
	case path == "opensource/headlamp-k8s/headlamp":
		spec.id, spec.family, spec.license = "headlamp", "cluster", "Apache-2.0"
		spec.source = "ghcr.io/headlamp-k8s/headlamp:" + tag
	case path == "istio-ecosystem/authservice":
		spec.id, spec.family, spec.license = "authservice", "identity", "Apache-2.0"
		spec.source = "ghcr.io/istio-ecosystem/authservice/authservice:" + tag
	case path == "opensource/kyverno":
		spec.id, spec.family, spec.license = "kyverno-admission-controller", "policy", "Apache-2.0"
		spec.source = "reg.kyverno.io/kyverno/kyverno:" + tag
	case path == "opensource/kyverno/kyvernopre":
		spec.id, spec.family, spec.license = "kyverno-preflight", "policy", "Apache-2.0"
		spec.source = "reg.kyverno.io/kyverno/kyvernopre:" + tag
	case path == "opensource/kyverno/kyvernocli":
		spec.id, spec.family, spec.license = "kyverno-cli", "policy", "Apache-2.0"
		spec.source = "reg.kyverno.io/kyverno/kyverno-cli:" + tag
	case strings.HasPrefix(path, "opensource/kyverno/kyverno/"):
		name := strings.TrimPrefix(path, "opensource/kyverno/kyverno/")
		spec.id, spec.family, spec.license = "kyverno-"+name, "policy", "Apache-2.0"
		if name == "readiness-checker" {
			spec.source = "ghcr.io/kyverno/readiness-checker:" + tag
		} else {
			spec.source = "reg.kyverno.io/kyverno/" + name + ":" + tag
		}
	case path == "opensource/kyverno/policy-reporter":
		spec.id, spec.family, spec.license = "policy-reporter", "policy", "MIT"
		spec.source = "ghcr.io/kyverno/policy-reporter:" + tag
	case path == "nirmata/policy-reporter/policy-reporter-ui":
		spec.id, spec.family, spec.license = "policy-reporter-ui", "policy", "MIT"
		spec.source = "ghcr.io/kyverno/policy-reporter-ui:" + tag
	case path == "opensource/kyverno/policy-reporter/kyverno-plugin":
		spec.id, spec.family, spec.license = "policy-reporter-kyverno-plugin", "policy", "MIT"
		spec.source = "ghcr.io/kyverno/policy-reporter/kyverno-plugin:" + tag
	case path == "opensource/fluent/fluent-bit":
		spec.id, spec.family, spec.license = "fluent-bit", "observability", "Apache-2.0"
		spec.source = "cr.fluentbit.io/fluent/fluent-bit:" + strings.TrimPrefix(tag, "v")
	case path == "opensource/grafana/tempo":
		spec.id, spec.family, spec.license = "tempo", "observability", "AGPL-3.0-only"
		spec.source = "docker.io/grafana/tempo:" + tag
	case strings.HasPrefix(path, "opensource/prometheus-operator/"):
		name := strings.TrimPrefix(path, "opensource/prometheus-operator/")
		spec.id, spec.family, spec.license = name, "observability", "Apache-2.0"
		spec.source = "quay.io/prometheus-operator/" + name + ":" + tag
	case path == "opensource/thanos/thanos":
		spec.id, spec.family, spec.license = "thanos", "observability", "Apache-2.0"
		spec.source = "quay.io/thanos/thanos:" + tag
	case path == "opensource/kubernetes/kube-state-metrics":
		spec.id, spec.family, spec.license = "kube-state-metrics", "observability", "Apache-2.0"
		spec.source = "registry.k8s.io/kube-state-metrics/kube-state-metrics:" + tag
	case path == "opensource/prometheus/node-exporter":
		spec.id, spec.family, spec.license = "node-exporter", "observability", "Apache-2.0"
		spec.source = "quay.io/prometheus/node-exporter:" + tag
	case path == "opensource/prometheus/alertmanager" ||
		path == "opensource/prometheus/prometheus":
		name := strings.TrimPrefix(path, "opensource/prometheus/")
		spec.id, spec.family, spec.license = name, "observability", "Apache-2.0"
		spec.source = "quay.io/prometheus/" + name + ":" + tag
	case path == "opensource/ingress-nginx/kube-webhook-certgen":
		spec.id, spec.family, spec.license = "kube-webhook-certgen", "cluster", "Apache-2.0"
		spec.source = "registry.k8s.io/ingress-nginx/kube-webhook-certgen:" + tag
	case path == "kiwigrid/k8s-sidecar":
		spec.id, spec.family, spec.license = "k8s-sidecar", "observability", "MIT"
		spec.source = "quay.io/kiwigrid/k8s-sidecar:" + tag
	case path == "opensource/keycloak/keycloak":
		spec.id, spec.family, spec.license = "keycloak", "identity", "Apache-2.0"
		spec.source = "quay.io/keycloak/keycloak:" + tag
	case path == "redhat/ubi/ubi9":
		spec.id, spec.family, spec.license = "ubi9", "foundation", "GPL-2.0-or-later"
		spec.source = "registry.access.redhat.com/ubi9/ubi:" + tag
	case path == "redhat/ubi/ubi9-minimal":
		spec.id, spec.family, spec.license = "ubi9-minimal", "foundation", "GPL-2.0-or-later"
		spec.source = "registry.access.redhat.com/ubi9/ubi-minimal:" + tag
	case path == "hashicorp/vault":
		spec.id, spec.family, spec.license = "vault", "secrets", "BUSL-1.1"
		spec.source = "docker.io/hashicorp/vault:" + tag
	case path == "hashicorp/vault/vault-k8s":
		spec.id, spec.family, spec.license = "vault-k8s", "secrets", "MPL-2.0"
		spec.source = "docker.io/hashicorp/vault-k8s:" + strings.TrimPrefix(tag, "v")
	case path == "opensource/cloudnativepg/cloudnative-pg":
		version := strings.TrimSuffix(tag, "-ubi9")
		spec.id, spec.family, spec.license = "cloudnative-pg", "data", "Apache-2.0"
		spec.source = "ghcr.io/cloudnative-pg/cloudnative-pg:" + version
	case path == "opensource/deuxfleurs-org/garage":
		version := strings.TrimPrefix(tag, "v")
		spec.id, spec.family, spec.license = "garage", "data", "AGPL-3.0-only"
		spec.source = "docker.io/dxflrs/garage:v" + version
	case path == "opensource/kubernetes-sigs/metrics-server":
		spec.id, spec.family, spec.license = "metrics-server", "cluster", "Apache-2.0"
		spec.source = "registry.k8s.io/metrics-server/metrics-server:" + tag
	default:
		return officialImageSpec{}, fmt.Errorf(
			"%s renders %s without an official vendor image mapping", artifact, reference,
		)
	}
	if spec.provenance == "" {
		spec.provenance = imageRepository(spec.source)
	}
	return spec, nil
}

func directOfficialImage(repository, tag string) (officialImageSpec, error) {
	sourceRepository := repository
	if !strings.Contains(strings.Split(repository, "/")[0], ".") {
		if strings.Contains(repository, "/") {
			sourceRepository = "docker.io/" + repository
		} else {
			sourceRepository = "docker.io/library/" + repository
		}
	}
	id := repository[strings.LastIndex(repository, "/")+1:]
	spec := officialImageSpec{
		id: id, source: sourceRepository + ":" + tag,
		provenance: sourceRepository,
	}
	if identity, found := configuredOfficialImages[sourceRepository]; found {
		spec.id = identity.id
		spec.family = identity.family
		spec.license = identity.license
		spec.provenance = identity.provenance
		return spec, nil
	}
	switch {
	case strings.HasPrefix(sourceRepository, "ghcr.io/fluxcd/"):
		spec.id, spec.family, spec.license = id, "flux", "Apache-2.0"
	case sourceRepository == "ghcr.io/cloudnative-pg/postgresql":
		spec.id, spec.family, spec.license = "postgresql-"+strings.TrimPrefix(tag, "v"), "data", "PostgreSQL"
		spec.provenance = "https://github.com/cloudnative-pg/postgres-containers"
	case sourceRepository == "docker.io/opensearchproject/opensearch" ||
		sourceRepository == "docker.io/opensearchproject/opensearch-dashboards":
		spec.family, spec.license = "search", "Apache-2.0"
		spec.provenance = "https://github.com/opensearch-project"
	default:
		return officialImageSpec{}, fmt.Errorf(
			"rendered image %s:%s has no verified official vendor provenance",
			sourceRepository,
			tag,
		)
	}
	return spec, nil
}

func officialKubectlImage(
	reference string,
	kubernetesVersion string,
	minorVersions map[string]string,
) (officialImageSpec, error) {
	parts := strings.Split(kubernetesVersion, ".")
	if len(parts) != 3 {
		return officialImageSpec{}, fmt.Errorf("Kubernetes version %q is not exact", kubernetesVersion)
	}
	version := "v" + kubernetesVersion
	repository := imageRepository(reference)
	renderedTag := imageTag(reference)
	if repository == "registry1.dso.mil/ironbank/opensource/kubernetes/kubectl" {
		trimmed := strings.TrimPrefix(renderedTag, "v")
		components := strings.Split(trimmed, ".")
		if len(components) == 3 {
			version = "v" + trimmed
		} else if len(components) == 2 {
			var exists bool
			version, exists = minorVersions["v"+trimmed]
			if !exists {
				return officialImageSpec{}, fmt.Errorf(
					"rendered kubectl tag %s has no resolved official patch", renderedTag,
				)
			}
		} else {
			return officialImageSpec{}, fmt.Errorf(
				"rendered kubectl tag %s is not a precise major/minor or patch identity",
				renderedTag,
			)
		}
	}
	id := "kubectl"
	if version != "v"+kubernetesVersion {
		id = "kubectl-" + strings.ReplaceAll(strings.TrimPrefix(version, "v"), ".", "-")
	}
	return officialImageSpec{
		id: id, family: "cluster", license: "Apache-2.0",
		provenance: "https://github.com/kubernetes/kubernetes",
		source:     "registry.k8s.io/kubectl:" + version,
	}, nil
}

func resolveKubectlMinorTags(
	ctx context.Context,
	observations []renderedImageObservation,
	kubernetesVersion string,
) (map[string]string, error) {
	result := make(map[string]string)
	cluster := strings.Split(kubernetesVersion, ".")
	if len(cluster) != 3 {
		return nil, fmt.Errorf("Kubernetes version %q is not exact", kubernetesVersion)
	}
	for _, observation := range observations {
		if imageRepository(observation.reference) !=
			"registry1.dso.mil/ironbank/opensource/kubernetes/kubectl" {
			continue
		}
		tag := imageTag(observation.reference)
		parts := strings.Split(strings.TrimPrefix(tag, "v"), ".")
		if len(parts) != 2 {
			continue
		}
		if parts[0] == cluster[0] && parts[1] == cluster[1] {
			result[tag] = "v" + kubernetesVersion
		} else {
			result[tag] = ""
		}
	}
	needsRemote := false
	for _, version := range result {
		if version == "" {
			needsRemote = true
		}
	}
	if !needsRemote {
		return result, nil
	}
	repository, err := name.NewRepository("registry.k8s.io/kubectl")
	if err != nil {
		return nil, err
	}
	tags, err := remote.List(
		repository,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return nil, fmt.Errorf("list official kubectl patches: %w", err)
	}
	bestByMinor := make(map[string]*semver.Version, len(result))
	bestTagByMinor := make(map[string]string, len(result))
	for _, tag := range tags {
		version, parseErr := semver.NewVersion(strings.TrimPrefix(tag, "v"))
		if parseErr != nil || version.Prerelease() != "" {
			continue
		}
		minor := fmt.Sprintf("v%d.%d", version.Major(), version.Minor())
		selected, needed := result[minor]
		if !needed || selected != "" {
			continue
		}
		if best := bestByMinor[minor]; best == nil || version.GreaterThan(best) {
			bestByMinor[minor], bestTagByMinor[minor] = version, tag
		}
	}
	for minor, selected := range result {
		if selected != "" {
			continue
		}
		bestTag := bestTagByMinor[minor]
		if bestTag == "" {
			return nil, fmt.Errorf("official kubectl has no stable patch for %s", minor)
		}
		result[minor] = bestTag
	}
	return result, nil
}

func artifactFamily(artifact string) string {
	artifact = strings.TrimPrefix(artifact, "package/")
	artifact = strings.TrimPrefix(artifact, "chart/")
	artifact = strings.TrimPrefix(artifact, "bootstrap/")
	if artifact == "" || artifact == "bigbang" {
		return "platform"
	}
	return artifact
}
