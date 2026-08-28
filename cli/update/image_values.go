package update

import (
	"errors"
	"fmt"
	"strings"

	"atum/cli/config"
)

type imageValueShape uint8

const (
	imageRepositoryTag imageValueShape = iota
	imageSplitRegistryRepositoryTag
	imageFullReference
	imageRepositoryAsImageTag
	imageRepositoryAsRepoTag
	imageDefaultRegistryRepositoryTag
)

type imageValueProjection struct {
	artifact   string
	repository string
	path       string
	shape      imageValueShape
}

type selectedImageKey struct {
	artifact   string
	repository string
}

type selectedImageIndex map[selectedImageKey][]config.Image

func indexSelectedImages(images []config.Image) selectedImageIndex {
	index := make(selectedImageIndex, len(images))
	for _, image := range images {
		repositories := make(map[string]struct{}, len(image.BigBangRefs))
		for _, reference := range image.BigBangRefs {
			repositories[imageRepository(reference)] = struct{}{}
		}
		for _, artifact := range image.Consumers {
			for repository := range repositories {
				key := selectedImageKey{
					artifact:   artifact,
					repository: repository,
				}
				index[key] = append(index[key], image)
			}
		}
	}
	return index
}

// projectSelectedImageValues is the selected-chart image boundary. Each entry
// names one public value in the exact chart selected by the updater. A chart
// upgrade that removes or changes one of these values must fail its candidate
// render instead of being masked by a blanket post-renderer.
func projectSelectedImageValues(generated map[string]any, desired config.Document) error {
	images := indexSelectedImages(desired.Delivery.Images)
	projections := []imageValueProjection{
		repositoryTag("package/authservice", "registry1.dso.mil/ironbank/istio-ecosystem/authservice", "addons.authservice.values.image"),
		repositoryTag("package/cloudnative-pg", "registry1.dso.mil/ironbank/opensource/cloudnativepg/cloudnative-pg", "packages.cloudnative-pg.values.upstream.image"),
		fullReference("package/postgresql", "ghcr.io/cloudnative-pg/postgresql", "packages.postgresql.values.cluster.imageName"),
		repositoryTag("package/fluentbit", "registry1.dso.mil/ironbank/opensource/fluent/fluent-bit", "fluentbit.values.upstream.image"),
		repositoryTag("package/garage", "registry1.dso.mil/ironbank/opensource/deuxfleurs-org/garage", "packages.garage.values.upstream.image"),
		repositoryTag("package/garage", "registry1.dso.mil/ironbank/afdco/docker/busybox", "packages.garage.values.upstream.initImage"),
		repositoryTag("package/garage", "registry1.dso.mil/ironbank/big-bang/base", "packages.garage.values.garageInit.image"),

		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/certificates", "addons.gitlab.values.global.certificates.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/kubectl", "addons.gitlab.values.global.kubectl.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-base", "addons.gitlab.values.global.gitlabBase.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-container-registry", "addons.gitlab.values.upstream.registry.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/cfssl-self-sign", "addons.gitlab.values.upstream.shared-secrets.selfsign.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-toolbox-ee", "addons.gitlab.values.upstream.gitlab.toolbox.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-exporter", "addons.gitlab.values.upstream.gitlab.gitlab-exporter.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-toolbox-ee", "addons.gitlab.values.upstream.gitlab.migrations.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-webservice-ee", "addons.gitlab.values.upstream.gitlab.webservice.image"),
		repositoryAsImageTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-workhorse-ee", "addons.gitlab.values.upstream.gitlab.webservice.workhorse"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-sidekiq-ee", "addons.gitlab.values.upstream.gitlab.sidekiq.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitaly", "addons.gitlab.values.upstream.gitlab.gitaly.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitlab-shell", "addons.gitlab.values.upstream.gitlab.gitlab-shell.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/gitlab/gitlab-org/build/cng/gitaly", "addons.gitlab.values.upstream.gitlab.praefect.image"),
		repositoryTag("package/gitlab", "registry1.dso.mil/ironbank/redhat/ubi/ubi9", "addons.gitlab.values.upstream.upgradeCheck.image"),

		splitImage("package/grafana", "registry1.dso.mil/ironbank/big-bang/grafana/grafana-plugins", "grafana.values.upstream.image"),
		splitImage("package/grafana", "registry1.dso.mil/ironbank/kiwigrid/k8s-sidecar", "grafana.values.upstream.sidecar.image"),

		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/harbor-portal", "addons.harbor.values.upstream.portal.image"),
		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/harbor-core", "addons.harbor.values.upstream.core.image"),
		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/harbor-jobservice", "addons.harbor.values.upstream.jobservice.image"),
		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/registry", "addons.harbor.values.upstream.registry.registry.image"),
		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/harbor-registryctl", "addons.harbor.values.upstream.registry.controller.image"),
		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/trivy-adapter", "addons.harbor.values.upstream.trivy.image"),
		repositoryTag("package/harbor", "registry1.dso.mil/ironbank/opensource/goharbor/harbor-exporter", "addons.harbor.values.upstream.exporter.image"),
		splitImage("package/harbor", "registry1.dso.mil/ironbank/opensource/postgres/postgresql", "addons.harbor.values.postgresql.image"),
		splitImage("package/harbor", "registry1.dso.mil/ironbank/opensource/redis/redis8-slim", "addons.harbor.values.redis-bb.upstream.image"),

		splitImage("package/headlamp", "registry1.dso.mil/ironbank/opensource/headlamp-k8s/headlamp", "addons.headlamp.values.upstream.image"),

		repositoryTag("package/keycloak", "registry1.dso.mil/ironbank/opensource/keycloak/keycloak", "addons.keycloak.values.upstream.image"),
		splitImage("package/keycloak", "registry1.dso.mil/ironbank/opensource/postgres/postgresql", "addons.keycloak.values.postgresql.image"),

		repoTag("package/kiali", "registry1.dso.mil/ironbank/opensource/kiali/kiali-operator", "kiali.values.upstream.image"),
		fullReference("package/kiali", "registry1.dso.mil/ironbank/opensource/kiali/kiali", "kiali.values.upstream.cr.spec.deployment.image_name"),

		defaultRegistryImage("package/kyverno", "registry1.dso.mil/ironbank/opensource/kyverno/kyvernopre", "kyverno.values.upstream.admissionController.initContainer.image"),
		defaultRegistryImage("package/kyverno", "registry1.dso.mil/ironbank/opensource/kyverno", "kyverno.values.upstream.admissionController.container.image"),
		defaultRegistryImage("package/kyverno", "registry1.dso.mil/ironbank/opensource/kyverno/kyverno/background-controller", "kyverno.values.upstream.backgroundController.image"),
		defaultRegistryImage("package/kyverno", "registry1.dso.mil/ironbank/opensource/kyverno/kyverno/cleanup-controller", "kyverno.values.upstream.cleanupController.image"),
		defaultRegistryImage("package/kyverno", "registry1.dso.mil/ironbank/opensource/kyverno/kyverno/reports-controller", "kyverno.values.upstream.reportsController.image"),
		defaultRegistryImage("package/kyverno", "registry1.dso.mil/ironbank/opensource/kyverno/kyvernocli", "kyverno.values.upstream.crds.migration.image"),
		splitImage("package/kyverno", kyvernoWebhookCleanupRepository, "kyverno.values.upstream.webhooksCleanup.image"),

		splitImage("package/kyverno-reporter", "registry1.dso.mil/ironbank/opensource/kyverno/policy-reporter", "kyvernoReporter.values.upstream.image"),
		splitImage("package/kyverno-reporter", "registry1.dso.mil/ironbank/nirmata/policy-reporter/policy-reporter-ui", "kyvernoReporter.values.upstream.ui.image"),
		splitImage("package/kyverno-reporter", "registry1.dso.mil/ironbank/opensource/kyverno/policy-reporter/kyverno-plugin", "kyvernoReporter.values.upstream.plugin.kyverno.image"),
		repositoryTag("package/metrics-server", "registry1.dso.mil/ironbank/opensource/kubernetes-sigs/metrics-server", "addons.metricsServer.values.upstream.image"),

		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/prometheus/alertmanager", "monitoring.values.upstream.alertmanager.alertmanagerSpec.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/kubernetes/kube-state-metrics", "monitoring.values.upstream.kube-state-metrics.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/prometheus/prometheus", "monitoring.values.upstream.prometheus.prometheusSpec.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/prometheus/node-exporter", "monitoring.values.upstream.prometheus-node-exporter.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/ingress-nginx/kube-webhook-certgen", "monitoring.values.upstream.prometheusOperator.admissionWebhooks.patch.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/prometheus-operator/prometheus-operator", "monitoring.values.upstream.prometheusOperator.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/prometheus-operator/prometheus-config-reloader", "monitoring.values.upstream.prometheusOperator.prometheusConfigReloader.image"),
		splitImage("package/monitoring", "registry1.dso.mil/ironbank/opensource/thanos/thanos", "monitoring.values.upstream.prometheusOperator.thanosImage"),

		splitImage("package/redis", "registry1.dso.mil/ironbank/opensource/redis/redis8-slim", "packages.redis.values.upstream.image"),
		splitImage("package/tempo", "registry1.dso.mil/ironbank/opensource/grafana/tempo", "tempo.values.upstream.tempo"),
		repositoryTag("package/vault", "registry1.dso.mil/ironbank/hashicorp/vault", "addons.vault.values.upstream.server.image"),
		repositoryTag("package/vault", "registry1.dso.mil/ironbank/hashicorp/vault", "addons.vault.values.upstream.injector.agentImage"),
		repositoryTag("package/vault", "registry1.dso.mil/ironbank/hashicorp/vault/vault-k8s", "addons.vault.values.upstream.injector.image"),

		repositoryTag("chart/cert-manager", "quay.io/jetstack/cert-manager-controller", "packages.cert-manager.values.image"),
		repositoryTag("chart/cert-manager", "quay.io/jetstack/cert-manager-webhook", "packages.cert-manager.values.webhook.image"),
		repositoryTag("chart/cert-manager", "quay.io/jetstack/cert-manager-cainjector", "packages.cert-manager.values.cainjector.image"),
		repositoryTag("chart/cert-manager", "quay.io/jetstack/cert-manager-startupapicheck", "packages.cert-manager.values.startupapicheck.image"),
		repositoryTag("chart/cert-manager", "quay.io/jetstack/cert-manager-acmesolver", "packages.cert-manager.values.acmesolver.image"),
		repositoryTag("chart/opensearch", "docker.io/opensearchproject/opensearch", "packages.opensearch.values.image"),
		repositoryTag("chart/opensearch-dashboards", "docker.io/opensearchproject/opensearch-dashboards", "packages.opensearch-dashboards.values.image"),
	}

	seenPaths := make(map[string]struct{}, len(projections))
	for _, projection := range projections {
		if _, duplicate := seenPaths[projection.path]; duplicate {
			return fmt.Errorf("image value path %s is projected more than once", projection.path)
		}
		seenPaths[projection.path] = struct{}{}
		image, err := selectedArtifactImage(
			images,
			projection.artifact,
			projection.repository,
		)
		if err != nil {
			return err
		}
		if err := projectImageValue(generated, projection, image); err != nil {
			return err
		}
	}
	if err := projectIstioControllerImages(generated, images); err != nil {
		return err
	}
	if err := projectChartGlobalImageRegistries(generated, images); err != nil {
		return err
	}
	if err := projectMonitoringBlackboxImage(generated, images); err != nil {
		return err
	}
	if err := projectRedisModuleCompatibility(generated, images); err != nil {
		return err
	}
	return projectKyvernoWatchListCompatibility(generated, desired, images)
}

func projectMonitoringBlackboxImage(
	generated map[string]any,
	images selectedImageIndex,
) error {
	const repository = "registry1.dso.mil/ironbank/opensource/prometheus/blackbox_exporter"
	image, err := selectedArtifactImage(images, "package/monitoring", repository)
	if err != nil {
		return err
	}
	if err := projectImageValue(
		generated,
		splitImage(
			"package/monitoring",
			repository,
			"monitoring.values.blackboxExporter.image",
		),
		image,
	); err != nil {
		return err
	}
	registry, _, found := strings.Cut(imageRepository(image.Target), "/")
	if !found {
		return fmt.Errorf("delivery target %s has no registry", image.Target)
	}
	// The selected exporter subchart gives global.imageRegistry precedence over
	// image.registry, so both public values must identify Harbor.
	return setNestedValue(
		generated,
		"monitoring.values.blackboxExporter.global.imageRegistry",
		registry,
	)
}

const redisModuleConfiguration = `loadmodule /usr/local/lib/redis/modules/redisearch.so
loadmodule /usr/local/lib/redis/modules/redisbloom.so
loadmodule /usr/local/lib/redis/modules/redistimeseries.so
loadmodule /usr/local/lib/redis/modules/rejson.so`

// projectRedisModuleCompatibility preserves the selected Redis package's four
// capabilities while replacing its Iron Bank filesystem convention with the
// official Redis image convention. Final image admission reads these mounted
// directives and proves that every projected module exists in the exact
// immutable image before the generated values can be published.
func projectRedisModuleCompatibility(
	generated map[string]any,
	images selectedImageIndex,
) error {
	const ironBankRedis = "registry1.dso.mil/ironbank/opensource/redis/redis8-slim"
	redis, err := selectedArtifactImage(images, "package/redis", ironBankRedis)
	if err != nil {
		return err
	}
	if imageRepository(redis.Delivery.Default.Source) != "docker.io/library/redis" {
		return fmt.Errorf(
			"selected Redis package maps %s to unsupported official source %q",
			ironBankRedis,
			redis.Delivery.Default.Source,
		)
	}
	return setNestedValue(
		generated,
		"packages.redis.values.upstream.commonConfiguration",
		redisModuleConfiguration,
	)
}

const (
	kyvernoWatchListPackageVersion     = "3.8.2-bb.2"
	kyvernoWatchListApplicationVersion = "1.18.2"
	kyvernoWatchListKubernetesMinor    = "1.35."
)

// projectKyvernoWatchListCompatibility disables only client-go's streaming
// list optimization for the exact release boundary that hung every Kyverno
// controller before its ConfigMap informer warmed. Ordinary LIST+WATCH remains
// enabled. The exact guards stop the updater at the next package, application,
// or Kubernetes-minor boundary so this fallback cannot silently become a
// permanent platform default.
func projectKyvernoWatchListCompatibility(
	generated map[string]any,
	desired config.Document,
	images selectedImageIndex,
) error {
	kyverno, err := selectedArtifactImage(
		images,
		kyvernoArtifact,
		"registry1.dso.mil/ironbank/opensource/kyverno",
	)
	if err != nil {
		return err
	}
	target, err := desired.Orchestration.TargetRelease()
	if err != nil {
		return err
	}
	packageVersion := ""
	for _, selected := range desired.Platform.Packages {
		if selected.ID != "kyverno" {
			continue
		}
		if packageVersion != "" {
			return errors.New("selected platform contains duplicate Kyverno packages")
		}
		packageVersion = selected.Source.Version
	}
	if packageVersion == "" {
		return errors.New("selected platform has no Kyverno package")
	}
	if packageVersion != kyvernoWatchListPackageVersion ||
		kyverno.Version != kyvernoWatchListApplicationVersion ||
		!strings.HasPrefix(target.Kubernetes, kyvernoWatchListKubernetesMinor) {
		return fmt.Errorf(
			"Kyverno WatchListClient fallback requires review outside package %s, application %s, Kubernetes %sx (selected %s, %s, %s)",
			kyvernoWatchListPackageVersion,
			kyvernoWatchListApplicationVersion,
			kyvernoWatchListKubernetesMinor,
			packageVersion,
			kyverno.Version,
			target.Kubernetes,
		)
	}
	return setNestedValue(
		generated,
		"kyverno.values.upstream.global.extraEnvVars",
		[]any{map[string]any{
			"name":  "KUBE_FEATURE_WatchListClient",
			"value": "false",
		}},
	)
}

func repositoryTag(artifact, repository, path string) imageValueProjection {
	return imageValueProjection{artifact: artifact, repository: repository, path: path, shape: imageRepositoryTag}
}

func splitImage(artifact, repository, path string) imageValueProjection {
	return imageValueProjection{artifact: artifact, repository: repository, path: path, shape: imageSplitRegistryRepositoryTag}
}

func fullReference(artifact, repository, path string) imageValueProjection {
	return imageValueProjection{artifact: artifact, repository: repository, path: path, shape: imageFullReference}
}

func repositoryAsImageTag(artifact, repository, path string) imageValueProjection {
	return imageValueProjection{artifact: artifact, repository: repository, path: path, shape: imageRepositoryAsImageTag}
}

func repoTag(artifact, repository, path string) imageValueProjection {
	return imageValueProjection{artifact: artifact, repository: repository, path: path, shape: imageRepositoryAsRepoTag}
}

func defaultRegistryImage(artifact, repository, path string) imageValueProjection {
	return imageValueProjection{artifact: artifact, repository: repository, path: path, shape: imageDefaultRegistryRepositoryTag}
}

func selectedArtifactImage(
	images selectedImageIndex,
	artifact string,
	repository string,
) (config.Image, error) {
	var result config.Image
	for _, image := range images[selectedImageKey{
		artifact:   artifact,
		repository: repository,
	}] {
		if result.ID != "" && result.ID != image.ID {
			return config.Image{}, fmt.Errorf(
				"%s repository %s maps to both %s and %s",
				artifact,
				repository,
				result.ID,
				image.ID,
			)
		}
		result = image
	}
	if result.ID == "" {
		return config.Image{}, fmt.Errorf(
			"%s has no current delivery image for public value repository %s",
			artifact,
			repository,
		)
	}
	return result, nil
}

func projectImageValue(
	generated map[string]any,
	projection imageValueProjection,
	image config.Image,
) error {
	repository := imageRepository(image.Target)
	tag := imageTag(image.Target)
	if repository == "" || tag == "" {
		return fmt.Errorf("delivery target %s is not tag-addressable", image.Target)
	}
	switch projection.shape {
	case imageRepositoryTag:
		if err := setNestedValue(generated, projection.path+".repository", repository); err != nil {
			return err
		}
		return setNestedValue(generated, projection.path+".tag", tag)
	case imageSplitRegistryRepositoryTag, imageDefaultRegistryRepositoryTag:
		registry, remainder, found := strings.Cut(repository, "/")
		if !found {
			return fmt.Errorf("delivery target %s has no registry", image.Target)
		}
		registryField := ".registry"
		if projection.shape == imageDefaultRegistryRepositoryTag {
			registryField = ".defaultRegistry"
		}
		for _, field := range [...]struct {
			suffix string
			value  string
		}{
			{registryField, registry},
			{".repository", remainder},
			{".tag", tag},
		} {
			if err := setNestedValue(generated, projection.path+field.suffix, field.value); err != nil {
				return err
			}
		}
		return nil
	case imageFullReference:
		return setNestedValue(generated, projection.path, image.Target)
	case imageRepositoryAsImageTag:
		if err := setNestedValue(generated, projection.path+".image", repository); err != nil {
			return err
		}
		return setNestedValue(generated, projection.path+".tag", tag)
	case imageRepositoryAsRepoTag:
		if err := setNestedValue(generated, projection.path+".repo", repository); err != nil {
			return err
		}
		return setNestedValue(generated, projection.path+".tag", tag)
	default:
		return errors.New("unsupported selected image value projection")
	}
}

func projectIstioControllerImages(generated map[string]any, images selectedImageIndex) error {
	pilot, err := selectedArtifactImage(
		images,
		"package/istiod",
		"registry1.dso.mil/ironbank/opensource/istio/pilot",
	)
	if err != nil {
		return err
	}
	proxy, err := selectedArtifactImage(
		images,
		"package/istiod",
		"registry1.dso.mil/ironbank/opensource/istio/proxyv2",
	)
	if err != nil {
		return err
	}
	pilotHub, pilotName := splitImageRepository(imageRepository(pilot.Target))
	proxyHub, proxyName := splitImageRepository(imageRepository(proxy.Target))
	if pilotHub == "" || pilotHub != proxyHub ||
		pilotName != "pilot" || proxyName != "proxyv2" ||
		imageTag(pilot.Target) != imageTag(proxy.Target) {
		return fmt.Errorf(
			"Istio pilot %s and proxy %s cannot share the official global hub/tag values",
			pilot.Target,
			proxy.Target,
		)
	}
	if err := setNestedValue(generated, "istiod.values.upstream.global.hub", pilotHub); err != nil {
		return err
	}
	return setNestedValue(generated, "istiod.values.upstream.global.tag", imageTag(pilot.Target))
}

func projectChartGlobalImageRegistries(generated map[string]any, images selectedImageIndex) error {
	for _, chart := range [...]struct {
		artifact   string
		repository string
		path       string
	}{
		{
			artifact:   "package/grafana",
			repository: "registry1.dso.mil/ironbank/big-bang/grafana/grafana-plugins",
			path:       "grafana.values.global.imageRegistry",
		},
		{
			artifact:   "package/kyverno",
			repository: "registry1.dso.mil/ironbank/opensource/kyverno",
			path:       "kyverno.values.global.image.registry",
		},
	} {
		image, err := selectedArtifactImage(images, chart.artifact, chart.repository)
		if err != nil {
			return err
		}
		registry, _, found := strings.Cut(imageRepository(image.Target), "/")
		if !found {
			return fmt.Errorf("delivery target %s has no registry", image.Target)
		}
		if err := setNestedValue(generated, chart.path, registry); err != nil {
			return err
		}
	}
	return nil
}

func splitImageRepository(repository string) (string, string) {
	index := strings.LastIndexByte(repository, '/')
	if index < 1 || index == len(repository)-1 {
		return "", ""
	}
	return repository[:index], repository[index+1:]
}
