package update

import (
	"testing"

	"atum/cli/config"
)

func TestOfficialBlackboxExporterImageAndValuesAreProjected(t *testing.T) {
	t.Parallel()

	const (
		ironBank = "registry1.dso.mil/ironbank/opensource/prometheus/blackbox_exporter"
		target   = "10.77.0.9:32443/atum/blackbox-exporter:v0.28.0"
	)
	spec, err := officialImageFor(
		ironBank+":v0.28.0",
		"package/monitoring",
		"1.35.4",
		nil,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if spec.id != "blackbox-exporter" ||
		spec.source != "quay.io/prometheus/blackbox-exporter:v0.28.0" ||
		spec.license != "Apache-2.0" {
		t.Fatalf("official blackbox exporter mapping = %#v", spec)
	}

	images := selectedImageIndex{
		{
			artifact:   "package/monitoring",
			repository: ironBank,
		}: {{
			ID:          spec.id,
			Version:     "0.28.0",
			Target:      target,
			BigBangRefs: []string{ironBank + ":v0.28.0"},
			Consumers:   []string{"package/monitoring"},
			Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type:   "mirror",
				Source: spec.source,
			}},
		}},
	}
	generated := make(map[string]any)
	if err := projectMonitoringBlackboxImage(generated, images); err != nil {
		t.Fatal(err)
	}
	blackbox := mapAt(generated, "monitoring", "values", "blackboxExporter")
	image := mapAt(blackbox, "image")
	if stringAt(image, "registry") != "10.77.0.9:32443" ||
		stringAt(image, "repository") != "atum/blackbox-exporter" ||
		stringAt(image, "tag") != "v0.28.0" {
		t.Fatalf("projected blackbox exporter image = %#v", image)
	}
	if stringAt(mapAt(blackbox, "global"), "imageRegistry") != "10.77.0.9:32443" {
		t.Fatalf("projected blackbox exporter global registry = %#v", blackbox["global"])
	}
}

func TestOfficialRedisModulePathsAreProjected(t *testing.T) {
	t.Parallel()

	const ironBankRedis = "registry1.dso.mil/ironbank/opensource/redis/redis8-slim"
	images := selectedImageIndex{
		{
			artifact:   "package/redis",
			repository: ironBankRedis,
		}: {{
			ID:          "redis-8-8-0",
			Version:     "8.8.0",
			BigBangRefs: []string{ironBankRedis + ":8.8.0"},
			Consumers:   []string{"package/redis"},
			Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/library/redis:8.8.0",
			}},
		}},
	}
	generated := make(map[string]any)
	if err := projectRedisModuleCompatibility(generated, images); err != nil {
		t.Fatal(err)
	}
	packages := generated["packages"].(map[string]any)
	redis := packages["redis"].(map[string]any)
	values := redis["values"].(map[string]any)
	upstream := values["upstream"].(map[string]any)
	if got := upstream["commonConfiguration"]; got != redisModuleConfiguration {
		t.Fatalf("projected Redis configuration = %#v, want %#v", got, redisModuleConfiguration)
	}
}

func TestKialiImageNameAndVersionAreProjectedSeparately(t *testing.T) {
	t.Parallel()

	const (
		target     = "10.77.0.9:32443/atum/kiali:v2.30.0-mirror-set-deadbeef"
		deployment = "kiali.values.upstream.cr.spec.deployment"
	)
	generated := make(map[string]any)
	if err := projectImageValue(
		generated,
		imageNameVersion("package/kiali", "registry1.dso.mil/ironbank/opensource/kiali/kiali", deployment),
		config.Image{Target: target},
	); err != nil {
		t.Fatal(err)
	}
	kialiDeployment := mapAt(generated, "kiali", "values", "upstream", "cr", "spec", "deployment")
	if got := stringAt(kialiDeployment, "image_name"); got != "10.77.0.9:32443/atum/kiali" {
		t.Fatalf("Kiali image_name = %q", got)
	}
	if got := stringAt(kialiDeployment, "image_version"); got != "v2.30.0-mirror-set-deadbeef" {
		t.Fatalf("Kiali image_version = %q", got)
	}
}
