package update

import (
	"strings"

	"atum/cli/config"
)

func resetRenderedImageInventory(desired *config.Document) {
	retained := desired.Delivery.Images[:0]
	for _, image := range desired.Delivery.Images {
		if image.Discovery == "configuration" ||
			image.Discovery == "first-party" ||
			image.Discovery == "controller-generated" {
			image.BigBangRefs = []string{}
			image.Consumers = []string{}
			retained = append(retained, image)
		}
	}
	desired.Delivery.Images = retained
	ensureOperatorImages(desired)
}

func ensureOperatorImages(desired *config.Document) {
	byID := make(map[string]struct{}, len(desired.Delivery.Images))
	for _, image := range desired.Delivery.Images { byID[image.ID] = struct{}{} }
	prefix := desired.Delivery.Policy.RuntimeRegistryPrefix
	if _, exists := byID["operator-builder"]; !exists {
		desired.Delivery.Images = append(desired.Delivery.Images, config.Image{
			ID: "operator-builder", Family: "build-system", Version: "1.26.0",
			Target: prefix + "operator-builder:1.26.0", Scopes: []string{"build-system"},
			Runtime: false, License: "BSD-3-Clause", Provenance: "docker.io/library/golang",
			Consumers: []string{"configuration/atum-operator"}, BigBangRefs: []string{},
			Discovery: "configuration", Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type: "mirror", Source: "docker.io/library/golang:1.26.0-alpine",
				Digest: "sha256:" + strings.Repeat("0", 64),
			}},
		})
	}
	if _, exists := byID["atum-operator"]; !exists {
		desired.Delivery.Images = append(desired.Delivery.Images, config.Image{
			ID: "atum-operator", Family: "platform-control", Version: "0.1.0",
			Target: prefix + "atum-operator:0.1.0", Scopes: []string{"bigbang"},
			Runtime: true, License: "Apache-2.0", Provenance: "https://github.com/rlewkowicz/atum",
			Consumers: []string{"platform/apps/atum-operator"}, BigBangRefs: []string{},
			Discovery: "first-party", Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type: "build", BakeTarget: "atum-operator",
				Materials: []string{"platform/build/docker/Dockerfile.operator", "cmd/atum-operator", "operator", "go.mod", "go.sum"},
			}},
		})
	}
}
