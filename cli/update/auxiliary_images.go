package update

import (
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
	const operatorVersion = "0.1.1"

	byID := make(map[string]int, len(desired.Delivery.Images))
	for index := range desired.Delivery.Images {
		byID[desired.Delivery.Images[index].ID] = index
	}
	prefix := desired.Delivery.Policy.RuntimeRegistryPrefix
	canonical := []config.Image{
		{
			ID: "operator-builder", Family: "build-system", Version: "1.26.0",
			Target: prefix + "operator-builder:1.26.0", Scopes: []string{"build-system"},
			Runtime: false, License: "BSD-3-Clause", Provenance: "docker.io/library/golang",
			Consumers: []string{"configuration/atum-operator"}, BigBangRefs: []string{},
			Discovery: "configuration", Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type: "mirror", Source: "docker.io/library/golang:1.26.0-alpine",
			}},
		},
		{
			ID: "atum-operator", Family: "platform-control", Version: operatorVersion,
			Target: prefix + "atum-operator:" + operatorVersion, Scopes: []string{"bigbang"},
			Runtime: true, License: "Apache-2.0", Provenance: "https://github.com/rlewkowicz/atum",
			Consumers: []string{"platform/apps/atum-operator"}, BigBangRefs: []string{},
			Discovery: "first-party", Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type: "build", BakeTarget: "atum-operator",
				Materials: []string{"platform/build/docker/Dockerfile.operator", "cmd/atum-operator", "operator", "go.mod", "go.sum"},
			}},
		},
	}
	for _, image := range canonical {
		if index, exists := byID[image.ID]; exists {
			desired.Delivery.Images[index] = image
			continue
		}
		byID[image.ID] = len(desired.Delivery.Images)
		desired.Delivery.Images = append(desired.Delivery.Images, image)
	}
}
