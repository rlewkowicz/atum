package update

import "atum/cli/config"

func resetRenderedImageInventory(desired *config.Document) {
	retained := desired.Delivery.Images[:0]
	for _, image := range desired.Delivery.Images {
		if image.Discovery == "configuration" ||
			image.Discovery == "controller-generated" {
			image.BigBangRefs = []string{}
			image.Consumers = []string{}
			retained = append(retained, image)
		}
	}
	desired.Delivery.Images = retained
}
