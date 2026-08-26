package orchestration

import (
	"path/filepath"
)

const installInventoryMax = 16 << 20

func (service Service) installInventoryPath() string {
	return filepath.Join(
		service.Project.Desired.Orchestration.Inventory,
		"hosts.yaml",
	)
}
