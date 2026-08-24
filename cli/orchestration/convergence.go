package orchestration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitsnapshot"
)

const orchestrationInputSchema = "atum.dev/orchestration-input/v1"

type orchestrationInput struct {
	SchemaVersion   string               `json:"schemaVersion"`
	Cluster         string               `json:"cluster"`
	Configuration   config.Orchestration `json:"configuration"`
	SourceSHA256    string               `json:"sourceSha256"`
	InventoryPath   string               `json:"inventoryPath"`
	InventorySHA256 string               `json:"inventorySha256"`
}

// orchestrationInputSHA256 is the exact desired-state handoff to Kubespray:
// declarative orchestration configuration, tracked Atum-owned orchestration
// files, and the generated infrastructure inventory. Platform and CLI-only
// edits therefore do not cause an unnecessary cluster.yml replay.
func (service Service) orchestrationInputSHA256(inventoryPath string) (string, error) {
	if service.Project == nil {
		return "", fmt.Errorf("Atum project is not loaded")
	}
	cleanInventory, err := fssecure.Relative(inventoryPath)
	if err != nil {
		return "", fmt.Errorf("resolve orchestration inventory: %w", err)
	}
	if cleanInventory != service.installInventoryPath() {
		return "", fmt.Errorf(
			"orchestration inventory %s does not match committed path %s",
			cleanInventory,
			service.installInventoryPath(),
		)
	}
	snapshot, err := gitsnapshot.Load(service.Project.Root)
	if err != nil {
		return "", err
	}
	sourceSHA, err := snapshot.SHA256Prefix(service.Project.Desired.Orchestration.Directory)
	if err != nil {
		return "", fmt.Errorf("identify tracked orchestration source: %w", err)
	}
	inventorySHA, err := regularProjectFileSHA256(
		service.Project.Root,
		cleanInventory,
		installInventoryMax,
	)
	if err != nil {
		return "", fmt.Errorf("identify generated orchestration inventory: %w", err)
	}
	data, err := config.MarshalJSON(orchestrationInput{
		SchemaVersion:   orchestrationInputSchema,
		Cluster:         service.Project.Desired.Project.Cluster,
		Configuration:   service.Project.Desired.Orchestration,
		SourceSHA256:    sourceSHA,
		InventoryPath:   cleanInventory,
		InventorySHA256: inventorySHA,
	})
	if err != nil {
		return "", fmt.Errorf("encode orchestration input identity: %w", err)
	}
	return config.SHA256(data), nil
}

func (service Service) requireOrchestrationInput(
	inventoryPath string,
	expected string,
) error {
	actual, err := service.orchestrationInputSHA256(inventoryPath)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf(
			"orchestration inputs changed during convergence: found %s, want %s",
			actual,
			expected,
		)
	}
	return nil
}

func regularProjectFileSHA256(root, relative string, limit int64) (string, error) {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	written, readErr := io.Copy(hash, io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written > limit {
		return "", fmt.Errorf("file exceeds %d bytes", limit)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
