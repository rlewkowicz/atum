package orchestration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
)

const (
	installIntentSchema = "atum.dev/orchestration-install/v1"
	installIntentPath   = ".atum/state/orchestration-install.json"
	installIntentLimit  = 64 << 10
	installInventoryMax = 16 << 20
)

type installIntent struct {
	SchemaVersion   string                `json:"schemaVersion"`
	Cluster         string                `json:"cluster"`
	DesiredSHA256   string                `json:"desiredSha256"`
	Release         config.ClusterRelease `json:"release"`
	InventoryPath   string                `json:"inventoryPath"`
	InventorySHA256 string                `json:"inventorySha256"`
	ToolchainSHA256 string                `json:"toolchainSha256"`
}

func (service Service) readInstallIntent() (installIntent, bool, error) {
	file, err := fssecure.OpenRegular(service.Project.Root, installIntentPath)
	if errors.Is(err, os.ErrNotExist) {
		return installIntent{}, false, nil
	}
	if err != nil {
		return installIntent{}, false, fmt.Errorf("open orchestration install checkpoint: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, installIntentLimit+1))
	closeErr := file.Close()
	if readErr != nil {
		return installIntent{}, false, fmt.Errorf("read orchestration install checkpoint: %w", readErr)
	}
	if closeErr != nil {
		return installIntent{}, false, fmt.Errorf("close orchestration install checkpoint: %w", closeErr)
	}
	if len(data) > installIntentLimit {
		return installIntent{}, false, errors.New("orchestration install checkpoint exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var intent installIntent
	if err := decoder.Decode(&intent); err != nil {
		return installIntent{}, false, fmt.Errorf("decode orchestration install checkpoint: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return installIntent{}, false, fmt.Errorf("decode orchestration install checkpoint: %w", err)
	}
	if err := service.validateInstallIntent(intent); err != nil {
		return installIntent{}, false, err
	}
	return intent, true, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("checkpoint contains multiple JSON values")
		}
		return err
	}
	return nil
}

func (service Service) validateInstallIntent(intent installIntent) error {
	if intent.SchemaVersion != installIntentSchema || intent.Cluster != service.Project.Desired.Project.Cluster {
		return errors.New("orchestration install checkpoint belongs to an unsupported schema or cluster")
	}
	for _, field := range [...]struct {
		name   string
		digest string
	}{
		{name: "desired", digest: intent.DesiredSHA256},
		{name: "inventory", digest: intent.InventorySHA256},
		{name: "toolchain", digest: intent.ToolchainSHA256},
	} {
		if !validCheckpointSHA256(field.digest) {
			return fmt.Errorf("orchestration install checkpoint has an invalid %s SHA-256", field.name)
		}
	}
	cleanInventory, err := fssecure.Relative(intent.InventoryPath)
	if err != nil || cleanInventory != intent.InventoryPath {
		return errors.New("orchestration install checkpoint has an invalid inventory path")
	}
	committed, found := releaseForKubernetes(service.Project.Desired.Orchestration.Releases, intent.Release.Kubernetes)
	if !found || !sameClusterRelease(committed, intent.Release) {
		return fmt.Errorf("orchestration install checkpoint release %s is absent from the exact committed ladder", intent.Release.Kubernetes)
	}
	return nil
}

func (service Service) validateResumableInstallIntent(intent installIntent, target config.ClusterRelease) error {
	if intent.DesiredSHA256 != service.Project.DesiredSHA256 || !sameClusterRelease(intent.Release, target) {
		return errors.New("orchestration install checkpoint does not match the exact current desired release")
	}
	if intent.InventoryPath != service.installInventoryPath() {
		return fmt.Errorf("orchestration install checkpoint inventory %s does not match %s", intent.InventoryPath, service.installInventoryPath())
	}
	return nil
}

func (service Service) resumableInstallPlan(
	intent installIntent,
	target config.ClusterRelease,
	current string,
) (UpgradePlan, error) {
	if err := service.validateResumableInstallIntent(intent, target); err != nil {
		return UpgradePlan{}, fmt.Errorf("resume interrupted cluster install: %w", err)
	}
	if current != "" && current != target.Kubernetes {
		return UpgradePlan{}, fmt.Errorf("interrupted install targets Kubernetes %s but the API reports %s", target.Kubernetes, current)
	}
	return UpgradePlan{
		Current: current,
		Target:  target.Kubernetes,
		Order:   InstallTarget,
		Steps:   []config.ClusterRelease{target},
	}, nil
}

func (service Service) validateCompletedInstallIntent(intent installIntent, state ClusterState) error {
	if state.Phase != "ready" || state.TargetKubernetes != "" ||
		state.RecordedKubernetes != intent.Release.Kubernetes ||
		state.Kubernetes != intent.Release.Kubernetes ||
		state.KubesprayVersion != intent.Release.Kubespray.Version ||
		state.KubesprayCommit != intent.Release.Kubespray.Commit {
		return errors.New("live cluster identity does not exactly complete the pending orchestration install checkpoint")
	}
	return nil
}

func (service Service) ensureInstallIntent(release config.ClusterRelease, inventoryPath string, toolchain Toolchain) error {
	want, err := service.installIntent(release, inventoryPath, toolchain)
	if err != nil {
		return err
	}
	current, exists, err := service.readInstallIntent()
	if err != nil {
		return err
	}
	if exists {
		if !sameInstallIntent(current, want) {
			return errors.New("existing orchestration install checkpoint does not match the exact release, inventory, and toolchain")
		}
		return nil
	}
	data, err := json.Marshal(want)
	if err != nil {
		return fmt.Errorf("encode orchestration install checkpoint: %w", err)
	}
	data = append(data, '\n')
	if err := fssecure.WriteRegular(service.Project.Root, installIntentPath, data, 0o600); err != nil {
		return fmt.Errorf("write orchestration install checkpoint: %w", err)
	}
	published, exists, err := service.readInstallIntent()
	if err != nil {
		return err
	}
	if !exists || !sameInstallIntent(published, want) {
		return errors.New("published orchestration install checkpoint failed exact verification")
	}
	return nil
}

func (service Service) installIntent(
	release config.ClusterRelease,
	inventoryPath string,
	toolchain Toolchain,
) (installIntent, error) {
	cleanInventory, err := fssecure.Relative(inventoryPath)
	if err != nil {
		return installIntent{}, fmt.Errorf("resolve install inventory: %w", err)
	}
	if cleanInventory != service.installInventoryPath() {
		return installIntent{}, fmt.Errorf("install inventory %s does not match committed path %s", cleanInventory, service.installInventoryPath())
	}
	if !sameClusterRelease(toolchain.Release, release) || !validCheckpointSHA256(toolchain.IdentitySHA256) {
		return installIntent{}, errors.New("prepared Kubespray toolchain does not exactly match the install release")
	}
	inventorySHA, err := regularProjectFileSHA256(
		service.Project.Root,
		cleanInventory,
		installInventoryMax,
	)
	if err != nil {
		return installIntent{}, fmt.Errorf("identify install inventory: %w", err)
	}
	return installIntent{
		SchemaVersion:   installIntentSchema,
		Cluster:         service.Project.Desired.Project.Cluster,
		DesiredSHA256:   service.Project.DesiredSHA256,
		Release:         release,
		InventoryPath:   cleanInventory,
		InventorySHA256: inventorySHA,
		ToolchainSHA256: toolchain.IdentitySHA256,
	}, nil
}

func (service Service) clearInstallIntent() error {
	if err := fssecure.RemoveRegular(service.Project.Root, installIntentPath); err != nil {
		return fmt.Errorf("clear completed orchestration install checkpoint: %w", err)
	}
	return nil
}

func (service Service) installInventoryPath() string {
	return filepath.Join(service.Project.Desired.Orchestration.Inventory, "hosts.yaml")
}

func validCheckpointSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func sameClusterRelease(left, right config.ClusterRelease) bool {
	leftData, leftErr := config.CanonicalJSON(left)
	rightData, rightErr := config.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func sameInstallIntent(left, right installIntent) bool {
	leftData, leftErr := config.CanonicalJSON(left)
	rightData, rightErr := config.CanonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}
