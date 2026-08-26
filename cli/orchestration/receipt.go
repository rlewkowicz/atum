package orchestration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"atum/cli/fssecure"
)

const (
	orchestrationReceiptSchema = "atum.dev/orchestration-receipt/v1"
	orchestrationReceiptPath   = ".atum/state/orchestration-receipt.json"
	orchestrationReceiptLimit  = 64 << 10
)

type orchestrationReceipt struct {
	SchemaVersion       string `json:"schemaVersion"`
	Cluster             string `json:"cluster"`
	Kubernetes          string `json:"kubernetes"`
	KubesprayVersion    string `json:"kubesprayVersion"`
	KubesprayCommit     string `json:"kubesprayCommit"`
	OrchestrationSHA256 string `json:"orchestrationSha256"`
	NextKubernetes      string `json:"nextKubernetes,omitempty"`
}

func (service Service) readOrchestrationReceipt() (orchestrationReceipt, bool, error) {
	file, err := fssecure.OpenRegular(service.Project.Root, orchestrationReceiptPath)
	if errors.Is(err, os.ErrNotExist) {
		return orchestrationReceipt{}, false, nil
	}
	if err != nil {
		return orchestrationReceipt{}, false, fmt.Errorf("open orchestration receipt: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, orchestrationReceiptLimit+1))
	closeErr := file.Close()
	if readErr != nil {
		return orchestrationReceipt{}, false, fmt.Errorf("read orchestration receipt: %w", readErr)
	}
	if closeErr != nil {
		return orchestrationReceipt{}, false, fmt.Errorf("close orchestration receipt: %w", closeErr)
	}
	if len(data) > orchestrationReceiptLimit {
		return orchestrationReceipt{}, false, errors.New("orchestration receipt exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt orchestrationReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return orchestrationReceipt{}, false, fmt.Errorf("decode orchestration receipt: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return orchestrationReceipt{}, false, fmt.Errorf("decode orchestration receipt: %w", err)
	}
	if err := service.validateOrchestrationReceipt(receipt); err != nil {
		return orchestrationReceipt{}, false, err
	}
	return receipt, true, nil
}

func (service Service) validateOrchestrationReceipt(receipt orchestrationReceipt) error {
	if receipt.SchemaVersion != orchestrationReceiptSchema ||
		receipt.Cluster != service.Project.Desired.Project.Cluster {
		return errors.New("orchestration receipt belongs to an unsupported schema or cluster")
	}
	release, found := releaseForKubernetes(
		service.Project.Desired.Orchestration.Releases,
		receipt.Kubernetes,
	)
	if !found || release.Kubespray.Version != receipt.KubesprayVersion ||
		release.Kubespray.Commit != receipt.KubesprayCommit {
		return fmt.Errorf(
			"orchestration receipt Kubernetes %s has no exact committed Kubespray release",
			receipt.Kubernetes,
		)
	}
	if !validCheckpointSHA256(receipt.OrchestrationSHA256) {
		return errors.New("orchestration receipt has an invalid input SHA-256")
	}
	if receipt.NextKubernetes != "" {
		next, found := releaseForKubernetes(
			service.Project.Desired.Orchestration.Releases,
			receipt.NextKubernetes,
		)
		if !found || releaseIndex(service.Project.Desired.Orchestration.Releases, next.Kubernetes) !=
			releaseIndex(service.Project.Desired.Orchestration.Releases, release.Kubernetes)+1 {
			return fmt.Errorf(
				"orchestration receipt checkpoint does not advance one exact release from %s to %s",
				receipt.Kubernetes,
				receipt.NextKubernetes,
			)
		}
	}
	return nil
}

func (service Service) writeOrchestrationReceipt(state ClusterState) error {
	receipt := orchestrationReceipt{
		SchemaVersion:       orchestrationReceiptSchema,
		Cluster:             service.Project.Desired.Project.Cluster,
		Kubernetes:          state.RecordedKubernetes,
		KubesprayVersion:    state.KubesprayVersion,
		KubesprayCommit:     state.KubesprayCommit,
		OrchestrationSHA256: state.OrchestrationSHA256,
		NextKubernetes:      state.TargetKubernetes,
	}
	if err := service.validateOrchestrationReceipt(receipt); err != nil {
		return err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode orchestration receipt: %w", err)
	}
	data = append(data, '\n')
	if err := fssecure.WriteRegular(
		service.Project.Root,
		orchestrationReceiptPath,
		data,
		0o600,
	); err != nil {
		return fmt.Errorf("write orchestration receipt: %w", err)
	}
	return nil
}
