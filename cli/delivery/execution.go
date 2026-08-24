package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/update"
)

const (
	executionStatePath   = ".atum/state/deployment.lock.json"
	executionStateSchema = "atum.dev/deployment-state/v1"
	executionStateLimit  = 8 << 20
)

type executionState struct {
	SchemaVersion string      `json:"schemaVersion"`
	DesiredSHA256 string      `json:"desiredSha256"`
	SourceSHA256  string      `json:"sourceSha256"`
	ResolvedLock  config.Lock `json:"resolvedLock"`
}

// ResolveForApply resolves and bundles the default deployment profile without
// replacing atum.lock.json. The complete result is stored beneath ignored
// local state and remains bound to the current desired document, build graph,
// and tracked working-tree source.
func (service *Service) ResolveForApply(ctx context.Context) (*config.Project, BundleResult, error) {
	unlock, err := update.LockProject(ctx, service.root)
	if err != nil {
		return nil, BundleResult{}, fmt.Errorf("lock project state: %w", err)
	}
	defer unlock()
	if err := update.RecoverLocked(service.root); err != nil {
		return nil, BundleResult{}, fmt.Errorf("recover interrupted update: %w", err)
	}
	canonical, err := config.Load(service.root)
	if err != nil {
		return nil, BundleResult{}, err
	}
	if !canonical.Lock.Delivery.Pending() && canonical.Lock.Bundle != nil {
		if result, reused, err := reuseExistingBundle(canonical); err != nil {
			return nil, BundleResult{}, err
		} else if reused {
			if err := pruneBundleArtifacts(canonical, canonical.Lock.Bundle); err != nil {
				return nil, BundleResult{}, err
			}
			return canonical, result, nil
		}
	}

	working, current, err := loadExecutionProject(canonical)
	if err != nil {
		return nil, BundleResult{}, err
	}
	if current && working.Lock.Bundle != nil {
		if result, reused, err := reuseExistingBundle(working); err != nil {
			return nil, BundleResult{}, err
		} else if reused {
			if err := pruneBundleArtifacts(working, canonical.Lock.Bundle, working.Lock.Bundle); err != nil {
				return nil, BundleResult{}, err
			}
			return working, result, nil
		}
	}
	if working == nil {
		clone := *canonical
		working = &clone
	}
	working.Lock.Bundle = nil
	profile := canonical.Lock.Delivery.Profile
	if profile == "" {
		profile = canonical.Desired.Delivery.Policy.DefaultProfile
	}
	resolved, err := service.resolveLocalDelivery(ctx, working, PublishOptions{Profile: profile})
	if err != nil {
		return nil, BundleResult{}, err
	}
	if !canonical.Lock.Delivery.Pending() && !reflect.DeepEqual(resolved.lock, canonical.Lock.Delivery) {
		return nil, BundleResult{}, errors.New("local reproduction differs from the committed image delivery lock")
	}
	working.Lock.DesiredSHA256 = working.DesiredSHA256
	working.Lock.Delivery = resolved.lock
	working.Lock.Bundle = nil
	if err := working.Validate(); err != nil {
		return nil, BundleResult{}, fmt.Errorf("validate local deployment lock: %w", err)
	}
	result, err := service.bundleLocked(ctx, working, BundleOptions{}, &resolved, false)
	if err != nil {
		return nil, BundleResult{}, err
	}
	if err := persistExecutionProject(working); err != nil {
		return nil, BundleResult{}, err
	}
	if err := pruneBundleArtifacts(working, canonical.Lock.Bundle, working.Lock.Bundle); err != nil {
		return nil, BundleResult{}, err
	}
	return working, result, nil
}

// LoadExecutionProject returns the exact ignored deployment state selected by
// ResolveForApply after the caller reacquires the project-wide read lock.
func LoadExecutionProject(canonical *config.Project) (*config.Project, error) {
	if canonical == nil {
		return nil, errors.New("Atum project is not loaded")
	}
	project, current, err := loadExecutionProject(canonical)
	if err != nil {
		return nil, err
	}
	if current && project != nil && project.Lock.Bundle != nil {
		return project, nil
	}
	if !canonical.Lock.Delivery.Pending() && canonical.Lock.Bundle != nil {
		sourceSHA, err := config.AtumSourceSHA256(canonical)
		if err != nil {
			return nil, err
		}
		if sourceSHA == canonical.Lock.Bundle.AtumSourceSHA256 {
			return canonical, nil
		}
	}
	return nil, errors.New("local deployment state is absent or stale")
}

func loadExecutionProject(canonical *config.Project) (*config.Project, bool, error) {
	file, err := fssecure.OpenRegular(canonical.Root, executionStatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open local deployment state: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, executionStateLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, false, errors.Join(readErr, closeErr)
	}
	if len(data) > executionStateLimit {
		return nil, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state executionState
	if err := decoder.Decode(&state); err != nil {
		return nil, false, nil
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false, nil
	}
	if state.SchemaVersion != executionStateSchema || state.DesiredSHA256 != canonical.DesiredSHA256 {
		return nil, false, nil
	}
	project := *canonical
	project.Lock = state.ResolvedLock
	bundle := project.Lock.Bundle
	project.Lock.Bundle = nil
	if err := project.Validate(); err != nil {
		return nil, false, nil
	}
	project.Lock.Bundle = bundle
	sourceSHA, err := config.AtumSourceSHA256(&project)
	if err != nil {
		return nil, false, err
	}
	if state.SourceSHA256 != sourceSHA {
		project.Lock.Bundle = nil
		return &project, false, nil
	}
	if bundle == nil || bundle.AtumSourceSHA256 != sourceSHA {
		project.Lock.Bundle = nil
		return &project, false, nil
	}
	if err := project.Validate(); err != nil {
		project.Lock.Bundle = nil
		return &project, false, nil
	}
	return &project, true, nil
}

func persistExecutionProject(project *config.Project) error {
	if project == nil || project.Lock.Bundle == nil {
		return errors.New("complete local deployment state is required")
	}
	if err := project.Validate(); err != nil {
		return fmt.Errorf("validate completed local deployment state: %w", err)
	}
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return err
	}
	state := executionState{
		SchemaVersion: executionStateSchema,
		DesiredSHA256: project.DesiredSHA256,
		SourceSHA256:  sourceSHA,
		ResolvedLock:  project.Lock,
	}
	data, err := config.MarshalJSON(state)
	if err != nil {
		return fmt.Errorf("encode local deployment state: %w", err)
	}
	if err := fssecure.WriteRegular(project.Root, executionStatePath, data, 0o600); err != nil {
		return fmt.Errorf("write local deployment state: %w", err)
	}
	return nil
}
