package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	SchemaVersion  string           `json:"schemaVersion"`
	DesiredSHA256  string           `json:"desiredSha256"`
	RootLockSHA256 string           `json:"rootLockSha256"`
	SourceSHA256   string           `json:"sourceSha256"`
	Delivery       config.ImageLock `json:"delivery"`
	Bundle         *config.Bundle   `json:"bundle,omitempty"`
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
	working, current, err := loadExecutionProject(canonical)
	if err != nil {
		return nil, BundleResult{}, err
	}
	if current && working.ExecutionBundle != nil {
		if result, reused, err := reuseExistingBundle(working); err != nil {
			return nil, BundleResult{}, err
		} else if reused {
			if err := pruneBundleArtifacts(working, working.ExecutionBundle); err != nil {
				return nil, BundleResult{}, err
			}
			return working, result, nil
		}
	}
	if working == nil {
		clone := *canonical
		working = &clone
	}
	working.ExecutionBundle = nil
	profile := canonical.Lock.Delivery.Profile
	if profile == "" {
		profile = canonical.Desired.Delivery.Policy.DefaultProfile
	}
	resolved, err := service.resolveLocalDelivery(ctx, working, PublishOptions{Profile: profile})
	if err != nil {
		return nil, BundleResult{}, err
	}
	if !canonical.Lock.Delivery.Pending() &&
		!matchesCommittedDelivery(resolved.lock, canonical.Lock.Delivery) {
		return nil, BundleResult{}, errors.New(
			"local delivery inputs differ from the committed image delivery lock",
		)
	}
	working.Lock.DesiredSHA256 = working.DesiredSHA256
	working.Lock.Delivery = resolved.lock
	if err := working.Validate(); err != nil {
		return nil, BundleResult{}, fmt.Errorf("validate local deployment lock: %w", err)
	}
	result, err := service.bundleLocked(ctx, working, BundleOptions{}, &resolved)
	if err != nil {
		return nil, BundleResult{}, err
	}
	if err := persistExecutionProject(working); err != nil {
		return nil, BundleResult{}, err
	}
	if err := pruneBundleArtifacts(working, working.ExecutionBundle); err != nil {
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
	if current && project != nil && project.ExecutionBundle != nil {
		return project, nil
	}
	return nil, errors.New("local deployment receipt is absent or stale; rerun the bundle command")
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
	if state.SchemaVersion != executionStateSchema ||
		state.DesiredSHA256 != canonical.DesiredSHA256 ||
		state.RootLockSHA256 != config.SHA256(canonical.LockData) {
		return nil, false, nil
	}
	project := *canonical
	project.Lock.Delivery = state.Delivery
	project.ExecutionBundle = state.Bundle
	if err := project.Validate(); err != nil {
		return nil, false, nil
	}
	sourceSHA, err := config.AtumSourceSHA256(&project)
	if err != nil {
		return nil, false, err
	}
	if state.SourceSHA256 != sourceSHA {
		return nil, false, nil
	}
	if state.Bundle != nil {
		if err := validateBundleReceipt(&project, state.Bundle); err != nil {
			return nil, false, nil
		}
	}
	return &project, true, nil
}

func persistExecutionProject(project *config.Project) error {
	if project == nil || project.Lock.Delivery.Pending() {
		return errors.New("complete local delivery receipt is required")
	}
	if project.ExecutionBundle != nil {
		if err := validateBundleReceipt(project, project.ExecutionBundle); err != nil {
			return fmt.Errorf("validate completed local deployment receipt: %w", err)
		}
	}
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return err
	}
	state := executionState{
		SchemaVersion:  executionStateSchema,
		DesiredSHA256:  project.DesiredSHA256,
		RootLockSHA256: config.SHA256(project.LockData),
		SourceSHA256:   sourceSHA,
		Delivery:       project.Lock.Delivery,
		Bundle:         project.ExecutionBundle,
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

func validateBundleReceipt(project *config.Project, bundle *config.Bundle) error {
	if project == nil || bundle == nil || bundle.Size < 1 ||
		!validSHA256Text(bundle.SHA256) || !validSHA256Text(bundle.AtumSourceSHA256) {
		return errors.New("deployment bundle receipt identity is invalid")
	}
	clean, err := fssecure.Relative(filepath.FromSlash(bundle.File))
	if err != nil || filepath.ToSlash(clean) != bundle.File {
		return errors.New("deployment bundle receipt path is invalid")
	}
	lockData, err := config.MarshalJSON(project.Lock)
	if err != nil {
		return fmt.Errorf("encode deployment delivery receipt: %w", err)
	}
	parts := strings.Split(bundle.File, "/")
	filename := "atum-bundle-" + bundle.SHA256 + ".tar"
	if len(parts) != 4 || parts[0] != ".atum" || parts[1] != "artifacts" ||
		parts[2] != config.SHA256(lockData) || parts[3] != filename {
		return errors.New("deployment bundle receipt path does not match its delivery identity")
	}
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return err
	}
	if bundle.AtumSourceSHA256 != sourceSHA {
		return errors.New("deployment bundle receipt does not match the tracked source identity")
	}
	hasReference := bundle.OCIReference != ""
	hasDigest := bundle.OCIDigest != ""
	if hasReference != hasDigest {
		return errors.New("deployment bundle OCI receipt is incomplete")
	}
	if hasReference {
		expected := project.Desired.Delivery.Registry.Host + "/seed-artifacts/atum-bundle:sha256-" + bundle.SHA256
		if bundle.OCIReference != expected ||
			!strings.HasPrefix(bundle.OCIDigest, "sha256:") ||
			!validSHA256Text(strings.TrimPrefix(bundle.OCIDigest, "sha256:")) {
			return errors.New("deployment bundle OCI receipt does not match its content identity")
		}
	}
	return nil
}
