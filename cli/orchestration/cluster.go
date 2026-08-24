package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/kube"

	"github.com/Masterminds/semver/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	identityNamespace = "kube-system"
	identityName      = "atum-system"
	identitySchema    = "atum.dev/cluster-identity/v1"
)

var (
	ErrClusterAbsent      = errors.New("cluster kubeconfig is absent")
	ErrClusterUnavailable = errors.New("cluster API is unavailable")
)

type UpgradeOrder string

type ConvergenceMode uint8

const (
	InstallTarget    UpgradeOrder = "install"
	FinalizeInstall  UpgradeOrder = "install-finalize"
	ReconcileCurrent UpgradeOrder = "reconcile"
	PlatformFirst    UpgradeOrder = "platform-first"
	KubernetesFirst  UpgradeOrder = "kubernetes-first"
	AlreadyCurrent   UpgradeOrder = "current"
)

const (
	ApplyConvergence ConvergenceMode = iota + 1
	UpgradeConvergence
	FullConvergence
)

type ClusterState struct {
	Kubernetes          string
	RecordedKubernetes  string
	KubesprayVersion    string
	KubesprayCommit     string
	BigBangVersion      string
	BigBangCommit       string
	PlatformConstraints []config.CompatibilityConstraint
	OrchestrationSHA256 string
	Phase               string
	TargetKubernetes    string
}

type UpgradePlan struct {
	Current      string
	Target       string
	Order        UpgradeOrder
	ResumeFrom   string
	ResumeTarget string
	Steps        []config.ClusterRelease
}

type clusterClient = kube.Observer

func (service Service) RecordPlatform(ctx context.Context) error {
	client, state, err := service.validatedPlatformState(ctx)
	if err != nil {
		return err
	}
	if err := service.validateLiveBigBang(ctx, client, service.Project.Desired.Platform.BigBang.Version, service.Project.Desired.Platform.BigBang.Commit); err != nil {
		return err
	}
	state.BigBangVersion = service.Project.Desired.Platform.BigBang.Version
	state.BigBangCommit = service.Project.Desired.Platform.BigBang.Commit
	state.PlatformConstraints = append(
		[]config.CompatibilityConstraint(nil),
		service.Project.Lock.Compatibility.Constraints...,
	)
	return service.writeIdentity(ctx, state, nil)
}

func (service Service) ValidatePlatformPrerequisites(ctx context.Context) error {
	client, state, err := service.validatedPlatformState(ctx)
	if err != nil {
		return err
	}
	_, err = service.bigBangTransition(ctx, client, state)
	return err
}

func (service Service) validatedPlatformState(ctx context.Context) (*clusterClient, ClusterState, error) {
	if service.Project == nil {
		return nil, ClusterState{}, errors.New("Atum project is not loaded")
	}
	client, err := service.clusterClient()
	if err != nil {
		return nil, ClusterState{}, err
	}
	state, err := service.discoverState(ctx, client)
	if err != nil {
		return nil, ClusterState{}, err
	}
	if err := service.validatePlatformState(state); err != nil {
		return nil, ClusterState{}, err
	}
	return client, state, nil
}

func (service Service) validatePlatformState(state ClusterState) error {
	if state.Phase != "ready" {
		return fmt.Errorf("platform mutation requires a ready Kubernetes identity, found phase %q", state.Phase)
	}
	if err := service.validateClusterIdentity(state); err != nil {
		return err
	}
	constraints, err := parsePlatformConstraints(service.Project.Lock.Compatibility.Constraints)
	if err != nil {
		return fmt.Errorf("parse desired platform Kubernetes constraints: %w", err)
	}
	kubernetesVersion, _ := semver.NewVersion(state.Kubernetes)
	if unsupported := firstUnsupportedConstraint(constraints, kubernetesVersion); unsupported != "" {
		return fmt.Errorf("desired platform constraint %s does not support live Kubernetes %s", unsupported, state.Kubernetes)
	}
	return nil
}

func (service Service) validateClusterIdentity(state ClusterState) error {
	release, tracked := releaseForKubernetes(service.Project.Desired.Orchestration.Releases, state.Kubernetes)
	if !tracked || state.KubesprayVersion != release.Kubespray.Version || state.KubesprayCommit != release.Kubespray.Commit {
		return fmt.Errorf("Kubernetes %s has no exact committed Kubespray identity", state.Kubernetes)
	}
	return nil
}

func (service Service) clusterClient() (*clusterClient, error) {
	kubeconfig := service.environment("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(
			service.Project.Root,
			service.Project.Desired.Orchestration.Inventory,
			"artifacts",
			"admin.conf",
		)
	}
	client, err := kube.New(kubeconfig)
	if errors.Is(err, kube.ErrKubeconfigAbsent) {
		return nil, ErrClusterAbsent
	}
	return client, err
}

func (service Service) discoverState(ctx context.Context, client *clusterClient) (ClusterState, error) {
	version, err := client.ServerVersion(ctx)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return ClusterState{}, contextErr
		}
		if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
			return ClusterState{}, fmt.Errorf("discover live Kubernetes version: %w", err)
		}
		return ClusterState{}, fmt.Errorf("%w: discover live Kubernetes version: %v", ErrClusterUnavailable, err)
	}
	kubernetesVersion, err := canonicalKubernetesVersion(version)
	if err != nil {
		return ClusterState{}, err
	}
	state := ClusterState{Kubernetes: kubernetesVersion}
	identity, found, err := client.ConfigMapData(ctx, identityNamespace, identityName)
	if err == nil && found {
		if identity["schemaVersion"] != identitySchema || identity["cluster"] != service.Project.Desired.Project.Cluster {
			return ClusterState{}, errors.New("live atum-system identity belongs to an unsupported schema or cluster")
		}
		state.KubesprayVersion = identity["kubesprayVersion"]
		state.KubesprayCommit = identity["kubesprayCommit"]
		state.RecordedKubernetes = identity["kubernetes"]
		state.BigBangVersion = identity["bigBangVersion"]
		state.BigBangCommit = identity["bigBangCommit"]
		state.OrchestrationSHA256 = identity["orchestrationSha256"]
		if err := json.Unmarshal([]byte(identity["platformConstraints"]), &state.PlatformConstraints); err != nil {
			return ClusterState{}, fmt.Errorf("decode live platform constraints: %w", err)
		}
		state.Phase = identity["phase"]
		state.TargetKubernetes = identity["targetKubernetes"]
		if err := service.validateDiscoveredIdentity(state); err != nil {
			return ClusterState{}, err
		}
		return state, nil
	}
	if err != nil {
		return ClusterState{}, fmt.Errorf("read live cluster identity: %w", err)
	}
	return state, nil
}

func (service Service) validateDiscoveredIdentity(state ClusterState) error {
	if state.RecordedKubernetes == "" ||
		(state.RecordedKubernetes != state.Kubernetes && state.TargetKubernetes != state.Kubernetes) {
		return fmt.Errorf("live identity records Kubernetes %q but the API server reports %s", state.RecordedKubernetes, state.Kubernetes)
	}
	bigBangFields := 0
	for _, value := range [...]string{state.BigBangVersion, state.BigBangCommit} {
		if value != "" {
			bigBangFields++
		}
	}
	if bigBangFields != 0 && bigBangFields != 2 {
		return errors.New("live cluster identity has an incomplete Big Bang source")
	}
	if (bigBangFields == 0) != (len(state.PlatformConstraints) == 0) {
		return errors.New("live cluster identity has an incomplete platform compatibility record")
	}
	if _, err := parsePlatformConstraints(state.PlatformConstraints); err != nil {
		return fmt.Errorf("validate live platform constraints: %w", err)
	}
	if state.OrchestrationSHA256 != "" && !validCheckpointSHA256(state.OrchestrationSHA256) {
		return errors.New("live cluster identity has an invalid orchestration input SHA-256")
	}
	switch state.Phase {
	case "ready":
		if state.TargetKubernetes != "" {
			return errors.New("ready cluster identity retains an upgrade target")
		}
	case "upgrading":
		if state.TargetKubernetes == "" {
			return errors.New("upgrading cluster identity has no target Kubernetes release")
		}
		releases := service.Project.Desired.Orchestration.Releases
		recordedIndex := releaseIndex(releases, state.RecordedKubernetes)
		targetIndex := releaseIndex(releases, state.TargetKubernetes)
		if recordedIndex < 0 || targetIndex != recordedIndex+1 {
			return fmt.Errorf("upgrading cluster identity does not advance one exact release from %s to %s", state.RecordedKubernetes, state.TargetKubernetes)
		}
	default:
		return fmt.Errorf("live cluster identity has unsupported phase %q", state.Phase)
	}
	return nil
}

func (service Service) bigBangTransition(ctx context.Context, client *clusterClient, state ClusterState) (bool, error) {
	live, err := service.liveBigBang(ctx, client)
	if err != nil {
		return false, err
	}
	if live == nil {
		if state.BigBangVersion == "" {
			return false, nil
		}
		return false, errors.New("recorded Big Bang source is absent from the live cluster")
	}
	if state.BigBangVersion != "" && liveBigBangIdentityMatches(live, state.BigBangVersion, state.BigBangCommit) {
		return false, validateLiveBigBangSource(live, state.BigBangVersion, state.BigBangCommit)
	}
	desired := service.Project.Desired.Platform.BigBang
	if liveBigBangIdentityMatches(live, desired.Version, desired.Commit) {
		// An exact desired ref with incomplete readiness is a known interrupted
		// platform handoff. The platform convergence path owns the bounded Flux
		// wait and records the new identity only after the source is Ready.
		return state.BigBangVersion != desired.Version || state.BigBangCommit != desired.Commit, nil
	}
	return false, errors.New("live Big Bang source matches neither the recorded nor desired immutable source")
}

func (service Service) validateLiveBigBang(ctx context.Context, client *clusterClient, version, commit string) error {
	live, err := service.liveBigBang(ctx, client)
	if err != nil {
		return err
	}
	if live == nil {
		return errors.New("recorded Big Bang source is absent from the live cluster")
	}
	return validateLiveBigBangSource(live, version, commit)
}

func (service Service) liveBigBang(ctx context.Context, client *clusterClient) (*kube.Object, error) {
	repository, found, err := client.GetResource(ctx, kube.GitRepository, "bigbang", "bigbang")
	if !found && err == nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read live Big Bang source: %w", err)
	}
	return repository, nil
}

func validateLiveBigBangSource(repository *kube.Object, version, commit string) error {
	ref, found, err := unstructured.NestedStringMap(repository.Object, "spec", "ref")
	if err != nil || !found || ref["tag"] != version || ref["commit"] != commit {
		return fmt.Errorf("live Big Bang source does not match recorded tag %s at %s", version, commit)
	}
	revision, found, err := unstructured.NestedString(repository.Object, "status", "artifact", "revision")
	if err != nil || !found || (revision != commit && !strings.HasSuffix(revision, ":"+commit)) {
		return fmt.Errorf("live Big Bang source has not fetched recorded commit %s", commit)
	}
	conditions, found, err := unstructured.NestedSlice(repository.Object, "status", "conditions")
	if err != nil || !found {
		return errors.New("live Big Bang source has no readiness status")
	}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok || condition["type"] != "Ready" || condition["status"] != "True" {
			continue
		}
		observed, _, _ := unstructured.NestedInt64(condition, "observedGeneration")
		if observed == repository.GetGeneration() {
			return nil
		}
	}
	return errors.New("live Big Bang source is not Ready at its current generation")
}

func liveBigBangIdentityMatches(repository *kube.Object, version, commit string) bool {
	ref, found, err := unstructured.NestedStringMap(repository.Object, "spec", "ref")
	return err == nil && found && ref["tag"] == version && ref["commit"] == commit
}

func (service Service) identityForRelease(release config.ClusterRelease, previous ClusterState) ClusterState {
	return ClusterState{
		Kubernetes:          release.Kubernetes,
		KubesprayVersion:    release.Kubespray.Version,
		KubesprayCommit:     release.Kubespray.Commit,
		BigBangVersion:      previous.BigBangVersion,
		BigBangCommit:       previous.BigBangCommit,
		PlatformConstraints: append([]config.CompatibilityConstraint(nil), previous.PlatformConstraints...),
		OrchestrationSHA256: previous.OrchestrationSHA256,
		Phase:               "ready",
	}
}

type namedConstraint struct {
	id         string
	constraint *semver.Constraints
}

func parsePlatformConstraints(entries []config.CompatibilityConstraint) ([]namedConstraint, error) {
	parsed := make([]namedConstraint, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if entry.ID == "" || entry.Constraint == "" {
			return nil, errors.New("platform constraint requires an id and expression")
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			return nil, fmt.Errorf("platform constraint id %q is duplicated", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		constraint, err := semver.NewConstraint(entry.Constraint)
		if err != nil {
			return nil, fmt.Errorf("%s=%s: %w", entry.ID, entry.Constraint, err)
		}
		parsed[index] = namedConstraint{id: entry.ID, constraint: constraint}
	}
	return parsed, nil
}

func firstUnsupportedConstraint(constraints []namedConstraint, versions ...*semver.Version) string {
	for _, version := range versions {
		for _, constraint := range constraints {
			if !constraint.constraint.Check(version) {
				return constraint.id + "=" + constraint.constraint.String()
			}
		}
	}
	return ""
}

func canonicalKubernetesVersion(raw string) (string, error) {
	version, err := semver.NewVersion(strings.TrimPrefix(raw, "v"))
	if err != nil || version.Prerelease() != "" || version.Metadata() != "" {
		return "", fmt.Errorf("live Kubernetes version %q is not a stable semantic release", raw)
	}
	return version.String(), nil
}
