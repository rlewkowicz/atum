package orchestration

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/kube"

	"github.com/Masterminds/semver/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	OrchestrationSHA256 string
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

func (service Service) ValidatePlatformPrerequisites(ctx context.Context) error {
	client, state, err := service.validatedPlatformState(ctx)
	if err != nil {
		return err
	}
	_, err = service.bigBangObservation(ctx, client)
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
	if state.RecordedKubernetes != state.Kubernetes {
		return fmt.Errorf("orchestration receipt records Kubernetes %q but the API server reports %s", state.RecordedKubernetes, state.Kubernetes)
	}
	release, tracked := releaseForKubernetes(service.Project.Desired.Orchestration.Releases, state.Kubernetes)
	if !tracked || state.KubesprayVersion != release.Kubespray.Version ||
		state.KubesprayCommit != release.Kubespray.Commit {
		return fmt.Errorf("Kubernetes %s has no exact committed Kubespray receipt", state.Kubernetes)
	}
	return nil
}

func (service Service) clusterClient() (*clusterClient, error) {
	kubeconfig := service.environment("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(service.Project.Root, service.Project.Desired.Orchestration.Inventory, "artifacts", "admin.conf")
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
	receipt, found, err := service.readOrchestrationReceipt()
	if err != nil {
		return ClusterState{}, err
	}
	if !found {
		return state, nil
	}
	state.RecordedKubernetes = receipt.Kubernetes
	state.KubesprayVersion = receipt.KubesprayVersion
	state.KubesprayCommit = receipt.KubesprayCommit
	state.OrchestrationSHA256 = receipt.OrchestrationSHA256
	state.TargetKubernetes = receipt.NextKubernetes
	if state.RecordedKubernetes != state.Kubernetes && state.TargetKubernetes != state.Kubernetes {
		return ClusterState{}, fmt.Errorf(
			"orchestration receipt records Kubernetes %q with checkpoint %q but the API server reports %s",
			state.RecordedKubernetes, state.TargetKubernetes, state.Kubernetes,
		)
	}
	return state, nil
}

func (service Service) bigBangObservation(
	ctx context.Context,
	client *clusterClient,
) (kube.FluxRootObservation, error) {
	artifact, err := service.bigBangArtifact()
	if err != nil {
		return kube.FluxRootObservation{}, err
	}
	url, tag, err := artifact.FluxOCITarget()
	if err != nil {
		return kube.FluxRootObservation{}, err
	}
	observation, err := client.ObserveFluxHelmRoot(
		ctx,
		"bigbang",
		"bigbang",
		kube.FluxRootTarget{URL: url, Tag: tag},
	)
	if err != nil {
		return kube.FluxRootObservation{}, err
	}
	return observation, nil
}

func (service Service) bigBangArtifact() (config.ChartArtifact, error) {
	return service.Project.BigBangArtifact()
}

func (service Service) receiptForRelease(release config.ClusterRelease, previous ClusterState) ClusterState {
	return ClusterState{
		Kubernetes: release.Kubernetes, RecordedKubernetes: release.Kubernetes,
		KubesprayVersion: release.Kubespray.Version, KubesprayCommit: release.Kubespray.Commit,
		OrchestrationSHA256: previous.OrchestrationSHA256,
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
