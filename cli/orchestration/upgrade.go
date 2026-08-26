package orchestration

import (
	"context"
	"errors"
	"fmt"

	"atum/cli/config"
	"atum/cli/kube"

	"github.com/Masterminds/semver/v3"
)

func (service Service) Plan(ctx context.Context) (UpgradePlan, error) {
	if service.Project == nil {
		return UpgradePlan{}, errors.New("Atum project is not loaded")
	}
	target, err := service.Project.Desired.Orchestration.TargetRelease()
	if err != nil {
		return UpgradePlan{}, err
	}
	client, err := service.clusterClient()
	if errors.Is(err, ErrClusterAbsent) {
		return UpgradePlan{Target: target.Kubernetes, Order: InstallTarget, Steps: []config.ClusterRelease{target}}, nil
	}
	if err != nil {
		return UpgradePlan{}, err
	}
	state, err := service.discoverState(ctx, client)
	if err != nil {
		return UpgradePlan{}, err
	}
	if state.RecordedKubernetes == "" {
		if state.Kubernetes != target.Kubernetes {
			return UpgradePlan{}, fmt.Errorf(
				"live Kubernetes %s has no local orchestration receipt and does not match committed target %s; refusing to adopt it",
				state.Kubernetes,
				target.Kubernetes,
			)
		}
		return UpgradePlan{Current: state.Kubernetes, Target: target.Kubernetes, Order: FinalizeInstall}, nil
	}
	if state.TargetKubernetes == "" &&
		state.Kubernetes == target.Kubernetes &&
		state.KubesprayVersion == target.Kubespray.Version &&
		state.KubesprayCommit == target.Kubespray.Commit {
		inputSHA, err := service.orchestrationInputSHA256(service.installInventoryPath())
		if err != nil {
			return UpgradePlan{}, err
		}
		if state.OrchestrationSHA256 != inputSHA {
			return UpgradePlan{
				Current: state.Kubernetes,
				Target:  target.Kubernetes,
				Order:   ReconcileCurrent,
			}, nil
		}
	}
	root, err := service.bigBangObservation(ctx, client)
	if err != nil {
		return UpgradePlan{}, err
	}
	if !root.Complete() {
		if err := service.validatePlatformState(state); err != nil {
			return service.upgradePlan(state, root)
		}
		return UpgradePlan{
			Current: state.Kubernetes,
			Target:  target.Kubernetes,
			Order:   PlatformFirst,
		}, nil
	}
	return service.upgradePlan(state, root)
}

func (service Service) ConvergePlanned(
	ctx context.Context,
	plan UpgradePlan,
	inventoryPath string,
	rawArgs []string,
	mode ConvergenceMode,
) (UpgradePlan, error) {
	if err := service.ValidatePlan(plan, mode); err != nil {
		return UpgradePlan{}, err
	}
	if plan.Order == PlatformFirst {
		return UpgradePlan{}, errors.New("the desired Big Bang release must be reconciled before this Kubernetes upgrade; run atum apply")
	}
	if plan.Order == FinalizeInstall {
		client, err := service.clusterClient()
		if err != nil {
			return UpgradePlan{}, err
		}
		state, err := service.discoverState(ctx, client)
		if err != nil {
			return UpgradePlan{}, err
		}
		if _, err := service.convergeCurrentConfiguration(
			ctx,
			client,
			state,
			func() config.ClusterRelease {
				target, _ := service.Project.Desired.Orchestration.TargetRelease()
				return target
			}(),
			inventoryPath,
			rawArgs,
		); err != nil {
			return UpgradePlan{}, fmt.Errorf("finalize installed cluster configuration: %w", err)
		}
		return plan, nil
	}
	if plan.Order == ReconcileCurrent || plan.Order == AlreadyCurrent {
		client, err := service.clusterClient()
		if err != nil {
			return UpgradePlan{}, err
		}
		state, err := service.discoverState(ctx, client)
		if err != nil {
			return UpgradePlan{}, err
		}
		target, _ := service.Project.Desired.Orchestration.TargetRelease()
		if err := service.validateCurrentTargetState(state, target); err != nil {
			return UpgradePlan{}, err
		}
		if _, err := service.convergeCurrentConfiguration(
			ctx,
			client,
			state,
			target,
			inventoryPath,
			rawArgs,
		); err != nil {
			return UpgradePlan{}, err
		}
		return plan, nil
	}
	toolchains, err := service.prepareReleases(ctx, plan.Steps)
	if err != nil {
		return UpgradePlan{}, err
	}
	if len(toolchains) != len(plan.Steps) {
		return UpgradePlan{}, errors.New("prepared Kubespray toolchains do not match the upgrade ladder")
	}
	if plan.Order == InstallTarget {
		toolchain := toolchains[0]
		inputSHA, err := service.orchestrationInputSHA256(inventoryPath)
		if err != nil {
			return UpgradePlan{}, err
		}
		if err := service.waitForInstallConnections(ctx, toolchain, inventoryPath); err != nil {
			return UpgradePlan{}, err
		}
		if err := service.runKubespray(ctx, toolchain, inventoryPath, "cluster.yml", rawArgs); err != nil {
			return UpgradePlan{}, err
		}
		client, err := service.clusterClient()
		if err != nil {
			return UpgradePlan{}, fmt.Errorf("load installed cluster: %w", err)
		}
		if err := service.waitHealthy(ctx, client, plan.Target); err != nil {
			return UpgradePlan{}, err
		}
		if err := service.requireOrchestrationInput(inventoryPath, inputSHA); err != nil {
			return UpgradePlan{}, err
		}
	state := service.receiptForRelease(plan.Steps[0], ClusterState{})
		state.OrchestrationSHA256 = inputSHA
		if err := service.writeOrchestrationReceipt(state); err != nil {
			return UpgradePlan{}, err
		}
		verified, err := service.discoverState(ctx, client)
		if err != nil {
			return UpgradePlan{}, fmt.Errorf("verify installed orchestration receipt: %w", err)
		}
		if err := service.validateClusterIdentity(verified); err != nil {
			return UpgradePlan{}, err
		}
		return plan, nil
	}
	client, err := service.clusterClient()
	if err != nil {
		return UpgradePlan{}, err
	}
	state, err := service.discoverState(ctx, client)
	if err != nil {
		return UpgradePlan{}, err
	}
	inputSHA, err := service.orchestrationInputSHA256(inventoryPath)
	if err != nil {
		return UpgradePlan{}, err
	}
	for index, release := range plan.Steps {
		toolchain := toolchains[index]
		resumingCheckpoint := plan.ResumeTarget != "" && index == 0
		if !resumingCheckpoint {
			if err := service.waitHealthy(ctx, client, state.Kubernetes); err != nil {
				return UpgradePlan{}, fmt.Errorf("pre-upgrade health gate: %w", err)
			}
			inProgress := state
			inProgress.TargetKubernetes = release.Kubernetes
			if err := service.writeOrchestrationReceipt(inProgress); err != nil {
				return UpgradePlan{}, err
			}
		}
		if toolchain.Release.Kubernetes != release.Kubernetes ||
			toolchain.Release.Kubespray.Commit != release.Kubespray.Commit {
			return UpgradePlan{}, fmt.Errorf("prepared Kubespray toolchain %s does not match Kubernetes %s", toolchain.Release.Kubespray.Commit, release.Kubernetes)
		}
		if err := service.convergeExistingKubespray(
			ctx, client, toolchain, inventoryPath, "upgrade-cluster.yml",
			rawArgs, release.Kubernetes,
		); err != nil {
			return UpgradePlan{}, fmt.Errorf(
				"converge existing cluster at Kubernetes %s: %w",
				release.Kubernetes, err)
		}
		state = service.receiptForRelease(release, state)
		if index == len(plan.Steps)-1 {
			if err := service.requireOrchestrationInput(inventoryPath, inputSHA); err != nil {
				return UpgradePlan{}, err
			}
			state.OrchestrationSHA256 = inputSHA
		}
		if err := service.writeOrchestrationReceipt(state); err != nil {
			return UpgradePlan{}, err
		}
	}
	return plan, nil
}

func (service Service) convergeCurrentConfiguration(
	ctx context.Context,
	client *clusterClient,
	state ClusterState,
	target config.ClusterRelease,
	inventoryPath string,
	rawArgs []string,
) (ClusterState, error) {
	inputSHA, err := service.orchestrationInputSHA256(inventoryPath)
	if err != nil {
		return ClusterState{}, err
	}
	if state.OrchestrationSHA256 == inputSHA {
		if err := service.waitHealthy(ctx, client, target.Kubernetes); err != nil {
			return ClusterState{}, err
		}
		return state, nil
	}
	toolchains, err := service.prepareReleases(ctx, []config.ClusterRelease{target})
	if err != nil {
		return ClusterState{}, err
	}
	if len(toolchains) != 1 {
		return ClusterState{}, errors.New("prepared Kubespray toolchain does not match the current release")
	}
	toolchain := toolchains[0]
	if err := service.convergeExistingKubespray(
		ctx, client, toolchain, inventoryPath, "cluster.yml", rawArgs, target.Kubernetes,
	); err != nil {
		return ClusterState{}, fmt.Errorf("current cluster configuration convergence: %w", err)
	}
	if err := service.requireOrchestrationInput(inventoryPath, inputSHA); err != nil {
		return ClusterState{}, err
	}
	state = service.receiptForRelease(target, state)
	state.OrchestrationSHA256 = inputSHA
	if err := service.writeOrchestrationReceipt(state); err != nil {
		return ClusterState{}, err
	}
	return state, nil
}

func (service Service) convergeExistingKubespray(
	ctx context.Context,
	client *clusterClient,
	toolchain Toolchain,
	inventoryPath, playbook string,
	rawArgs []string,
	kubernetes string,
) error {
	if err := service.runKubespray(ctx, toolchain, inventoryPath, playbook, rawArgs); err != nil {
		return err
	}
	if err := service.waitHealthy(ctx, client, kubernetes); err != nil {
		return fmt.Errorf("post-Kubespray health gate: %w", err)
	}
	return nil
}

func (service Service) ValidatePlan(plan UpgradePlan, mode ConvergenceMode) error {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	switch plan.Order {
	case InstallTarget, FinalizeInstall, ReconcileCurrent, PlatformFirst, KubernetesFirst, AlreadyCurrent:
	default:
		return fmt.Errorf("unsupported orchestration upgrade order %q", plan.Order)
	}
	if plan.ResumeTarget != "" && (plan.Order != KubernetesFirst || len(plan.Steps) != 1 ||
		plan.ResumeFrom == "" || plan.Steps[0].Kubernetes != plan.ResumeTarget ||
		(plan.Current != plan.ResumeFrom && plan.Current != plan.ResumeTarget)) {
		return errors.New("interrupted upgrade plan must replay exactly its live Kubernetes checkpoint")
	}
	if plan.Order == InstallTarget && (len(plan.Steps) != 1 || plan.Steps[0].Kubernetes != plan.Target) {
		return errors.New("cluster install plan must contain its one exact target release")
	}
	if plan.Order == FinalizeInstall && len(plan.Steps) != 0 {
		return errors.New("cluster install finalization cannot contain upgrade steps")
	}
	switch mode {
	case ApplyConvergence, FullConvergence:
		requiresKubernetesUpgrade := plan.Order == KubernetesFirst ||
			(plan.Order == PlatformFirst && plan.Current != plan.Target)
		if requiresKubernetesUpgrade && !service.Project.Desired.Orchestration.AutomaticUpgrade {
			return errors.New("automatic Kubernetes upgrades are disabled; run atum orchestration upgrade explicitly")
		}
	case UpgradeConvergence:
		if plan.Order == InstallTarget {
			return errors.New("orchestration upgrade requires an existing cluster")
		}
	default:
		return fmt.Errorf("unsupported orchestration convergence mode %d", mode)
	}
	if plan.Order == PlatformFirst && mode != FullConvergence {
		return errors.New("the desired Big Bang release must be reconciled before this Kubernetes upgrade; run atum apply")
	}
	return nil
}

func (service Service) validateCurrentTargetState(
	state ClusterState,
	target config.ClusterRelease,
) error {
	if state.TargetKubernetes != "" || state.Kubernetes != target.Kubernetes ||
		state.RecordedKubernetes != target.Kubernetes ||
		state.KubesprayVersion != target.Kubespray.Version ||
		state.KubesprayCommit != target.Kubespray.Commit {
		return errors.New("live cluster changed after selecting current-configuration convergence")
	}
	return nil
}

func (service Service) upgradePlan(
	state ClusterState,
	_ kube.FluxRootObservation,
) (UpgradePlan, error) {
	target, err := service.Project.Desired.Orchestration.TargetRelease()
	if err != nil {
		return UpgradePlan{}, err
	}
	current, err := semver.NewVersion(state.Kubernetes)
	if err != nil {
		return UpgradePlan{}, fmt.Errorf("parse live Kubernetes version %s: %w", state.Kubernetes, err)
	}
	targetVersion, _ := semver.NewVersion(target.Kubernetes)
	if current.GreaterThan(targetVersion) {
		return UpgradePlan{}, fmt.Errorf("live Kubernetes %s is newer than committed target %s; refusing mutation", current, targetVersion)
	}
	plan := UpgradePlan{Current: current.String(), Target: targetVersion.String()}
	if state.TargetKubernetes != "" {
		origin, originTracked := releaseForKubernetes(
			service.Project.Desired.Orchestration.Releases, state.RecordedKubernetes,
		)
		checkpoint, checkpointTracked := releaseForKubernetes(
			service.Project.Desired.Orchestration.Releases, state.TargetKubernetes,
		)
		if !originTracked || !checkpointTracked {
			return UpgradePlan{}, fmt.Errorf("interrupted upgrade from %s to %s is absent from the committed ladder", state.RecordedKubernetes, state.TargetKubernetes)
		}
		if state.KubesprayVersion != origin.Kubespray.Version || state.KubesprayCommit != origin.Kubespray.Commit {
			return UpgradePlan{}, fmt.Errorf(
				"interrupted upgrade from Kubernetes %s reports Kubespray %s at %s, want %s at %s",
				state.RecordedKubernetes, state.KubesprayVersion, state.KubesprayCommit,
				origin.Kubespray.Version, origin.Kubespray.Commit,
			)
		}
		plan.Order = KubernetesFirst
		plan.ResumeFrom = state.RecordedKubernetes
		plan.ResumeTarget = state.TargetKubernetes
		plan.Steps = []config.ClusterRelease{checkpoint}
		return plan, nil
	}
	currentRelease, tracked := releaseForKubernetes(service.Project.Desired.Orchestration.Releases, current.String())
	if current.Equal(targetVersion) {
		if state.KubesprayVersion != target.Kubespray.Version || state.KubesprayCommit != target.Kubespray.Commit {
			return UpgradePlan{}, fmt.Errorf(
				"live Kubernetes %s has no exact Kubespray %s identity; refusing to adopt unproven state",
				current, target.Kubespray.Version,
			)
		}
		plan.Order = AlreadyCurrent
		return plan, nil
	}
	if !tracked {
		return UpgradePlan{}, fmt.Errorf("live Kubernetes %s is absent from the committed release ladder", current)
	}
	if state.KubesprayVersion != currentRelease.Kubespray.Version || state.KubesprayCommit != currentRelease.Kubespray.Commit {
		return UpgradePlan{}, fmt.Errorf(
			"live Kubernetes %s reports Kubespray %s at %s, want %s at %s; refusing an unproven sequential upgrade",
			current, state.KubesprayVersion, state.KubesprayCommit,
			currentRelease.Kubespray.Version, currentRelease.Kubespray.Commit,
		)
	}
	for _, release := range service.Project.Desired.Orchestration.Releases {
		candidate, _ := semver.NewVersion(release.Kubernetes)
		if candidate.GreaterThan(current) {
			plan.Steps = append(plan.Steps, release)
		}
	}
	if len(plan.Steps) == 0 {
		return UpgradePlan{}, fmt.Errorf("release ladder has no step from Kubernetes %s to %s", current, targetVersion)
	}
	first, _ := semver.NewVersion(plan.Steps[0].Kubernetes)
	if first.Major() != current.Major() || first.Minor() > current.Minor()+1 {
		return UpgradePlan{}, fmt.Errorf("release ladder skips Kubernetes %s between %s and %s", nextMinor(current), current, first)
	}
	desiredConstraints, err := parsePlatformConstraints(service.Project.Lock.Compatibility.Constraints)
	if err != nil {
		return UpgradePlan{}, fmt.Errorf("parse desired platform Kubernetes constraints: %w", err)
	}
	desiredVersions := make([]*semver.Version, 1, len(plan.Steps)+1)
	desiredVersions[0] = current
	for _, release := range plan.Steps {
		candidate, _ := semver.NewVersion(release.Kubernetes)
		desiredVersions = append(desiredVersions, candidate)
	}
	platformFirst := firstUnsupportedConstraint(desiredConstraints, desiredVersions...) == ""
	if !platformFirst {
		plan.Order = KubernetesFirst
		return plan, nil
	}
	plan.Order = PlatformFirst
	return plan, nil
}

func nextMinor(version *semver.Version) string {
	return fmt.Sprintf("%d.%d", version.Major(), version.Minor()+1)
}

func releaseForKubernetes(releases []config.ClusterRelease, version string) (config.ClusterRelease, bool) {
	index := releaseIndex(releases, version)
	if index < 0 {
		return config.ClusterRelease{}, false
	}
	return releases[index], true
}

func releaseIndex(releases []config.ClusterRelease, version string) int {
	for index := range releases {
		if releases[index].Kubernetes == version {
			return index
		}
	}
	return -1
}
