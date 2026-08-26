package orchestration

import (
	"context"
	"errors"
	"fmt"
	"reflect"

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
	position, err := service.liveReleasePosition(state, target)
	if err != nil {
		return UpgradePlan{}, err
	}
	root, err := service.bigBangObservation(ctx, client)
	if err != nil {
		return UpgradePlan{}, err
	}
	return service.upgradePlan(root, position)
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
	if plan.Order == AlreadyCurrent {
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
		if mode == ApplyConvergence {
			if err := service.convergeCurrentConfiguration(
				ctx,
				client,
				target,
				inventoryPath,
				rawArgs,
			); err != nil {
				return UpgradePlan{}, err
			}
		} else if err := service.waitHealthy(
			ctx,
			client,
			target.Kubernetes,
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
		verified, err := service.discoverState(ctx, client)
		if err != nil {
			return UpgradePlan{}, fmt.Errorf("verify installed Kubernetes version: %w", err)
		}
		if verified.Kubernetes != plan.Target {
			return UpgradePlan{}, fmt.Errorf(
				"installed Kubernetes reports %s, want %s",
				verified.Kubernetes,
				plan.Target,
			)
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
	if state.Kubernetes != plan.Current {
		return UpgradePlan{}, fmt.Errorf(
			"live Kubernetes changed from planned %s to %s before Kubespray",
			plan.Current,
			state.Kubernetes,
		)
	}
	if err := service.validateClusterIdentity(state); err != nil {
		return UpgradePlan{}, err
	}
	inputSHA, err := service.orchestrationInputSHA256(inventoryPath)
	if err != nil {
		return UpgradePlan{}, err
	}
	for index, release := range plan.Steps {
		toolchain := toolchains[index]
		if err := service.waitHealthy(ctx, client, state.Kubernetes); err != nil {
			return UpgradePlan{}, fmt.Errorf("pre-upgrade health gate: %w", err)
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
		if err := service.requireOrchestrationInput(inventoryPath, inputSHA); err != nil {
			return UpgradePlan{}, err
		}
		state, err = service.discoverState(ctx, client)
		if err != nil {
			return UpgradePlan{}, err
		}
		if state.Kubernetes != release.Kubernetes {
			return UpgradePlan{}, fmt.Errorf(
				"post-Kubespray Kubernetes reports %s, want %s",
				state.Kubernetes,
				release.Kubernetes,
			)
		}
	}
	return plan, nil
}

func (service Service) convergeCurrentConfiguration(
	ctx context.Context,
	client *clusterClient,
	target config.ClusterRelease,
	inventoryPath string,
	rawArgs []string,
) error {
	inputSHA, err := service.orchestrationInputSHA256(inventoryPath)
	if err != nil {
		return err
	}
	toolchains, err := service.prepareReleases(ctx, []config.ClusterRelease{target})
	if err != nil {
		return err
	}
	if len(toolchains) != 1 {
		return errors.New("prepared Kubespray toolchain does not match the current release")
	}
	toolchain := toolchains[0]
	if err := service.waitHealthy(ctx, client, target.Kubernetes); err != nil {
		return fmt.Errorf("pre-Kubespray health gate: %w", err)
	}
	if err := service.convergeExistingKubespray(
		ctx, client, toolchain, inventoryPath, "cluster.yml", rawArgs, target.Kubernetes,
	); err != nil {
		return fmt.Errorf("current cluster configuration convergence: %w", err)
	}
	if err := service.requireOrchestrationInput(inventoryPath, inputSHA); err != nil {
		return err
	}
	return nil
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
	case InstallTarget, PlatformFirst, KubernetesFirst, AlreadyCurrent:
	default:
		return fmt.Errorf("unsupported orchestration upgrade order %q", plan.Order)
	}
	target, err := service.Project.Desired.Orchestration.TargetRelease()
	if err != nil {
		return err
	}
	if plan.Target != target.Kubernetes {
		return fmt.Errorf(
			"orchestration plan target %s does not match committed target %s",
			plan.Target,
			target.Kubernetes,
		)
	}
	if plan.Order == InstallTarget &&
		(plan.Current != "" ||
			len(plan.Steps) != 1 ||
			!reflect.DeepEqual(plan.Steps[0], target)) {
		return errors.New("cluster install plan must contain its one exact target release")
	}
	if plan.Order == AlreadyCurrent &&
		(plan.Current != plan.Target || len(plan.Steps) != 0) {
		return errors.New(
			"current cluster plan must match the committed target without upgrade steps",
		)
	}
	if plan.Order == KubernetesFirst || plan.Order == PlatformFirst {
		currentIndex := releaseIndex(
			service.Project.Desired.Orchestration.Releases,
			plan.Current,
		)
		if currentIndex < 0 {
			return fmt.Errorf(
				"live Kubernetes %s is absent from the committed release ladder",
				plan.Current,
			)
		}
		if len(plan.Steps) != 1 ||
			currentIndex+1 >= len(service.Project.Desired.Orchestration.Releases) ||
			!reflect.DeepEqual(
				plan.Steps[0],
				service.Project.Desired.Orchestration.Releases[currentIndex+1],
			) {
			return errors.New(
				"Kubernetes upgrade plan must contain only the next exact committed release",
			)
		}
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
	if state.Kubernetes != target.Kubernetes {
		return fmt.Errorf(
			"live Kubernetes changed from committed target %s to %s",
			target.Kubernetes,
			state.Kubernetes,
		)
	}
	return service.validateClusterIdentity(state)
}

func (service Service) upgradePlan(
	root kube.FluxRootObservation,
	position liveReleasePosition,
) (UpgradePlan, error) {
	current := position.current
	targetVersion := position.target
	plan := UpgradePlan{Current: current.String(), Target: targetVersion.String()}
	releases := service.Project.Desired.Orchestration.Releases
	if current.Equal(targetVersion) {
		plan.Order = AlreadyCurrent
		return plan, nil
	}
	next := releases[position.currentIndex+1]
	first, err := semver.NewVersion(next.Kubernetes)
	if err != nil {
		return UpgradePlan{}, fmt.Errorf(
			"parse next committed Kubernetes version %s: %w",
			next.Kubernetes,
			err,
		)
	}
	if first.Major() != current.Major() || first.Minor() > current.Minor()+1 {
		return UpgradePlan{}, fmt.Errorf("release ladder skips Kubernetes %s between %s and %s", nextMinor(current), current, first)
	}
	plan.Steps = []config.ClusterRelease{next}
	desiredConstraints, err := parsePlatformConstraints(service.Project.Lock.Compatibility.Constraints)
	if err != nil {
		return UpgradePlan{}, fmt.Errorf("parse desired platform Kubernetes constraints: %w", err)
	}
	platformCompatible := firstUnsupportedConstraint(
		desiredConstraints,
		current,
		first,
	) == ""
	if !root.Complete() && platformCompatible {
		plan.Order = PlatformFirst
		return plan, nil
	}
	plan.Order = KubernetesFirst
	return plan, nil
}

type liveReleasePosition struct {
	current      *semver.Version
	target       *semver.Version
	currentIndex int
}

func (service Service) liveReleasePosition(
	state ClusterState,
	target config.ClusterRelease,
) (liveReleasePosition, error) {
	current, err := semver.NewVersion(state.Kubernetes)
	if err != nil {
		return liveReleasePosition{}, fmt.Errorf(
			"parse live Kubernetes version %s: %w",
			state.Kubernetes,
			err,
		)
	}
	targetVersion, err := semver.NewVersion(target.Kubernetes)
	if err != nil {
		return liveReleasePosition{}, fmt.Errorf(
			"parse committed target Kubernetes version %s: %w",
			target.Kubernetes,
			err,
		)
	}
	if current.GreaterThan(targetVersion) {
		return liveReleasePosition{}, fmt.Errorf(
			"live Kubernetes %s is newer than committed target %s; refusing mutation",
			current,
			targetVersion,
		)
	}
	releases := service.Project.Desired.Orchestration.Releases
	currentIndex := releaseIndex(releases, current.String())
	if currentIndex < 0 {
		return liveReleasePosition{}, fmt.Errorf(
			"live Kubernetes %s is absent from the committed release ladder",
			current,
		)
	}
	targetIndex := releaseIndex(releases, targetVersion.String())
	if targetIndex < 0 {
		return liveReleasePosition{}, fmt.Errorf(
			"committed target Kubernetes %s is absent from its release ladder",
			targetVersion,
		)
	}
	if currentIndex > targetIndex ||
		(current.LessThan(targetVersion) && currentIndex == targetIndex) {
		return liveReleasePosition{}, fmt.Errorf(
			"live Kubernetes %s is not an earlier committed step toward %s",
			current,
			targetVersion,
		)
	}
	return liveReleasePosition{
		current:      current,
		target:       targetVersion,
		currentIndex: currentIndex,
	}, nil
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
