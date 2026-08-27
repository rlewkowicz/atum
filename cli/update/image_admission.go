package update

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"atum/cli/config"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"
	"mvdan.cc/sh/v3/syntax"
)

const maxOfficialFilesystemBytes int64 = 8 << 30
const maxOfficialEntrypointBytes int64 = 1 << 20
const maxOfficialFilesystemEntries = 2_000_000
const maxMountedScriptDepth = 16
const boundedMountedGlob = "__ATUM_MOUNTED_GLOB__"
const imageAdmissionContract = "atum.dev/image-admission/v3"

type finalImageUse struct {
	artifact            string
	invocation          containerInvocation
	obligations         []filesystemObligation
	requiredPaths       []string
	requiredEnvironment []string
}

type filesystemObligation struct {
	Path        string
	Origin      string
	Executable  bool
	SearchPATH  bool
	Interpreter string
}

type officialImageInspection struct {
	material              string
	config                config.ImageOfficialConfig
	pathExists            map[string]bool
	pathStates            map[string]officialPathState
	entrypointEnvironment map[string]bool
	uses                  []finalImageUse
	imageEnvironment      []string
	defaultUID            int
	defaultGID            int
	defaultIdentityKnown  bool
}

type officialPathState struct {
	present      bool
	mode         int64
	uid          int
	gid          int
	kind         byte
	link         string
	content      []byte
	resolved     string
	contentKnown bool
}

type officialPathIndex struct {
	states   map[string]officialPathState
	children map[string]map[string]struct{}
}

func newOfficialPathIndex(capacity int) *officialPathIndex {
	return &officialPathIndex{
		states:   make(map[string]officialPathState, capacity),
		children: make(map[string]map[string]struct{}, capacity/2),
	}
}

func (index *officialPathIndex) set(name string, state officialPathState) {
	if _, exists := index.states[name]; !exists {
		parent := officialPathParent(name)
		children := index.children[parent]
		if children == nil {
			children = make(map[string]struct{})
			index.children[parent] = children
		}
		children[name] = struct{}{}
	}
	index.states[name] = state
}

func (index *officialPathIndex) removeSubtree(root string) {
	delete(index.children[officialPathParent(root)], root)
	stack := []string{root}
	for len(stack) != 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		for child := range index.children[current] {
			stack = append(stack, child)
		}
		delete(index.children, current)
		delete(index.states, current)
	}
}

func (index *officialPathIndex) removeChildren(root string) {
	for len(index.children[root]) != 0 {
		for child := range index.children[root] {
			index.removeSubtree(child)
			break
		}
	}
}

func officialPathParent(name string) string {
	parent := path.Dir(name)
	if parent == "." {
		return ""
	}
	return parent
}

type officialInspectionRequest struct {
	imageIndex int
	uses       []finalImageUse
}

type officialInspectionResult struct {
	inspection   officialImageInspection
	cached       *config.ImageCompatibility
	mirrorDigest string
}

type configuredOfficialIdentity struct {
	id         string
	family     string
	provenance string
	license    string
}

var configuredOfficialImages = map[string]configuredOfficialIdentity{
	"docker.io/docker/buildkit-syft-scanner": {
		id:         "sbom-scanner",
		family:     "build-system",
		provenance: "docker.io/docker/buildkit-syft-scanner",
		license:    "Apache-2.0",
	},
	"docker.io/moby/buildkit": {
		id:         "buildkit",
		family:     "build-system",
		provenance: "https://github.com/moby/buildkit",
		license:    "Apache-2.0",
	},
	"docker.io/library/golang": {
		id:         "operator-builder",
		family:     "build-system",
		provenance: "docker.io/library/golang",
		license:    "BSD-3-Clause",
	},
	"docker.io/rancher/local-path-provisioner": {
		id:         "local-path-provisioner",
		family:     "storage",
		provenance: "https://github.com/rancher/local-path-provisioner",
		license:    "Apache-2.0",
	},
	"ghcr.io/kube-vip/kube-vip": {
		id:         "kube-vip",
		family:     "cluster",
		provenance: "https://github.com/kube-vip/kube-vip",
		license:    "Apache-2.0",
	},
	"ghcr.io/kube-vip/kube-vip-cloud-provider": {
		id:         "kube-vip-cloud-provider",
		family:     "cluster",
		provenance: "https://github.com/kube-vip/kube-vip-cloud-provider",
		license:    "Apache-2.0",
	},
	"quay.io/jetstack/cert-manager-acmesolver": {
		id:         "cert-manager-acmesolver",
		family:     "cert-manager",
		provenance: "https://github.com/cert-manager/cert-manager",
		license:    "Apache-2.0",
	},
	"quay.io/jetstack/cert-manager-cainjector": {
		id:         "cert-manager-cainjector",
		family:     "cert-manager",
		provenance: "https://github.com/cert-manager/cert-manager",
		license:    "Apache-2.0",
	},
	"quay.io/jetstack/cert-manager-controller": {
		id:         "cert-manager-controller",
		family:     "cert-manager",
		provenance: "https://github.com/cert-manager/cert-manager",
		license:    "Apache-2.0",
	},
	"quay.io/jetstack/cert-manager-startupapicheck": {
		id:         "cert-manager-startupapicheck",
		family:     "cert-manager",
		provenance: "https://github.com/cert-manager/cert-manager",
		license:    "Apache-2.0",
	},
	"quay.io/jetstack/cert-manager-webhook": {
		id:         "cert-manager-webhook",
		family:     "cert-manager",
		provenance: "https://github.com/cert-manager/cert-manager",
		license:    "Apache-2.0",
	},
}

// admitFinalRenderedImages is the only mirror/build decision writer. Source
// aliases have already proposed official candidates and native chart values;
// this function joins the final internal targets back to those candidates,
// inspects only official immutable material, and compares the effective
// runtime contract before admitting delivery.
func admitFinalRenderedImages(
	ctx context.Context,
	parallelism int,
	desired *config.Document,
	artifacts []chartArtifact,
	inspections []chartInspection,
	previous map[string]config.Image,
	renderContractsUnchanged bool,
	progress func(completed, total int),
) error {
	if len(artifacts) != len(inspections) {
		return errors.New("final rendered image admission set is incomplete")
	}
	byTarget := make(map[string]int, len(desired.Delivery.Images))
	for index := range desired.Delivery.Images {
		target := desired.Delivery.Images[index].Target
		if _, duplicate := byTarget[target]; duplicate {
			return fmt.Errorf("final internal target %s has multiple candidate bindings", target)
		}
		byTarget[target] = index
	}
	uses := make(map[int][]finalImageUse, len(byTarget))
	seenTargets := make(map[int]struct{}, len(byTarget))
	for artifactIndex := range artifacts {
		inspection := inspections[artifactIndex]
		for _, reference := range inspection.Images {
			imageIndex, found := byTarget[reference]
			if !found {
				return fmt.Errorf(
					"final render %s uses %s without one proposed official binding",
					artifacts[artifactIndex].ID,
					reference,
				)
			}
			seenTargets[imageIndex] = struct{}{}
		}
		for _, invocation := range inspection.Invocations {
			reference := invocation.Reference
			if reference == "auto" || !validImageReference(reference) {
				continue
			}
			imageIndex, found := byTarget[reference]
			if !found {
				return fmt.Errorf(
					"final rendered container %s/%s uses %s without one proposed official binding",
					artifacts[artifactIndex].ID,
					invocation.Location,
					reference,
				)
			}
			use, err := inspectFinalImageUse(artifacts[artifactIndex].ID, invocation)
			if err != nil {
				return err
			}
			uses[imageIndex] = append(uses[imageIndex], use)
			seenTargets[imageIndex] = struct{}{}
		}
	}
	requests := make([]officialInspectionRequest, 0, len(seenTargets))
	preAdmitted := 0
	for index := range desired.Delivery.Images {
		image := &desired.Delivery.Images[index]
		switch image.Discovery {
		case "rendered":
			if _, observed := seenTargets[index]; !observed {
				return fmt.Errorf(
					"official candidate %s has no final rendered target observation",
					image.ID,
				)
			}
		case "configuration":
			identity, err := configuredImageIdentity(*image)
			if err != nil {
				return err
			}
			image.Provenance = identity.provenance
			uses[index] = append(uses[index], finalImageUse{
				artifact: "configuration/" + image.ID,
				invocation: containerInvocation{
					Location:   "configuration/" + image.ID,
					Reference:  image.Target,
					Repository: imageRepository(image.Target),
					Runtime:    map[string]any{},
					PodRuntime: map[string]any{},
				},
			})
			seenTargets[index] = struct{}{}
		case "first-party":
			if image.Delivery.Default.Type != "build" ||
				image.Delivery.Default.BakeTarget == "" {
				return fmt.Errorf("first-party image %s has no reproducible build", image.ID)
			}
			preAdmitted++
			continue
		case "controller-generated":
			return fmt.Errorf(
				"controller-generated image %s has no current official admission boundary",
				image.ID,
			)
		case "kubespray":
			if _, rendered := seenTargets[index]; rendered {
				return fmt.Errorf(
					"Kubespray image %s is also owned by a rendered platform contract",
					image.ID,
				)
			}
			if image.Delivery.Default.Type != "mirror" ||
				image.Delivery.Default.Source == "" ||
				!strings.HasPrefix(image.Delivery.Default.Digest, "sha256:") {
				return fmt.Errorf(
					"Kubespray image %s has no exact official offline mirror",
					image.ID,
				)
			}
			preAdmitted++
			continue
		default:
			return fmt.Errorf("image %s has unknown discovery evidence %q", image.ID, image.Discovery)
		}
		if image.Delivery.Default.Type != "mirror" ||
			image.Delivery.Default.Source == "" {
			return fmt.Errorf("official candidate %s was admitted before final render", image.ID)
		}
		requests = append(requests, officialInspectionRequest{
			imageIndex: index,
			uses:       uses[index],
		})
	}

	results := make([]officialInspectionResult, len(requests))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(max(1, parallelism))
	completed := 0
	if progress != nil && preAdmitted != 0 {
		progress(preAdmitted, len(desired.Delivery.Images))
	}
	var progressMu sync.Mutex
	reportCompleted := func() {
		if progress == nil {
			return
		}
		progressMu.Lock()
		completed++
		progress(preAdmitted+completed, len(desired.Delivery.Images))
		progressMu.Unlock()
	}
	for requestIndex := range requests {
		requestIndex := requestIndex
		group.Go(func() error {
			request := requests[requestIndex]
			image := desired.Delivery.Images[request.imageIndex]
			source := image.Delivery.Default.Source
			previousImage, hadPrevious := previous[image.ID]
			if renderContractsUnchanged && hadPrevious {
				if digest, reusable := reusableMirrorDigest(image, previousImage); reusable {
					results[requestIndex].mirrorDigest = digest
					reportCompleted()
					return nil
				}
			}
			var cached *config.ImageCompatibility
			var err error
			if reusableCompatibilityCandidate(image, previousImage) {
				cached, err = reusableCompatibility(
					source,
					request.uses,
					previousImage.Compatibility,
				)
			}
			if err != nil {
				return fmt.Errorf(
					"inspect official candidate for %s: %w",
					image.ID,
					err,
				)
			}
			if cached != nil {
				results[requestIndex].cached = cached
			} else {
				results[requestIndex].inspection, err = inspectOfficialCandidate(
					groupContext,
					source,
					image,
					request.uses,
				)
			}
			if err != nil {
				return fmt.Errorf(
					"inspect official candidate for %s: %w",
					image.ID,
					err,
				)
			}
			reportCompleted()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}

	var admissionErrors []error
	for requestIndex, request := range requests {
		image := &desired.Delivery.Images[request.imageIndex]
		result := results[requestIndex]
		if result.mirrorDigest != "" {
			image.Delivery.Default.Digest = result.mirrorDigest
			image.Compatibility = nil
			continue
		}
		if result.cached != nil {
			mismatches := strings.Split(result.cached.Incompatibility, "; ")
			bakeTarget, extraMaterials, err := compatibilityBuildRecipe(
				*image,
				desired.Delivery.Policy.BuildBase,
				mismatches,
			)
			if err != nil {
				admissionErrors = append(
					admissionErrors,
					officialCandidateCompatibilityError(
						"cached ",
						image.ID,
						mismatches,
						err,
					),
				)
				continue
			}
			applyCompatibilityIdentity(image, bakeTarget)
			image.Compatibility = result.cached
			image.Delivery.Default = config.DeliveryChoice{
				Type:       "build",
				BakeTarget: bakeTarget,
				Materials: compactSorted(append(
					[]string{result.cached.OfficialMaterial},
					extraMaterials...,
				)),
			}
			continue
		}
		inspection := result.inspection
		mismatches := compareOfficialCandidate(*image, inspection, inspection.uses)
		if len(mismatches) == 0 {
			if strings.Contains(image.Delivery.Default.Source, "@") {
				return fmt.Errorf(
					"compatible official candidate %s has no tag-addressable mirror source",
					image.ID,
				)
			}
			_, digest, found := strings.Cut(inspection.material, "@")
			if !found || !strings.HasPrefix(digest, "sha256:") {
				return fmt.Errorf(
					"compatible official candidate %s has invalid immutable material %q",
					image.ID,
					inspection.material,
				)
			}
			image.Delivery.Default.Digest = digest
			image.Compatibility = nil
			continue
		}
		bakeTarget, extraMaterials, err := compatibilityBuildRecipe(
			*image,
			desired.Delivery.Policy.BuildBase,
			mismatches,
		)
		if err != nil {
			admissionErrors = append(
				admissionErrors,
				officialCandidateCompatibilityError(
					"",
					image.ID,
					mismatches,
					err,
				),
			)
			continue
		}
		applyCompatibilityIdentity(image, bakeTarget)
		observations := make([]config.ImageRuntimeEvidence, 0, len(inspection.uses))
		for _, use := range inspection.uses {
			runAsUser, runAsGroup := invocationRunAs(use.invocation)
			observations = append(observations, config.ImageRuntimeEvidence{
				Artifact:              use.artifact,
				RenderedLocation:      use.invocation.Location,
				RuntimeContractSHA256: use.invocation.RuntimeContractSHA256,
				Command:               stringSlice(use.invocation.Command),
				Arguments:             stringSlice(use.invocation.Args),
				RunAsUser:             runAsUser,
				RunAsGroup:            runAsGroup,
				RequiredPaths:         append([]string{}, use.requiredPaths...),
				RequiredEnvironment:   append([]string{}, use.requiredEnvironment...),
			})
		}
		sort.Slice(observations, func(i, j int) bool {
			if observations[i].Artifact != observations[j].Artifact {
				return observations[i].Artifact < observations[j].Artifact
			}
			return observations[i].RenderedLocation < observations[j].RenderedLocation
		})
		image.Compatibility = &config.ImageCompatibility{
			Contract:         imageAdmissionContract,
			Observations:     observations,
			Incompatibility:  strings.Join(mismatches, "; "),
			OfficialMaterial: inspection.material,
			OfficialConfig:   inspection.config,
		}
		image.Delivery.Default = config.DeliveryChoice{
			Type:       "build",
			BakeTarget: bakeTarget,
			Materials:  compactSorted(append([]string{inspection.material}, extraMaterials...)),
		}
	}
	sort.Slice(desired.Delivery.Images, func(i, j int) bool {
		return desired.Delivery.Images[i].ID < desired.Delivery.Images[j].ID
	})
	return errors.Join(admissionErrors...)
}

func officialCandidateCompatibilityError(
	prefix string,
	imageID string,
	mismatches []string,
	err error,
) error {
	return fmt.Errorf(
		"%sofficial candidate %s does not satisfy its final render (%s): %w",
		prefix,
		imageID,
		strings.Join(mismatches, "; "),
		err,
	)
}

func reusableMirrorDigest(candidate, previous config.Image) (string, bool) {
	if previous.Delivery.Default.Type != "mirror" ||
		previous.Delivery.Default.Source != candidate.Delivery.Default.Source ||
		!strings.HasPrefix(previous.Delivery.Default.Digest, "sha256:") {
		return "", false
	}
	digest := previous.Delivery.Default.Digest
	candidate.Delivery = config.ImageDelivery{}
	candidate.Compatibility = nil
	previous.Delivery = config.ImageDelivery{}
	previous.Compatibility = nil
	if !reflect.DeepEqual(candidate, previous) {
		return "", false
	}
	return digest, true
}

func reusableCompatibilityCandidate(candidate, previous config.Image) bool {
	if previous.Delivery.Default.Type != "build" ||
		previous.Delivery.Default.BakeTarget == "" ||
		previous.Compatibility == nil {
		return false
	}
	applyCompatibilityIdentity(
		&candidate,
		previous.Delivery.Default.BakeTarget,
	)
	candidate.Delivery = config.ImageDelivery{}
	candidate.Compatibility = nil
	previous.Delivery = config.ImageDelivery{}
	previous.Compatibility = nil
	return reflect.DeepEqual(candidate, previous)
}

func applyCompatibilityIdentity(image *config.Image, bakeTarget string) {
	switch {
	case bakeTarget == "grafana-plugins":
		image.License = "AGPL-3.0-only AND Apache-2.0"
		image.Provenance = strings.Join([]string{
			image.Provenance,
			"https://github.com/grafana/grafana-polystat-panel",
			"https://github.com/RedisGrafana/grafana-redis-datasource",
		}, ";")
	case bakeTarget == "garage-init-helper":
		image.Provenance = image.Provenance + ";https://snapshot.debian.org/"
	case strings.HasPrefix(bakeTarget, "kubectl-helper-"):
		image.License = "Apache-2.0 AND Debian"
		image.Provenance = image.Provenance + ";https://snapshot.debian.org/"
	case bakeTarget == "vault-curl-compat":
		image.License += " AND curl"
		image.Provenance += ";https://curl.se/;https://github.com/rlewkowicz/atum"
	case strings.HasPrefix(bakeTarget, "postgresql-"):
		image.License += " AND Apache-2.0"
		image.Provenance += ";https://github.com/bitnami/charts;https://github.com/rlewkowicz/atum"
	}
}

func inspectFinalImageUse(
	artifact string,
	invocation containerInvocation,
) (finalImageUse, error) {
	obligations, err := requiredInvocationObligations(invocation, nil, nil, nil, "")
	if err != nil {
		return finalImageUse{}, fmt.Errorf(
			"inspect final rendered command %s/%s: %w",
			artifact,
			invocation.Location,
			err,
		)
	}
	return finalImageUse{
		artifact:      artifact,
		invocation:    invocation,
		obligations:   obligations,
		requiredPaths: obligationPaths(obligations),
	}, nil
}

func configuredImageIdentity(image config.Image) (configuredOfficialIdentity, error) {
	source := image.Delivery.Default.Source
	if strings.HasPrefix(imageRepository(source), "registry1.dso.mil/") {
		return configuredOfficialIdentity{}, fmt.Errorf(
			"configured image %s uses forbidden Registry1 source %s",
			image.ID,
			source,
		)
	}
	identity, found := configuredOfficialImages[imageRepository(source)]
	if !found {
		return configuredOfficialIdentity{}, fmt.Errorf(
			"configured image %s source %s has no verified official vendor binding",
			image.ID,
			source,
		)
	}
	if image.License != identity.license {
		return configuredOfficialIdentity{}, fmt.Errorf(
			"configured image %s license %q does not match official binding %q",
			image.ID,
			image.License,
			identity.license,
		)
	}
	return identity, nil
}

func reusableCompatibility(
	source string,
	uses []finalImageUse,
	previous *config.ImageCompatibility,
) (*config.ImageCompatibility, error) {
	if previous == nil ||
		previous.Contract != imageAdmissionContract ||
		previous.Incompatibility == "" ||
		!compatibilityObservationsMatch(uses, previous.Observations) {
		return nil, nil
	}
	if strings.HasPrefix(imageRepository(source), "registry1.dso.mil/") {
		return nil, errors.New("Registry1 candidates are forbidden")
	}
	reference, err := name.ParseReference(source)
	if err != nil {
		return nil, fmt.Errorf("parse official image %s: %w", source, err)
	}
	material, err := name.ParseReference(previous.OfficialMaterial)
	if err != nil {
		return nil, fmt.Errorf(
			"parse prior official material %s: %w",
			previous.OfficialMaterial,
			err,
		)
	}
	if _, immutable := material.(name.Digest); !immutable {
		return nil, fmt.Errorf(
			"prior official material %s is not immutable",
			previous.OfficialMaterial,
		)
	}
	if reference.Context().Name() != material.Context().Name() {
		return nil, nil
	}
	return previous, nil
}

func compatibilityObservationsMatch(
	uses []finalImageUse,
	observations []config.ImageRuntimeEvidence,
) bool {
	if len(uses) != len(observations) {
		return false
	}
	byLocation := make(map[string]string, len(observations))
	for _, observation := range observations {
		key := observation.Artifact + "\x00" + observation.RenderedLocation
		if key == "\x00" || observation.RuntimeContractSHA256 == "" {
			return false
		}
		if _, duplicate := byLocation[key]; duplicate {
			return false
		}
		byLocation[key] = observation.RuntimeContractSHA256
	}
	for _, use := range uses {
		key := use.artifact + "\x00" + use.invocation.Location
		digest, found := byLocation[key]
		if !found || digest != use.invocation.RuntimeContractSHA256 {
			return false
		}
		delete(byLocation, key)
	}
	return len(byLocation) == 0
}

func inspectOfficialCandidate(
	ctx context.Context,
	source string,
	imageRecord config.Image,
	uses []finalImageUse,
) (officialImageInspection, error) {
	if strings.HasPrefix(imageRepository(source), "registry1.dso.mil/") {
		return officialImageInspection{}, errors.New("Registry1 candidates are forbidden")
	}
	reference, err := name.ParseReference(source)
	if err != nil {
		return officialImageInspection{}, fmt.Errorf("parse official image %s: %w", source, err)
	}
	descriptor, err := remote.Get(
		reference,
		remote.WithContext(ctx),
		remote.WithPlatform(linuxAMD64),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return officialImageInspection{}, fmt.Errorf("resolve official image %s: %w", source, err)
	}
	image, err := descriptor.Image()
	if err != nil {
		return officialImageInspection{}, fmt.Errorf("read official image %s: %w", source, err)
	}
	configuration, err := image.ConfigFile()
	if err != nil {
		return officialImageInspection{}, fmt.Errorf("read official image config %s: %w", source, err)
	}
	if configuration.OS != linuxAMD64.OS ||
		configuration.Architecture != linuxAMD64.Architecture {
		return officialImageInspection{}, fmt.Errorf(
			"official image %s resolved to %s/%s, want linux/amd64",
			source,
			configuration.OS,
			configuration.Architecture,
		)
	}
	manifestDigest, err := image.Digest()
	if err != nil {
		return officialImageInspection{}, fmt.Errorf(
			"resolve official manifest %s: %w",
			source,
			err,
		)
	}
	configDigest, err := image.ConfigName()
	if err != nil {
		return officialImageInspection{}, fmt.Errorf("resolve official config %s: %w", source, err)
	}
	material := imageRepository(source) + "@" + manifestDigest.String()
	normalizedUses := make([]finalImageUse, len(uses))
	var obligations []filesystemObligation
	var requiredEnvironment []string
	for i := range uses {
		normalizedUses[i] = uses[i]
		normalized, normalizeErr := requiredInvocationObligations(
			uses[i].invocation,
			configuration.Config.Entrypoint,
			configuration.Config.Cmd,
			configuration.Config.Env,
			configuration.Config.WorkingDir,
		)
		if normalizeErr != nil {
			return officialImageInspection{}, fmt.Errorf(
				"normalize %s/%s: %w",
				uses[i].artifact,
				uses[i].invocation.Location,
				normalizeErr,
			)
		}
		normalizedUses[i].obligations = normalized
		normalizedUses[i].requiredPaths = obligationQueryPaths(
			normalized,
			configuration.Config.Env,
		)
		normalizedUses[i].requiredEnvironment = requiredEntrypointEnvironment(
			imageRecord,
			uses[i].invocation,
		)
		obligations = append(obligations, normalized...)
		requiredEnvironment = append(
			requiredEnvironment,
			normalizedUses[i].requiredEnvironment...,
		)
	}
	requiredEnvironment = compactSorted(requiredEnvironment)
	entrypointPaths := officialEntrypointCandidates(
		configuration.Config.Entrypoint,
		configuration.Config.Env,
	)
	entrypointContentPaths := entrypointPaths
	if len(requiredEnvironment) == 0 {
		entrypointContentPaths = nil
	}
	identityPaths := []string(nil)
	if configuredIdentityNeedsLookup(configuration.Config.User) {
		identityPaths = []string{"/etc/passwd", "/etc/group"}
	}
	filesystemPaths := obligationQueryPaths(obligations, configuration.Config.Env)
	filesystemPaths = compactSorted(append(
		append(filesystemPaths, entrypointPaths...),
		identityPaths...,
	))
	pathExists := make(map[string]bool, len(filesystemPaths))
	pathStates := make(map[string]officialPathState, len(filesystemPaths))
	inspectedStates := make(map[string]officialPathState)
	if len(filesystemPaths) != 0 || len(requiredEnvironment) != 0 {
		inspectedStates, err = inspectOfficialFilesystem(
			image,
			compactSorted(append(append([]string{}, filesystemPaths...), entrypointPaths...)),
			compactSorted(append(entrypointContentPaths, identityPaths...)),
		)
		if err != nil {
			return officialImageInspection{}, fmt.Errorf(
				"inspect official filesystem %s: %w",
				source,
				err,
			)
		}
		for _, required := range filesystemPaths {
			state := inspectedStates[required]
			pathStates[required] = state
			pathExists[required] = state.present
		}
	}
	filesystem := make([]config.ImageFilesystemEvidence, 0, len(pathExists))
	for _, required := range filesystemPaths {
		state := pathStates[required]
		mode := ""
		fileType := ""
		if state.present {
			mode = fmt.Sprintf("%04o", state.mode&0o7777)
			fileType = officialPathType(state.kind)
		}
		filesystem = append(filesystem, config.ImageFilesystemEvidence{
			Path: required, Present: pathExists[required],
			Type: fileType, Link: state.link,
			Mode: mode, UID: state.uid, GID: state.gid,
		})
	}
	entrypointFiles, entrypointEnvironment := officialEntrypointEvidence(
		entrypointContentPaths,
		requiredEnvironment,
		inspectedStates,
	)
	defaultUID, defaultGID, defaultIdentityKnown := resolveConfiguredIdentity(
		configuration.Config.User,
		inspectedStates["/etc/passwd"].content,
		inspectedStates["/etc/group"].content,
	)
	return officialImageInspection{
		material: material,
		config: config.ImageOfficialConfig{
			SHA256: configDigest.String(),
			Entrypoint: append(
				make([]string, 0, len(configuration.Config.Entrypoint)),
				configuration.Config.Entrypoint...,
			),
			Command: append(
				make([]string, 0, len(configuration.Config.Cmd)),
				configuration.Config.Cmd...,
			),
			User:            configuration.Config.User,
			Filesystem:      filesystem,
			EntrypointFiles: entrypointFiles,
		},
		pathExists:            pathExists,
		pathStates:            pathStates,
		entrypointEnvironment: entrypointEnvironment,
		uses:                  normalizedUses,
		imageEnvironment:      append([]string(nil), configuration.Config.Env...),
		defaultUID:            defaultUID,
		defaultGID:            defaultGID,
		defaultIdentityKnown:  defaultIdentityKnown,
	}, nil
}

func configuredIdentityNeedsLookup(user string) bool {
	if user == "" {
		return false
	}
	name, group, found := strings.Cut(user, ":")
	if !found {
		group = ""
	}
	_, numericUser := parseNumericID(name)
	_, numericGroup := parseNumericID(group)
	return !numericUser || (group != "" && !numericGroup) ||
		(group == "" && name != "0")
}

func resolveConfiguredIdentity(
	configured string,
	passwd []byte,
	group []byte,
) (int, int, bool) {
	if configured == "" {
		return 0, 0, true
	}
	userName, groupName, found := strings.Cut(configured, ":")
	if !found {
		groupName = ""
	}
	uid, uidKnown := parseNumericID(userName)
	gid, gidKnown := parseNumericID(groupName)
	var passwdGID int
	var passwdFound bool
	for _, line := range bytes.Split(passwd, []byte{'\n'}) {
		fields := bytes.Split(line, []byte{':'})
		if len(fields) < 4 {
			continue
		}
		entryUID, entryUIDKnown := parseNumericID(string(fields[2]))
		entryGID, entryGIDKnown := parseNumericID(string(fields[3]))
		if !entryUIDKnown || !entryGIDKnown {
			continue
		}
		if (!uidKnown && string(fields[0]) == userName) ||
			(uidKnown && entryUID == uid) {
			uid = entryUID
			uidKnown = true
			passwdGID = entryGID
			passwdFound = true
			break
		}
	}
	if groupName == "" && passwdFound {
		gid, gidKnown = passwdGID, true
	}
	if groupName != "" && !gidKnown {
		for _, line := range bytes.Split(group, []byte{'\n'}) {
			fields := bytes.Split(line, []byte{':'})
			if len(fields) < 3 || string(fields[0]) != groupName {
				continue
			}
			gid, gidKnown = parseNumericID(string(fields[2]))
			break
		}
	}
	return uid, gid, uidKnown && gidKnown
}

func officialPathType(kind byte) string {
	switch kind {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hardlink"
	default:
		if kind == 0 {
			return "file"
		}
		return fmt.Sprintf("tar-%d", kind)
	}
}

// inspectOfficialImage is retained as a narrow test seam. Delivery admission
// always uses inspectOfficialCandidate so candidate defaults and final
// invocation evidence are normalized together.
func inspectOfficialImage(
	ctx context.Context,
	source string,
	requiredPaths []string,
	requiredEnvironment []string,
) (officialImageInspection, error) {
	use := finalImageUse{
		artifact: "inspection",
		invocation: containerInvocation{
			Location:   "inspection",
			Runtime:    map[string]any{},
			PodRuntime: map[string]any{},
		},
	}
	for _, required := range requiredPaths {
		use.obligations = append(use.obligations, filesystemObligation{
			Path:       required,
			Origin:     "inspection",
			Executable: standardExecutablePath(required),
		})
	}
	inspection, err := inspectOfficialCandidate(
		ctx,
		source,
		config.Image{},
		[]finalImageUse{use},
	)
	if err != nil {
		return officialImageInspection{}, err
	}
	if len(requiredEnvironment) == 0 {
		return inspection, nil
	}
	inspection.entrypointEnvironment = make(map[string]bool, len(requiredEnvironment))
	for _, required := range requiredEnvironment {
		for _, entrypoint := range inspection.config.EntrypointFiles {
			if containsString(entrypoint.Environment, required) {
				inspection.entrypointEnvironment[required] = true
			}
		}
	}
	return inspection, nil
}

func inspectOfficialFilesystem(
	image v1.Image,
	requiredPaths []string,
	contentPaths []string,
) (map[string]officialPathState, error) {
	contentQueries := make(map[string]struct{}, len(contentPaths))
	for _, required := range contentPaths {
		clean := strings.TrimPrefix(path.Clean("/"+required), "/")
		if clean != "." && clean != "" {
			contentQueries[clean] = struct{}{}
		}
	}
	indexCapacity := min(maxOfficialFilesystemEntries, max(1024, len(requiredPaths)*16))
	index := newOfficialPathIndex(indexCapacity)
	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}
	var processed int64
	for _, layer := range layers {
		stream, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}
		reader := tar.NewReader(io.LimitReader(stream, maxOfficialFilesystemBytes-processed+1))
		for {
			header, readErr := reader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = stream.Close()
				return nil, readErr
			}
			processed += header.Size
			if processed > maxOfficialFilesystemBytes {
				_ = stream.Close()
				return nil, fmt.Errorf(
					"official filesystem exceeds %d inspected bytes",
					maxOfficialFilesystemBytes,
				)
			}
			clean := strings.TrimPrefix(path.Clean("/"+header.Name), "/")
			if clean == "" || clean == "." {
				continue
			}
			base := path.Base(clean)
			if strings.HasPrefix(base, ".wh.") {
				directory := path.Dir(clean)
				if directory == "." {
					directory = ""
				}
				if base == ".wh..wh..opq" {
					index.removeChildren(directory)
					continue
				}
				deleted := path.Join(directory, strings.TrimPrefix(base, ".wh."))
				index.removeSubtree(deleted)
				continue
			}
			var content []byte
			_, contentRequested := contentQueries[clean]
			contentKnown := false
			if contentRequested &&
				(header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
				if header.Size > maxOfficialEntrypointBytes {
					_ = stream.Close()
					return nil, fmt.Errorf(
						"official entrypoint %s exceeds %d bytes",
						"/"+clean,
						maxOfficialEntrypointBytes,
					)
				}
				contentKnown = true
				content, err = io.ReadAll(io.LimitReader(reader, maxOfficialEntrypointBytes+1))
				if err != nil {
					_ = stream.Close()
					return nil, err
				}
				if int64(len(content)) > maxOfficialEntrypointBytes {
					_ = stream.Close()
					return nil, fmt.Errorf(
						"official entrypoint %s exceeds %d bytes",
						"/"+clean,
						maxOfficialEntrypointBytes,
					)
				}
			}
			if _, exists := index.states[clean]; !exists &&
				len(index.states) >= maxOfficialFilesystemEntries {
				_ = stream.Close()
				return nil, fmt.Errorf(
					"official filesystem exceeds %d entries",
					maxOfficialFilesystemEntries,
				)
			}
			index.set(clean, officialPathState{
				present:      true,
				mode:         header.Mode,
				uid:          header.Uid,
				gid:          header.Gid,
				kind:         header.Typeflag,
				link:         header.Linkname,
				content:      content,
				contentKnown: contentKnown,
			})
		}
		if err := stream.Close(); err != nil {
			return nil, err
		}
	}
	result := make(map[string]officialPathState, len(requiredPaths))
	missingContent := make(map[string]struct{})
	for _, required := range requiredPaths {
		clean := strings.TrimPrefix(path.Clean("/"+required), "/")
		state, resolveErr := resolveOfficialPath(index, clean, nil)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve official path %s: %w", required, resolveErr)
		}
		result[required] = state
		if _, requested := contentQueries[clean]; requested &&
			state.present && !state.contentKnown && state.resolved != "" {
			missingContent[state.resolved] = struct{}{}
		}
	}
	if len(missingContent) != 0 {
		contents, contentErr := readOfficialFileContents(image, missingContent)
		if contentErr != nil {
			return nil, contentErr
		}
		for required, state := range result {
			if content, found := contents[state.resolved]; found {
				state.content = content
				state.contentKnown = true
				result[required] = state
			}
		}
	}
	return result, nil
}

func readOfficialFileContents(
	image v1.Image,
	requested map[string]struct{},
) (map[string][]byte, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}
	contents := make(map[string][]byte, len(requested))
	requestedSubtrees := indexRequestedSubtrees(requested)
	var processed int64
	for _, layer := range layers {
		stream, openErr := layer.Uncompressed()
		if openErr != nil {
			return nil, openErr
		}
		reader := tar.NewReader(io.LimitReader(stream, maxOfficialFilesystemBytes-processed+1))
		for {
			header, readErr := reader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = stream.Close()
				return nil, readErr
			}
			processed += header.Size
			if processed > maxOfficialFilesystemBytes {
				_ = stream.Close()
				return nil, fmt.Errorf(
					"official filesystem exceeds %d inspected bytes",
					maxOfficialFilesystemBytes,
				)
			}
			clean := strings.TrimPrefix(path.Clean("/"+header.Name), "/")
			base := path.Base(clean)
			if strings.HasPrefix(base, ".wh.") {
				directory := officialPathParent(clean)
				if base == ".wh..wh..opq" {
					for _, requestedPath := range requestedSubtrees[directory] {
						if requestedPath != directory {
							delete(contents, requestedPath)
						}
					}
					continue
				}
				deleted := path.Join(directory, strings.TrimPrefix(base, ".wh."))
				for _, requestedPath := range requestedSubtrees[deleted] {
					delete(contents, requestedPath)
				}
				continue
			}
			if _, wanted := requested[clean]; !wanted ||
				(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
				continue
			}
			if header.Size > maxOfficialEntrypointBytes {
				_ = stream.Close()
				return nil, fmt.Errorf(
					"official entrypoint /%s exceeds %d bytes",
					clean,
					maxOfficialEntrypointBytes,
				)
			}
			content, contentErr := io.ReadAll(io.LimitReader(reader, maxOfficialEntrypointBytes+1))
			if contentErr != nil {
				_ = stream.Close()
				return nil, contentErr
			}
			if int64(len(content)) > maxOfficialEntrypointBytes {
				_ = stream.Close()
				return nil, fmt.Errorf(
					"official entrypoint /%s exceeds %d bytes",
					clean,
					maxOfficialEntrypointBytes,
				)
			}
			contents[clean] = content
		}
		if closeErr := stream.Close(); closeErr != nil {
			return nil, closeErr
		}
	}
	return contents, nil
}

func indexRequestedSubtrees(
	requested map[string]struct{},
) map[string][]string {
	subtrees := make(map[string][]string, len(requested))
	for requestedPath := range requested {
		for ancestor := requestedPath; ; ancestor = officialPathParent(ancestor) {
			subtrees[ancestor] = append(subtrees[ancestor], requestedPath)
			if ancestor == "" {
				break
			}
		}
	}
	return subtrees
}

func resolveOfficialPath(
	index *officialPathIndex,
	current string,
	visited map[string]struct{},
) (officialPathState, error) {
	if visited == nil {
		visited = make(map[string]struct{}, 8)
	}
	if len(visited) > 64 {
		return officialPathState{}, errors.New("link chain exceeds 64 entries")
	}
	if _, duplicate := visited[current]; duplicate {
		return officialPathState{}, fmt.Errorf("link cycle at /%s", current)
	}
	visited[current] = struct{}{}
	components := strings.Split(strings.Trim(current, "/"), "/")
	for componentIndex := range components {
		prefix := path.Join(components[:componentIndex+1]...)
		state, found := index.states[prefix]
		if !found || (state.kind != tar.TypeSymlink && state.kind != tar.TypeLink) {
			continue
		}
		target := state.link
		if target == "" {
			return officialPathState{}, fmt.Errorf("empty link target at /%s", prefix)
		}
		if state.kind == tar.TypeSymlink && !path.IsAbs(target) {
			target = path.Join(path.Dir("/"+prefix), target)
		}
		if componentIndex+1 < len(components) {
			target = path.Join(target, path.Join(components[componentIndex+1:]...))
		}
		target = strings.TrimPrefix(path.Clean("/"+target), "/")
		resolved, err := resolveOfficialPath(index, target, visited)
		if err != nil {
			return officialPathState{}, err
		}
		if !resolved.present {
			if componentIndex+1 < len(components) {
				return officialPathState{}, nil
			}
			return officialPathState{}, fmt.Errorf(
				"dangling link /%s -> /%s",
				prefix,
				target,
			)
		}
		resolved.link = state.link
		return resolved, nil
	}
	state, found := index.states[current]
	if !found {
		// A queried directory may be implicit in the archive.
		if len(index.children[current]) != 0 {
			return officialPathState{present: true, kind: tar.TypeDir, mode: 0o755}, nil
		}
		return officialPathState{}, nil
	}
	state.resolved = current
	return state, nil
}

func officialEntrypointCandidates(entrypoint, environment []string) []string {
	if len(entrypoint) == 0 {
		return nil
	}
	executable := strings.TrimSpace(entrypoint[0])
	if executable == "" {
		return nil
	}
	if strings.HasPrefix(executable, "/") {
		return []string{path.Clean(executable)}
	}
	if strings.Contains(executable, "/") {
		return []string{path.Clean("/" + executable)}
	}
	return compactSorted(executablePATHCandidates(executable, environment))
}

func officialEntrypointEvidence(
	entrypointPaths []string,
	requiredEnvironment []string,
	states map[string]officialPathState,
) ([]config.ImageEntrypointEvidence, map[string]bool) {
	evidence := make([]config.ImageEntrypointEvidence, 0, len(entrypointPaths))
	implemented := make(map[string]bool, len(requiredEnvironment))
	for _, candidate := range entrypointPaths {
		state := states[candidate]
		if !state.present || len(state.content) == 0 {
			continue
		}
		references := make([]string, 0, len(requiredEnvironment))
		for _, variable := range requiredEnvironment {
			if bytes.Contains(state.content, []byte(variable)) {
				references = append(references, variable)
				implemented[variable] = true
			}
		}
		digest := sha256.Sum256(state.content)
		evidence = append(evidence, config.ImageEntrypointEvidence{
			Path:        candidate,
			SHA256:      hex.EncodeToString(digest[:]),
			Environment: references,
		})
	}
	return evidence, implemented
}

func compareOfficialCandidate(
	image config.Image,
	inspection officialImageInspection,
	uses []finalImageUse,
) []string {
	var mismatches []string
	for _, use := range uses {
		prefix := use.artifact + "/" + use.invocation.Location + ": "
		obligations := use.obligations
		if len(obligations) == 0 {
			for _, required := range use.requiredPaths {
				obligations = append(obligations, filesystemObligation{
					Path:       required,
					Origin:     "runtime contract",
					Executable: standardExecutablePath(required),
				})
			}
		}
		for _, obligation := range obligations {
			candidates := []string{obligation.Path}
			if obligation.SearchPATH {
				candidates = executablePATHCandidates(
					obligation.Path,
					inspection.imageEnvironment,
				)
				if len(candidates) == 0 {
					mismatches = append(
						mismatches,
						prefix+obligation.Origin+
							" cannot resolve bare executable "+obligation.Path+
							" because the official PATH is absent or unsupported",
					)
					continue
				}
			}
			compatible := false
			for _, candidate := range candidates {
				if obligation.Executable {
					compatible = compatible || executablePathCompatible(
						inspection,
						candidate,
						use.invocation,
					)
					continue
				}
				compatible = compatible || inspection.pathExists[candidate]
			}
			if compatible {
				if obligation.Interpreter != "" &&
					!interpreterCompatible(
						inspection,
						candidates,
						obligation.Interpreter,
					) {
					mismatches = append(
						mismatches,
						prefix+obligation.Origin+" requires official "+
							obligation.Interpreter+"-compatible interpreter "+
							obligation.Path,
					)
				}
				continue
			}
			kind := "path "
			if obligation.Executable {
				kind = "executable "
			}
			mismatches = append(
				mismatches,
				prefix+obligation.Origin+" requires official "+kind+obligation.Path,
			)
			if obligation.Interpreter != "" {
				mismatches = append(
					mismatches,
					prefix+obligation.Origin+" requires official "+
						obligation.Interpreter+"-compatible interpreter "+
						obligation.Path,
				)
			}
		}
		environment := use.requiredEnvironment
		if environment == nil {
			environment = requiredEntrypointEnvironment(image, use.invocation)
		}
		for _, required := range environment {
			if !inspection.entrypointEnvironment[required] {
				mismatches = append(
					mismatches,
					prefix+"official entrypoint does not implement final environment contract "+required,
				)
			}
		}
	}
	return compactSorted(mismatches)
}

func interpreterCompatible(
	inspection officialImageInspection,
	candidates []string,
	interpreter string,
) bool {
	if interpreter != "bash" {
		return false
	}
	for _, candidate := range candidates {
		state := inspection.pathStates[candidate]
		if state.present && path.Base(state.resolved) == "bash" {
			return true
		}
	}
	return false
}

func executablePathCompatible(
	inspection officialImageInspection,
	candidate string,
	invocation containerInvocation,
) bool {
	state, hasState := inspection.pathStates[candidate]
	if !hasState {
		return inspection.pathExists[candidate]
	}
	if !state.present {
		return false
	}
	mode := state.mode & 0o777
	if mode&0o111 == 0 {
		return false
	}
	runAsUser, runAsGroup := invocationRunAs(invocation)
	if runAsUser == "" {
		if !inspection.defaultIdentityKnown {
			return false
		}
		runAsUser = strconv.Itoa(inspection.defaultUID)
		if runAsGroup == "" {
			runAsGroup = strconv.Itoa(inspection.defaultGID)
		}
	}
	uid, userKnown := parseNumericID(runAsUser)
	gid, groupKnown := parseNumericID(runAsGroup)
	switch {
	case !userKnown:
		return false
	case uid == state.uid:
		return mode&0o100 != 0
	case groupKnown && gid == state.gid:
		return mode&0o010 != 0
	default:
		return mode&0o001 != 0
	}
}

func invocationRunAs(invocation containerInvocation) (string, string) {
	user, group := securityContextIDs(invocation.PodRuntime)
	containerUser, containerGroup := securityContextIDs(invocation.Runtime)
	if containerUser != "" {
		user = containerUser
	}
	if containerGroup != "" {
		group = containerGroup
	}
	return user, group
}

func securityContextIDs(runtime map[string]any) (string, string) {
	security, _ := runtime["securityContext"].(map[string]any)
	return scalarID(security["runAsUser"]), scalarID(security["runAsGroup"])
}

func scalarID(value any) string {
	switch typed := value.(type) {
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
	}
	return ""
}

func parseNumericID(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= 0
}

func requiredInvocationPaths(invocation containerInvocation) ([]string, error) {
	obligations, err := requiredInvocationObligations(invocation, nil, nil, nil, "")
	if err != nil {
		return nil, err
	}
	return obligationPaths(obligations), nil
}

func requiredInvocationObligations(
	invocation containerInvocation,
	defaultEntrypoint []string,
	defaultCommand []string,
	imageEnvironment []string,
	defaultWorkingDirectory string,
) ([]filesystemObligation, error) {
	if runtimeWorkingDirectory, _ := invocation.Runtime["workingDir"].(string); runtimeWorkingDirectory == "" && defaultWorkingDirectory != "" {
		invocation.Runtime = cloneMap(invocation.Runtime)
		invocation.Runtime["workingDir"] = defaultWorkingDirectory
	}
	command := stringSlice(invocation.Command)
	arguments := stringSlice(invocation.Args)
	defaultsKnown := defaultEntrypoint != nil ||
		defaultCommand != nil ||
		imageEnvironment != nil
	if len(command) == 0 {
		command = append([]string(nil), defaultEntrypoint...)
	}
	if len(arguments) == 0 {
		arguments = append([]string(nil), defaultCommand...)
	}
	if len(command) == 0 && len(arguments) != 0 && defaultsKnown {
		command, arguments = arguments[:1], arguments[1:]
	}
	mounted := make(map[string]mountedConfigFile, len(invocation.MountedFiles))
	for _, file := range invocation.MountedFiles {
		if !path.IsAbs(file.Destination) || !validHexSHA256(file.SHA256) ||
			len(file.Content) > maxMountedConfigFileBytes {
			return nil, fmt.Errorf(
				"mounted ConfigMap %q has invalid bounded evidence",
				file.Destination,
			)
		}
		digest := sha256.Sum256(file.Content)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return nil, fmt.Errorf(
				"mounted ConfigMap %q content does not match its digest",
				file.Destination,
			)
		}
		mounted[path.Clean(file.Destination)] = file
	}
	mounts := compactSorted(append(
		invocationMountPaths(invocation.Runtime),
		invocation.PodMountPaths...,
	))
	var obligations []filesystemObligation
	if len(command) != 0 {
		if err := appendCommandObligations(
			command,
			arguments,
			"effective command",
			invocation,
			mounted,
			mounts,
			&obligations,
			0,
		); err != nil {
			return nil, err
		}
	} else {
		var runtimePaths []string
		collectRuntimePaths(arguments, "arguments", &runtimePaths)
		for _, required := range runtimePaths {
			appendFileObligation(required, "arguments", mounts, &obligations)
		}
	}
	for _, probe := range [...]string{"livenessProbe", "readinessProbe", "startupProbe"} {
		value, exists := invocation.Runtime[probe]
		if !exists {
			continue
		}
		probeMap, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s is not a structured probe", probe)
		}
		execAction, hasExec := probeMap["exec"].(map[string]any)
		if !hasExec {
			continue
		}
		probeCommand := stringSlice(execAction["command"])
		if len(probeCommand) == 0 {
			return nil, fmt.Errorf("%s exec command is empty or dynamic", probe)
		}
		if err := appendCommandObligations(
			probeCommand[:1],
			probeCommand[1:],
			probe,
			invocation,
			mounted,
			mounts,
			&obligations,
			0,
		); err != nil {
			return nil, err
		}
	}
	lifecycle, _ := invocation.Runtime["lifecycle"].(map[string]any)
	for _, phase := range [...]string{"postStart", "preStop"} {
		action, _ := lifecycle[phase].(map[string]any)
		execAction, hasExec := action["exec"].(map[string]any)
		if !hasExec {
			continue
		}
		lifecycleCommand := stringSlice(execAction["command"])
		if len(lifecycleCommand) == 0 {
			return nil, fmt.Errorf("lifecycle %s exec command is empty or dynamic", phase)
		}
		if err := appendCommandObligations(
			lifecycleCommand[:1],
			lifecycleCommand[1:],
			"lifecycle "+phase,
			invocation,
			mounted,
			mounts,
			&obligations,
			0,
		); err != nil {
			return nil, err
		}
	}
	if workingDirectory, _ := invocation.Runtime["workingDir"].(string); workingDirectory != "" {
		if !path.IsAbs(workingDirectory) {
			return nil, fmt.Errorf("workingDir %q is not absolute", workingDirectory)
		}
		appendFileObligation(
			path.Clean(workingDirectory),
			"workingDir",
			mounts,
			&obligations,
		)
	}
	for _, file := range invocation.MountedFiles {
		var configured []string
		collectConfigurationImagePaths(string(file.Content), &configured)
		for _, configuredPath := range configured {
			appendFileObligation(
				configuredPath,
				"mounted ConfigMap "+file.Destination,
				mounts,
				&obligations,
			)
		}
	}
	return compactObligations(obligations), nil
}

func appendCommandObligations(
	command []string,
	arguments []string,
	origin string,
	invocation containerInvocation,
	mounted map[string]mountedConfigFile,
	mounts []string,
	obligations *[]filesystemObligation,
	depth int,
) error {
	if depth > maxMountedScriptDepth {
		return fmt.Errorf("%s mounted script recursion exceeds %d", origin, maxMountedScriptDepth)
	}
	if len(command) == 0 || strings.TrimSpace(command[0]) == "" ||
		strings.Contains(command[0], "$") {
		return fmt.Errorf("%s executable is dynamic or empty", origin)
	}
	executable := strings.TrimSpace(command[0])
	if file, found := mounted[path.Clean(executable)]; found {
		return appendMountedScriptObligations(
			file,
			origin,
			invocation,
			mounted,
			mounts,
			obligations,
			depth+1,
			true,
		)
	}
	obligation, err := executableObligation(executable, origin, invocation)
	if err != nil {
		return err
	}
	if !pathProvidedByRuntime(obligation.Path, mounts) {
		*obligations = append(*obligations, obligation)
	}
	if script, scripted := shellInvocationScript(command, arguments); scripted {
		commands, scanErr := shellCommands(script)
		if scanErr != nil {
			return fmt.Errorf("%s: %w", origin, scanErr)
		}
		for _, call := range commands {
			if call.boundedGlob {
				if err := appendBoundedMountedScripts(
					origin,
					invocation,
					mounted,
					mounts,
					obligations,
					depth+1,
				); err != nil {
					return err
				}
				continue
			}
			if call.source {
				file, found := mounted[path.Clean(call.executable)]
				if !found {
					return fmt.Errorf(
						"%s sources unsupported non-mounted script %q",
						origin,
						call.executable,
					)
				}
				if err := appendMountedScriptObligations(
					file,
					origin+" source "+call.executable,
					invocation,
					mounted,
					mounts,
					obligations,
					depth+1,
					false,
				); err != nil {
					return err
				}
				continue
			}
			if err := appendCommandObligations(
				[]string{call.executable},
				call.arguments,
				origin+" shell",
				invocation,
				mounted,
				mounts,
				obligations,
				depth+1,
			); err != nil {
				return err
			}
		}
		return nil
	}
	scriptPath, hasScript, scriptErr := shellInvocationFile(command, arguments)
	if scriptErr != nil {
		return fmt.Errorf("%s: %w", origin, scriptErr)
	}
	if hasScript {
		file, mountedScript := mounted[path.Clean(scriptPath)]
		if mountedScript {
			if err := appendMountedScriptObligations(
				file,
				origin+" mounted script",
				invocation,
				mounted,
				mounts,
				obligations,
				depth+1,
				false,
			); err != nil {
				return err
			}
		}
	}
	var runtimePaths []string
	collectRuntimePaths(arguments, "arguments", &runtimePaths)
	for _, required := range runtimePaths {
		appendFileObligation(required, origin+" argument", mounts, obligations)
	}
	return nil
}

func appendMountedScriptObligations(
	file mountedConfigFile,
	origin string,
	invocation containerInvocation,
	mounted map[string]mountedConfigFile,
	mounts []string,
	obligations *[]filesystemObligation,
	depth int,
	useShebang bool,
) error {
	if bytes.IndexByte(file.Content, 0) >= 0 {
		return fmt.Errorf("%s mounted executable %q is not text", origin, file.Destination)
	}
	commands, err := shellCommandsWithVariables(
		string(file.Content),
		map[string]string{"0": file.Destination},
	)
	if err != nil {
		return fmt.Errorf("%s mounted executable %q: %w", origin, file.Destination, err)
	}
	if useShebang {
		interpreter, found := mountedScriptInterpreter(file.Content, origin)
		if found {
			*obligations = append(*obligations, interpreter)
		}
	}
	for _, call := range commands {
		if call.boundedGlob {
			if err := appendBoundedMountedScripts(
				origin,
				invocation,
				mounted,
				mounts,
				obligations,
				depth+1,
			); err != nil {
				return err
			}
			continue
		}
		if call.source {
			source, found := mounted[path.Clean(call.executable)]
			if !found {
				return fmt.Errorf(
					"%s mounted script sources unsupported path %q",
					origin,
					call.executable,
				)
			}
			if err := appendMountedScriptObligations(
				source,
				origin+" source "+call.executable,
				invocation,
				mounted,
				mounts,
				obligations,
				depth+1,
				false,
			); err != nil {
				return err
			}
			continue
		}
		if err := appendCommandObligations(
			[]string{call.executable},
			call.arguments,
			origin+" mounted script",
			invocation,
			mounted,
			mounts,
			obligations,
			depth+1,
		); err != nil {
			return err
		}
	}
	return nil
}

func appendBoundedMountedScripts(
	origin string,
	invocation containerInvocation,
	mounted map[string]mountedConfigFile,
	mounts []string,
	obligations *[]filesystemObligation,
	depth int,
) error {
	found := false
	for _, file := range mounted {
		firstLine, _, _ := strings.Cut(string(file.Content), "\n")
		if !strings.HasSuffix(file.Destination, ".sh") &&
			firstLine != "#!/bin/sh" &&
			firstLine != "#!/bin/bash" &&
			firstLine != "#!/usr/bin/env sh" &&
			firstLine != "#!/usr/bin/env bash" {
			continue
		}
		found = true
		if err := appendMountedScriptObligations(
			file,
			origin+" bounded mounted script",
			invocation,
			mounted,
			mounts,
			obligations,
			depth,
			true,
		); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%s dynamic mounted-script glob has no bounded scripts", origin)
	}
	return nil
}

func mountedScriptInterpreter(
	content []byte,
	origin string,
) (filesystemObligation, bool) {
	firstLine, _, _ := strings.Cut(string(content), "\n")
	firstLine = strings.TrimSuffix(firstLine, "\r")
	var obligation filesystemObligation
	switch firstLine {
	case "#!/bin/sh":
		obligation.Path = "/bin/sh"
	case "#!/bin/bash":
		obligation.Path = "/bin/bash"
		obligation.Interpreter = "bash"
	case "#!/usr/bin/env sh":
		obligation.Path = "sh"
		obligation.SearchPATH = true
	case "#!/usr/bin/env bash":
		obligation.Path = "bash"
		obligation.SearchPATH = true
		obligation.Interpreter = "bash"
	default:
		return filesystemObligation{}, false
	}
	obligation.Origin = origin + " shebang"
	obligation.Executable = true
	if path.Base(obligation.Path) == "sh" && scriptRequiresBash(content) {
		obligation.Interpreter = "bash"
	}
	return obligation, true
}

func scriptRequiresBash(content []byte) bool {
	program, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).
		Parse(bytes.NewReader(content), "mounted-script")
	if err != nil {
		return false
	}
	requiresBash := false
	syntax.Walk(program, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.ArithmCmd,
			*syntax.ArrayExpr,
			*syntax.CStyleLoop,
			*syntax.CoprocClause,
			*syntax.ExtGlob,
			*syntax.LetClause,
			*syntax.ProcSubst,
			*syntax.TestClause:
			requiresBash = true
			return false
		}
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			requiresBash = typed.RsrvWord
		case *syntax.SglQuoted:
			requiresBash = typed.Dollar
		}
		return !requiresBash
	})
	if requiresBash {
		return true
	}
	_, err = syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(bytes.NewReader(content), "mounted-script")
	return err != nil
}

func executableObligation(
	executable string,
	origin string,
	invocation containerInvocation,
) (filesystemObligation, error) {
	switch {
	case path.IsAbs(executable):
		return filesystemObligation{
			Path: path.Clean(executable), Origin: origin, Executable: true,
		}, nil
	case strings.Contains(executable, "/"):
		workingDirectory, _ := invocation.Runtime["workingDir"].(string)
		if !path.IsAbs(workingDirectory) {
			return filesystemObligation{}, fmt.Errorf(
				"%s relative executable %q has no absolute workingDir",
				origin,
				executable,
			)
		}
		return filesystemObligation{
			Path:       path.Join(workingDirectory, executable),
			Origin:     origin,
			Executable: true,
		}, nil
	default:
		return filesystemObligation{
			Path: executable, Origin: origin, Executable: true, SearchPATH: true,
		}, nil
	}
}

func appendFileObligation(
	required string,
	origin string,
	mounts []string,
	obligations *[]filesystemObligation,
) {
	if !path.IsAbs(required) || runtimeProvidedPath(required) ||
		pathProvidedByRuntime(required, mounts) {
		return
	}
	*obligations = append(*obligations, filesystemObligation{
		Path:   path.Clean(required),
		Origin: origin,
	})
}

func pathProvidedByRuntime(candidate string, mounts []string) bool {
	if !path.IsAbs(candidate) {
		return false
	}
	candidate = path.Clean(candidate)
	for _, mount := range mounts {
		if candidate == mount ||
			strings.HasPrefix(candidate, strings.TrimSuffix(mount, "/")+"/") {
			return true
		}
	}
	return false
}

func compactObligations(obligations []filesystemObligation) []filesystemObligation {
	sort.Slice(obligations, func(i, j int) bool {
		if obligations[i].Path != obligations[j].Path {
			return obligations[i].Path < obligations[j].Path
		}
		if obligations[i].Executable != obligations[j].Executable {
			return !obligations[i].Executable
		}
		if obligations[i].SearchPATH != obligations[j].SearchPATH {
			return !obligations[i].SearchPATH
		}
		if obligations[i].Interpreter != obligations[j].Interpreter {
			return obligations[i].Interpreter < obligations[j].Interpreter
		}
		return obligations[i].Origin < obligations[j].Origin
	})
	result := obligations[:0]
	for _, obligation := range obligations {
		if len(result) != 0 {
			previous := result[len(result)-1]
			if previous.Path == obligation.Path &&
				previous.Executable == obligation.Executable &&
				previous.SearchPATH == obligation.SearchPATH &&
				previous.Interpreter == obligation.Interpreter {
				continue
			}
		}
		result = append(result, obligation)
	}
	return result
}

func obligationPaths(obligations []filesystemObligation) []string {
	var result []string
	for _, obligation := range obligations {
		if path.IsAbs(obligation.Path) {
			result = append(result, obligation.Path)
		}
	}
	return compactSorted(result)
}

func obligationQueryPaths(
	obligations []filesystemObligation,
	environment []string,
) []string {
	var result []string
	for _, obligation := range obligations {
		if obligation.SearchPATH {
			result = append(result, executablePATHCandidates(obligation.Path, environment)...)
			continue
		}
		result = append(result, obligation.Path)
	}
	return compactSorted(result)
}

func configurationImagePath(candidate string) bool {
	clean := path.Clean(candidate)
	if !strings.HasPrefix(clean, "/") || strings.Count(clean, "/") < 2 {
		return false
	}
	return !strings.ContainsAny(clean, "^$*?[]{}|")
}

func collectConfigurationImagePaths(value any, destination *[]string) {
	switch typed := value.(type) {
	case string:
		section := ""
		for _, line := range strings.Split(typed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") ||
				strings.HasPrefix(line, "//") ||
				strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.ToLower(strings.TrimSpace(
					strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"),
				))
				continue
			}
			separator := strings.IndexAny(line, "=:")
			if separator <= 0 {
				continue
			}
			key := strings.ToLower(strings.Trim(strings.TrimSpace(line[:separator]), `"'`))
			if !staticConfigurationPathKey(section, key) {
				continue
			}
			var candidates []string
			collectRuntimePaths(line[separator+1:], "configuration", &candidates)
			for _, candidate := range candidates {
				if configurationImagePath(candidate) {
					*destination = append(*destination, candidate)
				}
			}
		}
	case map[string]any:
		for _, nested := range typed {
			collectConfigurationImagePaths(nested, destination)
		}
	case []any:
		for _, nested := range typed {
			collectConfigurationImagePaths(nested, destination)
		}
	}
}

func staticConfigurationPathKey(section, key string) bool {
	if key == "static.path" || strings.HasSuffix(key, ".static.path") ||
		key == "plugin.path" || strings.HasSuffix(key, ".plugin.path") {
		return true
	}
	return key == "path" && strings.Contains(section, "plugin")
}

func shellInvocationScript(command, arguments []string) (string, bool) {
	switch commandName(command) {
	case "sh", "bash", "ash", "dash":
	default:
		return "", false
	}
	tail := make([]string, 0, max(0, len(command)-1)+len(arguments))
	if len(command) > 1 {
		tail = append(tail, command[1:]...)
	}
	tail = append(tail, arguments...)
	for index := 0; index < len(tail); index++ {
		argument := tail[index]
		if argument == "--" || len(argument) < 2 ||
			(argument[0] != '-' && argument[0] != '+') {
			return "", false
		}
		options := strings.TrimLeft(argument, "-+")
		if strings.ContainsRune(options, 'c') {
			if index+1 >= len(tail) {
				return "", false
			}
			return tail[index+1], true
		}
		if options == "o" || options == "O" {
			index++
			if index >= len(tail) {
				return "", false
			}
		}
	}
	return "", false
}

func shellInvocationFile(
	command, arguments []string,
) (string, bool, error) {
	switch commandName(command) {
	case "sh", "bash", "ash", "dash":
	default:
		return "", false, nil
	}
	tail := make([]string, 0, max(0, len(command)-1)+len(arguments))
	if len(command) > 1 {
		tail = append(tail, command[1:]...)
	}
	tail = append(tail, arguments...)
	for index := 0; index < len(tail); index++ {
		argument := strings.TrimSpace(tail[index])
		if argument == "--" {
			index++
			if index >= len(tail) {
				return "", false, nil
			}
			argument = strings.TrimSpace(tail[index])
		}
		if argument == "" || strings.Contains(argument, "$") {
			return "", false, errors.New(
				"shell script path is empty or dynamic",
			)
		}
		if argument[0] != '-' && argument[0] != '+' {
			return argument, true, nil
		}
		options := strings.TrimLeft(argument, "-+")
		if strings.ContainsRune(options, 'c') {
			return "", false, nil
		}
		if options == "o" || options == "O" {
			index++
			if index >= len(tail) {
				return "", false, errors.New(
					"shell option requires a missing value",
				)
			}
		}
	}
	return "", false, nil
}

func requiredEntrypointEnvironment(
	image config.Image,
	invocation containerInvocation,
) []string {
	var proposed []string
	for _, reference := range image.BigBangRefs {
		switch imageRepository(reference) {
		case "registry1.dso.mil/ironbank/opensource/postgres/postgresql":
			proposed = append(proposed, "POSTGRESQL_VOLUME_DIR")
		}
	}
	if len(proposed) == 0 {
		return []string{}
	}
	rendered := make(map[string]struct{})
	entries, _ := invocation.Runtime["env"].([]any)
	for _, entry := range entries {
		variable, _ := entry.(map[string]any)
		name, _ := variable["name"].(string)
		if name != "" {
			rendered[name] = struct{}{}
		}
	}
	required := proposed[:0]
	for _, name := range proposed {
		if _, observed := rendered[name]; observed {
			required = append(required, name)
		}
	}
	required = compactSorted(required)
	if required == nil {
		return []string{}
	}
	return required
}

func runtimeProvidedPath(candidate string) bool {
	clean := path.Clean(candidate)
	if clean == "/" || clean == "/dev" || strings.HasPrefix(clean, "/dev/") ||
		clean == "/proc" || strings.HasPrefix(clean, "/proc/") ||
		clean == "/sys" || strings.HasPrefix(clean, "/sys/") ||
		clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") ||
		clean == "/var/run/secrets/kubernetes.io/serviceaccount" ||
		strings.HasPrefix(clean, "/var/run/secrets/kubernetes.io/serviceaccount/") {
		return true
	}
	return false
}

func invocationMountPaths(runtime map[string]any) []string {
	raw, _ := runtime["volumeMounts"].([]any)
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		mount, _ := entry.(map[string]any)
		value, _ := mount["mountPath"].(string)
		if strings.HasPrefix(value, "/") {
			result = append(result, path.Clean(value))
		}
	}
	return compactSorted(result)
}

func collectRuntimePaths(value any, key string, destination *[]string) {
	switch typed := value.(type) {
	case string:
		if key == "mountPath" || key == "subPath" || key == "subPathExpr" {
			return
		}
		for _, token := range strings.FieldsFunc(typed, func(character rune) bool {
			return character == ' ' || character == '\t' || character == '\r' ||
				character == '\n' || character == '"' || character == '\'' ||
				character == ',' || character == ';' || character == '=' ||
				character == '(' || character == ')' || character == '[' ||
				character == ']'
		}) {
			token = strings.TrimRight(token, ":")
			if strings.HasPrefix(token, "/") && !strings.Contains(token, "$") {
				// Root-relative HTTP endpoints such as /metrics and /healthz
				// are common flag values. They are not evidence of immutable
				// image content; arguments must identify a concrete nested
				// filesystem location before admission inspects the layer.
				if key == "arguments" && !configurationImagePath(token) {
					continue
				}
				*destination = append(*destination, path.Clean(token))
			}
		}
	case []any:
		for _, item := range typed {
			collectRuntimePaths(item, key, destination)
		}
	case []string:
		for _, item := range typed {
			collectRuntimePaths(item, key, destination)
		}
	case map[string]any:
		for childKey, item := range typed {
			collectRuntimePaths(item, childKey, destination)
		}
	}
}

func stringSlice(value any) []string {
	if values, ok := value.([]string); ok {
		return append([]string{}, values...)
	}
	raw, ok := value.([]any)
	if !ok {
		return []string{}
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return []string{}
		}
		result = append(result, text)
	}
	return result
}

func commandName(command []string) string {
	if len(command) == 0 {
		return ""
	}
	return path.Base(command[0])
}

func executableCandidates(executable string) []string {
	executable = strings.TrimSpace(executable)
	if executable == "" || strings.Contains(executable, "$") {
		return nil
	}
	if strings.HasPrefix(executable, "/") {
		return []string{path.Clean(executable)}
	}
	if strings.Contains(executable, "/") {
		return nil
	}
	return []string{
		"/usr/local/sbin/" + executable,
		"/usr/local/bin/" + executable,
		"/usr/sbin/" + executable,
		"/usr/bin/" + executable,
		"/sbin/" + executable,
		"/bin/" + executable,
	}
}

func executablePATHCandidates(executable string, environment []string) []string {
	if executable == "" || strings.ContainsAny(executable, "/$\x00") {
		return nil
	}
	for _, variable := range environment {
		name, value, found := strings.Cut(variable, "=")
		if !found || name != "PATH" {
			continue
		}
		var candidates []string
		for _, directory := range strings.Split(value, ":") {
			if !path.IsAbs(directory) || strings.Contains(directory, "$") {
				continue
			}
			candidates = append(candidates, path.Join(directory, executable))
		}
		return candidates
	}
	return nil
}

func standardExecutablePath(candidate string) bool {
	for _, prefix := range [...]string{
		"/usr/local/sbin/", "/usr/local/bin/", "/usr/sbin/",
		"/usr/bin/", "/sbin/", "/bin/",
	} {
		if strings.HasPrefix(candidate, prefix) &&
			!strings.Contains(strings.TrimPrefix(candidate, prefix), "/") {
			return true
		}
	}
	return false
}

var shellBuiltins = map[string]struct{}{
	":": {}, ".": {}, "[": {}, "[[": {}, "alias": {}, "bg": {},
	"break": {}, "builtin": {}, "cd": {}, "command": {}, "continue": {},
	"declare": {}, "dirs": {}, "disown": {}, "echo": {}, "enable": {},
	"eval": {}, "exec": {}, "exit": {}, "export": {}, "false": {},
	"fc": {}, "fg": {}, "getopts": {}, "hash": {}, "help": {},
	"history": {}, "jobs": {}, "kill": {}, "let": {}, "local": {},
	"logout": {}, "mapfile": {}, "popd": {}, "printf": {}, "pushd": {},
	"pwd": {}, "read": {}, "readarray": {}, "readonly": {}, "return": {},
	"set": {}, "shift": {}, "shopt": {}, "source": {}, "suspend": {},
	"test": {}, "times": {}, "trap": {}, "true": {}, "type": {},
	"typeset": {}, "ulimit": {}, "umask": {}, "unalias": {}, "unset": {},
	"wait": {},
}

type shellCommand struct {
	executable  string
	arguments   []string
	source      bool
	boundedGlob bool
}

func shellExecutables(script string) ([]string, error) {
	commands, err := shellCommands(script)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, command := range commands {
		if !command.source {
			result = append(result, command.executable)
		}
	}
	return compactSorted(result), nil
}

func shellCommands(script string) ([]shellCommand, error) {
	return shellCommandsWithVariables(script, nil)
}

func shellCommandsWithVariables(
	script string,
	initialVariables map[string]string,
) ([]shellCommand, error) {
	program, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).
		Parse(strings.NewReader(script), "rendered-command")
	if err != nil {
		return nil, fmt.Errorf("parse rendered shell command: %w", err)
	}
	functions := make(map[string]struct{})
	variables := make(map[string]string, len(initialVariables))
	for name, value := range initialVariables {
		variables[name] = value
	}
	ambiguousVariables := make(map[string]struct{})
	syntax.Walk(program, func(node syntax.Node) bool {
		declaration, ok := node.(*syntax.FuncDecl)
		if ok && declaration.Name != nil {
			functions[declaration.Name.Value] = struct{}{}
		}
		loop, ok := node.(*syntax.ForClause)
		if ok {
			iterator, wordLoop := loop.Loop.(*syntax.WordIter)
			if wordLoop && iterator.Name != nil && len(iterator.Items) == 1 {
				item, static := staticShellWordWithVariables(
					iterator.Items[0],
					variables,
				)
				if static && item == "*" {
					variables[iterator.Name.Value] = boundedMountedGlob
				}
			}
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 {
			return true
		}
		for _, assignment := range call.Assigns {
			if assignment.Name == nil || assignment.Value == nil ||
				assignment.Append || assignment.Index != nil ||
				assignment.Array != nil {
				continue
			}
			value, static := staticShellWordWithVariables(
				assignment.Value,
				variables,
			)
			if !static {
				delete(variables, assignment.Name.Value)
				ambiguousVariables[assignment.Name.Value] = struct{}{}
				continue
			}
			if previous, exists := variables[assignment.Name.Value]; exists && previous != value {
				delete(variables, assignment.Name.Value)
				ambiguousVariables[assignment.Name.Value] = struct{}{}
				continue
			}
			if _, ambiguous := ambiguousVariables[assignment.Name.Value]; !ambiguous {
				variables[assignment.Name.Value] = value
			}
		}
		return true
	})
	var result []shellCommand
	var scanErr error
	syntax.Walk(program, func(node syntax.Node) bool {
		if scanErr != nil {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		command, found, commandErr := shellCallCommand(call, functions, variables)
		if commandErr != nil {
			scanErr = commandErr
			return false
		}
		if found {
			result = append(result, command)
		}
		return true
	})
	if scanErr != nil {
		return nil, scanErr
	}
	return result, nil
}

func shellCallCommand(
	call *syntax.CallExpr,
	functions map[string]struct{},
	variables map[string]string,
) (shellCommand, bool, error) {
	if len(call.Args) == 0 {
		return shellCommand{}, false, nil
	}
	index := 0
	executable, static := staticShellWordWithVariables(call.Args[index], variables)
	if !static {
		if statusOnlyCommandSubstitution(call.Args[index], variables) {
			return shellCommand{}, false, nil
		}
		return shellCommand{}, false, errors.New("dynamic shell executable is unsupported")
	}
	for executable == "builtin" || executable == "command" ||
		executable == "exec" || executable == "env" {
		wrapper := executable
		index++
		for index < len(call.Args) {
			option, optionStatic := staticShellWordWithVariables(
				call.Args[index],
				variables,
			)
			if !optionStatic {
				return shellCommand{}, false, fmt.Errorf(
					"%s wrapper has a dynamic command boundary",
					executable,
				)
			}
			if !strings.HasPrefix(option, "-") &&
				(executable != "env" || !strings.Contains(option, "=")) {
				break
			}
			index++
		}
		if index == len(call.Args) {
			if wrapper != "env" {
				return shellCommand{}, false, nil
			}
			return shellCommand{}, false, fmt.Errorf(
				"%s wrapper has no executable",
				wrapper,
			)
		}
		executable, static = staticShellWordWithVariables(
			call.Args[index],
			variables,
		)
		if !static {
			return shellCommand{}, false, errors.New(
				"wrapped shell executable is dynamic",
			)
		}
	}
	if _, declared := functions[executable]; declared {
		return shellCommand{}, false, nil
	}
	if executable == boundedMountedGlob ||
		executable == "./"+boundedMountedGlob {
		return shellCommand{boundedGlob: true}, true, nil
	}
	if executable == "." || executable == "source" {
		if index+1 >= len(call.Args) {
			return shellCommand{}, false, fmt.Errorf("%s has no script path", executable)
		}
		source, sourceStatic := staticShellWordWithVariables(
			call.Args[index+1],
			variables,
		)
		if !sourceStatic || !path.IsAbs(source) {
			return shellCommand{}, false, fmt.Errorf(
				"%s script path is dynamic or relative",
				executable,
			)
		}
		return shellCommand{executable: path.Clean(source), source: true}, true, nil
	}
	if _, builtin := shellBuiltins[executable]; builtin {
		if executable == "eval" {
			return shellCommand{}, false, errors.New(
				"eval creates an unsupported dynamic command boundary",
			)
		}
		return shellCommand{}, false, nil
	}
	arguments := make([]string, 0, len(call.Args)-index-1)
	for _, argument := range call.Args[index+1:] {
		value, argumentStatic := staticShellWordWithVariables(argument, variables)
		if argumentStatic {
			arguments = append(arguments, value)
			continue
		}
		arguments = append(arguments, "")
	}
	if (commandName([]string{executable}) == "sh" ||
		commandName([]string{executable}) == "bash") &&
		len(arguments) >= 2 &&
		(arguments[0] == "-c" || arguments[0] == "-ec" || arguments[0] == "-ce") {
		if arguments[1] == "" {
			return shellCommand{}, false, fmt.Errorf(
				"%s receives a dynamic script",
				executable,
			)
		}
	}
	return shellCommand{executable: executable, arguments: arguments}, true, nil
}

func statusOnlyCommandSubstitution(
	word *syntax.Word,
	variables map[string]string,
) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	substitution, ok := word.Parts[0].(*syntax.CmdSubst)
	if !ok || len(substitution.Stmts) == 0 {
		return false
	}
	for _, statement := range substitution.Stmts {
		redirected := false
		for _, redirect := range statement.Redirs {
			if redirect.Op != syntax.RdrOut ||
				redirect.N != nil && redirect.N.Value != "1" {
				continue
			}
			destination, static := staticShellWordWithVariables(
				redirect.Word,
				variables,
			)
			if static && destination == "/dev/null" {
				redirected = true
				break
			}
		}
		if !redirected {
			return false
		}
	}
	return true
}

func staticShellWord(word *syntax.Word) (string, bool) {
	return staticShellWordWithVariables(word, nil)
}

func staticShellWordWithVariables(
	word *syntax.Word,
	variables map[string]string,
) (string, bool) {
	var builder strings.Builder
	var appendParts func([]syntax.WordPart) bool
	appendParts = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch typed := part.(type) {
			case *syntax.Lit:
				builder.WriteString(typed.Value)
			case *syntax.SglQuoted:
				builder.WriteString(typed.Value)
			case *syntax.DblQuoted:
				if !appendParts(typed.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if typed.Param == nil || !typed.Short && typed.Rbrace.IsValid() &&
					(typed.Excl || typed.Length || typed.IsSet ||
						typed.Index != nil || typed.Slice != nil ||
						typed.Repl != nil || typed.Exp != nil ||
						len(typed.Modifiers) != 0) {
					return false
				}
				value, found := variables[typed.Param.Value]
				if !found {
					return false
				}
				builder.WriteString(value)
			case *syntax.CmdSubst:
				value, found := staticShellCommandSubstitution(typed, variables)
				if !found {
					return false
				}
				builder.WriteString(value)
			default:
				return false
			}
		}
		return true
	}
	if !appendParts(word.Parts) {
		return "", false
	}
	return builder.String(), true
}

func staticShellCommandSubstitution(
	substitution *syntax.CmdSubst,
	variables map[string]string,
) (string, bool) {
	if len(substitution.Stmts) != 1 ||
		substitution.Stmts[0].Negated ||
		substitution.Stmts[0].Background ||
		len(substitution.Stmts[0].Redirs) != 0 {
		return "", false
	}
	call, ok := substitution.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 2 {
		return "", false
	}
	executable, executableStatic := staticShellWordWithVariables(
		call.Args[0],
		variables,
	)
	argument, argumentStatic := staticShellWordWithVariables(
		call.Args[1],
		variables,
	)
	if !executableStatic || !argumentStatic {
		return "", false
	}
	switch executable {
	case "dirname":
		return path.Dir(argument), true
	case "basename":
		return path.Base(argument), true
	default:
		return "", false
	}
}

func compatibilityBuildRecipe(
	image config.Image,
	buildBase string,
	mismatches []string,
) (string, []string, error) {
	if image.ID == "opensearch" ||
		image.ID == "opensearch-dashboards" {
		return "", nil, fmt.Errorf(
			"direct-chart image %s requires an official immutable mirror; compatibility builds are forbidden",
			image.ID,
		)
	}
	requirements, err := parseCompatibilityRequirements(mismatches)
	if err != nil {
		return "", nil, err
	}
	const dockerfile = "platform/build/docker/Dockerfile.delivery"
	if requirementsOnly(requirements, "path", map[string]struct{}{
		"/var/lib/bb-plugins/polystat-panel":   {},
		"/var/lib/bb-plugins/redis-datasource": {},
	}) && requirementsContain(requirements,
		"path", "/var/lib/bb-plugins/polystat-panel") &&
		requirementsContain(requirements,
			"path", "/var/lib/bb-plugins/redis-datasource") {
		return "grafana-plugins", []string{
			dockerfile,
			buildBase,
			"platform/build/compat/debian",
			"https://github.com/grafana/grafana-polystat-panel/releases/download/v2.1.16/grafana-polystat-panel-2.1.16.zip#sha256:3e1791f83b4db03134dac24521a52407c1990a1b56356dc440580ee4664f214c",
			"https://github.com/RedisGrafana/grafana-redis-datasource/releases/download/v2.2.0/redis-datasource-2.2.0.zip#sha256:6b86adf28d7ce5748ec8dc5964a7dbd3f8f5095a0a43d259c74a1fa0f501a8ab",
		}, nil
	}
	if postgresqlRecipeRequirements(requirements) {
		return image.ID + "-compat", []string{
			dockerfile,
			"platform/build/compat/postgresql",
		}, nil
	}
	if kubectlHelperRequirements(requirements, map[string]struct{}{
		"awk": {}, "bash": {}, "chmod": {}, "cp": {}, "grep": {},
		"ls": {}, "sh": {}, "sleep": {},
	}) && requirementsContainExecutableBase(requirements, "bash") &&
		len(requirements) > 1 {
		versionID := strings.NewReplacer(".", "-", "_", "-").Replace(image.Version)
		return "kubectl-helper-" + versionID + "-compat", []string{
			dockerfile,
			buildBase,
			"platform/build/compat/debian",
		}, nil
	}
	if requirementsOnlyExecutableBase(requirements, map[string]struct{}{
		"bash": {}, "ca-certificates": {}, "cat": {}, "chmod": {},
		"coreutils": {}, "curl": {}, "jq": {},
	}) && requirementsContainExecutableBase(requirements, "curl") &&
		requirementsContainExecutableBase(requirements, "jq") {
		return "garage-init-helper", []string{
			dockerfile,
			buildBase,
			"platform/build/compat/debian",
		}, nil
	}
	if requirementsOnly(requirements, "executable", map[string]struct{}{
		"curl": {},
	}) && requirementsContain(requirements, "executable", "curl") {
		return "vault-curl-compat", []string{
			dockerfile,
			"platform/build/compat/vault",
			"docker.io/curlimages/curl@sha256:43ebaa53d3806db6b1ce4353b6b26ae638ec1c167ee351524b05690f988bb20d",
		}, nil
	}
	return "", nil, errors.New(
		"no compatibility recipe proves the complete normalized mismatch set",
	)
}

type compatibilityRequirement struct {
	kind  string
	value string
}

func parseCompatibilityRequirements(
	mismatches []string,
) ([]compatibilityRequirement, error) {
	requirements := make([]compatibilityRequirement, 0, len(mismatches))
	for _, mismatch := range mismatches {
		var requirement compatibilityRequirement
		for _, marker := range [...]struct {
			text string
			kind string
		}{
			{" requires official executable ", "executable"},
			{" requires official path ", "path"},
			{
				"official entrypoint does not implement final environment contract ",
				"environment",
			},
			{" requires official bash-compatible interpreter ", "bash-interpreter"},
		} {
			index := strings.LastIndex(mismatch, marker.text)
			if index < 0 {
				continue
			}
			requirement = compatibilityRequirement{
				kind:  marker.kind,
				value: strings.TrimSpace(mismatch[index+len(marker.text):]),
			}
			break
		}
		if requirement.kind == "" || requirement.value == "" {
			return nil, fmt.Errorf(
				"unsupported normalized compatibility mismatch %q",
				mismatch,
			)
		}
		requirements = append(requirements, requirement)
	}
	if len(requirements) == 0 {
		return nil, errors.New("compatibility mismatch set is empty")
	}
	return requirements, nil
}

func kubectlHelperRequirements(
	requirements []compatibilityRequirement,
	allowedExecutables map[string]struct{},
) bool {
	for _, requirement := range requirements {
		switch requirement.kind {
		case "executable":
			if _, exists := allowedExecutables[path.Base(requirement.value)]; !exists {
				return false
			}
		case "bash-interpreter":
			base := path.Base(requirement.value)
			if base != "bash" && base != "sh" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func requirementsOnly(
	requirements []compatibilityRequirement,
	kind string,
	allowed map[string]struct{},
) bool {
	for _, requirement := range requirements {
		if requirement.kind != kind {
			return false
		}
		if _, exists := allowed[requirement.value]; !exists {
			return false
		}
	}
	return true
}

func requirementsContain(
	requirements []compatibilityRequirement,
	kind string,
	value string,
) bool {
	for _, requirement := range requirements {
		if requirement.kind == kind && requirement.value == value {
			return true
		}
	}
	return false
}

func requirementsOnlyExecutableBase(
	requirements []compatibilityRequirement,
	allowed map[string]struct{},
) bool {
	for _, requirement := range requirements {
		if requirement.kind != "executable" {
			return false
		}
		if _, exists := allowed[path.Base(requirement.value)]; !exists {
			return false
		}
	}
	return true
}

func requirementsContainExecutableBase(
	requirements []compatibilityRequirement,
	value string,
) bool {
	for _, requirement := range requirements {
		if requirement.kind == "executable" &&
			path.Base(requirement.value) == value {
			return true
		}
	}
	return false
}

func postgresqlRecipeRequirements(
	requirements []compatibilityRequirement,
) bool {
	hasVolumeContract := false
	for _, requirement := range requirements {
		switch {
		case requirement.kind == "environment" &&
			requirement.value == "POSTGRESQL_VOLUME_DIR":
			hasVolumeContract = true
		case requirement.kind == "executable" &&
			requirement.value == "/bin/sh":
		default:
			return false
		}
	}
	return hasVolumeContract
}
