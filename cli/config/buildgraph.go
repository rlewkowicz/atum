package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/fssecure"
)

const buildGraphPath = "platform/build/docker-bake.hcl"

func validateBuildGraph(problems *[]string, project *Project, files map[string][]byte, allowStale bool) {
	path, err := fssecure.Resolve(project.Root, buildGraphPath, false)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("build graph path is invalid: %v", err))
		return
	}
	data, exists := files[buildGraphPath]
	if !exists {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("build graph cannot be read: %v", err))
		return
	}
	graph, err := parseBakeGraph(data, path)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("build graph is invalid: %v", err))
		return
	}
	base := graph.variableString("ATUM_DEBIAN_IMAGE")
	if base != project.Desired.Delivery.Policy.BuildBase {
		*problems = append(*problems, fmt.Sprintf("build graph Debian base %q does not match policy buildBase", base))
	}
	graph.validate(problems, project.Desired.Delivery.Policy, deliveryTargetNames(project.Desired.Delivery.Images))
	for _, image := range project.Desired.Delivery.Images {
		target := image.Delivery.Default.BakeTarget
		if target != "" {
			if _, exists := graph.targets[target]; !exists {
				*problems = append(*problems, fmt.Sprintf(
					"delivery image %s references missing Bake target %s", image.ID, target,
				))
			}
		}
	}
	graph.validateVersionMappedTargets(problems, project.Desired.Delivery.Images)
	graph.validateDeliveryTargets(problems, project, files)
	graphSHA, err := deliveryGraphSHA256(project, project.Lock.Delivery.Profile, files)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("delivery graph identity cannot be resolved: %v", err))
	} else if !allowStale && graphSHA != project.Lock.Delivery.GraphSHA256 {
		*problems = append(*problems, fmt.Sprintf("delivery graph hash is %s, want %s", project.Lock.Delivery.GraphSHA256, graphSHA))
	}
}

func (graph *bakeGraph) validateVersionMappedTargets(problems *[]string, images []Image) {
	for i := range images {
		image := &images[i]
		mapping := image.VersionMapping
		if mapping == nil ||
			(mapping.Source != "upstreamImageTag" && mapping.Source != "chartAppVersion") {
			continue
		}
		expectedTargetTag := mapping.TagPrefix + image.Version + mapping.TagSuffix
		if imageReferenceTag(image.Target) != expectedTargetTag {
			*problems = append(*problems, fmt.Sprintf(
				"delivery image %s target tag does not match its mapped version", image.ID,
			))
		}

	}
}

func normalizedImageReferenceRepository(reference string) string {
	repository := imageReferenceRepository(reference)
	registry, remainder, qualified := strings.Cut(repository, "/")
	if !qualified {
		return "docker.io/library/" + repository
	}
	if registry == "docker.io" || registry == "index.docker.io" {
		return "docker.io/" + remainder
	}
	if registry != "localhost" && !strings.ContainsAny(registry, ".:") {
		return "docker.io/" + repository
	}
	return repository
}

func imageReferenceRepository(reference string) string {
	if before, _, found := strings.Cut(reference, "@"); found {
		reference = before
	}
	lastSlash := strings.LastIndexByte(reference, '/')
	if colon := strings.LastIndexByte(reference, ':'); colon > lastSlash {
		return reference[:colon]
	}
	return reference
}

// DeliveryGraphSHA256 returns the content identity for all inputs reachable by
// a delivery profile. It is shared by update resolution, publication, and
// publication verification so those paths cannot drift onto different graph
// projections.
func DeliveryGraphSHA256(project *Project, profile string) (string, error) {
	return deliveryGraphSHA256(project, profile, nil)
}

// DeliveryGraphSHA256WithFiles resolves the graph against an atomic candidate
// tree. Upstream updates use it before publishing any changed build input.
func DeliveryGraphSHA256WithFiles(project *Project, profile string, files map[string][]byte) (string, error) {
	return deliveryGraphSHA256(project, profile, files)
}

// ReachableBakeTargets returns every concrete target required by roots. Image
// delivery uses it to replace registry exporters with local caches when a
// minimal bootstrap seed is built before Harbor exists.
func ReachableBakeTargets(project *Project, roots []string) ([]string, error) {
	data, _, err := graphFile(project, buildGraphPath, nil)
	if err != nil {
		return nil, err
	}
	graph, err := parseBakeGraph(data, filepath.Join(project.Root, buildGraphPath))
	if err != nil {
		return nil, err
	}
	reachable := graph.reachable(roots)
	targets := make([]string, 0, len(reachable))
	for name := range reachable {
		if _, exists := graph.targets[name]; !exists {
			return nil, fmt.Errorf("Bake dependency %s is not defined", name)
		}
		targets = append(targets, name)
	}
	sort.Strings(targets)
	return targets, nil
}

func deliveryGraphSHA256(project *Project, profile string, files map[string][]byte) (string, error) {
	if profile != "platform" {
		return "", fmt.Errorf("unsupported delivery profile %q", profile)
	}
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "delivery-graph-v3\x00%s\x00", profile)
	for _, relative := range []string{"platform/build/.dockerignore", buildGraphPath} {
		data, mode, err := graphFile(project, relative, files)
		if err != nil {
			return "", err
		}
		_ = mode
		digest := sha256.Sum256(data)
		_, _ = fmt.Fprintf(hash, "%s  %s\n", hex.EncodeToString(digest[:]), filepath.Base(relative))
	}
	graphFiles := []string{
		"docker/Dockerfile.delivery",
		"docker/Dockerfile.operator",
	}
	repositoryFiles := make([]string, 0, 16)
	for _, image := range project.Desired.Delivery.Images {
		if image.Delivery.Default.Type != "build" {
			continue
		}
		for _, material := range image.Delivery.Default.Materials {
			local, exists := strings.CutPrefix(material, filepath.ToSlash(filepath.Dir(buildGraphPath))+"/")
			if !exists {
				if image.Discovery == "first-party" {
					resolved, err := repositoryGraphMaterialFiles(project, material)
					if err != nil {
						return "", fmt.Errorf("resolve first-party build material %s: %w", material, err)
					}
					repositoryFiles = append(repositoryFiles, resolved...)
				}
				continue
			}
			files, err := localGraphMaterialFiles(project, local)
			if err != nil {
				return "", fmt.Errorf("resolve build material %s: %w", material, err)
			}
			graphFiles = append(graphFiles, files...)
		}
	}
	repositoryFiles = compactStrings(repositoryFiles)
	sort.Strings(repositoryFiles)
	for _, relative := range repositoryFiles {
		data, mode, err := graphFile(project, relative, files)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(data)
		_, _ = fmt.Fprintf(hash, "%s\x00%o\n%s  %s\n", relative, mode.Perm(), hex.EncodeToString(digest[:]), relative)
	}
	graphFiles = compactStrings(graphFiles)
	sort.Strings(graphFiles)
	for _, relative := range graphFiles {
		projectRelative := filepath.ToSlash(filepath.Join(filepath.Dir(buildGraphPath), relative))
		data, mode, err := graphFile(project, projectRelative, files)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(data)
		_, _ = fmt.Fprintf(hash, "%s\x00%o\n%s  %s\n", relative, mode.Perm(), hex.EncodeToString(digest[:]), relative)
	}
	buildkit := ""
	sbom := ""
	operatorBuilder := ""
	operatorBuild := false
	for _, image := range project.Desired.Delivery.Images {
		if image.ID == "atum-operator" &&
			image.Delivery.Default.Type == "build" {
			operatorBuild = true
		}
		if image.Delivery.Default.Type != "mirror" ||
			image.Delivery.Default.Source == "" || image.Delivery.Default.Digest == "" {
			continue
		}
		reference := image.Delivery.Default.Source + "@" + image.Delivery.Default.Digest
		switch image.ID {
		case "buildkit":
			buildkit = reference
		case "sbom-scanner":
			sbom = reference
		case "operator-builder":
			operatorBuilder = reference
		}
	}
	if buildkit == "" {
		return "", fmt.Errorf("delivery graph has no buildkit image")
	}
	if sbom == "" {
		return "", fmt.Errorf("delivery graph has no sbom-scanner image")
	}
	if operatorBuild && operatorBuilder == "" {
		return "", fmt.Errorf("delivery graph has no operator-builder image")
	}
	for _, input := range []string{
		"ATUM_CACHE_REGISTRY=" + project.Desired.Delivery.Registry.Host + "/buildkit",
		"ATUM_BOOTSTRAP_OUTPUT=type=registry,oci-mediatypes=true,rewrite-timestamp=true",
		"ATUM_BUILDKIT_IMAGE=" + buildkit,
		fmt.Sprintf("ATUM_BUILD_PARALLELISM=%d", project.Desired.Delivery.Policy.BuildParallelism),
		"ATUM_DEBIAN_IMAGE=" + project.Desired.Delivery.Policy.BuildBase,
		"ATUM_PLATFORM=" + project.Desired.Project.Platform,
		"ATUM_SBOM_GENERATOR_IMAGE=" + sbom,
		"ATUM_OPERATOR_BUILDER_IMAGE=" + operatorBuilder,
		"SOURCE_DATE_EPOCH=0",
	} {
		_, _ = fmt.Fprintln(hash, input)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func deliveryTargetNames(images []Image) []string {
	targets := make([]string, 0, len(images))
	for _, image := range images {
		if image.Delivery.Default.BakeTarget != "" {
			targets = append(targets, image.Delivery.Default.BakeTarget)
		}
	}
	return compactStrings(targets)
}

func localGraphMaterialFiles(project *Project, relative string) ([]string, error) {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(buildGraphPath)
	path, err := fssecure.Resolve(project.Root, filepath.ToSlash(filepath.Join(base, clean)), false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		return []string{filepath.ToSlash(clean)}, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("material is not a regular file or directory")
	}
	files := make([]string, 0, 8)
	err = fssecure.WalkRegularFiles(path, func(_ string, relative string, _ os.FileInfo) error {
		files = append(files, filepath.ToSlash(filepath.Join(clean, relative)))
		return nil
	})
	return files, err
}

func repositoryGraphMaterialFiles(project *Project, relative string) ([]string, error) {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return nil, err
	}
	path, err := fssecure.Resolve(project.Root, clean, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		return []string{filepath.ToSlash(clean)}, nil
	}
	if !info.IsDir() {
		return nil, errors.New("material is not a regular file or directory")
	}
	result := make([]string, 0, 16)
	err = fssecure.WalkRegularFiles(path, func(_ string, child string, _ os.FileInfo) error {
		result = append(result, filepath.ToSlash(filepath.Join(clean, child)))
		return nil
	})
	return result, err
}

func compactStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := values[:0]
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func graphFile(project *Project, relative string, files map[string][]byte) ([]byte, os.FileMode, error) {
	path, err := fssecure.Resolve(project.Root, relative, false)
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("build graph input %s is not a regular file", relative)
	}
	if data, exists := files[filepath.Clean(relative)]; exists {
		return data, info.Mode(), nil
	}
	data, err := os.ReadFile(path)
	return data, info.Mode(), err
}

func validatePinnedBuildMaterial(problems *[]string, policy DeliveryPolicy, label, material string) {
	for _, prefix := range policy.ForbiddenArtifactPrefixes {
		if strings.HasPrefix(material, prefix) {
			*problems = append(*problems, fmt.Sprintf("%s uses forbidden artifact %s", label, material))
		}
	}
	switch {
	case strings.HasPrefix(material, filepath.ToSlash(filepath.Dir(buildGraphPath))+"/"):
		local := strings.TrimPrefix(material, filepath.ToSlash(filepath.Dir(buildGraphPath))+"/")
		if _, err := fssecure.Relative(local); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s local input is invalid: %s", label, material))
		}
	case material == "go.mod" || material == "go.sum" ||
		material == "cmd/atum-operator" || material == "operator":
		if _, err := fssecure.Relative(material); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s first-party input is invalid: %s", label, material))
		}
	case strings.HasPrefix(material, "https://"):
		marker := "#sha256:"
		index := strings.LastIndex(material, marker)
		if index < 0 || !validHexSHA256(material[index+len(marker):]) {
			*problems = append(*problems, fmt.Sprintf("%s HTTPS input is not checksum-pinned: %s", label, material))
		}
	case strings.Contains(material, "/"):
		parts := strings.Split(material, "@sha256:")
		if len(parts) != 2 || !validHexSHA256(parts[1]) {
			*problems = append(*problems, fmt.Sprintf("%s image input is not digest-pinned: %s", label, material))
		}
	default:
		*problems = append(*problems, fmt.Sprintf("%s has unsupported opaque input %s", label, material))
	}
}

func queryValue(raw, key string) string {
	for _, field := range strings.SplitN(raw, "?", 2)[1:] {
		for _, parameter := range strings.Split(field, "&") {
			name, value, found := strings.Cut(parameter, "=")
			if found && name == key {
				return value
			}
		}
	}
	return ""
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
