package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"atum/cli/config"
	"atum/cli/gitcache"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type resolvedGit struct {
	Source   config.GitSource
	Checkout string
	Releases []gitcache.Release
}

type resolvedPackage struct {
	Package  config.Package
	Checkout string
	ChartName string
}

type resolvedSupportSource struct {
	Support  config.SupportSource
	Checkout string
}

type resolvedVendor struct {
	Vendor    config.Vendor
	Directory string
}

func resolveLatestGit(ctx context.Context, cache *gitcache.Manager, name string, source config.GitSource) (resolvedGit, error) {
	if len(source.Patches) != 0 {
		return resolvedGit{}, fmt.Errorf("%s uses patches; upstream cache sources must remain immutable and overrides belong outside the checkout", name)
	}
	releases, err := cache.Releases(ctx, source.URL)
	if err != nil {
		return resolvedGit{}, err
	}
	currentTag := sourceGitTag(source)
	releases, err = canonicalReleaseTags(releases, currentTag)
	if err != nil {
		return resolvedGit{}, fmt.Errorf("resolve %s release tags: %w", name, err)
	}
	currentIndex := -1
	for i := range releases {
		if releases[i].Version == currentTag {
			currentIndex = i
			if releases[i].Commit != source.Commit {
				return resolvedGit{}, fmt.Errorf("%s tag %s moved from %s to %s", name, currentTag, source.Commit, releases[i].Commit)
			}
			break
		}
	}
	if currentIndex < 0 {
		return resolvedGit{}, fmt.Errorf("%s current tag %s is absent from the upstream stable release set", name, currentTag)
	}
	releases = releases[:currentIndex+1]
	return resolveGitRelease(ctx, cache, name, source, releases, 0)
}

func resolvePinnedGit(
	ctx context.Context,
	cache *gitcache.Manager,
	name string,
	source config.GitSource,
	commit string,
) (resolvedGit, error) {
	if err := validateGitCommit(commit); err != nil {
		return resolvedGit{}, err
	}
	if len(source.Patches) != 0 {
		return resolvedGit{}, fmt.Errorf("%s uses patches; upstream cache sources must remain immutable and overrides belong outside the checkout", name)
	}
	releases, err := cache.Releases(ctx, source.URL)
	if err != nil {
		return resolvedGit{}, err
	}
	releases, err = canonicalReleaseTags(releases, sourceGitTag(source))
	if err != nil {
		return resolvedGit{}, fmt.Errorf("resolve %s release tags: %w", name, err)
	}
	for _, release := range releases {
		if release.Commit != commit {
			continue
		}
		return resolveGitRelease(ctx, cache, name, source, []gitcache.Release{release}, 0)
	}
	return resolvedGit{}, fmt.Errorf("%s commit %s is not the commit of a stable semantic-version release", name, commit)
}

func validateGitCommit(commit string) error {
	if len(commit) != 40 {
		return fmt.Errorf("Git commit %q must contain 40 lowercase hexadecimal characters", commit)
	}
	for _, character := range commit {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return fmt.Errorf("Git commit %q must contain 40 lowercase hexadecimal characters", commit)
		}
	}
	return nil
}

func canonicalReleaseTags(releases []gitcache.Release, currentTag string) ([]gitcache.Release, error) {
	return canonicalSemanticVersions(
		releases, currentTag, "tag", "release tag",
		func(release gitcache.Release) string { return release.Version },
	)
}

func resolveGitRelease(
	ctx context.Context,
	cache *gitcache.Manager,
	name string,
	source config.GitSource,
	releases []gitcache.Release,
	index int,
) (resolvedGit, error) {
	if index < 0 || index >= len(releases) {
		return resolvedGit{}, fmt.Errorf("%s release index %d is out of range", name, index)
	}
	release := releases[index]
	checkout, err := cache.Hydrate(ctx, name, source.URL, release)
	if err != nil {
		return resolvedGit{}, err
	}
	resolvedVersion := release.Version
	resolvedRef := source.Ref
	if source.Ref != "" {
		resolvedVersion = strings.TrimPrefix(release.Version, "v")
		resolvedRef = release.Version
	}
	resolved := source
	resolved.Version = resolvedVersion
	resolved.Ref = resolvedRef
	resolved.Commit = release.Commit
	resolved.KubeVersion = ""
	return resolvedGit{
		Source:   resolved,
		Checkout: checkout,
		Releases: releases,
	}, nil
}

func resolvePackages(
	ctx context.Context,
	cache *gitcache.Manager,
	parallelism int,
	configured []config.Package,
	previous []config.Package,
	allowDowngrade bool,
) ([]resolvedPackage, error) {
	resolved := make([]resolvedPackage, len(configured))
	previousByID := make(map[string]config.Package, len(previous))
	for index := range previous {
		previousByID[previous[index].ID] = previous[index]
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for i := range configured {
		i := i
		group.Go(func() error {
			current := configured[i]
			url, version := current.Source.URL, current.Source.Version
			old, hadPrevious := previousByID[current.ID]
			if !allowDowngrade {
				if hadPrevious && old.Source.Version != "" {
					if err := requireNonDowngrade(current.ID, old.Source.Version, version); err != nil {
						return err
					}
				}
			}
			release, branch, err := cache.ResolveTagWithDefaultBranch(groupContext, url, version)
			if err != nil {
				return err
			}
			if hadPrevious && old.Source.Version == version &&
				old.Source.Commit != "" && release.Commit != old.Source.Commit {
				return fmt.Errorf("package %s tag %s moved from %s to %s", current.ID, version, old.Source.Commit, release.Commit)
			}
			checkout, err := cache.Hydrate(groupContext, "package-"+current.ID, url, release)
			if err != nil {
				return err
			}
			metadata, err := readChartMetadata(filepath.Join(checkout, filepath.FromSlash(current.RepositoryChartPath())))
			if err != nil {
				return fmt.Errorf("inspect package %s: %w", current.ID, err)
			}
			if !tagOwnsChartVersion(version, metadata.Version) {
				return fmt.Errorf("package %s tag %s contains chart version %s", current.ID, version, metadata.Version)
			}
			current.Source = config.GitSource{
				URL:         url,
				Version:     version,
				Branch:      branch,
				Commit:      release.Commit,
				KubeVersion: metadata.KubeVersion,
			}
			current.License = packageLicenseReference(checkout, current.Source)
			resolved[i] = resolvedPackage{
				Package: current, Checkout: checkout, ChartName: metadata.Name,
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return resolved, nil
}

func packageLicenseReference(checkout string, source config.GitSource) string {
	for _, relative := range [...]string{
		"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md",
		"chart/LICENSE", "chart/LICENSE.md", "chart/LICENSE.txt",
	} {
		info, err := os.Stat(filepath.Join(checkout, filepath.FromSlash(relative)))
		if err == nil && info.Mode().IsRegular() {
			return source.URL + " @ " + source.Commit + " / " + relative
		}
	}
	return source.URL + " @ " + source.Commit
}

func tagOwnsChartVersion(tag, chartVersion string) bool {
	return tag == chartVersion || strings.HasSuffix(tag, "-v"+chartVersion)
}

func readBigBangValues(bigBangCheckout string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(bigBangCheckout, "chart", "values.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read Big Bang package defaults: %w", err)
	}
	var bigBangValues map[string]any
	if err := yaml.Unmarshal(data, &bigBangValues); err != nil {
		return nil, fmt.Errorf("decode Big Bang package defaults: %w", err)
	}
	return bigBangValues, nil
}

func resolveWrapperSupportSource(
	ctx context.Context,
	cache *gitcache.Manager,
	bigBang resolvedGit,
	requirement config.WrapperSourceRequirement,
	previous config.Resolved,
) ([]resolvedSupportSource, error) {
	if !requirement.Required {
		return nil, nil
	}
	declaration := requirement.Declaration
	release, branch, err := cache.ResolveTagWithDefaultBranch(ctx, declaration.URL, declaration.Tag)
	if err != nil {
		return nil, fmt.Errorf("resolve Big Bang wrapper tag %s: %w", declaration.Tag, err)
	}
	if err := validateWrapperSourceContinuity(previous, bigBang.Source, declaration, release.Commit); err != nil {
		return nil, err
	}
	support := config.SupportSource{
		ID: "wrapper", ValuesPath: "wrapper", ChartPath: declaration.ChartPath,
		Source: config.GitSource{
			URL: declaration.URL, Version: declaration.Tag, Branch: branch, Commit: release.Commit,
		},
	}
	if err := config.ValidateWrapperSupportSource(support); err != nil {
		return nil, err
	}
	checkout, err := cache.Hydrate(ctx, "support-wrapper", declaration.URL, release)
	if err != nil {
		return nil, err
	}
	metadata, err := readChartMetadata(filepath.Join(checkout, filepath.FromSlash(declaration.ChartPath)))
	if err != nil {
		return nil, fmt.Errorf("inspect Big Bang wrapper chart: %w", err)
	}
	if metadata.Version != declaration.Tag {
		return nil, fmt.Errorf("Big Bang wrapper tag %s contains chart version %s", declaration.Tag, metadata.Version)
	}
	return []resolvedSupportSource{{
		Support:  support,
		Checkout: checkout,
	}}, nil
}

func validateWrapperSourceContinuity(
	previous config.Resolved,
	bigBang config.GitSource,
	declaration config.WrapperSourceDeclaration,
	commit string,
) error {
	for _, old := range previous.SupportSources {
		if old.ID != "wrapper" {
			continue
		}
		if previous.BigBang.Commit == bigBang.Commit {
			if normalizedGitURL(old.Source.URL) != normalizedGitURL(declaration.URL) ||
				old.Source.Version != declaration.Tag || old.ChartPath != declaration.ChartPath {
				return errors.New("selected Big Bang release changed its wrapper source declaration")
			}
		}
		if normalizedGitURL(old.Source.URL) == normalizedGitURL(declaration.URL) &&
			old.Source.Version == declaration.Tag && old.Source.Commit != commit {
			return fmt.Errorf("Big Bang wrapper tag %s moved from %s to %s",
				declaration.Tag, old.Source.Commit, commit)
		}
	}
	return nil
}

func hydrateConfiguredGit(
	ctx context.Context,
	cache *gitcache.Manager,
	parallelism int,
	sources []config.Package,
) (map[string]string, error) {
	checkouts := make(map[string]string, len(sources))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	results := make([]string, len(sources))
	for i := range sources {
		i := i
		group.Go(func() error {
			source := sources[i].Source
			checkout, err := cache.Hydrate(groupContext, "package-"+sources[i].ID, source.URL, gitcache.Release{
				Version: sourceGitTag(source),
				Commit:  source.Commit,
			})
			if err != nil {
				return err
			}
			results[i] = checkout
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	for i := range sources {
		checkouts[sources[i].ID] = results[i]
	}
	return checkouts, nil
}

func resolveVendors(
	ctx context.Context,
	cache *gitcache.Manager,
	root string,
	parallelism int,
	configured []config.Vendor,
) ([]resolvedVendor, error) {
	if len(configured) == 0 {
		return nil, nil
	}
	resolved := make([]resolvedVendor, len(configured))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for i := range configured {
		i := i
		group.Go(func() error {
			vendor := configured[i]
			if len(vendor.Source.Patches) != 0 {
				return fmt.Errorf("vendor %s source patches must be recorded in vendor.patches, not source.patches", vendor.ID)
			}
			currentCheckout, err := cache.Hydrate(groupContext, "vendor-"+vendor.ID, vendor.Source.URL, gitcache.Release{
				Version: sourceGitTag(vendor.Source), Commit: vendor.Source.Commit,
			})
			if err != nil {
				return err
			}
			currentDirectory, currentSHA, err := reconstructVendor(root, currentCheckout, vendor)
			if err != nil {
				return err
			}
			if err := verifyTrackedVendor(root, vendor, currentDirectory, currentSHA); err != nil {
				return err
			}
			candidate, err := resolveLatestGit(groupContext, cache, "vendor-"+vendor.ID, vendor.Source)
			if err != nil {
				return err
			}
			vendor.Source = candidate.Source
			candidateDirectory, candidateSHA, err := reconstructVendor(root, candidate.Checkout, vendor)
			if err != nil {
				return err
			}
			vendor.TreeSHA256 = candidateSHA
			resolved[i] = resolvedVendor{Vendor: vendor, Directory: candidateDirectory}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return resolved, nil
}

func normalizedGitURL(value string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(value), "/"), ".git")
}

func sourceGitTag(source config.GitSource) string {
	if source.Ref != "" {
		return source.Ref
	}
	return source.Version
}

func verifyTrackedChartBindings(
	values map[string]any,
	charts []config.TrackedChart,
) error {
	for _, chart := range charts {
		chartValues, err := valuesAt(values, chart.ValuesPath)
		if err != nil {
			return fmt.Errorf("resolve chart %s values: %w", chart.ID, err)
		}
		helmRepository, ok := chartValues["helmRepo"].(map[string]any)
		if !ok {
			return fmt.Errorf("chart %s has no helmRepo configuration", chart.ID)
		}
		repositoryName, _ := helmRepository["repoName"].(string)
		chartName, _ := helmRepository["chartName"].(string)
		version, _ := helmRepository["tag"].(string)
		sourceType, _ := chartValues["sourceType"].(string)
		if sourceType != "helmRepo" || repositoryName != "atum" ||
			chartName != chart.Name || version != chart.Version {
			return fmt.Errorf("chart %s binds repository %q and chart %q, want chart %q",
				chart.ID, repositoryName, chartName, chart.Name)
		}
	}
	return nil
}

func bigBangSourceValues(
	root string,
	registry config.Registry,
	artifact config.ChartArtifact,
	files map[string][]byte,
) (map[string]any, error) {
	const relative = "platform/apps/bigbang/source-bigbang.yaml"
	if _, err := readManagedYAML(root, files, relative); err != nil {
		return nil, err
	}
	return map[string]any{
		"apiVersion": "source.toolkit.fluxcd.io/v1",
		"kind":       "OCIRepository",
		"metadata": map[string]any{
			"name": "bigbang", "namespace": "bigbang",
		},
		"spec": map[string]any{
			"interval": "10m",
			"provider": "generic",
			"insecure": !registry.TLSVerify,
			"url":      "oci://" + imageRepository(artifact.Target),
			"ref": map[string]any{
				"tag": artifact.Version,
			},
			"layerSelector": map[string]any{
				"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
				"operation": "copy",
			},
		},
	}, nil
}

func configureBigBangChartRef(
	release map[string]any,
	registry config.Registry,
	version string,
) error {
	spec, ok := release["spec"].(map[string]any)
	if !ok {
		return errors.New("Big Bang HelmRelease has no spec")
	}
	delete(spec, "chart")
	spec["chartRef"] = map[string]any{
		"kind": "OCIRepository", "name": "bigbang", "namespace": "bigbang",
	}
	if version == "" || registry.Host == "" || registry.Project == "" {
		return errors.New("Big Bang OCI chart reference requires version and registry")
	}
	return nil
}

func internalSourceURL(sources config.SourceRegistry, organization, repository string) string {
	return strings.TrimSuffix(sources.ClusterURL, "/") + "/" + organization + "/" + repository + ".git"
}
