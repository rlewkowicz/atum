package update

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/config"
)

type packageValueCandidate struct {
	path        string
	integration string
	repository  string
	version     string
	chartPath   string
}

type packageValueIdentity struct {
	repository string
	version    string
	chartPath  string
}

// discoverBigBangPackages renders the exact selected Big Bang root chart
// before any child source is hydrated. The rendered source and HelmRelease
// handoffs own package membership; the public values are consulted only once
// to recover the chart's source-value path for the generated override.
func discoverBigBangPackages(
	checkout string,
	kubernetesVersion string,
	defaults map[string]any,
	publicValues map[string]any,
) ([]config.Package, config.WrapperSourceRequirement, error) {
	collector := newReleaseValueCollector("bigbang")
	if _, err := renderChart(
		filepath.Join(checkout, "chart"),
		kubernetesVersion,
		publicValues,
		nil,
		collector,
		releaseOptions("bigbang", "bigbang"),
	); err != nil {
		return nil, config.WrapperSourceRequirement{}, fmt.Errorf(
			"render selected Big Bang package handoffs: %w", err,
		)
	}
	effective := mergeValues(defaults, publicValues)
	candidates, err := directPackageValueCandidates(effective)
	if err != nil {
		return nil, config.WrapperSourceRequirement{}, err
	}
	candidatesByIdentity := make(
		map[packageValueIdentity][]packageValueCandidate,
		len(candidates),
	)
	for _, candidate := range candidates {
		identity := packageValueIdentity{
			repository: normalizedGitURL(candidate.repository),
			version:    candidate.version,
			chartPath:  candidate.chartPath,
		}
		candidatesByIdentity[identity] = append(
			candidatesByIdentity[identity],
			candidate,
		)
	}
	wrapper, err := config.BigBangWrapperSourceRequirement(defaults, effective)
	if err != nil {
		return nil, config.WrapperSourceRequirement{}, err
	}
	var wrapperKey resourceKey
	if wrapper.Required {
		wrapperKey, err = renderedWrapperSource(collector, wrapper.Declaration)
		if err != nil {
			return nil, config.WrapperSourceRequirement{}, err
		}
	}

	referenced := make(map[resourceKey][]releaseValues)
	for _, releases := range collector.releases {
		for _, release := range releases {
			if release.source.kind == "GitRepository" {
				referenced[release.source] = append(referenced[release.source], release)
			}
		}
	}
	packages := make([]config.Package, 0, len(referenced))
	ids := make(map[string]resourceKey, len(referenced))
	paths := make(map[string]resourceKey, len(referenced))
	repositories := make(map[string]resourceKey, len(referenced))
	for key, releases := range referenced {
		if wrapper.Required && key == wrapperKey {
			continue
		}
		repository, exists := collector.repositories[resourceKey{
			namespace: key.namespace,
			name:      key.name,
			kind:      "GitRepository",
		}]
		if !exists {
			return nil, config.WrapperSourceRequirement{}, fmt.Errorf(
				"rendered HelmRelease source %s/%s is absent", key.namespace, key.name,
			)
		}
		candidate, err := matchRenderedPackageCandidate(
			key,
			repository,
			releases,
			candidatesByIdentity,
		)
		if err != nil {
			return nil, config.WrapperSourceRequirement{}, err
		}
		canonical, err := config.CanonicalPackageRepositoryURL(candidate.repository)
		if err != nil {
			return nil, config.WrapperSourceRequirement{}, fmt.Errorf(
				"rendered package %s repository: %w", key.name, err,
			)
		}
		if previous, duplicate := ids[key.name]; duplicate {
			return nil, config.WrapperSourceRequirement{}, fmt.Errorf(
				"rendered package id %s is shared by %s/%s and %s/%s",
				key.name, previous.namespace, previous.name, key.namespace, key.name,
			)
		}
		if previous, duplicate := paths[candidate.path]; duplicate {
			return nil, config.WrapperSourceRequirement{}, fmt.Errorf(
				"rendered package values path %s is shared by %s and %s",
				candidate.path, previous.name, key.name,
			)
		}
		if previous, duplicate := repositories[canonical]; duplicate {
			return nil, config.WrapperSourceRequirement{}, fmt.Errorf(
				"rendered package repository %s is shared by %s and %s",
				candidate.repository, previous.name, key.name,
			)
		}
		ids[key.name], paths[candidate.path], repositories[canonical] = key, key, key
		packages = append(packages, config.Package{
			ID:          key.name,
			ValuesPath:  candidate.path,
			License:     candidate.repository + " @ " + candidate.version + " / LICENSE",
			Integration: candidate.integration,
			ChartPath:   candidate.chartPath,
			Source: config.GitSource{
				URL:     candidate.repository,
				Version: candidate.version,
			},
		})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].ID < packages[j].ID })
	return packages, wrapper, nil
}

func directPackageValueCandidates(values map[string]any) ([]packageValueCandidate, error) {
	var candidates []packageValueCandidate
	appendCandidate := func(path, integration string, raw any) error {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil
		}
		git, ok := entry["git"].(map[string]any)
		if !ok {
			return nil
		}
		repository, _ := git["repo"].(string)
		version, _ := git["tag"].(string)
		repository, version = strings.TrimSpace(repository), strings.TrimSpace(version)
		if repository == "" || version == "" {
			return fmt.Errorf("Big Bang public package source %s is incomplete", path)
		}
		if _, err := config.CanonicalPackageRepositoryURL(repository); err != nil {
			return fmt.Errorf("Big Bang public package source %s: %w", path, err)
		}
		chartPath := "chart"
		if configured, exists := git["path"]; exists {
			chartPath, ok = configured.(string)
			if !ok {
				return fmt.Errorf("Big Bang public package source %s chart path is not text", path)
			}
		}
		chartPath = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.TrimSpace(chartPath))), "./")
		if !config.SafeRepositoryChartPath(chartPath) {
			return fmt.Errorf("Big Bang public package source %s chart path %q is invalid", path, chartPath)
		}
		candidates = append(candidates, packageValueCandidate{
			path: path, integration: integration, repository: repository,
			version: version, chartPath: chartPath,
		})
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "addons" || key == "packages" || key == "wrapper" {
			continue
		}
		if err := appendCandidate(key, "integrated", values[key]); err != nil {
			return nil, err
		}
	}
	for _, group := range []struct {
		key         string
		integration string
	}{
		{key: "addons", integration: "integrated"},
		{key: "packages", integration: "generic"},
	} {
		entries, _ := values[group.key].(map[string]any)
		names := make([]string, 0, len(entries))
		for name := range entries {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if name == "sample" {
				continue
			}
			if err := appendCandidate(group.key+"."+name, group.integration, entries[name]); err != nil {
				return nil, err
			}
		}
	}
	return candidates, nil
}

func matchRenderedPackageCandidate(
	key resourceKey,
	repository repositoryResource,
	releases []releaseValues,
	candidates map[packageValueIdentity][]packageValueCandidate,
) (packageValueCandidate, error) {
	if repository.refTag == "" {
		return packageValueCandidate{}, fmt.Errorf(
			"rendered package source %s/%s has no public immutable tag", key.namespace, key.name,
		)
	}
	chartPath := ""
	for _, release := range releases {
		candidatePath := strings.TrimPrefix(
			filepath.ToSlash(filepath.Clean(strings.TrimSpace(release.chart))), "./",
		)
		if chartPath == "" {
			chartPath = candidatePath
		} else if chartPath != candidatePath {
			return packageValueCandidate{}, fmt.Errorf(
				"rendered package source %s/%s serves conflicting chart paths %s and %s",
				key.namespace, key.name, chartPath, candidatePath,
			)
		}
	}
	matches := candidates[packageValueIdentity{
		repository: normalizedGitURL(repository.url),
		version:    repository.refTag,
		chartPath:  chartPath,
	}]
	if len(matches) == 0 {
		return packageValueCandidate{}, fmt.Errorf(
			"rendered package source %s/%s (%s@%s, chart %s) has no exact public values owner",
			key.namespace, key.name, repository.url, repository.refTag, chartPath,
		)
	}
	if len(matches) != 1 {
		return packageValueCandidate{}, fmt.Errorf(
			"rendered package source %s/%s matches multiple public values paths",
			key.namespace,
			key.name,
		)
	}
	return matches[0], nil
}

func renderedWrapperSource(
	collector *releaseValueCollector,
	declaration config.WrapperSourceDeclaration,
) (resourceKey, error) {
	var match resourceKey
	found := false
	references := make(map[resourceKey]map[string]struct{}, len(collector.releases))
	for _, releases := range collector.releases {
		for _, release := range releases {
			chartPath := strings.TrimPrefix(
				filepath.ToSlash(filepath.Clean(strings.TrimSpace(release.chart))),
				"./",
			)
			paths := references[release.source]
			if paths == nil {
				paths = make(map[string]struct{})
				references[release.source] = paths
			}
			paths[chartPath] = struct{}{}
		}
	}
	for key, repository := range collector.repositories {
		if key.kind != "GitRepository" ||
			normalizedGitURL(repository.url) != normalizedGitURL(declaration.URL) ||
			repository.refTag != declaration.Tag {
			continue
		}
		if _, referenced := references[key][declaration.ChartPath]; !referenced {
			continue
		}
		if found {
			return resourceKey{}, fmt.Errorf("selected Big Bang rendered ambiguous wrapper sources")
		}
		match, found = key, true
	}
	if !found {
		return resourceKey{}, fmt.Errorf("selected Big Bang rendered no exact wrapper source handoff")
	}
	return match, nil
}
