package update

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"atum/cli/config"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/sync/errgroup"
)

type resolvedTrackedChart struct {
	Chart       config.TrackedChart
	ArchivePath string
}

type resolvedBootstrapChart struct {
	Chart       config.Chart
	ArchivePath string
}

type chartCatalog struct {
	ID                string
	Name              string
	Current           string
	CurrentArchiveSHA string
	Source            config.ChartSource
	Releases          []chartRelease
	mu                sync.Mutex
	fetched           map[string]chartRelease
	compatibilityMu   sync.Mutex
	compatibility     map[string]*chartCompatibilityState
}

type chartCompatibilityState struct {
	scanned  int
	matches  []chartRelease
	failures []string
}

func resolveTrackedChartCatalogs(
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []config.TrackedChart,
) ([]*chartCatalog, error) {
	return resolveChartCatalogs(ctx, client, parallelism, configured,
		func(ctx context.Context, client *chartClient, chart config.TrackedChart) (*chartCatalog, error) {
			return resolveChartCatalog(
				ctx, client, chart.ID, chart.Name, chart.Version, chart.ArchiveSHA256, chart.Source,
			)
		})
}

func resolveBootstrapChartCatalogs(
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []config.Chart,
) ([]*chartCatalog, error) {
	return resolveChartCatalogs(ctx, client, parallelism, configured,
		func(ctx context.Context, client *chartClient, chart config.Chart) (*chartCatalog, error) {
			return resolveChartCatalog(ctx, client, chart.ID, chart.Name, chart.Version, chart.ArchiveSHA256, chart.Source)
		})
}

func resolveChartCatalogs[T any](
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []T,
	resolve func(context.Context, *chartClient, T) (*chartCatalog, error),
) ([]*chartCatalog, error) {
	catalogs := make([]*chartCatalog, len(configured))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for i := range configured {
		i := i
		group.Go(func() error {
			catalog, err := resolve(groupContext, client, configured[i])
			if err != nil {
				return err
			}
			catalogs[i] = catalog
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return catalogs, nil
}

func resolveChartCatalog(
	ctx context.Context,
	client *chartClient,
	id, name, current, currentArchiveSHA string,
	source config.ChartSource,
) (*chartCatalog, error) {
	releases, err := releasesForSource(ctx, client, source, name)
	if err != nil {
		return nil, err
	}
	releases, err = canonicalChartReleases(releases, current)
	if err != nil {
		return nil, fmt.Errorf("resolve chart %s releases: %w", id, err)
	}
	currentIndex := -1
	for i := range releases {
		if releases[i].Version == current {
			currentIndex = i
			break
		}
	}
	if currentIndex < 0 {
		return nil, fmt.Errorf("chart %s current release %s is absent from its stable upstream release set", id, current)
	}
	catalog := &chartCatalog{
		ID:                id,
		Name:              name,
		Current:           current,
		CurrentArchiveSHA: currentArchiveSHA,
		Source:            source,
		Releases:          releases[:currentIndex+1],
		fetched:           make(map[string]chartRelease),
		compatibility:     make(map[string]*chartCompatibilityState),
	}
	currentRelease, err := catalog.fetch(ctx, client, catalog.Releases[len(catalog.Releases)-1])
	if err != nil {
		return nil, err
	}
	if err := catalog.verifyCurrent(currentRelease); err != nil {
		return nil, err
	}
	catalog.Releases = chartReleaseCandidates(releases, currentIndex, currentRelease.AppVersion)
	return catalog, nil
}

func stableSemanticApplication(value string) (*semver.Version, bool) {
	version, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	return version, err == nil && version.Prerelease() == ""
}

func canonicalChartReleases(releases []chartRelease, current string) ([]chartRelease, error) {
	return canonicalSemanticVersions(
		releases, current, "chart version", "chart release",
		func(release chartRelease) string { return release.Version },
	)
}

func chartReleaseCandidates(releases []chartRelease, currentIndex int, currentAppVersion string) []chartRelease {
	limit := currentIndex + 1
	if eligible, _ := eligibleChartAppVersion(currentAppVersion); !eligible {
		// A prior resolver could advance a stable chart whose application was
		// still a prerelease. Include older releases only for this repair path;
		// stable current applications retain the normal no-downgrade window.
		limit = len(releases)
	}
	return releases[:limit]
}

func eligibleChartAppVersion(appVersion string) (bool, string) {
	appVersion = strings.TrimSpace(appVersion)
	if appVersion == "" {
		return false, "has no appVersion"
	}
	version, err := semver.NewVersion(strings.TrimPrefix(appVersion, "v"))
	if err == nil && version.Prerelease() != "" {
		return false, "deploys prerelease appVersion " + appVersion
	}
	// Helm permits opaque appVersion values. When one is not semantic, the
	// stable chart release remains the only upstream stability authority.
	return true, ""
}

func (catalog *chartCatalog) fetch(ctx context.Context, client *chartClient, release chartRelease) (chartRelease, error) {
	catalog.mu.Lock()
	cached, exists := catalog.fetched[release.Version]
	catalog.mu.Unlock()
	if exists {
		return cached, nil
	}
	fetched, err := client.Fetch(ctx, release)
	if err != nil {
		return chartRelease{}, err
	}
	metadata, err := readChartMetadata(fetched.ArchivePath)
	if err != nil {
		return chartRelease{}, err
	}
	if metadata.Name != catalog.Name || metadata.Version != fetched.Version {
		return chartRelease{}, fmt.Errorf("chart %s release %s contains chart %s version %s",
			catalog.ID, fetched.Version, metadata.Name, metadata.Version)
	}
	fetched.AppVersion = metadata.AppVersion
	fetched.KubeVersion = metadata.KubeVersion
	catalog.mu.Lock()
	if previous, loaded := catalog.fetched[release.Version]; loaded {
		fetched = previous
	} else {
		catalog.fetched[release.Version] = fetched
	}
	catalog.mu.Unlock()
	return fetched, nil
}

func (catalog *chartCatalog) compatibleAt(
	ctx context.Context,
	client *chartClient,
	kubernetesVersion string,
	offset int,
) (chartRelease, error) {
	if offset < 0 {
		return chartRelease{}, fmt.Errorf("chart %s compatibility offset cannot be negative", catalog.ID)
	}
	version, err := semver.NewVersion(strings.TrimPrefix(kubernetesVersion, "v"))
	if err != nil {
		return chartRelease{}, fmt.Errorf("parse Kubernetes version %s: %w", kubernetesVersion, err)
	}
	catalog.compatibilityMu.Lock()
	defer catalog.compatibilityMu.Unlock()
	state := catalog.compatibility[kubernetesVersion]
	if state == nil {
		state = &chartCompatibilityState{}
		catalog.compatibility[kubernetesVersion] = state
	}
	for len(state.matches) <= offset && state.scanned < len(catalog.Releases) {
		release := catalog.Releases[state.scanned]
		fetched, err := catalog.fetch(ctx, client, release)
		if err != nil {
			return chartRelease{}, err
		}
		if fetched.Version == catalog.Current {
			if err := catalog.verifyCurrent(fetched); err != nil {
				return chartRelease{}, err
			}
		}
		if eligible, reason := eligibleChartAppVersion(fetched.AppVersion); !eligible {
			state.failures = append(state.failures, fetched.Version+" "+reason)
			state.scanned++
			continue
		}
		compatible, err := chartSupportsKubernetes(catalog.ID, fetched.KubeVersion, version)
		if err != nil {
			return chartRelease{}, err
		}
		if compatible {
			state.matches = append(state.matches, fetched)
		} else {
			state.failures = append(
				state.failures,
				fetched.Version+" requires "+fetched.KubeVersion,
			)
		}
		state.scanned++
	}
	if offset < len(state.matches) {
		return state.matches[offset], nil
	}
	return chartRelease{}, fmt.Errorf("%w: chart %s has no release compatible with Kubernetes %s (%s)",
		errNoCompatibleKubernetes,
		catalog.ID,
		kubernetesVersion,
		strings.Join(state.failures, "; "),
	)
}

func chartSupportsKubernetes(id, constraint string, version *semver.Version) (bool, error) {
	constraint = normalizeConstraint(constraint)
	if constraint == "" {
		return true, nil
	}
	parsed, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("parse chart %s Kubernetes constraint %s: %w", id, constraint, err)
	}
	return parsed.Check(version), nil
}

func (catalog *chartCatalog) verifyCurrent(fetched chartRelease) error {
	if fetched.Version != catalog.Current {
		return fmt.Errorf("chart %s current material resolved release %s, want %s", catalog.ID, fetched.Version, catalog.Current)
	}
	if fetched.ArchiveSHA != catalog.CurrentArchiveSHA {
		return fmt.Errorf("chart %s current archive changed from %s to %s", catalog.ID, catalog.CurrentArchiveSHA, fetched.ArchiveSHA)
	}
	if catalog.Source.Type == "oci" && fetched.Digest != catalog.Source.Digest {
		return fmt.Errorf("chart %s current OCI digest changed from %s to %s", catalog.ID, catalog.Source.Digest, fetched.Digest)
	}
	if catalog.Source.Type == "https" && fetched.URL != catalog.Source.URL {
		return fmt.Errorf("chart %s current archive URL changed from %s to %s", catalog.ID, catalog.Source.URL, fetched.URL)
	}
	return nil
}

func resolveTrackedChartsForKubernetes(
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []config.TrackedChart,
	catalogs []*chartCatalog,
	kubernetesVersion string,
	offsets map[string]int,
) ([]resolvedTrackedChart, error) {
	return resolveChartsForKubernetes(
		ctx, client, parallelism, configured, catalogs, kubernetesVersion, offsets, "tracked",
		func(chart config.TrackedChart) string { return chart.ID },
		func(chart config.TrackedChart, fetched chartRelease) (resolvedTrackedChart, error) {
			chart.Version = fetched.Version
			chart.AppVersion = fetched.AppVersion
			chart.KubeVersion = fetched.KubeVersion
			chart.ArchiveSHA256 = fetched.ArchiveSHA
			chart.Source = resolvedChartSource(chart.Source, fetched)
			return resolvedTrackedChart{
				Chart:       chart,
				ArchivePath: fetched.ArchivePath,
			}, nil
		},
	)
}

func resolveBootstrapChartsForKubernetes(
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []config.Chart,
	catalogs []*chartCatalog,
	kubernetesVersion string,
	offsets map[string]int,
) ([]resolvedBootstrapChart, error) {
	return resolveChartsForKubernetes(
		ctx, client, parallelism, configured, catalogs, kubernetesVersion, offsets, "bootstrap",
		func(chart config.Chart) string { return chart.ID },
		func(chart config.Chart, fetched chartRelease) (resolvedBootstrapChart, error) {
			var err error
			chart.Version = fetched.Version
			chart.AppVersion = fetched.AppVersion
			chart.KubeVersion = fetched.KubeVersion
			chart.Source = resolvedChartSource(chart.Source, fetched)
			chart.File = chart.Name + "-" + fetched.Version + ".tgz"
			chart.ArchiveSHA256 = fetched.ArchiveSHA
			chart.Target, err = replaceImageTag(chart.Target, fetched.Version)
			if err != nil {
				return resolvedBootstrapChart{}, fmt.Errorf("update bootstrap chart target %s: %w", chart.ID, err)
			}
			return resolvedBootstrapChart{Chart: chart, ArchivePath: fetched.ArchivePath}, nil
		},
	)
}

func resolveChartsForKubernetes[Configured, Resolved any](
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []Configured,
	catalogs []*chartCatalog,
	kubernetesVersion string,
	offsets map[string]int,
	label string,
	id func(Configured) string,
	resolve func(Configured, chartRelease) (Resolved, error),
) ([]Resolved, error) {
	if len(configured) != len(catalogs) {
		return nil, fmt.Errorf("%s chart catalog count %d does not match configuration count %d", label, len(catalogs), len(configured))
	}
	resolved := make([]Resolved, len(configured))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for i := range configured {
		i := i
		group.Go(func() error {
			fetched, err := catalogs[i].compatibleAt(groupContext, client, kubernetesVersion, offsets[id(configured[i])])
			if err != nil {
				return err
			}
			value, err := resolve(configured[i], fetched)
			if err != nil {
				return err
			}
			resolved[i] = value
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return resolved, nil
}

func fetchConfiguredTrackedCharts(
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []config.TrackedChart,
) (map[string]string, error) {
	paths := make([]string, len(configured))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	for i := range configured {
		i := i
		group.Go(func() error {
			fetched, err := client.Fetch(groupContext, releaseForConfigured(
				configured[i].Source,
				configured[i].Version,
				configured[i].ArchiveSHA256,
			))
			if err != nil {
				return err
			}
			if configured[i].Source.Type == "oci" && fetched.Digest != configured[i].Source.Digest {
				return fmt.Errorf("configured chart %s OCI digest is %s, want %s", configured[i].ID, fetched.Digest, configured[i].Source.Digest)
			}
			paths[i] = fetched.ArchivePath
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(configured))
	for i := range configured {
		result[configured[i].ID] = paths[i]
	}
	return result, nil
}

func fetchConfiguredBootstrapCharts(
	ctx context.Context,
	client *chartClient,
	parallelism int,
	configured []config.Chart,
) (map[string]string, error) {
	tracked := make([]config.TrackedChart, len(configured))
	for i := range configured {
		tracked[i] = config.TrackedChart{
			ID:            configured[i].ID,
			Name:          configured[i].Name,
			Version:       configured[i].Version,
			Source:        configured[i].Source,
			ArchiveSHA256: configured[i].ArchiveSHA256,
		}
	}
	return fetchConfiguredTrackedCharts(ctx, client, parallelism, tracked)
}

func releasesForSource(ctx context.Context, client *chartClient, source config.ChartSource, name string) ([]chartRelease, error) {
	switch source.Type {
	case "https":
		return client.HTTPSReleases(ctx, source.IndexURL, name)
	case "oci":
		return client.OCIReleases(ctx, source.URL)
	default:
		return nil, fmt.Errorf("chart %s has unsupported source type %q", name, source.Type)
	}
}

func releaseForConfigured(source config.ChartSource, version, archiveSHA string) chartRelease {
	return chartRelease{
		Version:    version,
		URL:        source.URL,
		Digest:     source.Digest,
		ArchiveSHA: archiveSHA,
	}
}

func resolvedChartSource(original config.ChartSource, release chartRelease) config.ChartSource {
	if original.Type == "oci" {
		return config.ChartSource{Type: "oci", URL: original.URL, Digest: release.Digest}
	}
	return config.ChartSource{Type: "https", URL: release.URL, IndexURL: original.IndexURL}
}

func requireNonDowngrade(id, current, candidate string) error {
	currentVersion, err := semanticReleaseVersion(current)
	if err != nil {
		return fmt.Errorf("parse current release version %s for %s: %w", current, id, err)
	}
	candidateVersion, err := semanticReleaseVersion(candidate)
	if err != nil {
		return fmt.Errorf("parse candidate release version %s for %s: %w", candidate, id, err)
	}
	if candidateVersion.LessThan(currentVersion) {
		return fmt.Errorf("%s latest upstream release %s is older than locked release %s", id, candidate, current)
	}
	return nil
}

func semanticReleaseVersion(tag string) (*semver.Version, error) {
	version := strings.TrimPrefix(tag, "v")
	if separator := strings.LastIndex(version, "-v"); separator >= 0 {
		version = version[separator+2:]
	}
	return semver.NewVersion(version)
}
