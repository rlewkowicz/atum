package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/singleflight"
	"gopkg.in/yaml.v3"
	helmregistry "helm.sh/helm/v4/pkg/registry"
)

// FetchBootstrapChart materializes one exact chart archive in the shared
// content-addressed cache. Delivery uses the same verified fetch path as the
// updater so chart resolution and bundle assembly cannot diverge.
func FetchBootstrapChart(ctx context.Context, root string, chart config.Chart) (string, error) {
	return fetchLockedChart(ctx, root, chart.ID, chart.Version, chart.Source, chart.ArchiveSHA256)
}

// FetchTrackedChart materializes one exact Big Bang extension chart through
// the same bounded, content-addressed cache used during update resolution.
func FetchTrackedChart(ctx context.Context, root string, chart config.TrackedChart) (string, error) {
	return fetchLockedChart(ctx, root, chart.ID, chart.Version, chart.Source, chart.ArchiveSHA256)
}

func fetchLockedChart(
	ctx context.Context,
	root, id, version string,
	source config.ChartSource,
	archiveSHA256 string,
) (string, error) {
	release, err := newChartClient(root).Fetch(ctx, chartRelease{
		Version:    version,
		URL:        source.URL,
		Digest:     source.Digest,
		ArchiveSHA: archiveSHA256,
	})
	if err != nil {
		return "", fmt.Errorf("fetch chart %s: %w", id, err)
	}
	if release.ArchiveSHA != archiveSHA256 {
		return "", fmt.Errorf("chart %s archive is %s, want %s", id, release.ArchiveSHA, archiveSHA256)
	}
	return release.ArchivePath, nil
}

const (
	indexLimit      = 32 << 20
	ociTagPageLimit = 1 << 20
	ociTagPageSize  = 100
	ociTagLimit     = 10_000
	ociTagPageCount = 100
)

type chartClient struct {
	root      string
	cacheRoot string
	http      *http.Client
	indexes   singleflight.Group
}

type temporaryChart struct {
	file   *os.File
	path   string
	remove bool
}

func newTemporaryChart(directory, pattern string) (*temporaryChart, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return nil, err
	}
	return &temporaryChart{file: file, path: file.Name(), remove: true}, nil
}

func (temporary *temporaryChart) cleanup() {
	_ = temporary.file.Close()
	if temporary.remove {
		_ = os.Remove(temporary.path)
	}
}

func (temporary *temporaryChart) finish() error {
	if err := temporary.file.Sync(); err != nil {
		return fmt.Errorf("sync temporary chart: %w", err)
	}
	if err := temporary.file.Close(); err != nil {
		return fmt.Errorf("close temporary chart: %w", err)
	}
	return nil
}

func (temporary *temporaryChart) publish(destination string) error {
	if err := os.Rename(temporary.path, destination); err != nil {
		return err
	}
	temporary.remove = false
	return nil
}

type chartRelease struct {
	Version     string
	AppVersion  string
	KubeVersion string
	URL         string
	Digest      string
	ArchiveSHA  string
	ArchivePath string
}

type indexDocument struct {
	Entries map[string][]indexRelease `yaml:"entries"`
}

type indexRelease struct {
	Version     string   `yaml:"version"`
	AppVersion  string   `yaml:"appVersion"`
	KubeVersion string   `yaml:"kubeVersion"`
	URLs        []string `yaml:"urls"`
	Digest      string   `yaml:"digest"`
}

func newChartClient(root string) *chartClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 32
	transport.MaxIdleConnsPerHost = 8
	return &chartClient{
		root:      root,
		cacheRoot: filepath.Join(root, ".atum", "cache", "charts"),
		http: &http.Client{
			Timeout:   2 * time.Minute,
			Transport: transport,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if request.URL.Scheme != "https" {
					return fmt.Errorf("refuse chart redirect to %s", request.URL)
				}
				if len(via) >= 10 {
					return errors.New("refuse chart redirect chain longer than 10 requests")
				}
				return nil
			},
		},
	}
}

func (c *chartClient) HTTPSReleases(ctx context.Context, indexURL, chartName string) ([]chartRelease, error) {
	resolved, err, _ := c.indexes.Do(indexURL, func() (any, error) {
		return c.readHTTPS(ctx, indexURL, indexLimit)
	})
	if err != nil {
		return nil, err
	}
	body := resolved.([]byte)
	var index indexDocument
	if err := yaml.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("decode Helm index %s: %w", indexURL, err)
	}
	entries := index.Entries[chartName]
	if len(entries) == 0 {
		return nil, fmt.Errorf("Helm index %s has no chart %q", indexURL, chartName)
	}
	base, err := url.Parse(indexURL)
	if err != nil {
		return nil, fmt.Errorf("parse Helm index URL %s: %w", indexURL, err)
	}
	releases := make([]chartRelease, 0, len(entries))
	for _, entry := range entries {
		semantic, parseErr := semver.NewVersion(strings.TrimPrefix(entry.Version, "v"))
		if parseErr != nil || semantic.Prerelease() != "" || len(entry.URLs) == 0 {
			continue
		}
		var archiveURL *url.URL
		for _, candidate := range entry.URLs {
			resolved, resolveErr := base.Parse(candidate)
			if resolveErr == nil && resolved.Scheme == "https" {
				archiveURL = resolved
				break
			}
		}
		if archiveURL == nil {
			continue
		}
		digest := strings.TrimPrefix(entry.Digest, "sha256:")
		if !validHexSHA256(digest) {
			continue
		}
		releases = append(releases, chartRelease{
			Version:     entry.Version,
			AppVersion:  strings.TrimSpace(entry.AppVersion),
			KubeVersion: normalizeConstraint(entry.KubeVersion),
			URL:         archiveURL.String(),
			ArchiveSHA:  digest,
		})
	}
	sortChartReleases(releases)
	if len(releases) == 0 {
		return nil, fmt.Errorf("Helm index %s has no stable, checksum-pinned %s releases", indexURL, chartName)
	}
	return releases, nil
}

func (c *chartClient) OCIReleases(ctx context.Context, repositoryURL string) ([]chartRelease, error) {
	repositoryName := strings.TrimPrefix(repositoryURL, "oci://")
	if repositoryName == repositoryURL {
		return nil, fmt.Errorf("OCI chart repository %q is invalid", repositoryURL)
	}
	repository, err := name.NewRepository(repositoryName)
	if err != nil {
		return nil, fmt.Errorf("parse OCI chart repository %s: %w", repositoryURL, err)
	}
	puller, err := remote.NewPuller(
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPageSize(ociTagPageSize),
		remote.WithTransport(cappedRoundTripper{base: c.http.Transport, limit: ociTagPageLimit}),
	)
	if err != nil {
		return nil, fmt.Errorf("configure OCI chart listing for %s: %w", repositoryURL, err)
	}
	lister, err := puller.Lister(ctx, repository)
	if err != nil {
		return nil, fmt.Errorf("list OCI chart tags from %s: %w", repositoryURL, err)
	}
	tags := make([]string, 0, ociTagPageSize)
	for page := 0; lister.HasNext(); page++ {
		if page >= ociTagPageCount {
			return nil, fmt.Errorf("OCI chart repository %s exceeds %d tag pages", repositoryURL, ociTagPageCount)
		}
		result, listErr := lister.Next(ctx)
		if listErr != nil {
			return nil, fmt.Errorf("list OCI chart tags from %s: %w", repositoryURL, listErr)
		}
		if len(result.Tags) > ociTagPageSize || len(tags)+len(result.Tags) > ociTagLimit {
			return nil, fmt.Errorf("OCI chart repository %s exceeds %d tags", repositoryURL, ociTagLimit)
		}
		for _, tag := range result.Tags {
			if len(tag) > 256 {
				return nil, fmt.Errorf("OCI chart repository %s contains an oversized tag", repositoryURL)
			}
		}
		tags = append(tags, result.Tags...)
	}
	releases := make([]chartRelease, 0, len(tags))
	for _, tag := range tags {
		semantic, parseErr := semver.NewVersion(strings.TrimPrefix(tag, "v"))
		if parseErr != nil || semantic.Prerelease() != "" {
			continue
		}
		releases = append(releases, chartRelease{Version: tag, URL: repositoryURL})
	}
	sortChartReleases(releases)
	if len(releases) == 0 {
		return nil, fmt.Errorf("OCI chart repository %s has no stable semantic-version tags", repositoryURL)
	}
	return releases, nil
}

type cappedRoundTripper struct {
	base  http.RoundTripper
	limit int64
}

func (transport cappedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = struct {
		io.Reader
		io.Closer
	}{Reader: io.LimitReader(response.Body, transport.limit+1), Closer: response.Body}
	return response, nil
}

func (c *chartClient) Fetch(ctx context.Context, release chartRelease) (chartRelease, error) {
	if strings.HasPrefix(release.URL, "oci://") {
		return c.fetchOCI(ctx, release)
	}
	if !strings.HasPrefix(release.URL, "https://") || !validHexSHA256(release.ArchiveSHA) {
		return chartRelease{}, fmt.Errorf("chart %s does not have a pinned HTTPS archive", release.Version)
	}
	path, err := c.store(ctx, release.ArchiveSHA, func(destination io.Writer) error {
		return c.copyHTTPS(ctx, release.URL, destination, config.ChartArchiveLimit)
	})
	if err != nil {
		return chartRelease{}, err
	}
	release.ArchivePath = path
	return release, nil
}

func (c *chartClient) fetchOCI(ctx context.Context, release chartRelease) (chartRelease, error) {
	if err := c.ensureCache(); err != nil {
		return chartRelease{}, fmt.Errorf("create chart cache: %w", err)
	}
	reference, err := name.ParseReference(strings.TrimPrefix(release.URL, "oci://") + ":" + release.Version)
	if err != nil {
		return chartRelease{}, fmt.Errorf("parse OCI chart %s:%s: %w", release.URL, release.Version, err)
	}
	lockIdentity := sha256.Sum256([]byte(reference.Name()))
	unlock, err := fssecure.LockContext(
		ctx,
		c.root,
		filepath.Join(".atum", "cache", "charts", hex.EncodeToString(lockIdentity[:])+".lock"),
		100*time.Millisecond,
	)
	if err != nil {
		return chartRelease{}, fmt.Errorf("lock OCI chart cache %s: %w", reference, err)
	}
	defer unlock()

	descriptor, err := remote.Get(reference, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return chartRelease{}, fmt.Errorf("resolve OCI chart %s: %w", reference, err)
	}
	resolvedDigest := descriptor.Digest.String()
	if release.Digest != "" && release.Digest != resolvedDigest {
		return chartRelease{}, fmt.Errorf("OCI chart %s resolved to %s, want %s", reference, resolvedDigest, release.Digest)
	}
	if validHexSHA256(release.ArchiveSHA) {
		filename := release.ArchiveSHA + ".tgz"
		destination := filepath.Join(c.cacheRoot, filename)
		if err := verifyChartCacheFile(c.root, filepath.Join(".atum", "cache", "charts", filename), release.ArchiveSHA); err == nil {
			release.Digest = resolvedDigest
			release.ArchivePath = destination
			return release, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return chartRelease{}, err
		}
	}
	image, err := descriptor.Image()
	if err != nil {
		return chartRelease{}, fmt.Errorf("read OCI chart manifest %s: %w", reference, err)
	}
	layers, err := image.Layers()
	if err != nil {
		return chartRelease{}, fmt.Errorf("list OCI chart layers %s: %w", reference, err)
	}
	var contentLayer v1.Layer
	contentLayers := 0
	for _, layer := range layers {
		mediaType, mediaErr := layer.MediaType()
		if mediaErr != nil {
			return chartRelease{}, fmt.Errorf("inspect OCI chart layer %s: %w", reference, mediaErr)
		}
		if string(mediaType) == helmregistry.ChartLayerMediaType {
			contentLayer = layer
			contentLayers++
		}
	}
	if contentLayers != 1 {
		return chartRelease{}, fmt.Errorf("OCI artifact %s has %d Helm chart content layers, want exactly one", reference, contentLayers)
	}
	chartLayer, err := contentLayer.Compressed()
	if err != nil {
		return chartRelease{}, fmt.Errorf("open OCI chart layer %s: %w", reference, err)
	}
	defer chartLayer.Close()

	temporary, err := newTemporaryChart(c.cacheRoot, ".oci-chart-")
	if err != nil {
		return chartRelease{}, fmt.Errorf("create temporary OCI chart: %w", err)
	}
	defer temporary.cleanup()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary.file, hash), io.LimitReader(chartLayer, config.ChartArchiveLimit+1))
	if err != nil {
		return chartRelease{}, fmt.Errorf("download OCI chart %s: %w", reference, err)
	}
	if written > config.ChartArchiveLimit {
		return chartRelease{}, fmt.Errorf("OCI chart %s exceeds %d bytes", reference, config.ChartArchiveLimit)
	}
	if err := temporary.finish(); err != nil {
		return chartRelease{}, fmt.Errorf("finish OCI chart %s: %w", reference, err)
	}
	release.ArchiveSHA = hex.EncodeToString(hash.Sum(nil))
	release.Digest = resolvedDigest
	filename := release.ArchiveSHA + ".tgz"
	destination := filepath.Join(c.cacheRoot, filename)
	relative := filepath.Join(".atum", "cache", "charts", filename)
	if err := verifyChartCacheFile(c.root, relative, release.ArchiveSHA); err == nil {
		release.ArchivePath = destination
		return release, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return chartRelease{}, err
	}
	if err := temporary.publish(destination); err != nil {
		return chartRelease{}, fmt.Errorf("publish chart cache: %w", err)
	}
	if err := verifyChartCacheFile(c.root, relative, release.ArchiveSHA); err != nil {
		return chartRelease{}, err
	}
	release.ArchivePath = destination
	return release, nil
}

func (c *chartClient) store(ctx context.Context, expectedSHA string, write func(io.Writer) error) (string, error) {
	if err := c.ensureCache(); err != nil {
		return "", fmt.Errorf("create chart cache: %w", err)
	}
	filename := expectedSHA + ".tgz"
	destination := filepath.Join(c.cacheRoot, filename)
	relative := filepath.Join(".atum", "cache", "charts", filename)
	unlock, err := fssecure.LockContext(ctx, c.root, relative+".lock", 100*time.Millisecond)
	if err != nil {
		return "", fmt.Errorf("lock chart cache: %w", err)
	}
	defer unlock()
	if err := verifyChartCacheFile(c.root, relative, expectedSHA); err == nil {
		return destination, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	temporary, err := newTemporaryChart(c.cacheRoot, ".chart-")
	if err != nil {
		return "", fmt.Errorf("create temporary chart: %w", err)
	}
	defer temporary.cleanup()
	hash := sha256.New()
	if err := write(io.MultiWriter(temporary.file, hash)); err != nil {
		return "", err
	}
	actualSHA := hex.EncodeToString(hash.Sum(nil))
	if actualSHA != expectedSHA {
		return "", fmt.Errorf("chart archive checksum is %s, want %s", actualSHA, expectedSHA)
	}
	if err := temporary.finish(); err != nil {
		return "", fmt.Errorf("finish chart archive: %w", err)
	}
	if err := temporary.publish(destination); err != nil {
		return "", fmt.Errorf("publish chart cache: %w", err)
	}
	if err := verifyChartCacheFile(c.root, relative, expectedSHA); err != nil {
		return "", err
	}
	return destination, nil
}

func verifyChartCacheFile(root, relative, expectedSHA string) error {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if info.Size() <= 0 || info.Size() > config.ChartArchiveLimit {
		_ = file.Close()
		return fmt.Errorf("chart cache %s has invalid size %d", relative, info.Size())
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if written != info.Size() || actual != expectedSHA {
		return fmt.Errorf("immutable chart cache %s is %s/%d, want %s/%d",
			relative, actual, written, expectedSHA, info.Size())
	}
	return nil
}

func (c *chartClient) ensureCache() error {
	cacheRoot, err := fssecure.EnsureDirectory(c.root, filepath.Join(".atum", "cache", "charts"), 0o700)
	if err != nil {
		return err
	}
	if cacheRoot != filepath.Clean(c.cacheRoot) {
		return fmt.Errorf("chart cache resolved to %s, want %s", cacheRoot, c.cacheRoot)
	}
	return nil
}

func verifyFileSHA256(root, relative, expected string) error {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash %s: %w", relative, err)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != expected {
		return fmt.Errorf("immutable cache %s has checksum %s, want %s", relative, actual, expected)
	}
	return nil
}

func (c *chartClient) readHTTPS(ctx context.Context, source string, limit int64) ([]byte, error) {
	body, err := c.openHTTPS(ctx, source)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", source, limit)
	}
	return data, nil
}

func (c *chartClient) copyHTTPS(ctx context.Context, source string, destination io.Writer, limit int64) error {
	body, err := c.openHTTPS(ctx, source)
	if err != nil {
		return err
	}
	defer body.Close()
	written, err := io.Copy(destination, io.LimitReader(body, limit+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", source, err)
	}
	if written > limit {
		return fmt.Errorf("%s exceeds %d bytes", source, limit)
	}
	return nil
}

func (c *chartClient) openHTTPS(ctx context.Context, source string) (io.ReadCloser, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", source, err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", source, err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("download %s: HTTP %s", source, response.Status)
	}
	return response.Body, nil
}

func sortChartReleases(releases []chartRelease) {
	type semanticRelease struct {
		release chartRelease
		version *semver.Version
	}
	semantic := make([]semanticRelease, len(releases))
	for i := range releases {
		version, _ := semver.NewVersion(strings.TrimPrefix(releases[i].Version, "v"))
		semantic[i] = semanticRelease{release: releases[i], version: version}
	}
	sort.Slice(semantic, func(i, j int) bool {
		if comparison := semantic[i].version.Compare(semantic[j].version); comparison != 0 {
			return comparison > 0
		}
		return semantic[i].release.Version < semantic[j].release.Version
	})
	for i := range semantic {
		releases[i] = semantic[i].release
	}
}

func normalizeConstraint(value string) string {
	return strings.Join(strings.Fields(strings.Trim(value, `"'`)), " ")
}

func validHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
