package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"atum/cli/config"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
	chart "helm.sh/helm/v4/pkg/chart/v2"
)

var deterministicChartTime = time.Unix(0, 0).UTC()

type chartPackageInput struct {
	ID           string
	Kind         string
	SourceURL    string
	SourceCommit string
	ChartPath    string
	Path         string
	UpstreamSHA  string
	Values       map[string]any
	Instances    []releaseValueInstance
}

func selectedChartPackageInputs(
	bigBang resolvedGit,
	packages []resolvedPackage,
	support []resolvedSupportSource,
	charts []resolvedTrackedChart,
	bootstrap []resolvedBootstrapChart,
	artifacts []chartArtifact,
) ([]chartPackageInput, error) {
	artifactsByID := make(map[string]chartArtifact, len(artifacts))
	for index := range artifacts {
		artifactsByID[artifacts[index].ID] = artifacts[index]
	}
	inputs := make([]chartPackageInput, 0, 1+len(packages)+len(support)+len(charts)+len(bootstrap))
	add := func(input chartPackageInput) error {
		hash, err := chartInputSHA(input.Path)
		if err != nil {
			return fmt.Errorf("hash upstream chart %s: %w", input.ID, err)
		}
		input.UpstreamSHA = hash
		inputs = append(inputs, input)
		return nil
	}
	if err := add(chartPackageInput{
		ID: "bigbang", Kind: "root", SourceURL: bigBang.Source.URL,
		SourceCommit: bigBang.Source.Commit, ChartPath: "chart",
		Path:      filepath.Join(bigBang.Checkout, "chart"),
		Values:    artifactsByID["bigbang"].Values,
		Instances: artifactsByID["bigbang"].Instances,
	}); err != nil {
		return nil, err
	}
	for index := range packages {
		pkg := packages[index]
		kind := pkg.Package.Integration
		if kind == "" {
			kind = "integrated"
		}
		id := "package/" + pkg.Package.ID
		if err := add(chartPackageInput{
			ID: id, Kind: kind, SourceURL: pkg.Package.Source.URL,
			SourceCommit: pkg.Package.Source.Commit, ChartPath: pkg.Package.RepositoryChartPath(),
			Path:   filepath.Join(pkg.Checkout, filepath.FromSlash(pkg.Package.RepositoryChartPath())),
			Values: artifactsByID[id].Values, Instances: artifactsByID[id].Instances,
		}); err != nil {
			return nil, err
		}
	}
	for index := range support {
		item := support[index]
		id := "wrapper/" + item.Support.ID
		artifact, exists := artifactsByID[id]
		if !exists {
			return nil, fmt.Errorf("admitted chart artifact %s is missing", id)
		}
		if err := add(chartPackageInput{
			ID: id, Kind: "wrapper",
			SourceURL: item.Support.Source.URL, SourceCommit: item.Support.Source.Commit,
			ChartPath: item.Support.ChartPath,
			Path:      filepath.Join(item.Checkout, filepath.FromSlash(item.Support.ChartPath)),
			Values:    artifact.Values, Instances: artifact.Instances,
		}); err != nil {
			return nil, err
		}
	}
	for index := range charts {
		item := charts[index]
		id := "chart/" + item.Chart.ID
		if err := add(chartPackageInput{
			ID: id, Kind: "generic", SourceURL: item.Chart.Source.URL,
			ChartPath: item.Chart.Name, Path: item.ArchivePath,
			Values: artifactsByID[id].Values, Instances: artifactsByID[id].Instances,
		}); err != nil {
			return nil, err
		}
	}
	for index := range bootstrap {
		item := bootstrap[index]
		id := "bootstrap/" + item.Chart.ID
		if err := add(chartPackageInput{
			ID: id, Kind: "bootstrap", SourceURL: item.Chart.Source.URL,
			ChartPath: item.Chart.Name, Path: item.ArchivePath,
			Values: artifactsByID[id].Values, Instances: artifactsByID[id].Instances,
		}); err != nil {
			return nil, err
		}
	}
	return inputs, nil
}

// packageChartInventory materializes the canonical chart graph in one bounded
// pass. Each archive is content-addressed beneath the updater cache so all
// later consumers use identical bytes.
func packageChartInventory(
	ctx context.Context,
	root string,
	registry config.Registry,
	parallelism int,
	inputs []chartPackageInput,
	report func(int, int),
) ([]config.ChartArtifact, error) {
	artifacts := make([]config.ChartArtifact, len(inputs))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	completed := 0
	var progressMu sync.Mutex
	for index := range inputs {
		index := index
		group.Go(func() error {
			if err := groupContext.Err(); err != nil {
				return err
			}
			artifact, err := packageChart(root, registry, inputs[index])
			if err != nil {
				return err
			}
			artifacts[index] = artifact
			if report != nil {
				progressMu.Lock()
				completed++
				report(completed, len(inputs))
				progressMu.Unlock()
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].ID < artifacts[j].ID })
	return artifacts, nil
}

func packageChart(root string, registry config.Registry, input chartPackageInput) (config.ChartArtifact, error) {
	selections := make([]chartValueSelection, 0, max(1, len(input.Instances)))
	for index := range input.Instances {
		selections = append(selections, chartValueSelection{
			identity: input.Instances[index].identity,
			values:   input.Instances[index].values,
		})
	}
	if len(selections) == 0 {
		selections = append(selections, chartValueSelection{
			identity: input.ID,
			values:   input.Values,
		})
	}
	loaded, normalizations, err := loadNormalizedChart(input.Path, selections)
	if err != nil {
		return config.ChartArtifact{}, fmt.Errorf("normalize chart artifact %s: %w", input.ID, err)
	}
	if loaded.Metadata == nil {
		return config.ChartArtifact{}, fmt.Errorf("chart artifact %s has no metadata", input.ID)
	}
	archiveRoot := filepath.Join(".atum", "cache", "packaged-charts")
	if err := os.MkdirAll(filepath.Join(root, archiveRoot), 0o700); err != nil {
		return config.ChartArtifact{}, err
	}
	temporary, err := os.CreateTemp(filepath.Join(root, archiveRoot), ".chart-*.tgz")
	if err != nil {
		return config.ChartArtifact{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	hash := sha256.New()
	counting := &countingWriter{writer: io.MultiWriter(temporary, hash)}
	if err := writeDeterministicChart(counting, loaded); err != nil {
		temporary.Close()
		return config.ChartArtifact{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return config.ChartArtifact{}, err
	}
	if err := temporary.Close(); err != nil {
		return config.ChartArtifact{}, err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	file := digest + ".tgz"
	relative := filepath.Join(archiveRoot, file)
	destination := filepath.Join(root, relative)
	if err := verifyChartCacheFile(root, relative, digest); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return config.ChartArtifact{}, err
		}
		if err := os.Link(temporaryPath, destination); err != nil {
			if !os.IsExist(err) {
				return config.ChartArtifact{}, err
			}
			if err := verifyChartCacheFile(root, relative, digest); err != nil {
				return config.ChartArtifact{}, err
			}
		}
	}
	target := registry.Host + "/" + registry.Project + "/" + loaded.Metadata.Name + ":" + loaded.Metadata.Version
	return config.ChartArtifact{
		ID: input.ID, Kind: input.Kind, SourceURL: input.SourceURL,
		SourceCommit: input.SourceCommit, ChartPath: input.ChartPath,
		Name: loaded.Metadata.Name, Version: loaded.Metadata.Version,
		UpstreamSHA256: input.UpstreamSHA, ArchiveSHA256: digest,
		Size: counting.count, File: filepath.ToSlash(relative), Target: target,
		Normalizations: normalizations,
	}, nil
}

type countingWriter struct {
	writer io.Writer
	count  int64
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	n, err := writer.writer.Write(data)
	writer.count += int64(n)
	return n, err
}

func writeDeterministicChart(destination io.Writer, root *chart.Chart) error {
	gzipWriter, err := gzip.NewWriterLevel(destination, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = deterministicChartTime
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeChartTree(tarWriter, root, ""); err != nil {
		return err
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

func writeChartTree(writer *tar.Writer, current *chart.Chart, prefix string) error {
	base := filepath.ToSlash(filepath.Join(prefix, current.Name()))
	metadata, err := yaml.Marshal(current.Metadata)
	if err != nil {
		return err
	}
	files := map[string][]byte{"Chart.yaml": metadata}
	if current.Lock != nil {
		data, err := yaml.Marshal(current.Lock)
		if err != nil {
			return err
		}
		files["Chart.lock"] = data
	}
	values, err := yaml.Marshal(current.Values)
	if err != nil {
		return err
	}
	files["values.yaml"] = values
	if len(current.Schema) != 0 {
		files["values.schema.json"] = current.Schema
	}
	for _, file := range current.Templates {
		files[file.Name] = file.Data
	}
	for _, file := range current.Files {
		files[file.Name] = file.Data
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		header := &tar.Header{
			Name: filepath.ToSlash(filepath.Join(base, name)), Mode: 0o644,
			Size: int64(len(data)), ModTime: deterministicChartTime,
			AccessTime: deterministicChartTime, ChangeTime: deterministicChartTime,
			Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatGNU,
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
	}
	dependencies := append([]*chart.Chart(nil), current.Dependencies()...)
	sort.Slice(dependencies, func(i, j int) bool {
		left := dependencies[i].Name() + "\x00" + dependencies[i].Metadata.Version
		right := dependencies[j].Name() + "\x00" + dependencies[j].Metadata.Version
		return left < right
	})
	for _, dependency := range dependencies {
		if err := writeChartTree(writer, dependency, filepath.Join(base, "charts")); err != nil {
			return err
		}
	}
	return nil
}

func chartInputSHA(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().IsRegular() {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return "", err
		}
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
	return hashTree(path)
}
