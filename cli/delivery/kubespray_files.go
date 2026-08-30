package delivery

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/process"

	"golang.org/x/sync/errgroup"
)

const (
	fileManifestSchema                   = "atum.dev/kubespray-files/v1"
	maxConcurrentBastionFileSSHTransfers = 8
)

type FileManifestIdentity struct {
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
	Bytes  int64  `json:"bytes"`
}

type FileBlob struct {
	SHA256    string   `json:"sha256"`
	Size      int64    `json:"size"`
	Paths     []string `json:"paths"`
	CacheFile string   `json:"-"`
}

type FileManifest struct {
	Identity FileManifestIdentity `json:"identity"`
	Blobs    []FileBlob           `json:"-"`
	Data     []byte               `json:"-"`
}

type kubesprayFileProjectionEntry struct {
	label  string
	path   string
	sha256 string
	size   int64
}

// KubesprayFileProjection is the immutable byte-identity set observed at the
// Terraform-owned private bastion endpoint.
type KubesprayFileProjection struct {
	entries []kubesprayFileProjectionEntry
}

// Count reports the number of original-domain paths in the projection.
func (projection KubesprayFileProjection) Count() int {
	return len(projection.entries)
}

// SelectedKubesprayFileProjection projects one release's selected files.
func SelectedKubesprayFileProjection(
	files []config.KubesprayFile,
) (KubesprayFileProjection, error) {
	entries := make([]kubesprayFileProjectionEntry, 0, len(files))
	for _, file := range files {
		entries = append(entries, kubesprayFileProjectionEntry{
			label:  file.ID,
			path:   file.RepositoryPath,
			sha256: file.SHA256,
			size:   file.Size,
		})
	}
	return newKubesprayFileProjection(entries)
}

// ManifestKubesprayFileProjection projects the complete selected ladder union.
func ManifestKubesprayFileProjection(
	manifest FileManifest,
) (KubesprayFileProjection, error) {
	count := 0
	for _, blob := range manifest.Blobs {
		count += len(blob.Paths)
	}
	entries := make([]kubesprayFileProjectionEntry, 0, count)
	for _, blob := range manifest.Blobs {
		for _, repositoryPath := range blob.Paths {
			entries = append(entries, kubesprayFileProjectionEntry{
				label:  repositoryPath,
				path:   repositoryPath,
				sha256: blob.SHA256,
				size:   blob.Size,
			})
		}
	}
	return newKubesprayFileProjection(entries)
}

func newKubesprayFileProjection(
	entries []kubesprayFileProjectionEntry,
) (KubesprayFileProjection, error) {
	if len(entries) == 0 {
		return KubesprayFileProjection{}, errors.New(
			"Kubespray file projection is empty",
		)
	}
	paths := make(map[string]string, len(entries))
	for _, entry := range entries {
		decoded, digestErr := hex.DecodeString(entry.sha256)
		canonicalPath, pathErr := config.KubesprayFileRepositoryPath(
			"https://" + entry.path,
		)
		if entry.label == "" ||
			entry.path == "" ||
			pathErr != nil ||
			canonicalPath != entry.path ||
			digestErr != nil ||
			len(decoded) != 32 ||
			entry.sha256 != strings.ToLower(entry.sha256) ||
			entry.size <= 0 {
			return KubesprayFileProjection{}, fmt.Errorf(
				"Kubespray file projection entry %q is invalid",
				entry.label,
			)
		}
		if previous, duplicate := paths[entry.path]; duplicate {
			return KubesprayFileProjection{}, fmt.Errorf(
				"Kubespray file projection path %s is duplicated by %s and %s",
				entry.path,
				previous,
				entry.label,
			)
		}
		paths[entry.path] = entry.label
	}
	return KubesprayFileProjection{
		entries: append([]kubesprayFileProjectionEntry(nil), entries...),
	}, nil
}

// ObserveKubesprayFileProjection proves every projected path directly against
// the fixed private bastion without proxy or redirect behavior.
func ObserveKubesprayFileProjection(
	ctx context.Context,
	endpoint string,
	projection KubesprayFileProjection,
	parallelism int,
) error {
	endpoint = strings.TrimSuffix(endpoint, "/")
	if endpoint != config.SeedKubesprayFilesURL {
		return fmt.Errorf(
			"Kubespray files endpoint %q is not the fixed private bastion",
			endpoint,
		)
	}
	if len(projection.entries) == 0 {
		return errors.New("Kubespray file projection is empty")
	}
	client, transport := directKubesprayFilesClient(parallelism)
	defer transport.CloseIdleConnections()
	return observeKubesprayFileProjection(
		ctx,
		client,
		endpoint,
		projection,
		parallelism,
	)
}

func directKubesprayFilesClient(
	parallelism int,
) (*http.Client, *http.Transport) {
	limit := config.EffectiveWorkLimit(
		parallelism,
		0,
		config.DefaultWorkLimit,
	)
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           limit,
		MaxIdleConnsPerHost:    limit,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
		CheckRedirect: func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}, transport
}

func observeKubesprayFileProjection(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	projection KubesprayFileProjection,
	parallelism int,
) error {
	if client == nil || endpoint == "" || len(projection.entries) == 0 {
		return errors.New("complete direct files observation inputs are required")
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism,
		0,
		config.DefaultWorkLimit,
	))
	for index := range projection.entries {
		entry := projection.entries[index]
		group.Go(func() error {
			request, err := http.NewRequestWithContext(
				groupContext,
				http.MethodGet,
				endpoint+"/"+entry.path,
				nil,
			)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if err != nil {
				return fmt.Errorf("%s is unavailable: %w", entry.label, err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
				return fmt.Errorf(
					"%s returned HTTP %d",
					entry.label,
					response.StatusCode,
				)
			}
			if response.ContentLength >= 0 &&
				response.ContentLength != entry.size {
				return fmt.Errorf(
					"%s has Content-Length %d, want %d",
					entry.label,
					response.ContentLength,
					entry.size,
				)
			}
			digest, size, err := readerSHA256(
				io.LimitReader(response.Body, entry.size+1),
			)
			if err != nil {
				return fmt.Errorf("read %s: %w", entry.label, err)
			}
			if size != entry.size || digest != entry.sha256 {
				return fmt.Errorf("%s content identity differs", entry.label)
			}
			return nil
		})
	}
	return group.Wait()
}

// MaterializeFileManifest creates the one publication vocabulary consumed by
// both OpenSSH publication and the Terraform-owned remote helper. Content is
// grouped by SHA-256 while every selected original-domain path is retained.
func MaterializeFileManifest(project *config.Project) (FileManifest, error) {
	if project == nil {
		return FileManifest{}, errors.New("Atum project is not loaded")
	}
	byDigest := make(map[string]*FileBlob)
	pathDigests := make(map[string]string)
	for _, inventory := range project.Desired.Delivery.Kubespray {
		for _, selected := range inventory.Files {
			if previous, exists := pathDigests[selected.RepositoryPath]; exists &&
				previous != selected.SHA256 {
				return FileManifest{}, fmt.Errorf(
					"Kubespray repository path %s resolves to multiple digests",
					selected.RepositoryPath,
				)
			}
			pathDigests[selected.RepositoryPath] = selected.SHA256
			blob := byDigest[selected.SHA256]
			if blob == nil {
				blob = &FileBlob{
					SHA256:    selected.SHA256,
					Size:      selected.Size,
					CacheFile: selected.CacheFile,
				}
				byDigest[selected.SHA256] = blob
			} else if blob.Size != selected.Size {
				return FileManifest{}, fmt.Errorf(
					"Kubespray digest %s has inconsistent sizes",
					selected.SHA256,
				)
			}
			if !containsString(blob.Paths, selected.RepositoryPath) {
				blob.Paths = append(blob.Paths, selected.RepositoryPath)
			}
		}
	}
	if len(byDigest) == 0 {
		return FileManifest{}, errors.New("Kubespray file publication manifest is empty")
	}
	blobs := make([]FileBlob, 0, len(byDigest))
	var total int64
	for _, blob := range byDigest {
		sort.Strings(blob.Paths)
		file, err := fssecure.OpenRegular(project.Root, blob.CacheFile)
		if err != nil {
			return FileManifest{}, fmt.Errorf("open Kubespray file %s: %w", blob.SHA256, err)
		}
		digest, size, hashErr := readerSHA256(file)
		closeErr := file.Close()
		if hashErr != nil {
			return FileManifest{}, hashErr
		}
		if closeErr != nil {
			return FileManifest{}, closeErr
		}
		if digest != blob.SHA256 || size != blob.Size {
			return FileManifest{}, fmt.Errorf(
				"Kubespray file %s is %s/%d, want %s/%d",
				blob.CacheFile, digest, size, blob.SHA256, blob.Size,
			)
		}
		blobs = append(blobs, *blob)
		total += blob.Size
	}
	sort.Slice(blobs, func(i, j int) bool {
		return blobs[i].SHA256 < blobs[j].SHA256
	})
	var manifest bytes.Buffer
	manifest.WriteString(fileManifestSchema)
	manifest.WriteByte('\n')
	for index := range blobs {
		manifest.WriteString(blobs[index].SHA256)
		manifest.WriteByte('\t')
		manifest.WriteString(strconv.FormatInt(blobs[index].Size, 10))
		for _, repositoryPath := range blobs[index].Paths {
			if strings.ContainsAny(repositoryPath, "\t\r\n") {
				return FileManifest{}, fmt.Errorf(
					"Kubespray repository path %q cannot be represented",
					repositoryPath,
				)
			}
			manifest.WriteByte('\t')
			manifest.WriteString(repositoryPath)
		}
		manifest.WriteByte('\n')
	}
	data := manifest.Bytes()
	return FileManifest{
		Identity: FileManifestIdentity{
			SHA256: config.SHA256(data),
			Count:  len(blobs),
			Bytes:  total,
		},
		Blobs: blobs,
		Data:  append([]byte(nil), data...),
	}, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func openFileBlob(project *config.Project, blob FileBlob) (*os.File, error) {
	file, err := fssecure.OpenRegular(project.Root, blob.CacheFile)
	if err != nil {
		return nil, fmt.Errorf("open Kubespray file %s: %w", blob.SHA256, err)
	}
	return file, nil
}

const missingDigestOutputLimit = 64 << 10

type limitedOutput struct {
	buffer bytes.Buffer
	limit  int
	full   bool
}

func (output *limitedOutput) Write(data []byte) (int, error) {
	if output.buffer.Len()+len(data) > output.limit {
		remaining := max(output.limit-output.buffer.Len(), 0)
		_, _ = output.buffer.Write(data[:remaining])
		output.full = true
		return len(data), nil
	}
	return output.buffer.Write(data)
}

func PublishFileManifest(
	ctx context.Context,
	runner process.Runner,
	sshBinary string,
	privateKey string,
	project *config.Project,
	manifest FileManifest,
	bastionIdentity string,
	parallelism int,
	report func(string, int64, bool),
) error {
	if runner == nil || sshBinary == "" || project == nil ||
		manifest.Identity.Count == 0 || len(manifest.Data) == 0 {
		return errors.New("complete Kubespray file publication inputs are required")
	}
	identity, err := expandIdentityPath(privateKey)
	if err != nil {
		return err
	}
	knownHosts, trustRelative, err := prepareBastionKnownHosts(
		project,
		bastionIdentity,
	)
	if err != nil {
		return err
	}
	base := []string{
		"-i", identity,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=30",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HashKnownHosts=yes",
		"root@10.77.0.9",
		"/usr/local/sbin/atum-kubespray-files",
	}
	var output limitedOutput
	output.limit = missingDigestOutputLimit
	args := append(append([]string(nil), base...), "report", manifest.Identity.SHA256)
	if err := runner.Run(ctx, process.Command{
		Name: sshBinary, Args: args, Stdin: bytes.NewReader(manifest.Data),
		Stdout: &output,
	}); err != nil {
		return fmt.Errorf("inspect retained Kubespray files: %w", err)
	}
	if output.full {
		return errors.New("retained Kubespray file report exceeds its output limit")
	}
	missing, err := parseMissingDigests(output.buffer.String(), manifest)
	if err != nil {
		return err
	}
	byDigest := make(map[string]FileBlob, len(manifest.Blobs))
	for _, blob := range manifest.Blobs {
		byDigest[blob.SHA256] = blob
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(min(
		config.EffectiveWorkLimit(
			parallelism,
			project.Desired.Updates.Parallelism,
			defaultParallelism,
		),
		maxConcurrentBastionFileSSHTransfers,
	))
	for digest := range missing {
		blob := byDigest[digest]
		group.Go(func() error {
			file, openErr := openFileBlob(project, blob)
			if openErr != nil {
				return openErr
			}
			defer file.Close()
			putArgs := append(
				append([]string(nil), base...),
				"put", manifest.Identity.SHA256, blob.SHA256,
			)
			if runErr := runner.Run(groupContext, process.Command{
				Name:  sshBinary,
				Args:  putArgs,
				Stdin: io.LimitReader(file, blob.Size+1),
			}); runErr != nil {
				return fmt.Errorf("publish Kubespray file %s: %w", blob.SHA256, runErr)
			}
			if report != nil {
				report(blob.SHA256, blob.Size, false)
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	for _, blob := range manifest.Blobs {
		if _, uploaded := missing[blob.SHA256]; !uploaded && report != nil {
			report(blob.SHA256, 0, true)
		}
	}
	args = append(append([]string(nil), base...), "activate", manifest.Identity.SHA256)
	if err := runner.Run(ctx, process.Command{
		Name: sshBinary, Args: args, Stdout: io.Discard,
	}); err != nil {
		return fmt.Errorf("activate retained Kubespray files: %w", err)
	}
	return cleanRetiredBastionTrust(project, trustRelative)
}

func prepareBastionKnownHosts(
	project *config.Project,
	bastionIdentity string,
) (string, string, error) {
	if project == nil || bastionIdentity == "" ||
		len(bastionIdentity) > 1024 ||
		strings.ContainsAny(bastionIdentity, "\r\n\x00") {
		return "", "", errors.New("Terraform bastion resource identity is invalid")
	}
	base := filepath.Join(".atum", "state", "ssh", "bastion")
	if _, err := fssecure.EnsureDirectory(project.Root, base, 0o700); err != nil {
		return "", "", err
	}
	current := filepath.Join(base, config.SHA256([]byte(bastionIdentity)))
	root, err := fssecure.EnsureDirectory(project.Root, current, 0o700)
	if err != nil {
		return "", "", err
	}
	knownHosts := filepath.Join(root, "known_hosts")
	file, err := os.OpenFile(
		knownHosts,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return "", "", closeErr
		}
	} else if !errors.Is(err, os.ErrExist) {
		return "", "", err
	}
	info, err := os.Lstat(knownHosts)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		if err != nil {
			return "", "", err
		}
		return "", "", errors.New("Atum bastion known-hosts record is not a private regular file")
	}
	return knownHosts, current, nil
}

func cleanRetiredBastionTrust(
	project *config.Project,
	current string,
) error {
	baseRelative := filepath.Join(".atum", "state", "ssh", "bastion")
	base, err := fssecure.Resolve(project.Root, baseRelative, false)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	currentName := filepath.Base(current)
	for _, entry := range entries {
		if entry.Name() == currentName {
			continue
		}
		if !entry.IsDir() {
			return fmt.Errorf(
				"unexpected Atum bastion trust artifact %s",
				entry.Name(),
			)
		}
		if err := fssecure.RemoveTree(
			project.Root,
			filepath.Join(baseRelative, entry.Name()),
		); err != nil {
			return err
		}
	}
	return nil
}

func parseMissingDigests(raw string, manifest FileManifest) (map[string]struct{}, error) {
	expected := make(map[string]struct{}, len(manifest.Blobs))
	for _, blob := range manifest.Blobs {
		expected[blob.SHA256] = struct{}{}
	}
	missing := make(map[string]struct{})
	for _, digest := range strings.Fields(raw) {
		if _, exists := expected[digest]; !exists {
			return nil, fmt.Errorf(
				"retained Kubespray file helper reported unknown digest %q",
				digest,
			)
		}
		if _, duplicate := missing[digest]; duplicate {
			return nil, fmt.Errorf(
				"retained Kubespray file helper duplicated digest %s",
				digest,
			)
		}
		missing[digest] = struct{}{}
	}
	return missing, nil
}

func expandIdentityPath(value string) (string, error) {
	if value == "" {
		return "", errors.New("SSH private-key path is required")
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve SSH private-key home: %w", err)
		}
		value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve SSH private-key path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect SSH private key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("SSH private key is not a regular file")
	}
	return absolute, nil
}
