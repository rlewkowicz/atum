package oci

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"atum/cli/config"
	"atum/cli/secretvalue"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	// Delivery owns target-level parallelism. Keep each graph copy single-stream
	// so the user-visible parallelism bound also caps sockets and blob buffers.
	copyConcurrency = 1
	metadataLimit   = 4 << 20
	transferTimeout = 12 * time.Hour
)

type Credentials struct {
	Username string
	Password secretvalue.Value
	CACert   []byte
}

func (credentials *Credentials) Clear() {
	if credentials == nil {
		return
	}
	credentials.Username = ""
	credentials.Password.Clear()
	clear(credentials.CACert)
	credentials.CACert = nil
}

// Client owns registry authentication and transport policy. Credentials are
// kept in memory and never written to a Docker auth file or process argv.
type Client struct {
	target  config.Registry
	creds   Credentials
	rootCAs *x509.CertPool
	mu      sync.Mutex
	clients map[string]*auth.Client
}

func NewClient(target config.Registry, credentials Credentials) (*Client, error) {
	if strings.TrimSpace(target.Host) == "" {
		return nil, errors.New("registry host is empty")
	}
	if (credentials.Username == "") != (len(credentials.Password) == 0) {
		return nil, errors.New("registry username and password must be supplied together")
	}
	var rootCAs *x509.CertPool
	if len(credentials.CACert) != 0 {
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(credentials.CACert) {
			return nil, errors.New("registry CA does not contain a PEM certificate")
		}
	}
	return &Client{
		target: target,
		creds: Credentials{
			Username: credentials.Username,
			Password: credentials.Password.Clone(),
			CACert:   append([]byte(nil), credentials.CACert...),
		},
		rootCAs: rootCAs,
		clients: make(map[string]*auth.Client, 8),
	}, nil
}

// Clear releases the registry client's owned credential bytes and cached
// authentication holders after the final network handoff.
func (client *Client) Clear() {
	if client == nil {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.creds.Clear()
	for registry, configured := range client.clients {
		if configured != nil {
			configured.Credential = func(context.Context, string) (auth.Credential, error) {
				return auth.EmptyCredential, nil
			}
			if configured.Client != nil {
				configured.Client.CloseIdleConnections()
			}
		}
		delete(client.clients, registry)
	}
	client.rootCAs = nil
}

func (client *Client) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	parsed, repository, err := client.repository(reference)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	descriptor, err := repository.Resolve(ctx, parsed.Identifier)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("resolve %s: %w", reference, err)
	}
	return descriptor, nil
}

func (client *Client) ValidateLinuxAMD64(ctx context.Context, reference string, descriptor ocispec.Descriptor) error {
	_, repository, err := client.repository(reference)
	if err != nil {
		return err
	}
	if err := ValidateLinuxAMD64(ctx, repository, descriptor); err != nil {
		return fmt.Errorf("validate %s: %w", reference, err)
	}
	return nil
}

func (client *Client) ValidateLinuxAMD64Manifest(ctx context.Context, reference string, descriptor ocispec.Descriptor) error {
	_, repository, err := client.repository(reference)
	if err != nil {
		return err
	}
	if err := ValidateLinuxAMD64Manifest(ctx, repository, descriptor); err != nil {
		return fmt.Errorf("validate %s: %w", reference, err)
	}
	return nil
}

// ValidateHelmChart proves that a registry manifest contains the one exact
// checksum-pinned Helm archive Atum selected. It validates only bounded OCI
// metadata; the content-addressed chart layer itself need not be downloaded a
// second time merely to establish the same SHA-256 and size.
func (client *Client) ValidateHelmChart(
	ctx context.Context,
	reference string,
	descriptor ocispec.Descriptor,
	archiveSHA256 string,
	archiveSize int64,
) error {
	if descriptor.MediaType != ocispec.MediaTypeImageManifest &&
		descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return fmt.Errorf("chart %s resolves to unsupported media type %s", reference, descriptor.MediaType)
	}
	if archiveSize <= 0 {
		return fmt.Errorf("chart %s has invalid archive size %d", reference, archiveSize)
	}
	wanted := digest.NewDigestFromEncoded(digest.SHA256, archiveSHA256)
	if err := wanted.Validate(); err != nil {
		return fmt.Errorf("chart %s archive digest is invalid: %w", reference, err)
	}
	_, repository, err := client.repository(reference)
	if err != nil {
		return err
	}
	data, err := fetchBounded(ctx, repository, descriptor)
	if err != nil {
		return fmt.Errorf("read chart manifest %s: %w", reference, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("decode chart manifest %s: %w", reference, err)
	}
	if manifest.SchemaVersion != 2 {
		return fmt.Errorf("chart %s has manifest schema version %d", reference, manifest.SchemaVersion)
	}
	if manifest.Config.MediaType != "application/vnd.cncf.helm.config.v1+json" {
		return fmt.Errorf("chart %s has config media type %s", reference, manifest.Config.MediaType)
	}
	if _, err := fetchBounded(ctx, repository, manifest.Config); err != nil {
		return fmt.Errorf("read chart config %s: %w", reference, err)
	}
	if len(manifest.Layers) != 1 {
		return fmt.Errorf("chart %s contains %d layers, want one", reference, len(manifest.Layers))
	}
	layer := manifest.Layers[0]
	if layer.MediaType != "application/vnd.cncf.helm.chart.content.v1.tar+gzip" ||
		layer.Digest != wanted || layer.Size != archiveSize {
		return fmt.Errorf("chart %s layer is %s/%s/%d, want exact Helm archive %s/%d",
			reference, layer.MediaType, layer.Digest, layer.Size, wanted, archiveSize)
	}
	exists, err := repository.Exists(ctx, layer)
	if err != nil {
		return fmt.Errorf("inspect chart layer %s: %w", reference, err)
	}
	if !exists {
		return fmt.Errorf("chart %s is missing its exact archive layer %s", reference, layer.Digest)
	}
	return nil
}

// Mirror copies one exact linux/amd64 source manifest into the configured
// target tag. The declarative updater resolves tags to platform manifests, so
// a multi-platform index is never accepted as the pinned source digest.
func (client *Client) Mirror(ctx context.Context, source string, digest string, target string) (ocispec.Descriptor, error) {
	sourceReference, sourceRepository, err := client.repository(source)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	targetReference, targetRepository, err := client.repository(target)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if targetReference.Registry != client.target.Host {
		return ocispec.Descriptor{}, fmt.Errorf("mirror destination %s is outside %s", target, client.target.Host)
	}
	options := oras.DefaultCopyOptions
	options.CopyGraphOptions.Concurrency = copyConcurrency
	options.CopyGraphOptions.MaxMetadataBytes = metadataLimit
	options.WithTargetPlatform(&ocispec.Platform{OS: "linux", Architecture: "amd64"})
	descriptor, err := oras.Copy(ctx, sourceRepository, digest, targetRepository, targetReference.Identifier, options)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("mirror %s@%s to %s: %w", sourceReference.RepositoryName(), digest, target, err)
	}
	if descriptor.Digest.String() != digest {
		return ocispec.Descriptor{}, fmt.Errorf("mirror %s produced %s, want %s", target, descriptor.Digest, digest)
	}
	return descriptor, nil
}

func (client *Client) CopyToStore(
	ctx context.Context,
	source string,
	digest string,
	target oras.Target,
	tag string,
) (ocispec.Descriptor, error) {
	_, repository, err := client.repository(source)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	options := oras.DefaultCopyOptions
	options.CopyGraphOptions.Concurrency = copyConcurrency
	options.CopyGraphOptions.MaxMetadataBytes = metadataLimit
	descriptor, err := oras.Copy(ctx, repository, digest, target, tag, options)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("copy %s@%s into OCI layout: %w", source, digest, err)
	}
	if descriptor.Digest.String() != digest {
		return ocispec.Descriptor{}, fmt.Errorf("OCI layout copied %s for %s, want %s", descriptor.Digest, source, digest)
	}
	return descriptor, nil
}

func (client *Client) CopyFromStore(
	ctx context.Context,
	source oras.ReadOnlyTarget,
	digest string,
	target string,
) (ocispec.Descriptor, error) {
	targetReference, repository, err := client.repository(target)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if targetReference.Registry != client.target.Host {
		return ocispec.Descriptor{}, fmt.Errorf("build destination %s is outside %s", target, client.target.Host)
	}
	options := oras.DefaultCopyOptions
	options.CopyGraphOptions.Concurrency = copyConcurrency
	options.CopyGraphOptions.MaxMetadataBytes = metadataLimit
	descriptor, err := oras.Copy(ctx, source, digest, repository, targetReference.Identifier, options)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("publish OCI layout to %s: %w", target, err)
	}
	if descriptor.Digest.String() != digest {
		return ocispec.Descriptor{}, fmt.Errorf("publish %s produced %s, want %s", target, descriptor.Digest, digest)
	}
	return descriptor, nil
}

// CopyTargetToStore copies an exact graph from an already-open content target
// into another target. It is used for local build outputs so publication
// never needs to round-trip those bytes through a registry.
func CopyTargetToStore(
	ctx context.Context,
	source oras.ReadOnlyTarget,
	digest string,
	target oras.Target,
	tag string,
) (ocispec.Descriptor, error) {
	options := oras.DefaultCopyOptions
	options.CopyGraphOptions.Concurrency = copyConcurrency
	options.CopyGraphOptions.MaxMetadataBytes = metadataLimit
	descriptor, err := oras.Copy(ctx, source, digest, target, tag, options)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("copy OCI graph %s as %s: %w", digest, tag, err)
	}
	if descriptor.Digest.String() != digest {
		return ocispec.Descriptor{}, fmt.Errorf("OCI graph %s copied as %s", digest, descriptor.Digest)
	}
	return descriptor, nil
}

func (client *Client) repository(reference string) (Reference, *remote.Repository, error) {
	parsed, err := ParseReference(reference)
	if err != nil {
		return Reference{}, nil, err
	}
	repository, err := remote.NewRepository(parsed.RepositoryName())
	if err != nil {
		return Reference{}, nil, fmt.Errorf("open OCI repository %s: %w", parsed.RepositoryName(), err)
	}
	repository.TagListPageSize = 100
	repository.TagListMaxPages = 100
	repository.MaxMetadataBytes = metadataLimit
	repository.PlainHTTP = parsed.Registry == client.target.Host && !client.target.TLSVerify
	repository.Client = client.authClient(parsed.Registry)
	return parsed, repository, nil
}

func (client *Client) authClient(registry string) *auth.Client {
	client.mu.Lock()
	defer client.mu.Unlock()
	if existing := client.clients[registry]; existing != nil {
		return existing
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = 90 * time.Second
	if registry == client.target.Host && client.target.TLSVerify {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if client.rootCAs != nil {
			tlsConfig.RootCAs = client.rootCAs
		}
		transport.TLSClientConfig = tlsConfig
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   transferTimeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("registry redirect chain exceeds 10 requests")
			}
			plainTarget := !client.target.TLSVerify && request.URL.Scheme == "http" &&
				request.URL.Host == client.target.Host
			if request.URL.Scheme != "https" && !plainTarget {
				return fmt.Errorf("refuse registry redirect to %s", request.URL)
			}
			return nil
		},
	}
	credentials := auth.CredentialFunc(func(context.Context, string) (auth.Credential, error) {
		return auth.EmptyCredential, nil
	})
	if registry == client.target.Host && client.creds.Username != "" {
		password := string(client.creds.Password.Bytes())
		credentials = auth.StaticCredential(registry, auth.Credential{
			Username: client.creds.Username,
			Password: password,
		})
		password = ""
	}
	configured := &auth.Client{
		Client:     httpClient,
		Cache:      auth.NewCache(),
		Credential: credentials,
		Header:     http.Header{"User-Agent": {"atum"}},
	}
	client.clients[registry] = configured
	return configured
}
