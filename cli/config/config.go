package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"atum/cli/fssecure"
	"atum/cli/treehash"

	"github.com/Masterminds/semver/v3"
	"github.com/huandu/xstrings"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	DesiredFilename = "atum.json"
	LockFilename    = "atum.lock.json"
	desiredSchema   = "atum.dev/config/v1"
	lockSchema      = "atum.dev/lock/v1"
	desiredSchemaID = "https://atum.dev/schema/config/v1"
	lockSchemaID    = "https://atum.dev/schema/lock/v1"
)

type Project struct {
	Root           string
	DesiredPath    string
	LockPath       string
	DesiredSHA256  string
	DeliverySHA256 string
	DesiredData    []byte
	LockData       []byte
	Desired        Document
	Lock           Lock
}

type LoadOptions struct {
	AllowStale bool
}

type CandidateFile struct {
	Data   []byte
	Mode   os.FileMode
	Exists bool
}

type CandidateFiles struct {
	Files               map[string]CandidateFile
	CompleteDirectories map[string]struct{}
}

type Document struct {
	Schema         string         `json:"$schema"`
	SchemaVersion  string         `json:"schemaVersion"`
	Project        ProjectConfig  `json:"project"`
	Updates        UpdatePolicy   `json:"updates"`
	Infrastructure Infrastructure `json:"infrastructure"`
	Orchestration  Orchestration  `json:"orchestration"`
	Platform       Platform       `json:"platform"`
	Secrets        Secrets        `json:"secrets"`
	Delivery       Delivery       `json:"delivery"`
}

type UpdatePolicy struct {
	Parallelism int  `json:"parallelism"`
	StableOnly  bool `json:"stableOnly"`
}

type ProjectConfig struct {
	Name     string `json:"name"`
	Cluster  string `json:"cluster"`
	Platform string `json:"platform"`
}

type Infrastructure struct {
	Active  string                          `json:"active"`
	Targets map[string]InfrastructureTarget `json:"targets"`
}

type InfrastructureTarget struct {
	Driver          string       `json:"driver"`
	Directory       string       `json:"directory"`
	AutoApprove     bool         `json:"autoApprove"`
	PlatformProfile string       `json:"platformProfile"`
	LocalAccess     *LocalAccess `json:"localAccess,omitempty"`
}

const MaxPassthroughHosts = 32

type LocalAccess struct {
	Domain                string   `json:"domain"`
	DNSServer             string   `json:"dnsServer"`
	PublicIngressVIP      string   `json:"publicIngressVIP"`
	PassthroughIngressVIP string   `json:"passthroughIngressVIP"`
	LoadBalancerRange     string   `json:"loadBalancerRange"`
	PassthroughHosts      []string `json:"passthroughHosts"`
}

type Orchestration struct {
	Directory        string           `json:"directory"`
	Inventory        string           `json:"inventory"`
	AnsibleUser      string           `json:"ansibleUser"`
	Forks            int              `json:"forks"`
	AutomaticUpgrade bool             `json:"automaticUpgrade"`
	Releases         []ClusterRelease `json:"releases"`
}

type ClusterRelease struct {
	Kubernetes string              `json:"kubernetes"`
	Kubespray  GitSource           `json:"kubespray"`
	Checksums  KubernetesChecksums `json:"checksums"`
}

func (orchestration Orchestration) TargetRelease() (ClusterRelease, error) {
	if len(orchestration.Releases) == 0 {
		return ClusterRelease{}, errors.New("orchestration release ladder is empty")
	}
	return orchestration.Releases[len(orchestration.Releases)-1], nil
}

type GitSource struct {
	URL         string   `json:"url"`
	Version     string   `json:"version"`
	Ref         string   `json:"ref,omitempty"`
	Branch      string   `json:"branch,omitempty"`
	Commit      string   `json:"commit"`
	Patches     []string `json:"patches,omitempty"`
	KubeVersion string   `json:"kubeVersion,omitempty"`
	Assets      []Asset  `json:"assets,omitempty"`
}

type Asset struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	File         string `json:"file"`
	SourceSHA256 string `json:"sourceSha256"`
	SHA256       string `json:"sha256"`
}

type Platform struct {
	Directory        string          `json:"directory"`
	Sources          SourceRegistry  `json:"sources"`
	PackageSelection string          `json:"packageSelection"`
	BigBang          GitSource       `json:"bigBang"`
	Flux             GitSource       `json:"flux"`
	Packages         []Package       `json:"packages"`
	Charts           []TrackedChart  `json:"charts"`
	Vendors          []Vendor        `json:"vendors"`
	Values           PlatformValues  `json:"values"`
	Bootstrap        BootstrapCharts `json:"bootstrap"`
}

type SourceRegistry struct {
	ExternalURL          string `json:"externalUrl"`
	ClusterURL           string `json:"clusterUrl"`
	Organization         string `json:"organization"`
	Repository           string `json:"repository"`
	UpstreamOrganization string `json:"upstreamOrganization"`
}

type Package struct {
	ID         string    `json:"id"`
	ValuesPath string    `json:"valuesPath"`
	License    string    `json:"license"`
	Source     GitSource `json:"source"`
}

type TrackedChart struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	ValuesPath    string      `json:"valuesPath"`
	FluxSource    string      `json:"fluxSource"`
	Version       string      `json:"version"`
	AppVersion    string      `json:"appVersion"`
	License       string      `json:"license"`
	KubeVersion   string      `json:"kubeVersion,omitempty"`
	Source        ChartSource `json:"source"`
	ArchiveSHA256 string      `json:"archiveSha256"`
}

type Vendor struct {
	ID         string    `json:"id"`
	Owner      string    `json:"owner"`
	Directory  string    `json:"directory"`
	Source     GitSource `json:"source"`
	Subpath    string    `json:"subpath"`
	Patches    []string  `json:"patches"`
	TreeSHA256 string    `json:"treeSha256"`
}

type PlatformValues struct {
	Operational string            `json:"operational"`
	Generated   string            `json:"generated"`
	Profiles    map[string]string `json:"profiles"`
}

// SortedProfileNames returns profile map keys in their deterministic rendering
// and hashing order.
func (values PlatformValues) SortedProfileNames() []string {
	names := make([]string, 0, len(values.Profiles))
	for name := range values.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type BootstrapCharts struct {
	SchemaVersion string   `json:"schemaVersion"`
	Registry      Registry `json:"registry"`
	ImmutableTags bool     `json:"immutableTags"`
	Charts        []Chart  `json:"charts"`
}

type Chart struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	Version       string              `json:"version"`
	AppVersion    string              `json:"appVersion"`
	ImageBindings []ChartImageBinding `json:"imageBindings"`
	KubeVersion   string              `json:"kubeVersion,omitempty"`
	License       string              `json:"license"`
	Source        ChartSource         `json:"source"`
	Values        string              `json:"values"`
	FluxSource    string              `json:"fluxSource"`
	File          string              `json:"file"`
	ArchiveSHA256 string              `json:"archiveSha256"`
	Target        string              `json:"target"`
	Profiles      []string            `json:"profiles,omitempty"`
}

type ChartImageBinding struct {
	ID              string `json:"id"`
	ValuesPath      string `json:"valuesPath"`
	ImageRepository string `json:"imageRepository,omitempty"`
	TagSuffix       string `json:"tagSuffix,omitempty"`
}

type ChartSource struct {
	Type     string `json:"type"`
	URL      string `json:"url"`
	IndexURL string `json:"indexUrl,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

// ActiveTarget returns the single target selected by the desired state.
func (d Document) ActiveTarget() (InfrastructureTarget, bool) {
	target, exists := d.Infrastructure.Targets[d.Infrastructure.Active]
	return target, exists
}

// ActiveProfileValuesPath returns the target-profile values path selected by
// the active infrastructure target.
func (d Document) ActiveProfileValuesPath() (string, bool) {
	target, exists := d.ActiveTarget()
	if !exists {
		return "", false
	}
	path, exists := d.Platform.Values.Profiles[target.PlatformProfile]
	return path, exists
}

// ActiveBootstrapCharts returns the bootstrap charts reconciled by the active
// profile. Charts without an explicit profile remain global. Validated profile
// slices are sorted, allowing allocation-free membership checks.
func (d Document) ActiveBootstrapCharts() []Chart {
	target, exists := d.ActiveTarget()
	if !exists {
		return nil
	}
	charts := d.Platform.Bootstrap.Charts
	activeCount := 0
	for i := range charts {
		if charts[i].activeForProfile(target.PlatformProfile) {
			activeCount++
		}
	}
	if activeCount == len(charts) {
		return charts
	}
	active := make([]Chart, 0, activeCount)
	for i := range charts {
		if charts[i].activeForProfile(target.PlatformProfile) {
			active = append(active, charts[i])
		}
	}
	return active
}

func (chart Chart) activeForProfile(profile string) bool {
	if len(chart.Profiles) == 0 {
		return true
	}
	_, exists := slices.BinarySearch(chart.Profiles, profile)
	return exists
}

type Secrets struct {
	SOPSFile  string `json:"sopsFile"`
	LocalFile string `json:"localFile"`
}

type Delivery struct {
	Registry         Registry           `json:"registry"`
	Seed             SeedPlane          `json:"seed"`
	Profiles         map[string]Profile `json:"profiles"`
	Policy           DeliveryPolicy     `json:"policy"`
	Images           []Image            `json:"images"`
	RenderedBaseline RenderedBaseline   `json:"renderedBaseline"`
	LegacyCrosswalk  LegacyCrosswalk    `json:"legacyCrosswalk"`
}

type SeedPlane struct {
	Forgejo SeedForgejo `json:"forgejo"`
	Harbor  SeedHarbor  `json:"harbor"`
}

type SeedForgejo struct {
	URL   string    `json:"url"`
	Image SeedImage `json:"image"`
}

type SeedHarbor struct {
	URL       string      `json:"url"`
	Version   string      `json:"version"`
	Installer SeedAsset   `json:"installer"`
	Images    []SeedImage `json:"images"`
}

type SeedAsset struct {
	URL    string `json:"url"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type SeedImage struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Digest string `json:"digest"`
}

type Registry struct {
	Host      string `json:"host"`
	Project   string `json:"project"`
	TLSVerify bool   `json:"tlsVerify"`
}

type Profile struct {
	Description       string `json:"description"`
	PreferSourceBuild bool   `json:"preferSourceBuild"`
}

type DeliveryPolicy struct {
	DefaultProfile            string   `json:"defaultProfile"`
	BuildBase                 string   `json:"buildBase"`
	BuildParallelism          int      `json:"buildParallelism"`
	DebianSnapshot            string   `json:"debianSnapshot"`
	ForbiddenArtifactPrefixes []string `json:"forbiddenArtifactPrefixes"`
	RuntimeRegistryPrefix     string   `json:"runtimeRegistryPrefix"`
	MutableTagsForbidden      bool     `json:"mutableTagsForbidden"`
	MirrorDigestRequired      bool     `json:"mirrorDigestRequired"`
}

type Image struct {
	ID             string               `json:"id"`
	Family         string               `json:"family"`
	Version        string               `json:"version"`
	Target         string               `json:"target"`
	Scopes         []string             `json:"scopes"`
	Runtime        bool                 `json:"runtime"`
	License        string               `json:"license"`
	Consumers      []string             `json:"consumers"`
	BigBangRefs    []string             `json:"bigBangRefs"`
	VersionMapping *ImageVersionMapping `json:"versionMapping,omitempty"`
	Delivery       ImageDelivery        `json:"delivery"`
}

type ImageVersionMapping struct {
	Artifact          string                    `json:"artifact"`
	Source            string                    `json:"source"`
	UpstreamTagPrefix string                    `json:"upstreamTagPrefix,omitempty"`
	TagPrefix         string                    `json:"tagPrefix,omitempty"`
	TagSuffix         string                    `json:"tagSuffix,omitempty"`
	Build             *ImageBuildVersionMapping `json:"build,omitempty"`
}

type ImageBuildVersionMapping struct {
	ImageRepository string `json:"imageRepository,omitempty"`
	ImageTagPrefix  string `json:"imageTagPrefix,omitempty"`
	BakeContext     string `json:"bakeContext,omitempty"`
	GitURL          string `json:"gitUrl"`
	GitTagPrefix    string `json:"gitTagPrefix,omitempty"`
	GitContext      string `json:"gitContext"`
	FullTagSuffix   string `json:"fullTagSuffix"`
}

type ImageDelivery struct {
	Default         DeliveryChoice `json:"default"`
	FullBuildTarget string         `json:"fullBuildTarget,omitempty"`
}

type DeliveryChoice struct {
	Type       string   `json:"type"`
	Source     string   `json:"source,omitempty"`
	Digest     string   `json:"digest,omitempty"`
	BakeTarget string   `json:"bakeTarget,omitempty"`
	Materials  []string `json:"materials,omitempty"`
}

type VersionedCommit struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type ScopeCounts struct {
	Prep    int `json:"prep"`
	BigBang int `json:"bigbang"`
	Unique  int `json:"unique"`
}

type DeliveryCounts struct {
	Total    int `json:"total"`
	Mirrored int `json:"mirrored"`
	Built    int `json:"built"`
}

type RenderedBaseline struct {
	SchemaVersion string                  `json:"schemaVersion"`
	BigBang       VersionedCommit         `json:"bigBang"`
	Counts        ScopeCounts             `json:"counts"`
	Normalization string                  `json:"normalization"`
	Entries       []RenderedBaselineEntry `json:"entries"`
}

type RenderedBaselineEntry struct {
	ImageID  string   `json:"imageId"`
	Target   string   `json:"target"`
	Scopes   []string `json:"scopes"`
	Evidence string   `json:"evidence"`
}

type LegacyCrosswalk struct {
	SchemaVersion       string                 `json:"schemaVersion"`
	BigBang             VersionedCommit        `json:"bigBang"`
	Strategy            string                 `json:"strategy"`
	DefaultCounts       DeliveryCounts         `json:"defaultCounts"`
	CompatibilityBuilds []string               `json:"compatibilityBuilds"`
	Entries             []LegacyCrosswalkEntry `json:"entries"`
}

type LegacyCrosswalkEntry struct {
	ImageID            string              `json:"imageId"`
	Family             string              `json:"family"`
	Scopes             []string            `json:"scopes"`
	Consumers          []string            `json:"consumers"`
	BigBangRefs        []string            `json:"bigBangRefs"`
	Replacement        string              `json:"replacement"`
	DefaultDelivery    string              `json:"defaultDelivery"`
	OfficialSource     *OfficialSource     `json:"officialSource,omitempty"`
	CompatibilityBuild *CompatibilityBuild `json:"compatibilityBuild,omitempty"`
}

type OfficialSource struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

type CompatibilityBuild struct {
	BakeTarget string   `json:"bakeTarget"`
	Materials  []string `json:"materials"`
}

type Lock struct {
	Schema        string        `json:"$schema"`
	SchemaVersion string        `json:"schemaVersion"`
	DesiredSHA256 string        `json:"desiredSha256"`
	Resolved      Resolved      `json:"resolved"`
	Compatibility Compatibility `json:"compatibility"`
	Delivery      ImageLock     `json:"delivery"`
	Bundle        *Bundle       `json:"bundle"`
}

type Resolved struct {
	ClusterReleases []ClusterRelease `json:"clusterReleases"`
	BigBang         GitSource        `json:"bigBang"`
	Flux            GitSource        `json:"flux"`
	Packages        []Package        `json:"packages"`
	SupportSources  []SupportSource  `json:"supportSources,omitempty"`
	Charts          []TrackedChart   `json:"charts"`
	Vendors         []Vendor         `json:"vendors"`
	Bootstrap       BootstrapCharts  `json:"bootstrap"`
}

// SupportSource is an immutable source selected transitively by an upstream
// platform release. It is resolved state, never independently desired state.
type SupportSource struct {
	ID         string    `json:"id"`
	ValuesPath string    `json:"valuesPath"`
	ChartPath  string    `json:"chartPath"`
	Source     GitSource `json:"source"`
}

// WrapperConsumer is the canonical projection of one declared dependency that
// asks Big Bang to protect its namespace with the shared wrapper chart.
type WrapperConsumer struct {
	OwnerID     string
	ValuesPath  string
	PackageKey  string
	ReleaseName string
	Namespace   string
}

// RepositorySource is the canonical inventory of repositories published to
// the deployment source plane. CacheKey is local-only and is not serialized.
type RepositorySource struct {
	ID       string
	CacheKey string
	Source   GitSource
}

func RepositoryInventory(desired Document, resolved Resolved) ([]RepositorySource, error) {
	inventory := make([]RepositorySource, 0, 2+len(desired.Platform.Packages)+len(resolved.SupportSources))
	inventory = append(inventory,
		RepositorySource{ID: "bigbang", CacheKey: "bigbang", Source: desired.Platform.BigBang},
		RepositorySource{ID: "flux", CacheKey: "flux", Source: desired.Platform.Flux},
	)
	for _, pkg := range desired.Platform.Packages {
		inventory = append(inventory, RepositorySource{
			ID: pkg.ID, CacheKey: "package-" + pkg.ID, Source: pkg.Source,
		})
	}
	for _, support := range resolved.SupportSources {
		inventory = append(inventory, RepositorySource{
			ID: support.ID, CacheKey: "support-" + support.ID, Source: support.Source,
		})
	}
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].ID < inventory[j].ID })
	for i := range inventory {
		if !validResourceID(inventory[i].ID) {
			return nil, fmt.Errorf("repository source id %q is invalid", inventory[i].ID)
		}
		if i > 0 && inventory[i-1].ID == inventory[i].ID {
			return nil, fmt.Errorf("repository source id %q is duplicated", inventory[i].ID)
		}
	}
	return inventory, nil
}

type Compatibility struct {
	KubernetesVersion string                    `json:"kubernetesVersion"`
	BigBangConstraint string                    `json:"bigBangConstraint"`
	Status            string                    `json:"status"`
	Constraints       []CompatibilityConstraint `json:"constraints"`
	Checksums         KubernetesChecksums       `json:"checksums"`
}

type CompatibilityConstraint struct {
	ID         string `json:"id"`
	Constraint string `json:"constraint"`
}

type KubernetesChecksums struct {
	Kubelet string `json:"kubelet"`
	Kubeadm string `json:"kubeadm"`
	Kubectl string `json:"kubectl"`
}

type ImageLock struct {
	SchemaVersion   string         `json:"schemaVersion"`
	Profile         string         `json:"profile"`
	Platform        string         `json:"platform"`
	InventorySHA256 string         `json:"inventorySha256"`
	GraphSHA256     string         `json:"graphSha256"`
	Counts          DeliveryCounts `json:"counts"`
	Images          []LockedImage  `json:"images"`
}

// Pending reports whether upstream resolution has intentionally invalidated
// all prior delivery results. An empty image set is unambiguous because every
// supported Atum profile has a non-empty desired runtime inventory.
func (lock ImageLock) Pending() bool {
	return len(lock.Images) == 0
}

type LockedImage struct {
	ID          string         `json:"id"`
	Target      string         `json:"target"`
	Digest      string         `json:"digest"`
	InputSHA256 string         `json:"inputSha256"`
	Delivery    LockedDelivery `json:"delivery"`
}

type LockedDelivery struct {
	Type          string   `json:"type"`
	Source        string   `json:"source,omitempty"`
	Digest        string   `json:"digest,omitempty"`
	BakeTarget    string   `json:"bakeTarget,omitempty"`
	Materials     []string `json:"materials,omitempty"`
	SourceProfile string   `json:"sourceProfile"`
}

type Bundle struct {
	File             string `json:"file"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	AtumSourceSHA256 string `json:"atumSourceSha256"`
	OCIReference     string `json:"ociReference,omitempty"`
	OCIDigest        string `json:"ociDigest,omitempty"`
}

type LegacyBaseline struct {
	BigBangVersion string `json:"bigBangVersion"`
	BigBangCommit  string `json:"bigBangCommit"`
	FluxVersion    string `json:"fluxVersion"`
	Platform       string `json:"platform"`
}

type LegacyImagesDocument struct {
	SchemaVersion string             `json:"schemaVersion"`
	Baseline      LegacyBaseline     `json:"baseline"`
	Registry      Registry           `json:"registry"`
	Seed          SeedPlane          `json:"seed"`
	Profiles      map[string]Profile `json:"profiles"`
	Policy        DeliveryPolicy     `json:"policy"`
	Images        []Image            `json:"images"`
}

func (d Document) LegacyImages() LegacyImagesDocument {
	return LegacyImagesDocument{
		SchemaVersion: "atum.dev/images/v3",
		Baseline: LegacyBaseline{
			BigBangVersion: d.Platform.BigBang.Version,
			BigBangCommit:  d.Platform.BigBang.Commit,
			FluxVersion:    d.Platform.Flux.Version,
			Platform:       d.Project.Platform,
		},
		Registry: d.Delivery.Registry,
		Seed:     d.Delivery.Seed,
		Profiles: d.Delivery.Profiles,
		Policy:   d.Delivery.Policy,
		Images:   d.Delivery.Images,
	}
}

func (d Document) DeliverySHA256() (string, error) {
	data, err := canonicalJSON(d.LegacyImages())
	if err != nil {
		return "", err
	}
	return SHA256(data), nil
}

func (d Document) DesiredSHA256() (string, error) {
	data, err := canonicalJSON(d)
	if err != nil {
		return "", err
	}
	return SHA256(data), nil
}

func (d Document) ImageInputSHA256(image Image, delivery LockedDelivery, graphSHA256 string) (string, error) {
	material := struct {
		ID               string         `json:"id"`
		Version          string         `json:"version"`
		Target           string         `json:"target"`
		ResolvedDelivery LockedDelivery `json:"resolvedDelivery"`
	}{
		ID:               image.ID,
		Version:          image.Version,
		Target:           image.Target,
		ResolvedDelivery: delivery,
	}
	encoded, err := CanonicalJSON(material)
	if err != nil {
		return "", err
	}
	switch delivery.Type {
	case "mirror":
		return SHA256(encoded), nil
	case "build":
		if !validHexSHA256(graphSHA256) {
			return "", errors.New("build input requires a valid graph hash")
		}
		hash := sha256.New()
		_, _ = hash.Write([]byte(graphSHA256))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(encoded)
		return hex.EncodeToString(hash.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported delivery type %q", delivery.Type)
	}
}

func canonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return canonical.Bytes(), nil
}

// CanonicalJSON returns the same recursively key-sorted JSON representation
// used by the declarative delivery identity, without a trailing newline. It is
// exported for lock material whose existing shell contract hashes command
// substitution output rather than a JSON stream.
func CanonicalJSON(value any) ([]byte, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(data, []byte{'\n'}), nil
}

func Load(rootHint string) (*Project, error) {
	return LoadWithOptions(rootHint, LoadOptions{})
}

func LoadWithOptions(rootHint string, options LoadOptions) (*Project, error) {
	root, err := Discover(rootHint)
	if err != nil {
		return nil, err
	}
	desiredPath, err := fssecure.Resolve(root, DesiredFilename, false)
	if err != nil {
		return nil, fmt.Errorf("resolve desired state: %w", err)
	}
	desiredData, err := os.ReadFile(desiredPath)
	if err != nil {
		return nil, fmt.Errorf("read desired state: %w", err)
	}
	lockPath, err := fssecure.Resolve(root, LockFilename, false)
	if err != nil {
		return nil, fmt.Errorf("resolve resolved state: %w", err)
	}
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read resolved state: %w", err)
	}
	if err := validateSchemas(root, desiredData, lockData); err != nil {
		return nil, err
	}
	var desired Document
	if err := DecodeJSON(desiredData, &desired); err != nil {
		return nil, fmt.Errorf("decode %s: %w", DesiredFilename, err)
	}
	desiredIdentity, err := desired.DesiredSHA256()
	if err != nil {
		return nil, fmt.Errorf("resolve desired state identity: %w", err)
	}
	deliveryIdentity, err := desired.DeliverySHA256()
	if err != nil {
		return nil, fmt.Errorf("resolve desired delivery identity: %w", err)
	}

	var lock Lock
	if err := DecodeJSON(lockData, &lock); err != nil {
		return nil, fmt.Errorf("decode %s: %w", LockFilename, err)
	}

	project := &Project{
		Root:           root,
		DesiredPath:    desiredPath,
		LockPath:       lockPath,
		DesiredSHA256:  desiredIdentity,
		DeliverySHA256: deliveryIdentity,
		DesiredData:    append([]byte(nil), desiredData...),
		LockData:       append([]byte(nil), lockData...),
		Desired:        desired,
		Lock:           lock,
	}
	if err := project.validate(options.AllowStale, nil); err != nil {
		return nil, err
	}
	return project, nil
}

func ValidateCandidate(root string, desired Document, lock Lock, candidate CandidateFiles) (*Project, []byte, []byte, error) {
	desiredData, err := MarshalJSON(desired)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode desired state: %w", err)
	}
	lockData, err := MarshalJSON(lock)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode resolved state: %w", err)
	}
	if err := validateSchemas(root, desiredData, lockData); err != nil {
		return nil, nil, nil, err
	}
	identity, err := desired.DesiredSHA256()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve desired state identity: %w", err)
	}
	deliveryIdentity, err := desired.DeliverySHA256()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve desired delivery identity: %w", err)
	}
	project := &Project{
		Root:           root,
		DesiredPath:    filepath.Join(root, DesiredFilename),
		LockPath:       filepath.Join(root, LockFilename),
		DesiredSHA256:  identity,
		DeliverySHA256: deliveryIdentity,
		DesiredData:    append([]byte(nil), desiredData...),
		LockData:       append([]byte(nil), lockData...),
		Desired:        desired,
		Lock:           lock,
	}
	files := make(map[string][]byte, len(candidate.Files))
	for relative, file := range candidate.Files {
		if file.Exists {
			files[relative] = file.Data
		}
	}
	if err := project.validate(false, files); err != nil {
		return nil, nil, nil, err
	}
	if err := validateCandidateVendorTrees(desired.Platform.Vendors, candidate); err != nil {
		return nil, nil, nil, err
	}
	return project, desiredData, lockData, nil
}

func validateCandidateVendorTrees(vendors []Vendor, candidate CandidateFiles) error {
	for _, vendor := range vendors {
		directory := filepath.Clean(vendor.Directory)
		if _, complete := candidate.CompleteDirectories[directory]; !complete {
			return fmt.Errorf("candidate vendor %s directory %s is not a complete managed snapshot", vendor.ID, directory)
		}
		prefix := directory + string(filepath.Separator)
		files := make([]treehash.File, 0, 64)
		for relative, file := range candidate.Files {
			if !file.Exists || !strings.HasPrefix(filepath.Clean(relative), prefix) {
				continue
			}
			path := strings.TrimPrefix(filepath.Clean(relative), prefix)
			if path == "" || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
				return fmt.Errorf("candidate vendor %s contains invalid path %s", vendor.ID, relative)
			}
			files = append(files, treehash.File{
				Path: filepath.ToSlash(path),
				Mode: file.Mode,
				Data: file.Data,
			})
		}
		digest, err := treehash.Sum(files)
		if err != nil {
			return fmt.Errorf("hash candidate vendor %s: %w", vendor.ID, err)
		}
		if digest != vendor.TreeSHA256 {
			return fmt.Errorf("candidate vendor %s tree hash is %s, want %s", vendor.ID, digest, vendor.TreeSHA256)
		}
	}
	return nil
}

func MarshalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Discover(rootHint string) (string, error) {
	start := strings.TrimSpace(rootHint)
	explicit := start != ""
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("determine working directory: %w", err)
		}
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve project root %q: %w", start, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect project root %q: %w", start, err)
	}
	if !info.IsDir() {
		if filepath.Base(abs) != DesiredFilename {
			return "", fmt.Errorf("project root %q is not a directory or %s", start, DesiredFilename)
		}
		abs = filepath.Dir(abs)
	}
	if explicit {
		candidate := filepath.Join(abs, DesiredFilename)
		if desired, statErr := os.Stat(candidate); statErr != nil || !desired.Mode().IsRegular() {
			return "", fmt.Errorf("project root %s does not contain %s", abs, DesiredFilename)
		}
		return fssecure.Root(abs)
	}
	for dir := filepath.Clean(abs); ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, DesiredFilename)
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			return fssecure.Root(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return "", fmt.Errorf("find %s from %s", DesiredFilename, start)
}

func (p *Project) Validate() error {
	return p.validate(false, nil)
}

func (p *Project) validate(allowStale bool, files map[string][]byte) error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	if p.Desired.Schema != "./atum.schema.json" || p.Desired.SchemaVersion != desiredSchema {
		add("desired schema must be %s", desiredSchema)
	}
	if p.Lock.Schema != "./atum.lock.schema.json" || p.Lock.SchemaVersion != lockSchema {
		add("lock schema must be %s", lockSchema)
	}
	if !allowStale && p.Lock.DesiredSHA256 != p.DesiredSHA256 {
		add("%s is stale: desiredSha256 is %s, want %s", LockFilename, p.Lock.DesiredSHA256, p.DesiredSHA256)
	}
	if p.Desired.Project.Name == "" || p.Desired.Project.Cluster == "" {
		add("project name and cluster are required")
	}
	if p.Desired.Project.Platform != "linux/amd64" {
		add("project platform must be linux/amd64")
	}
	if p.Desired.Updates.Parallelism < 1 || p.Desired.Updates.Parallelism > 64 {
		add("update parallelism must be between 1 and 64")
	}
	if p.Desired.Delivery.Policy.BuildParallelism < 1 || p.Desired.Delivery.Policy.BuildParallelism > 64 {
		add("delivery build parallelism must be between 1 and 64")
	}
	if !p.Desired.Updates.StableOnly {
		add("update policy must reject prerelease sources")
	}
	activeTarget, ok := p.Desired.ActiveTarget()
	if !ok {
		add("infrastructure active target %q is not defined", p.Desired.Infrastructure.Active)
	} else if activeTarget.Driver != "terraform" {
		add("infrastructure target %q uses unsupported driver %q", p.Desired.Infrastructure.Active, activeTarget.Driver)
	}
	profileNames := p.Desired.Platform.Values.SortedProfileNames()
	if len(profileNames) == 0 {
		add("platform values must define at least one profile")
	}
	valuesPathOwners := make(map[string]string, len(profileNames)+2)
	if operationalPath, err := fssecure.Relative(p.Desired.Platform.Values.Operational); err == nil {
		valuesPathOwners[operationalPath] = "platform operational values"
	}
	if generatedPath, err := fssecure.Relative(p.Desired.Platform.Values.Generated); err == nil {
		if previous, duplicate := valuesPathOwners[generatedPath]; duplicate {
			add("platform generated values path %q aliases %s", generatedPath, previous)
		} else {
			valuesPathOwners[generatedPath] = "platform generated values"
		}
	}
	for _, name := range profileNames {
		valuesPath := p.Desired.Platform.Values.Profiles[name]
		if !validResourceID(name) {
			add("platform profile name %q is invalid", name)
		}
		validateRelative(&problems, "platform profile "+name+" values", valuesPath)
		normalizedPath, err := fssecure.Relative(valuesPath)
		if err != nil {
			continue
		}
		expectedPath := filepath.Join(p.Desired.Platform.Directory, "profiles", name, "prep", "values.yaml")
		if normalizedPath != filepath.Clean(expectedPath) {
			add("platform profile %s values path must be %q", name, filepath.ToSlash(expectedPath))
		}
		if previous, duplicate := valuesPathOwners[normalizedPath]; duplicate {
			add("platform profile %s values path %q aliases %s", name, normalizedPath, previous)
		} else {
			valuesPathOwners[normalizedPath] = "platform profile " + name
		}
	}
	targetNames := make([]string, 0, len(p.Desired.Infrastructure.Targets))
	for name := range p.Desired.Infrastructure.Targets {
		targetNames = append(targetNames, name)
	}
	sort.Strings(targetNames)
	for _, name := range targetNames {
		target := p.Desired.Infrastructure.Targets[name]
		validateRelative(&problems, "infrastructure target "+name+" directory", target.Directory)
		if path, err := fssecure.Resolve(p.Root, target.Directory, false); err != nil {
			add("infrastructure target %s directory is missing: %v", name, err)
		} else if info, err := os.Stat(path); err != nil || !info.IsDir() {
			add("infrastructure target %s path is not a directory", name)
		}
		if !validResourceID(target.PlatformProfile) {
			add("infrastructure target %s platform profile %q is invalid", name, target.PlatformProfile)
		} else if _, exists := p.Desired.Platform.Values.Profiles[target.PlatformProfile]; !exists {
			add("infrastructure target %s references unknown platform profile %q", name, target.PlatformProfile)
		}
		if target.PlatformProfile == "local" {
			if target.LocalAccess == nil {
				add("infrastructure target %s requires local access configuration", name)
			} else {
				validateLocalAccess(&problems, name, *target.LocalAccess)
			}
		} else if target.LocalAccess != nil {
			add("infrastructure target %s may define local access only for the local platform profile", name)
		}
	}
	validateRelative(&problems, "orchestration directory", p.Desired.Orchestration.Directory)
	validateRelative(&problems, "orchestration inventory", p.Desired.Orchestration.Inventory)
	validateAnsibleUser(&problems, p.Desired.Orchestration.AnsibleUser)
	if p.Desired.Orchestration.Forks < 2 || p.Desired.Orchestration.Forks > 64 {
		add("orchestration forks must be between 2 and 64")
	}
	validateRelative(&problems, "platform directory", p.Desired.Platform.Directory)
	validateSourceRegistry(&problems, p.Desired.Platform.Sources)
	validateRelative(&problems, "package selection", p.Desired.Platform.PackageSelection)
	validateRelative(&problems, "operational values", p.Desired.Platform.Values.Operational)
	validateRelative(&problems, "generated values", p.Desired.Platform.Values.Generated)
	validateRelative(&problems, "SOPS file", p.Desired.Secrets.SOPSFile)
	validateRelative(&problems, "local secrets file", p.Desired.Secrets.LocalFile)
	sopsFile := filepath.ToSlash(filepath.Clean(p.Desired.Secrets.SOPSFile))
	localFile := filepath.ToSlash(filepath.Clean(p.Desired.Secrets.LocalFile))
	if sopsFile == localFile {
		add("SOPS and local secrets files must be distinct")
	}
	if sopsFile == ".atum" || strings.HasPrefix(sopsFile, ".atum/") {
		add("SOPS file must be tracked outside .atum")
	}
	if !strings.HasPrefix(localFile, ".atum/") {
		add("local secrets file must remain beneath ignored .atum")
	}
	validateClusterReleases(&problems, p.Desired.Orchestration.Releases)
	validateGitSource(&problems, "Big Bang", p.Desired.Platform.BigBang)
	validateGitSource(&problems, "Flux", p.Desired.Platform.Flux)
	validatePackages(&problems, p.Desired.Platform.Packages)
	validateTrackedCharts(&problems, p.Desired.Platform.Charts)
	validateVendors(&problems, p.Desired.Platform.Vendors)
	selectedIDs := make(map[string]string, len(p.Desired.Platform.Packages)+len(p.Desired.Platform.Charts))
	selectedPaths := make(map[string]string, len(p.Desired.Platform.Packages)+len(p.Desired.Platform.Charts))
	for _, pkg := range p.Desired.Platform.Packages {
		selectedIDs[pkg.ID] = "package"
		selectedPaths[pkg.ValuesPath] = "package"
	}
	for _, chart := range p.Desired.Platform.Charts {
		if owner, exists := selectedIDs[chart.ID]; exists {
			add("platform chart id %q conflicts with a %s", chart.ID, owner)
		}
		if owner, exists := selectedPaths[chart.ValuesPath]; exists {
			add("platform chart values path %q conflicts with a %s", chart.ValuesPath, owner)
		}
		selectedIDs[chart.ID] = "chart"
		selectedPaths[chart.ValuesPath] = "chart"
	}
	if p.Desired.Platform.Bootstrap.SchemaVersion != "atum.dev/bootstrap-charts/v1" {
		add("bootstrap chart schema is unsupported")
	}
	if !p.Desired.Platform.Bootstrap.ImmutableTags {
		add("bootstrap chart registry must enforce immutable tags")
	}
	if p.Desired.Delivery.Registry.Host == "" || p.Desired.Delivery.Registry.Project != "atum" {
		add("delivery registry must identify the internal atum Harbor project")
	}
	if p.Desired.Platform.Bootstrap.Registry.Host != p.Desired.Delivery.Registry.Host ||
		p.Desired.Platform.Bootstrap.Registry.Project != "charts" ||
		p.Desired.Platform.Bootstrap.Registry.TLSVerify != p.Desired.Delivery.Registry.TLSVerify {
		add("bootstrap registry must identify the internal charts project on the delivery Harbor endpoint")
	}
	validateSeedPlane(&problems, p.Desired.Platform.Sources, p.Desired.Delivery.Registry, p.Desired.Delivery.Policy, p.Desired.Delivery.Seed)
	if p.Desired.Delivery.Policy.DefaultProfile != "platform" {
		add("delivery default profile must be platform")
	}
	if _, ok := p.Desired.Delivery.Profiles[p.Desired.Delivery.Policy.DefaultProfile]; !ok {
		add("delivery default profile %q is not defined", p.Desired.Delivery.Policy.DefaultProfile)
	}
	platformProfile, hasPlatform := p.Desired.Delivery.Profiles["platform"]
	fullBuildProfile, hasFullBuild := p.Desired.Delivery.Profiles["full-build"]
	if len(p.Desired.Delivery.Profiles) != 2 || !hasPlatform || !hasFullBuild ||
		platformProfile.PreferSourceBuild || !fullBuildProfile.PreferSourceBuild {
		add("delivery profiles must define platform mirrors and the full-build source option")
	}
	if !p.Desired.Delivery.Policy.MutableTagsForbidden || !p.Desired.Delivery.Policy.MirrorDigestRequired {
		add("delivery policy must forbid mutable tags and require mirror digests")
	}
	if !strings.HasSuffix(p.Desired.Delivery.Policy.RuntimeRegistryPrefix, "/") {
		add("delivery runtimeRegistryPrefix must end with a slash")
	}
	expectedRuntimePrefix := p.Desired.Delivery.Registry.Host + "/" + p.Desired.Delivery.Registry.Project + "/"
	if p.Desired.Delivery.Policy.RuntimeRegistryPrefix != expectedRuntimePrefix {
		add("delivery runtimeRegistryPrefix must be %q", expectedRuntimePrefix)
	}

	imageIDs := make(map[string]*Image, len(p.Desired.Delivery.Images))
	imageTargets := make(map[string]string, len(p.Desired.Delivery.Images))
	versionArtifacts := make(map[string]struct{}, 1+len(p.Desired.Platform.Packages)+len(p.Desired.Platform.Charts))
	versionArtifacts["bigbang"] = struct{}{}
	for i := range p.Desired.Platform.Packages {
		versionArtifacts["package/"+p.Desired.Platform.Packages[i].ID] = struct{}{}
	}
	for i := range p.Desired.Platform.Charts {
		versionArtifacts["chart/"+p.Desired.Platform.Charts[i].ID] = struct{}{}
	}
	for i := range p.Desired.Delivery.Images {
		image := &p.Desired.Delivery.Images[i]
		if !validResourceID(image.ID) || image.Target == "" || image.Version == "" {
			add("delivery image %d has an invalid id, version, or target", i)
			continue
		}
		if previous, exists := imageIDs[image.ID]; exists {
			add("delivery image id %q duplicates target %q", image.ID, previous.Target)
		}
		if previous, exists := imageTargets[image.Target]; exists {
			add("delivery target %q is shared by %s and %s", image.Target, previous, image.ID)
		}
		imageIDs[image.ID] = image
		imageTargets[image.Target] = image.ID
		if !strings.HasPrefix(image.Target, p.Desired.Delivery.Policy.RuntimeRegistryPrefix) {
			add("delivery image %s target is outside runtimeRegistryPrefix", image.ID)
		}
		if p.Desired.Delivery.Policy.MutableTagsForbidden && mutableImageReference(image.Target) {
			add("delivery image %s target uses a missing or mutable tag", image.ID)
		}
		seenScopes := make(map[string]struct{}, len(image.Scopes))
		for _, scope := range image.Scopes {
			if scope != "prep" && scope != "bigbang" && scope != "build-system" {
				add("delivery image %s uses unsupported scope %q", image.ID, scope)
			}
			if _, duplicate := seenScopes[scope]; duplicate {
				add("delivery image %s repeats scope %q", image.ID, scope)
			}
			seenScopes[scope] = struct{}{}
		}
		if mapping := image.VersionMapping; mapping != nil {
			_, artifactExists := versionArtifacts[mapping.Artifact]
			validAffixes := !strings.ContainsAny(mapping.UpstreamTagPrefix+mapping.TagPrefix+mapping.TagSuffix, ":@/")
			validMapping := artifactExists && validAffixes
			switch mapping.Source {
			case "chartAppVersion":
				validMapping = validMapping && mapping.TagSuffix == "" && image.Delivery.Default.Type == "mirror"
				if build := mapping.Build; build == nil {
					validMapping = validMapping && image.Delivery.FullBuildTarget == ""
				} else {
					validMapping = validMapping && image.Delivery.FullBuildTarget != "" &&
						build.ImageRepository != "" && build.BakeContext == "" &&
						build.GitURL != "" && build.GitContext != "" && build.FullTagSuffix != "" &&
						!strings.ContainsAny(build.ImageTagPrefix+build.GitTagPrefix+build.FullTagSuffix, ":@/")
				}
			case "upstreamImageTag":
				build := mapping.Build
				validMapping = validMapping && build != nil && image.Delivery.FullBuildTarget != "" &&
					build.GitURL != "" && build.GitContext != "" && build.FullTagSuffix != "" &&
					!strings.ContainsAny(build.ImageTagPrefix+build.GitTagPrefix+build.FullTagSuffix, ":@/")
				if image.Delivery.Default.Type == "build" {
					validMapping = validMapping && build.ImageRepository != "" && build.BakeContext != ""
				}
			default:
				validMapping = false
			}
			if !validMapping {
				add("delivery image %s has an invalid version mapping", image.ID)
			}
		}
		switch image.Delivery.Default.Type {
		case "mirror":
			if image.Delivery.Default.Source == "" || !validDigest(image.Delivery.Default.Digest) {
				add("delivery mirror %s requires source and sha256 digest", image.ID)
			}
			for _, prefix := range p.Desired.Delivery.Policy.ForbiddenArtifactPrefixes {
				if strings.HasPrefix(image.Delivery.Default.Source, prefix) {
					add("delivery mirror %s uses forbidden source %s", image.ID, image.Delivery.Default.Source)
				}
			}
			if p.Desired.Delivery.Policy.MutableTagsForbidden && mutableImageReference(image.Delivery.Default.Source) {
				add("delivery mirror %s uses a missing or mutable source tag", image.ID)
			}
		case "build":
			if image.Delivery.Default.BakeTarget == "" || len(image.Delivery.Default.Materials) == 0 {
				add("delivery build %s requires bakeTarget and materials", image.ID)
			}
			for _, material := range image.Delivery.Default.Materials {
				validatePinnedBuildMaterial(&problems, p.Desired.Delivery.Policy, "delivery build "+image.ID, material)
			}
		default:
			add("delivery image %s has unsupported type %q", image.ID, image.Delivery.Default.Type)
		}
	}
	baselineIdentity := VersionedCommit{Version: p.Desired.Platform.BigBang.Version, Commit: p.Desired.Platform.BigBang.Commit}
	if !reflect.DeepEqual(p.Desired.Delivery.RenderedBaseline.BigBang, baselineIdentity) ||
		!reflect.DeepEqual(p.Desired.Delivery.LegacyCrosswalk.BigBang, baselineIdentity) {
		add("rendered image evidence does not identify the selected Big Bang release")
	}
	validateImageEvidence(
		&problems,
		imageIDs,
		p.Desired.Delivery.RenderedBaseline,
		p.Desired.Delivery.LegacyCrosswalk,
		allowStale,
	)
	validateBootstrapImageBindings(&problems, p.Desired.Platform.Bootstrap.Charts, imageIDs, allowStale)
	validateBuildGraph(&problems, p, files, allowStale)
	validateCharts(&problems, p.Desired.Platform.Bootstrap.Charts, p.Desired.Platform.Values.Profiles)
	validateBundledChartInventory(
		&problems,
		p.Desired.Platform.Bootstrap.Registry,
		p.Desired.Platform.Bootstrap.Charts,
		p.Desired.Platform.Charts,
	)
	validateLock(&problems, p, allowStale, files)
	requiredFiles := []string{
		"atum.schema.json",
		"atum.lock.schema.json",
		filepath.Join(p.Desired.Orchestration.Directory, "ansible.cfg"),
		filepath.Join(p.Desired.Orchestration.Directory, "requirements.txt"),
		filepath.Join(p.Desired.Orchestration.Inventory, "group_vars", "all", "all.yml"),
		filepath.Join(p.Desired.Orchestration.Inventory, "group_vars", "all", "containerd.yml"),
		filepath.Join(p.Desired.Orchestration.Inventory, "group_vars", "k8s_cluster", "addons.yml"),
		filepath.Join(p.Desired.Orchestration.Inventory, "group_vars", "k8s_cluster", "k8s-cluster.yml"),
		p.Desired.Platform.PackageSelection,
		p.Desired.Platform.Values.Operational,
		p.Desired.Platform.Values.Generated,
		filepath.Join(p.Desired.Platform.Directory, "apps", "prep", "namespace.yaml"),
		filepath.Join(p.Desired.Platform.Directory, "clusters", p.Desired.Project.Cluster, "bigbang.yaml"),
		filepath.Join(p.Desired.Platform.Directory, "clusters", p.Desired.Project.Cluster, "kustomization.yaml"),
		filepath.Join(p.Desired.Platform.Directory, "clusters", p.Desired.Project.Cluster, "platform-profile-access.yaml"),
		filepath.Join(p.Desired.Platform.Directory, "clusters", p.Desired.Project.Cluster, "platform-profile-prep.yaml"),
		filepath.Join(
			p.Desired.Platform.Directory, "clusters", p.Desired.Project.Cluster, "flux-system", "platform-profile.yaml",
		),
	}
	for _, profile := range profileNames {
		profileRoot := filepath.Join(p.Desired.Platform.Directory, "profiles", profile)
		requiredFiles = append(
			requiredFiles,
			p.Desired.Platform.Values.Profiles[profile],
			filepath.Join(profileRoot, "prep", "kustomization.yaml"),
			filepath.Join(profileRoot, "access", "kustomization.yaml"),
		)
	}
	for _, relative := range requiredFiles {
		if _, exists := files[relative]; exists {
			continue
		}
		if info, err := statProjectPath(p.Root, relative); err != nil || !info.Mode().IsRegular() {
			add("required tracked file %s is missing", relative)
		}
	}
	if _, err := p.Desired.ResolvePlatformValues(repositoryPlatformValueLoader(p.Root, files)); err != nil {
		add("platform values are invalid: %v", err)
	}
	for _, chart := range p.Desired.Platform.Bootstrap.Charts {
		if info, err := candidateFileInfo(p.Root, chart.Values, files); err != nil || !info.Mode().IsRegular() {
			add("bootstrap chart values file %s is missing", chart.Values)
		}
		if info, err := candidateFileInfo(p.Root, chart.FluxSource, files); err != nil || !info.Mode().IsRegular() {
			add("bootstrap chart Flux source %s is missing", chart.FluxSource)
		}
	}
	for _, chart := range p.Desired.Platform.Charts {
		if info, err := candidateFileInfo(p.Root, chart.FluxSource, files); err != nil || !info.Mode().IsRegular() {
			add("platform chart Flux source %s is missing", chart.FluxSource)
		}
	}
	for _, vendor := range p.Desired.Platform.Vendors {
		path, err := fssecure.Resolve(p.Root, vendor.Directory, false)
		if info, statErr := os.Stat(path); err != nil || statErr != nil || !info.IsDir() {
			add("vendor directory %s is missing", vendor.Directory)
		}
	}
	for label, source := range projectGitSources(&p.Desired) {
		for _, patch := range source.Patches {
			if info, err := statProjectPath(p.Root, patch); err != nil || !info.Mode().IsRegular() {
				add("%s patch %s is missing", label, patch)
			}
		}
		for _, asset := range source.Assets {
			if data, exists := files[asset.File]; exists {
				if digest := SHA256(data); digest != asset.SHA256 {
					add("%s asset %s candidate hash is %s, want %s", label, asset.File, digest, asset.SHA256)
				}
				continue
			}
			assetPath, pathErr := fssecure.Resolve(p.Root, asset.File, false)
			if info, err := os.Stat(assetPath); pathErr != nil || err != nil || !info.Mode().IsRegular() {
				add("%s asset %s is missing", label, asset.File)
			} else if allowStale {
				continue
			} else if digest, err := fileSHA256(assetPath); err != nil {
				add("%s asset %s cannot be hashed: %v", label, asset.File, err)
			} else if digest != asset.SHA256 {
				add("%s asset %s hash is %s, want %s", label, asset.File, digest, asset.SHA256)
			}
		}
	}
	for _, vendor := range p.Desired.Platform.Vendors {
		for _, patch := range vendor.Patches {
			if info, err := statProjectPath(p.Root, patch); err != nil || !info.Mode().IsRegular() {
				add("vendor %s patch %s is missing", vendor.ID, patch)
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return errors.New("invalid Atum project:\n  - " + strings.Join(problems, "\n  - "))
}

func validateAnsibleUser(problems *[]string, user string) {
	if user == "" || user[0] == '-' {
		*problems = append(*problems, "orchestration ansibleUser must be set and cannot begin with a dash")
		return
	}
	for _, character := range user {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			*problems = append(*problems, fmt.Sprintf("orchestration ansibleUser %q contains unsupported characters", user))
			return
		}
	}
}

func validateLock(problems *[]string, p *Project, allowStale bool, files map[string][]byte) {
	add := func(format string, args ...any) {
		*problems = append(*problems, fmt.Sprintf(format, args...))
	}
	lock := &p.Lock
	desired := &p.Desired
	if !allowStale && (!reflect.DeepEqual(lock.Resolved.ClusterReleases, desired.Orchestration.Releases) ||
		!reflect.DeepEqual(lock.Resolved.BigBang, desired.Platform.BigBang) ||
		!reflect.DeepEqual(lock.Resolved.Flux, desired.Platform.Flux) ||
		!reflect.DeepEqual(lock.Resolved.Packages, desired.Platform.Packages) ||
		!reflect.DeepEqual(lock.Resolved.Charts, desired.Platform.Charts) ||
		!reflect.DeepEqual(lock.Resolved.Vendors, desired.Platform.Vendors)) {
		add("resolved source or Kubernetes versions do not match desired state")
	}
	if !allowStale && !equalBootstrap(lock.Resolved.Bootstrap, desired.Platform.Bootstrap) {
		add("resolved bootstrap charts do not match desired state")
	}
	validateSupportSources(problems, p, allowStale, files)
	target, targetErr := desired.Orchestration.TargetRelease()
	if targetErr != nil {
		add("desired orchestration target is invalid: %v", targetErr)
	}
	if !allowStale && (lock.Compatibility.KubernetesVersion != target.Kubernetes ||
		lock.Compatibility.BigBangConstraint != desired.Platform.BigBang.KubeVersion ||
		lock.Compatibility.Status != "compatible" ||
		!reflect.DeepEqual(lock.Compatibility.Constraints, desiredConstraints(desired))) {
		add("compatibility resolution does not match desired state")
	}
	for name, checksum := range map[string]string{
		"kubeadm": lock.Compatibility.Checksums.Kubeadm,
		"kubectl": lock.Compatibility.Checksums.Kubectl,
		"kubelet": lock.Compatibility.Checksums.Kubelet,
	} {
		if !validDigest(checksum) {
			add("compatibility %s checksum is invalid", name)
		}
	}
	if !allowStale && targetErr == nil && !reflect.DeepEqual(lock.Compatibility.Checksums, target.Checksums) {
		add("compatibility checksums do not match the terminal cluster release")
	}
	if lock.Delivery.SchemaVersion != "atum.dev/image-lock/v3" || lock.Delivery.Platform != desired.Project.Platform {
		add("delivery lock schema or platform is invalid")
	}
	if _, exists := desired.Delivery.Profiles[lock.Delivery.Profile]; !exists {
		add("delivery lock profile %q is not defined", lock.Delivery.Profile)
	}
	if !allowStale && lock.Delivery.InventorySHA256 != p.DeliverySHA256 {
		add("delivery inventory hash is %s, want %s", lock.Delivery.InventorySHA256, p.DeliverySHA256)
	}
	pendingDelivery := lock.Delivery.Pending()
	if !allowStale && !pendingDelivery && len(lock.Delivery.Images) != len(desired.Delivery.Images) {
		add("delivery lock has %d images, desired state has %d", len(lock.Delivery.Images), len(desired.Delivery.Images))
	}
	if pendingDelivery && lock.Bundle != nil {
		add("pending image delivery cannot reference a deployment bundle")
	}
	desiredImages := make(map[string]*Image, len(desired.Delivery.Images))
	for i := range desired.Delivery.Images {
		image := &desired.Delivery.Images[i]
		desiredImages[image.ID] = image
	}
	seen := make(map[string]struct{}, len(lock.Delivery.Images))
	counts := DeliveryCounts{Total: len(lock.Delivery.Images)}
	for i := range lock.Delivery.Images {
		image := &lock.Delivery.Images[i]
		want, exists := desiredImages[image.ID]
		if !allowStale && (!exists || want.Target != image.Target) {
			add("locked image %s target does not match desired state", image.ID)
		}
		if _, duplicate := seen[image.ID]; duplicate {
			add("locked image id %q is duplicated", image.ID)
		}
		seen[image.ID] = struct{}{}
		if !validDigest(image.Digest) || !validHexSHA256(image.InputSHA256) {
			add("locked image %s has an invalid digest or input hash", image.ID)
		}
		switch image.Delivery.Type {
		case "mirror":
			counts.Mirrored++
			if image.Delivery.Source == "" || !validDigest(image.Delivery.Digest) ||
				image.Delivery.BakeTarget != "" || len(image.Delivery.Materials) != 0 || image.Delivery.SourceProfile != "platform" {
				add("locked mirror %s has invalid delivery material", image.ID)
			}
		case "build":
			counts.Built++
			if image.Delivery.Source != "" || image.Delivery.Digest != "" || image.Delivery.BakeTarget == "" ||
				len(image.Delivery.Materials) == 0 ||
				(image.Delivery.SourceProfile != "platform" && image.Delivery.SourceProfile != "full-build") {
				add("locked build %s has invalid delivery material", image.ID)
			}
			if !allowStale {
				for _, material := range image.Delivery.Materials {
					if strings.HasPrefix(material, "bake:") || strings.HasPrefix(material, "graph:sha256:") {
						continue
					}
					validatePinnedBuildMaterial(problems, desired.Delivery.Policy, "locked build "+image.ID, material)
				}
			}
		default:
			add("locked image %s has unsupported delivery type %q", image.ID, image.Delivery.Type)
		}
		if !allowStale && exists && !lockedDeliveryMatches(image.Delivery, desiredDeliveryForProfile(want, lock.Delivery.Profile, lock.Delivery.GraphSHA256)) {
			add("locked image %s delivery does not match desired state", image.ID)
		}
		if !allowStale && exists {
			expectedInput, err := desired.ImageInputSHA256(*want, image.Delivery, lock.Delivery.GraphSHA256)
			if err != nil {
				add("locked image %s input cannot be resolved: %v", image.ID, err)
			} else if image.InputSHA256 != expectedInput {
				add("locked image %s input hash is %s, want %s", image.ID, image.InputSHA256, expectedInput)
			}
		}
		if image.Delivery.Type == "mirror" && image.Digest != image.Delivery.Digest {
			add("locked mirror %s result digest differs from its source digest", image.ID)
		}
	}
	if !reflect.DeepEqual(lock.Delivery.Counts, counts) {
		add("delivery lock counts do not match its image entries")
	}
	if !validHexSHA256(lock.Delivery.InventorySHA256) || !validHexSHA256(lock.Delivery.GraphSHA256) {
		add("delivery lock inventory or graph hash is invalid")
	}
	if lock.Bundle != nil {
		clean, err := fssecure.Relative(lock.Bundle.File)
		if err != nil || filepath.ToSlash(clean) != lock.Bundle.File || lock.Bundle.Size < 1 ||
			!validHexSHA256(lock.Bundle.SHA256) || !validHexSHA256(lock.Bundle.AtumSourceSHA256) {
			add("deployment bundle identity is invalid")
		} else {
			snapshot := *lock
			snapshot.Bundle = nil
			snapshotData, marshalErr := MarshalJSON(snapshot)
			if marshalErr != nil {
				add("deployment bundle parent lock cannot be encoded: %v", marshalErr)
			}
			parts := strings.Split(lock.Bundle.File, "/")
			filename := "atum-bundle-" + lock.Bundle.SHA256 + ".tar"
			if len(parts) != 4 || parts[0] != ".atum" || parts[1] != "artifacts" ||
				marshalErr != nil || parts[2] != SHA256(snapshotData) || parts[3] != filename {
				add("deployment bundle path does not match its content identity")
			}
		}
		hasReference := lock.Bundle.OCIReference != ""
		hasDigest := lock.Bundle.OCIDigest != ""
		if hasReference != hasDigest {
			add("deployment bundle OCI identity is incomplete")
		} else if hasReference {
			expectedReference := desired.Delivery.Registry.Host + "/seed-artifacts/atum-bundle:sha256-" + lock.Bundle.SHA256
			if lock.Bundle.OCIReference != expectedReference || !validDigest(lock.Bundle.OCIDigest) {
				add("deployment bundle OCI identity does not match its content identity")
			}
		}
	}
}

func validateSupportSources(problems *[]string, p *Project, allowStale bool, files map[string][]byte) {
	sources := p.Lock.Resolved.SupportSources
	if allowStale {
		return
	}
	values, err := p.Desired.ResolvePlatformValues(repositoryPlatformValueLoader(p.Root, files))
	if err != nil {
		return
	}
	consumers, err := ActiveWrapperConsumers(p.Desired.Platform, values.Merged)
	if err != nil {
		*problems = append(*problems, "active wrapper consumers are invalid: "+err.Error())
		return
	}
	if len(consumers) == 0 {
		if len(sources) != 0 {
			*problems = append(*problems, "resolved support sources are present without active wrapper consumers")
		}
		return
	}
	if len(sources) != 1 {
		*problems = append(*problems, "active wrapper consumers require exactly one resolved wrapper support source")
		return
	}
	source := sources[0]
	if err := ValidateWrapperSupportSource(source); err != nil {
		*problems = append(*problems, "resolved wrapper support source is invalid: "+err.Error())
	}
	wrapper, _ := values.Merged["wrapper"].(map[string]any)
	sourceType, _ := wrapper["sourceType"].(string)
	gitValues, _ := wrapper["git"].(map[string]any)
	internalURL := strings.TrimSuffix(p.Desired.Platform.Sources.ClusterURL, "/") + "/" +
		p.Desired.Platform.Sources.UpstreamOrganization + "/" + source.ID + ".git"
	if sourceType != "git" ||
		stringValue(gitValues, "repo") != internalURL ||
		stringValue(gitValues, "tag") != "" ||
		stringValue(gitValues, "semver") != source.Source.Version ||
		stringValue(gitValues, "branch") != source.Source.Branch ||
		stringValue(gitValues, "commit") != source.Source.Commit ||
		stringValue(gitValues, "path") != source.ChartPath {
		*problems = append(*problems, "generated wrapper values do not exactly project the resolved support source")
	}
	if _, err := RepositoryInventory(p.Desired, p.Lock.Resolved); err != nil {
		*problems = append(*problems, err.Error())
	}
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func ActiveWrapperConsumers(platform Platform, values map[string]any) ([]WrapperConsumer, error) {
	type dependency struct {
		id string
	}
	declared := make(map[string]dependency, len(platform.Packages)+len(platform.Charts))
	addDependency := func(id, path string) error {
		prefix, packageKey, found := strings.Cut(path, ".")
		if !found || prefix != "packages" || packageKey == "" || strings.ContainsRune(packageKey, '.') {
			return nil
		}
		if previous, exists := declared[packageKey]; exists && previous.id != id {
			return fmt.Errorf("wrapper package %s is declared by both %s and %s", packageKey, previous.id, id)
		}
		declared[packageKey] = dependency{id: id}
		return nil
	}
	for _, pkg := range platform.Packages {
		if err := addDependency(pkg.ID, pkg.ValuesPath); err != nil {
			return nil, err
		}
	}
	for _, chart := range platform.Charts {
		if err := addDependency(chart.ID, chart.ValuesPath); err != nil {
			return nil, err
		}
	}
	packageValues, _ := values["packages"].(map[string]any)
	keys := make([]string, 0, len(packageValues))
	for key := range packageValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	consumers := make([]WrapperConsumer, 0, len(keys))
	releaseOwners := make(map[string]WrapperConsumer, len(keys))
	for _, rawPackageKey := range keys {
		dependencyValues, ok := packageValues[rawPackageKey].(map[string]any)
		if !ok {
			continue
		}
		wrapper, _ := dependencyValues["wrapper"].(map[string]any)
		wrapperEnabled := helmValueTruthy(wrapper["enabled"])
		dependencyEnabled := true
		if configured, exists := dependencyValues["enabled"]; exists {
			dependencyEnabled = helmValueTruthy(configured)
		}
		if !wrapperEnabled || !dependencyEnabled {
			continue
		}
		dependency, exists := declared[rawPackageKey]
		if !exists {
			return nil, fmt.Errorf(
				"enabled wrapper package packages.%s is not a declared platform dependency",
				rawPackageKey,
			)
		}
		packageKey, err := bigBangPackageIdentity(rawPackageKey)
		if err != nil {
			return nil, fmt.Errorf("wrapper package packages.%s: %w", rawPackageKey, err)
		}
		namespace := packageKey
		namespaceValues, _ := dependencyValues["namespace"].(map[string]any)
		if raw, exists := namespaceValues["name"]; exists && helmValueTruthy(raw) {
			configured, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("wrapper namespace for packages.%s is not a string", rawPackageKey)
			}
			namespace = strings.TrimSpace(configured)
		}
		helmRelease, _ := dependencyValues["helmRelease"].(map[string]any)
		if raw, exists := helmRelease["namespace"]; exists && helmValueTruthy(raw) {
			configured, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("wrapper HelmRelease namespace for packages.%s is not a string", rawPackageKey)
			}
			namespace = strings.TrimSpace(configured)
		}
		if !validDNSLabel(namespace) {
			return nil, fmt.Errorf("wrapper namespace %q for packages.%s is invalid", namespace, rawPackageKey)
		}
		releaseName := packageKey + "-wrapper"
		if !validDNSLabel(releaseName) {
			return nil, fmt.Errorf("wrapper release name %q for packages.%s is invalid", releaseName, rawPackageKey)
		}
		consumer := WrapperConsumer{
			OwnerID: dependency.id, ValuesPath: "packages." + rawPackageKey, PackageKey: packageKey,
			ReleaseName: releaseName, Namespace: namespace,
		}
		if previous, duplicate := releaseOwners[consumer.ReleaseName]; duplicate {
			return nil, fmt.Errorf("wrapper release %s is ambiguously owned by %s in %s and %s in %s",
				consumer.ReleaseName, previous.OwnerID, previous.Namespace, consumer.OwnerID, consumer.Namespace)
		}
		releaseOwners[consumer.ReleaseName] = consumer
		consumers = append(consumers, consumer)
	}
	sort.Slice(consumers, func(i, j int) bool {
		if consumers[i].ReleaseName != consumers[j].ReleaseName {
			return consumers[i].ReleaseName < consumers[j].ReleaseName
		}
		return consumers[i].OwnerID < consumers[j].OwnerID
	})
	return consumers, nil
}

var bigBangNonWord = regexp.MustCompile(`\W+`)

// bigBangPackageIdentity mirrors the selected Big Bang resourceName helper:
// regexReplaceAll "\\W+" "-", trimPrefix "-", trunc 63, trimSuffix "-",
// then Sprig's kebabcase (xstrings.ToKebabCase).
func bigBangPackageIdentity(value string) (string, error) {
	rendered := bigBangNonWord.ReplaceAllString(value, "-")
	rendered = strings.TrimPrefix(rendered, "-")
	if len(rendered) > 63 {
		rendered = rendered[:63]
	}
	rendered = strings.TrimSuffix(rendered, "-")
	rendered = xstrings.ToKebabCase(rendered)
	if !validDNSLabel(rendered) {
		return "", fmt.Errorf("Big Bang resourceName renders invalid identity %q", rendered)
	}
	return rendered, nil
}

func helmValueTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case int:
		return typed != 0
	case int8:
		return typed != 0
	case int16:
		return typed != 0
	case int32:
		return typed != 0
	case int64:
		return typed != 0
	case uint:
		return typed != 0
	case uint8:
		return typed != 0
	case uint16:
		return typed != 0
	case uint32:
		return typed != 0
	case uint64:
		return typed != 0
	case float32:
		return typed != 0
	case float64:
		return typed != 0
	case []any:
		return len(typed) != 0
	case map[string]any:
		return len(typed) != 0
	default:
		return true
	}
}

func ValidateWrapperSupportDeclaration(sourceURL, version, chartPath string) error {
	if sourceURL != strings.TrimSpace(sourceURL) ||
		version != strings.TrimSpace(version) ||
		chartPath != strings.TrimSpace(chartPath) {
		return errors.New("wrapper declaration fields cannot contain surrounding whitespace")
	}
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("wrapper declaration requires an HTTPS Git URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(version) == "" {
		return errors.New("wrapper declaration requires a non-empty tag")
	}
	if !SafeRepositoryChartPath(chartPath) {
		return errors.New("wrapper declaration requires a safe chart path")
	}
	return nil
}

func ValidateWrapperSupportSource(source SupportSource) error {
	if source.ID != "wrapper" || source.ValuesPath != "wrapper" {
		return errors.New("wrapper support source has an unexpected ID or values path")
	}
	if err := ValidateWrapperSupportDeclaration(source.Source.URL, source.Source.Version, source.ChartPath); err != nil {
		return err
	}
	if !validGitBranch(source.Source.Branch) || source.Source.Ref != "" ||
		source.Source.KubeVersion != "" || len(source.Source.Patches) != 0 || len(source.Source.Assets) != 0 {
		return errors.New("wrapper support source requires one valid branch and no ref, Kubernetes constraint, patches, or assets")
	}
	if err := validGitCommitIdentity(source.Source.Commit); err != nil {
		return err
	}
	return nil
}

func validGitCommitIdentity(commit string) error {
	if len(commit) != 40 {
		return errors.New("wrapper support source requires a 40-character commit")
	}
	for _, char := range commit {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return errors.New("wrapper support source commit must be lowercase hexadecimal")
		}
	}
	return nil
}

func SafeRepositoryChartPath(value string) bool {
	if value == "" || strings.ContainsRune(value, '\\') || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func equalBootstrap(left, right BootstrapCharts) bool {
	return reflect.DeepEqual(left, right)
}

type profiledDelivery struct {
	choice        DeliveryChoice
	sourceProfile string
}

func desiredDeliveryForProfile(image *Image, profile, graphSHA256 string) profiledDelivery {
	if profile == "full-build" && image.Delivery.FullBuildTarget != "" {
		return profiledDelivery{
			choice: DeliveryChoice{
				Type:       "build",
				BakeTarget: image.Delivery.FullBuildTarget,
				Materials: []string{
					"bake:" + image.Delivery.FullBuildTarget,
					"graph:sha256:" + graphSHA256,
				},
			},
			sourceProfile: "full-build",
		}
	}
	return profiledDelivery{choice: image.Delivery.Default, sourceProfile: "platform"}
}

// ResolveDelivery returns the exact delivery contract used to publish an
// image for a named profile. Build graph identity is part of full-build
// material so callers cannot publish a source-built result against an
// unrelated graph.
func ResolveDelivery(image Image, profile, graphSHA256 string) (LockedDelivery, error) {
	if profile != "platform" && profile != "full-build" {
		return LockedDelivery{}, fmt.Errorf("unsupported delivery profile %q", profile)
	}
	resolved := desiredDeliveryForProfile(&image, profile, graphSHA256)
	choice := resolved.choice
	return LockedDelivery{
		Type:          choice.Type,
		Source:        choice.Source,
		Digest:        choice.Digest,
		BakeTarget:    choice.BakeTarget,
		Materials:     append([]string(nil), choice.Materials...),
		SourceProfile: resolved.sourceProfile,
	}, nil
}

func lockedDeliveryMatches(locked LockedDelivery, expected profiledDelivery) bool {
	desired := expected.choice
	if locked.Type != desired.Type || locked.SourceProfile != expected.sourceProfile {
		return false
	}
	switch desired.Type {
	case "mirror":
		return locked.Source == desired.Source && locked.Digest == desired.Digest && locked.BakeTarget == "" && len(locked.Materials) == 0
	case "build":
		return locked.Source == "" && locked.Digest == "" && locked.BakeTarget == desired.BakeTarget && reflect.DeepEqual(locked.Materials, desired.Materials)
	default:
		return false
	}
}

func validateImageEvidence(
	problems *[]string,
	images map[string]*Image,
	baseline RenderedBaseline,
	crosswalk LegacyCrosswalk,
	allowStale bool,
) {
	if baseline.SchemaVersion != "atum.dev/rendered-image-baseline/v2" ||
		(!allowStale && len(baseline.Entries) != len(images)) {
		*problems = append(*problems, "rendered image baseline does not cover the delivery inventory")
	}
	if crosswalk.SchemaVersion != "atum.dev/bigbang-public-crosswalk/v2" ||
		(!allowStale && len(crosswalk.Entries) != len(images)) {
		*problems = append(*problems, "legacy crosswalk does not cover the delivery inventory")
	}
	seenBaseline := make(map[string]struct{}, len(baseline.Entries))
	counts := ScopeCounts{Unique: len(images)}
	for _, image := range images {
		for _, scope := range image.Scopes {
			switch scope {
			case "prep":
				counts.Prep++
			case "bigbang":
				counts.BigBang++
			}
		}
	}
	if !allowStale && !reflect.DeepEqual(baseline.Counts, counts) {
		*problems = append(*problems, "rendered image baseline counts do not match delivery inventory")
	}
	for _, entry := range baseline.Entries {
		evidenceKnown := entry.Evidence == "rendered" || entry.Evidence == "controller-generated" || entry.Evidence == "configuration"
		image, ok := images[entry.ImageID]
		if (!ok && !allowStale) ||
			(ok && (image.Target != entry.Target || !reflect.DeepEqual(image.Scopes, entry.Scopes))) ||
			!evidenceKnown {
			*problems = append(*problems, fmt.Sprintf("baseline entry %s does not match delivery inventory", entry.ImageID))
		}
		if _, exists := seenBaseline[entry.ImageID]; exists {
			*problems = append(*problems, fmt.Sprintf("baseline entry %s is duplicated", entry.ImageID))
		}
		seenBaseline[entry.ImageID] = struct{}{}
	}
	seenCrosswalk := make(map[string]struct{}, len(crosswalk.Entries))
	deliveryCounts := DeliveryCounts{Total: len(images)}
	compatibilityBuilds := make([]string, 0, len(images))
	for _, image := range images {
		if image.Delivery.Default.Type == "mirror" {
			deliveryCounts.Mirrored++
		} else if image.Delivery.Default.Type == "build" {
			deliveryCounts.Built++
			compatibilityBuilds = append(compatibilityBuilds, image.ID)
		}
	}
	if !allowStale && !reflect.DeepEqual(crosswalk.DefaultCounts, deliveryCounts) {
		*problems = append(*problems, "legacy crosswalk counts do not match delivery inventory")
	}
	sort.Strings(compatibilityBuilds)
	declaredBuilds := append([]string(nil), crosswalk.CompatibilityBuilds...)
	sort.Strings(declaredBuilds)
	if !allowStale && !reflect.DeepEqual(declaredBuilds, compatibilityBuilds) {
		*problems = append(*problems, "legacy crosswalk compatibility builds do not match delivery inventory")
	}
	for _, entry := range crosswalk.Entries {
		image, ok := images[entry.ImageID]
		if (!ok && !allowStale) ||
			(ok && (image.Target != entry.Replacement || image.Family != entry.Family ||
				!reflect.DeepEqual(image.Scopes, entry.Scopes) || !reflect.DeepEqual(image.Consumers, entry.Consumers) ||
				!reflect.DeepEqual(image.BigBangRefs, entry.BigBangRefs) ||
				image.Delivery.Default.Type != entry.DefaultDelivery)) {
			*problems = append(*problems, fmt.Sprintf("crosswalk entry %s does not match delivery inventory", entry.ImageID))
		}
		if (entry.OfficialSource == nil) == (entry.CompatibilityBuild == nil) {
			*problems = append(*problems, fmt.Sprintf("crosswalk entry %s must define exactly one delivery source", entry.ImageID))
		} else if ok && entry.OfficialSource != nil &&
			(entry.OfficialSource.Reference != image.Delivery.Default.Source || entry.OfficialSource.Digest != image.Delivery.Default.Digest) {
			*problems = append(*problems, fmt.Sprintf("crosswalk mirror %s does not match delivery source", entry.ImageID))
		} else if ok && entry.CompatibilityBuild != nil &&
			(entry.CompatibilityBuild.BakeTarget != image.Delivery.Default.BakeTarget ||
				!reflect.DeepEqual(entry.CompatibilityBuild.Materials, image.Delivery.Default.Materials)) {
			*problems = append(*problems, fmt.Sprintf("crosswalk build %s does not match delivery source", entry.ImageID))
		}
		if _, exists := seenCrosswalk[entry.ImageID]; exists {
			*problems = append(*problems, fmt.Sprintf("crosswalk entry %s is duplicated", entry.ImageID))
		}
		seenCrosswalk[entry.ImageID] = struct{}{}
	}
}

func mutableImageReference(reference string) bool {
	if strings.Contains(reference, "@") {
		return true
	}
	lastSlash := strings.LastIndexByte(reference, '/')
	colon := strings.LastIndexByte(reference, ':')
	if colon <= lastSlash || colon == len(reference)-1 {
		return true
	}
	switch strings.ToLower(reference[colon+1:]) {
	case "latest", "stable", "current", "main", "master", "edge", "nightly", "dev", "development":
		return true
	default:
		return false
	}
}

func imageReferenceTag(reference string) string {
	lastSlash := strings.LastIndexByte(reference, '/')
	colon := strings.LastIndexByte(reference, ':')
	if colon <= lastSlash || colon == len(reference)-1 {
		return ""
	}
	return reference[colon+1:]
}

func invalidImageRepository(repository string) bool {
	if repository == "" {
		return false
	}
	lastSlash := strings.LastIndexByte(repository, '/')
	return lastSlash <= 0 || lastSlash == len(repository)-1 ||
		strings.ContainsAny(repository, "@ \t\r\n") ||
		strings.Contains(repository[lastSlash+1:], ":")
}

func validateCharts(problems *[]string, charts []Chart, profiles map[string]string) {
	seenIDs := make(map[string]struct{}, len(charts))
	seenNames := make(map[string]struct{}, len(charts))
	seenTargets := make(map[string]struct{}, len(charts))
	for i := range charts {
		chart := &charts[i]
		if !validResourceID(chart.ID) || chart.Name == "" || chart.Version == "" || chart.AppVersion == "" ||
			len(chart.ImageBindings) == 0 || chart.License == "" ||
			chart.Source.URL == "" || chart.Values == "" || chart.FluxSource == "" || chart.File == "" || filepath.Base(chart.File) != chart.File ||
			chart.Target == "" || !validHexSHA256(chart.ArchiveSHA256) {
			*problems = append(*problems, fmt.Sprintf("bootstrap chart %d has invalid identity", i))
		}
		validateRelative(problems, "bootstrap chart "+chart.ID+" values", chart.Values)
		validateRelative(problems, "bootstrap chart "+chart.ID+" Flux source", chart.FluxSource)
		if _, exists := seenIDs[chart.ID]; exists {
			*problems = append(*problems, fmt.Sprintf("bootstrap chart id %q is duplicated", chart.ID))
		}
		if _, exists := seenNames[chart.Name]; exists {
			*problems = append(*problems, fmt.Sprintf("bootstrap chart name %q is duplicated", chart.Name))
		}
		if _, exists := seenTargets[chart.Target]; exists {
			*problems = append(*problems, fmt.Sprintf("bootstrap chart target %q is duplicated", chart.Target))
		}
		seenIDs[chart.ID] = struct{}{}
		seenNames[chart.Name] = struct{}{}
		seenTargets[chart.Target] = struct{}{}
		validateChartSource(problems, "bootstrap chart "+chart.ID, chart.Source)
		if !slices.IsSorted(chart.Profiles) {
			*problems = append(*problems, fmt.Sprintf("bootstrap chart %s profiles must be sorted", chart.ID))
		}
		seenProfiles := make(map[string]struct{}, len(chart.Profiles))
		for _, profile := range chart.Profiles {
			if !validResourceID(profile) {
				*problems = append(*problems, fmt.Sprintf("bootstrap chart %s has invalid profile %q", chart.ID, profile))
			}
			if _, duplicate := seenProfiles[profile]; duplicate {
				*problems = append(*problems, fmt.Sprintf("bootstrap chart %s repeats profile %q", chart.ID, profile))
				continue
			}
			seenProfiles[profile] = struct{}{}
			if _, exists := profiles[profile]; !exists {
				*problems = append(*problems, fmt.Sprintf("bootstrap chart %s references unknown profile %q", chart.ID, profile))
			}
		}
	}
}

func validateBootstrapImageBindings(problems *[]string, charts []Chart, images map[string]*Image, allowStale bool) {
	claimed := make(map[string]string)
	for i := range charts {
		chart := &charts[i]
		seen := make(map[string]struct{}, len(chart.ImageBindings))
		for _, binding := range chart.ImageBindings {
			imageID := binding.ID
			if !validResourceID(imageID) || binding.ValuesPath == "" || strings.HasPrefix(binding.ValuesPath, ".") ||
				strings.HasSuffix(binding.ValuesPath, ".") || strings.Contains(binding.ValuesPath, "..") ||
				invalidImageRepository(binding.ImageRepository) ||
				strings.ContainsAny(binding.TagSuffix, ":@/") {
				*problems = append(*problems, fmt.Sprintf("bootstrap chart %s has invalid image binding for %s", chart.ID, imageID))
				continue
			}
			if _, duplicate := seen[imageID]; duplicate {
				*problems = append(*problems, fmt.Sprintf("bootstrap chart %s repeats image binding %s", chart.ID, imageID))
				continue
			}
			seen[imageID] = struct{}{}
			if owner, duplicate := claimed[imageID]; duplicate {
				*problems = append(*problems, fmt.Sprintf("bootstrap image %s is shared by %s and %s", imageID, owner, chart.ID))
				continue
			}
			claimed[imageID] = chart.ID
			image, exists := images[imageID]
			if !exists {
				*problems = append(*problems, fmt.Sprintf("bootstrap chart %s references missing image %s", chart.ID, imageID))
				continue
			}
			if image.Delivery.Default.Type != "mirror" || image.Delivery.FullBuildTarget != "" {
				*problems = append(*problems, fmt.Sprintf("bootstrap image %s must use only its official mirror", imageID))
			}
			if !slices.Contains(image.Scopes, "prep") {
				*problems = append(*problems, fmt.Sprintf("bootstrap image %s is not in prep scope", imageID))
			}
			if !allowStale {
				tag := imageReferenceTag(image.Delivery.Default.Source)
				version := strings.TrimPrefix(strings.TrimSuffix(tag, binding.TagSuffix), "v")
				if tag == "" || imageReferenceTag(image.Target) != tag || image.Version != version {
					*problems = append(*problems, fmt.Sprintf("bootstrap image %s source, target, and version are inconsistent", imageID))
				}
			}
		}
	}
}

func validatePackages(problems *[]string, packages []Package) {
	seenIDs := make(map[string]struct{}, len(packages))
	seenValues := make(map[string]struct{}, len(packages))
	for i := range packages {
		pkg := &packages[i]
		if !validResourceID(pkg.ID) || pkg.ValuesPath == "" || pkg.License == "" {
			*problems = append(*problems, fmt.Sprintf("platform package %d has invalid identity", i))
		}
		if pkg.Source.Branch == "" {
			*problems = append(*problems, fmt.Sprintf("platform package %s requires the branch containing its exact commit", pkg.ID))
		}
		if _, exists := seenIDs[pkg.ID]; exists {
			*problems = append(*problems, fmt.Sprintf("platform package id %q is duplicated", pkg.ID))
		}
		if _, exists := seenValues[pkg.ValuesPath]; exists {
			*problems = append(*problems, fmt.Sprintf("platform package values path %q is duplicated", pkg.ValuesPath))
		}
		seenIDs[pkg.ID] = struct{}{}
		seenValues[pkg.ValuesPath] = struct{}{}
		validateGitSource(problems, "platform package "+pkg.ID, pkg.Source)
	}
}

func validateTrackedCharts(problems *[]string, charts []TrackedChart) {
	seenIDs := make(map[string]struct{}, len(charts))
	seenValues := make(map[string]struct{}, len(charts))
	for i := range charts {
		chart := &charts[i]
		if !validResourceID(chart.ID) || chart.Name == "" || chart.ValuesPath == "" || chart.FluxSource == "" || chart.Version == "" ||
			chart.AppVersion == "" || chart.License == "" || !validHexSHA256(chart.ArchiveSHA256) {
			*problems = append(*problems, fmt.Sprintf("platform chart %d has invalid identity", i))
		}
		if _, exists := seenIDs[chart.ID]; exists {
			*problems = append(*problems, fmt.Sprintf("platform chart id %q is duplicated", chart.ID))
		}
		if _, exists := seenValues[chart.ValuesPath]; exists {
			*problems = append(*problems, fmt.Sprintf("platform chart values path %q is duplicated", chart.ValuesPath))
		}
		seenIDs[chart.ID] = struct{}{}
		seenValues[chart.ValuesPath] = struct{}{}
		validateRelative(problems, "platform chart "+chart.ID+" Flux source", chart.FluxSource)
		validateChartSource(problems, "platform chart "+chart.ID, chart.Source)
	}
}

func validateBundledChartInventory(problems *[]string, registry Registry, bootstrap []Chart, tracked []TrackedChart) {
	seenIDs := make(map[string]string, len(bootstrap)+len(tracked))
	seenFiles := make(map[string]string, len(bootstrap)+len(tracked))
	seenTargets := make(map[string]string, len(bootstrap)+len(tracked))
	add := func(id, name, version, file, target string) {
		claim := func(label, value string, seen map[string]string) {
			if previous, duplicate := seen[value]; duplicate {
				*problems = append(*problems, fmt.Sprintf("bundled chart %s %q is shared by %s and %s", label, value, previous, id))
			}
			seen[value] = id
		}
		claim("id", id, seenIDs)
		claim("file", file, seenFiles)
		claim("target", target, seenTargets)
		expectedFile := name + "-" + version + ".tgz"
		expectedTarget := registry.Host + "/" + registry.Project + "/" + name + ":" + version
		if file != expectedFile || target != expectedTarget {
			*problems = append(*problems, fmt.Sprintf("bundled chart %s does not match internal file and target naming", id))
		}
	}
	for _, chart := range bootstrap {
		add(chart.ID, chart.Name, chart.Version, chart.File, chart.Target)
	}
	for _, chart := range tracked {
		filename := chart.Name + "-" + chart.Version + ".tgz"
		target := registry.Host + "/" + registry.Project + "/" + chart.Name + ":" + chart.Version
		add(chart.ID, chart.Name, chart.Version, filename, target)
	}
}

func validateVendors(problems *[]string, vendors []Vendor) {
	seen := make(map[string]struct{}, len(vendors))
	for i := range vendors {
		vendor := &vendors[i]
		if vendor.ID == "" || strings.ContainsAny(vendor.ID, `/\\`) || vendor.ID == "." || vendor.ID == ".." ||
			vendor.Owner == "" || vendor.Subpath == "" || !validHexSHA256(vendor.TreeSHA256) {
			*problems = append(*problems, fmt.Sprintf("platform vendor %d has invalid identity", i))
		}
		if _, exists := seen[vendor.ID]; exists {
			*problems = append(*problems, fmt.Sprintf("platform vendor id %q is duplicated", vendor.ID))
		}
		seen[vendor.ID] = struct{}{}
		validateRelative(problems, "platform vendor "+vendor.ID+" directory", vendor.Directory)
		validateRelative(problems, "platform vendor "+vendor.ID+" subpath", vendor.Subpath)
		validateGitSource(problems, "platform vendor "+vendor.ID, vendor.Source)
		for _, patch := range vendor.Patches {
			validateRelative(problems, "platform vendor "+vendor.ID+" patch", patch)
		}
	}
}

func validateChartSource(problems *[]string, label string, source ChartSource) {
	switch source.Type {
	case "oci":
		if !strings.HasPrefix(source.URL, "oci://") || !validDigest(source.Digest) || source.IndexURL != "" {
			*problems = append(*problems, fmt.Sprintf("%s has invalid OCI source", label))
		}
	case "https":
		if !strings.HasPrefix(source.URL, "https://") || !strings.HasPrefix(source.IndexURL, "https://") || source.Digest != "" {
			*problems = append(*problems, fmt.Sprintf("%s has invalid HTTPS source", label))
		}
	default:
		*problems = append(*problems, fmt.Sprintf("%s has unsupported source type %q", label, source.Type))
	}
}

func desiredConstraints(desired *Document) []CompatibilityConstraint {
	constraints := make([]CompatibilityConstraint, 0, 1+len(desired.Platform.Packages)+len(desired.Platform.Charts)+len(desired.Platform.Bootstrap.Charts))
	if desired.Platform.BigBang.KubeVersion != "" {
		constraints = append(constraints, CompatibilityConstraint{ID: "bigbang", Constraint: desired.Platform.BigBang.KubeVersion})
	}
	for _, pkg := range desired.Platform.Packages {
		if pkg.Source.KubeVersion != "" {
			constraints = append(constraints, CompatibilityConstraint{ID: "package/" + pkg.ID, Constraint: pkg.Source.KubeVersion})
		}
	}
	for _, chart := range desired.Platform.Charts {
		if chart.KubeVersion != "" {
			constraints = append(constraints, CompatibilityConstraint{ID: "chart/" + chart.ID, Constraint: chart.KubeVersion})
		}
	}
	for _, chart := range desired.Platform.Bootstrap.Charts {
		if chart.KubeVersion != "" {
			constraints = append(constraints, CompatibilityConstraint{ID: "bootstrap/" + chart.ID, Constraint: chart.KubeVersion})
		}
	}
	sort.Slice(constraints, func(i, j int) bool { return constraints[i].ID < constraints[j].ID })
	return constraints
}

func validateClusterReleases(problems *[]string, releases []ClusterRelease) {
	if len(releases) == 0 {
		*problems = append(*problems, "orchestration requires at least one exact cluster release")
		return
	}
	var previousKubernetes, previousKubespray *semver.Version
	var kubesprayURL string
	for index := range releases {
		release := releases[index]
		label := fmt.Sprintf("orchestration release %d", index)
		kubernetes, err := semver.NewVersion(strings.TrimPrefix(release.Kubernetes, "v"))
		if err != nil || kubernetes.Prerelease() != "" || release.Kubernetes != kubernetes.String() {
			*problems = append(*problems, fmt.Sprintf("%s Kubernetes version %q is not a canonical stable release", label, release.Kubernetes))
		}
		validateGitSource(problems, label+" Kubespray", release.Kubespray)
		kubespray, kubesprayErr := semver.NewVersion(strings.TrimPrefix(release.Kubespray.Version, "v"))
		if kubesprayErr != nil || kubespray.Prerelease() != "" {
			*problems = append(*problems, fmt.Sprintf("%s Kubespray version %q is not a stable semantic release", label, release.Kubespray.Version))
		}
		if index == 0 {
			kubesprayURL = release.Kubespray.URL
		} else if release.Kubespray.URL != kubesprayURL {
			*problems = append(*problems, fmt.Sprintf("%s changes the Kubespray repository", label))
		}
		for name, checksum := range map[string]string{
			"kubeadm": release.Checksums.Kubeadm,
			"kubectl": release.Checksums.Kubectl,
			"kubelet": release.Checksums.Kubelet,
		} {
			if !validDigest(checksum) {
				*problems = append(*problems, fmt.Sprintf("%s %s checksum is invalid", label, name))
			}
		}
		if previousKubernetes != nil && err == nil {
			minorDelta := int64(kubernetes.Minor()) - int64(previousKubernetes.Minor())
			if !kubernetes.GreaterThan(previousKubernetes) || kubernetes.Major() != previousKubernetes.Major() ||
				minorDelta < 0 || minorDelta > 1 {
				*problems = append(*problems, fmt.Sprintf("%s must advance Kubernetes by a patch or exactly one minor from %s", label, previousKubernetes))
			}
			if previousKubespray != nil && kubesprayErr == nil {
				kubesprayMinorDelta := int64(kubespray.Minor()) - int64(previousKubespray.Minor())
				if kubespray.Major() != previousKubespray.Major() || kubespray.LessThan(previousKubespray) ||
					kubesprayMinorDelta != minorDelta {
					*problems = append(*problems, fmt.Sprintf("%s Kubespray release does not align with Kubernetes progression from %s", label, previousKubernetes))
				}
			}
		}
		if err == nil {
			previousKubernetes = kubernetes
		}
		if kubesprayErr == nil {
			previousKubespray = kubespray
		}
	}
}

func validateGitSource(problems *[]string, name string, source GitSource) {
	if !strings.HasPrefix(source.URL, "https://") || source.Version == "" || len(source.Commit) != 40 {
		*problems = append(*problems, fmt.Sprintf("%s source requires URL, version, and 40-character commit", name))
		return
	}
	if source.Ref != "" && strings.TrimPrefix(source.Ref, "v") != strings.TrimPrefix(source.Version, "v") {
		*problems = append(*problems, fmt.Sprintf("%s ref %q does not identify version %q", name, source.Ref, source.Version))
	}
	if source.Branch != "" && (!validGitBranch(source.Branch) || source.Ref != "") {
		*problems = append(*problems, fmt.Sprintf("%s branch %q is invalid or conflicts with ref", name, source.Branch))
	}
	for _, char := range source.Commit {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			*problems = append(*problems, fmt.Sprintf("%s commit must be lowercase hexadecimal", name))
			break
		}
	}
	for _, patch := range source.Patches {
		validateRelative(problems, name+" patch", patch)
	}
	assetIDs := make(map[string]struct{}, len(source.Assets))
	assetFiles := make(map[string]struct{}, len(source.Assets))
	for i, asset := range source.Assets {
		if asset.ID == "" || !strings.HasPrefix(asset.URL, "https://") || !validHexSHA256(asset.SourceSHA256) || !validHexSHA256(asset.SHA256) {
			*problems = append(*problems, fmt.Sprintf("%s asset %d has invalid identity", name, i))
		}
		validateRelative(problems, name+" asset "+asset.ID, asset.File)
		if _, exists := assetIDs[asset.ID]; exists {
			*problems = append(*problems, fmt.Sprintf("%s asset id %q is duplicated", name, asset.ID))
		}
		if _, exists := assetFiles[asset.File]; exists {
			*problems = append(*problems, fmt.Sprintf("%s asset file %q is duplicated", name, asset.File))
		}
		assetIDs[asset.ID] = struct{}{}
		assetFiles[asset.File] = struct{}{}
	}
}

func validateSourceRegistry(problems *[]string, sources SourceRegistry) {
	for label, raw := range map[string]string{
		"external URL": sources.ExternalURL,
		"cluster URL":  sources.ClusterURL,
	} {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			*problems = append(*problems, fmt.Sprintf("platform source %s must be an HTTP(S) origin", label))
		}
	}
	for label, value := range map[string]string{
		"organization":          sources.Organization,
		"repository":            sources.Repository,
		"upstream organization": sources.UpstreamOrganization,
	} {
		if !fssecure.ValidName(value) {
			*problems = append(*problems, fmt.Sprintf("platform source %s %q is invalid", label, value))
		}
	}
}

func validateSeedPlane(
	problems *[]string,
	sources SourceRegistry,
	registry Registry,
	policy DeliveryPolicy,
	seed SeedPlane,
) {
	if seed.Forgejo.URL != sources.ExternalURL || seed.Forgejo.URL != sources.ClusterURL {
		*problems = append(*problems, "seed Forgejo URL must be the exact external and cluster source origin")
	}
	registryScheme := "https://"
	if !registry.TLSVerify {
		registryScheme = "http://"
	}
	if seed.Harbor.URL != registryScheme+registry.Host {
		*problems = append(*problems, "seed Harbor URL must match the delivery registry transport and host")
	}
	if !strings.HasPrefix(seed.Harbor.Version, "v") || strings.ContainsAny(seed.Harbor.Version, `/\\@:`) {
		*problems = append(*problems, "seed Harbor version must be a canonical v-prefixed release")
	}
	installer := seed.Harbor.Installer
	expectedInstaller := "harbor-online-installer-" + seed.Harbor.Version + ".tgz"
	installerURL, installerErr := url.Parse(installer.URL)
	if installerErr != nil || installerURL.Scheme != "https" || installerURL.User != nil || installerURL.RawQuery != "" ||
		installerURL.Fragment != "" || filepath.Base(installerURL.Path) != expectedInstaller ||
		installer.File != expectedInstaller || !validHexSHA256(installer.SHA256) ||
		installer.Size < 1 || installer.Size > SeedAssetLimit {
		*problems = append(*problems, "seed Harbor installer has an invalid exact release identity")
	}
	wantedHarbor := map[string]string{
		"harbor-prepare":     "docker.io/goharbor/prepare",
		"harbor-log":         "docker.io/goharbor/harbor-log",
		"harbor-nginx":       "docker.io/goharbor/nginx-photon",
		"harbor-portal":      "docker.io/goharbor/harbor-portal",
		"harbor-core":        "docker.io/goharbor/harbor-core",
		"harbor-jobservice":  "docker.io/goharbor/harbor-jobservice",
		"harbor-registry":    "docker.io/goharbor/registry-photon",
		"harbor-registryctl": "docker.io/goharbor/harbor-registryctl",
		"harbor-database":    "docker.io/goharbor/harbor-db",
		"harbor-redis":       "docker.io/goharbor/valkey-photon",
	}
	seen := make(map[string]struct{}, len(wantedHarbor)+1)
	validateImage := func(label string, image SeedImage, version string) {
		if !validResourceID(image.ID) || !validDigest(image.Digest) || mutableImageReference(image.Source) ||
			(version != "" && !strings.HasSuffix(image.Source, ":"+version)) {
			*problems = append(*problems, fmt.Sprintf("%s image %q has an invalid exact source identity", label, image.ID))
		}
		for _, prefix := range policy.ForbiddenArtifactPrefixes {
			if strings.HasPrefix(image.Source, prefix) {
				*problems = append(*problems, fmt.Sprintf("%s image %s uses forbidden source %s", label, image.ID, image.Source))
			}
		}
		if _, duplicate := seen[image.ID]; duplicate {
			*problems = append(*problems, fmt.Sprintf("seed image id %q is duplicated", image.ID))
		}
		seen[image.ID] = struct{}{}
	}
	validateImage("seed Forgejo", seed.Forgejo.Image, "")
	if seed.Forgejo.Image.ID != "forgejo" ||
		!strings.HasPrefix(seed.Forgejo.Image.Source, "code.forgejo.org/forgejo/forgejo:") ||
		!strings.HasSuffix(seed.Forgejo.Image.Source, "-rootless") {
		*problems = append(*problems, "seed Forgejo must use the official rootless Forgejo image")
	}
	for _, image := range seed.Harbor.Images {
		validateImage("seed Harbor", image, seed.Harbor.Version)
		repository, expected := wantedHarbor[image.ID]
		if !expected {
			*problems = append(*problems, fmt.Sprintf("seed Harbor image id %q is unsupported", image.ID))
		} else if image.Source != repository+":"+seed.Harbor.Version {
			*problems = append(*problems, fmt.Sprintf("seed Harbor image %s must use %s", image.ID, repository))
		}
		delete(wantedHarbor, image.ID)
	}
	if len(wantedHarbor) != 0 {
		missing := make([]string, 0, len(wantedHarbor))
		for id := range wantedHarbor {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		*problems = append(*problems, "seed Harbor image inventory omits "+strings.Join(missing, ", "))
	}
}

func validResourceID(value string) bool {
	if value == "" {
		return false
	}
	first := value[0]
	if (first < 'a' || first > 'z') && (first < '0' || first > '9') {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validateLocalAccess(problems *[]string, target string, access LocalAccess) {
	label := "infrastructure target " + target + " local access "
	baseDomainValid := validDNSDomain(access.Domain)
	if !baseDomainValid {
		*problems = append(*problems, label+"domain must be a lowercase DNS domain")
	}
	if len(access.PassthroughHosts) > MaxPassthroughHosts {
		*problems = append(*problems, fmt.Sprintf(
			"%spassthrough hosts must contain at most %d labels",
			label, MaxPassthroughHosts,
		))
	}
	seenHosts := make(map[string]struct{},
		min(len(access.PassthroughHosts), MaxPassthroughHosts))
	keycloakHosts := 0
	for _, host := range access.PassthroughHosts {
		hostValid := validDNSLabel(host)
		if !hostValid {
			*problems = append(*problems, fmt.Sprintf("%spassthrough host %q must be a lowercase DNS label", label, host))
		} else if baseDomainValid && !validDNSDomain(host+"."+access.Domain) {
			*problems = append(*problems, fmt.Sprintf(
				"%spassthrough host %q with domain %q must form a valid DNS domain",
				label, host, access.Domain,
			))
		}
		if host == "keycloak" {
			keycloakHosts++
		}
		if _, duplicate := seenHosts[host]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%spassthrough host %q is duplicated", label, host))
		}
		seenHosts[host] = struct{}{}
	}
	if keycloakHosts != 1 {
		*problems = append(*problems, label+"must contain passthrough host \"keycloak\" exactly once")
	}

	static := []struct {
		name  string
		value string
	}{
		{name: "DNS server", value: access.DNSServer},
		{name: "public ingress VIP", value: access.PublicIngressVIP},
		{name: "passthrough ingress VIP", value: access.PassthroughIngressVIP},
	}
	type namedAddress struct {
		name    string
		address netip.Addr
	}
	staticAddresses := make([]namedAddress, 0, len(static))
	for i := range static {
		address, err := netip.ParseAddr(static[i].value)
		if err != nil || !address.Is4() {
			*problems = append(*problems, fmt.Sprintf("%s%s %q must be an IPv4 address", label, static[i].name, static[i].value))
			continue
		}
		staticAddresses = append(staticAddresses, namedAddress{name: static[i].name, address: address})
	}
	owners := make(map[netip.Addr]string, len(staticAddresses))
	for _, staticAddress := range staticAddresses {
		if previous, duplicate := owners[staticAddress.address]; duplicate {
			*problems = append(*problems, fmt.Sprintf("%s%s duplicates %s at %s", label, staticAddress.name, previous, staticAddress.address))
		} else {
			owners[staticAddress.address] = staticAddress.name
		}
	}

	first, last, validRange := parseIPv4Range(problems, label, access.LoadBalancerRange)
	if !validRange {
		return
	}
	if first.Compare(last) > 0 {
		*problems = append(*problems, fmt.Sprintf("%sload-balancer range %q must be ascending", label, access.LoadBalancerRange))
		return
	}
	for _, staticAddress := range staticAddresses {
		if staticAddress.address.Compare(first) >= 0 && staticAddress.address.Compare(last) <= 0 {
			*problems = append(*problems, fmt.Sprintf("%sload-balancer range overlaps the %s at %s", label, staticAddress.name, staticAddress.address))
		}
	}
}

func parseIPv4Range(problems *[]string, label, value string) (netip.Addr, netip.Addr, bool) {
	firstValue, lastValue, found := strings.Cut(value, "-")
	if !found || firstValue == "" || lastValue == "" || strings.Contains(lastValue, "-") {
		*problems = append(*problems, fmt.Sprintf("%sload-balancer range %q must contain two IPv4 addresses separated by a hyphen", label, value))
		return netip.Addr{}, netip.Addr{}, false
	}
	first, firstErr := netip.ParseAddr(firstValue)
	last, lastErr := netip.ParseAddr(lastValue)
	if firstErr != nil || lastErr != nil || !first.Is4() || !last.Is4() {
		*problems = append(*problems, fmt.Sprintf("%sload-balancer range %q must contain two IPv4 addresses", label, value))
		return netip.Addr{}, netip.Addr{}, false
	}
	return first, last, true
}

func validDNSDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validGitBranch(branch string) bool {
	return branch != "" &&
		!strings.HasPrefix(branch, ".") &&
		!strings.HasSuffix(branch, ".") &&
		!strings.HasSuffix(branch, "/") &&
		!strings.HasSuffix(branch, ".lock") &&
		!strings.ContainsAny(branch, " \\~^:?*[") &&
		!strings.Contains(branch, "..") &&
		!strings.Contains(branch, "@{") &&
		!strings.Contains(branch, "//")
}

func projectGitSources(desired *Document) map[string]GitSource {
	sources := make(map[string]GitSource, 2+len(desired.Orchestration.Releases)+len(desired.Platform.Packages)+len(desired.Platform.Vendors))
	for _, release := range desired.Orchestration.Releases {
		sources["Kubespray "+release.Kubernetes] = release.Kubespray
	}
	sources["Big Bang"] = desired.Platform.BigBang
	sources["Flux"] = desired.Platform.Flux
	for _, pkg := range desired.Platform.Packages {
		sources["package "+pkg.ID] = pkg.Source
	}
	for _, vendor := range desired.Platform.Vendors {
		sources["vendor "+vendor.ID] = vendor.Source
	}
	return sources
}

func validateRelative(problems *[]string, field, value string) {
	if _, err := fssecure.Relative(value); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s must be a non-empty project-relative path", field))
	}
}

func statProjectPath(root, relative string) (os.FileInfo, error) {
	path, err := fssecure.Resolve(root, relative, false)
	if err != nil {
		return nil, err
	}
	return os.Stat(path)
}

func candidateFileInfo(root, relative string, files map[string][]byte) (os.FileInfo, error) {
	if data, exists := files[relative]; exists {
		return candidateInfo{name: filepath.Base(relative), size: int64(len(data))}, nil
	}
	return statProjectPath(root, relative)
}

type candidateInfo struct {
	name string
	size int64
}

func (info candidateInfo) Name() string  { return info.name }
func (info candidateInfo) Size() int64   { return info.size }
func (candidateInfo) Mode() os.FileMode  { return 0o644 }
func (candidateInfo) ModTime() time.Time { return time.Time{} }
func (candidateInfo) IsDir() bool        { return false }
func (candidateInfo) Sys() any           { return nil }

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validHexSHA256(strings.TrimPrefix(value, "sha256:"))
}

func validHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := range len(value) {
		character := value[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateSchemas(root string, desiredData, lockData []byte) error {
	type resource struct {
		filename     string
		id           string
		instanceName string
		instance     []byte
	}
	resources := [...]resource{
		{filename: "atum.schema.json", id: desiredSchemaID, instanceName: DesiredFilename, instance: desiredData},
		{filename: "atum.lock.schema.json", id: lockSchemaID, instanceName: LockFilename, instance: lockData},
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	documents := make([]any, len(resources))
	for i := range resources {
		path, pathErr := fssecure.Resolve(root, resources[i].filename, false)
		if pathErr != nil {
			return fmt.Errorf("resolve %s: %w", resources[i].filename, pathErr)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", resources[i].filename, err)
		}
		if err := json.Unmarshal(data, &documents[i]); err != nil {
			return fmt.Errorf("decode %s: %w", resources[i].filename, err)
		}
		if err := compiler.AddResource(resources[i].id, documents[i]); err != nil {
			return fmt.Errorf("load %s: %w", resources[i].filename, err)
		}
	}
	for i := range resources {
		schema, err := compiler.Compile(resources[i].id)
		if err != nil {
			return fmt.Errorf("compile %s: %w", resources[i].filename, err)
		}
		var instance any
		if err := json.Unmarshal(resources[i].instance, &instance); err != nil {
			return fmt.Errorf("decode %s: %w", resources[i].filename, err)
		}
		if err := schema.Validate(instance); err != nil {
			return fmt.Errorf("validate %s with %s: %w", resources[i].instanceName, resources[i].filename, err)
		}
	}
	return nil
}

// DecodeJSON decodes exactly one JSON value and rejects unknown fields.
func DecodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON documents are not allowed")
		}
		return err
	}
	return nil
}

func SHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fileSHA256(path string) (string, error) {
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

func WriteJSONAtomic(filename string, value any, mode os.FileMode) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode %s: %w", filename, err)
	}
	directory := filepath.Dir(filename)
	file, err := os.CreateTemp(directory, ".atum-json-")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", filename, err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if _, err := file.Write(buffer.Bytes()); err != nil {
		file.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporary, filename); err != nil {
		return fmt.Errorf("replace %s: %w", filename, err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}
