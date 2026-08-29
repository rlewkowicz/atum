package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/gitsnapshot"
	atumoci "atum/cli/oci"
	"atum/cli/update"

	"github.com/go-git/go-git/v5/plumbing/filemode"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
)

const (
	publicationReceiptPath   = ".atum/state/publication.lock.json"
	publicationReceiptSchema = "atum.dev/publication/v2"
)

type ArtifactIdentity struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Chart struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	Target         string `json:"target"`
	ArchiveSHA256  string `json:"archiveSha256"`
	ManifestDigest string `json:"manifestDigest"`
	Size           int64  `json:"size"`
	Path           string `json:"-"`
}

type Image struct {
	config.LockedImage
	Store oras.ReadOnlyTarget `json:"-"`
}

type Publication struct {
	SourceRoot     string
	SourceCommit   string
	SourceTag      string
	SourceSHA256   string
	Images         []Image
	Charts         []Chart
	Seed           ArtifactIdentity
	KubesprayFiles FileManifest
	Delivery       config.ImageLock
}

type Receipt struct {
	SchemaVersion   string               `json:"schemaVersion"`
	DesiredSHA256   string               `json:"desiredSha256"`
	RootLockSHA256  string               `json:"rootLockSha256"`
	SourceSHA256    string               `json:"sourceSha256"`
	SourceCommit    string               `json:"sourceCommit"`
	SourceTag       string               `json:"sourceTag"`
	Delivery        config.ImageLock     `json:"delivery"`
	Charts          []Chart              `json:"charts"`
	Seed            ArtifactIdentity     `json:"seed"`
	KubesprayFiles FileManifestIdentity `json:"kubesprayFiles"`
}

func (service *Service) Prepare(ctx context.Context, options PreparationOptions) (*config.Project, *Publication, error) {
	unlock, err := update.LockProject(ctx, service.root)
	if err != nil {
		return nil, nil, fmt.Errorf("lock project state: %w", err)
	}
	defer unlock()
	if err := update.RecoverLocked(service.root); err != nil {
		return nil, nil, fmt.Errorf("recover interrupted update: %w", err)
	}
	project, err := config.Load(service.root)
	if err != nil {
		return nil, nil, err
	}
	if err := config.ValidateSourceSnapshot(project); err != nil {
		return nil, nil, fmt.Errorf("validate exact source handoff: %w", err)
	}
	local, err := service.resolveLocalDelivery(ctx, project, options)
	if err != nil {
		return nil, nil, err
	}
	if !project.Lock.Delivery.Pending() &&
		!matchesCommittedDelivery(local.lock, project.Lock.Delivery) {
		return nil, nil, errors.New(
			"local publication graph differs from the committed delivery lock",
		)
	}
	project.Lock.Delivery = local.lock
	sourceRoot, sourceIdentity, err := materializePublicationSource(project)
	if err != nil {
		return nil, nil, err
	}
	images, err := publicationImages(project, local)
	if err != nil {
		return nil, nil, err
	}
	charts, err := publicationCharts(project)
	if err != nil {
		return nil, nil, err
	}
	seed, err := service.prepareSeed(ctx, project, local)
	if err != nil {
		return nil, nil, err
	}
	files, err := MaterializeFileManifest(project)
	if err != nil {
		return nil, nil, err
	}
	return project, &Publication{
		SourceRoot:     sourceRoot,
		SourceCommit:   sourceIdentity.Commit,
		SourceTag:      "source-sha256-" + sourceIdentity.SHA256,
		SourceSHA256:   sourceIdentity.SHA256,
		Images:         images,
		Charts:         charts,
		Seed:           seed,
		KubesprayFiles: files,
		Delivery:       local.lock,
	}, nil
}

func materializePublicationSource(
	project *config.Project,
) (string, gitsnapshot.Identity, error) {
	snapshot, err := gitsnapshot.Load(project.Root)
	if err != nil {
		return "", gitsnapshot.Identity{}, err
	}
	identity, err := snapshot.Identity(nil)
	if err != nil {
		return "", gitsnapshot.Identity{}, err
	}
	relative := filepath.Join(
		".atum", "state", "publications", identity.SHA256, "source",
	)
	if err := fssecure.RemoveTree(project.Root, relative); err != nil {
		return "", gitsnapshot.Identity{}, err
	}
	root, err := fssecure.EnsureDirectory(project.Root, relative, 0o700)
	if err != nil {
		return "", gitsnapshot.Identity{}, err
	}
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	for _, entry := range snapshot.Files {
		name, err := cleanArchiveName(entry.Name)
		if err != nil {
			return "", gitsnapshot.Identity{}, err
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return "", gitsnapshot.Identity{}, err
		}
		switch entry.Mode {
		case filemode.Regular, filemode.Deprecated:
			if err := materializeGitFile(entry, target, 0o644, *buffer); err != nil {
				return "", gitsnapshot.Identity{}, err
			}
		case filemode.Executable:
			if err := materializeGitFile(entry, target, 0o755, *buffer); err != nil {
				return "", gitsnapshot.Identity{}, err
			}
		case filemode.Symlink:
			link, err := entry.Contents()
			if err != nil || !containedLink(name, link) {
				if err != nil {
					return "", gitsnapshot.Identity{}, err
				}
				return "", gitsnapshot.Identity{}, fmt.Errorf(
					"Git symlink %s escapes through %s", name, link,
				)
			}
			if err := os.Symlink(link, target); err != nil {
				return "", gitsnapshot.Identity{}, err
			}
		default:
			return "", gitsnapshot.Identity{}, fmt.Errorf(
				"Git source contains unsupported mode %s at %s",
				entry.Mode,
				name,
			)
		}
	}
	return root, identity, nil
}

func publicationImages(
	project *config.Project,
	local localDelivery,
) ([]Image, error) {
	images := make([]Image, len(local.lock.Images))
	for index, locked := range local.lock.Images {
		var store oras.ReadOnlyTarget
		if mirror, found := local.mirrors[locked.ID]; found {
			store = mirror.store
		} else if build, found := local.builds[locked.ID]; found {
			store = build.store
		} else {
			return nil, fmt.Errorf(
				"canonical local publication input for image %s is missing",
				locked.ID,
			)
		}
		images[index] = Image{LockedImage: locked, Store: store}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
	if len(images) != len(project.Desired.Delivery.Images) {
		return nil, errors.New("canonical local image publication graph is incomplete")
	}
	return images, nil
}

func publicationCharts(project *config.Project) ([]Chart, error) {
	charts := make([]Chart, len(project.Lock.Resolved.Artifacts))
	for index, artifact := range project.Lock.Resolved.Artifacts {
		path, err := fssecure.Resolve(project.Root, artifact.File, false)
		if err != nil {
			return nil, err
		}
		charts[index] = Chart{
			ID:            artifact.ID,
			Name:          artifact.Name,
			Version:       artifact.Version,
			Target:        artifact.Target,
			ArchiveSHA256: artifact.ArchiveSHA256,
			Size:          artifact.Size,
			Path:          path,
		}
	}
	sort.Slice(charts, func(i, j int) bool { return charts[i].ID < charts[j].ID })
	return charts, nil
}

func SaveReceipt(project *config.Project, publication *Publication) error {
	if project == nil || publication == nil {
		return errors.New("complete publication is required")
	}
	receipt := Receipt{
		SchemaVersion:   publicationReceiptSchema,
		DesiredSHA256:   project.DesiredSHA256,
		RootLockSHA256:  config.SHA256(project.LockData),
		SourceSHA256:    publication.SourceSHA256,
		SourceCommit:    publication.SourceCommit,
		SourceTag:       publication.SourceTag,
		Delivery:        publication.Delivery,
		Charts:          append([]Chart(nil), publication.Charts...),
		Seed:            publication.Seed,
		KubesprayFiles:  publication.KubesprayFiles.Identity,
	}
	for index := range receipt.Charts {
		if !validPublicationDigest(receipt.Charts[index].ManifestDigest) {
			return fmt.Errorf(
				"chart %s has no exact Harbor publication result",
				receipt.Charts[index].ID,
			)
		}
		receipt.Charts[index].Path = ""
	}
	data, err := config.MarshalJSON(receipt)
	if err != nil {
		return err
	}
	return fssecure.WriteRegular(project.Root, publicationReceiptPath, data, 0o600)
}

func LoadReceipt(project *config.Project) (Receipt, error) {
	if project == nil {
		return Receipt{}, errors.New("Atum project is not loaded")
	}
	file, err := fssecure.OpenRegular(project.Root, publicationReceiptPath)
	if err != nil {
		return Receipt{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return Receipt{}, err
	}
	if info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return Receipt{}, fmt.Errorf(
			"publication receipt mode is %04o, want 0600",
			info.Mode().Perm(),
		)
	}
	defer file.Close()
	var receipt Receipt
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Receipt{}, errors.New("publication receipt contains multiple values")
		}
		return Receipt{}, err
	}
	snapshot, err := gitsnapshot.Load(project.Root)
	if err != nil {
		return Receipt{}, err
	}
	source, err := snapshot.Identity(nil)
	if err != nil {
		return Receipt{}, err
	}
	files, err := MaterializeFileManifest(project)
	if err != nil {
		return Receipt{}, fmt.Errorf("materialize Kubespray files receipt identity: %w", err)
	}
	if receipt.SchemaVersion != publicationReceiptSchema ||
		receipt.DesiredSHA256 != project.DesiredSHA256 ||
		receipt.RootLockSHA256 != config.SHA256(project.LockData) ||
		receipt.SourceSHA256 != source.SHA256 ||
		receipt.SourceCommit != source.Commit ||
		receipt.SourceTag != "source-sha256-"+source.SHA256 ||
		len(receipt.Delivery.Images) != len(project.Desired.Delivery.Images) ||
		len(receipt.Charts) != len(project.Lock.Resolved.Artifacts) ||
		receipt.Seed.File != filepath.ToSlash(filepath.Join(
			".atum",
			"artifacts",
			"seed",
			"atum-seed-"+receipt.Seed.SHA256+".tar",
		)) ||
		receipt.Seed.SHA256 == "" ||
		receipt.Seed.Size <= 0 ||
		!validFileManifestReceipt(receipt.KubesprayFiles, files.Identity) {
		return Receipt{}, errors.New("local publication receipt is absent or stale")
	}
	runtime := *project
	runtime.Lock.Delivery = receipt.Delivery
	if err := runtime.Validate(); err != nil {
		return Receipt{}, fmt.Errorf("validate local publication receipt: %w", err)
	}
	artifacts := make(map[string]config.ChartArtifact, len(project.Lock.Resolved.Artifacts))
	for _, artifact := range project.Lock.Resolved.Artifacts {
		if _, duplicate := artifacts[artifact.ID]; duplicate {
			return Receipt{}, fmt.Errorf("locked chart %s is duplicated", artifact.ID)
		}
		artifacts[artifact.ID] = artifact
	}
	seenCharts := make(map[string]struct{}, len(receipt.Charts))
	for _, chart := range receipt.Charts {
		artifact, found := artifacts[chart.ID]
		if !found {
			return Receipt{}, fmt.Errorf("publication chart %s is not locked", chart.ID)
		}
		if _, duplicate := seenCharts[chart.ID]; duplicate {
			return Receipt{}, fmt.Errorf("publication chart %s is duplicated", chart.ID)
		}
		seenCharts[chart.ID] = struct{}{}
		if chart.Name != artifact.Name ||
			chart.Version != artifact.Version ||
			chart.Target != artifact.Target ||
			chart.ArchiveSHA256 != artifact.ArchiveSHA256 ||
			!validPublicationDigest(chart.ManifestDigest) ||
			chart.Size != artifact.Size {
			return Receipt{}, errors.New("local chart publication receipt is stale")
		}
	}
	seed, err := fssecure.OpenRegular(project.Root, receipt.Seed.File)
	if err != nil {
		return Receipt{}, fmt.Errorf("open minimal seed from publication receipt: %w", err)
	}
	digest, size, hashErr := readerSHA256(seed)
	closeErr := seed.Close()
	if hashErr != nil {
		return Receipt{}, hashErr
	}
	if closeErr != nil {
		return Receipt{}, closeErr
	}
	if digest != receipt.Seed.SHA256 || size != receipt.Seed.Size {
		return Receipt{}, errors.New("minimal seed from publication receipt is stale")
	}
	return receipt, nil
}

func validFileManifestReceipt(
	actual FileManifestIdentity,
	expected FileManifestIdentity,
) bool {
	return actual == expected &&
		actual.SHA256 != "" &&
		actual.Count > 0 &&
		actual.Bytes > 0
}

func validPublicationDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func PublishImages(
	ctx context.Context,
	client *atumoci.Client,
	publication *Publication,
	parallelism int,
	report func(string, int64, bool),
) error {
	if publication == nil || len(publication.Images) == 0 {
		return errors.New("canonical image publication inputs are absent")
	}
	return publishPreparedImages(ctx, client, publication.Images, parallelism, report)
}

func publishPreparedImages(
	ctx context.Context,
	client *atumoci.Client,
	images []Image,
	parallelism int,
	report func(string, int64, bool),
) error {
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism,
		0,
		config.DefaultWorkLimit,
	))
	for index := range images {
		image := images[index]
		group.Go(func() error {
			descriptor, resolveErr := client.Resolve(
				groupContext,
				image.Target,
			)
			if resolveErr == nil {
				if descriptor.Digest.String() != image.Digest {
					return fmt.Errorf(
						"immutable Harbor image %s resolves to %s, want %s",
						image.ID,
						descriptor.Digest,
						image.Digest,
					)
				}
				if err := validatePublishedImage(
					groupContext,
					client,
					image,
					descriptor,
				); err != nil {
					return err
				}
				if report != nil {
					report(image.ID, 0, true)
				}
				return nil
			}
			if !errors.Is(resolveErr, errdef.ErrNotFound) {
				return resolveErr
			}
			descriptor, err := client.CopyFromStore(
				groupContext,
				image.Store,
				image.Digest,
				image.Target,
				func(delta int64) {
					if report != nil {
						report(image.ID, delta, false)
					}
				},
			)
			if err != nil {
				return err
			}
			if descriptor.Digest.String() != image.Digest {
				return fmt.Errorf(
					"published image %s resolved to %s, want %s",
					image.ID,
					descriptor.Digest,
					image.Digest,
				)
			}
			if err := validatePublishedImage(
				groupContext,
				client,
				image,
				descriptor,
			); err != nil {
				return err
			}
			if report != nil {
				report(image.ID, 0, true)
			}
			return nil
		})
	}
	return group.Wait()
}

func validatePublishedImage(
	ctx context.Context,
	client *atumoci.Client,
	image Image,
	descriptor ocispec.Descriptor,
) error {
	if image.Delivery.Type == "mirror" {
		if err := client.ValidateLinuxAMD64(
			ctx,
			image.Target,
			descriptor,
		); err != nil {
			return err
		}
	} else if err := client.ValidateLinuxAMD64(
		ctx,
		image.Target,
		descriptor,
	); err != nil {
		return err
	}
	resolved, err := client.Resolve(ctx, image.Target)
	if err != nil {
		return err
	}
	if resolved.Digest.String() != image.Digest {
		return fmt.Errorf(
			"published image %s changed to %s, want %s",
			image.ID,
			resolved.Digest,
			image.Digest,
		)
	}
	return nil
}
