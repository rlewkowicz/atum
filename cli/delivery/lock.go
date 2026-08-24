package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"

	"atum/cli/config"
	"atum/cli/fssecure"
)

func currentEntries(project *config.Project) map[string]config.LockedImage {
	entries := make(map[string]config.LockedImage, len(project.Lock.Delivery.Images))
	for _, entry := range project.Lock.Delivery.Images {
		entries[entry.ID] = entry
	}
	return entries
}

func reusableEntry(
	project *config.Project,
	profile string,
	selected selectedImage,
	entries map[string]config.LockedImage,
) (config.LockedImage, bool) {
	lock := project.Lock.Delivery
	if lock.Profile != profile {
		return config.LockedImage{}, false
	}
	entry, exists := entries[selected.Image.ID]
	if exists && entry.Target == selected.Image.Target &&
		entry.InputSHA256 == selected.InputSHA &&
		reflect.DeepEqual(entry.Delivery, selected.Delivery) {
		return entry, true
	}
	return config.LockedImage{}, false
}

func reusableBundle(project *config.Project, delivery config.ImageLock) (*config.Bundle, error) {
	if project.Lock.Bundle == nil || project.Lock.DesiredSHA256 != project.DesiredSHA256 ||
		!reflect.DeepEqual(delivery, project.Lock.Delivery) {
		return nil, nil
	}
	sourceSHA, err := config.AtumSourceSHA256(project)
	if err != nil {
		return nil, err
	}
	if sourceSHA != project.Lock.Bundle.AtumSourceSHA256 {
		return nil, nil
	}
	bundle := *project.Lock.Bundle
	return &bundle, nil
}

func assembleImageLock(
	project *config.Project,
	profile string,
	inventorySHA string,
	graphSHA string,
	selectedIDs map[string]struct{},
	results map[string]config.LockedImage,
) (config.ImageLock, error) {
	partial := len(selectedIDs) != len(project.Desired.Delivery.Images)
	if partial && (project.Lock.Delivery.Profile != profile ||
		project.Lock.Delivery.InventorySHA256 != inventorySHA ||
		project.Lock.Delivery.GraphSHA256 != graphSHA ||
		len(project.Lock.Delivery.Images) != len(project.Desired.Delivery.Images)) {
		return config.ImageLock{}, fmt.Errorf("partial publication requires a complete current %s image lock", profile)
	}
	images := make([]config.LockedImage, 0, len(project.Desired.Delivery.Images))
	old := currentEntries(project)
	for _, desired := range project.Desired.Delivery.Images {
		entry, published := results[desired.ID]
		if !published {
			if _, selected := selectedIDs[desired.ID]; selected {
				return config.ImageLock{}, fmt.Errorf("selected image %s has no publication result", desired.ID)
			}
			var exists bool
			entry, exists = old[desired.ID]
			if !exists {
				return config.ImageLock{}, fmt.Errorf("unselected image %s has no prior lock entry", desired.ID)
			}
		}
		images = append(images, entry)
	}
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
	counts := config.DeliveryCounts{Total: len(images)}
	for _, image := range images {
		switch image.Delivery.Type {
		case "mirror":
			counts.Mirrored++
		case "build":
			counts.Built++
		default:
			return config.ImageLock{}, fmt.Errorf("image %s has unsupported locked delivery %q", image.ID, image.Delivery.Type)
		}
	}
	return config.ImageLock{
		SchemaVersion:   "atum.dev/image-lock/v3",
		Profile:         profile,
		Platform:        project.Desired.Project.Platform,
		InventorySHA256: inventorySHA,
		GraphSHA256:     graphSHA,
		Counts:          counts,
		Images:          images,
	}, nil
}

func writeRootLock(project *config.Project, delivery config.ImageLock, bundle *config.Bundle) (bool, error) {
	if err := compareFile(project.Root, config.DesiredFilename, project.DesiredData); err != nil {
		return false, fmt.Errorf("desired state changed during image operation: %w", err)
	}
	if err := compareFile(project.Root, config.LockFilename, project.LockData); err != nil {
		return false, fmt.Errorf("resolved state changed during image operation: %w", err)
	}
	graphSHA, err := config.DeliveryGraphSHA256(project, delivery.Profile)
	if err != nil {
		return false, fmt.Errorf("recompute delivery graph: %w", err)
	}
	if graphSHA != delivery.GraphSHA256 {
		return false, fmt.Errorf("delivery graph changed during image operation: found %s, want %s", graphSHA, delivery.GraphSHA256)
	}
	next := project.Lock
	next.DesiredSHA256 = project.DesiredSHA256
	next.Delivery = delivery
	next.Bundle = bundle
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode resolved state: %w", err)
	}
	data = append(data, '\n')
	validation := *project
	validation.Lock = next
	validation.LockData = data
	if err := validation.Validate(); err != nil {
		return false, fmt.Errorf("refuse invalid image lock: %w", err)
	}
	if bytes.Equal(data, project.LockData) {
		return false, nil
	}
	if err := compareFile(project.Root, config.DesiredFilename, project.DesiredData); err != nil {
		return false, fmt.Errorf("desired state changed while preparing image lock: %w", err)
	}
	if err := compareFile(project.Root, config.LockFilename, project.LockData); err != nil {
		return false, fmt.Errorf("resolved state changed while preparing image lock: %w", err)
	}
	graphSHA, err = config.DeliveryGraphSHA256(project, delivery.Profile)
	if err != nil {
		return false, fmt.Errorf("recheck delivery graph before publishing image lock: %w", err)
	}
	if graphSHA != delivery.GraphSHA256 {
		return false, fmt.Errorf("delivery graph changed while preparing image lock: found %s, want %s", graphSHA, delivery.GraphSHA256)
	}
	if bundle != nil {
		sourceSHA, err := config.AtumSourceSHA256(&validation)
		if err != nil {
			return false, fmt.Errorf("recheck deployment source before publishing image lock: %w", err)
		}
		if sourceSHA != bundle.AtumSourceSHA256 {
			return false, fmt.Errorf("deployment source changed while preparing image lock: found %s, want %s", sourceSHA, bundle.AtumSourceSHA256)
		}
	}
	if err := fssecure.ReplaceRegular(project.Root, config.LockFilename, data, 0o644); err != nil {
		return false, err
	}
	project.Lock = next
	project.LockData = data
	return true, nil
}

func compareFile(root, relative string, expected []byte) error {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	want := sha256.Sum256(expected)
	if !bytes.Equal(hash.Sum(nil), want[:]) {
		return fmt.Errorf("%s has checksum %s, want %s", relative, hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(want[:]))
	}
	return nil
}
