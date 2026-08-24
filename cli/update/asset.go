package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"atum/cli/config"
	"atum/cli/fssecure"
)

// FetchSeedAsset returns one checksum-pinned, size-bounded bootstrap asset
// from the project cache. The cache name is content-addressed and every reuse
// is streamed through the expected digest before it is returned.
func FetchSeedAsset(ctx context.Context, root string, asset config.SeedAsset) (string, error) {
	cacheRelative := filepath.Join(".atum", "cache", "seed-assets")
	if _, err := fssecure.EnsureDirectory(root, cacheRelative, 0o700); err != nil {
		return "", fmt.Errorf("create seed asset cache: %w", err)
	}
	relative := filepath.Join(cacheRelative, asset.SHA256+"-"+filepath.Base(asset.File))
	if err := verifySeedAsset(root, relative, asset); err == nil {
		return fssecure.Resolve(root, relative, false)
	} else if !os.IsNotExist(err) {
		if removeErr := fssecure.RemoveRegular(root, relative); removeErr != nil && !os.IsNotExist(removeErr) {
			return "", fmt.Errorf("replace invalid seed asset cache: %w", removeErr)
		}
	}

	client := newChartClient(root)
	body, err := client.openHTTPS(ctx, asset.URL)
	if err != nil {
		return "", err
	}
	defer body.Close()
	hash := sha256.New()
	var written int64
	err = fssecure.CreateRegularWith(root, relative, 0o600, func(destination io.Writer) error {
		limited := &io.LimitedReader{R: body, N: config.SeedAssetLimit + 1}
		var copyErr error
		written, copyErr = io.Copy(io.MultiWriter(destination, hash), limited)
		if copyErr != nil {
			return copyErr
		}
		if written > config.SeedAssetLimit {
			return fmt.Errorf("seed asset %s exceeds %d bytes", asset.URL, config.SeedAssetLimit)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("cache seed asset %s: %w", asset.URL, err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if written != asset.Size || actual != asset.SHA256 {
		_ = fssecure.RemoveRegular(root, relative)
		return "", fmt.Errorf("seed asset %s is %s/%d, want %s/%d", asset.URL, actual, written, asset.SHA256, asset.Size)
	}
	return fssecure.Resolve(root, relative, false)
}

func verifySeedAsset(root, relative string, asset config.SeedAsset) error {
	file, err := fssecure.OpenRegular(root, relative)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != asset.Size || info.Size() < 1 || info.Size() > config.SeedAssetLimit {
		return fmt.Errorf("cached seed asset has size %d, want %d", info.Size(), asset.Size)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return err
	}
	if written != asset.Size || hex.EncodeToString(hash.Sum(nil)) != asset.SHA256 {
		return fmt.Errorf("cached seed asset does not match %s", asset.SHA256)
	}
	return nil
}
