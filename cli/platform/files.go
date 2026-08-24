package platform

import (
	"fmt"
	"io"
	"os"
)

// readBounded reads one regular source artifact without allowing an
// unexpectedly large file to become an unbounded allocation.
func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		_ = file.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, fmt.Errorf("%s is not a regular file within %d bytes", path, limit)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) != info.Size() || int64(len(data)) > limit {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	return data, nil
}
