package orchestration

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

const installInventoryMax = 16 << 20

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("receipt contains multiple JSON values")
		}
		return err
	}
	return nil
}

func (service Service) installInventoryPath() string {
	return filepath.Join(
		service.Project.Desired.Orchestration.Inventory,
		"hosts.yaml",
	)
}

func validCheckpointSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
