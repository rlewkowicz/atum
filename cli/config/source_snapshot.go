package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"atum/cli/gitsnapshot"
)

// AtumSourceSHA256 identifies the current tracked Atum handoff with the
// deployment bundle field normalized away. The bundle can therefore bind all
// reviewed working-tree source without hashing its own final artifact identity.
func AtumSourceSHA256(project *Project) (string, error) {
	lockData, err := SourceLockData(project)
	if err != nil {
		return "", err
	}
	snapshot, err := gitsnapshot.Load(project.Root)
	if err != nil {
		return "", err
	}
	identity, err := snapshot.SHA256(map[string][]byte{LockFilename: lockData})
	if err != nil {
		return "", fmt.Errorf("identify Atum source snapshot: %w", err)
	}
	return identity, nil
}

// SourceLockData returns the tracked root lock with only the recursive bundle
// result removed. Runtime delivery resolution may use an ignored execution
// lock, so source identity must be derived from the bytes actually present in
// the working tree rather than from an in-memory runtime lock.
func SourceLockData(project *Project) ([]byte, error) {
	if project == nil || len(project.LockData) == 0 {
		return nil, fmt.Errorf("Atum project has no tracked lock data")
	}
	decoder := json.NewDecoder(bytes.NewReader(project.LockData))
	decoder.DisallowUnknownFields()
	var snapshot Lock
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode tracked source lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("tracked source lock contains multiple JSON values")
		}
		return nil, fmt.Errorf("decode trailing tracked source lock: %w", err)
	}
	snapshot.Bundle = nil
	data, err := MarshalJSON(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode normalized source lock: %w", err)
	}
	return data, nil
}
