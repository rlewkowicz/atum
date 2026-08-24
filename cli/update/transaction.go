package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"atum/cli/fssecure"
)

const (
	transactionSchema    = "atum.dev/update-transaction/v2"
	transactionPrepared  = "prepared"
	transactionCommitted = "committed"
	transactionIDBytes   = 12
	transactionCopySize  = 128 << 10
)

type managedVersion struct {
	exists bool
	mode   uint32
	digest string
	data   []byte
}

type transactionEntry struct {
	expected  managedVersion
	candidate managedVersion
}

type fileTransaction struct {
	root        string
	files       map[string]transactionEntry
	directories map[string]string
}

type transactionJournal struct {
	SchemaVersion string              `json:"schemaVersion"`
	State         string              `json:"state"`
	Files         []transactionRecord `json:"files"`
}

type transactionRecord struct {
	Path            string `json:"path"`
	OriginalExists  bool   `json:"originalExists"`
	OriginalMode    uint32 `json:"originalMode,omitempty"`
	OriginalSHA256  string `json:"originalSha256,omitempty"`
	CandidateExists bool   `json:"candidateExists"`
	CandidateMode   uint32 `json:"candidateMode,omitempty"`
	CandidateSHA256 string `json:"candidateSha256,omitempty"`
}

func newFileTransaction(root string) *fileTransaction {
	return &fileTransaction{
		root:        root,
		files:       make(map[string]transactionEntry),
		directories: make(map[string]string),
	}
}

func snapshotManagedFile(root, relative string) (managedVersion, error) {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return managedVersion{}, err
	}
	path, err := fssecure.Resolve(root, clean, true)
	if err != nil {
		return managedVersion{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return managedVersion{}, nil
	}
	if err != nil {
		return managedVersion{}, fmt.Errorf("inspect managed file %s: %w", clean, err)
	}
	if !info.Mode().IsRegular() {
		return managedVersion{}, fmt.Errorf("managed path %s is not a regular file", clean)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return managedVersion{}, fmt.Errorf("read managed file %s: %w", clean, err)
	}
	digest := sha256.Sum256(data)
	return managedVersion{
		exists: true,
		mode:   uint32(info.Mode().Perm()),
		digest: hex.EncodeToString(digest[:]),
		data:   data,
	}, nil
}

func (transaction *fileTransaction) Add(relative string, data []byte, expected managedVersion) error {
	mode := expected.mode
	if !expected.exists {
		mode = 0o644
	}
	return transaction.add(relative, expected, managedVersion{
		exists: true,
		mode:   mode,
		digest: hashBytes(data),
		data:   append([]byte(nil), data...),
	})
}

func (transaction *fileTransaction) AddMode(relative string, data []byte, mode os.FileMode, expected managedVersion) error {
	if !mode.IsRegular() || mode.Perm() == 0 {
		return fmt.Errorf("managed file %s has invalid candidate mode %s", relative, mode)
	}
	return transaction.add(relative, expected, managedVersion{
		exists: true,
		mode:   uint32(mode.Perm()),
		digest: hashBytes(data),
		data:   append([]byte(nil), data...),
	})
}

func (transaction *fileTransaction) Delete(relative string, expected managedVersion) error {
	if !expected.exists {
		return nil
	}
	return transaction.add(relative, expected, managedVersion{})
}

func (transaction *fileTransaction) add(relative string, expected, candidate managedVersion) error {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return err
	}
	if _, exists := transaction.files[clean]; exists {
		return fmt.Errorf("managed path %s is duplicated", clean)
	}
	if err := validateManagedVersion(expected); err != nil {
		return fmt.Errorf("managed path %s expected state: %w", clean, err)
	}
	if err := validateManagedVersion(candidate); err != nil {
		return fmt.Errorf("managed path %s candidate state: %w", clean, err)
	}
	transaction.files[clean] = transactionEntry{expected: withoutData(expected), candidate: candidate}
	return nil
}

func validateManagedVersion(version managedVersion) error {
	if !version.exists {
		if version.mode != 0 || version.digest != "" || len(version.data) != 0 {
			return errors.New("absent file carries material")
		}
		return nil
	}
	if version.mode == 0 || version.mode > 0o777 || !validHexSHA256(version.digest) {
		return errors.New("file mode or digest is invalid")
	}
	if version.data != nil && hashBytes(version.data) != version.digest {
		return errors.New("file bytes do not match digest")
	}
	return nil
}

func withoutData(version managedVersion) managedVersion {
	version.data = nil
	return version
}

func (transaction *fileTransaction) Changed() []string {
	paths := transaction.paths()
	changed := paths[:0]
	for _, relative := range paths {
		entry := transaction.files[relative]
		if !sameManagedVersion(entry.expected, entry.candidate) {
			changed = append(changed, relative)
		}
	}
	return changed
}

func (transaction *fileTransaction) Commit() error {
	if recovered, err := recoverTransactions(transaction.root); err != nil {
		return err
	} else if recovered {
		return errors.New("an interrupted update was recovered after candidate resolution; retry the update")
	}
	changed := transaction.Changed()
	if err := transaction.Verify(); err != nil {
		return err
	}
	if len(changed) == 0 {
		return nil
	}

	transactionRoot, id, directory, err := createTransactionDirectory(transaction.root)
	if err != nil {
		return err
	}
	removeDirectory := true
	defer func() {
		if removeDirectory {
			_ = os.RemoveAll(directory)
		}
	}()

	candidateDirectory := filepath.Join(directory, "candidate")
	backupDirectory := filepath.Join(directory, "backup")
	for _, path := range []string{candidateDirectory, backupDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create update transaction %s: %w", id, err)
		}
	}

	journal := transactionJournal{
		SchemaVersion: transactionSchema,
		State:         transactionPrepared,
		Files:         make([]transactionRecord, len(changed)),
	}
	copyBuffer := make([]byte, transactionCopySize)
	for i, relative := range changed {
		entry := transaction.files[relative]
		journal.Files[i] = transactionRecord{
			Path:            relative,
			OriginalExists:  entry.expected.exists,
			OriginalMode:    entry.expected.mode,
			OriginalSHA256:  entry.expected.digest,
			CandidateExists: entry.candidate.exists,
			CandidateMode:   entry.candidate.mode,
			CandidateSHA256: entry.candidate.digest,
		}
		if entry.candidate.exists {
			if err := writeSyncedFile(transactionCandidate(directory, i), entry.candidate.data, os.FileMode(entry.candidate.mode)); err != nil {
				return fmt.Errorf("stage managed file %s: %w", relative, err)
			}
		}
		if entry.expected.exists {
			canonical, err := fssecure.Resolve(transaction.root, relative, false)
			if err != nil {
				return err
			}
			if err := copySyncedFile(canonical, transactionBackup(directory, i), os.FileMode(entry.expected.mode), copyBuffer); err != nil {
				return fmt.Errorf("backup managed file %s: %w", relative, err)
			}
			backup, err := snapshotAbsoluteFile(transactionBackup(directory, i))
			if err != nil {
				return fmt.Errorf("verify backup managed file %s: %w", relative, err)
			}
			if !sameManagedVersion(backup, entry.expected) {
				return fmt.Errorf("backup managed file %s does not match its expected state", relative)
			}
		}
	}
	for _, path := range []string{candidateDirectory, backupDirectory} {
		if err := syncDirectory(path); err != nil {
			return err
		}
	}
	if err := transaction.Verify(); err != nil {
		return err
	}
	if _, err := writeTransactionJournal(directory, journal); err != nil {
		return err
	}

	for i, record := range journal.Files {
		canonical, err := ensureManagedParent(transaction.root, record.Path)
		if err != nil {
			return rollbackTransaction(transaction.root, directory, journal, fmt.Errorf("prepare managed file %s: %w", record.Path, err))
		}
		if record.CandidateExists {
			err = os.Rename(transactionCandidate(directory, i), canonical)
		} else {
			err = os.Remove(canonical)
		}
		if err != nil {
			return rollbackTransaction(transaction.root, directory, journal, fmt.Errorf("replace managed file %s: %w", record.Path, err))
		}
		if err := syncDirectory(filepath.Dir(canonical)); err != nil {
			return rollbackTransaction(transaction.root, directory, journal, err)
		}
	}
	journal.State = transactionCommitted
	published, err := writeTransactionJournal(directory, journal)
	if err != nil {
		if published {
			removeDirectory = false
			return err
		}
		return rollbackTransaction(transaction.root, directory, journal, err)
	}
	if err := removeTransactionDirectory(transactionRoot, directory); err != nil {
		removeDirectory = false
		return err
	}
	removeDirectory = false
	return nil
}

func (transaction *fileTransaction) Verify() error {
	for _, relative := range transaction.paths() {
		actual, err := snapshotManagedFile(transaction.root, relative)
		if err != nil {
			return err
		}
		if !sameManagedVersion(actual, transaction.files[relative].expected) {
			return fmt.Errorf("managed file %s changed while upstream updates were resolving; retry without discarding the concurrent edit", relative)
		}
	}
	for directory, expected := range transaction.directories {
		actual, err := snapshotDirectoryDigest(transaction.root, directory)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("managed directory %s changed while upstream updates were resolving; retry without discarding the concurrent edit", directory)
		}
	}
	return nil
}

func (transaction *fileTransaction) GuardDirectory(relative, expected string) error {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return err
	}
	if expected == "" {
		return fmt.Errorf("managed directory %s has an empty identity", clean)
	}
	if _, exists := transaction.directories[clean]; exists {
		return fmt.Errorf("managed directory %s is duplicated", clean)
	}
	transaction.directories[clean] = expected
	return nil
}

func snapshotAbsoluteFile(path string) (managedVersion, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return managedVersion{}, err
	}
	if !info.Mode().IsRegular() {
		return managedVersion{}, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return managedVersion{}, err
	}
	return managedVersion{
		exists: true,
		mode:   uint32(info.Mode().Perm()),
		digest: hashBytes(data),
		data:   data,
	}, nil
}

func rollbackTransaction(root, directory string, journal transactionJournal, cause error) error {
	prepared := journal
	prepared.State = transactionPrepared
	if rollbackErr := recoverPreparedTransaction(root, directory, prepared); rollbackErr != nil {
		return errors.Join(cause, rollbackErr)
	}
	return cause
}

// Recover restores an interrupted prepared update or finishes cleanup after a
// fully committed update. Callers must hold the updater's project lock.
func RecoverLocked(root string) error {
	_, err := recoverTransactions(root)
	return err
}

func Recover(ctx context.Context, root string) error {
	unlock, err := lockUpdates(ctx, root)
	if err != nil {
		return err
	}
	defer unlock()
	return RecoverLocked(root)
}

func recoverTransactions(root string) (bool, error) {
	transactionRoot, resolveErr := fssecure.Resolve(root, filepath.Join(".atum", "state", "update-transactions"), true)
	if resolveErr != nil {
		return false, fmt.Errorf("resolve update transaction root: %w", resolveErr)
	}
	entries, err := os.ReadDir(transactionRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect update transactions: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validTransactionID(entry.Name()) {
			return false, fmt.Errorf("unexpected update transaction entry %s", entry.Name())
		}
		directory := filepath.Join(transactionRoot, entry.Name())
		journal, exists, err := readTransactionJournal(directory)
		if err != nil {
			return false, err
		}
		if !exists {
			if err := removeTransactionDirectory(transactionRoot, directory); err != nil {
				return false, err
			}
			continue
		}
		switch journal.State {
		case transactionPrepared:
			if err := recoverPreparedTransaction(root, directory, journal); err != nil {
				return false, err
			}
		case transactionCommitted:
			if err := verifyCommittedTransaction(root, journal); err != nil {
				return false, err
			}
		default:
			return false, fmt.Errorf("update transaction %s has unsupported state %q", entry.Name(), journal.State)
		}
		if err := removeTransactionDirectory(transactionRoot, directory); err != nil {
			return false, err
		}
	}
	return len(entries) != 0, nil
}

func createTransactionDirectory(root string) (string, string, string, error) {
	transactionRoot, err := fssecure.EnsureDirectory(root, filepath.Join(".atum", "state", "update-transactions"), 0o700)
	if err != nil {
		return "", "", "", fmt.Errorf("create update transaction root: %w", err)
	}
	var entropy [transactionIDBytes]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", "", "", fmt.Errorf("generate update transaction identity: %w", err)
	}
	id := hex.EncodeToString(entropy[:])
	directory := filepath.Join(transactionRoot, id)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", "", "", fmt.Errorf("create update transaction %s: %w", id, err)
	}
	if err := syncDirectory(transactionRoot); err != nil {
		_ = os.Remove(directory)
		return "", "", "", err
	}
	return transactionRoot, id, directory, nil
}

func writeTransactionJournal(directory string, journal transactionJournal) (bool, error) {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode update transaction journal: %w", err)
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(directory, ".journal-")
	if err != nil {
		return false, fmt.Errorf("create update transaction journal: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("secure update transaction journal: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("write update transaction journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("sync update transaction journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close update transaction journal: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, "journal.json")); err != nil {
		return false, fmt.Errorf("publish update transaction journal: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return true, err
	}
	return true, nil
}

func readTransactionJournal(directory string) (transactionJournal, bool, error) {
	path := filepath.Join(directory, "journal.json")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return transactionJournal{}, false, nil
	}
	if err != nil {
		return transactionJournal{}, false, fmt.Errorf("open update transaction journal: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return transactionJournal{}, false, fmt.Errorf("read update transaction journal: %w", err)
	}
	if len(data) > 1<<20 {
		return transactionJournal{}, false, errors.New("update transaction journal exceeds 1048576 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal transactionJournal
	if err := decoder.Decode(&journal); err != nil {
		return transactionJournal{}, false, fmt.Errorf("decode update transaction journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON documents are not allowed")
		}
		return transactionJournal{}, false, fmt.Errorf("decode update transaction journal: %w", err)
	}
	if journal.SchemaVersion != transactionSchema || len(journal.Files) == 0 {
		return transactionJournal{}, false, errors.New("update transaction journal has an invalid schema or empty file set")
	}
	seen := make(map[string]struct{}, len(journal.Files))
	for i := range journal.Files {
		record := &journal.Files[i]
		clean, err := fssecure.Relative(record.Path)
		if err != nil || clean != record.Path || !validJournalMaterial(*record) {
			return transactionJournal{}, false, fmt.Errorf("update transaction journal has invalid file record %d", i)
		}
		if _, duplicate := seen[record.Path]; duplicate {
			return transactionJournal{}, false, fmt.Errorf("update transaction journal repeats %s", record.Path)
		}
		seen[record.Path] = struct{}{}
	}
	return journal, true, nil
}

func validJournalMaterial(record transactionRecord) bool {
	valid := func(exists bool, mode uint32, digest string) bool {
		if !exists {
			return mode == 0 && digest == ""
		}
		return mode > 0 && mode <= 0o777 && validHexSHA256(digest)
	}
	return valid(record.OriginalExists, record.OriginalMode, record.OriginalSHA256) &&
		valid(record.CandidateExists, record.CandidateMode, record.CandidateSHA256)
}

func recoverPreparedTransaction(root, directory string, journal transactionJournal) error {
	directories := make(map[string]struct{}, len(journal.Files))
	for i := len(journal.Files) - 1; i >= 0; i-- {
		record := journal.Files[i]
		canonical, err := ensureManagedParent(root, record.Path)
		if err != nil {
			return err
		}
		if record.OriginalExists {
			backup := transactionBackup(directory, i)
			backupState, stateErr := regularFileVersion(backup)
			switch {
			case stateErr == nil:
				if backupState.mode != record.OriginalMode || backupState.digest != record.OriginalSHA256 {
					return fmt.Errorf("update transaction backup for %s does not match its journal", record.Path)
				}
				current, currentErr := snapshotManagedFile(root, record.Path)
				if currentErr != nil {
					return currentErr
				}
				if current.exists && current.mode == record.OriginalMode && current.digest == record.OriginalSHA256 {
					break
				}
				candidatePresent := current.exists && record.CandidateExists &&
					current.mode == record.CandidateMode && current.digest == record.CandidateSHA256
				candidateDeleted := !current.exists && !record.CandidateExists
				if !candidatePresent && !candidateDeleted {
					return fmt.Errorf("managed file %s changed after an interrupted update; refusing to overwrite it during recovery", record.Path)
				}
				if err := os.Rename(backup, canonical); err != nil {
					return fmt.Errorf("restore managed file %s: %w", record.Path, err)
				}
			case errors.Is(stateErr, os.ErrNotExist):
				state, currentErr := snapshotManagedFile(root, record.Path)
				if currentErr != nil || !state.exists || state.mode != record.OriginalMode || state.digest != record.OriginalSHA256 {
					return fmt.Errorf("managed file %s cannot be proven restored after interrupted update", record.Path)
				}
			default:
				return stateErr
			}
		} else {
			state, stateErr := snapshotManagedFile(root, record.Path)
			if stateErr != nil {
				return stateErr
			}
			if state.exists {
				if !record.CandidateExists || state.mode != record.CandidateMode || state.digest != record.CandidateSHA256 {
					return fmt.Errorf("new managed file %s changed before rollback", record.Path)
				}
				if err := os.Remove(canonical); err != nil {
					return fmt.Errorf("remove new managed file %s during rollback: %w", record.Path, err)
				}
			}
		}
		directories[filepath.Dir(canonical)] = struct{}{}
	}
	for directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func verifyCommittedTransaction(root string, journal transactionJournal) error {
	for _, record := range journal.Files {
		state, err := snapshotManagedFile(root, record.Path)
		if err != nil {
			return fmt.Errorf("verify committed managed file %s: %w", record.Path, err)
		}
		if state.exists != record.CandidateExists ||
			(state.exists && (state.mode != record.CandidateMode || state.digest != record.CandidateSHA256)) {
			return fmt.Errorf("committed managed file %s does not match its transaction journal", record.Path)
		}
	}
	return nil
}

func ensureManagedParent(root, relative string) (string, error) {
	clean, err := fssecure.Relative(relative)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(clean)
	if parent == "." {
		return fssecure.Resolve(root, clean, true)
	}
	if _, err := fssecure.EnsureDirectory(root, parent, 0o755); err != nil {
		return "", err
	}
	return fssecure.Resolve(root, clean, true)
}

func removeTransactionDirectory(transactionRoot, directory string) error {
	if filepath.Dir(directory) != transactionRoot || !validTransactionID(filepath.Base(directory)) {
		return fmt.Errorf("refuse to remove invalid update transaction path %s", directory)
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove update transaction %s: %w", filepath.Base(directory), err)
	}
	return syncDirectory(transactionRoot)
}

func transactionCandidate(directory string, index int) string {
	return filepath.Join(directory, "candidate", fmt.Sprintf("%06d", index))
}

func transactionBackup(directory string, index int) string {
	return filepath.Join(directory, "backup", fmt.Sprintf("%06d", index))
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func copySyncedFile(source, destination string, mode os.FileMode, buffer []byte) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := output.Chmod(mode); err != nil {
		_ = output.Close()
		return err
	}
	if _, err := io.CopyBuffer(output, input, buffer); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func regularFileVersion(path string) (managedVersion, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return managedVersion{}, err
	}
	if !info.Mode().IsRegular() {
		return managedVersion{}, fmt.Errorf("%s is not a regular file", path)
	}
	digest, err := hashRegularFile(path)
	if err != nil {
		return managedVersion{}, err
	}
	return managedVersion{exists: true, mode: uint32(info.Mode().Perm()), digest: digest}, nil
}

func hashRegularFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func hashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func sameManagedVersion(left, right managedVersion) bool {
	return left.exists == right.exists && left.mode == right.mode && left.digest == right.digest
}

func validTransactionID(value string) bool {
	if len(value) != transactionIDBytes*2 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (transaction *fileTransaction) paths() []string {
	paths := make([]string, 0, len(transaction.files))
	for path := range transaction.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open transaction directory %s: %w", path, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync transaction directory %s: %w", path, err)
	}
	return nil
}
