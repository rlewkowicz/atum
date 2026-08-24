package treehash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
)

type File struct {
	Path string
	Mode fs.FileMode
	Data []byte
}

func Sum(files []File) (string, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	hash := sha256.New()
	previous := ""
	for _, file := range files {
		if file.Path == "" || file.Path == previous || !file.Mode.IsRegular() {
			return "", fmt.Errorf("tree contains an invalid or duplicate regular file %q", file.Path)
		}
		previous = file.Path
		digest := sha256.Sum256(file.Data)
		_, _ = fmt.Fprintf(hash, "%s\x00%04o\x00%s\n", file.Path, file.Mode.Perm(), hex.EncodeToString(digest[:]))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
