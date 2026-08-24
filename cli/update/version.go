package update

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

func canonicalSemanticVersions[T any](
	items []T,
	current, currentLabel, itemLabel string,
	versionOf func(T) string,
) ([]T, error) {
	currentVersion, err := semver.NewVersion(strings.TrimPrefix(current, "v"))
	if err != nil {
		return nil, fmt.Errorf("current %s %q is not semantic", currentLabel, current)
	}
	wantsPrefix := strings.HasPrefix(current, "v")
	result := make([]T, 0, len(items))
	for start := 0; start < len(items); {
		versionText := versionOf(items[start])
		version, err := semver.NewVersion(strings.TrimPrefix(versionText, "v"))
		if err != nil {
			return nil, fmt.Errorf("%s %q is not semantic", itemLabel, versionText)
		}
		end := start + 1
		for end < len(items) {
			candidate, parseErr := semver.NewVersion(strings.TrimPrefix(versionOf(items[end]), "v"))
			if parseErr != nil || !candidate.Equal(version) {
				break
			}
			end++
		}
		chosen := start
		for index := start; index < end; index++ {
			candidate := versionOf(items[index])
			if version.Equal(currentVersion) && candidate == current {
				chosen = index
				break
			}
			if strings.HasPrefix(candidate, "v") == wantsPrefix {
				chosen = index
			}
		}
		result = append(result, items[chosen])
		start = end
	}
	return result, nil
}
