package config

import (
	"fmt"
	"sort"
	"strings"

	"atum/cli/fssecure"

	"go.yaml.in/yaml/v3"
)

// PlatformValueLoader reads one repository-relative values document.
type PlatformValueLoader func(string) (map[string]any, error)

// ResolvedPlatformValues is the canonical three-layer Big Bang values view.
// Merged is independent from every source map and follows Helm precedence:
// operational, generated, then the active target profile.
type ResolvedPlatformValues struct {
	ProfileName string
	ProfilePath string
	Operational map[string]any
	Generated   map[string]any
	Profile     map[string]any
	Merged      map[string]any
}

// ResolvePlatformValues loads and merges the values selected by the active
// infrastructure target.
func (d Document) ResolvePlatformValues(load PlatformValueLoader) (ResolvedPlatformValues, error) {
	target, exists := d.ActiveTarget()
	if !exists {
		return ResolvedPlatformValues{}, fmt.Errorf("active infrastructure target %q is not defined", d.Infrastructure.Active)
	}
	profilePath, exists := d.Platform.Values.Profiles[target.PlatformProfile]
	if !exists {
		return ResolvedPlatformValues{}, fmt.Errorf("platform profile %q has no values document", target.PlatformProfile)
	}
	operational, err := load(d.Platform.Values.Operational)
	if err != nil {
		return ResolvedPlatformValues{}, fmt.Errorf("load operational platform values: %w", err)
	}
	generated, err := load(d.Platform.Values.Generated)
	if err != nil {
		return ResolvedPlatformValues{}, fmt.Errorf("load generated platform values: %w", err)
	}
	profile, err := load(profilePath)
	if err != nil {
		return ResolvedPlatformValues{}, fmt.Errorf("load platform profile %s values: %w", target.PlatformProfile, err)
	}
	merged, err := MergePlatformValues(operational, generated, profile)
	if err != nil {
		return ResolvedPlatformValues{}, fmt.Errorf("merge platform profile %s values: %w", target.PlatformProfile, err)
	}
	return ResolvedPlatformValues{
		ProfileName: target.PlatformProfile,
		ProfilePath: profilePath,
		Operational: operational,
		Generated:   generated,
		Profile:     profile,
		Merged:      merged,
	}, nil
}

func repositoryPlatformValueLoader(root string, files map[string][]byte) PlatformValueLoader {
	return func(relative string) (map[string]any, error) {
		clean, data, err := fssecure.ReadRegularCandidate(root, relative, files)
		if err != nil {
			return nil, err
		}
		var values map[string]any
		if err := yaml.Unmarshal(data, &values); err != nil {
			return nil, fmt.Errorf("decode %s: %w", clean, err)
		}
		if values == nil {
			values = make(map[string]any)
		}
		return values, nil
	}
}

// MergePlatformValues applies the one authoritative platform values order.
// Profiles cannot author a leaf already owned by generated values; those
// leaves contain updater-selected source pins, post-renderers, and images.
func MergePlatformValues(operational, generated, profile map[string]any) (map[string]any, error) {
	if path := firstValueCollision(generated, profile, nil); path != "" {
		return nil, fmt.Errorf("profile value %s is updater-owned by generated values", path)
	}
	merged := clonePlatformValues(operational)
	mergePlatformValues(merged, generated)
	mergePlatformValues(merged, profile)
	return merged, nil
}

func firstValueCollision(generated, profile map[string]any, prefix []string) string {
	keys := make([]string, 0, len(profile))
	for key := range profile {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		generatedValue, exists := generated[key]
		if !exists {
			continue
		}
		path := append(prefix, key)
		profileMap, profileIsMap := profile[key].(map[string]any)
		generatedMap, generatedIsMap := generatedValue.(map[string]any)
		if profileIsMap && generatedIsMap {
			if len(generatedMap) == 0 && len(profileMap) != 0 {
				return strings.Join(path, ".")
			}
			if collision := firstValueCollision(generatedMap, profileMap, path); collision != "" {
				return collision
			}
			continue
		}
		return strings.Join(path, ".")
	}
	return ""
}

func mergePlatformValues(destination, source map[string]any) {
	for key, value := range source {
		sourceMap, sourceIsMap := value.(map[string]any)
		destinationMap, destinationIsMap := destination[key].(map[string]any)
		if sourceIsMap && destinationIsMap {
			mergePlatformValues(destinationMap, sourceMap)
			continue
		}
		destination[key] = clonePlatformValue(value)
	}
}

func clonePlatformValues(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = clonePlatformValue(value)
	}
	return result
}

func clonePlatformValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return clonePlatformValues(typed)
	case []any:
		result := make([]any, len(typed))
		for i := range typed {
			result[i] = clonePlatformValue(typed[i])
		}
		return result
	default:
		return value
	}
}
