package tui

import (
	"reflect"
	"slices"
	"testing"

	"atum/cli/config"
	"atum/cli/progress"
)

func TestProjectPhasesAreDeterministicAndProfileScoped(t *testing.T) {
	t.Parallel()

	project := &config.Project{Desired: config.Document{
		Infrastructure: config.Infrastructure{
			Active: "local",
			Targets: map[string]config.InfrastructureTarget{
				"local": {
					PlatformProfile: "local",
					LocalAccess:     &config.LocalAccess{Domain: "atum.test"},
				},
				"cloud": {PlatformProfile: "cloud"},
			},
		},
		Platform: config.Platform{
			Bootstrap: config.BootstrapCharts{Charts: []config.Chart{
				{ID: "global"},
				{ID: "kube-vip", Profiles: []string{"local"}},
				{ID: "cloud-only", Profiles: []string{"cloud"}},
			}},
			Packages: []config.Package{{ID: "headlamp"}},
			Charts:   []config.TrackedChart{{ID: "monitoring"}},
		},
	}}

	first := projectPhases(project, ScopePlatform)
	second := projectPhases(project, ScopePlatform)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("phase rows changed between renders:\n%#v\n%#v", first, second)
	}
	local := phaseItemIDs(t, first, progress.Platform)
	for _, id := range []string{
		"global", "kube-vip", "local-dns", "local-certificates", "platform-profile-identity",
		"headlamp", "monitoring",
	} {
		if !slices.Contains(local, id) {
			t.Errorf("local rows %v omit %q", local, id)
		}
	}
	for _, id := range []string{"kube-vip", "local-dns", "local-certificates", "platform-profile-identity"} {
		if got := countID(local, id); got != 1 {
			t.Errorf("local row %q appears %d times, want one owner", id, got)
		}
	}
	if slices.Contains(local, "cloud-only") {
		t.Fatalf("local rows include cloud-only chart: %v", local)
	}

	project.Desired.Infrastructure.Active = "cloud"
	cloud := phaseItemIDs(t, projectPhases(project, ScopePlatform), progress.Platform)
	if !slices.Contains(cloud, "global") || !slices.Contains(cloud, "cloud-only") {
		t.Fatalf("cloud rows omit active charts: %v", cloud)
	}
	for _, id := range []string{
		"kube-vip", "local-dns", "local-certificates", "platform-profile-identity",
	} {
		if slices.Contains(cloud, id) {
			t.Errorf("cloud rows include local-only item %q: %v", id, cloud)
		}
	}
}

func countID(ids []string, wanted string) int {
	count := 0
	for _, id := range ids {
		if id == wanted {
			count++
		}
	}
	return count
}

func phaseItemIDs(t *testing.T, phases []phaseSpec, phase progress.Phase) []string {
	t.Helper()
	for _, candidate := range phases {
		if candidate.id != phase {
			continue
		}
		ids := make([]string, len(candidate.items))
		for index := range candidate.items {
			ids[index] = candidate.items[index].id
		}
		return ids
	}
	t.Fatalf("phase %q not found", phase)
	return nil
}
