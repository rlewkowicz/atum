package tui

import (
	"reflect"
	"slices"
	"testing"

	"atum/cli/config"
	"atum/cli/progress"
)

func TestUpdateScopeContainsOnlyUpdaterState(t *testing.T) {
	t.Parallel()

	phases := projectPhases(&config.Project{Root: t.TempDir()}, ScopeUpdates)
	if len(phases) != 1 || phases[0].id != progress.Updates {
		t.Fatalf("update phases = %#v, want one updates phase", phases)
	}
	got := phaseItemIDs(t, phases, progress.Updates)
	want := []string{
		"update-releases",
		"update-render",
		"kubespray-artifacts",
		"update-exact-render",
		"update-charts",
		"update-packaged-render",
		"update-images",
		"update-state",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("update items = %v, want %v", got, want)
	}
}

func TestProjectPhasesAreDeterministicAndLocalScoped(t *testing.T) {
	t.Parallel()

	project := &config.Project{Desired: config.Document{
		Infrastructure: config.Infrastructure{
			Active: "local",
			Targets: map[string]config.InfrastructureTarget{
				"local": {
					PlatformProfile: "local",
					LocalAccess:     &config.LocalAccess{Domain: "atum.test"},
				},
			},
		},
		Platform: config.Platform{
			Bootstrap: config.BootstrapCharts{Charts: []config.Chart{
				{ID: "global"},
				{ID: "kube-vip", Profiles: []string{"local"}},
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
		"global", "kube-vip", "local-dns", "local-certificates", "headlamp", "monitoring",
	} {
		if !slices.Contains(local, id) {
			t.Errorf("local rows %v omit %q", local, id)
		}
	}
	for _, id := range []string{
		"kube-vip", "local-dns", "local-certificates",
	} {
		if got := countID(local, id); got != 1 {
			t.Errorf("local row %q appears %d times, want one owner", id, got)
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
