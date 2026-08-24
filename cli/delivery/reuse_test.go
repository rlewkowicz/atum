package delivery

import (
	"testing"

	"atum/cli/config"
)

func TestBundleReuseInventoryIncludesResolvedWrapper(t *testing.T) {
	t.Parallel()

	project := &config.Project{
		Desired: config.Document{Platform: config.Platform{
			BigBang: config.GitSource{Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Flux:    config.GitSource{Commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		}},
		Lock: config.Lock{Resolved: config.Resolved{SupportSources: []config.SupportSource{{
			ID: "wrapper",
			Source: config.GitSource{
				URL: "https://repo.example/wrapper.git", Version: "0.4.15",
				Branch: "main", Commit: "cccccccccccccccccccccccccccccccccccccccc",
			},
		}}}},
	}
	repositories, err := expectedRepositorySources(project)
	if err != nil {
		t.Fatalf("expected bundle repositories: %v", err)
	}
	wrapper, exists := repositories["wrapper"]
	if !exists || wrapper.Commit != "cccccccccccccccccccccccccccccccccccccccc" {
		t.Fatalf("wrapper bundle reuse source = %#v, exists %t", wrapper, exists)
	}
	if len(repositories) != 3 {
		t.Fatalf("bundle reuse repository count = %d, want 3", len(repositories))
	}
}
