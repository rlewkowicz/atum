package config

import "testing"

func TestValidateVersionMappedTargetsSupportsChartApplicationBuild(t *testing.T) {
	t.Parallel()

	const (
		revision = "0123456789abcdef0123456789abcdef01234567"
		target   = "registry.test/atum/operator:2.8.0"
	)
	graph := &bakeGraph{
		targets: map[string]bakeTarget{
			"operator": {
				tags: []string{target + "-debian13-r1"},
				contexts: map[string]string{
					"operator_source": "https://github.com/example/operator.git?tag=v2.8.0&checksum=" + revision,
				},
				args: map[string]string{
					"ATUM_IMAGE_VERSION":  "2.8.0",
					"ATUM_IMAGE_REVISION": revision,
				},
			},
		},
	}
	images := []Image{{
		ID:      "operator",
		Version: "2.8.0",
		Target:  target,
		VersionMapping: &ImageVersionMapping{
			Artifact: "chart/operator",
			Source:   "chartAppVersion",
			Build: &ImageBuildVersionMapping{
				ImageRepository: "docker.io/example/operator",
				ImageTagPrefix:  "",
				GitURL:          "https://github.com/example/operator.git",
				GitTagPrefix:    "v",
				GitContext:      "operator_source",
				FullTagSuffix:   "-debian13-r1",
			},
		},
		Delivery: ImageDelivery{
			Default: DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/example/operator:2.8.0",
			},
			FullBuildTarget: "operator",
		},
	}}
	var problems []string
	graph.validateVersionMappedTargets(&problems, images)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}

	images[0].Delivery.Default.Source = "docker.io/other/operator:2.8.0"
	problems = nil
	graph.validateVersionMappedTargets(&problems, images)
	if len(problems) == 0 {
		t.Fatal("mismatched mirror repository was accepted")
	}

	images[0].Delivery.Default.Source = "docker.io/example/operator:2.8.0"
	full := graph.targets["operator"]
	full.contexts["operator_source"] = "https://github.com/example/operator.git?tag=v2.8.0&checksum=89abcdef0123456789abcdef0123456789abcdef"
	graph.targets["operator"] = full
	problems = nil
	graph.validateVersionMappedTargets(&problems, images)
	if len(problems) == 0 {
		t.Fatal("mismatched source context was accepted")
	}
}
