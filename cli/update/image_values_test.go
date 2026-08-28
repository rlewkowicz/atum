package update

import (
	"testing"

	"atum/cli/config"
)

func TestOfficialRedisModulePathsAreProjected(t *testing.T) {
	t.Parallel()

	const ironBankRedis = "registry1.dso.mil/ironbank/opensource/redis/redis8-slim"
	images := selectedImageIndex{
		{
			artifact:   "package/redis",
			repository: ironBankRedis,
		}: {{
			ID:          "redis-8-8-0",
			Version:     "8.8.0",
			BigBangRefs: []string{ironBankRedis + ":8.8.0"},
			Consumers:   []string{"package/redis"},
			Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
				Type:   "mirror",
				Source: "docker.io/library/redis:8.8.0",
			}},
		}},
	}
	generated := make(map[string]any)
	if err := projectRedisModuleCompatibility(generated, images); err != nil {
		t.Fatal(err)
	}
	packages := generated["packages"].(map[string]any)
	redis := packages["redis"].(map[string]any)
	values := redis["values"].(map[string]any)
	upstream := values["upstream"].(map[string]any)
	if got := upstream["commonConfiguration"]; got != redisModuleConfiguration {
		t.Fatalf("projected Redis configuration = %#v, want %#v", got, redisModuleConfiguration)
	}
}
