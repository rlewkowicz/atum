package update

import (
	"strings"
	"testing"

	"atum/cli/config"
)

func TestProjectSSHIdentityDefaultsOnceAndPreservesHumanPath(t *testing.T) {
	t.Parallel()

	desired := config.Document{Infrastructure: config.Infrastructure{
		Active: "local",
		Targets: map[string]config.InfrastructureTarget{
			"local": {},
		},
	}}
	projectSSHIdentity(&desired)
	target := desired.Infrastructure.Targets["local"]
	if target.SSH.PrivateKeyPath != config.DefaultSSHPrivateKeyPath ||
		target.SSH.PublicKeyPath() != config.DefaultSSHPrivateKeyPath+".pub" {
		t.Fatalf("default key pair = %#v / %q", target.SSH, target.SSH.PublicKeyPath())
	}
	target.SSH.PrivateKeyPath = "/keys/site"
	desired.Infrastructure.Targets["local"] = target
	projectSSHIdentity(&desired)
	target = desired.Infrastructure.Targets["local"]
	if target.SSH.PrivateKeyPath != "/keys/site" ||
		target.SSH.PublicKeyPath() != "/keys/site.pub" {
		t.Fatalf("human key pair was not preserved: %#v", target.SSH)
	}
}

func TestProjectSSHIdentitySchemaIsDeterministic(t *testing.T) {
	t.Parallel()

	input := []byte(`{
    "infrastructureTarget": {
      "required": ["driver", "directory", "autoApprove", "platformProfile"],
        "platformProfile": {"const": "local"},
        "localAccess": {"$ref": "#/$defs/localAccess"}
    },
    "localAccess": {
}`)
	first, err := projectSSHIdentitySchemaData(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := projectSSHIdentitySchemaData(first)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) ||
		!strings.Contains(string(first), `"privateKeyPath": {"$ref": "#/$defs/nonEmpty"}`) {
		t.Fatalf("SSH schema projection is unstable:\n%s", first)
	}
}
