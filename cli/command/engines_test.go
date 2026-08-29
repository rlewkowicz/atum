package command

import (
	"slices"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestTerraformEnvironmentProjectsOneCanonicalSSHDeclaration(t *testing.T) {
	t.Parallel()

	target := config.InfrastructureTarget{
		SSH: config.SSHKeyPair{PrivateKeyPath: "/keys/atum"},
		LocalAccess: &config.LocalAccess{
			Domain: "atum.test",
			DNSServer: "10.77.0.1",
			PublicIngressVIP: "10.77.0.20",
			PassthroughIngressVIP: "10.77.0.21",
			LoadBalancerRange: "10.77.0.22-10.77.0.39",
		},
	}
	environment, err := terraformTargetEnvironment(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(
		environment,
		"TF_VAR_ssh_private_key_path=/keys/atum",
	) {
		t.Fatalf("Terraform environment = %#v", environment)
	}
	for _, entry := range environment {
		if strings.Contains(entry, "ssh_public_key") {
			t.Fatalf("independent public-key input survived: %q", entry)
		}
	}
}

func TestTerraformBastionIdentityIsBoundedAndSingleValued(t *testing.T) {
	t.Parallel()

	if identity, err := parseTerraformBastionIdentity([]byte("domain-uuid\n")); err != nil ||
		identity != "domain-uuid" {
		t.Fatalf("identity = %q, error = %v", identity, err)
	}
	for _, invalid := range [][]byte{
		nil,
		[]byte("one\ntwo"),
		[]byte(strings.Repeat("x", 1025)),
	} {
		if _, err := parseTerraformBastionIdentity(invalid); err == nil {
			t.Fatalf("invalid identity was accepted: %q", invalid)
		}
	}
}
