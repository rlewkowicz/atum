package preflight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"atum/cli/config"
	"atum/cli/process"
)

func TestRequirementsForScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope Scope
		want  requirementSet
	}{
		{"infrastructure", Infrastructure, requirementSet{terraform: true, localTarget: true}},
		{"terraform passthrough", TerraformDirect, requirementSet{terraform: true}},
		{"platform", Platform, requirementSet{docker: true, python: true, ssh: true, flux: true}},
		{"full", Full, requirementSet{
			terraform: true, docker: true, python: true, ssh: true, flux: true, localTarget: true,
		}},
		{"DNS access", AccessDNS, requirementSet{resolver: true, serviceManager: true, sudo: true}},
		{"CA access", AccessCA, requirementSet{sudo: true, trust: true}},
		{"access removal", AccessUninstall, requirementSet{
			resolver: true, serviceManager: true, sudo: true, trust: true,
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := requirementsFor(test.scope)
			if err != nil {
				t.Fatalf("requirements: %v", err)
			}
			if got != test.want {
				t.Fatalf("requirements = %#v, want %#v", got, test.want)
			}
		})
	}
	if _, err := requirementsFor(invalidScope); err == nil {
		t.Fatal("invalid scope did not fail")
	}
}

func TestVersionParsers(t *testing.T) {
	t.Parallel()

	if got, err := checkTerraformVersion(
		`{"terraform_version":"1.13.2"}`, ">= 1.10.0, < 2.0.0",
	); err != nil || got != "1.13.2" {
		t.Fatalf("Terraform version = %q, %v", got, err)
	}
	if _, err := checkTerraformVersion(
		`{"terraform_version":"1.9.8"}`, ">= 1.10.0",
	); err == nil || !strings.Contains(err.Error(), "does not satisfy") {
		t.Fatalf("incompatible Terraform error = %v", err)
	}
	if got, err := checkFluxVersion("flux version 2.6.4", "v2.6.1"); err != nil || got != "2.6.4" {
		t.Fatalf("Flux version = %q, %v", got, err)
	}
	if _, err := checkFluxVersion("flux version 2.7.0", "v2.6.1"); err == nil ||
		!strings.Contains(err.Error(), "require stable 2.6.x") {
		t.Fatalf("incompatible Flux error = %v", err)
	}
	if version, identity, err := dockerVersionParser(
		"client=28.3.3 server=28.3.3",
	); err != nil || version != identity || identity != "client=28.3.3 server=28.3.3" {
		t.Fatalf("Docker identity = %q, %q, %v", version, identity, err)
	}
}

func TestVirshProbeSeparatesConnectionDiagnostics(t *testing.T) {
	t.Parallel()

	const uri = "qemu:///system?socket=/run/libvirt/virtqemud-sock"
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	runner := &virshProbeRunner{uri: uri}
	service := Service{
		Project: &config.Project{Root: "."},
		Runner:  runner,
		Environment: func(name string) string {
			if name == "ATUM_VIRSH_BIN" {
				return executable
			}
			return ""
		},
	}
	result := service.virshSpec(uri).probe(context.Background(), newCapture())
	if !result.OK() {
		t.Fatalf("virsh probe failed: %s", result.Problem)
	}
	if result.Health != "connected "+uri {
		t.Fatalf("virsh health = %q", result.Health)
	}
	if runner.calls != 2 {
		t.Fatalf("virsh calls = %d, want 2", runner.calls)
	}
}

func TestLibvirtURIComparisonIsSemantic(t *testing.T) {
	t.Parallel()

	left := "qemu:///system?socket=%2Frun%2Flibvirt%2Fvirtqemud-sock&mode=direct"
	right := "qemu:///system?mode=direct&socket=/run/libvirt/virtqemud-sock"
	if !sameLibvirtURI(left, right) {
		t.Fatal("equivalent libvirt URIs differ")
	}
	if sameLibvirtURI(left, "qemu:///system") {
		t.Fatal("different libvirt URIs compare equal")
	}
}

type virshProbeRunner struct {
	uri   string
	calls int
}

func (runner *virshProbeRunner) Run(_ context.Context, command process.Command) error {
	runner.calls++
	switch runner.calls {
	case 1:
		if !reflect.DeepEqual(command.Args, []string{"--version"}) {
			return fmt.Errorf("version arguments = %q", command.Args)
		}
		_, err := io.WriteString(command.Stdout, "12.0.0\n")
		return err
	case 2:
		if !reflect.DeepEqual(command.Args, []string{"-c", runner.uri, "uri"}) {
			return fmt.Errorf("URI arguments = %q", command.Args)
		}
		if _, err := io.WriteString(
			command.Stderr,
			"warning: modular daemon selected the requested direct socket\n",
		); err != nil {
			return err
		}
		_, err := io.WriteString(command.Stdout, runner.uri+"\n")
		return err
	default:
		return errors.New("unexpected virsh probe call")
	}
}

func TestCaptureIsBounded(t *testing.T) {
	t.Parallel()

	output := newCapture()
	data := bytes.Repeat([]byte("x"), outputLimit+17)
	if written, err := output.Write(data); err != nil || written != len(data) {
		t.Fatalf("write = %d, %v", written, err)
	}
	text, truncated := output.text()
	if len(output.data) != outputLimit || text != strings.Repeat("x", 512)+"…" || !truncated {
		t.Fatalf("capture length/text/truncation = %d, %q, %t",
			len(output.data), text, truncated)
	}
	output.reset()
	if text, truncated := output.text(); text != "" || truncated {
		t.Fatalf("reset capture = %q, %t", text, truncated)
	}
}

func TestPreflightErrorPreservesDeclarationOrder(t *testing.T) {
	t.Parallel()

	failures := []failure{
		{
			spec: Specification{
				Tool: Terraform, Required: "Terraform 1.13",
				Override: "ATUM_TERRAFORM_BIN", InstallURL: "https://terraform.example",
			},
			result: Result{Problem: "binary not found"},
		},
		{
			spec:   Specification{Tool: Flux, InstallURL: "https://flux.example"},
			result: Result{Problem: "wrong version"},
		},
	}
	got := (&Error{failures: failures}).Error()
	want := strings.Join([]string{
		"preflight failed",
		"- terraform-cli: binary not found; require Terraform 1.13; override ATUM_TERRAFORM_BIN; install: https://terraform.example",
		"- flux: wrong version; install: https://flux.example",
	}, "\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
