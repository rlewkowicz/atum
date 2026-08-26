package orchestration

import (
	"testing"

	"atum/cli/config"
)

func TestPrivateAnsibleInputContract(t *testing.T) {
	t.Parallel()

	if privateAnsibleInputPlaceholder != "@atum-private-input" {
		t.Fatalf("private input placeholder = %q", privateAnsibleInputPlaceholder)
	}
	for _, playbook := range []string{"platform-secrets.yml"} {
		args := privateProjectionArguments("inventory", "orchestration", playbook)
		if len(args) != 5 || args[2] != "--extra-vars" ||
			args[3] != privateAnsibleInputPlaceholder ||
			args[4] != "orchestration/playbooks/"+playbook {
			t.Fatalf("%s private arguments = %#v", playbook, args)
		}
	}
	if err := validatePrivateAnsibleInput(nil); err != nil {
		t.Fatalf("absent private input: %v", err)
	}
	payload := []byte(`{"private":"redacted"}`)
	if err := validatePrivateAnsibleInput(payload); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, maxPrivateAnsibleInputBytes+1)
	if err := validatePrivateAnsibleInput(oversized); err == nil {
		t.Fatal("oversized private stdin payload was accepted")
	}
	bound, err := bindPrivateAnsibleArguments(
		privateProjectionArguments("inventory", "orchestration", "platform-secrets.yml"),
		".atum/runtime/ansible/private.fifo",
	)
	if err != nil {
		t.Fatal(err)
	}
	if bound[3] != "@.atum/runtime/ansible/private.fifo" {
		t.Fatalf("bound private argument = %q", bound[3])
	}
}

func TestProjectionWritersRejectMissingProjection(t *testing.T) {
	t.Parallel()

	service := Service{Project: &config.Project{}}
	if err := service.ProjectFluxSOPSIdentity(t.Context(), nil); err == nil {
		t.Fatal("missing Flux SOPS identity was accepted")
	}
}
