package platform

import (
	"bytes"
	"encoding/base64"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"atum/cli/identity"
)

func TestAdmitFluxRootOrdersIdentityBeforeActivation(t *testing.T) {
	t.Parallel()
	var order []string
	step := func(name string) func() error {
		return func() error {
			order = append(order, name)
			return nil
		}
	}
	err := admitFluxRoot(fluxAdmissionSteps{
		installControllers: step("install"),
		verifyCandidate:    step("verify"),
		projectIdentity:    step("identity"),
		activateSource:     step("activate"),
		verifyDeployed:     step("deployed"),
		bootstrapRoot:      step("bootstrap"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"install", "verify", "identity", "activate", "deployed", "bootstrap"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("Flux admission order = %v, want %v", order, want)
	}
}

func TestAdmitFluxRootStopsAtEveryAdmissionFailure(t *testing.T) {
	t.Parallel()
	names := []string{"install", "verify", "identity", "activate", "deployed", "bootstrap"}
	for failure := range names {
		failure := failure
		t.Run(names[failure], func(t *testing.T) {
			t.Parallel()
			var calls []string
			steps := make([]func() error, len(names))
			for index, name := range names {
				index, name := index, name
				steps[index] = func() error {
					calls = append(calls, name)
					if index == failure {
						return errors.New("injected admission failure")
					}
					return nil
				}
			}
			err := admitFluxRoot(fluxAdmissionSteps{
				installControllers: steps[0],
				verifyCandidate:    steps[1],
				projectIdentity:    steps[2],
				activateSource:     steps[3],
				verifyDeployed:     steps[4],
				bootstrapRoot:      steps[5],
			})
			if err == nil {
				t.Fatal("admission failure was ignored")
			}
			if !reflect.DeepEqual(calls, names[:failure+1]) {
				t.Fatalf("calls after failure = %v, want %v", calls, names[:failure+1])
			}
		})
	}
}

func TestHandoffRetainsNoDerivedIdentityProjection(t *testing.T) {
	t.Parallel()
	if _, exists := reflect.TypeFor[Handoff]().FieldByName("identityProjection"); exists {
		t.Fatal("long-lived platform handoff retains a derived identity projection")
	}
}

func TestAdmissionFailureBeforeProjectionDoesNotDeriveIdentity(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"install", "candidate"} {
		failure := failure
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			derived := false
			fail := func() error { return errors.New("injected pre-admission failure") }
			install := func() error { return nil }
			verify := func() error { return nil }
			if failure == "install" {
				install = fail
			} else {
				verify = fail
			}
			err := admitFluxRoot(fluxAdmissionSteps{
				installControllers: install,
				verifyCandidate:    verify,
				projectIdentity: func() error {
					derived = true
					return nil
				},
				activateSource: func() error { return nil },
				verifyDeployed: func() error { return nil },
				bootstrapRoot:  func() error { return nil },
			})
			if err == nil {
				t.Fatal("pre-admission failure was ignored")
			}
			if derived {
				t.Fatal("identity was derived before its admission boundary")
			}
		})
	}
}

func TestActivatedRetryVerifiesDeployedBeforeBootstrap(t *testing.T) {
	t.Parallel()
	for _, receiptFailure := range []bool{false, true} {
		receiptFailure := receiptFailure
		t.Run(map[bool]string{false: "exact", true: "mismatch"}[receiptFailure], func(t *testing.T) {
			t.Parallel()
			activated := true
			activationCalls := 0
			bootstrapCalls := 0
			noOp := func() error { return nil }
			err := admitFluxRoot(fluxAdmissionSteps{
				installControllers: noOp,
				verifyCandidate:    noOp,
				projectIdentity:    noOp,
				activateSource: func() error {
					return activateSourceOnce(&activated, func() error {
						activationCalls++
						return nil
					})
				},
				verifyDeployed: func() error {
					if receiptFailure {
						return errors.New("deployed branch mismatch")
					}
					return nil
				},
				bootstrapRoot: func() error {
					bootstrapCalls++
					return nil
				},
			})
			if receiptFailure != (err != nil) {
				t.Fatalf("retry error = %v, receipt failure = %t", err, receiptFailure)
			}
			if activationCalls != 0 {
				t.Fatalf("activated retry rewrote the source %d times", activationCalls)
			}
			wantBootstrapCalls := 1
			if receiptFailure {
				wantBootstrapCalls = 0
			}
			if bootstrapCalls != wantBootstrapCalls {
				t.Fatalf("bootstrap calls = %d, want %d", bootstrapCalls, wantBootstrapCalls)
			}
		})
	}
}

func TestConsumeIdentityProjectionClearsSuccessAndFailure(t *testing.T) {
	t.Parallel()
	for _, failure := range []bool{false, true} {
		failure := failure
		t.Run(map[bool]string{false: "success", true: "failure"}[failure], func(t *testing.T) {
			t.Parallel()
			projection := testIdentityProjection(t)
			original := projection
			err := consumeIdentityProjection(&projection, func(current *identity.BootstrapProjection) error {
				if current.Digest() == "" {
					t.Fatal("writer received an already-cleared projection")
				}
				if failure {
					return errors.New("injected projection failure")
				}
				return nil
			})
			if failure != (err != nil) {
				t.Fatalf("projection error = %v, failure = %t", err, failure)
			}
			if projection != nil || original.Digest() != "" {
				t.Fatal("consumed projection retained its pointer or digest")
			}
		})
	}
	var cloud *identity.BootstrapProjection
	if err := consumeIdentityProjection(&cloud, nil); err != nil {
		t.Fatalf("cloud projection no-op failed: %v", err)
	}
}

func TestIdentityProjectionRederivationIsDeterministic(t *testing.T) {
	t.Parallel()
	first := testIdentityProjection(t)
	digest := first.Digest()
	if err := consumeIdentityProjection(&first, func(*identity.BootstrapProjection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	second := testIdentityProjection(t)
	if second.Digest() != digest {
		t.Fatalf("re-derived digest = %q, want %q", second.Digest(), digest)
	}
	second.Clear()
}

func testIdentityProjection(t *testing.T) *identity.BootstrapProjection {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := identity.Load(root, "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seed := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	projection, err := identity.Derive(contract, seed, "atum", "atum.test")
	if err != nil {
		t.Fatal(err)
	}
	return projection
}
