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

func TestHandoffRetainsNoDerivedIdentityProjectionOrLifecycleFlag(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeFor[Handoff]()
	for _, name := range []string{"credentials", "identityProjection", "activated"} {
		if _, exists := typ.FieldByName(name); exists {
			t.Fatalf("long-lived platform handoff retains %s", name)
		}
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
}

func TestIdentityProjectionRederivationIsDeterministic(t *testing.T) {
	t.Parallel()
	first := testIdentityProjection(t)
	digest := first.Digest()
	if err := consumeIdentityProjection(
		&first,
		func(*identity.BootstrapProjection) error { return nil },
	); err != nil {
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
	contract, err := identity.Load(
		root, "platform/profiles/local/identity/contract.yaml",
	)
	if err != nil {
		t.Fatal(err)
	}
	rawSeed := bytes.Repeat([]byte{0x42}, 32)
	seed := make([]byte, base64.RawStdEncoding.EncodedLen(len(rawSeed)))
	base64.RawStdEncoding.Encode(seed, rawSeed)
	clear(rawSeed)
	defer clear(seed)
	projection, err := identity.Derive(
		contract, seed, "atum", "atum.test",
	)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}
