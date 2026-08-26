package identity

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDeriveIsStableAndSeparated(t *testing.T) {
	contract, err := Load(repositoryRoot(t), "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rawSeed := bytes.Repeat([]byte{0x5a}, 32)
	seed := make([]byte, base64.RawStdEncoding.EncodedLen(len(rawSeed)))
	base64.RawStdEncoding.Encode(seed, rawSeed)
	clear(rawSeed)
	defer clear(seed)
	first, err := Derive(contract, seed, "atum", "atum.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Derive(contract, seed, "atum", "atum.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.digest, second.digest) ||
		!bytes.Equal(first.values["ATUM_IDENTITY_ADMIN_PASSWORD"], second.values["ATUM_IDENTITY_ADMIN_PASSWORD"]) ||
		!bytes.Equal(first.values[clientSecretKey("atum-grafana")], second.values[clientSecretKey("atum-grafana")]) {
		t.Fatal("identical derivation inputs were unstable")
	}
	if bytes.Equal(first.values["ATUM_IDENTITY_ADMIN_PASSWORD"], []byte("atum")) ||
		bytes.Equal(first.values["ATUM_IDENTITY_ADMIN_PASSWORD"], first.values["ATUM_IDENTITY_BOOTSTRAP_PASSWORD"]) ||
		bytes.Equal(first.values["ATUM_IDENTITY_BOOTSTRAP_PASSWORD"], first.values[clientSecretKey("atum-grafana")]) ||
		bytes.Equal(first.values[clientSecretKey("atum-grafana")], first.values[clientSecretKey("atum-gitlab")]) {
		t.Fatal("administrator/bootstrap/client derivation purposes were not separated")
	}
	if _, exists := first.values[clientSecretKey("atum-headlamp")]; exists {
		t.Fatal("public PKCE client received a secret")
	}
	serialized, err := first.MarshalAnsibleJSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, seed) {
		t.Fatal("serialized projection retained the raw identity seed")
	}
	first.Clear()
	if len(first.digest) != 0 || len(first.values) != 0 {
		t.Fatal("projection clear retained credentials")
	}
}

func TestDeriveSeparatesDomainAndClient(t *testing.T) {
	seed := bytes.Repeat([]byte{0xa5}, 32)
	one, err := derive(seed, clientPurpose+"/grafana", "atum", "atum.test", "atum-grafana")
	if err != nil {
		t.Fatal(err)
	}
	two, err := derive(seed, clientPurpose+"/grafana", "atum", "other.test", "atum-grafana")
	if err != nil {
		t.Fatal(err)
	}
	three, err := derive(seed, clientPurpose+"/grafana", "atum", "atum.test", "atum-gitlab")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one, two) || bytes.Equal(one, three) {
		t.Fatal("domain or client identity did not separate derived secrets")
	}
	clear(one)
	clear(two)
	clear(three)
	clear(seed)
}
