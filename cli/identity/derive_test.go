package identity

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeriveIsStableAndSeparated(t *testing.T) {
	contract, err := Load(repositoryRoot(t), "platform/profiles/local/identity/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seed := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	first, err := Derive(contract, seed, "atum", "atum.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Derive(contract, seed, "atum", "atum.test")
	if err != nil {
		t.Fatal(err)
	}
	if first.digest != second.digest ||
		first.values[clientSecretKey("atum-grafana")] != second.values[clientSecretKey("atum-grafana")] {
		t.Fatal("identical derivation inputs were unstable")
	}
	if first.values["ATUM_IDENTITY_BOOTSTRAP_PASSWORD"] == first.values[clientSecretKey("atum-grafana")] ||
		first.values[clientSecretKey("atum-grafana")] == first.values[clientSecretKey("atum-gitlab")] {
		t.Fatal("bootstrap/client derivation purposes were not separated")
	}
	if _, exists := first.values[clientSecretKey("atum-headlamp")]; exists {
		t.Fatal("public PKCE client received a secret")
	}
	serialized, err := first.MarshalAnsibleJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), seed) {
		t.Fatal("serialized projection retained the raw identity seed")
	}
	first.Clear()
	if first.digest != "" || len(first.values) != 0 {
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
