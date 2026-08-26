package secretvalue

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalProjectionIsDeterministicBoundedAndClearable(t *testing.T) {
	t.Parallel()
	values := Values{
		"Z_SECRET": []byte("slash\\quote\""),
		"A_SECRET": []byte("line\nvalue"),
	}
	digest := []byte("digest")
	data, err := MarshalProjection(
		"projection", values, "projection_digest", digest, 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	const expected = `{"projection":{"A_SECRET":"line\nvalue","Z_SECRET":"slash\\quote\""},"projection_digest":"digest"}`
	if !bytes.Equal(data, []byte(expected)) {
		t.Fatalf("projection JSON = %q", data)
	}
	if !json.Valid(data) {
		t.Fatal("projection output is not valid JSON")
	}
	if _, err := MarshalProjection(
		"projection", values, "projection_digest", digest, len(data)-1,
	); err == nil {
		t.Fatal("oversized projection was accepted")
	}
	values.Clear()
	if len(values) != 0 {
		t.Fatal("projection values were retained after Clear")
	}
}

func TestValueClearOverwritesOwnedBytes(t *testing.T) {
	t.Parallel()
	value := New([]byte("clear-me"))
	alias := value.Bytes()
	value.Clear()
	if value != nil {
		t.Fatal("cleared value retained its slice")
	}
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatalf("Clear did not overwrite the owned bytes: %q", alias)
	}
}

func TestValueJSONDecodeIsBoundedAndRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	var value Value
	for _, input := range [][]byte{
		[]byte(`"unterminated`),
		[]byte(`"\ud800"`),
		[]byte{'"', 0x01, '"'},
	} {
		if err := value.UnmarshalJSON(input); err == nil {
			t.Fatalf("malformed secret JSON %q was accepted", input)
		}
	}
	oversized := make([]byte, MaxValueBytes+3)
	oversized[0] = '"'
	for index := 1; index < len(oversized)-1; index++ {
		oversized[index] = 'x'
	}
	oversized[len(oversized)-1] = '"'
	defer clear(oversized)
	if err := value.UnmarshalJSON(oversized); err == nil {
		t.Fatal("oversized secret JSON was accepted")
	}
}
