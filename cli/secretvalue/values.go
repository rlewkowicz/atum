// Package secretvalue owns clearable, byte-backed secret projections and their
// single bounded JSON handoff. It deliberately avoids converting secret values
// to Go strings while preparing subprocess stdin.
package secretvalue

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxValueBytes = 1 << 20

// Value is one bounded, byte-backed secret. It owns its bytes and can be
// overwritten deterministically; callers must not retain Bytes after Clear.
type Value []byte

func New(value []byte) Value {
	return append(Value(nil), value...)
}

func (value Value) Bytes() []byte {
	return value
}

func (value Value) Clone() Value {
	return New(value)
}

func (value *Value) Clear() {
	if value == nil {
		return
	}
	clear(*value)
	*value = nil
}

func (value Value) MarshalJSON() ([]byte, error) {
	if len(value) > MaxValueBytes || !utf8.Valid(value) {
		return nil, errors.New("secret value is invalid or exceeds its bound")
	}
	return appendQuotedBytes(make([]byte, 0, len(value)+2), value), nil
}

func (value *Value) UnmarshalJSON(data []byte) error {
	if value == nil {
		return errors.New("secret value destination is nil")
	}
	decoded, err := decodeJSONString(data, MaxValueBytes)
	if err != nil {
		return err
	}
	value.Clear()
	*value = decoded
	return nil
}

func decodeJSONString(data []byte, limit int) (Value, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, errors.New("secret value must be a JSON string")
	}
	result := make(Value, 0, min(len(data)-2, limit))
	fail := func(err error) (Value, error) {
		clear(result)
		return nil, err
	}
	for index := 1; index < len(data)-1; index++ {
		character := data[index]
		if character != '\\' {
			if character < 0x20 {
				return fail(errors.New("secret value contains an unescaped control character"))
			}
			result = append(result, character)
		} else {
			index++
			if index >= len(data)-1 {
				return fail(errors.New("secret value has an incomplete JSON escape"))
			}
			switch data[index] {
			case '"', '\\', '/':
				result = append(result, data[index])
			case 'b':
				result = append(result, '\b')
			case 'f':
				result = append(result, '\f')
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case 'u':
				first, next, err := decodeHexRune(data, index+1)
				if err != nil {
					return fail(err)
				}
				index = next - 1
				runeValue := rune(first)
				if utf16.IsSurrogate(runeValue) {
					if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
						return fail(errors.New("secret value has an incomplete UTF-16 surrogate pair"))
					}
					second, afterSecond, err := decodeHexRune(data, index+3)
					if err != nil {
						return fail(err)
					}
					runeValue = utf16.DecodeRune(runeValue, rune(second))
					if runeValue == utf8.RuneError {
						return fail(errors.New("secret value has an invalid UTF-16 surrogate pair"))
					}
					index = afterSecond - 1
				}
				result = utf8.AppendRune(result, runeValue)
			default:
				return fail(errors.New("secret value has an invalid JSON escape"))
			}
		}
		if len(result) > limit {
			return fail(fmt.Errorf("secret value exceeds %d bytes", limit))
		}
	}
	if !utf8.Valid(result) {
		return fail(errors.New("secret value is not valid UTF-8"))
	}
	return result, nil
}

func decodeHexRune(data []byte, start int) (uint16, int, error) {
	if start+4 > len(data)-1 {
		return 0, start, errors.New("secret value has an incomplete Unicode escape")
	}
	var value uint16
	for _, character := range data[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, start, errors.New("secret value has an invalid Unicode escape")
		}
	}
	return value, start + 4, nil
}

// Values is a clearable set of secret projection values.
type Values map[string][]byte

// Clear overwrites and releases every value.
func (values Values) Clear() {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}

// MarshalProjection encodes one Ansible projection without constructing an
// intermediate map of immutable strings. The caller owns and must clear the
// returned buffer.
func MarshalProjection(
	valuesField string,
	values Values,
	digestField string,
	digest []byte,
	limit int,
) ([]byte, error) {
	if valuesField == "" || digestField == "" {
		return nil, errors.New("secret projection field names are required")
	}
	if len(values) == 0 || len(digest) == 0 {
		return nil, errors.New("secret projection values and digest are required")
	}
	if limit <= 0 {
		return nil, errors.New("secret projection limit must be positive")
	}

	keys := make([]string, 0, len(values))
	capacity := len(valuesField) + len(digestField) + len(digest) + 16
	for key, value := range values {
		if key == "" || !utf8.ValidString(key) {
			return nil, errors.New("secret projection contains an invalid key")
		}
		if !utf8.Valid(value) {
			return nil, fmt.Errorf("secret projection value %q is not valid UTF-8", key)
		}
		keys = append(keys, key)
		capacity += len(key) + len(value) + 6
	}
	slices.Sort(keys)
	capacity = min(capacity, limit)

	result := make([]byte, 0, capacity)
	result = append(result, '{')
	result = strconv.AppendQuote(result, valuesField)
	result = append(result, ':', '{')
	for index, key := range keys {
		if index != 0 {
			result = append(result, ',')
		}
		result = strconv.AppendQuote(result, key)
		result = append(result, ':')
		result = appendQuotedBytes(result, values[key])
		if len(result) > limit {
			clear(result)
			return nil, fmt.Errorf("secret projection exceeds %d bytes", limit)
		}
	}
	result = append(result, '}', ',')
	result = strconv.AppendQuote(result, digestField)
	result = append(result, ':')
	result = appendQuotedBytes(result, digest)
	result = append(result, '}')
	if len(result) > limit {
		clear(result)
		return nil, fmt.Errorf("secret projection exceeds %d bytes", limit)
	}
	return result, nil
}

// MarshalKubernetesSecret encodes one Flux-consumed Secret without first
// converting clearable values into immutable Go strings. JSON is valid
// Kubernetes YAML input and gives SOPS one bounded, canonical document.
func MarshalKubernetesSecret(
	name string,
	namespace string,
	annotation string,
	digest []byte,
	values Values,
	limit int,
	watch bool,
) ([]byte, error) {
	return marshalKubernetesSecret(
		name, namespace, annotation, digest, values, limit, watch, false,
	)
}

// MarshalImmutableKubernetesSecret emits an install-time Secret that rejects
// mutation instead of implying that its consumers support live rotation.
func MarshalImmutableKubernetesSecret(
	name string,
	namespace string,
	annotation string,
	digest []byte,
	values Values,
	limit int,
	watch bool,
) ([]byte, error) {
	return marshalKubernetesSecret(
		name, namespace, annotation, digest, values, limit, watch, true,
	)
}

func marshalKubernetesSecret(
	name string,
	namespace string,
	annotation string,
	digest []byte,
	values Values,
	limit int,
	watch bool,
	immutable bool,
) ([]byte, error) {
	for label, value := range map[string]string{
		"name": name, "namespace": namespace, "annotation": annotation,
	} {
		if value == "" || !utf8.ValidString(value) {
			return nil, fmt.Errorf("Kubernetes Secret %s is invalid", label)
		}
	}
	if len(values) == 0 || len(digest) == 0 {
		return nil, errors.New("Kubernetes Secret values and digest are required")
	}
	if limit <= 0 {
		return nil, errors.New("Kubernetes Secret limit must be positive")
	}

	keys := make([]string, 0, len(values))
	capacity := len(name) + len(namespace) + len(annotation) + len(digest) + 256
	for key, value := range values {
		if key == "" || !utf8.ValidString(key) {
			return nil, errors.New("Kubernetes Secret contains an invalid key")
		}
		if !utf8.Valid(value) {
			return nil, fmt.Errorf("Kubernetes Secret value %q is not valid UTF-8", key)
		}
		keys = append(keys, key)
		capacity += len(key) + len(value) + 6
	}
	slices.Sort(keys)
	capacity = min(capacity, limit)

	result := make([]byte, 0, capacity)
	result = append(result, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":`...)
	result = strconv.AppendQuote(result, name)
	result = append(result, `,"namespace":`...)
	result = strconv.AppendQuote(result, namespace)
	if watch {
		result = append(result, `,"labels":{"reconcile.fluxcd.io/watch":"Enabled"}`...)
	}
	result = append(result, `,"annotations":{`...)
	result = strconv.AppendQuote(result, annotation)
	result = append(result, ':')
	result = appendQuotedBytes(result, digest)
	result = append(result, `}},"type":"Opaque"`...)
	if immutable {
		result = append(result, `,"immutable":true`...)
	}
	result = append(result, `,"stringData":{`...)
	for index, key := range keys {
		if index != 0 {
			result = append(result, ',')
		}
		result = strconv.AppendQuote(result, key)
		result = append(result, ':')
		result = appendQuotedBytes(result, values[key])
		if len(result) > limit {
			clear(result)
			return nil, fmt.Errorf("Kubernetes Secret exceeds %d bytes", limit)
		}
	}
	result = append(result, '}', '}', '\n')
	if len(result) > limit {
		clear(result)
		return nil, fmt.Errorf("Kubernetes Secret exceeds %d bytes", limit)
	}
	return result, nil
}

func appendQuotedBytes(destination, value []byte) []byte {
	const hexadecimal = "0123456789abcdef"

	destination = append(destination, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			destination = append(destination, '\\', character)
		case '\b':
			destination = append(destination, '\\', 'b')
		case '\f':
			destination = append(destination, '\\', 'f')
		case '\n':
			destination = append(destination, '\\', 'n')
		case '\r':
			destination = append(destination, '\\', 'r')
		case '\t':
			destination = append(destination, '\\', 't')
		default:
			if character < 0x20 {
				destination = append(destination,
					'\\', 'u', '0', '0',
					hexadecimal[character>>4],
					hexadecimal[character&0x0f],
				)
				continue
			}
			destination = append(destination, character)
		}
	}
	return append(destination, '"')
}
