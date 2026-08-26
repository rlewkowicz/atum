package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/process"
)

const sopsCommandTimeout = 30 * time.Second

// SOPSAdapter is the exact preflight-selected official SOPS process handoff.
// It performs no executable lookup: every cryptographic operation invokes the
// same absolute path whose version identity preflight validated.
type SOPSAdapter struct {
	binary string
	runner process.Runner
}

func NewSOPSAdapter(binary string, runner process.Runner) (SOPSAdapter, error) {
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		return SOPSAdapter{}, errors.New(
			"validated SOPS binary must be an exact absolute path",
		)
	}
	if runner == nil {
		return SOPSAdapter{}, errors.New("SOPS runner is unavailable")
	}
	return SOPSAdapter{binary: binary, runner: runner}, nil
}

func encryptDocument(
	ctx context.Context,
	adapter SOPSAdapter,
	document Document,
	recipientValues []string,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("SOPS context is required")
	}
	recipients, err := normalizeRecipients(recipientValues)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode secrets for SOPS: %w", err)
	}
	defer clear(plaintext)
	if len(plaintext) > fileLimit {
		return nil, fmt.Errorf("SOPS plaintext exceeds %d bytes", fileLimit)
	}
	return adapter.run(ctx, []string{
		"--encrypt",
		"--input-type", "json",
		"--output-type", "yaml",
		"--age", strings.Join(recipients, ","),
		"/dev/stdin",
	}, plaintext)
}

func decryptDocument(
	ctx context.Context,
	adapter SOPSAdapter,
	ciphertext []byte,
) (Document, error) {
	if ctx == nil {
		return Document{}, errors.New("SOPS context is required")
	}
	plaintext, err := adapter.run(ctx, []string{
		"--decrypt",
		"--input-type", "yaml",
		"--output-type", "json",
		"/dev/stdin",
	}, ciphertext)
	if err != nil {
		return Document{}, err
	}
	defer clear(plaintext)
	var document Document
	if err := config.DecodeJSON(plaintext, &document); err != nil {
		document.Clear()
		return Document{}, fmt.Errorf("decode SOPS plaintext: %w", err)
	}
	return document, nil
}

// EncryptKubernetesSecret delegates the Flux-compatible SOPS document format
// to the exact preflight-selected SOPS binary. Kubernetes identity and
// metadata remain visible so Kustomize can identify the object; only data
// fields are encrypted.
func (adapter SOPSAdapter) EncryptKubernetesSecret(
	ctx context.Context,
	plaintext []byte,
	recipient string,
) ([]byte, error) {
	recipients, err := normalizeRecipients([]string{recipient})
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > fileLimit {
		return nil, fmt.Errorf("Kubernetes Secret plaintext size is outside 1..%d bytes", fileLimit)
	}
	return adapter.run(ctx, []string{
		"--encrypt",
		"--input-type", "json",
		"--output-type", "json",
		"--encrypted-regex", "^(data|stringData)$",
		"--age", recipients[0],
		"/dev/stdin",
	}, plaintext)
}

func normalizeRecipients(values []string) ([]string, error) {
	recipients := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, ",\r\n\x00") {
			return nil, fmt.Errorf("invalid age recipient %q", value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		recipients = append(recipients, value)
	}
	if len(recipients) == 0 {
		return nil, errors.New("no unique age recipients were supplied")
	}
	return recipients, nil
}

func (adapter SOPSAdapter) run(
	ctx context.Context,
	arguments []string,
	input []byte,
) ([]byte, error) {
	if adapter.binary == "" || adapter.runner == nil {
		return nil, errors.New("SOPS adapter is not configured")
	}
	if ctx == nil {
		return nil, errors.New("SOPS context is required")
	}
	commandContext, cancel := context.WithTimeout(ctx, sopsCommandTimeout)
	defer cancel()
	output := newBoundedBuffer(fileLimit)
	defer output.Clear()
	err := adapter.runner.Run(commandContext, process.Command{
		Name:   adapter.binary,
		Args:   append([]string(nil), arguments...),
		Stdin:  bytes.NewReader(input),
		Stdout: output,
		Stderr: io.Discard,
	})
	if callerErr := ctx.Err(); callerErr != nil {
		return nil, fmt.Errorf("SOPS command canceled: %w", callerErr)
	}
	if err != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return nil, errors.New("SOPS command timed out")
		}
		return nil, fmt.Errorf("SOPS command failed: %w", err)
	}
	if output.overflow {
		return nil, fmt.Errorf("SOPS output exceeds %d bytes", fileLimit)
	}
	if output.buffer.Len() == 0 {
		return nil, errors.New("SOPS returned empty output")
	}
	result := append([]byte(nil), output.buffer.Bytes()...)
	return result, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	buffer := &boundedBuffer{limit: limit}
	buffer.buffer.Grow(min(limit, 4096))
	return buffer
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		_, _ = buffer.buffer.Write(data[:min(len(data), remaining)])
	}
	if len(data) > remaining {
		buffer.overflow = true
	}
	return len(data), nil
}

func (buffer *boundedBuffer) Clear() {
	data := buffer.buffer.Bytes()
	clear(data)
	buffer.buffer.Reset()
	buffer.overflow = false
}
