package tui

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"atum/cli/config"

	tea "github.com/charmbracelet/bubbletea"
)

type fakeTerminalProgram struct {
	mu         sync.Mutex
	releaseErr error
	restoreErr error
	releases   int
	restores   int
	messages   []tea.Msg
}

func (program *fakeTerminalProgram) ReleaseTerminal() error {
	program.mu.Lock()
	defer program.mu.Unlock()
	program.releases++
	return program.releaseErr
}

func (program *fakeTerminalProgram) RestoreTerminal() error {
	program.mu.Lock()
	defer program.mu.Unlock()
	program.restores++
	return program.restoreErr
}

func (program *fakeTerminalProgram) Send(message tea.Msg) {
	program.mu.Lock()
	program.messages = append(program.messages, message)
	program.mu.Unlock()
}

func TestWithTerminalRestoresOnceAndPreservesErrors(t *testing.T) {
	t.Parallel()

	workFailure := errors.New("callback failed")
	restoreFailure := errors.New("restore failed")
	program := &fakeTerminalProgram{restoreErr: restoreFailure}
	input := bytes.NewReader(nil)
	output := new(bytes.Buffer)
	errorOutput := new(bytes.Buffer)
	session := &Session{
		interactive: true, terminal: program,
		input: input, output: output, errorOutput: errorOutput,
		pendingEvents: make(map[string]queuedProgress),
	}
	err := session.WithTerminal(func(gotInput io.Reader, gotOutput, gotError io.Writer) error {
		if gotInput != input || gotOutput != output || gotError != errorOutput {
			t.Fatal("terminal callback did not receive original streams")
		}
		return workFailure
	})
	if !errors.Is(err, workFailure) || !errors.Is(err, restoreFailure) {
		t.Fatalf("terminal errors = %v", err)
	}
	if program.releases != 1 || program.restores != 1 {
		t.Fatalf("terminal release/restore = %d/%d, want 1/1",
			program.releases, program.restores)
	}
}

func TestWithTerminalReleaseFailureSkipsWorkAndStillRestores(t *testing.T) {
	t.Parallel()

	releaseFailure := errors.New("release failed")
	program := &fakeTerminalProgram{releaseErr: releaseFailure}
	session := &Session{
		interactive: true, terminal: program,
		input: bytes.NewReader(nil), output: io.Discard, errorOutput: io.Discard,
		pendingEvents: make(map[string]queuedProgress),
	}
	called := false
	err := session.WithTerminal(func(io.Reader, io.Writer, io.Writer) error {
		called = true
		return nil
	})
	if called || !errors.Is(err, releaseFailure) || program.restores != 1 {
		t.Fatalf("release failure result called=%t restores=%d err=%v",
			called, program.restores, err)
	}
}

func TestWithTerminalRejectsConcurrentOwnership(t *testing.T) {
	t.Parallel()

	session := &Session{
		input: bytes.NewReader(nil), output: io.Discard, errorOutput: io.Discard,
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- session.WithTerminal(func(io.Reader, io.Writer, io.Writer) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	if err := session.WithTerminal(func(io.Reader, io.Writer, io.Writer) error {
		return nil
	}); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("concurrent terminal handoff error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first terminal handoff: %v", err)
	}
}

func TestWithTerminalIsDirectInCompactAndRawModes(t *testing.T) {
	t.Parallel()

	for _, raw := range []bool{false, true} {
		raw := raw
		t.Run(map[bool]string{false: "compact", true: "raw"}[raw], func(t *testing.T) {
			t.Parallel()
			program := &fakeTerminalProgram{}
			session := &Session{
				raw: raw, terminal: program,
				input: bytes.NewReader(nil), output: io.Discard, errorOutput: io.Discard,
			}
			called := false
			if err := session.WithTerminal(func(io.Reader, io.Writer, io.Writer) error {
				called = true
				return nil
			}); err != nil || !called {
				t.Fatalf("direct terminal callback called=%t err=%v", called, err)
			}
			if program.releases != 0 || program.restores != 0 {
				t.Fatalf("direct mode released terminal %d/%d times",
					program.releases, program.restores)
			}
		})
	}
}

func TestCompletionRendersOutsideRawLogInCompactAndRawModes(t *testing.T) {
	t.Parallel()

	completion, err := NewCompletion(testCompletionSpec())
	if err != nil {
		t.Fatalf("construct completion: %v", err)
	}
	for _, raw := range []bool{false, true} {
		raw := raw
		t.Run(map[bool]string{false: "compact", true: "raw"}[raw], func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			var output bytes.Buffer
			session, err := New(Options{
				Project: &config.Project{Root: root}, Title: "completion",
				Raw: raw, Input: bytes.NewReader(nil), Output: &output,
				Error: io.Discard,
			})
			if err != nil {
				t.Fatalf("create session: %v", err)
			}
			logPath := session.LogPath()
			if err := session.Finish(completion, nil); err != nil {
				t.Fatalf("finish session: %v", err)
			}
			if text := output.String(); !strings.Contains(text, "Password  atum") {
				t.Fatalf("completion output omitted credentials:\n%s", text)
			}
			logData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(logPath)))
			if err != nil {
				t.Fatalf("read raw log: %v", err)
			}
			if strings.Contains(string(logData), "Password  atum") ||
				strings.Contains(string(logData), "keycloak.atum.test") {
				t.Fatalf("raw log contains completion:\n%s", logData)
			}
		})
	}
}
