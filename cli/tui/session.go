package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/process"
	"atum/cli/progress"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

type Options struct {
	Project *config.Project
	Title   string
	Scope   Scope
	Raw     bool
	Input   io.Reader
	Output  io.Writer
	Error   io.Writer
	Cancel  func()
}

type eventSignature struct {
	state                    progress.State
	detail                   string
	current, total           int
	bytesCurrent, bytesTotal int64
}

type terminalProgram interface {
	ReleaseTerminal() error
	RestoreTerminal() error
	Send(tea.Msg)
}

var singleLineReplacer = strings.NewReplacer("\r", " ", "\n", " ")

const displayDetailLimit = 4 << 10
const sessionHeartbeatInterval = 15 * time.Second
const interactiveFlushInterval = 500 * time.Millisecond

type Session struct {
	title       string
	raw         bool
	interactive bool
	input       io.Reader
	output      io.Writer
	errorOutput io.Writer
	log         *lockedLog
	logPath     string
	parser      outputParser
	program     *tea.Program
	terminal    terminalProgram
	programDone chan error

	screenMu       sync.Mutex
	terminalActive atomic.Bool
	reportMu       sync.Mutex
	lastEvents     map[string]eventSignature
	activeEvents   map[string]struct{}
	compactState   map[string]eventSignature
	pendingEvents  map[string]queuedProgress
	eventSequence  uint64
	closed         bool
	heartbeatStop  chan struct{}
	heartbeatDone  chan struct{}
	heartbeatOnce  sync.Once
	flushStop      chan struct{}
	flushDone      chan struct{}
	flushOnce      sync.Once
}

func New(options Options) (*Session, error) {
	if options.Project == nil {
		return nil, errors.New("Atum project is required for progress reporting")
	}
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.Error == nil {
		options.Error = os.Stderr
	}
	file, relative, err := createLog(options.Project.Root, options.Title)
	if err != nil {
		return nil, err
	}
	terminal := terminalWriter(options.Output)
	interactive := !options.Raw && terminal
	locked := &lockedLog{file: file}
	if interactive {
		locked.tail = newLogTail()
	}
	session := &Session{
		title: options.Title, raw: options.Raw,
		input: options.Input, output: options.Output, errorOutput: options.Error,
		log: locked, logPath: filepath.ToSlash(relative), parser: newOutputParser(),
		lastEvents: make(map[string]eventSignature, 64), activeEvents: make(map[string]struct{}, 16),
		compactState: make(map[string]eventSignature, 64), pendingEvents: make(map[string]queuedProgress, 64),
		heartbeatStop: make(chan struct{}), heartbeatDone: make(chan struct{}),
		flushStop: make(chan struct{}), flushDone: make(chan struct{}),
	}
	_, _ = fmt.Fprintf(session.log, "%s session title=%q mode=%s\n",
		time.Now().UTC().Format(time.RFC3339Nano), boundedDetail(options.Title), sessionMode(options.Raw, terminal))
	session.interactive = interactive
	if session.interactive {
		model := newModel(options.Title, session.logPath, projectPhases(options.Project, options.Scope), options.Cancel)
		session.program = tea.NewProgram(
			model,
			tea.WithInput(options.Input),
			tea.WithOutput(options.Output),
			tea.WithFPS(2),
		)
		session.terminal = session.program
		session.programDone = make(chan error, 1)
		go func() {
			_, runErr := session.program.Run()
			session.programDone <- runErr
		}()
		go session.flushInteractiveEvents()
	} else if options.Raw {
		_, _ = fmt.Fprintf(options.Error, "[atum] raw log: %s\n", session.logPath)
	} else {
		_, _ = fmt.Fprintf(options.Output, "Atum %s\nraw log: %s\n", options.Title, session.logPath)
	}
	go session.heartbeat()
	return session, nil
}

func sessionMode(raw, terminal bool) string {
	if raw {
		return "raw"
	}
	if terminal {
		return "tui"
	}
	return "compact"
}

func createLog(root, title string) (*os.File, string, error) {
	base := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + safeLogName(title)
	for attempt := range 32 {
		name := base + ".log"
		if attempt != 0 {
			name = base + "-" + strconv.Itoa(attempt) + ".log"
		}
		relative := filepath.Join(".atum", "logs", name)
		file, err := fssecure.CreateRegularExclusive(root, relative, 0o600)
		if err == nil {
			return file, relative, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", fmt.Errorf("create Atum raw log: %w", err)
		}
	}
	return nil, "", errors.New("create Atum raw log: exhausted unique names")
}

func safeLogName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	builder.Grow(min(len(value), 48))
	separator := false
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			if separator && builder.Len() != 0 {
				builder.WriteByte('-')
			}
			separator = false
			builder.WriteRune(character)
			if builder.Len() >= 48 {
				break
			}
		} else {
			separator = true
		}
	}
	if builder.Len() == 0 {
		return "operation"
	}
	return strings.TrimSuffix(builder.String(), "-")
}

func terminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd())) && strings.TrimSpace(os.Getenv("TERM")) != "dumb"
}

func (session *Session) LogPath() string { return session.logPath }

func (session *Session) LogWriter() io.Writer { return session.log }

func (session *Session) Logger(format string) *slog.Logger {
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(session.log, options))
	}
	return slog.New(slog.NewTextHandler(session.log, options))
}

func (session *Session) WrapRunner(runner process.Runner) process.Runner {
	return sessionRunner{session: session, runner: runner}
}

func (session *Session) WrapOutputRunner(runner process.OutputRunner) process.OutputRunner {
	return sessionOutputRunner{session: session, runner: runner}
}

// WithTerminal transfers exclusive terminal custody to work. Interactive
// sessions stop all frame sends while Bubble Tea is released; compact and raw
// sessions execute the callback directly because they hold no terminal state.
func (session *Session) WithTerminal(
	work func(io.Reader, io.Writer, io.Writer) error,
) error {
	if work == nil {
		return errors.New("terminal callback is required")
	}
	if !session.terminalActive.CompareAndSwap(false, true) {
		return errors.New("terminal handoff is already active")
	}
	defer session.terminalActive.Store(false)

	session.reportMu.Lock()
	interactive := session.interactive
	closed := session.closed
	program := session.terminal
	session.reportMu.Unlock()
	if closed {
		return errors.New("progress session is already closed")
	}
	if !interactive || program == nil {
		return work(session.input, session.output, session.errorOutput)
	}

	// Publish the current batch before stopping renderer writes. Later progress
	// remains queued because every Program.Send is serialized by screenMu.
	session.sendPendingEvents()
	session.screenMu.Lock()
	releaseErr := program.ReleaseTerminal()
	var workErr error
	if releaseErr == nil {
		workErr = work(session.input, session.output, session.errorOutput)
	}
	restoreErr := program.RestoreTerminal()
	if restoreErr == nil {
		program.Send(tea.ClearScreen())
	}
	session.screenMu.Unlock()
	session.sendPendingEvents()

	if releaseErr != nil {
		releaseErr = fmt.Errorf("release managed terminal: %w", releaseErr)
	}
	if restoreErr != nil {
		restoreErr = fmt.Errorf("restore managed terminal: %w", restoreErr)
	}
	return errors.Join(releaseErr, workErr, restoreErr)
}

func (session *Session) Report(event progress.Event) {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	session.reportUnlocked(event)
}

func (session *Session) reportUnlocked(event progress.Event) {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	event.Detail = boundedDetail(event.Detail)
	key := string(event.Phase) + "/" + event.ID
	signature := eventSignature{
		state: event.State, detail: event.Detail,
		current: event.Current, total: event.Total,
		bytesCurrent: event.BytesCurrent, bytesTotal: event.BytesTotal,
	}
	session.reportMu.Lock()
	if session.closed {
		session.reportMu.Unlock()
		return
	}
	if event.ID == "*" {
		prefix := string(event.Phase) + "/"
		for activeKey := range session.activeEvents {
			if strings.HasPrefix(activeKey, prefix) {
				delete(session.activeEvents, activeKey)
			}
		}
	} else if event.State == progress.Running {
		session.activeEvents[key] = struct{}{}
	} else {
		delete(session.activeEvents, key)
	}
	if session.lastEvents[key] == signature {
		session.reportMu.Unlock()
		return
	}
	session.lastEvents[key] = signature
	detail := singleLineReplacer.Replace(event.Detail)
	_, _ = fmt.Fprintf(
		session.log,
		"%s progress phase=%s item=%s state=%s current=%d total=%d bytes_current=%d bytes_total=%d detail=%q\n",
		event.Time.UTC().Format(time.RFC3339Nano), event.Phase, event.ID, stateName(event.State),
		event.Current, event.Total, event.BytesCurrent, event.BytesTotal, detail,
	)
	interactive := session.interactive
	if interactive {
		pending, found := session.pendingEvents[key]
		if found && pending.event.Restart && event.State == progress.Running {
			event.Restart = true
		}
		terminalPending := found &&
			(pending.event.State == progress.Complete || pending.event.State == progress.Failed)
		if !terminalPending || event.State != progress.Running || event.Restart {
			session.eventSequence++
			session.pendingEvents[key] = queuedProgress{sequence: session.eventSequence, event: event}
		}
	}
	if session.raw {
		_, _ = fmt.Fprintln(session.errorOutput, "[atum] "+compactEvent(event))
	} else if !interactive && session.compactChanged(key, signature) {
		_, _ = fmt.Fprintln(session.output, compactEvent(event))
	}
	session.reportMu.Unlock()
}

func (session *Session) flushInteractiveEvents() {
	ticker := time.NewTicker(interactiveFlushInterval)
	defer func() {
		ticker.Stop()
		session.sendPendingEvents()
		close(session.flushDone)
	}()
	for {
		select {
		case <-session.flushStop:
			return
		case <-ticker.C:
			session.sendPendingEvents()
		}
	}
}

func (session *Session) sendPendingEvents() {
	session.reportMu.Lock()
	batch := make(progressBatchMsg, 0, len(session.pendingEvents))
	for key, queued := range session.pendingEvents {
		batch = append(batch, queued)
		delete(session.pendingEvents, key)
	}
	program := session.program
	session.reportMu.Unlock()
	if len(batch) != 0 {
		sort.Slice(batch, func(left, right int) bool { return batch[left].sequence < batch[right].sequence })
	}
	if program != nil && len(batch) != 0 {
		session.sendProgram(program, batch)
	}
	if program != nil && session.log.tail != nil {
		if snapshot, changed := session.log.tail.snapshot(); changed {
			session.sendProgram(program, snapshot)
		}
	}
}

func (session *Session) sendProgram(program *tea.Program, message tea.Msg) {
	session.screenMu.Lock()
	program.Send(message)
	session.screenMu.Unlock()
}

func (session *Session) stopInteractiveEvents() {
	if !session.interactive {
		return
	}
	session.flushOnce.Do(func() { close(session.flushStop) })
	<-session.flushDone
}

func (session *Session) heartbeat() {
	ticker := time.NewTicker(sessionHeartbeatInterval)
	defer func() {
		ticker.Stop()
		close(session.heartbeatDone)
	}()
	for {
		select {
		case <-session.heartbeatStop:
			return
		case now := <-ticker.C:
			session.reportMu.Lock()
			if session.closed {
				session.reportMu.Unlock()
				return
			}
			active := len(session.activeEvents)
			interactive := session.interactive
			raw := session.raw
			title := session.title
			logPath := session.logPath
			session.reportMu.Unlock()

			_, _ = fmt.Fprintf(session.log, "%s heartbeat active=%d\n", now.UTC().Format(time.RFC3339Nano), active)
			if raw {
				_, _ = fmt.Fprintf(session.errorOutput, "[atum] %s still running — %d active steps; raw log %s\n", title, active, logPath)
			} else if !interactive {
				_, _ = fmt.Fprintf(session.output, "… Atum %s still running — %d active steps\n", title, active)
			}
		}
	}
}

func (session *Session) stopHeartbeat() {
	session.heartbeatOnce.Do(func() { close(session.heartbeatStop) })
	<-session.heartbeatDone
}

func boundedDetail(detail string) string {
	if len(detail) <= displayDetailLimit {
		return detail
	}
	end := displayDetailLimit
	for end > 0 && !utf8.ValidString(detail[:end]) {
		end--
	}
	return detail[:end] + "…"
}

func (session *Session) compactChanged(key string, signature eventSignature) bool {
	previous, found := session.compactState[key]
	session.compactState[key] = signature
	if !found || previous.state != signature.state ||
		previous.current != signature.current ||
		previous.total != signature.total ||
		previous.bytesCurrent != signature.bytesCurrent ||
		previous.bytesTotal != signature.bytesTotal {
		return true
	}
	return false
}

func compactEvent(event progress.Event) string {
	icon := "…"
	if event.State == progress.Complete {
		icon = "✓"
	} else if event.State == progress.Failed {
		icon = "✗"
	}
	label := event.Label
	if label == "" {
		label = displayName(event.ID)
	}
	detail := event.Detail
	if event.Total > 0 {
		count := fmt.Sprintf("%d/%d", event.Current, event.Total)
		if detail == "" {
			detail = count
		} else {
			detail = count + " " + detail
		}
	}
	if event.BytesCurrent > 0 || event.BytesTotal > 0 {
		bytes := formatBytes(event.BytesCurrent)
		if event.BytesTotal > 0 {
			bytes += "/" + formatBytes(event.BytesTotal)
		}
		if detail == "" {
			detail = bytes
		} else {
			detail = bytes + " · " + detail
		}
	}
	line := icon + " " + displayName(string(event.Phase)) + " / " + label
	if detail != "" {
		line += " — " + singleLineReplacer.Replace(detail)
	}
	return line
}

func formatBytes(value int64) string {
	const unit = int64(1024)
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	divisor, suffix := unit, "KiB"
	for _, next := range []string{"MiB", "GiB", "TiB"} {
		if value < divisor*unit {
			break
		}
		divisor *= unit
		suffix = next
	}
	return fmt.Sprintf("%.1f %s", float64(value)/float64(divisor), suffix)
}

func stateName(state progress.State) string {
	switch state {
	case progress.Running:
		return "running"
	case progress.Complete:
		return "complete"
	case progress.Failed:
		return "failed"
	default:
		return "pending"
	}
}

func (session *Session) observeLine(command process.Command, line string) {
	if session.raw {
		return
	}
	session.parser.observe(session, command, line)
}

func (session *Session) Finish(completion Completion, workErr error) error {
	session.reportMu.Lock()
	if session.closed {
		session.reportMu.Unlock()
		return workErr
	}
	interactive := session.interactive
	program := session.program
	done := session.programDone
	session.closed = true
	session.reportMu.Unlock()

	session.stopInteractiveEvents()
	var rendererErr error
	if interactive && program != nil {
		session.sendProgram(program, finishMsg{completion: completion, err: workErr})
		rendererErr = <-done
	} else {
		state := "complete"
		if workErr != nil {
			state = "failed: " + workErr.Error()
		}
		if !session.raw {
			_, rendererErr = fmt.Fprintln(session.output, "Atum "+session.title+" "+state)
		}
		if workErr == nil && completion.Valid() {
			_, completionErr := fmt.Fprintln(session.output, renderCompletionText(completion))
			rendererErr = errors.Join(rendererErr, completionErr)
		}
	}
	session.stopHeartbeat()
	result := "complete"
	if workErr != nil || rendererErr != nil {
		result = "failed"
	}
	_, _ = fmt.Fprintf(session.log, "%s session result=%s\n", time.Now().UTC().Format(time.RFC3339Nano), result)
	syncErr := session.log.Sync()
	closeErr := session.log.Close()
	return errors.Join(workErr, rendererErr, syncErr, closeErr)
}

type lockedLog struct {
	mu   sync.Mutex
	file *os.File
	tail *logTail
}

func (log *lockedLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	written, err := log.file.Write(data)
	if written != 0 && log.tail != nil {
		log.tail.Write(data[:written])
	}
	return written, err
}

func (log *lockedLog) Sync() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.file.Sync()
}

func (log *lockedLog) Close() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.file.Close()
}

type sessionRunner struct {
	session *Session
	runner  process.Runner
}

func (runner sessionRunner) Run(ctx context.Context, command process.Command) error {
	if runner.runner == nil {
		return errors.New("command runner is unavailable")
	}
	_, _ = fmt.Fprintf(runner.session.log, "%s process\n", time.Now().UTC().Format(time.RFC3339Nano))
	observers := make([]*lineObserver, 0, 2)
	if command.Stdout == nil {
		observer := &lineObserver{session: runner.session, command: command}
		observers = append(observers, observer)
		command.Stdout = runner.session.stream(runner.session.output, observer)
	}
	if command.Stderr == nil {
		observer := &lineObserver{session: runner.session, command: command}
		observers = append(observers, observer)
		command.Stderr = runner.session.stream(runner.session.errorOutput, observer)
	}
	err := runner.runner.Run(ctx, command)
	for _, observer := range observers {
		observer.Close()
	}
	runner.session.parser.finishCommand(runner.session, command, err)
	return err
}

func (session *Session) stream(console io.Writer, observer io.Writer) io.Writer {
	stream := &streamWriter{log: session.log}
	if session.raw {
		stream.console = console
	} else {
		stream.observer = observer
	}
	return stream
}

type streamWriter struct {
	log      io.Writer
	console  io.Writer
	observer io.Writer
}

func (writer *streamWriter) Write(data []byte) (int, error) {
	if err := writeStream(writer.log, data); err != nil {
		return 0, err
	}
	if err := writeStream(writer.console, data); err != nil {
		return 0, err
	}
	if err := writeStream(writer.observer, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func writeStream(destination io.Writer, data []byte) error {
	if destination == nil {
		return nil
	}
	written, err := destination.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

type sessionOutputRunner struct {
	session *Session
	runner  process.OutputRunner
}

func (runner sessionOutputRunner) Output(ctx context.Context, command process.Command) ([]byte, error) {
	if runner.runner == nil {
		return nil, errors.New("output command runner is unavailable")
	}
	if command.Stderr == nil {
		command.Stderr = runner.session.stream(runner.session.errorOutput, nil)
	}
	_, _ = fmt.Fprintf(runner.session.log, "%s process-output\n", time.Now().UTC().Format(time.RFC3339Nano))
	return runner.runner.Output(ctx, command)
}
