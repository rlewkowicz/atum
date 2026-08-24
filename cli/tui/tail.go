package tui

import (
	"bytes"
	"strings"
	"sync"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

const (
	logTailLineLimit = 128
	logTailByteLimit = 4 << 10
)

type logSnapshotMsg struct {
	lines   [logTailLineLimit]string
	start   int
	count   int
	partial string
}

type logTail struct {
	mu        sync.Mutex
	lines     [logTailLineLimit]string
	partial   []byte
	start     int
	count     int
	revision  uint64
	published uint64
	truncated bool
}

func newLogTail() *logTail {
	return &logTail{partial: make([]byte, 0, logTailByteLimit)}
}

func (tail *logTail) Write(data []byte) {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	for len(data) != 0 {
		separator := bytes.IndexAny(data, "\r\n")
		if separator < 0 {
			tail.appendPartial(data)
			return
		}
		tail.appendPartial(data[:separator])
		tail.commitPartial()
		separatorByte := data[separator]
		data = data[separator+1:]
		if separatorByte == '\r' && len(data) != 0 && data[0] == '\n' {
			data = data[1:]
		}
	}
}

func (tail *logTail) appendPartial(data []byte) {
	remaining := logTailByteLimit - len(tail.partial)
	if remaining <= 0 {
		if !tail.truncated {
			tail.truncated = true
			tail.revision++
		}
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
		tail.truncated = true
	}
	tail.partial = append(tail.partial, data...)
	tail.revision++
}

func (tail *logTail) commitPartial() {
	line := sanitizeLogLine(string(tail.partial))
	if tail.truncated {
		line += "…"
	}
	index := (tail.start + tail.count) % logTailLineLimit
	if tail.count == logTailLineLimit {
		index = tail.start
		tail.start = (tail.start + 1) % logTailLineLimit
	} else {
		tail.count++
	}
	tail.lines[index] = line
	tail.partial = tail.partial[:0]
	tail.truncated = false
	tail.revision++
}

func (tail *logTail) snapshot() (logSnapshotMsg, bool) {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	if tail.revision == tail.published {
		return logSnapshotMsg{}, false
	}
	tail.published = tail.revision
	partial := sanitizeLogLine(string(tail.partial))
	if tail.truncated {
		partial += "…"
	}
	return logSnapshotMsg{
		lines: tail.lines, start: tail.start, count: tail.count,
		partial: partial,
	}, true
}

func sanitizeLogLine(line string) string {
	if strings.IndexByte(line, '\x1b') >= 0 {
		line = ansi.Strip(line)
	}
	for _, character := range line {
		if unicode.IsControl(character) {
			return strings.Map(func(character rune) rune {
				if character == '\t' {
					return ' '
				}
				if unicode.IsControl(character) {
					return -1
				}
				return character
			}, line)
		}
	}
	return line
}
