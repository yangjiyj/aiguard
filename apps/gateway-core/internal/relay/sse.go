package relay

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

var (
	ErrSSELineTooLong  = errors.New("SSE line exceeds configured limit")
	ErrSSEEventTooLong = errors.New("SSE event exceeds configured limit")
)

type SSELimits struct {
	MaxLineBytes  int
	MaxEventBytes int
	// PreserveRaw retains complete wire frames, including comment-only frames.
	PreserveRaw bool
}

type SSEEvent struct {
	Event string
	Data  string
	Raw   []byte
}

type SSEReader struct {
	reader        *bufio.Reader
	maxLineBytes  int
	maxEventBytes int
	eventName     string
	data          strings.Builder
	eventBytes    int
	eof           bool
	preserveRaw   bool
	raw           []byte
}

func NewSSEReader(input io.Reader, limits SSELimits) *SSEReader {
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = 64 << 10
	}
	if limits.MaxEventBytes <= 0 {
		limits.MaxEventBytes = 1 << 20
	}
	bufferSize := limits.MaxLineBytes
	if bufferSize > 64<<10 {
		bufferSize = 64 << 10
	}
	return &SSEReader{
		reader:        bufio.NewReaderSize(input, bufferSize),
		maxLineBytes:  limits.MaxLineBytes,
		maxEventBytes: limits.MaxEventBytes,
		preserveRaw:   limits.PreserveRaw,
	}
}

func (r *SSEReader) Next() (SSEEvent, error) {
	if r.eof {
		return SSEEvent{}, io.EOF
	}
	for {
		line, err := r.readLine()
		if err != nil && !errors.Is(err, io.EOF) {
			if r.preserveRaw {
				r.raw = append(r.raw, line...)
			}
			return SSEEvent{}, err
		}
		if len(line) > 0 {
			if r.eventBytes+len(line) > r.maxEventBytes {
				if r.preserveRaw {
					r.raw = append(r.raw, line...)
				}
				return SSEEvent{}, ErrSSEEventTooLong
			}
			r.eventBytes += len(line)
			if r.preserveRaw {
				r.raw = append(r.raw, line...)
			}
		}
		trimmed := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if trimmed == "" {
			if r.data.Len() > 0 || r.eventName != "" || (r.preserveRaw && len(r.raw) > 0) {
				event := SSEEvent{Event: r.eventName, Data: r.data.String(), Raw: r.raw}
				r.resetEvent()
				if errors.Is(err, io.EOF) {
					r.eof = true
				}
				return event, nil
			}
		} else {
			r.parseLine(trimmed)
		}
		if errors.Is(err, io.EOF) {
			if r.data.Len() > 0 || r.eventName != "" || (r.preserveRaw && len(r.raw) > 0) {
				event := SSEEvent{Event: r.eventName, Data: r.data.String(), Raw: r.raw}
				r.resetEvent()
				r.eof = true
				return event, nil
			}
			r.eof = true
			return SSEEvent{}, io.EOF
		}
	}
}

func (r *SSEReader) readLine() ([]byte, error) {
	var line []byte
	for {
		part, err := r.reader.ReadSlice('\n')
		if len(line)+len(part) > r.maxLineBytes {
			if r.preserveRaw {
				line = append(line, part...)
			}
			return line, ErrSSELineTooLong
		}
		line = append(line, part...)
		if err == nil {
			return line, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

// RemainingRaw includes bytes consumed by a failed frame parser and its
// buffered transport remainder. The caller applies fail-open policy first.
func (r *SSEReader) RemainingRaw() io.Reader {
	pending := r.raw
	r.resetEvent()
	r.eof = true
	return io.MultiReader(bytes.NewReader(pending), r.reader)
}

func (r *SSEReader) parseLine(line string) {
	if strings.HasPrefix(line, ":") {
		return
	}
	field, value, found := strings.Cut(line, ":")
	if !found {
		field, value = line, ""
	}
	value = strings.TrimPrefix(value, " ")
	switch field {
	case "event":
		r.eventName = value
	case "data":
		if r.data.Len() > 0 {
			r.data.WriteByte('\n')
		}
		r.data.WriteString(value)
	}
}

func (r *SSEReader) resetEvent() {
	r.eventName = ""
	r.data.Reset()
	r.eventBytes = 0
	r.raw = nil
}
