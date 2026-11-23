package relay

import (
	"errors"
	"strings"
	"testing"
)

func TestSSEReaderPreservesMultilineDataAndBoundsFrames(t *testing.T) {
	reader := NewSSEReader(strings.NewReader("event: response.output_text.delta\ndata: {\"delta\":\ndata: \"hello\"}\n\n"), SSELimits{MaxLineBytes: 64, MaxEventBytes: 128})
	event, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if event.Event != "response.output_text.delta" || event.Data != "{\"delta\":\n\"hello\"}" {
		t.Fatalf("event=%+v", event)
	}

	tooLong := NewSSEReader(strings.NewReader("data: "+strings.Repeat("x", 65)+"\n\n"), SSELimits{MaxLineBytes: 64, MaxEventBytes: 128})
	if _, err := tooLong.Next(); !errors.Is(err, ErrSSELineTooLong) {
		t.Fatalf("err=%v; want ErrSSELineTooLong", err)
	}
}

func TestSSEReaderBoundsUnterminatedEvent(t *testing.T) {
	reader := NewSSEReader(strings.NewReader("data: "+strings.Repeat("x", 20)), SSELimits{MaxLineBytes: 64, MaxEventBytes: 16})
	if _, err := reader.Next(); !errors.Is(err, ErrSSEEventTooLong) {
		t.Fatalf("err=%v; want ErrSSEEventTooLong", err)
	}
}
