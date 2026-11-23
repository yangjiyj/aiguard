package relay

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestSSEPreserveRawHardening(t *testing.T) {
	limits := SSELimits{MaxLineBytes: 128, MaxEventBytes: 512}
	preserve := reflect.ValueOf(&limits).Elem().FieldByName("PreserveRaw")
	if !preserve.IsValid() {
		t.Fatal("bounded SSE reader must expose opt-in PreserveRaw")
	}
	preserve.SetBool(true)
	frames := []string{": heartbeat\r\n\r\n", "id: response-1\r\nretry: 7000\r\nevent: delta\r\ndata: {\"delta\":\"safe\"}\r\n\r\n", "event: terminal\ndata: [DONE]\n\n"}
	reader := NewSSEReader(strings.NewReader(strings.Join(frames, "")), limits)
	for _, want := range frames {
		event, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		raw := reflect.ValueOf(event).FieldByName("Raw")
		if !raw.IsValid() || string(raw.Bytes()) != want {
			t.Fatalf("original event framing lost: event=%+v want=%q", event, want)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("end=%v", err)
	}
}

func TestSSEPreserveRawHardeningErrorRemainderIsByteExact(t *testing.T) {
	for _, tc := range []struct {
		name, body  string
		line, event int
		want        error
	}{
		{"line", ": h\nid: longer than limit\n\ndata: next\n\n", 8, 128, ErrSSELineTooLong},
		{"event", "id: one\ndata: safe\n\ndata: next\n\n", 64, 12, ErrSSEEventTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := SSELimits{MaxLineBytes: tc.line, MaxEventBytes: tc.event}
			field := reflect.ValueOf(&limits).Elem().FieldByName("PreserveRaw")
			if !field.IsValid() {
				t.Fatal("missing opt-in raw preservation")
			}
			field.SetBool(true)
			r := NewSSEReader(strings.NewReader(tc.body), limits)
			if _, err := r.Next(); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			remaining, ok := any(r).(interface{ RemainingRaw() io.Reader })
			if !ok {
				t.Fatal("failed parser has no byte-exact fail-open remainder")
			}
			raw, err := io.ReadAll(remaining.RemainingRaw())
			if err != nil || string(raw) != tc.body {
				t.Fatalf("consumed failure bytes lost: %q want=%q err=%v", raw, tc.body, err)
			}
		})
	}
}
