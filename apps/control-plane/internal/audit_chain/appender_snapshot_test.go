package audit_chain

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type gatedPayloadWriter struct {
	started chan struct{}
	release chan struct{}
	got     chan []byte
}

func (w *gatedPayloadWriter) Append(_ context.Context, _, _, _ string, payload map[string]any) error {
	close(w.started)
	<-w.release
	data, err := json.Marshal(payload)
	if err == nil {
		w.got <- data
	}
	return err
}
func TestAppenderEnqueueOwnsImmutableJSONSnapshot(t *testing.T) {
	w := &gatedPayloadWriter{started: make(chan struct{}), release: make(chan struct{}), got: make(chan []byte, 1)}
	a := NewAppender(w, false)
	nested := map[string]any{"value": "before"}
	array := []any{"original"}
	payload := map[string]any{"nested": nested, "array": array}
	a.Enqueue("tenant", "event", "id", payload)
	<-w.started
	nested["value"] = "after"
	array[0] = "changed"
	payload["extra"] = true
	close(w.release)
	got := <-w.got
	if string(got) != `{"array":["original"],"nested":{"value":"before"}}` {
		t.Fatalf("enqueue retained caller references: %s", got)
	}
}

type retrySnapshotWriter struct {
	caller map[string]any
	calls  int
	first  []byte
}

func (w *retrySnapshotWriter) Append(_ context.Context, _, _, _ string, payload map[string]any) error {
	w.calls++
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if w.calls == 1 {
		w.first = data
		w.caller["value"] = "changed"
		return errors.New("transient test failure")
	}
	if string(w.first) != string(data) {
		return errors.New("audit retry payload changed")
	}
	return nil
}
func TestAppenderSyncRetriesUseFrozenJSON(t *testing.T) {
	payload := map[string]any{"value": "original"}
	w := &retrySnapshotWriter{caller: payload}
	a := NewAppender(w, false)
	if err := a.AppendSync(context.Background(), "tenant", "event", "id", payload); err != nil || w.calls != 2 {
		t.Fatalf("retry did not retain first evidence: calls=%d %v", w.calls, err)
	}
}
