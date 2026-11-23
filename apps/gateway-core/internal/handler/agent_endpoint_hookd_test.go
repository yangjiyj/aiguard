package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointEventsHookdEnvelopeGzipAndBoundaries(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	event := map[string]any{"event_id": "11111111-1111-7111-8111-111111111111", "event_type": "session.start", "occurred_at": now, "agent": map[string]any{"product": "claude-code"}, "session": map[string]any{"session_id": "s"}, "context": map[string]any{"machine_id": "m", "hostname": "h", "os_user": "u"}}
	batch := map[string]any{"schema_version": "events.v1", "endpoint_id": "ep_fixture", "hookd_version": "dev", "sent_at": now, "events": []any{event}}
	calls := 0
	var forwarded []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		forwarded, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") != "" {
			t.Error("expanded body still marked gzip")
		}
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("endpoint credential lost")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":["11111111-1111-7111-8111-111111111111"],"duplicates":[],"rejected":[]}`))
	}))
	defer server.Close()
	g := &AgentEndpointGateway{controlURL: server.URL, client: server.Client(), bodyLimit: 8 << 20}
	send := func(endpoint string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(batch)
		var body bytes.Buffer
		z := gzip.NewWriter(&body)
		_, _ = z.Write(raw)
		_ = z.Close()
		req := httptest.NewRequest(http.MethodPost, "/agent/v1/events", &body)
		req.Header.Set("Content-Encoding", "gzip")
		rec := httptest.NewRecorder()
		g.events(rec, req, "fixture", map[string]any{"endpoint_id": endpoint, "capture_level": "metadata"})
		return rec
	}
	rec := send("ep_fixture")
	if rec.Code != 200 || calls != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(forwarded, []byte(`"session":{"session_id":"s"}`)) {
		t.Fatal("gateway changed nested payload")
	}
	rec = send("ep_otherxx")
	if rec.Code != 401 || calls != 1 {
		t.Fatal("endpoint mismatch forwarded")
	}
	event["content"] = map[string]any{"user_prompt": "do not forward"}
	rec = send("ep_fixture")
	if rec.Code != 422 || calls != 1 {
		t.Fatal("capture permission bypass")
	}
	delete(event, "content")
	event["api_key"] = "do not forward"
	rec = send("ep_fixture")
	if rec.Code != 422 || calls != 1 || strings.Contains(rec.Body.String(), "do not forward") {
		t.Fatal("unknown sensitive field leaked")
	}
	for _, container := range []any{"do not forward", map[string]any{"result": "do not forward"}, []any{"do not forward"}} {
		batch["events"] = []any{map[string]any{"event_id": "11111111-1111-7111-8111-111111111111", "event_type": "tool.post", "occurred_at": now, "result": container}}
		rec = send("ep_fixture")
		if rec.Code != 422 || calls != 1 || strings.Contains(rec.Body.String(), "do not forward") {
			t.Fatal("legacy capture bypass")
		}
	}

}
