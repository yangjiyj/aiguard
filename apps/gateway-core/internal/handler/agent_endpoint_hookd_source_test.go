package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Real hookd a0296bf6 wire batches (see packages/shared-go/endpointevents/testdata/
// hookd-a0296bf6/README.md). Only timestamps are shifted so the gateway's 30d/24h
// window, which uses wall-clock now, keeps accepting the captured bytes.
const gwHookdFixtureDir = "../../../../packages/shared-go/endpointevents/testdata/hookd-a0296bf6/"

func gwLoadRebasedHookdBatch(t *testing.T, name string) (map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(gwHookdFixtureDir + name)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var batch map[string]any
	if err := d.Decode(&batch); err != nil {
		t.Fatal(err)
	}
	sent, err := time.Parse(time.RFC3339Nano, batch["sent_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	shift := time.Since(sent)
	rebase := func(s string) string {
		ts, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts.Add(shift).UTC().Format(time.RFC3339Nano)
	}
	batch["sent_at"] = rebase(batch["sent_at"].(string))
	for _, item := range batch["events"].([]any) {
		event := item.(map[string]any)
		event["occurred_at"] = rebase(event["occurred_at"].(string))
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return batch, body
}

func gwPostHookdBatch(t *testing.T, body []byte, endpoint string) (*httptest.ResponseRecorder, int, []byte) {
	t.Helper()
	calls := 0
	var forwarded []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		forwarded, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":[],"duplicates":[],"rejected":[]}`))
	}))
	defer upstream.Close()
	g := &AgentEndpointGateway{controlURL: upstream.URL, client: upstream.Client(), bodyLimit: 8 << 20}
	var gz bytes.Buffer
	z := gzip.NewWriter(&gz)
	_, _ = z.Write(body)
	_ = z.Close()
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/events", &gz)
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	g.events(rec, req, "fixture", map[string]any{"endpoint_id": endpoint, "capture_level": "metadata"})
	return rec, calls, forwarded
}

// Covers F-EVSRC through the real gateway handler: (a) T13 deny batch, (b) T15
// reject batch, (c) the 7+1 mixed batch is forwarded intact, (d) bogus still 422.
func TestEndpointEventsHookdA0296bf6DecisionSources(t *testing.T) {
	for _, tc := range []struct{ file, source string }{
		{"batch-a-cc-t13-deny.json", "agent_authorization"},
		{"batch-b-cc-t15-reject.json", "agent_approval"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			batch, body := gwLoadRebasedHookdBatch(t, tc.file)
			if !bytes.Contains(body, []byte(`"source":"`+tc.source+`"`)) {
				t.Fatalf("fixture lost source %s", tc.source)
			}
			rec, calls, forwarded := gwPostHookdBatch(t, body, batch["endpoint_id"].(string))
			if rec.Code != http.StatusOK || calls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", rec.Code, calls, rec.Body.String())
			}
			if !bytes.Equal(forwarded, body) {
				t.Fatal("gateway changed the hookd batch")
			}
		})
	}
	t.Run("bogus source rejected", func(t *testing.T) {
		batch, body := gwLoadRebasedHookdBatch(t, "batch-a-cc-t13-deny.json")
		body = bytes.Replace(body, []byte(`"source":"agent_authorization"`), []byte(`"source":"bogus"`), 1)
		if !bytes.Contains(body, []byte(`"source":"bogus"`)) {
			t.Fatal("mutation not applied")
		}
		rec, calls, _ := gwPostHookdBatch(t, body, batch["endpoint_id"].(string))
		if rec.Code != http.StatusUnprocessableEntity || calls != 0 || !strings.Contains(rec.Body.String(), "AGENT_PRIVACY_REJECTED") {
			t.Fatalf("bogus source not rejected: status=%d calls=%d body=%s", rec.Code, calls, rec.Body.String())
		}
	})
}
