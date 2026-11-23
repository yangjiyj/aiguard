package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestEngineCallsDeclareWantSecretTextExceptTriage(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get(WantSecretTextHeader)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/check-input/batch":
			_, _ = w.Write([]byte(`[{"request_id":"a","findings":[],"action":"allow","inspection_status":"completed"}]`))
		default:
			_, _ = w.Write([]byte(`{"request_id":"a","findings":[],"action":"allow","inspection_status":"completed"}`))
		}
	}))
	defer server.Close()
	c := NewClient(server.URL)
	ctx := context.Background()
	_, _ = c.CheckInput(ctx, &CheckInputRequest{RequestID: "a", Content: "x"})
	_, _ = c.CheckInputBatch(ctx, []*CheckInputRequest{{RequestID: "a", Content: "x"}})
	_, _ = c.CheckOutput(ctx, "a", "x", map[string]interface{}{})
	_, _ = c.ApplyContext(ctx, &ApplyContextRequest{})
	_, _ = c.CheckTriage(ctx, &CheckTriageRequest{})

	if WantSecretTextHeader != "X-JJD-Want-Secret-Text" {
		t.Fatalf("header name=%q", WantSecretTextHeader)
	}
	for _, path := range []string{"/check-input/", "/check-input/batch", "/check-output/", "/apply-context/"} {
		got, ok := seen[path]
		if !ok || got != "1" {
			t.Errorf("%s: header=%q called=%v", path, got, ok)
		}
	}
	if got, ok := seen["/check-triage/"]; !ok || got != "" {
		t.Errorf("/check-triage/ 不应带头: %q called=%v", got, ok)
	}
}
