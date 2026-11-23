package headeraudit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientAppendCriticalUsesAuthenticatedStrictEnvelope(t *testing.T) {
	const canary = "must-not-leak-canary"
	var body, token string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = r.Header.Get(InternalTokenHeader)
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	e := Event{OccurrenceID: "be0e16c4-ac4a-4d1c-8f93-5bb20b4af755", Service: "gateway-core.api", HeaderKind: "session_id", RequestID: "req-1", SourceIP: "203.0.113.1"}
	c := NewClient(srv.URL, "secret")
	if err := c.AppendCritical(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if token != "secret" || !strings.Contains(body, `"occurrence_id":"be0e16c4-ac4a-4d1c-8f93-5bb20b4af755"`) || strings.Contains(body, canary) {
		t.Fatalf("bad request token-set=%v body=%s", token != "", body)
	}
}

func TestClientAppendCriticalFailsClosed(t *testing.T) {
	e := Event{OccurrenceID: "be0e16c4-ac4a-4d1c-8f93-5bb20b4af755", Service: "gateway-core.api", HeaderKind: "session_id", RequestID: "req-1", SourceIP: "203.0.113.1"}
	for _, tc := range []struct {
		name string
		c    *Client
	}{
		{"missing-url", NewClient("", "secret")},
		{"missing-secret", NewClient("http://127.0.0.1", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.AppendCritical(context.Background(), e); err == nil {
				t.Fatal("AppendCritical unexpectedly succeeded")
			}
		})
	}
}

func TestClientAppendCriticalRequires204(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer srv.Close()
			c := NewClient(srv.URL, "secret")
			err := c.AppendCritical(context.Background(), Event{OccurrenceID: "be0e16c4-ac4a-4d1c-8f93-5bb20b4af755", Service: "proxy-server.mitm", HeaderKind: "agent_type", RequestID: "req"})
			if err == nil {
				t.Fatalf("status %d accepted", status)
			}
		})
	}
}
