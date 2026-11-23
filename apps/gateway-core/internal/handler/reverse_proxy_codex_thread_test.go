package handler

import (
	"net/http/httptest"
	"testing"
)

func TestReverseProxyCodexThreadSurvivesContextAndProcessChanges(t *testing.T) {
	makeRecord := func(thread, session, body string) reverseProxyAuditRecord {
		req := httptest.NewRequest("POST", "/v1/responses", nil)
		req.Header.Set("User-Agent", "codex_exec/0.149.1")
		req.Header.Set("Thread-Id", thread)
		req.Header.Set("Session-Id", session)
		r, err := newReverseProxyAuditRecord("req", "tenant", "api.example-gateway.com", nil, req, []byte(body), nil, "success", 200, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a := makeRecord("thread-a", "process-1", `{"input":"same task","instructions":"old"}`)
	b := makeRecord("thread-a", "process-2", `{"input":"continued task","instructions":"changed"}`)
	c := makeRecord("thread-b", "process-2", `{"input":"same task","instructions":"old"}`)
	if a.AgentType != "openai-codex" || a.SessionID == "" {
		t.Fatalf("missing native identity: agent=%s", a.AgentType)
	}
	if a.SessionID != b.SessionID {
		t.Fatal("same thread split after restart/context change")
	}
	if a.SessionID == c.SessionID {
		t.Fatal("independent same-title tasks merged")
	}
}
