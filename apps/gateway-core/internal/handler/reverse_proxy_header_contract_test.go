package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReverseProxyAuditRecordSessionCompatibilityAndConflict(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("X-JJDGuard-Session-Id", "session-ok")
	req.Header.Set("X-NewAPI-Session-Id", "session-ok")
	record, err := newReverseProxyAuditRecord("req", "tenant", "example.com", nil, req, nil, nil, "success", 200, 0, 0)
	if err != nil || record.SessionID != "session-ok" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	req.Header.Set("X-NewAPI-Session-Id", "session-conflict-canary")
	_, err = newReverseProxyAuditRecord("req", "tenant", "example.com", nil, req, nil, nil, "success", 200, 0, 0)
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("unsafe conflict=%v", err)
	}
}
