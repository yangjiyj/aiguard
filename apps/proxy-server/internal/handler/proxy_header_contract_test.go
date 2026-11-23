package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewProxyAuditRecordPropagatesAgentHeaderConflict(t *testing.T) {
	req := httptest.NewRequest("POST", "https://example.com/v1/chat", nil)
	req.Header["X-JJDGuard-Agent-Type"] = []string{"agent-new-canary"}
	req.Header["X-NewAPI-Agent-Type"] = []string{"agent-old-canary"}
	record, err := NewProxyAuditRecord("req", "tenant", "example.com", req, LLMProviderMatch{}, true)
	if record.RequestID != "" || err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}
