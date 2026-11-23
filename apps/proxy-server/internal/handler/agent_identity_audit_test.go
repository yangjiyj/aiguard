package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForwardProxyKeepsSelfReportedNameAndUA(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.example.com/v1/messages", nil)
	req.Header.Set("User-Agent", "client/1")
	req.Header.Set("X-Agent-Type", "main")
	req.Header.Set("X-JJDGuard-Agent-Name", "custom-task")
	rec, err := NewProxyAuditRecord("req", "tenant", "api.example.com", req, LLMProviderMatch{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if rec.UserAgent != "client/1" || !strings.Contains(rec.AgentIdentityHeaders, "custom-task") {
		t.Fatal("identity lost")
	}
}
