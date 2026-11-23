package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAuthInfoRetainsAllowlistedIdentityHeaders(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/responses", nil)
	r.Header.Set("User-Agent", "codex_exec/1")
	r.Header.Set("X-Agent-Type", "main")
	r.Header.Set("Authorization", "Bearer hidden")
	a := GetAuthInfo(r)
	if a.UserAgent != "codex_exec/1" || !strings.Contains(a.AgentIdentityHeaders, "main") || strings.Contains(a.AgentIdentityHeaders, "hidden") {
		t.Fatalf("metadata lost or secret retained")
	}
}
