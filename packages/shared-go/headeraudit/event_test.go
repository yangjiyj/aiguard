package headeraudit

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
)

func TestNewEventUsesServerOccurrenceAndUntrustedRemoteAddr(t *testing.T) {
	h := make(http.Header)
	h["X-Request-Id"] = []string{"display-123"}
	h["x-request-id"] = []string{"spoof-second"}
	h.Set("X-Forwarded-For", "canary-forwarded")
	e, err := NewEvent("gateway-core.api", "session_id", h, "203.0.113.7:4312")
	if err != nil {
		t.Fatal(err)
	}
	if e.OccurrenceID == "" || e.RequestID == "" || e.RequestID == "display-123" || e.RequestID == "spoof-second" {
		t.Fatalf("unsafe identity: occurrence=%q request=%q", e.OccurrenceID, e.RequestID)
	}
	if e.SourceIP != net.ParseIP("203.0.113.7").String() {
		t.Fatalf("source_ip=%q", e.SourceIP)
	}
	b, _ := json.Marshal(e)
	if string(b) == "" || containsAny(string(b), "canary-forwarded", "display-123", "spoof-second") {
		t.Fatalf("event leaked untrusted values: %s", b)
	}
}

func TestNewEventAllowsClosedServiceAndKindOnly(t *testing.T) {
	for _, tc := range []struct{ service, kind string }{
		{"control-plane.internal", "internal_token"},
		{"control-plane.eval-integration", "tenant_id"},
		{"control-plane.portal-integration", "tenant_id"},
		{"gateway-core.api", "workspace_id"},
		{"gateway-core.reverse-proxy", "agent_type"},
		{"proxy-server.mitm", "agent_type"},
	} {
		if _, err := NewEvent(tc.service, tc.kind, nil, ""); err != nil {
			t.Fatalf("NewEvent(%q,%q): %v", tc.service, tc.kind, err)
		}
	}
	if _, err := NewEvent("evil-service", "tenant_id", nil, ""); err == nil {
		t.Fatal("unknown service accepted")
	}
	if _, err := NewEvent("gateway-core.api", "secret_value", nil, ""); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if value != "" && len(s) >= len(value) {
			for i := 0; i+len(value) <= len(s); i++ {
				if s[i:i+len(value)] == value {
					return true
				}
			}
		}
	}
	return false
}
