package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceLoginLocksUsernameAcrossIPsAndExpires(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()
	deps := &Dependencies{RedisClient: client}
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest("POST", "/admin/v1/service-login", nil)
		req.RemoteAddr = "10.0.0." + string(rune('a'+i)) + ":1234"
		w := httptest.NewRecorder()
		got := allowServiceLoginAttempt(w, req, deps, "connector")
		if got != (i < 10) {
			t.Fatalf("attempt %d allowed=%v status=%d", i, got, w.Code)
		}
		if i == 10 && (w.Code != 429 || w.Header().Get("Retry-After") != "60") {
			t.Fatalf("missing lock response")
		}
	}
	server.FastForward(time.Minute)
	if !allowServiceLoginAttempt(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), deps, "connector") {
		t.Fatal("lock did not expire")
	}
}
func TestServiceLoginLimiterUnavailableFailsClosed(t *testing.T) {
	w := httptest.NewRecorder()
	if allowServiceLoginAttempt(w, httptest.NewRequest("POST", "/", nil), &Dependencies{}, "connector") || w.Code != 503 {
		t.Fatal("missing limiter must fail closed")
	}
}

func TestConnectorRiskMetadataExcludesGatewayEvidence(t *testing.T) {
	e := &repository.SecurityEvent{ID: "risk1", TenantID: "tenant-a", RequestID: "request1", AgentInstanceID: "agent-known", RuleName: "SECRET-RULE", EvidenceRef: "SECRET-REF", MatchedSummary: map[string]interface{}{"body": "SECRET-BODY", "api_key": "SECRET-KEY", "agent_instance_id": "SECRET-SPOOF", "native_url": "https://private.invalid/SECRET"}}
	data := connectorRiskMetadata(e)
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("sensitive event field escaped metadata projection: %s", raw)
	}
	allowed := []string{"id", "request_id", "tenant_id", "project_id", "user_id", "event_type", "severity", "rule_id", "action_taken", "principal_key", "created_at", "agent_instance_id", "risk_category", "risk_factors", "native_url"}
	for _, key := range allowed {
		if _, ok := data[key]; !ok {
			t.Fatalf("missing correlation key %s", key)
		}
	}
	if len(data) != len(allowed) {
		t.Fatalf("unexpected fields: %v", data)
	}
	if data["agent_instance_id"] != e.AgentInstanceID || data["native_url"] != "/security/alerts?request_id=request1&event_id=risk1" {
		t.Fatal("native identity or record link did not come from trusted columns")
	}
}
