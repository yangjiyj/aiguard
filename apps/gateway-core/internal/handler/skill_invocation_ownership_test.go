package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 热修复：上报 Skill 调用时带上请求的用户 / 项目 / API key，控制面据此给告警做归属。
func TestRecordSkillInvocationCarriesRequestOwnership(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"invocation_id": "inv-owned"})
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "internal")
	_, err := client.RecordSkillInvocation(context.Background(), &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", RequestID: "request-a", SessionID: "session-a",
		UserID: "user-dev1", ProjectID: "proj-npu", ClientID: "key-123",
	}, "call-a", skillInvocationRecord{
		CanonicalName: "npu300-debug", Status: "confirmed", RawDecision: "confirm", EffectiveDecision: "confirm",
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if body["user_id"] != "user-dev1" || body["project_id"] != "proj-npu" || body["api_key_id"] != "key-123" {
		t.Fatalf("ownership not reported: %#v", body)
	}
}

func TestRecordSkillInvocationOmitsEmptyOwnership(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"invocation_id": "inv-anon"})
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "internal")
	_, err := client.RecordSkillInvocation(context.Background(), &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", RequestID: "request-a", SessionID: "session-a",
	}, "call-a", skillInvocationRecord{CanonicalName: "pdf", Status: "proposed", RawDecision: "allow", EffectiveDecision: "allow"})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	for _, key := range []string{"user_id", "project_id", "api_key_id"} {
		if _, exists := body[key]; exists {
			t.Fatalf("%s must be omitted when unknown (old control plane compatibility): %#v", key, body)
		}
	}
}
