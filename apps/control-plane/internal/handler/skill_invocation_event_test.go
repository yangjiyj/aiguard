package handler

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// 热修复：skill_invocation_risk 告警必须带上请求的用户 / 项目归属，否则按用户筛选查不到，
// 项目被写死成默认项目。

func TestSkillInvocationEventCarriesRequestOwnership(t *testing.T) {
	event := buildSkillInvocationSecurityEvent("tenant-a", recordSkillInvocationRequest{
		RequestID: "req-1", ToolCallID: "call-1", CanonicalName: "npu300-debug",
		RawDecision: "confirm", EffectiveDecision: "confirm",
		UserID: "user-dev1", ProjectID: "proj-npu", APIKeyID: "key-123",
	})
	if event.UserID != "user-dev1" || event.ProjectID != "proj-npu" {
		t.Fatalf("event lost ownership: user=%q project=%q", event.UserID, event.ProjectID)
	}
	if event.PrincipalKey != "user-dev1" {
		t.Fatalf("principal key must be the user id, got %q", event.PrincipalKey)
	}
	if got, _ := event.MatchedSummary["api_key_id"].(string); got != "key-123" {
		t.Fatalf("api key must be kept in the summary, got %#v", event.MatchedSummary["api_key_id"])
	}
	if event.Severity != "high" || event.ActionTaken != "confirm" {
		t.Fatalf("confirm decision semantics changed: %+v", event)
	}
}

func TestSkillInvocationEventPrincipalFallsBackToAPIKey(t *testing.T) {
	event := buildSkillInvocationSecurityEvent("tenant-a", recordSkillInvocationRequest{
		RequestID: "req-2", ToolCallID: "call-2", CanonicalName: "pdf", EffectiveDecision: "audit",
		ProjectID: "proj-npu", APIKeyID: "key-123",
	})
	if event.UserID != "" || event.PrincipalKey != "key-123" {
		t.Fatalf("without a user the key id is the principal: user=%q principal=%q", event.UserID, event.PrincipalKey)
	}
}

func TestSkillInvocationEventOldGatewayBehaviorUnchanged(t *testing.T) {
	// 旧网关不传这些字段：行为与改动前完全一致（默认项目、无用户、无主体键）。
	event := buildSkillInvocationSecurityEvent("tenant-a", recordSkillInvocationRequest{
		RequestID: "req-3", ToolCallID: "call-3", CanonicalName: "pdf", EffectiveDecision: "audit",
	})
	if event.ProjectID != defaultEvalIntegrationProjectID || event.UserID != "" || event.PrincipalKey != "" {
		t.Fatalf("old gateway payload must keep the previous behavior: %+v", event)
	}
	if _, exists := event.MatchedSummary["api_key_id"]; exists {
		t.Fatalf("no api key means no api_key_id in the summary: %#v", event.MatchedSummary)
	}
	if event.Severity != "low" || event.ActionTaken != "audit" {
		t.Fatalf("audit decision semantics changed: %+v", event)
	}
}

func TestSkillInvocationEventBlankOwnershipIsTreatedAsMissing(t *testing.T) {
	event := buildSkillInvocationSecurityEvent("tenant-a", recordSkillInvocationRequest{
		RequestID: "req-4", ToolCallID: "call-4", CanonicalName: "pdf", EffectiveDecision: "allow",
		UserID: "  ", ProjectID: "\t", APIKeyID: " ",
	})
	if event.ProjectID != defaultEvalIntegrationProjectID || event.UserID != "" || event.PrincipalKey != "" {
		t.Fatalf("blank ownership must fall back to defaults: %+v", event)
	}
}

func TestRecordSkillInvocationRequestDecodesOldAndNewPayloads(t *testing.T) {
	decode := func(payload string) (recordSkillInvocationRequest, error) {
		var request recordSkillInvocationRequest
		decoder := json.NewDecoder(bytes.NewReader([]byte(payload)))
		decoder.DisallowUnknownFields() // 与 decodeStrictSkillJSON 同口径
		err := decoder.Decode(&request)
		return request, err
	}
	if _, err := decode(`{"request_id":"r","tool_call_id":"c","canonical_name":"pdf","status":"proposed","raw_decision":"allow","effective_decision":"allow"}`); err != nil {
		t.Fatalf("old gateway payload must still decode: %v", err)
	}
	request, err := decode(`{"request_id":"r","tool_call_id":"c","canonical_name":"pdf","status":"proposed","raw_decision":"allow","effective_decision":"allow","user_id":"u1","project_id":"p1","api_key_id":"k1"}`)
	if err != nil || request.UserID != "u1" || request.ProjectID != "p1" || request.APIKeyID != "k1" {
		t.Fatalf("new payload fields not decoded: %+v err=%v", request, err)
	}
	if strings.Contains(skillEventTestJSON(t, recordSkillInvocationRequest{RequestID: "r"}), "user_id") {
		t.Fatal("empty ownership fields must be omitted when marshaling")
	}
}

func skillEventTestJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
