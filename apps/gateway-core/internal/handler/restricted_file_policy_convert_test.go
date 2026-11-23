package handler

import (
	"encoding/json"
	"testing"
)

// JSON 往返：restricted_file_patterns/restricted_file_action 进 EffectivePolicy.RestrictedFiles。
func TestConvertAgentGuardPolicyRestrictedFilesRoundTrip(t *testing.T) {
	raw := `{"data":{"id":"p1","name":"x","policy_version":"v1","mode":"audit","default_action":"allow","fail_policy":"fail_closed","rules":[],"exceptions":[],"restricted_file_patterns":["*.pdf","docs/**/*.docx"],"restricted_file_action":"alert_allow"}}`
	var resp agentGuardPolicyAPIResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	policy := convertAgentGuardPolicy(resp.Data)
	if policy.RestrictedFiles == nil {
		t.Fatalf("RestrictedFiles should be set: %+v", policy)
	}
	if len(policy.RestrictedFiles.Patterns) != 2 || policy.RestrictedFiles.Patterns[0] != "*.pdf" {
		t.Fatalf("patterns=%v", policy.RestrictedFiles.Patterns)
	}
	if policy.RestrictedFiles.Action != "alert_allow" {
		t.Fatalf("action=%q", policy.RestrictedFiles.Action)
	}
}

// 非法模式整体丢弃该列表（不拖垮策略其余部分）。
func TestConvertAgentGuardPolicyRestrictedFilesInvalidDropped(t *testing.T) {
	raw := `{"data":{"id":"p1","mode":"audit","default_action":"allow","fail_policy":"fail_closed","rules":[],"exceptions":[],"restricted_file_patterns":["http://x.com/a.pdf"],"restricted_file_action":"block"}}`
	var resp agentGuardPolicyAPIResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	policy := convertAgentGuardPolicy(resp.Data)
	if policy.RestrictedFiles != nil {
		t.Fatalf("invalid patterns should be dropped, got %+v", policy.RestrictedFiles)
	}
	// 策略其余部分仍正常转换
	if string(policy.Mode) == "" && policy.DefaultAction == "" {
		t.Fatalf("rest of policy should still convert: %+v", policy)
	}
}

// 非法动作丢弃；缺字段时为 nil。
func TestConvertAgentGuardPolicyRestrictedFilesInvalidActionAndAbsent(t *testing.T) {
	badAction := `{"data":{"id":"p1","mode":"audit","default_action":"allow","fail_policy":"fail_closed","rules":[],"exceptions":[],"restricted_file_patterns":["*.pdf"],"restricted_file_action":"confirm"}}`
	var resp agentGuardPolicyAPIResponse
	if err := json.Unmarshal([]byte(badAction), &resp); err != nil {
		t.Fatal(err)
	}
	if policy := convertAgentGuardPolicy(resp.Data); policy.RestrictedFiles != nil {
		t.Fatalf("invalid action should drop restricted files, got %+v", policy.RestrictedFiles)
	}

	absent := `{"data":{"id":"p1","mode":"audit","default_action":"allow","fail_policy":"fail_closed","rules":[],"exceptions":[]}}`
	var resp2 agentGuardPolicyAPIResponse
	if err := json.Unmarshal([]byte(absent), &resp2); err != nil {
		t.Fatal(err)
	}
	if policy := convertAgentGuardPolicy(resp2.Data); policy.RestrictedFiles != nil {
		t.Fatalf("absent fields should leave RestrictedFiles nil, got %+v", policy.RestrictedFiles)
	}
}

// 空动作默认为 block。
func TestConvertAgentGuardPolicyRestrictedFilesDefaultAction(t *testing.T) {
	raw := `{"data":{"id":"p1","mode":"audit","default_action":"allow","fail_policy":"fail_closed","rules":[],"exceptions":[],"restricted_file_patterns":["*.pdf"]}}`
	var resp agentGuardPolicyAPIResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	policy := convertAgentGuardPolicy(resp.Data)
	if policy.RestrictedFiles == nil || policy.RestrictedFiles.Action != "block" {
		t.Fatalf("default action should be block, got %+v", policy.RestrictedFiles)
	}
}
