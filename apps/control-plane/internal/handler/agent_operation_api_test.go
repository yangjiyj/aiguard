package handler

import (
	"strings"
	"testing"
)

func TestDecodeAgentOperationPolicyRequestIsStrictAndBounded(t *testing.T) {
	valid, err := decodeAgentOperationPolicyRequest(strings.NewReader(`{"scope_type":"application","scope_ref":"app-1","mode":"observe","action":"alert_allow","discardable_paths":["dist"],"notify_channel_ids":["channel-1","channel-1"],"version":2}`))
	if err != nil {
		t.Fatalf("decode valid request: %v", err)
	}
	if valid.Mode != "audit" {
		t.Fatalf("observe input mode=%q want audit", valid.Mode)
	}
	if len(valid.NotifyChannelIDs) != 1 {
		t.Fatalf("channel ids not deduplicated: %#v", valid.NotifyChannelIDs)
	}
	invalid := []string{
		`null`,
		`{"scope_type":"tenant","mode":"audit","action":"record","unknown":true}`,
		`{"scope_type":"tenant","mode":"audit","action":"record"} trailing`,
		`{"scope_type":"tenant","mode":"disabled","action":"record"}`,
		`{"scope_type":"tenant","mode":"audit","action":"allow"}`,
		`{"scope_type":"project","mode":"audit","action":"record"}`,
		`{"scope_type":"tenant","scope_ref":"not-empty","mode":"audit","action":"record"}`,
		`{"scope_type":"application","scope_ref":"","mode":"audit","action":"record"}`,
		`{"scope_type":"tenant","mode":"audit","action":"record","version":0}`,
		`{"scope_type":"application","scope_ref":"` + strings.Repeat("a", maxAgentOperationScopeRefLength+1) + `","mode":"audit","action":"record","version":1}`,
	}
	for _, raw := range invalid {
		if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err == nil {
			t.Fatalf("invalid request accepted: %s", raw)
		}
	}
	if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(strings.Repeat(" ", maxAgentOperationPolicyBodyBytes+1))); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestAgentOperationDiscardablePathsAreSafelyNormalized(t *testing.T) {
	invalid := []string{
		"", ".", "./dist", "../dist", "dist/../etc", "dist//child",
		"/", "/home/alice", "/repo", `C:\\`, `C:\\repo`, "~", "~/repo",
		"repo", ".git", "dir/.git", "dist/*", "dist[0-9]", `dist\\child`,
		strings.Repeat("a/", maxAgentOperationPathDepth) + "leaf",
	}
	for _, candidate := range invalid {
		raw := `{"scope_type":"tenant","mode":"audit","action":"record","version":1,"discardable_paths":["` + candidate + `"]}`
		if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err == nil {
			t.Errorf("unsafe path accepted: %q", candidate)
		}
	}
	nul := "{\"scope_type\":\"tenant\",\"mode\":\"audit\",\"action\":\"record\",\"version\":1,\"discardable_paths\":[\"dist\\u0000secret\"]}"
	if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(nul)); err == nil {
		t.Fatal("NUL path accepted")
	}
	valid, err := decodeAgentOperationPolicyRequest(strings.NewReader(
		`{"scope_type":"tenant","mode":"audit","action":"record","version":1,"discardable_paths":["frontend/dist","tmp/test-output","node_modules"]}`,
	))
	if err != nil || len(valid.DiscardablePaths) != 3 || valid.DiscardablePaths[0] != "frontend/dist" {
		t.Fatalf("safe paths rejected: request=%+v err=%v", valid, err)
	}
}

func TestAgentOperationNotifyChannelIDsAreBounded(t *testing.T) {
	tooLong := strings.Repeat("c", maxAgentOperationChannelIDLength+1)
	raw := `{"scope_type":"tenant","mode":"audit","action":"record","version":1,"notify_channel_ids":["` + tooLong + `"]}`
	if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err == nil {
		t.Fatal("overlong channel id accepted")
	}
	ids := make([]string, maxAgentOperationChannelIDs+1)
	for i := range ids {
		ids[i] = `"channel-` + strings.Repeat("x", i+1) + `"`
	}
	raw = `{"scope_type":"tenant","mode":"audit","action":"record","version":1,"notify_channel_ids":[` + strings.Join(ids, ",") + `]}`
	if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err == nil {
		t.Fatal("too many channel ids accepted")
	}
}

// 2.9.22 批次 2B：“确认”不再限定 MCP 与应用/智能体范围。原 invalid 表里的前两条（租户范围、
// 协议为空的确认）移到 valid；protocol 仍只能为空（所有协议）或 mcp，chat/responses 照旧非法。
func TestAgentOperationConfirmRequiresExplicitMCPProtocol(t *testing.T) {
	invalid := []string{
		`{"scope_type":"agent","scope_ref":"codex","mode":"strict","action":"confirm","protocol":"responses","version":1}`,
		`{"scope_type":"agent","scope_ref":"chat-agent","mode":"strict","action":"confirm","protocol":"chat","version":1}`,
	}
	for _, raw := range invalid {
		if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err == nil {
			t.Fatalf("confirm without MCP capability accepted: %s", raw)
		}
	}
	valid := []string{
		`{"scope_type":"tenant","mode":"strict","action":"confirm","version":1}`,
		`{"scope_type":"application","scope_ref":"app-chat","mode":"strict","action":"confirm","version":1}`,
		`{"scope_type":"tenant","mode":"strict","action":"block","version":1}`,
		`{"scope_type":"application","scope_ref":"app-mcp","mode":"strict","action":"confirm","protocol":"mcp","version":1}`,
		`{"scope_type":"agent","scope_ref":"mcp-client","mode":"strict","action":"confirm","protocol":"mcp","version":1}`,
	}
	for _, raw := range valid {
		if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err != nil {
			t.Fatalf("valid protocol capability rejected: %s: %v", raw, err)
		}
	}
}

func TestDecodeAgentOperationPolicyRequestParsesTenantScopeAndGlobalLimits(t *testing.T) {
	valid, err := decodeAgentOperationPolicyRequest(strings.NewReader(
		`{"tenant_scope":"all","scope_type":"agent","scope_ref":"*","mode":"light","action":"alert_allow","version":1}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if valid.TenantScope != "all" || valid.TenantID != "" || valid.ScopeRef != "*" {
		t.Fatalf("request=%+v", valid)
	}

	invalid := []string{
		`{"tenant_scope":"workspace","scope_type":"tenant","mode":"audit","action":"record","version":1}`,
		`{"tenant_scope":"all","tenant_id":"tenant-a","scope_type":"tenant","mode":"audit","action":"record","version":1}`,
		`{"tenant_scope":"all","scope_type":"application","scope_ref":"app-a","mode":"audit","action":"record","version":1}`,
		`{"tenant_scope":"all","scope_type":"agent","scope_ref":"*","mode":"light","action":"alert_allow","notify_channel_ids":["channel-a"],"version":1}`,
		`{"tenant_scope":"all","scope_type":"agent","scope_ref":"codex-*","mode":"light","action":"alert_allow","version":1}`,
	}
	for _, raw := range invalid {
		if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err == nil {
			t.Fatalf("invalid tenant scope accepted: %s", raw)
		}
	}
}
