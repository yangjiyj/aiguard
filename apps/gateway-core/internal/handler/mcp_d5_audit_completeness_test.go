package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// D5：record 模式下红线命中必须落 security_events（source=gateway_mcp），不因 auditOnly 被短路。
func TestD5_RedlineHitWritesSecurityEventUnderRecordMode(t *testing.T) {
	d := &mcpToolCallDecision{
		Qualified: "demo__echo",
		Decision: agentguard.Decision{
			RawDecision: agentguard.DecisionAudit, EffectiveDecision: agentguard.DecisionAudit,
			Evidence: []agentguard.Evidence{{RuleID: "mcp_redline_pii", Category: "mcp_redline"}},
		},
	}
	for _, auditOnly := range []bool{true, false} {
		if !mcpDecisionNeedsSecurityEvent(d, auditOnly) {
			t.Fatalf("auditOnly=%v: 红线命中必须写 security_events", auditOnly)
		}
	}
	rec := mcpBlockRecord()
	args := mcpSecurityEventArgs(rec, d, true)
	if got := args[7]; got != "security_audit_only" {
		t.Fatalf("record 模式 action_taken = %v，want security_audit_only（不得伪称拦截）", got)
	}
	var summary map[string]interface{}
	if err := json.Unmarshal(args[8].([]byte), &summary); err != nil || summary["source"] != "gateway_mcp" {
		t.Fatalf("matched_summary.source 必须是 gateway_mcp: %v %v", summary, err)
	}
}

// D5：record 模式下 raw=block 的决策（未真正阻断）同样要有 security_events。
func TestD5_RawBlockWritesSecurityEventUnderRecordMode(t *testing.T) {
	d := &mcpToolCallDecision{
		Qualified: "demo__rm",
		Decision:  agentguard.Decision{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionAudit},
	}
	if !mcpDecisionNeedsSecurityEvent(d, true) {
		t.Fatal("record 模式 raw=block 必须写 security_events")
	}
	// 普通放行不得刷屏
	plain := &mcpToolCallDecision{Decision: agentguard.Decision{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow}}
	if mcpDecisionNeedsSecurityEvent(plain, true) {
		t.Fatal("普通放行不应写 security_events")
	}
}
