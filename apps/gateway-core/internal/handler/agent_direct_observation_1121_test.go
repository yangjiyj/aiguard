package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 客户现场 14 天：agent_direct_api_call（「直接 API 调用」）2335 条，占全部命中四成。网关原生入口
// 送检时 client_type 恒为 "api"，引擎对每条被检消息都附一条该识别标签（观察，不计入安全发现），
// 于是它跟着每条安全事件写进 findings。期望：它只作请求上的识别标签，不再作为一条命中写进
// 安全事件；单独出现不成事件；与真实高危同现时高危照常成事件，标签作为事件上下文保留。

// siteAgentDirectFinding 是现场落库的形状：策略「API 直接调用检测」绑定后的规则号、低危、观察。
func siteAgentDirectFinding() SecurityFinding {
	notCounted := false
	return SecurityFinding{
		Type: "request_context", Category: "agent_direct_api_call", Severity: "low",
		RuleID: "rule_29d445a2-29d0-4f04-be9a-7bf6da439135", RuleName: "API 直接调用检测", RuleType: "agent_detect",
		PolicyCode: "builtin.agent_detect.e2d7dcc63727dab9", SourceRuleID: "context_agent_direct_api_call",
		Action: "allow", MatchedLocation: "request_context", MatchedTextPreview: "direct_api", Confidence: 1,
		EvidenceKind: "contextual", ContentSource: "user", CountsAsSecurityFinding: &notCounted,
		Triage: map[string]any{"disposition": "observation", "disposition_reason": "agent_inventory_metadata"},
	}
}

func siteHighRiskFinding() SecurityFinding {
	return SecurityFinding{
		Type: "content_safety", Category: "illegal_system_command_instructions", Severity: "high",
		RuleID: "rule_high_cmd", RuleName: "危险系统命令", PolicyCode: "builtin.content_safety.cmd",
		Action: "audit", MatchedLocation: "content[10:30]", Confidence: 0.9, ContentSource: "user",
	}
}

func decodeWrittenSummary(t *testing.T, db *mockDBExecutor) map[string]any {
	t.Helper()
	if db.execCalls != 1 {
		t.Fatalf("应写一条安全事件, execCalls=%d", db.execCalls)
	}
	for _, arg := range db.args[0] {
		if raw, ok := arg.([]byte); ok {
			var summary map[string]any
			if err := json.Unmarshal(raw, &summary); err == nil && summary["action_taken"] != nil {
				return summary
			}
		}
	}
	t.Fatal("没有找到 matched_summary")
	return nil
}

func summaryFindingCategories(summary map[string]any) []string {
	raw, _ := json.Marshal(summary)
	_ = json.Unmarshal(raw, &summary)
	var out []string
	items, _ := summary["findings"].([]any)
	for _, item := range items {
		if finding, ok := item.(map[string]any); ok {
			category, _ := finding["category"].(string)
			out = append(out, category)
		}
	}
	return out
}

func TestAgentDirectAloneWritesNoSecurityEvent(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		aw, _ := runInputWithFindings(t, auditOnly, siteAgentDirectFinding())
		if len(aw.SecurityEventWrites) != 0 {
			t.Fatalf("auditOnly=%v: 单独的直接调用标签不应成安全事件, got %+v", auditOnly, aw.SecurityEventWrites)
		}
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req_direct", TenantID: "t", ProjectID: "p", UserID: "u"}
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	(&RealAuditWriter{db: db}).WriteSecurityEvent(withRetainedObservationEvent(context.Background()), envelope,
		[]SecurityFinding{siteAgentDirectFinding()}, "security_audit", "inventory")
	if db.execCalls != 0 {
		t.Fatalf("写入器也不得单独落库直接调用标签, execCalls=%d", db.execCalls)
	}
}

func TestAgentDirectWithHighRiskKeepsHighRiskEventAndCarriesLabel(t *testing.T) {
	aw, written := runInputWithFindings(t, true, siteAgentDirectFinding(), siteHighRiskFinding())
	if len(aw.SecurityEventWrites) != 1 || len(written) != 1 {
		t.Fatalf("高危命中必须照常成事件, got %+v", aw.SecurityEventWrites)
	}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_direct_high", TenantID: "t", ProjectID: "p", UserID: "u"}
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	(&RealAuditWriter{db: db}).WriteSecurityEvent(context.Background(), envelope,
		[]SecurityFinding{siteAgentDirectFinding(), siteHighRiskFinding()}, "security_audit", "input matched")
	summary := decodeWrittenSummary(t, db)

	categories := summaryFindingCategories(summary)
	if len(categories) != 1 || categories[0] != "illegal_system_command_instructions" {
		t.Fatalf("事件 findings 只应保留真实命中，直接调用不再作为一条命中, got %v", categories)
	}
	labels, _ := summary["request_labels"].([]any)
	if len(labels) != 1 || labels[0] != "agent_direct_api_call" {
		t.Fatalf("直接调用应作为请求识别标签附在事件上, got %v", summary["request_labels"])
	}
	if summary["category"] != "illegal_system_command_instructions" || summary["findings_count"] != float64(1) {
		t.Fatalf("主命中与计数必须是高危命中, got category=%v count=%v", summary["category"], summary["findings_count"])
	}
	primary, _ := summary["primary_finding"].(map[string]any)
	if index, _ := primary["findings_index"].(float64); int(index) != 0 {
		t.Fatalf("主命中位置应指向剩下的高危命中, got %v", primary)
	}
	args := db.args[0]
	if args[6] != "high" || args[7] != "rule_high_cmd" {
		t.Fatalf("事件严重度/规则必须来自高危命中, severity=%v rule=%v", args[6], args[7])
	}
}

func TestAgentDirectEnforcedByPolicyStaysAFinding(t *testing.T) {
	enforced := siteAgentDirectFinding()
	counted := true
	enforced.CountsAsSecurityFinding = &counted
	enforced.Action = "block"
	enforced.Triage = nil
	summary := buildSecurityMatchedSummary([]SecurityFinding{enforced}, "security_blocked", "blocked")
	if categories := summaryFindingCategories(summary); len(categories) != 1 || categories[0] != "agent_direct_api_call" {
		t.Fatalf("客户把直接调用策略设为拦截时，它是真实命中，必须留在 findings, got %v", categories)
	}
	if labels, ok := summary["request_labels"]; ok {
		t.Fatalf("执法命中不应改写成标签, got %v", labels)
	}
}

func TestOtherRequestContextObservationsUnchanged(t *testing.T) {
	longSession := siteAgentDirectFinding()
	longSession.Category = "agent_long_session"
	longSession.RuleID = "context_agent_long_session"
	summary := buildSecurityMatchedSummary([]SecurityFinding{longSession, siteHighRiskFinding()}, "security_audit", "x")
	categories := summaryFindingCategories(summary)
	if len(categories) != 2 {
		t.Fatalf("其它请求上下文观察行为不变（仍随事件留证）, got %v", categories)
	}
	if _, ok := summary["request_labels"]; ok {
		t.Fatalf("其它类别不应生成直接调用标签, got %v", summary["request_labels"])
	}
}
