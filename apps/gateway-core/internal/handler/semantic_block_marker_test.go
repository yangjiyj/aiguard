package handler

import (
	"context"
	"testing"
)

// 复审 I3：网关为语义拦截写显式标记 block.semantic_enforced=true，读取侧只信这个标记（旧记录精确匹配）。
func TestSemanticBlockAttributionCarriesExplicitMarker(t *testing.T) {
	semantic := semanticBlockedFinding("上下文判官确认风险；智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85")
	pure := deriveBlockAttribution(context.Background(), "evt_semantic", []SecurityFinding{semantic}, "security_blocked", "blocked input message 0")
	if !pure.SemanticEnforced {
		t.Fatalf("纯语义拦截应写 semantic_enforced 标记, got %+v", pure)
	}
	phone := SecurityFinding{Type: "pii", Category: "phone_cn", RuleName: "手机号检测", Action: "block", Severity: "critical"}
	for name, findings := range map[string][]SecurityFinding{
		"semantic_first": {semantic, phone},
		"phone_first":    {phone, semantic},
	} {
		attribution := deriveBlockAttribution(context.Background(), "evt_mixed", findings, "security_blocked", "blocked input message 0")
		if attribution.RuleName != "手机号检测" {
			t.Fatalf("%s: 手机号为 critical、语义为 high，网关应选中手机号规则, got %q", name, attribution.RuleName)
		}
		if attribution.SemanticEnforced || attribution.SemanticConfidence != nil ||
			attribution.Basis != "规则「手机号检测」的处置动作为阻断" {
			t.Fatalf("%s: 选中手机号规则时不得带语义标记/置信度, got %+v", name, attribution)
		}
	}
}
