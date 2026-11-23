package handler

import (
	"context"
	"testing"
)

// 缺陷：语义拦截（策略「智能分析命中时=拦截」）的阻断依据被写成「规则『…』的处置动作为阻断」，
// 而该策略的处置动作其实是记录；真正的拦截原因是智能分析高置信拦截，且记录里没有置信度和阈值。

func semanticBlockedFinding(evidenceReason string) SecurityFinding {
	return SecurityFinding{
		Type: "semantic_attack", Category: "prompt_input_semantic_risk", Severity: "high", Confidence: 0.9,
		RuleID: "id.tenant.semantic", RuleName: "智能分析拦截", Action: "block", MatchedLocation: "content[0:41]",
		RedactedEvidence: "语义裁判判定：上下文语义风险（malicious）", EvidenceReason: evidenceReason,
		Triage: map[string]any{
			"semantic_enforcement": "blocked", "semantic_category": "prompt_input_semantic_risk",
			"semantic_confidence": 0.9, "semantic_block_min_confidence": 0.85,
		},
	}
}

func TestSemanticBlockAttributionUsesEngineReasonAndCarriesConfidence(t *testing.T) {
	finding := semanticBlockedFinding("上下文判官确认风险；智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85")
	attribution := deriveBlockAttribution(context.Background(), "evt_semantic", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	if attribution.Basis != "智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85" {
		t.Fatalf("语义拦截依据应沿用引擎文案, got %q", attribution.Basis)
	}
	if attribution.SemanticConfidence == nil || *attribution.SemanticConfidence != 0.9 ||
		attribution.SemanticBlockMinConfidence == nil || *attribution.SemanticBlockMinConfidence != 0.85 {
		t.Fatalf("阻断记录应带置信度与阈值, got %+v", attribution)
	}
}

func TestSemanticBlockAttributionFallsBackToTriageNumbers(t *testing.T) {
	attribution := deriveBlockAttribution(context.Background(), "evt_semantic", []SecurityFinding{semanticBlockedFinding("上下文判官确认风险")}, "security_blocked", "blocked input message 0")
	if attribution.Basis != "智能分析高置信拦截：置信度 0.90 ≥ 阈值 0.85" {
		t.Fatalf("缺少引擎文案时按 triage 数值生成同格式依据, got %q", attribution.Basis)
	}
}

func TestNonSemanticBlockAttributionBasisUnchanged(t *testing.T) {
	finding := SecurityFinding{Type: "pii", Category: "phone_cn", RuleName: "手机号检测", Action: "block", Severity: "high"}
	attribution := deriveBlockAttribution(context.Background(), "evt_rule", []SecurityFinding{finding}, "security_blocked", "blocked input message 0")
	if attribution.Basis != "规则「手机号检测」的处置动作为阻断" {
		t.Fatalf("其它拦截的依据文案保持不变, got %q", attribution.Basis)
	}
	if attribution.SemanticConfidence != nil || attribution.SemanticBlockMinConfidence != nil {
		t.Fatalf("非语义拦截不带语义字段, got %+v", attribution)
	}
	downgraded := semanticBlockedFinding("")
	downgraded.Triage = map[string]any{"semantic_enforcement": "downgraded"}
	if got := findingBlockBasis(downgraded); got != "规则「智能分析拦截」的处置动作为阻断" {
		t.Fatalf("未被智能分析拦截的语义发现不套用语义依据, got %q", got)
	}
}
