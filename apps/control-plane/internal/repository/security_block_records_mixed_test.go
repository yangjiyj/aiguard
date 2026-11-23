package repository

import "testing"

// 复审 I3：一次请求同时被手机号规则和语义拦截时，网关选的拦截规则是手机号（依据「规则『手机号检测』…」），
// 读取侧不能因为 findings 里语义排在前面就改成「智能分析高置信拦截」。

func phoneBlockedFinding() map[string]any {
	return map[string]any{"type": "pii", "category": "phone_cn", "action": "block", "rule_name": "手机号检测"}
}

func semanticBlockedFindingMap() map[string]any {
	return map[string]any{
		"type": "semantic_attack", "category": "prompt_input_semantic_risk", "action": "block",
		"rule_name": "智能分析拦截", "confidence": 0.9,
		"evidence_reason": "上下文判官确认风险；智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85",
		"triage":          map[string]any{"semantic_enforcement": "blocked", "semantic_confidence": 0.9, "semantic_block_min_confidence": 0.85},
	}
}

func TestMixedPhoneAndSemanticBlockKeepsGatewayChosenRule(t *testing.T) {
	orders := map[string][]any{
		"semantic_first": {semanticBlockedFindingMap(), phoneBlockedFinding()},
		"phone_first":    {phoneBlockedFinding(), semanticBlockedFindingMap()},
	}
	for name, findings := range orders {
		record := &SecurityBlockRecord{}
		summary := map[string]any{
			"block": map[string]any{"rule_name": "手机号检测", "category": "phone_cn",
				"basis": "规则「手机号检测」的处置动作为阻断"},
			"findings": findings,
		}
		projectSecurityBlockAttribution(record, summary, "", "", "")
		if record.RuleName != "手机号检测" || record.Basis != "规则「手机号检测」的处置动作为阻断" {
			t.Fatalf("%s: 依据必须与网关选中的手机号规则一致, got rule=%q basis=%q", name, record.RuleName, record.Basis)
		}
		if record.SemanticConfidence != nil || record.SemanticBlockMinConfidence != nil {
			t.Fatalf("%s: 非语义拦截不带语义置信度/阈值, got %+v", name, record)
		}
	}
}

func TestPureSemanticBlockStillCorrectedWithAndWithoutMarker(t *testing.T) {
	legacy := map[string]any{"rule_name": "智能分析拦截", "category": "prompt_input_semantic_risk",
		"basis": "规则「智能分析拦截」的处置动作为阻断"}
	marked := map[string]any{"rule_name": "智能分析拦截", "category": "prompt_input_semantic_risk", "semantic_enforced": true,
		"basis":               "智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85",
		"semantic_confidence": 0.9, "semantic_block_min_confidence": 0.85}
	for name, block := range map[string]map[string]any{"legacy": legacy, "marked": marked} {
		record := &SecurityBlockRecord{}
		projectSecurityBlockAttribution(record, map[string]any{"block": block,
			"findings": []any{phoneLikeAuditFinding(), semanticBlockedFindingMap()}}, "", "", "")
		if record.Basis != "智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85" ||
			record.SemanticConfidence == nil || *record.SemanticConfidence != 0.9 {
			t.Fatalf("%s: 纯语义拦截应为智能分析依据并带置信度, got %+v", name, record)
		}
	}
}

// 同一请求里只记录不拦截的其它命中，不影响语义拦截的识别。
func phoneLikeAuditFinding() map[string]any {
	return map[string]any{"type": "pii", "category": "email", "action": "audit", "rule_name": "邮箱地址检测"}
}
