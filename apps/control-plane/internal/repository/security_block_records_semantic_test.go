package repository

import "testing"

// 语义拦截的阻断记录：依据取智能分析高置信拦截文案，并带置信度与阈值。已部署网关
// （11a50f1d8）写入的 block.basis 是错误的「规则『…』的处置动作为阻断」，读取时按拦截
// finding 的 semantic_enforcement=blocked 纠正，存量记录无需迁移。

func semanticBlockSummary(storedBasis string, block map[string]any) map[string]any {
	if block == nil {
		block = map[string]any{}
	}
	block["block_id"] = "evt_semantic"
	block["layer"] = "input_content"
	block["rule_name"] = "智能分析拦截"
	block["basis"] = storedBasis
	return map[string]any{
		"stage": "input",
		"block": block,
		"findings": []any{map[string]any{
			"type": "semantic_attack", "category": "prompt_input_semantic_risk", "action": "block",
			"rule_name": "智能分析拦截", "confidence": 0.9,
			"evidence_reason": "上下文判官确认风险；智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85",
			"triage": map[string]any{
				"semantic_enforcement": "blocked", "semantic_confidence": 0.9,
				"semantic_block_min_confidence": 0.85,
			},
		}},
	}
}

func TestSemanticBlockRecordBasisAndConfidenceFromLegacyGatewayEvent(t *testing.T) {
	record := &SecurityBlockRecord{EventType: "semantic_attack", ActionTaken: "security_blocked"}
	projectSecurityBlockAttribution(record, semanticBlockSummary("规则「智能分析拦截」的处置动作为阻断", nil), "", "", "")
	if record.Basis != "智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85" {
		t.Fatalf("语义拦截依据应为智能分析高置信拦截, got %q", record.Basis)
	}
	if record.SemanticConfidence == nil || *record.SemanticConfidence != 0.9 ||
		record.SemanticBlockMinConfidence == nil || *record.SemanticBlockMinConfidence != 0.85 {
		t.Fatalf("记录应带置信度与阈值, got %+v", record)
	}
}

func TestSemanticBlockRecordPrefersFieldsWrittenByGateway(t *testing.T) {
	record := &SecurityBlockRecord{}
	block := map[string]any{"semantic_enforced": true, "semantic_confidence": 0.9, "semantic_block_min_confidence": 0.8}
	projectSecurityBlockAttribution(record, semanticBlockSummary("智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.80", block), "", "", "")
	if record.Basis != "智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.80" ||
		record.SemanticBlockMinConfidence == nil || *record.SemanticBlockMinConfidence != 0.8 {
		t.Fatalf("网关已写入的语义依据与字段应原样采用, got %+v", record)
	}
}

func TestNonSemanticBlockRecordBasisUnchanged(t *testing.T) {
	record := &SecurityBlockRecord{}
	summary := map[string]any{
		"block":    map[string]any{"rule_name": "手机号检测", "basis": "规则「手机号检测」的处置动作为阻断"},
		"findings": []any{map[string]any{"type": "pii", "category": "phone_cn", "action": "block", "rule_name": "手机号检测"}},
	}
	projectSecurityBlockAttribution(record, summary, "", "", "")
	if record.Basis != "规则「手机号检测」的处置动作为阻断" || record.SemanticConfidence != nil || record.SemanticBlockMinConfidence != nil {
		t.Fatalf("其它拦截保持原样, got %+v", record)
	}
}
