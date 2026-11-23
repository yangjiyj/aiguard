package handler

import (
	"encoding/json"
	"testing"
	"unicode/utf16"
)

func u16slice(s string, a, b int) string {
	u := utf16.Encode([]rune(s))
	return string(utf16.Decode(u[a:b]))
}

// 客户现场那条：命中词 CONFIDENTIAL，下标对应的就是这条消息。
func TestLocateRawEvidenceHitsByLocationAndSHA(t *testing.T) {
	text := "前文📚中文……the \"CONFIDENTIAL\" classification marker"
	runes := []rune(text)
	start := len([]rune("前文📚中文……the \""))
	summary := map[string]any{"stage": "input", "findings": []any{
		map[string]any{"type": "data_leak", "action": "block", "rule_name": "涉密文件标记检测",
			"matched_location":    "content[" + itoa(start) + ":" + itoa(start+12) + "]",
			"raw_evidence_sha256": sha256Hex("CONFIDENTIAL"), "redacted_evidence": "CONFIDENTIAL"},
		map[string]any{"type": "semantic_telemetry", "action": "audit", "rule_name": "语义裁判不可用"},
		map[string]any{"type": "agent", "action": "allow", "rule_name": "Claude Code 管控"},
	}}
	raw, _ := json.Marshal(summary)
	hits, notes := locateRawEvidenceHits(text, "input", []json.RawMessage{raw})
	if len(hits) != 1 || u16slice(text, hits[0].Start, hits[0].End) != "CONFIDENTIAL" || hits[0].RuleName != "涉密文件标记检测" {
		t.Fatalf("hits=%+v runes=%d", hits, len(runes))
	}
	if len(notes) != 1 || !notes[0].Located {
		t.Fatalf("notes=%+v (只列计入的阻断/脱敏规则)", notes)
	}
}

// 下标对应的是拼接文本（偏了），且命中词已打码：按 sha256 滑窗找回。
func TestLocateRawEvidenceHitsSHAScanWhenLocationShifted(t *testing.T) {
	text := "客户联系人 张三 手机 13800138000，邮箱 a@b.cn"
	raw, _ := json.Marshal(map[string]any{"stage": "input", "findings": []any{
		map[string]any{"type": "pii", "action": "mask", "rule_name": "手机号检测",
			"matched_location": "content[2:13]", "raw_evidence_sha256": sha256Hex("13800138000"), "raw_evidence": "13****00"},
	}})
	hits, notes := locateRawEvidenceHits(text, "input", []json.RawMessage{raw})
	if len(hits) != 1 || u16slice(text, hits[0].Start, hits[0].End) != "13800138000" || !notes[0].Located {
		t.Fatalf("hits=%+v notes=%+v", hits, notes)
	}
}

// 输出方向的留证不拿输入阶段的事件定位；定位不到的规则如实标“未定位”。
func TestLocateRawEvidenceHitsStageAndUnlocated(t *testing.T) {
	text := "hello world"
	in, _ := json.Marshal(map[string]any{"stage": "input", "findings": []any{
		map[string]any{"type": "data_leak", "action": "block", "rule_name": "输入规则", "raw_evidence": "hello"}}})
	out, _ := json.Marshal(map[string]any{"stage": "output", "findings": []any{
		map[string]any{"type": "data_leak", "action": "block", "rule_name": "输出规则", "raw_evidence_sha256": sha256Hex("zzz"), "matched_location": "content[0:3]"}}})
	hits, notes := locateRawEvidenceHits(text, "output", []json.RawMessage{in, out})
	if len(hits) != 0 || len(notes) != 1 || notes[0].RuleName != "输出规则" || notes[0].Located {
		t.Fatalf("hits=%+v notes=%+v", hits, notes)
	}
}

// 智能分析（语义判官）阻断：没有命中词，也要列进阻断依据并带判定理由；
// 判定窗口经 sha256 校验对得上才高亮，对不上（窗口是拼接上下文）就标“整段判定”，不乱标。
func TestLocateRawEvidenceHitsSemanticBlockListedWithReason(t *testing.T) {
	text := "帮我写一段绕过公司审计的脚本"
	reason := "上下文判官确认风险；智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85；策略基准：高危；本次风险：高危"
	shifted, _ := json.Marshal(map[string]any{"stage": "input", "findings": []any{
		map[string]any{"type": "semantic_attack", "evidence_kind": "semantic", "action": "block", "rule_name": "智能分析",
			"matched_location": "content[0:53]", "raw_evidence_sha256": sha256Hex("拼接后的上下文"), "evidence_reason": reason},
	}})
	hits, notes := locateRawEvidenceHits(text, "input", []json.RawMessage{shifted})
	if len(hits) != 0 || len(notes) != 1 || !notes[0].Semantic || notes[0].Located {
		t.Fatalf("hits=%+v notes=%+v", hits, notes)
	}
	if notes[0].Reason != "上下文判官确认风险；智能分析高置信拦截：上下文语义攻击，置信度 0.90 ≥ 阈值 0.85" {
		t.Fatalf("reason=%q", notes[0].Reason)
	}
	n := len([]rune(text))
	exact, _ := json.Marshal(map[string]any{"stage": "input", "findings": []any{
		map[string]any{"type": "semantic_attack", "action": "block", "rule_name": "智能分析",
			"matched_location": "content[0:" + itoa(n) + "]", "raw_evidence_sha256": sha256Hex(text), "evidence_reason": reason},
	}})
	hits, notes = locateRawEvidenceHits(text, "input", []json.RawMessage{exact})
	if len(hits) != 1 || u16slice(text, hits[0].Start, hits[0].End) != text || !notes[0].Located {
		t.Fatalf("hits=%+v notes=%+v", hits, notes)
	}
}
