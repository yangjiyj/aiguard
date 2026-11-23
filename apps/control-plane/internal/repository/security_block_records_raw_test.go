package repository

import "testing"

// 2.9.22 起 primary_finding 不再复制原文，用 findings_index 指向 findings 里的那一条（JSON 解出来是 float64）。
// 阻断记录取命中原文时要跟着引用找到原条目。
func TestBlockRecordRawEvidenceFollowsPrimaryFindingReference(t *testing.T) {
	summary := map[string]any{
		"findings": []any{
			map[string]any{"category": "pii_phone", "rule_id": "pii_phone", "raw_evidence": "13800000000"},
			map[string]any{"category": "openai_key", "rule_id": "openai_key", "raw_evidence": "sk-proj-RAW", "evidence_context": "key=sk-proj-RAW ok", "redacted_evidence": "sk****AW"},
		},
		"primary_finding": map[string]any{"category": "openai_key", "rule_id": "openai_key", "redacted_evidence": "sk****AW", "findings_index": float64(1)},
	}
	var record SecurityBlockRecord
	projectSecurityBlockAttribution(&record, summary, "", "", "")
	if record.RawEvidence != "sk-proj-RAW" || record.EvidenceContext != "key=sk-proj-RAW ok" || record.Detail != "sk****AW" {
		t.Fatalf("阻断记录应经 findings_index 取到主命中原文: %+v", record)
	}
	for _, bad := range []any{float64(9), float64(-1), "1"} {
		summary["primary_finding"].(map[string]any)["findings_index"] = bad
		record = SecurityBlockRecord{}
		projectSecurityBlockAttribution(&record, summary, "", "", "")
		if record.RawEvidence != "" || record.Category != "openai_key" {
			t.Fatalf("引用无效（%v）时不串用别的命中: %+v", bad, record)
		}
	}
}

// 依据的命中因事件原文总量超限没存原文时，阻断记录透出 raw_evidence_omitted，控制台据此提示去留存回捞。
func TestBlockRecordExposesRawEvidenceOmitted(t *testing.T) {
	summary := map[string]any{"findings": []any{map[string]any{
		"category": "pii_phone", "action": "block", "redacted_evidence": "138****0000", "raw_evidence_omitted": true,
	}}}
	var record SecurityBlockRecord
	projectSecurityBlockAttribution(&record, summary, "", "", "")
	if !record.RawEvidenceOmitted || record.RawEvidence != "" {
		t.Fatalf("阻断记录应标出原文已省略: %+v", record)
	}
}

// 依据的命中原文超过 4096 字被截断时，阻断记录带 raw_evidence_truncated，与 raw_evidence 同源（控制台显示“（已截断）”）。
func TestBlockRecordExposesRawEvidenceTruncated(t *testing.T) {
	summary := map[string]any{"findings": []any{map[string]any{
		"category": "project_code", "action": "block", "raw_evidence": "很长的原文前 4096 字", "raw_evidence_truncated": true,
	}}}
	var record SecurityBlockRecord
	projectSecurityBlockAttribution(&record, summary, "", "", "")
	if !record.RawEvidenceTruncated || record.RawEvidence == "" {
		t.Fatalf("阻断记录应带原文截断标记: %+v", record)
	}
	summary["findings"].([]any)[0].(map[string]any)["raw_evidence_truncated"] = false
	record = SecurityBlockRecord{}
	projectSecurityBlockAttribution(&record, summary, "", "", "")
	if record.RawEvidenceTruncated {
		t.Fatalf("未截断时不带标记: %+v", record)
	}
}
