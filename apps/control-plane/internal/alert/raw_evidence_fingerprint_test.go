package alert

import "testing"

func dataLeakFinding(extra map[string]any) map[string]any {
	finding := map[string]any{
		"type": "data_leak", "category": "code_leak_database_url", "severity": "high", "confidence": 0.9,
		"rule_id": "code_leak_database_url", "matched_text_preview": "po****db",
		"raw_evidence_sha256": "3c5e8d1e1d6f3a1b6a7f1d0e9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b",
	}
	for key, value := range extra {
		finding[key] = value
	}
	return finding
}

// 2.9.22 起网关给字面类命中存原文，同时保留 raw_evidence_sha256。data_leak 的告警组指纹继续按规则编号算：
// 同一命中在改动前后归到同一个告警组，不同原文也不会因为原文入库被拆成多个组（与 2.9.21 一致）。
func TestDataLeakGroupKeyUnchangedByRawEvidence(t *testing.T) {
	before := secEventWithFindings("before", "audit", dataLeakFinding(map[string]any{
		"evidence_context": "DATABASE_URL=postgres://app:<已隐藏 10 字>@db:5432/app",
	}))
	after := secEventWithFindings("after", "audit", dataLeakFinding(map[string]any{
		"raw_evidence":             "postgres://app:S3cretPass@db:5432/app",
		"evidence_context":         "DATABASE_URL=postgres://app:S3cretPass@db:5432/app",
		"evidence_identity_sha256": "4f2a0c3e9b8d7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a29",
	}))
	other := secEventWithFindings("other", "audit", dataLeakFinding(map[string]any{
		"raw_evidence":             "postgres://reporter:Another9@db2:5432/report",
		"raw_evidence_sha256":      "9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6",
		"evidence_identity_sha256": "1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00",
	}))
	if eventGroupKey(before) != eventGroupKey(after) {
		t.Fatal("原文入库改变了 data_leak 告警组指纹，升级前后同一命中会分成两个组")
	}
	if eventGroupKey(after) != eventGroupKey(other) {
		t.Fatal("原文入库后同一规则的不同命中被拆成多个告警组，与 2.9.21 归组口径不一致")
	}
}

// 2026-07-25～09-20 的旧事件只存了原文、没有原文哈希：维持按原文算指纹，已有告警组不变。
func TestDataLeakGroupKeyKeepsRawFingerprintForPreHashEvents(t *testing.T) {
	first := secEventWithFindings("first", "audit", map[string]any{
		"type": "data_leak", "category": "code_leak_database_url", "rule_id": "code_leak_database_url", "confidence": 0.9,
		"raw_evidence": "postgres://app:S3cretPass@db:5432/app",
	})
	second := secEventWithFindings("second", "audit", map[string]any{
		"type": "data_leak", "category": "code_leak_database_url", "rule_id": "code_leak_database_url", "confidence": 0.9,
		"raw_evidence": "postgres://reporter:Another9@db2:5432/report",
	})
	if eventGroupKey(first) == eventGroupKey(second) {
		t.Fatal("旧事件的原文指纹口径被改动")
	}
}
