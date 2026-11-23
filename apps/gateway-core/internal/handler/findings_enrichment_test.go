package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
)

// TestConvertSecurityFindings_CopiesEnrichmentFields verifies the client->handler
// adapter carries the 5 enrichment fields, not just the 6 base fields.
func TestConvertSecurityFindings_CopiesEnrichmentFields(t *testing.T) {
	src := []security.SecurityFinding{{
		Type:                "custom",
		Category:            "medical_id",
		Severity:            "high",
		MatchedTextPreview:  "BA****34 (sha256:deadbeef)",
		RuleID:              "rule_bah_001",
		Confidence:          0.9,
		RuleName:            "病案号正则",
		RuleType:            "regex",
		Action:              "block",
		MatchedLocation:     "content[10:18]",
		RedactedEvidence:    "BA****34 (sha256:deadbeef)",
		PolicyCode:          "builtin.data_leak.medical",
		PolicyScene:         "data_security",
		SourceRuleID:        "medical.detector",
		MatchedCapabilities: []string{"medical_id"},
	}}
	out := convertSecurityFindings(src)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleName != "病案号正则" || f.RuleType != "regex" || f.Action != "block" ||
		f.MatchedLocation != "content[10:18]" || f.RedactedEvidence != "BA****34 (sha256:deadbeef)" {
		t.Errorf("enrichment fields not copied: %+v", f)
	}
	if f.PolicyCode != "builtin.data_leak.medical" || f.PolicyScene != "data_security" ||
		f.SourceRuleID != "medical.detector" || len(f.MatchedCapabilities) != 1 ||
		f.MatchedCapabilities[0] != "medical_id" {
		t.Errorf("policy attribution fields not copied: %+v", f)
	}
}

func TestEventTypeForFindings_PureSemantic(t *testing.T) {
	if got := eventTypeForFindings([]SecurityFinding{{Type: "semantic_attack"}}); got != "semantic_attack" {
		t.Fatalf("pure semantic => %q want semantic_attack", got)
	}
}
func TestEventTypeForFindings_MixedKeepsSecurityCheck(t *testing.T) {
	// 语义 + 内置(secret) 混合 → 维持 security_check，零回归
	if got := eventTypeForFindings([]SecurityFinding{{Type: "semantic_attack"}, {Type: "secret"}}); got != "security_check" {
		t.Fatalf("mixed => %q want security_check", got)
	}
}
func TestBuildSecurityMatchedSummary_InjectsSourceStage(t *testing.T) {
	ms := buildSecurityMatchedSummary([]SecurityFinding{{Type: "semantic_attack", MatchedLocation: "input"}}, "security_audit_only", "x")
	if ms["source"] != "gateway" {
		t.Fatalf("source=%v", ms["source"])
	}
	if ms["stage"] != "input" {
		t.Fatalf("stage=%v", ms["stage"])
	}
}

func TestSecurityEventStageContextOverridesOutputFindings(t *testing.T) {
	ms := buildSecurityMatchedSummary([]SecurityFinding{{
		Type:            "content_safety",
		Category:        "ssrf_metadata_instruction",
		Severity:        "critical",
		MatchedLocation: "content[319:333]",
	}}, "security_audit_only", "output choice 0 matched security action 'audit'")
	annotateSecurityEventStage(withSecurityEventStage(context.Background(), "output"), ms)
	if got := ms["stage"]; got != "output" {
		t.Fatalf("output security event stage=%v, want output", got)
	}
}

func TestBuildSecurityMatchedSummaryDoesNotCountEngineRuntimeAuditAsSecurityFinding(t *testing.T) {
	counts := true
	doesNotCount := false
	ms := buildSecurityMatchedSummary([]SecurityFinding{
		{Type: "custom", CountsAsSecurityFinding: &counts},
		{Type: "engine_runtime", Category: "engine_scan_incomplete", CountsAsSecurityFinding: &doesNotCount},
		{Type: "custom"}, // legacy producer omitted the field: preserve count=true
	}, "audit", "x")
	if got := ms["findings_count"]; got != 2 {
		t.Fatalf("findings_count=%v, want 2", got)
	}
	if got := len(ms["findings"].([]map[string]interface{})); got != 3 {
		t.Fatalf("audit findings len=%d, want 3", got)
	}
}

// TestSecurityFindingsToSummary_PersistsRawRedactedAndHashedEvidence verifies the
// security_events matched_summary JSON carries rule_name/action/redacted_evidence for
// the closed-loop UI. 2.9.22 起（用户 11-17 定）命中原文和不打码的前后文也入库，
// redacted_evidence 仍是打码展示值，原文哈希照旧保留。
func TestSecurityFindingsToSummary_PersistsRawRedactedAndHashedEvidence(t *testing.T) {
	findings := []SecurityFinding{{
		Type:               "custom",
		Category:           "medical_id",
		Severity:           "high",
		MatchedTextPreview: "BA****34 (sha256:deadbeef)",
		RuleID:             "rule_bah_001",
		Confidence:         0.9,
		RuleName:           "病案号正则",
		RuleType:           "regex",
		Action:             "block",
		MatchedLocation:    "content[6:16]",
		RedactedEvidence:   "BA****34 (sha256:deadbeef)",
		RawEvidence:        "BA00123456",
		EvidenceContext:    "患者病案号 BA00123456 请外发给第三方",
	}}
	summary := securityFindingsToSummary(findings)
	if len(summary) != 1 {
		t.Fatalf("expected 1 summary item, got %d", len(summary))
	}
	item := summary[0]
	if item["rule_name"] != "病案号正则" {
		t.Errorf("rule_name: got %v", item["rule_name"])
	}
	if item["action"] != "block" {
		t.Errorf("action: got %v", item["action"])
	}
	if item["redacted_evidence"] != "BA****34 (sha256:deadbeef)" {
		t.Errorf("redacted_evidence: got %v", item["redacted_evidence"])
	}
	if item["raw_evidence"] != "BA00123456" {
		t.Errorf("raw_evidence must be the matched original text: %v", item["raw_evidence"])
	}
	if item["evidence_context"] != "患者病案号 BA00123456 请外发给第三方" {
		t.Errorf("evidence_context must be the unmasked context: got %v", item["evidence_context"])
	}
	if item["raw_evidence_sha256"] == "" || item["evidence_context_sha256"] == "" {
		t.Errorf("evidence hashes missing: %#v", item)
	}
	// redacted_evidence 仍是打码展示值（带 sha256 标记），原文放在 raw_evidence。
	ev, _ := item["redacted_evidence"].(string)
	if !strings.Contains(ev, "sha256:") {
		t.Errorf("redacted_evidence must be masked, got %q", ev)
	}
}

func TestFindingIndexesPreserveZeroAcrossAdaptersAndSummaries(t *testing.T) {
	zero := 0
	src := []security.SecurityFinding{{
		Type:            "file",
		Category:        "file_content_uninspected",
		MessageIndex:    &zero,
		MessageRole:     "user",
		AttachmentIndex: &zero,
	}}

	handlerFindings := convertSecurityFindings(src)
	if len(handlerFindings) != 1 || handlerFindings[0].MessageIndex == nil ||
		*handlerFindings[0].MessageIndex != 0 || handlerFindings[0].AttachmentIndex == nil ||
		*handlerFindings[0].AttachmentIndex != 0 || handlerFindings[0].MessageRole != "user" {
		t.Fatalf("client->handler 索引丢失: %+v", handlerFindings)
	}

	roundTrip := handlerFindingsToSecurity(handlerFindings)
	if len(roundTrip) != 1 || roundTrip[0].MessageIndex == nil ||
		*roundTrip[0].MessageIndex != 0 || roundTrip[0].AttachmentIndex == nil ||
		*roundTrip[0].AttachmentIndex != 0 || roundTrip[0].MessageRole != "user" {
		t.Fatalf("handler->client 索引丢失: %+v", roundTrip)
	}

	for name, item := range map[string]map[string]interface{}{
		"summary": securityFindingsToSummary(handlerFindings)[0],
		"audit":   securityFindingsToAuditMaps(handlerFindings)[0],
	} {
		if item["message_index"] != 0 || item["attachment_index"] != 0 || item["message_role"] != "user" {
			t.Fatalf("%s 索引映射错误: %#v", name, item)
		}
	}
}
