package handler

import (
	"fmt"
	"strings"
	"testing"
)

// 2.9.22 起（用户 11-17 定）raw_evidence、evidence_context 按原文入库；matched、matched_text 等其它字段
// 仍只存哈希和打码预览。
func TestBuildSecurityEventSummaryRedactsSensitiveFieldsButKeepsRawEvidence(t *testing.T) {
	findings := []map[string]interface{}{
		{
			"type":                 "secret",
			"severity":             "critical",
			"matched":              testOpenAILiveKey(),
			"matched_text":         testAWSAccessKeyID(),
			"matched_text_preview": "patient_name=张三 id_card=310101199001011234",
			"raw_evidence":         "password=ProductionSecret123",
			"evidence_context":     "customer password=ProductionSecret123",
		},
	}

	summary := buildSecurityEventSummary("api.deepseek.com:443", "input", findings)
	raw := fmt.Sprint(summary)

	for _, leaked := range []string{testOpenAILiveKey(), testAWSAccessKeyID(), "310101199001011234"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("security event summary leaked sensitive evidence %q in %#v", leaked, summary)
		}
	}
	stored := summary["findings"].([]map[string]interface{})[0]
	if stored["raw_evidence"] != "password=ProductionSecret123" || stored["evidence_context"] != "customer password=ProductionSecret123" {
		t.Fatalf("命中原文和前后文应按原样入库: %#v", stored)
	}
	if summary["target_host"] != "api.deepseek.com" {
		t.Fatalf("target host should be normalized without port, got %#v", summary["target_host"])
	}
	if summary["findings_count"] != 1 {
		t.Fatalf("findings_count = %#v, want 1", summary["findings_count"])
	}
}

func TestBuildSecurityEventSummaryIncludesAIIDEContext(t *testing.T) {
	record := ProxyAuditRecord{
		TargetHost:   "api5.cursor.sh:443",
		Provider:     "cursor",
		Product:      "cursor_agent",
		AccessType:   "ai_ide",
		TLSInspected: true,
	}

	summary := buildSecurityEventSummaryForRecord(record, "input", []map[string]interface{}{
		{"type": "secret", "severity": "high", "matched": testGitHubPAT()},
	})

	if summary["target_host"] != "api5.cursor.sh" {
		t.Fatalf("target host = %#v, want api5.cursor.sh", summary["target_host"])
	}
	if summary["access_type"] != "ai_ide" || summary["provider"] != "cursor" || summary["product"] != "cursor_agent" {
		t.Fatalf("AI IDE context missing from summary: %#v", summary)
	}
	if summary["tls_inspected"] != true {
		t.Fatalf("tls visibility missing from summary: %#v", summary)
	}
	if strings.Contains(fmt.Sprint(summary), testGitHubPAT()) {
		t.Fatalf("security event summary leaked token evidence: %#v", summary)
	}
}

func TestBuildSecurityEventSummaryPreservesFindingTriage(t *testing.T) {
	summary := buildSecurityEventSummary("api.deepseek.com:443", "output", []map[string]interface{}{
		{
			"type":              "custom",
			"category":          "customer_sensitive_data",
			"rule_id":           "rule_customer_keyword",
			"rule_name":         "客户项目代号",
			"rule_type":         "keyword",
			"redacted_evidence": "星河** (sha256:abcd1234)",
			"triage": map[string]interface{}{
				"verdict":     "audit_evidence",
				"reason":      "仅命中客户词库，未发现外发意图",
				"report_text": "本次访问建议保留审计。",
			},
		},
	})

	findings, ok := summary["findings"].([]map[string]interface{})
	if !ok || len(findings) != 1 {
		t.Fatalf("summary findings = %#v, want one finding", summary["findings"])
	}
	triage, ok := findings[0]["triage"].(map[string]interface{})
	if !ok {
		t.Fatalf("triage was not preserved in finding: %#v", findings[0])
	}
	if triage["verdict"] != "audit_evidence" || triage["report_text"] != "本次访问建议保留审计。" {
		t.Fatalf("unexpected triage: %#v", triage)
	}
	if strings.Contains(fmt.Sprint(summary), "星河计划") {
		t.Fatalf("summary leaked original sensitive term: %#v", summary)
	}
}

func TestSecurityEventProjectIDDefaultsForForwardProxy(t *testing.T) {
	if got := securityEventProjectID(ProxyAuditRecord{}); got != "project_default" {
		t.Fatalf("empty forward proxy security event project_id = %q, want project_default", got)
	}
	if got := securityEventProjectID(ProxyAuditRecord{ProjectID: "project_custom"}); got != "project_custom" {
		t.Fatalf("explicit forward proxy security event project_id = %q, want project_custom", got)
	}
}

func TestSecurityEventInsertIncludesRequiredProjectID(t *testing.T) {
	if !strings.Contains(securityEventInsertSQL(), "project_id") {
		t.Fatalf("security event insert must include project_id to satisfy NOT NULL schema")
	}
}

func TestProxySecurityEventAttributionUsesBoundPolicyIdentity(t *testing.T) {
	ruleID, classKey := proxySecurityEventAttribution([]map[string]interface{}{{
		"type": "secret", "category": "plain_password", "severity": "critical",
		"rule_id": "rule_bound_uuid", "policy_code": "builtin.data_leak.password",
	}})
	if ruleID != "rule_bound_uuid" || classKey != "plain_password" {
		t.Fatalf("attribution=%q/%q", ruleID, classKey)
	}
	if got := proxySecurityEventEffectiveSeverity([]map[string]interface{}{{
		"severity": "critical",
	}}, "high"); got != "critical" {
		t.Fatalf("effective severity=%q", got)
	}

	ruleID, classKey = proxySecurityEventAttribution([]map[string]interface{}{{
		"type": "secret", "category": "plain_password", "severity": "critical",
		"rule_id": "secret-password",
	}})
	if ruleID != "" || classKey != "plain_password" {
		t.Fatalf("unbound attribution=%q/%q", ruleID, classKey)
	}
}

func TestFindingEvidenceKeepsCanonicalPreviewAndExactLocation(t *testing.T) {
	finding := map[string]interface{}{"category": "plain_password", "raw_evidence": "SyntheticPassword42!", "matched_text_preview": "Sy****2!", "matched_location": "content[41:66]", "redacted_evidence": ""}
	got := redactFindings([]map[string]interface{}{finding})[0]
	if got["matched_location"] != "content[41:66]" {
		t.Fatalf("location lost: %#v", got)
	}
	if got["redacted_evidence"] == nil || got["redacted_evidence"] == "" {
		t.Fatalf("no canonical evidence: %#v", got)
	}
	if got["matched_text_preview"] == nil {
		t.Fatalf("canonical preview lost: %#v", got)
	}
	// 2.9.22 起命中原文入库（用户 11-17 定）；预览仍是打码值。
	if got["raw_evidence"] != "SyntheticPassword42!" || strings.Contains(fmt.Sprint(got["matched_text_preview"]), "SyntheticPassword42!") {
		t.Fatalf("raw_evidence 存原文、预览保持打码: %#v", got)
	}
	malformed := redactFindings([]map[string]interface{}{{"matched_location": "password=DoNotReveal123!"}})[0]
	if malformed["matched_location"] != nil {
		t.Fatal("unvalidated location persisted")
	}
}

func TestRedactFindingsDropsSecretTextEntirely(t *testing.T) {
	got := redactFindings([]map[string]interface{}{{
		"category": "ssh_private_key", "redacted_evidence": "-----BEGIN-----",
		"secret_text": "MIIEowFAKEBODY1234567890",
	}})[0]
	for k := range got {
		if strings.Contains(strings.ToLower(k), "secret_text") {
			t.Fatalf("输出含 secret_text 键: %v", k)
		}
	}
	blob := fmt.Sprint(got)
	for _, frag := range []string{"MIIEow", "890", "FAKEBODY"} {
		if strings.Contains(blob, frag) {
			t.Fatalf("泄露片段 %q: %s", frag, blob)
		}
	}
	if got["category"] != "ssh_private_key" || got["redacted_evidence"] != "-----BEGIN-----" {
		t.Fatalf("其余键被改动: %#v", got)
	}
}
