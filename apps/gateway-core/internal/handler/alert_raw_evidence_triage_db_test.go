package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 真库验证复核回写后 findings 顺序不变、主命中引用仍指向原来那条（需 CONTENT_LOGS_TEST_DATABASE_URL）。
func TestAnnotateTriageKeepsFindingsOrderOnPostgres(t *testing.T) {
	db, ctx, tenantID, projectID, providerID, modelID := setupAuditWriterNullUserFixture(t)
	writer := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	envelope := &modelrouter.RequestEnvelope{RequestID: tenantID + "_triage", TenantID: tenantID, ProjectID: projectID,
		ClientID: "key_triage", ProviderID: providerID, ModelID: modelID, EndpointType: "chat"}
	writer.EnsureRequestLog(ctx, envelope)
	findings := []SecurityFinding{}
	for i, severity := range []string{"medium", "critical", "low", "medium", "high"} {
		f := rawEvidenceSummaryCases()["无前后文"]
		f.Severity, f.RuleID, f.MatchedLocation = severity, "r"+string(rune('0'+i)), "input"
		findings = append(findings, f)
	}
	writer.WriteSecurityEvent(ctx, envelope, findings, "audit", "复核回写顺序")
	triaged := findings[3]
	triaged.Triage = map[string]any{"verdict": "likely_false_positive"}
	writer.AnnotateTriage(ctx, envelope, []SecurityFinding{triaged})

	var stored []byte
	if err := db.QueryRow(ctx, `SELECT matched_summary FROM security_events WHERE tenant_id=$1 AND request_id=$2`, tenantID, envelope.RequestID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Findings []map[string]any `json:"findings"`
		Primary  map[string]any   `json:"primary_finding"`
	}
	if err := json.Unmarshal(stored, &summary); err != nil {
		t.Fatal(err)
	}
	for i, f := range summary.Findings {
		if f["rule_id"] != "r"+string(rune('0'+i)) {
			t.Fatalf("复核回写后顺序变了: %v", summary.Findings)
		}
	}
	if summary.Findings[3]["triage"] == nil || summary.Findings[1]["triage"] != nil {
		t.Fatalf("复核标注落在对应的命中上: %v", summary.Findings)
	}
	index := int(summary.Primary["findings_index"].(float64))
	if summary.Findings[index]["rule_id"] != summary.Primary["rule_id"] || summary.Primary["rule_id"] != "r1" {
		t.Fatalf("主命中引用仍指向原来那条: %v", summary.Primary)
	}
}
