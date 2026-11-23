package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	securityrules "github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

func TestAssuranceContractEnrichesExactTenantRuleIDs(t *testing.T) {
	contracts := evalAssurancePolicyContracts()
	pack := &securityrules.RulePack{Policies: []securityrules.CompiledPolicy{{
		PolicyID: "rule-hardcoded-exact",
		Capabilities: []securityrules.CompiledPolicyCapability{{
			Category: "code_leak_password_in_code",
		}},
	}}}
	enrichAssurancePolicyRuleIDs(contracts, pack)
	for _, contract := range contracts {
		if contract["policy_id"] == "code.hardcoded_credential" {
			if contract["rule_id"] != "rule-hardcoded-exact" {
				t.Fatalf("hardcoded credential rule_id=%v", contract["rule_id"])
			}
			return
		}
	}
	t.Fatal("hardcoded credential assurance contract missing")
}

func TestEvalIntegrationAssuranceContractExportsPolicyAndLinkContracts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/assurance-contract", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant-1")
	w := httptest.NewRecorder()

	GetEvalIntegrationAssuranceContract(&Dependencies{})(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if body["schema_version"] != "gateway-assurance-contract/v1" {
		t.Fatalf("schema = %#v", body["schema_version"])
	}
	policies, ok := body["policies"].([]interface{})
	if !ok || len(policies) < 10 {
		t.Fatalf("expected broad policy contracts, got %#v", body["policies"])
	}
	coverage, ok := body["coverage"].(map[string]interface{})
	if !ok {
		t.Fatalf("contract must expose coverage summary, got %#v", body["coverage"])
	}
	if coverage["policy_source"] != "gateway_assurance_policy_registry" {
		t.Fatalf("coverage policy_source = %#v", coverage["policy_source"])
	}
	if got := int(coverage["policy_count"].(float64)); got != len(policies) {
		t.Fatalf("coverage policy_count = %d, want %d", got, len(policies))
	}
	if got := int(coverage["sample_variant_count"].(float64)); got < len(policies)*3 {
		t.Fatalf("coverage sample_variant_count = %d, want at least %d", got, len(policies)*3)
	}
	firstPolicy, ok := policies[0].(map[string]interface{})
	if !ok {
		t.Fatalf("policy item must be object: %#v", policies[0])
	}
	variants, ok := firstPolicy["sample_variants"].([]interface{})
	if !ok || len(variants) < 3 {
		t.Fatalf("policy must expose multiple sample variants, got %#v", firstPolicy["sample_variants"])
	}
	multiTurnPolicies := 0
	nonChatPolicies := 0
	for _, item := range policies {
		policy, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("policy item must be object: %#v", item)
		}
		if strings.TrimSpace(policy["rule_id"].(string)) == "" {
			t.Fatalf("policy must expose exact rule_id: %#v", policy)
		}
		stages, ok := policy["supported_stages"].([]interface{})
		if !ok || len(stages) == 0 {
			t.Fatalf("policy must expose supported_stages: %#v", policy)
		}
		transport, ok := policy["sample_transport"].(string)
		if !ok || transport == "" {
			t.Fatalf("policy must expose sample_transport: %#v", policy)
		}
		if transport != "chat" {
			nonChatPolicies++
		}
		variants, ok := policy["sample_variants"].([]interface{})
		if !ok {
			t.Fatalf("policy must expose sample variants: %#v", policy)
		}
		hasMultiTurn := false
		for _, raw := range variants {
			variant, ok := raw.(map[string]interface{})
			if ok && variant["variant_id"] == "multi_turn" {
				hasMultiTurn = true
				if variant["turn_count"] != float64(2) {
					t.Fatalf("multi_turn variant must declare two turns: %#v", variant)
				}
			}
		}
		if hasMultiTurn {
			multiTurnPolicies++
		}
	}
	if multiTurnPolicies != len(policies) {
		t.Fatalf("all policies must expose a multi_turn assurance variant, got %d/%d", multiTurnPolicies, len(policies))
	}
	if nonChatPolicies == 0 {
		t.Fatal("contract must identify non-chat stage coverage instead of pretending text coverage")
	}
	links, ok := body["link_contracts"].([]interface{})
	if !ok || len(links) < 8 {
		t.Fatalf("expected link contracts, got %#v", body["link_contracts"])
	}
	if !strings.Contains(w.Body.String(), "prompt_injection") {
		t.Fatalf("contract should include prompt injection coverage: %s", w.Body.String())
	}
}

func TestEvalIntegrationAssuranceContractHonorsAuditOnlyMode(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/assurance-contract", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant-1")
	w := httptest.NewRecorder()

	GetEvalIntegrationAssuranceContract(&Dependencies{})(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	policies, ok := body["policies"].([]interface{})
	if !ok || len(policies) == 0 {
		t.Fatalf("policies missing: %#v", body["policies"])
	}
	for _, item := range policies {
		policy, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if policy["mode"] == "strict" && policy["expected_decision"] == "block" {
			t.Fatalf("audit-only assurance must not expect a hard block: %#v", policy)
		}
	}
}

func TestEvalIntegrationAssuranceContractKeepsNonGatewayLinksOutOfEvidenceContract(t *testing.T) {
	t.Setenv("AUDIT_ASYNC_ENABLED", "false")
	contracts := evalAssuranceLinkContracts()
	for _, contract := range contracts {
		if contract["link_id"] == "outbox" && contract["required"] == true {
			t.Fatalf("sync audit mode must not require outbox evidence: %#v", contracts)
		}
		if contract["link_id"] == "writeback" {
			t.Fatalf("LSE question-bank writeback must not be a gateway evidence contract: %#v", contracts)
		}
	}
}

func TestEvalIntegrationAssuranceContractRequiresTenant(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/assurance-contract", nil)
	w := httptest.NewRecorder()

	GetEvalIntegrationAssuranceContract(&Dependencies{})(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestEvalIntegrationAssuranceEvidenceRequiresCorrelationFilter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/assurance-evidence", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant-1")
	w := httptest.NewRecorder()

	GetEvalIntegrationAssuranceEvidence(&Dependencies{})(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "trace") {
		t.Fatalf("response should explain required correlation filter: %s", w.Body.String())
	}
}

func TestAssuranceEvidenceResponseReportsChecksWithoutLeakingSensitiveFields(t *testing.T) {
	filter := evalAssuranceEvidenceQuery{
		TraceID: "trace-1",
	}
	resp := assuranceEvidenceResponse("tenant-1", filter, []*repository.EvalAuditEvent{
		{
			ID:                 "log-1",
			RequestID:          "req-1",
			TenantID:           "tenant-1",
			CreatedAt:          time.Unix(0, 0).UTC(),
			TraceID:            "trace-1",
			LSEEvalRunID:       "eval-1",
			LSETaskID:          "task-1",
			LSESampleID:        "sample-1",
			LSETargetID:        "target-1",
			RequestStatus:      "completed",
			StatusCode:         http.StatusForbidden,
			ContentLogCount:    2,
			SecurityEventCount: 1,
			SecurityEvents: []repository.EvalSecurityEvent{
				{
					ID:          "sec-1",
					EventType:   "prompt_guard",
					Severity:    "critical",
					ActionTaken: "block",
					MatchedSummary: map[string]interface{}{
						"findings": []interface{}{
							map[string]interface{}{
								"category":          "prompt_injection",
								"rule_id":           "pg-001",
								"rule_name":         "系统提示词泄露",
								"redacted_evidence": "Authorization: Bearer should-not-leak",
							},
						},
					},
				},
			},
		},
	}, nil)

	if resp["schema_version"] != "gateway-assurance-evidence/v1" {
		t.Fatalf("schema = %#v", resp["schema_version"])
	}
	checks, ok := resp["checks"].(map[string]bool)
	if !ok {
		t.Fatalf("checks missing: %#v", resp["checks"])
	}
	if !checks["request_log"] || !checks["content_log"] || !checks["security_event"] || !checks["alert"] {
		t.Fatalf("expected request/security/alert checks true, got %#v", checks)
	}
	if checks["outbox"] {
		t.Fatalf("outbox should not be faked true in sync mode: %#v", checks)
	}
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), "should-not-leak") {
		t.Fatalf("response leaked sensitive evidence: %s", string(encoded))
	}
}

// 审查第 8 项：契约按实际生效的执行模式报告“会不会真拦”，不再读环境变量。
// 部署变量为 true 但控制台显式 protect → 期望 block；没有部署变量、控制台显式 record → 期望 alert。
func TestEvalIntegrationAssuranceContractFollowsEffectiveExecutionMode(t *testing.T) {
	for _, tc := range []struct {
		env, mode string
		wantBlock bool
	}{{"true", "protect", true}, {"", "record", false}, {"true", "", false}, {"", "protect", true}} {
		t.Setenv("SECURITY_AUDIT_ONLY", tc.env)
		settings := map[string]string{"security_audit_only": "false"}
		if tc.mode != "" {
			settings["security_execution_mode"] = tc.mode
		}
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/eval-integration/assurance-contract", nil)
		req.Header.Set("X-JJDGuard-Tenant-Id", "tenant-1")
		w := httptest.NewRecorder()
		GetEvalIntegrationAssuranceContract(&Dependencies{SystemRepo: &capturingSystemRepo{settings: settings}})(w, req)
		var body map[string]interface{}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		sawStrictBlock := false
		for _, item := range body["policies"].([]interface{}) {
			policy := item.(map[string]interface{})
			if policy["mode"] == "strict" && policy["expected_decision"] == "block" {
				sawStrictBlock = true
			}
		}
		if sawStrictBlock != tc.wantBlock {
			t.Fatalf("env=%q mode=%q: strict 样本期望 block=%v，实际 %v", tc.env, tc.mode, tc.wantBlock, sawStrictBlock)
		}
	}
}
