package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/endpointpolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

func TestAgentEndpointDecideAuditUsesResolvedIdentityAndProposalFacts(t *testing.T) {
	var captured map[string]any
	policy := endpointTestBundle([]endpointpolicy.Rule{{ID: "audit_fixture_block", Match: endpointpolicy.Match{ToolNameRegex: "^audit_fixture$"}, Decision: "block", Risk: "high", Enabled: true}}, nil)
	var expected endpointpolicy.Bundle
	if err := json.Unmarshal(policy, &expected); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/admin/v1/internal/agent/policy-bundle" {
			if r.Header.Get("Authorization") != "Bearer "+endpointPolicyTestBearer || r.Header.Get("X-JJDGuard-Internal-Token") != "internal-test-secret" {
				t.Errorf("policy request authentication mismatch")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(policy)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/admin/v1/internal/tools/logs" {
			t.Errorf("unexpected audit request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Tenant-ID"); got != "tenant-resolved" {
			t.Errorf("tenant header=%q", got)
		}
		if got := r.Header.Get("X-JJDGuard-Internal-Token"); got != "internal-test-secret" {
			t.Errorf("internal token header=%q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode audit body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"tc-test"}`)
	}))
	defer server.Close()

	g := &AgentEndpointGateway{controlURL: server.URL, secret: "internal-test-secret", client: server.Client(), toolClient: &ToolRiskClient{
		controlPlaneURL:   server.URL,
		internalAPISecret: "internal-test-secret",
		httpClient:        server.Client(),
	}}
	body := `{"endpoint_id":"endpoint-resolved","session_id":"session-test","prompt_id":"prompt-test","tool_use_id":"call-test","agent":{"product":"claude-code"},"tool":{"name":"audit_fixture","type":"other"},"arguments":{"fixture":"safe"},"context":{}}`
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/decide", strings.NewReader(body))
	rec := httptest.NewRecorder()
	g.decide(rec, req, endpointPolicyTestBearer, map[string]any{
		"tenant_id":      "tenant-resolved",
		"endpoint_id":    "endpoint-resolved",
		"mode":           "monitor",
		"policy_version": "policy-test",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("decide status=%d body=%s", rec.Code, rec.Body.String())
	}
	if captured["tenant_id"] != "tenant-resolved" || captured["endpoint_id"] != "endpoint-resolved" {
		t.Fatalf("audit identity did not come from resolved context: %#v", captured)
	}
	if captured["session_id"] != "session-test" || captured["prompt_id"] != "prompt-test" || captured["tool_call_id"] != "call-test" {
		t.Fatalf("audit lifecycle identity mismatch: %#v", captured)
	}
	evidence, ok := captured["evidence_json"].(map[string]any)
	if !ok {
		t.Fatalf("audit evidence shape=%T", captured["evidence_json"])
	}
	intent, ok := evidence["t16_intent"].(map[string]any)
	if !ok || intent["prompt_ref_hash"] != agentintent.DigestString("prompt-test") ||
		intent["tool_call_ref_hash"] != agentintent.DigestString("call-test") ||
		intent["tool_name_ref_hash"] != agentintent.DigestString("audit_fixture") || intent["tool_type"] != "other" {
		t.Fatalf("T16 identity binding absent from proposal: %#v", evidence)
	}
	if captured["request_id"] != "" || captured["event_kind"] != "invocation_proposed" || captured["provenance"] != "agent_endpoint" || captured["attribution_mode"] != "endpoint_hook" {
		t.Fatalf("audit claimed a model request or wrong event: %#v", captured)
	}
	if captured["status"] != "audited" && captured["status"] != "blocked" {
		t.Fatalf("proposal status=%v", captured["status"])
	}
	var decision struct {
		RiskLevel string `json:"risk_level"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode decide response: %v", err)
	}
	if decision.RiskLevel == "" || captured["risk_level"] != decision.RiskLevel {
		t.Fatalf("audit risk=%v decide risk=%q", captured["risk_level"], decision.RiskLevel)
	}
	if captured["policy_version"] != "9" || captured["effective_decision"] != "audit" || captured["raw_decision"] != "block" || captured["effective_reason"] == "" {
		t.Fatalf("audit policy metadata missing or uses last-applied context: %#v", captured)
	}
	evidence, ok = captured["evidence_json"].(map[string]any)
	if !ok || evidence["policy_checksum"] != expected.Checksum || evidence["policy_rule_id"] != "audit_fixture_block" {
		t.Fatalf("audit policy evidence mismatch: %#v", captured["evidence_json"])
	}
	for _, field := range []string{"execution_forwarded", "execution_observed", "result_observed"} {
		if captured[field] != false {
			t.Fatalf("proposal field %s=%v, want false", field, captured[field])
		}
	}
	if captured["trace_id"] != "agent-call-test" {
		t.Fatalf("decision trace=%v", captured["trace_id"])
	}
}
