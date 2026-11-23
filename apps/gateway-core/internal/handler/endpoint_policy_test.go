package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/endpointpolicy"
)

const endpointPolicyTestBearer = "endpoint-fixture-token"

func endpointTestBundle(rules []endpointpolicy.Rule, secrets []endpointpolicy.SecretPattern) []byte {
	if rules == nil {
		rules = []endpointpolicy.Rule{}
	}
	if secrets == nil {
		secrets = []endpointpolicy.SecretPattern{
			{Kind: "aws_access_key_id", Regex: `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`},
			{Kind: "private_key", Regex: `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
			{Kind: "github_token", Regex: `\bgh[pousr]_[A-Za-z0-9_]{36,}\b`},
			{Kind: "openai_api_key", Regex: `\bsk-[A-Za-z0-9_-]{32,}\b`},
			{Kind: "canary_token", Regex: `\bcanary-[A-Za-z0-9_-]*(?:token|secret|credential)[A-Za-z0-9_-]*\b`},
		}
	}
	bundle := endpointpolicy.Bundle{SchemaVersion: "1.0", Version: 9, GeneratedAt: "2026-09-25T00:00:00Z", ModeDefault: "block", Rules: rules, SecretPatterns: secrets}
	bundle.Checksum = endpointpolicy.Checksum(bundle)
	data, _ := json.Marshal(bundle)
	return data
}

func endpointPolicyTestGateway(t *testing.T, raw []byte) (*AgentEndpointGateway, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/admin/v1/internal/agent/policy-bundle" || r.Method != http.MethodGet {
			t.Errorf("unexpected policy request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+endpointPolicyTestBearer {
			t.Errorf("policy request did not use authenticated endpoint bearer")
		}
		if r.Header.Get("X-JJDGuard-Internal-Token") != "internal-fixture" {
			t.Errorf("policy request did not use internal auth")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)
	return &AgentEndpointGateway{controlURL: server.URL, secret: "internal-fixture", client: server.Client()}, &calls
}

func callEndpointDecide(g *AgentEndpointGateway, body string, endpointID, mode string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/decide", strings.NewReader(body))
	w := httptest.NewRecorder()
	g.decide(w, req, endpointPolicyTestBearer, map[string]any{"endpoint_id": endpointID, "tenant_id": "tenant-fixture", "mode": mode})
	return w
}

func runEndpointDecideBody(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	g, _ := endpointPolicyTestGateway(t, endpointTestBundle(nil, nil))
	return callEndpointDecide(g, body, "ep_fixture01", "monitor")
}

func withSystemTool(body string, command string) string {
	body = strings.Replace(body, `"name":"Read","type":"file","mcp_server":"fixture"`, `"name":"Bash","type":"system","mcp_server":""`, 1)
	body = strings.Replace(body, `"arguments":{"file_path":"/tmp/fixture","nested":{"value":true}}`, `"arguments":{"command":"`+command+`"}`, 1)
	return body
}

func TestDecideFetchesAuthenticatedBundleAndReturnsActualVersionChecksumAndRule(t *testing.T) {
	raw := endpointTestBundle([]endpointpolicy.Rule{{ID: "fixture_policy_block", Match: endpointpolicy.Match{ToolType: "system", ToolNameRegex: `^Bash$`, CommandRegex: `^printf safe$`}, Decision: "block", Risk: "high", Enabled: true}}, nil)
	g, calls := endpointPolicyTestGateway(t, raw)
	w := callEndpointDecide(g, withSystemTool(hookdDecideRequestFixture, "printf safe"), "ep_fixture01", "block")
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var expected endpointpolicy.Bundle
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || *calls != 1 || body["policy_version"] != float64(expected.Version) || body["policy_checksum"] != expected.Checksum || body["rule_id"] != "fixture_policy_block" || body["raw_decision"] != "block" {
		t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
	}
}

func TestDecideEndpointModeClampsBundleBlock(t *testing.T) {
	raw := endpointTestBundle([]endpointpolicy.Rule{{ID: "fixture_policy_block", Match: endpointpolicy.Match{ToolType: "system", CommandRegex: `^printf safe$`}, Decision: "block", Risk: "high", Enabled: true}}, nil)
	for _, tc := range []struct{ mode, want string }{{"monitor", "audit"}, {"would_block", "audit"}, {"block", "block"}} {
		t.Run(tc.mode, func(t *testing.T) {
			g, _ := endpointPolicyTestGateway(t, raw)
			w := callEndpointDecide(g, withSystemTool(hookdDecideRequestFixture, "printf safe"), "ep_fixture01", tc.mode)
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || body["raw_decision"] != "block" || body["effective_decision"] != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// 2.9.22 批次 2B：raw_decision 仍报分析器与策略包规则中更严者（兼容旧字段）；生效动作里显式规则
// 允许降级分析器结论，见 TestDecide2922ExplicitEndpointRuleMayDowngrade。
func TestDecideKeepsStricterRiskAnalysisAndPassesContext(t *testing.T) {
	raw := endpointTestBundle([]endpointpolicy.Rule{{ID: "fixture_policy_audit", Match: endpointpolicy.Match{ToolType: "system", CommandRegex: `^printf safe$`}, Decision: "audit", Risk: "low", Enabled: true}}, nil)
	g, _ := endpointPolicyTestGateway(t, raw)
	w := callEndpointDecide(g, withSystemTool(hookdDecideRequestFixture, "printf safe"), "ep_fixture01", "block")
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || body["raw_decision"] != "confirm" || body["risk_level"] != "high" || body["rule_id"] != "fixture_policy_audit" {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDecideNoMatchReturnsActualBundleAndNoRule(t *testing.T) {
	raw := endpointTestBundle(nil, nil)
	g, _ := endpointPolicyTestGateway(t, raw)
	w := callEndpointDecide(g, hookdDecideRequestFixture, "ep_fixture01", "monitor")
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || body["policy_version"] != float64(9) || body["rule_id"] != "" {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDecideRefusesPolicyVersionChecksumAndAuthenticationMismatch(t *testing.T) {
	valid := endpointTestBundle(nil, nil)
	var parsed endpointpolicy.Bundle
	if err := json.Unmarshal(valid, &parsed); err != nil {
		t.Fatal(err)
	}
	badChecksum := bytes.Replace(valid, []byte(parsed.Checksum), []byte("sha256:"+strings.Repeat("0", 64)), 1)
	badVersionBundle := parsed
	badVersionBundle.Version = 0
	badVersionBundle.Checksum = endpointpolicy.Checksum(badVersionBundle)
	badVersion, _ := json.Marshal(badVersionBundle)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "checksum", raw: badChecksum},
		{name: "version", raw: badVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, calls := endpointPolicyTestGateway(t, tc.raw)
			w := callEndpointDecide(g, hookdDecideRequestFixture, "ep_fixture01", "monitor")
			if w.Code != http.StatusServiceUnavailable || *calls != 1 || !strings.Contains(w.Body.String(), "AGENT_POLICY_UNAVAILABLE") {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
			}
		})
	}
	g, calls := endpointPolicyTestGateway(t, valid)
	w := callEndpointDecide(g, hookdDecideRequestFixture, "different-endpoint", "monitor")
	if w.Code != http.StatusUnauthorized || *calls != 0 {
		t.Fatalf("endpoint mismatch status=%d policy calls=%d body=%s", w.Code, *calls, w.Body.String())
	}
}

func TestDecideUnknownRulesUseLocalFallbackUnlessKnownBlockDominates(t *testing.T) {
	secret := []endpointpolicy.SecretPattern{{Kind: "fixture_secret", Regex: `secret-value`}}
	unknownRule := endpointpolicy.Rule{ID: "fixture_secret_rule", Match: endpointpolicy.Match{ArgsSecretPattern: true}, Decision: "confirm", Risk: "high", Enabled: true}
	redacted := strings.Replace(hookdDecideRequestFixture, `"nested":{"value":true}`, `"nested":{"value":"%3Credacted%3E"}`, 1)
	for _, tc := range []struct {
		name, body string
		rules      []endpointpolicy.Rule
		wantStatus int
	}{
		{name: "redacted-secret", body: redacted, rules: []endpointpolicy.Rule{unknownRule}, wantStatus: http.StatusServiceUnavailable},
		{name: "home-ambiguous", body: strings.Replace(hookdDecideRequestFixture, "/tmp/fixture", "/home/example/.ssh/id_key", 1), rules: []endpointpolicy.Rule{{ID: "fixture_home_rule", Match: endpointpolicy.Match{ToolType: "file", PathGlob: []string{"~/.ssh/id_*"}}, Decision: "confirm", Risk: "high", Enabled: true}}, wantStatus: http.StatusServiceUnavailable},
		{name: "home-rule-excluded-by-tool-type", body: withSystemTool(hookdDecideRequestFixture, "printf safe"), rules: []endpointpolicy.Rule{{ID: "fixture_home_rule", Match: endpointpolicy.Match{ToolType: "file", PathGlob: []string{"~/.ssh/id_*"}}, Decision: "confirm", Risk: "high", Enabled: true}}, wantStatus: http.StatusOK},
		{name: "known-block-dominates-redaction", body: withSystemTool(redacted, "printf safe"), rules: []endpointpolicy.Rule{unknownRule, {ID: "known_block", Match: endpointpolicy.Match{ToolType: "system", CommandRegex: `.*`}, Decision: "block", Risk: "high", Enabled: true}}, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := endpointPolicyTestGateway(t, endpointTestBundle(tc.rules, secret))
			w := callEndpointDecide(g, tc.body, "ep_fixture01", "block")
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.name == "known-block-dominates-redaction" && !strings.Contains(w.Body.String(), `"rule_id":"known_block"`) {
				t.Fatalf("known block rule not returned: %s", w.Body.String())
			}
		})
	}
}

func TestEndpointPolicyTransportFailureReturnsFallbackStatus(t *testing.T) {
	g := &AgentEndpointGateway{controlURL: "http://policy.invalid", client: &http.Client{Transport: endpointTransportFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fixture unavailable")
	})}}
	w := callEndpointDecide(g, hookdDecideRequestFixture, "ep_fixture01", "monitor")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "AGENT_POLICY_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestFetchPolicyRejectsTrailingResponseData(t *testing.T) {
	raw := append(endpointTestBundle(nil, nil), []byte(" {}")...)
	g, _ := endpointPolicyTestGateway(t, raw)
	_, err := g.fetchEndpointPolicy(httptest.NewRequest(http.MethodGet, "/", nil).Context(), endpointPolicyTestBearer)
	if err == nil {
		t.Fatal("trailing response object accepted")
	}
}
