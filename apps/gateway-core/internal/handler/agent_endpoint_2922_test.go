package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/endpointpolicy"
)

// 批次 2B：端侧 decide 取租户有效策略（防护项、例外、规则）判定，执行模式取端点模式与全局执行
// 模式中更宽松者；8 条端侧内置规则是防护项 endpoint.rule.<规则 ID> 的命中。
func endpointRuntimeClient(t *testing.T, policyJSON string, globalRecord bool) *ToolRiskClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agentguard/effective-policy" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Tenant-ID") != "tenant-fixture" {
			t.Errorf("tenant header=%q", r.Header.Get("X-Tenant-ID"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + policyJSON + `}`))
	}))
	t.Cleanup(server.Close)
	client := NewToolRiskClient(server.URL, "internal-secret")
	setToolGuardTestPosture(t, client, globalRecord, false)
	return client
}

func endpointDecide2922(t *testing.T, bundle []byte, runtime *ToolRiskClient, endpointMode, path string) map[string]any {
	t.Helper()
	g, _ := endpointPolicyTestGateway(t, bundle)
	g.runtime = runtime
	body := strings.Replace(hookdDecideRequestFixture, "/tmp/fixture", path, 1)
	w := callEndpointDecide(g, body, "ep_fixture01", endpointMode)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

// 原“端点模式阻断时照拦”的口径改为“端点阻断 + 防护项阻断才拦”：读私钥默认告警放行，SSH 私钥配成阻断才拦。
func TestDecide2922EndpointBlockNeedsProtectionBlock(t *testing.T) {
	const base = `{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[]`
	byDefault := endpointDecide2922(t, endpointTestBundle(nil, nil), endpointRuntimeClient(t, base+`}`, false), "block", "/home/u/.ssh/id_rsa")
	if byDefault["effective_decision"] != "audit" {
		t.Fatalf("endpoint block alone must not block a default (alert-and-allow) protection item: %v", byDefault)
	}
	blocking := base + `,"protections":{"agent.ssh_private_key":{"action":"block","params":{}}}}`
	if got := endpointDecide2922(t, endpointTestBundle(nil, nil), endpointRuntimeClient(t, blocking, false), "block", "/home/u/.ssh/id_rsa"); got["effective_decision"] != "block" {
		t.Fatalf("endpoint block + protection block must block: %v", got)
	}
	if got := endpointDecide2922(t, endpointTestBundle(nil, nil), endpointRuntimeClient(t, blocking, false), "monitor", "/home/u/.ssh/id_rsa"); got["effective_decision"] != "audit" {
		t.Fatalf("endpoint monitor mode only records: %v", got)
	}
}

func TestDecide2922GlobalRecordModeNeverBlocks(t *testing.T) {
	blocking := `{"id":"p","mode":"strict","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"protections":{"agent.ssh_private_key":{"action":"block","params":{}}}}`
	got := endpointDecide2922(t, endpointTestBundle(nil, nil), endpointRuntimeClient(t, blocking, true), "block", "/home/u/.ssh/id_rsa")
	if got["effective_decision"] != "audit" {
		t.Fatalf("global record mode must win over an endpoint block mode: %v", got)
	}
}

func TestDecide2922BuiltinEndpointRuleFollowsProtectionItem(t *testing.T) {
	envRule := endpointpolicy.Rule{ID: "builtin_env_files", Match: endpointpolicy.Match{ToolType: "file", PathGlob: []string{"**/.env"}}, Decision: "audit", Risk: "high", Enabled: true}
	bundle := endpointTestBundle([]endpointpolicy.Rule{envRule}, nil)
	const base = `{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[]`
	if got := endpointDecide2922(t, bundle, endpointRuntimeClient(t, base+`,"exceptions":[]}`, false), "block", "/repo/.env"); got["effective_decision"] != "audit" {
		t.Fatalf("builtin rule alerts and allows by default: %v", got)
	}
	blocking := `,"protections":{"endpoint.rule.builtin_env_files":{"action":"block","params":{}}}`
	if got := endpointDecide2922(t, bundle, endpointRuntimeClient(t, base+`,"exceptions":[]`+blocking+`}`, false), "block", "/repo/.env"); got["effective_decision"] != "block" {
		t.Fatalf("builtin rule configured to block must block: %v", got)
	}
	exception := `,"exceptions":[{"id":"e-env","rule_id":"endpoint.rule.builtin_env_files","target_pattern":"","decision":"allow","expires_at":"2099-01-01T00:00:00Z"}]`
	if got := endpointDecide2922(t, bundle, endpointRuntimeClient(t, base+exception+blocking+`}`, false), "block", "/repo/.env"); got["effective_decision"] == "block" {
		t.Fatalf("an exception naming the builtin rule must release it: %v", got)
	}
}

// 端点策略包里管理员配置的显式规则允许降级分析器结论（以前一律取更严），但放不开防护项。
func TestDecide2922ExplicitEndpointRuleMayDowngrade(t *testing.T) {
	highRisk := `{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"protections":{"agent.high_risk_without_rule":{"action":"block","params":{}}}}`
	dropTable := func(bundle []byte) map[string]any {
		g, _ := endpointPolicyTestGateway(t, bundle)
		g.runtime = endpointRuntimeClient(t, highRisk, false)
		body := strings.Replace(hookdDecideRequestFixture, `"name":"Read","type":"file","mcp_server":"fixture"`, `"name":"run_sql","type":"database","mcp_server":""`, 1)
		body = strings.Replace(body, `"arguments":{"file_path":"/tmp/fixture","nested":{"value":true}}`, `"arguments":{"query":"DROP TABLE users"}`, 1)
		w := callEndpointDecide(g, body, "ep_fixture01", "block")
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var response map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		return response
	}
	if got := dropTable(endpointTestBundle(nil, nil)); got["effective_decision"] != "block" {
		t.Fatalf("fixture: high_risk_without_rule=block blocks DROP TABLE without a rule: %v", got)
	}
	auditRule := endpointpolicy.Rule{ID: "fixture_policy_audit", Match: endpointpolicy.Match{ToolType: "database", ToolNameRegex: "^run_sql$"}, Decision: "audit", Risk: "low", Enabled: true}
	if got := dropTable(endpointTestBundle([]endpointpolicy.Rule{auditRule}, nil)); got["effective_decision"] == "block" {
		t.Fatalf("an explicit audit rule downgrades an unconfigured analyzer verdict: %v", got)
	}
	fileAudit := endpointpolicy.Rule{ID: "fixture_file_audit", Match: endpointpolicy.Match{ToolType: "file", ToolNameRegex: "^Read$"}, Decision: "audit", Risk: "low", Enabled: true}
	blocking := `{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"protections":{"agent.ssh_private_key":{"action":"block","params":{}}}}`
	if got := endpointDecide2922(t, endpointTestBundle([]endpointpolicy.Rule{fileAudit}, nil), endpointRuntimeClient(t, blocking, false), "block", "/home/u/.ssh/id_rsa"); got["effective_decision"] != "block" {
		t.Fatalf("an explicit audit rule cannot loosen a protection item: %v", got)
	}
}

// 合流：端侧三条文件类内置规则（.env、SSH 私钥、SSH 授权公钥）的例外与 agent.env_file 等同口径，
// 按路径层级比对（filerestrict），不再是不分大小写的子串。
func TestDecide2922BuiltinFileRuleExceptionsFollowPathHierarchy(t *testing.T) {
	envRule := endpointpolicy.Rule{ID: "builtin_env_files", Match: endpointpolicy.Match{ToolType: "file", PathGlob: []string{"**/.env"}}, Decision: "audit", Risk: "high", Enabled: true}
	bundle := endpointTestBundle([]endpointpolicy.Rule{envRule}, nil)
	const base = `{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[]`
	const blocking = `,"protections":{"endpoint.rule.builtin_env_files":{"action":"block","params":{}}}`
	decide := func(pattern string) any {
		exception := `,"exceptions":[{"id":"e-env","rule_id":"endpoint.rule.builtin_env_files","target_pattern":"` + pattern + `","decision":"allow","expires_at":"2099-01-01T00:00:00Z"}]`
		return endpointDecide2922(t, bundle, endpointRuntimeClient(t, base+exception+blocking+`}`, false), "block", "/repo/app/.env")["effective_decision"]
	}
	for pattern, want := range map[string]string{
		".env":           "audit", // 文件名
		"/repo/app/":     "audit", // 目录
		"app/.env":       "audit", // 以 / 为界的后缀
		"env":            "block", // 子串不再放开
		"/REPO/app/.env": "block", // 区分大小写
		"/repo/ap":       "block", // 不按路径段的前缀
		"/other/":        "block",
	} {
		if got := decide(pattern); got != want {
			t.Errorf("exception %q: effective_decision=%v want %s", pattern, got, want)
		}
	}
}
