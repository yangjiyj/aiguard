package handler

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// TestBuildMCPToolContractsResolvesPolicyAndAuditOnlyCeiling 验证契约装配纯函数：
// 命中租户通配 block 策略 → expected_action=block；audit-only 天花板下
// effective_action_ceiling 被钳到 audit（守 audit-only 铁律，raw 期望与生效动作解耦）；
// removed 工具被跳过；poison_flags/risk_tags 原样透传。
func TestBuildMCPToolContractsResolvesPolicyAndAuditOnlyCeiling(t *testing.T) {
	policies := []*repository.MCPPolicy{
		{
			ID:            "pol-block",
			TenantID:      "tenant-1",
			ScopeType:     "tenant",
			ServerID:      "",
			ToolPattern:   "",
			Mode:          "strict",
			DefaultAction: "block",
			Enabled:       true,
			Priority:      10,
			UpdatedAt:     time.Unix(1000, 0).UTC(),
		},
	}
	tools := []*repository.MCPTool{
		{
			ToolName:    "fetch_url",
			RiskTags:    []string{"ssrf"},
			PoisonFlags: []string{"mcp_description_poison_exfil"},
			SchemaHash:  "sh1",
		},
		{
			ToolName: "stale_tool",
			Removed:  true, // 应被跳过
		},
	}

	contracts := buildMCPToolContracts("tenant-1", "srv-1", "payments", tools, policies, true)
	if len(contracts) != 1 {
		t.Fatalf("expected 1 contract (removed skipped), got %d", len(contracts))
	}
	c := contracts[0]
	if c["tool_name"] != "fetch_url" {
		t.Fatalf("tool_name = %v", c["tool_name"])
	}
	if c["qualified_name"] != "payments__fetch_url" {
		t.Fatalf("qualified_name = %v", c["qualified_name"])
	}
	if c["expected_action"] != "block" {
		t.Fatalf("expected_action = %v, want block", c["expected_action"])
	}
	if c["effective_action_ceiling"] != "audit" {
		t.Fatalf("effective_action_ceiling = %v, want audit (audit-only ceiling)", c["effective_action_ceiling"])
	}
	if c["policy_matched"] != true || c["policy_id"] != "pol-block" {
		t.Fatalf("policy match wrong: matched=%v id=%v", c["policy_matched"], c["policy_id"])
	}
	poison, _ := c["poison_flags"].([]string)
	if len(poison) != 1 || poison[0] != "mcp_description_poison_exfil" {
		t.Fatalf("poison_flags not passed through: %#v", c["poison_flags"])
	}
	redlines, _ := c["redline_triggers"].([]string)
	if len(redlines) != len(mcpContractRuntimeRedlines) {
		t.Fatalf("redline_triggers = %#v", c["redline_triggers"])
	}
	// 证据不应泄露原始入参/结果，只含核对位置。
	if _, ok := c["evidence_requirements"]; !ok {
		t.Fatalf("missing evidence_requirements")
	}
}

// TestBuildMCPToolContractsDefaultsToAuditOnMiss 全 miss → observe-first：mode/action=audit。
func TestBuildMCPToolContractsDefaultsToAuditOnMiss(t *testing.T) {
	tools := []*repository.MCPTool{{ToolName: "noop"}}
	contracts := buildMCPToolContracts("tenant-1", "srv-1", "svc", tools, nil, false)
	if len(contracts) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(contracts))
	}
	c := contracts[0]
	if c["policy_matched"] != false {
		t.Fatalf("expected no policy match, got %v", c["policy_matched"])
	}
	if c["expected_action"] != string(repository.AgentGuardActionAudit) {
		t.Fatalf("expected default action audit, got %v", c["expected_action"])
	}
	if c["effective_action_ceiling"] != string(repository.AgentGuardActionAudit) {
		t.Fatalf("non-block action should be unchanged by ceiling, got %v", c["effective_action_ceiling"])
	}
}

// TestMCPPolicyContractVersionDeterministicAndSensitive 版本指纹：同输入稳定、任一输入变即变。
func TestMCPPolicyContractVersionDeterministicAndSensitive(t *testing.T) {
	base := mcpPolicyContractVersion("mh1", time.Unix(1000, 0).UTC())
	if base != mcpPolicyContractVersion("mh1", time.Unix(1000, 0).UTC()) {
		t.Fatalf("version not deterministic")
	}
	if base == mcpPolicyContractVersion("mh2", time.Unix(1000, 0).UTC()) {
		t.Fatalf("version should change when manifest hash changes")
	}
	if base == mcpPolicyContractVersion("mh1", time.Unix(2000, 0).UTC()) {
		t.Fatalf("version should change when latest policy update changes")
	}
}

// TestEvalAssurancePolicyContractsIncludeMCP 契约类目含 5 条 MCP 类目 + detector 正确。
func TestEvalAssurancePolicyContractsIncludeMCP(t *testing.T) {
	policies := evalAssurancePolicyContracts()
	wantDetector := map[string]string{
		"mcp.param_ssrf":          "gateway_mcp",
		"mcp.credential_exfil":    "gateway_mcp",
		"mcp.destructive_command": "gateway_mcp",
		"mcp.tool_poisoning":      "security_engine",
		"mcp.shadow_tool":         "gateway_mcp",
		"mcp.rug_pull":            "gateway_mcp",
	}
	found := map[string]bool{}
	for _, p := range policies {
		id, _ := p["policy_id"].(string)
		if want, ok := wantDetector[id]; ok {
			found[id] = true
			if p["detector"] != want {
				t.Fatalf("%s detector = %v, want %v", id, p["detector"], want)
			}
		}
	}
	for id := range wantDetector {
		if !found[id] {
			t.Fatalf("missing MCP assurance policy category: %s", id)
		}
	}
}

// TestEvalToolRuleIDsExtractsRedlineRuleIDs 从 evidence_json 抽取命中的红线 rule_id。
func TestEvalToolRuleIDsExtractsRedlineRuleIDs(t *testing.T) {
	raw := json.RawMessage(`[{"rule_id":"mcp_redline_cloud_metadata","category":"mcp_redline"},{"category":"noise"}]`)
	ids := evalToolRuleIDs(raw)
	if len(ids) != 1 || ids[0] != "mcp_redline_cloud_metadata" {
		t.Fatalf("rule ids = %#v", ids)
	}
	if got := evalToolRuleIDs(json.RawMessage("[]")); len(got) != 0 {
		t.Fatalf("empty evidence should yield no rule ids, got %#v", got)
	}
	if got := evalToolRuleIDs(json.RawMessage("null")); len(got) != 0 {
		t.Fatalf("null evidence should yield no rule ids, got %#v", got)
	}
}
