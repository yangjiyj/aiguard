package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22：投毒等系统发现改为 mcp.* 防护项（见 mcp_protection_items_test.go），这里改用管理员
// 手动隔离（原用例的 description_poison 现在默认告警放行），断言不变：管理员隔离在审计模式下
// 仍保留原始阻断结论与证据。
func TestMCPSupplyChainQuarantinePreservesEvidenceUnderAuditOnly(t *testing.T) {
	policy := &MCPEffectivePolicy{
		Matched: true, PolicyID: "explicit-allow", Mode: "strict", Action: "allow",
		SupplyChainStatus: "quarantined", SupplyChainReasons: []string{"mcp_tool_quarantined", "manual_quarantine"},
		SupplyChainRevision: "mcpsc_1", StructuralBlock: true,
	}
	decision := synthesizeMCPDecision(policy, "safe_name", "{}", agentguard.ModeAudit)
	// 2.9.22：AdmissionFloor 已删除，MCP 准入阻断以 ConfiguredEnforcement 标记（本批行为不变）。
	if !decision.ConfiguredEnforcement || decision.RawDecision != agentguard.DecisionBlock ||
		decision.EffectiveDecision != agentguard.DecisionAudit {
		t.Fatalf("supply-chain quarantine was downgraded: %+v", decision)
	}
	if len(decision.Evidence) != 1 || decision.Evidence[0].RuleID != "mcp_supply_chain_admission" ||
		decision.Evidence[0].Hash != "mcpsc_1" {
		t.Fatalf("supply-chain evidence lost: %+v", decision.Evidence)
	}
}

func TestMCPApprovedPolicyIsNotCachedAheadOfQuarantine(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = fmt.Fprint(w, `{"matched":true,"policy_id":"allow","mode":"strict","action":"allow","supply_chain_status":"approved","supply_chain_revision":"v1","structural_block":false,"route_hash":"r1","approved_route_hash":"r1","schema_hash":"s1","approved_schema_hash":"s1"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"matched":true,"policy_id":"allow","mode":"strict","action":"block","supply_chain_status":"quarantined","supply_chain_reasons":["route_binding_changed"],"supply_chain_revision":"v2","structural_block":true,"route_hash":"r2","approved_route_hash":"r1","schema_hash":"s1","approved_schema_hash":"s1"}`)
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", RequestID: "request-a"}
	first := client.GetMCPEffectivePolicy(t.Context(), envelope, "server-a", "tool-a")
	second := client.GetMCPEffectivePolicy(t.Context(), envelope, "server-a", "tool-a")
	third := client.GetMCPEffectivePolicy(t.Context(), envelope, "server-a", "tool-a")
	if first.StructuralBlock || !second.StructuralBlock || !third.StructuralBlock {
		t.Fatalf("unexpected policy sequence: first=%+v second=%+v third=%+v", first, second, third)
	}
	if calls.Load() != 2 {
		t.Fatalf("approved response hid quarantine or block was not safely cached: calls=%d", calls.Load())
	}
	if second.RouteHash != "r2" || second.ApprovedRouteHash != "r1" ||
		second.SchemaHash != "s1" || second.ApprovedSchemaHash != "s1" {
		t.Fatalf("binding contract not decoded: %+v", second)
	}
}

func TestMCPGatewayRouteCacheCannotCrossApprovedBinding(t *testing.T) {
	policy := &MCPEffectivePolicy{
		Mode: "strict", Action: "allow", SupplyChainStatus: "approved",
		RouteHash: "new-route", ApprovedRouteHash: "new-route",
	}
	matching := enforceMCPGatewayRouteBinding(policy, "new-route")
	if matching.StructuralBlock {
		t.Fatalf("matching route was blocked: %+v", matching)
	}
	stale := enforceMCPGatewayRouteBinding(policy, "old-cached-route")
	// 2.9.22：不再把动作强改成 block（原断言 stale.Action == "block"），路由绑定不一致按
	// mcp.drift 防护项处置：默认告警放行，设为阻断时照拦。
	if !stale.StructuralBlock || len(stale.SupplyChainReasons) != 1 || stale.SupplyChainReasons[0] != "gateway_route_binding_mismatch" {
		t.Fatalf("stale gateway route crossed approval binding: %+v", stale)
	}
	blocked := synthesizeMCPDecisionForTenant(stale, "read", "{}", agentguard.ModeStrict, true, nil,
		mcpTenantContext{ServerName: "files", Protections: protection.Settings{protection.KeyMCPDrift: {Action: protection.ActionBlock}}})
	if blocked.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("mcp.drift=block must block a stale gateway route: %+v", blocked)
	}
}
