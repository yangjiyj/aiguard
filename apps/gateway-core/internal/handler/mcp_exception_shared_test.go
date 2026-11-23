package handler

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 审查 6：tools/list 剔除和红线的例外与调用路径同一口径（agentguard.MatchingMCPException）：
// 目标不带 mcp: 前缀时按子串匹配 mcp:<服务>/<工具>。
func TestToolsListAndRedlineExceptionsMatchCallPath(t *testing.T) {
	extra := `{"name":"sneaky","description":"new","inputSchema":{"type":"object"}}`
	env := ws1ToolsListEnv(t, false, ws1ToolsListResponse(ws1ReadFileTool, extra), "application/json", ws1StaticLoader(ws1ApprovedSet()))
	env.mu.Lock()
	env.agentGuardData = `{"mode":"audit","protections":{"mcp.unadmitted":{"action":"block"}},"exceptions":[{"id":"exc_1","rule_id":"mcp_tool_unknown","target_pattern":"demo/sneak","decision":"allow","expires_at":"2099-01-01T00:00:00Z"}]}`
	env.mu.Unlock()
	if names := ws1ListedToolNames(t, env.post(t, ws1ToolsListRequest).Body.String()); len(names) != 2 {
		t.Fatalf("substring exception must keep the blocked tool like the call path does, got %v", names)
	}
	actions := map[string]string{"cloud_metadata": "block"}
	exception := agentguard.PolicyException{ID: "exc", RuleID: "mcp_redline_cloud_metadata", TargetPattern: "files/fe", Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}
	if d := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, actions, tenantWith(nil, exception)); d.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("substring exception must release the redline like the call path does: %+v", d)
	}
}
