package handler

// Last-known-good blocks remain effective with an explicitly open fail mode.
// Closed mode is covered by mcp_policy_fail_mode_test.go.

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 先成功拉到 strict/block，再让控制面 503：管理员配的 block 必须照样生效。
func TestWS1PolicyFetchFailureUsesLastKnownGoodBlock(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	first := env.post(t, mcpToolsCallBody)
	if rpcErrorCode(t, first.Body.String()) != -32000 {
		t.Fatalf("前置：block 应生效: %s", first.Body.String())
	}
	env.mu.Lock()
	env.policyStatus = http.StatusServiceUnavailable
	env.mu.Unlock()
	second := env.post(t, mcpToolsCallBody)
	if hits := atomic.LoadInt32(env.upstreamHits); hits != 0 {
		t.Fatalf("控制面故障时沿用 last-known-good block，不得触达上游: hits=%d resp=%s", hits, second.Body.String())
	}
	if rpcErrorCode(t, second.Body.String()) != -32000 {
		t.Fatalf("应仍按策略阻断: %s", second.Body.String())
	}
}

// 从未拉到过：放行 + 覆盖缺口原因 mcp_policy_unavailable 留证。
func TestWS1PolicyNeverFetchedAllowsWithCoverageGap(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	env.handler.toolRiskClient.SetMCPPolicyFailMode("open")
	env.policyStatus = http.StatusServiceUnavailable
	w := env.post(t, mcpToolsCallBody)
	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("从未拉到策略应放行: code=%d hits=%d body=%s", w.Code, atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
	client := env.handler.toolRiskClient
	p := client.GetMCPEffectivePolicy(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant_other"}, "mcp_srv1", "delete_repo")
	if p.StructuralBlock || p.Action != "audit" || len(p.SupplyChainReasons) != 1 || p.SupplyChainReasons[0] != mcpPolicyUnavailableReason {
		t.Fatalf("缺口原因应为 %s: %#v", mcpPolicyUnavailableReason, p)
	}
}

// last-known-good 按主体+目标隔离：A 目标的 block 不会套到 B 目标上。
func TestWS1LastKnownGoodIsPerTarget(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	env.handler.toolRiskClient.SetMCPPolicyFailMode("open")
	env.post(t, mcpToolsCallBody) // 记下 delete_repo=block
	env.mu.Lock()
	env.policyStatus = http.StatusServiceUnavailable
	env.mu.Unlock()
	body := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	w := env.post(t, body)
	if atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("其他目标无 last-known-good，应放行: hits=%d resp=%s", atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
}
