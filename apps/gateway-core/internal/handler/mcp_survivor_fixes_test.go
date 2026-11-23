package handler

// 对抗审查幸存项修复回归（车道 G1）：
//  1. 现代 MCP batch 无条件拒绝（防 control-plane 请求放大 DoS）
//  2. 运行时转发剥离 Cookie / 代理鉴权 / hop-by-hop 头（凭据不外泄低信任上游）
//  5. fail-closed 可选（audit-only 铁律仍不破）
//  6. confirm 建单失败如实告知（不谎报"已创建确认单"）
//  8a. 红线检测对 JSON \u 转义做解码扫描（防转义绕过）

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// mcpFixEnv 是带计数器、可配置 confirmations 返回码的测试环境（比 newMCPTestEnv 更细）。
type mcpFixEnv struct {
	handler             *MCPProxyHandler
	router              *chi.Mux
	upstreamHits        *int32
	effectivePolicyHits *int32
	confirmations       *int32
	upstream            *httptest.Server
	controlPlane        *httptest.Server
}

func newMCPFixEnv(t *testing.T, auditOnly bool, policy MCPEffectivePolicy, confirmStatus int) *mcpFixEnv {
	t.Helper()
	if policy.SupplyChainStatus == "" {
		policy.SupplyChainStatus = "approved"
		policy.ServerAdmissionStatus = "approved"
		policy.ToolAdmissionStatus = "approved"
		policy.SupplyChainRevision = "revision-test"
		policy.ToolID = "tool-test"
		policy.RouteHash = strings.Repeat("a", 64)
		policy.ApprovedRouteHash = policy.RouteHash
		policy.ApprovedSchemaHash = strings.Repeat("b", 64)
	}
	var upstreamHits, effectivePolicyHits, confirmations int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(upstream.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/internal/system/settings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"security_audit_only": fmt.Sprintf("%v", auditOnly)})
	})
	mux.HandleFunc("/admin/v1/internal/agentguard/effective-policy", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":` + mcpFixAgentGuardData + `}`))
	})
	mux.HandleFunc("/admin/v1/internal/mcp/effective-policy", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&effectivePolicyHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy)
	})
	mux.HandleFunc("/admin/v1/internal/agentguard/confirmations", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&confirmations, 1)
		if confirmStatus == 0 {
			confirmStatus = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(confirmStatus)
		if confirmStatus < 400 {
			_, _ = w.Write([]byte(`{"confirmation_id":"agcf-test","invocation_id":"mcpinv-test","status":"pending","execution_status":"pending","retry_after_ms":10}`))
		}
	})
	mux.HandleFunc("/admin/v1/internal/tools/logs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	controlPlane := httptest.NewServer(mux)
	t.Cleanup(controlPlane.Close)

	client := NewToolRiskClient(controlPlane.URL, "test-secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, SecurityAuditOnly: auditOnly,
	})
	h := NewMCPProxyHandler(nil, client, false)
	useMCPTestUpstream(h, upstream)
	h.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo",
		ServerURL: upstream.URL, Status: "active", AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})

	router := chi.NewRouter()
	router.Route("/mcp", func(r chi.Router) {
		h.Register(r)
	})
	return &mcpFixEnv{
		handler:             h,
		router:              router,
		upstreamHits:        &upstreamHits,
		effectivePolicyHits: &effectivePolicyHits,
		confirmations:       &confirmations,
		upstream:            upstream,
		controlPlane:        controlPlane,
	}
}

// buildMCPBatch 造 n 条 tools/call 消息组成的 JSON-RPC batch。tool 名可全同或递增。
func buildMCPBatch(n int, distinct bool) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := "read_file"
		if distinct {
			name = fmt.Sprintf("tool_%d", i)
		}
		parts = append(parts, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{"i":%d}}}`, i, name, i))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// === 幸存项 1：现代 MCP batch 在决策前拒绝 ===

// 2025-06-18 起 batching 已移除；任何条数都回 -32600，且不查询策略、不触达上游。
func TestMCPAnyModernBatchRejectedBeforePolicyLookup(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)

	body := buildMCPBatch(2, false)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if !strings.Contains(w.Body.String(), `"code":-32600`) {
		t.Fatalf("现代 MCP batch 应回 -32600: status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.effectivePolicyHits) != 0 {
		t.Fatalf("batch 绝不能进入决策循环: hits=%d", atomic.LoadInt32(env.effectivePolicyHits))
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("batch 不许触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

// 单条 JSON-RPC 请求仍正常查询一次策略并转发一次。
func TestMCPSingleMessageProcessed(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("单条请求应正常处理: status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("单条请求应转发上游一次: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
	if atomic.LoadInt32(env.effectivePolicyHits) != 1 {
		t.Fatalf("单条 tools/call 应查询一次策略: hits=%d", atomic.LoadInt32(env.effectivePolicyHits))
	}
}

// === 幸存项 2：转发剥离客户端凭据头 ===

func TestMCPForwardStripsClientCredentialHeaders(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := NewMCPProxyHandler(nil, NewToolRiskClient("http://127.0.0.1:1", "x"), false)
	useMCPTestUpstream(h, upstream)
	server := &mcpServerRoute{ID: "s1", TenantID: "t", Name: "n", ServerURL: upstream.URL, Status: "active", AllowPrivateEgress: true}

	registerStreamableTestSession(t, h, "t", "s1", "sess-1", "\x1f\x1f", "")
	req := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer sk-secret")
	req.Header.Set("X-Api-Key", "k")
	req.Header.Set("Api-Key", "k2")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("Proxy-Authorization", "Basic xyz")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Trailer", "X-Foo")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("Mcp-Session-Id", "sess-1")           // MCP 协议头：应透传
	req.Header.Set("MCP-Protocol-Version", "2025-06-18") // MCP 协议头：应透传

	resp, _, err := h.forwardMCPUpstream(context.Background(), server, req, []byte(`{}`))
	if err != nil {
		t.Fatalf("转发失败: %v", err)
	}
	resp.Body.Close()

	for _, bad := range []string{"Authorization", "X-Api-Key", "Api-Key", "Cookie", "Proxy-Authorization", "Proxy-Connection", "TE", "Trailer", "Upgrade"} {
		if v := got.Get(bad); v != "" {
			t.Fatalf("凭据/hop-by-hop 头 %s 泄漏给上游: %q", bad, v)
		}
	}
	if got.Get("Mcp-Session-Id") != "sess-1" {
		t.Fatalf("MCP 协议头 Mcp-Session-Id 不应被剥离")
	}
	if got.Get("Mcp-Protocol-Version") != "2025-06-18" {
		t.Fatalf("MCP 协议头 MCP-Protocol-Version 不应被剥离")
	}
}

// === 幸存项 5：strict/block 策略受 audit-only 铁律钳制 ===
// （W1 1.5 删除了从未被调用的 mcpFailClosedEffectivePolicy；此处改用显式 strict/block 策略字面量，
// 保留原测试守护的语义：CallerMode=strict 真拦，CallerMode=audit 钳为 audit。）

// TestMCPFailClosedSynthesisRespectsCallerMode：strict/block 策略
// 在 CallerMode=strict 下真拦，在 CallerMode=audit（audit_only=true）下仍被钳为 audit。
func TestMCPFailClosedSynthesisRespectsCallerMode(t *testing.T) {
	fc := &MCPEffectivePolicy{Matched: true, Mode: "strict", Action: "block"}

	enforced := synthesizeMCPDecision(fc, "delete_repo", `{"repo":"demo"}`, agentguard.ModeStrict)
	if enforced.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("fail-closed + audit_only=false 应真拦: effective=%s", enforced.EffectiveDecision)
	}

	clamped := synthesizeMCPDecision(fc, "delete_repo", `{"repo":"demo"}`, agentguard.ModeAudit)
	if clamped.EffectiveDecision != agentguard.DecisionAudit {
		t.Fatalf("fail-closed 也不得破 audit-only 铁律: effective=%s, want audit", clamped.EffectiveDecision)
	}
}

// TestMCPGetEffectivePolicyFailModes：供应链状态不可证明时，无论旧的普通策略 failMode
// 如何配置，都必须形成结构性 block，不能让 open/audit-only 隐藏隔离状态。
func TestMCPGetEffectivePolicyFailModes(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // 立即关闭 → 拉取必然失败（连接被拒）

	env := &modelrouter.RequestEnvelope{TenantID: "tenant_test"}

	// 控制面不可达属于检测异常：无论 MCP_POLICY_FAIL_MODE 如何，一律记录放行，
	// 并以 supply_chain_status=unavailable 留证，不按结构性准入阻断。
	closedClient := NewToolRiskClient(deadURL, "x")
	closedClient.SetMCPPolicyFailMode("closed")
	openClient := NewToolRiskClient(deadURL, "x") // 默认 open
	for name, client := range map[string]*ToolRiskClient{"closed": closedClient, "open": openClient} {
		p := client.GetMCPEffectivePolicy(context.Background(), env, "srv", "tool")
		if p.Mode != "audit" || p.Action != "audit" || p.StructuralBlock || p.SupplyChainStatus != "unavailable" {
			t.Fatalf("%s: 控制面不可达应记录放行: mode=%s action=%s status=%s structural=%v",
				name, p.Mode, p.Action, p.SupplyChainStatus, p.StructuralBlock)
		}
	}
}

// mcpFixAgentGuardData 是 newMCPFixEnv 假控制面返回的 AgentGuard 有效策略 data（JSON）。
var mcpFixAgentGuardData = "null"

// 2.9.22：确认单建不出来按 mcp.confirm_unavailable 处置，默认告警放行：请求转发上游、留证。
func TestMCPConfirmCreationFailureAlertsAndForwardsByDefault(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm"}, http.StatusInternalServerError)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if strings.Contains(w.Body.String(), `"error"`) || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("default must forward with an alert: hits=%d body=%s", atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
}

// === 幸存项 6：confirm 建单失败如实告知 ===

// TestMCPConfirmCreationFailureTruthfulMessage：confirm 命中但 control-plane 建单返回 500 →
// 仍 fail-closed 阻断（不触达上游），但文案如实说"确认单创建失败"，绝不谎报"已创建确认单"。
func TestMCPConfirmCreationFailureTruthfulMessage(t *testing.T) {
	// 2.9.22：确认单建不出来默认告警放行（见 TestMCPConfirmCreationFailureAlertsAndForwardsByDefault）；
	// 这里验证配成阻断（mcp.confirm_unavailable=block）时照拦且文案如实。
	mcpFixAgentGuardData = `{"mode":"audit","protections":{"mcp.confirm_unavailable":{"action":"block"}}}`
	t.Cleanup(func() { mcpFixAgentGuardData = "null" })
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm"}, http.StatusInternalServerError)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	body := w.Body.String()
	if !strings.Contains(body, "确认单创建失败") {
		t.Fatalf("建单失败应如实告知，文案不符: %s", body)
	}
	if strings.Contains(body, "已创建确认单") {
		t.Fatalf("建单失败时绝不能谎报已创建确认单: %s", body)
	}
	if !strings.Contains(body, `"error"`) {
		t.Fatalf("建单失败仍应 fail-closed 阻断（回 JSON-RPC error）: %s", body)
	}
	if atomic.LoadInt32(env.confirmations) != 1 {
		t.Fatalf("应尝试建单一次: %d", atomic.LoadInt32(env.confirmations))
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("confirm 阻断后不许触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

// TestMCPConfirmCreationSuccessMessage：建单成功仍报"已创建确认单"（回归，避免误伤正常路径）。
func TestMCPConfirmCreationSuccessMessage(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm"}, http.StatusOK)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	body := w.Body.String()
	if !strings.Contains(body, "已创建确认单") {
		t.Fatalf("建单成功应报已创建确认单: %s", body)
	}
	if strings.Contains(body, "确认单创建失败") {
		t.Fatalf("建单成功不应出现失败文案: %s", body)
	}
}

// === 幸存项 8a：红线检测对 JSON \u 转义解码扫描 ===

func TestMCPRedlineUnicodeEscapeBypass(t *testing.T) {
	// 用运行时拼接构造 JSON \u 转义，源码里不出现反斜杠（bs 为单个反斜杠字符）。
	bs := string(rune(0x5C))
	// {"cmd":"rm -rf /"} —— r 解码为 'r'，原始串是「rm -rf /」不含字面 "rm"
	rmEscaped := `{"cmd":"` + bs + `u0072m -rf /"}`
	// {"a":{"b":["DROP TABLE users"]}} —— D 解码为 'D'，原始串不含 "DROP"
	dropEscaped := `{"a":{"b":["` + bs + `u0044ROP TABLE users"]}}`

	// 防御：确认原始串确实不含明文关键字（否则测的是原始扫描而非解码扫描）。
	if strings.Contains(rmEscaped, "rm ") || strings.Contains(dropEscaped, "DROP") {
		t.Fatalf("测试构造有误，原始串仍含明文关键字: %q / %q", rmEscaped, dropEscaped)
	}

	cases := []struct {
		name string
		args string
		want []string
	}{
		{"escaped_destructive_command", rmEscaped, []string{"destructive_command"}},
		{"nested_escaped_destructive_sql", dropEscaped, []string{"destructive_command"}},
		{"正常参数不误报", `{"path":"README.md"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchMCPRedlines(tc.args)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("matchMCPRedlines(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestMCPRedlineDecodedNoDoubleReport：保留的红线规则不因解码而重复计入。
func TestMCPRedlineDecodedNoDoubleReport(t *testing.T) {
	got := matchMCPRedlines(`{"url":"http://169.254.169.254/latest/meta-data"}`)
	if fmt.Sprint(got) != fmt.Sprint([]string{"cloud_metadata"}) {
		t.Fatalf("直接命中应恰返回一次 cloud_metadata，got %v", got)
	}
}

// TestMCPRequestEnvelopeUniqueRequestID 回归：每次 mcpRequestEnvelope 必须 mint 唯一
// request_id（不复用 auth 层按天截断的 info.RequestID），否则 request_logs 按 request_id
// upsert 会把同日所有 MCP 请求塌成一行、审计归并错乱（e2e 实测发现）。
func TestMCPRequestEnvelopeUniqueRequestID(t *testing.T) {
	// ensureMCPRequestID 每次都把 info.RequestID mint 成唯一 uuid，覆盖 auth 层按天截断值；
	// envelope 与所有审计留痕随后共用该唯一 id。两次请求必须得到不同 request_id。
	info1 := &auth.AuthInfo{RequestID: "req_20260702", TenantID: "t1", ProjectID: "p1"}
	ensureMCPRequestID(info1)
	e1 := mcpRequestEnvelope(info1)

	info2 := &auth.AuthInfo{RequestID: "req_20260702", TenantID: "t1", ProjectID: "p1"}
	ensureMCPRequestID(info2)
	e2 := mcpRequestEnvelope(info2)

	if e1.RequestID == "" || e2.RequestID == "" {
		t.Fatalf("request_id 不能为空: %q %q", e1.RequestID, e2.RequestID)
	}
	if e1.RequestID == e2.RequestID {
		t.Fatalf("两次请求 request_id 必须不同，得到相同: %s", e1.RequestID)
	}
	if e1.RequestID == "req_20260702" {
		t.Fatalf("不应保留 auth 层按天截断的 info.RequestID: %s", e1.RequestID)
	}
	// envelope 必须与 info（被 mint 后）一致，保证审计链共用同一 id
	if e1.RequestID != info1.RequestID {
		t.Fatalf("envelope request_id 应与 info 统一: envelope=%s info=%s", e1.RequestID, info1.RequestID)
	}
}
