package handler

// SECURITY_AUDIT_ONLY 回归：
// audit-only 下任何 MCP 决策——都只审计、绝不阻断：
// RawDecision=block ，EffectiveDecision 必须被钳为 audit，
// 不断流、不建确认单。audit_only=false + strict 才允许真拦截。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// === 决策合成层：铁律语义 ===

func TestMCPAuditOnlyPolicyBlockClampedToAudit(t *testing.T) {
	policy := &MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_t1", Mode: "strict", Action: "block"}
	decision := synthesizeMCPDecision(policy, "delete_repo", `{"repo":"demo"}`, agentguard.ModeAudit)

	if decision.RawDecision != agentguard.DecisionBlock {
		t.Fatalf("raw decision = %s, want block（原始结论必须如实留证）", decision.RawDecision)
	}
	if decision.EffectiveDecision != agentguard.DecisionAudit {
		t.Fatalf("effective decision = %s, want audit（audit-only 钳制铁律）", decision.EffectiveDecision)
	}
	if decision.EffectiveReason != "would-block" {
		t.Fatalf("effective reason = %s, want would-block", decision.EffectiveReason)
	}
}

func TestMCPStrictPolicyBlockEnforced(t *testing.T) {
	policy := &MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_t2", Mode: "strict", Action: "block"}
	decision := synthesizeMCPDecision(policy, "delete_repo", `{}`, agentguard.ModeStrict)

	if decision.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("effective decision = %s, want block（audit_only=false + strict 必须真拦）", decision.EffectiveDecision)
	}
}

func TestMCPPolicyModeAuditKeepsBlockObserved(t *testing.T) {
	// 策略自身 mode=audit（observe-first 上线姿态）：即便网关 strict，
	// clampModeToCeiling 取更宽松者 → 只审计。
	policy := &MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_t3", Mode: "audit", Action: "block"}
	decision := synthesizeMCPDecision(policy, "delete_repo", `{}`, agentguard.ModeStrict)

	if decision.EffectiveDecision != agentguard.DecisionAudit {
		t.Fatalf("policy mode=audit 时 effective = %s, want audit", decision.EffectiveDecision)
	}
	if decision.RawDecision != agentguard.DecisionBlock {
		t.Fatalf("raw = %s, want block", decision.RawDecision)
	}
}

// === JSON-RPC 解析 ===

func TestMCPJSONRPCParseSingle(t *testing.T) {
	msgs, batch, err := parseMCPRPCMessages([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`))
	if err != nil {
		t.Fatalf("单条解析失败: %v", err)
	}
	if batch {
		t.Fatalf("单条不应识别为 batch")
	}
	if len(msgs) != 1 || msgs[0].Method != "tools/call" || msgs[0].Params.Name != "read_file" {
		t.Fatalf("解析结果不符: %+v", msgs)
	}
	if !strings.Contains(string(msgs[0].Params.Arguments), "/etc/hosts") {
		t.Fatalf("arguments 未保留原文: %s", msgs[0].Params.Arguments)
	}
}

func TestMCPJSONRPCParseBatchRejected(t *testing.T) {
	body := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_data","arguments":{"data":"x"}}}
	]`
	msgs, batch, err := parseMCPRPCMessages([]byte(body))
	if !errors.Is(err, errMCPBatchUnsupported) {
		t.Fatalf("现代 MCP batch 应明确拒绝: %v", err)
	}
	if !batch || len(msgs) != 0 {
		t.Fatalf("batch 拒绝结果不符: batch=%v len=%d", batch, len(msgs))
	}
}

func TestMCPJSONRPCParseInvalid(t *testing.T) {
	for _, body := range []string{"", "   ", "not-json", `"just a string"`, `[]`, `[{"method":`} {
		if _, _, err := parseMCPRPCMessages([]byte(body)); err == nil {
			t.Fatalf("非法载荷 %q 应解析失败", body)
		}
	}
}

// === 红线正则（表驱动）===

func TestMCPRedlinePatterns(t *testing.T) {
	cases := []struct {
		name string
		args string
		want []string
	}{
		{"云元数据 AWS", `{"url":"http://169.254.169.254/latest/meta-data/iam"}`, []string{"cloud_metadata"}},
		{"云元数据 GCP", `{"url":"http://metadata.google.internal/computeMetadata/v1/"}`, []string{"cloud_metadata"}},
		{"私钥外传", `{"data":"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`, []string{"private_key_egress"}},
		{"正常参数", `{"path":"README.md","query":"select 1"}`, nil},
		{"空参数", ``, nil},
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

// === Handler 全链：不断流 / 不建单 / 真拦 ===

type mcpTestEnv struct {
	handler             *MCPProxyHandler
	router              *chi.Mux
	upstreamHits        *int32
	upstreamRequestBody *string
	confirmations       *int32
	confirmPayloads     *[]map[string]any
	toolLogs            *[]map[string]any
	agentGuardStatus    *int
	agentGuardBody      *string
	agentGuardFetches   *int32
	upstreamBody        *string
	upstreamStatus      *int
	upstreamContentType *string
	upstream            *httptest.Server
	controlPlane        *httptest.Server
}

func useMCPTestUpstream(h *MCPProxyHandler, upstream *httptest.Server) {
	h.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
		target, err := url.Parse(rawURL)
		if err != nil {
			return nil, nil, err
		}
		upstreamURL, err := url.Parse(upstream.URL)
		if err != nil || target.Host != upstreamURL.Host {
			return nil, nil, fmt.Errorf("unexpected MCP test target")
		}
		return upstream.Client(), target, nil
	}
}

// newMCPTestEnv 起一个假 control-plane（settings/effective-policy/confirmations/tools-logs）
// 和一个假 MCP 上游，装配无 DB 的 MCPProxyHandler（server 路由直接预热进缓存）。
func newMCPTestEnv(t *testing.T, auditOnly bool, policy MCPEffectivePolicy) *mcpTestEnv {
	t.Helper()
	if policy.SupplyChainStatus == "" {
		policy.SupplyChainStatus = "approved"
		policy.ServerAdmissionStatus = "approved"
		policy.ToolAdmissionStatus = "approved"
		policy.SupplyChainRevision = "revision-test"
		if policy.ToolID == "" {
			policy.ToolID = "tool-test"
		}
		policy.RouteHash = strings.Repeat("a", 64)
		policy.ApprovedRouteHash = policy.RouteHash
		policy.ApprovedSchemaHash = strings.Repeat("b", 64)
	}
	var upstreamHits, confirmations int32
	var upstreamRequestBody string
	var confirmPayloads []map[string]any
	var toolLogs []map[string]any
	agentGuardStatus := http.StatusOK
	agentGuardBody := `{"data":null}`
	var agentGuardFetches int32
	upstreamBody := `{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}]}}`
	upstreamStatus := http.StatusOK
	upstreamContentType := "application/json"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		requestBody, _ := io.ReadAll(r.Body)
		upstreamRequestBody = string(requestBody)
		w.Header().Set("Content-Type", upstreamContentType)
		w.WriteHeader(upstreamStatus)
		_, _ = w.Write([]byte(upstreamBody))
	}))
	t.Cleanup(upstream.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/internal/system/settings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"security_audit_only": fmt.Sprintf("%v", auditOnly)})
	})
	mux.HandleFunc("/admin/v1/internal/mcp/effective-policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 夹具策略是工具类（target_kind=tool）；与真实解析器同口径，非工具目标不命中它（W1 1.2）。
		if kind := r.URL.Query().Get("target_kind"); kind != "" && kind != "tool" {
			_ = json.NewEncoder(w).Encode(MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit", SupplyChainStatus: "not_applicable",
				RouteHash: policy.RouteHash, ApprovedRouteHash: policy.ApprovedRouteHash})
			return
		}
		_ = json.NewEncoder(w).Encode(policy)
	})
	mux.HandleFunc("/admin/v1/internal/agentguard/effective-policy", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&agentGuardFetches, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(agentGuardStatus)
		_, _ = w.Write([]byte(agentGuardBody))
	})
	mux.HandleFunc("/admin/v1/internal/agentguard/confirmations", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&confirmations, 1)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode confirmation payload: %v", err)
		}
		confirmPayloads = append(confirmPayloads, payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"confirmation_id":"agcf-test","invocation_id":"mcpinv-test","status":"pending","execution_status":"pending","retry_after_ms":10}`))
	})
	mux.HandleFunc("/admin/v1/internal/tools/logs", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode tool lifecycle audit: %v", err)
		}
		toolLogs = append(toolLogs, payload)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": fmt.Sprintf("tool-log-%d", len(toolLogs))})
	})
	controlPlane := httptest.NewServer(mux)
	t.Cleanup(controlPlane.Close)

	client := NewToolRiskClient(controlPlane.URL, "test-secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, SecurityAuditOnly: auditOnly,
	})
	h := NewMCPProxyHandler(nil, client, false)
	useMCPTestUpstream(h, upstream)
	// 预热 server 路由缓存（db=nil 时 lookupServer 只走缓存）。上游是 127.0.0.1
	// 的 httptest server，走 allow_private_egress=true 受控放行路径（顺带覆盖该分支）。
	h.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo",
		ServerURL: upstream.URL, Status: "active", AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})

	router := chi.NewRouter()
	router.Route("/mcp", func(r chi.Router) {
		h.Register(r)
	})
	return &mcpTestEnv{
		handler:             h,
		router:              router,
		upstreamHits:        &upstreamHits,
		upstreamRequestBody: &upstreamRequestBody,
		confirmations:       &confirmations,
		confirmPayloads:     &confirmPayloads,
		toolLogs:            &toolLogs,
		agentGuardStatus:    &agentGuardStatus,
		agentGuardBody:      &agentGuardBody,
		agentGuardFetches:   &agentGuardFetches,
		upstreamBody:        &upstreamBody,
		upstreamStatus:      &upstreamStatus,
		upstreamContentType: &upstreamContentType,
		upstream:            upstream,
		controlPlane:        controlPlane,
	}
}

func newMCPTestRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/mcp/mcp_srv1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := req.Context()
	ctx = context.WithValue(ctx, auth.TenantKey, "tenant_test")
	ctx = context.WithValue(ctx, auth.ProjectKey, "project_test")
	ctx = context.WithValue(ctx, auth.UserKey, "user_test")
	ctx = context.WithValue(ctx, auth.RequestIDKey, "req_mcp_test")
	ctx = context.WithValue(ctx, auth.KeyPrefixKey, "sk-"+"test")
	return req.WithContext(ctx)
}
func setMCPDestructivePolicy(env *mcpTestEnv, mode agentguard.Mode, action agentguard.DestructiveAction, sessionIDs ...string) {
	setMCPDestructivePolicyWithProtections(env, mode, action, nil, sessionIDs...)
}

func setMCPDestructivePolicyWithProtections(env *mcpTestEnv, mode agentguard.Mode, action agentguard.DestructiveAction, settings protection.Settings, sessionIDs ...string) {
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant_test", ProjectID: "project_test", UserID: "user_test", KeyPrefix: "sk-test", EndpointType: "proxy",
	}
	if len(sessionIDs) > 0 {
		envelope.SessionID = sessionIDs[0]
	}
	policy := &agentguard.EffectivePolicy{
		ID: "destructive-policy", Mode: mode, ConfirmChannelEnabled: true,
		Destructive:  &agentguard.DestructivePolicy{Mode: mode, Action: action, ScopeType: "tenant", Protocol: "mcp"},
		ConfigSource: agentguard.ConfigSourceTenantPolicy,
	}
	if settings != nil {
		// 与现网下发一致：防护项按全局执行模式执行（convertAgentGuardPolicy 总把 RuleMode 置为 strict）。
		policy.RuleMode, policy.Protections = agentguard.ModeStrict, settings
	}
	env.handler.toolRiskClient.agentGuardPolicyCache.set(agentGuardPolicyScopeCacheKey(envelope), policy)
}

const mcpToolsCallBody = `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_repo","arguments":{"repo":"demo"}}}`

// TestMCPAuditOnlyBlockDoesNotBreakStream：audit_only=true + 策略 strict/block →
// 请求照常转发上游、响应原样直回、不建确认单（铁律核心回归）。
func TestMCPAuditOnlyBlockDoesNotBreakStream(t *testing.T) {
	env := newMCPTestEnv(t, true, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_block", ToolID: "mcpt-delete", Mode: "strict", Action: "block"})

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	if w.Code != http.StatusOK {
		t.Fatalf("audit-only 下不许断流: status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("audit-only 下必须照常转发上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
	if !strings.Contains(w.Body.String(), `"result"`) || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("audit-only 下响应应为上游原文: %s", w.Body.String())
	}
	if atomic.LoadInt32(env.confirmations) != 0 {
		t.Fatalf("audit-only 下不许建确认单: %d", atomic.LoadInt32(env.confirmations))
	}
	if len(*env.toolLogs) != 2 {
		t.Fatalf("expected intent and execution lifecycle audits, got %#v", *env.toolLogs)
	}
	log := mcpAuditLogByEventType(t, *env.toolLogs, "number:9", "tool_execution_risk")
	if log["event_kind"] != "execution_forwarded" || log["execution_forwarded"] != true || log["execution_observed"] != true || log["result_observed"] != true || log["status"] != "success" || log["mcp_tool_id"] != "mcpt-delete" {
		t.Fatalf("actual MCP forward facts = %#v", log)
	}
}

// TestMCPAuditOnlyHighRiskDoesNotBreakStream：audit_only=true 下高风险命中
// 也只留痕，不断流、不建单。
func TestMCPAuditOnlyHighRiskDoesNotBreakStream(t *testing.T) {
	env := newMCPTestEnv(t, true, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /"}}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("audit-only 下高风险也不许真拦: status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("audit-only 下高风险命中必须照常转发: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
	if atomic.LoadInt32(env.confirmations) != 0 {
		t.Fatalf("audit-only 下高风险命中不建确认单: %d", atomic.LoadInt32(env.confirmations))
	}
}

// TestMCPStrictBlockRejectsRequest：audit_only=false + strict/block → 真拦：
// 回 JSON-RPC error(-32000, 中文带策略 id)，上游零调用。
func TestMCPStrictBlockRejectsRequest(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_block", Mode: "strict", Action: "block"})

	w := httptest.NewRecorder()
	request := newMCPTestRequest(mcpToolsCallBody)
	request = request.WithContext(context.WithValue(request.Context(), auth.TraceIDKey, "trace-mcp-base-block"))
	env.router.ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Fatalf("JSON-RPC error 应走 HTTP 200: %d", w.Code)
	}
	var resp struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	if resp.Error.Code != -32000 {
		t.Fatalf("error code = %d, want -32000", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "网关安全策略") || !strings.Contains(resp.Error.Message, "mcppol_block") {
		t.Fatalf("阻断文案应为中文并带策略 id: %s", resp.Error.Message)
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("strict block 下不许触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
	// 2.9.22 复审：delete_repo 是删除与破坏调用，MCP 策略的阻断胜出时 FinalAction 跟着是阻断，
	// 按删除与破坏记两条（意图 + 被拦），与卡片自己阻断时一致（原断言只有一条通用生命周期日志）。
	if len(*env.toolLogs) != 2 || (*env.toolLogs)[0]["event_type"] != "tool_destructive_intent" ||
		(*env.toolLogs)[0]["final_action"] != "block" || (*env.toolLogs)[1]["event_type"] != "tool_attempt_blocked" ||
		(*env.toolLogs)[1]["status"] != "blocked" {
		t.Fatalf("expected the destructive intent and the blocked attempt, got %#v", *env.toolLogs)
	}
	for _, log := range *env.toolLogs {
		if log["event_kind"] != "invocation_proposed" || log["execution_observed"] != false || log["result_observed"] != false {
			t.Fatalf("blocked MCP call must not claim execution: %#v", log)
		}
		requestID, _ := log["request_id"].(string)
		wantOperationID := operationID(destructiveOperationIdentity{
			TenantID: "tenant_test", Protocol: "mcp", RequestID: requestID, OutputItemID: "mcp:mcp_srv1",
			ToolCallID: "number:9", ToolName: "delete_repo", CanonicalArgs: `{"repo":"demo"}`,
		})
		if requestID == "" || log["operation_id"] != wantOperationID || log["trace_id"] != "trace-mcp-base-block" || wantOperationID == "trace-mcp-base-block" {
			t.Fatalf("blocked MCP correlation mismatch: log=%#v want_operation=%q", log, wantOperationID)
		}
	}
}

func TestMCPTransportErrorDoesNotClaimExecution(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow"})
	// Close the listener while preserving the registered URL. The gateway enters
	// client.Do and receives a transport error without any upstream response proof.
	env.upstream.Close()

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("transport error status=%d body=%s", w.Code, w.Body.String())
	}
	if len(*env.toolLogs) != 1 {
		t.Fatalf("expected one failed lifecycle audit, got %#v", *env.toolLogs)
	}
	log := (*env.toolLogs)[0]
	if log["event_kind"] != "invocation_proposed" || log["execution_forwarded"] != false || log["execution_observed"] != false || log["result_observed"] != false || log["status"] != "failed" {
		t.Fatalf("transport error must not claim upstream execution: %#v", log)
	}
}

// 现代 batch 在策略判定前即按协议错误拒绝。
func TestMCPStrictBatchRejectedBeforeToolPolicy(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_block", Mode: "strict", Action: "block"})

	body := `[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},` + mcpToolsCallBody + `]`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if !strings.Contains(w.Body.String(), `"code":-32600`) {
		t.Fatalf("现代 batch 未按协议拒绝: %s", w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("batch 拦截后不许触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

// TestMCPStrictConfirmCreatesConfirmation：strict/confirm → 建确认单 + 本次拒绝。
func TestMCPStrictConfirmCreatesConfirmation(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm"})

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	if !strings.Contains(w.Body.String(), "人工确认") {
		t.Fatalf("confirm 拒绝文案不符: %s", w.Body.String())
	}
	if atomic.LoadInt32(env.confirmations) != 1 {
		t.Fatalf("strict confirm 应建 1 张确认单: %d", atomic.LoadInt32(env.confirmations))
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("confirm 拒绝后不许触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

func TestMCPStrictConfirmUsesTypedJSONRPCID(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantCallID string
	}{
		{name: "number", body: mcpToolsCallBody, wantCallID: "number:9"},
		{name: "string", body: strings.Replace(mcpToolsCallBody, `"id":9`, `"id":"9"`, 1), wantCallID: "string:9"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_confirm", Mode: "strict", Action: "confirm"})
			w := httptest.NewRecorder()

			env.router.ServeHTTP(w, newMCPTestRequest(test.body))

			if len(*env.confirmPayloads) != 1 {
				t.Fatalf("confirmation payloads=%#v", *env.confirmPayloads)
			}
			if got := (*env.confirmPayloads)[0]["tool_call_id"]; got != test.wantCallID {
				t.Fatalf("tool_call_id=%#v, want %q", got, test.wantCallID)
			}
		})
	}
}

// TestMCPNonToolsCallPassthrough：非 tools/call 方法（initialize/tools/list）透传不拦。
func TestMCPNonToolsCallPassthrough(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_block", Mode: "strict", Action: "block"})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("非 tools/call 不应被拦: status=%d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("非 tools/call 应转发上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

// TestMCPDisabledServerRejected：server 非在用态（disabled）一律拒绝转发。
func TestMCPDisabledServerRejected(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	env.handler.serverCache.set("tenant_test\x1fmcp_srv2", &mcpServerRoute{
		ID: "mcp_srv2", TenantID: "tenant_test", Name: "off",
		ServerURL: env.upstream.URL, Status: "disabled", AllowPrivateEgress: true,
	})

	req := newMCPTestRequest(mcpToolsCallBody)
	req.URL.Path = "/mcp/mcp_srv2"
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("disabled server 应 403: %d %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("disabled server 不许触达上游: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}

// TestMCPUnknownServerNotFound：不存在（或跨租户）的 serverID → 404，租户硬隔离兜底。
func TestMCPUnknownServerNotFound(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})

	req := newMCPTestRequest(mcpToolsCallBody)
	req.URL.Path = "/mcp/mcp_other_tenant"
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("未知 server 应 404: %d %s", w.Code, w.Body.String())
	}
}

// Global audit-only (观察留痕) is the ceiling for destructive policies too: the
// console reports every behaviour as "仅记录" while it is on.
func TestMCPDestructivePolicyBlockIsRecordedUnderGlobalAuditOnly(t *testing.T) {
	env := newMCPTestEnv(t, true, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeLight, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("audit-only must forward the recorded call, upstream hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
	if atomic.LoadInt32(env.confirmations) != 0 {
		t.Fatalf("audit-only created %d confirmation tickets", atomic.LoadInt32(env.confirmations))
	}
}

func TestMCPDestructivePolicyBlockStopsCallUnderProtect(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeLight, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("destructive block reached upstream %d times", atomic.LoadInt32(env.upstreamHits))
	}
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("missing JSON-RPC safety error: %s", w.Body.String())
	}
}

// 2.9.22 批次 2B：参数解析失败是兜底防护项 agent.parse_rejected，不再随删除与破坏卡片处置。
// 原用例锁的是“卡片仅记录时转发并记破坏性兜底审计”，改为“默认告警放行时转发，审计里带解析失败
// 的命中，不再记成破坏性意图”。
func TestMCPParseRejectedArgumentsRecordPolicyForwardsWithFailSafeAudit(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"run_shell","arguments":["rm -rf /srv/isolated-fixture"]}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("default agent.parse_rejected should forward parse-rejected arguments once: status=%d upstream=%d body=%s", w.Code, atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
	if *env.upstreamRequestBody != body {
		t.Fatalf("forwarded body changed\nwant=%s\n got=%s", body, *env.upstreamRequestBody)
	}
	if atomic.LoadInt32(env.confirmations) != 0 {
		t.Fatalf("alert-and-allow created %d confirmation tickets", atomic.LoadInt32(env.confirmations))
	}
	requireMCPLogMentions(t, *env.toolLogs, "number:42", destructiveParseRejectedFailSafeReason)
	for _, log := range *env.toolLogs {
		if log["tool_call_id"] == "number:42" && log["event_type"] == "tool_destructive_intent" {
			t.Fatalf("a parse rejection is no longer a destructive intent: %#v", log)
		}
	}
}

// 2.9.22 批次 2B：原用例靠删除与破坏卡片的阻断拦下解析失败的参数，改为 agent.parse_rejected 配成阻断时照拦。
func TestMCPParseRejectedArgumentsBlockPolicyNeverReachesUpstream(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicyWithProtections(env, agentguard.ModeAudit, agentguard.DestructiveActionRecord,
		protection.Settings{"agent.parse_rejected": {Action: protection.ActionBlock}})
	body := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"run_shell","arguments":["rm -rf /srv/isolated-fixture"]}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("block policy forwarded parse-rejected arguments %d times", atomic.LoadInt32(env.upstreamHits))
	}
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("missing JSON-RPC safety error: %s", w.Body.String())
	}
	requireMCPLogMentions(t, *env.toolLogs, "number:42", destructiveParseRejectedFailSafeReason)
}

func requireMCPLogMentions(t *testing.T, logs []map[string]any, id, text string) {
	t.Helper()
	for _, log := range logs {
		if log["tool_call_id"] != id {
			continue
		}
		if encoded, _ := json.Marshal(log); strings.Contains(string(encoded), text) {
			return
		}
	}
	t.Fatalf("no MCP audit for call id %q mentions %q: %#v", id, text, logs)
}

func TestMCPDestructiveAlertAllowForwardsOriginalBodyExactlyOnce(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionAlertAllow)
	body := `{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture","note":" keep spacing "}}}`

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))

	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("alert_allow status=%d upstream=%d body=%s", w.Code, atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
	if *env.upstreamRequestBody != body {
		t.Fatalf("forwarded body changed\nwant=%s\n got=%s", body, *env.upstreamRequestBody)
	}
	if atomic.LoadInt32(env.confirmations) != 0 {
		t.Fatalf("alert_allow created %d confirmation tickets", atomic.LoadInt32(env.confirmations))
	}
}

func TestMCPDestructiveConfirmUsesExistingTicketWithoutImmediateForward(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{
		Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow",
	})
	setMCPDestructivePolicy(env, agentguard.ModeLight, agentguard.DestructiveActionConfirm)
	body := `{"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`

	w := httptest.NewRecorder()
	request := newMCPTestRequest(body)
	request = request.WithContext(context.WithValue(request.Context(), auth.TraceIDKey, "trace-mcp-independent"))
	env.router.ServeHTTP(w, request)

	if atomic.LoadInt32(env.confirmations) != 1 {
		t.Fatalf("destructive confirm created %d tickets, want 1", atomic.LoadInt32(env.confirmations))
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("destructive confirm forwarded before approval %d times", atomic.LoadInt32(env.upstreamHits))
	}
	if !strings.Contains(w.Body.String(), `"confirmation_id":"agcf-test"`) {
		t.Fatalf("missing existing confirmation ticket: %s", w.Body.String())
	}
	if len(*env.confirmPayloads) != 1 || len(*env.toolLogs) != 1 {
		t.Fatalf("confirmation payloads=%v tool logs=%v", *env.confirmPayloads, *env.toolLogs)
	}
	replay, _ := (*env.confirmPayloads)[0]["mcp_replay_context"].(map[string]interface{})
	replayOperationID, _ := replay["operation_id"].(string)
	logOperationID, _ := (*env.toolLogs)[0]["operation_id"].(string)
	if replayOperationID == "" || replayOperationID != logOperationID {
		t.Fatalf("first intent and replay operation mismatch: replay=%v log=%v", replay, (*env.toolLogs)[0])
	}
	if replay["trace_id"] != "trace-mcp-independent" || (*env.toolLogs)[0]["trace_id"] != "trace-mcp-independent" {
		t.Fatalf("trace id was replaced by operation id: replay=%v log=%v", replay, (*env.toolLogs)[0])
	}
	if replayOperationID == "trace-mcp-independent" {
		t.Fatalf("operation id must remain independent from trace id: %v", replay)
	}
}

func TestMCPAgentGuardPolicyRefreshUsesStaleSnapshotAndRecovers(t *testing.T) {
	var failureLog bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&failureLog)
	defer log.SetOutput(previousLogOutput)

	policy := MCPEffectivePolicy{Matched: true, PolicyID: "mcp-allow", Mode: "strict", Action: "allow"}
	env := newMCPTestEnv(t, false, policy)
	env.handler.toolRiskClient.agentGuardPolicyCache.ttl = 10 * time.Millisecond
	var staleFailureSignals atomic.Int32
	env.handler.toolRiskClient.agentGuardPolicyFailureHook = func(_ context.Context, _ *modelrouter.RequestEnvelope, _ error, staleAvailable bool) {
		if staleAvailable {
			staleFailureSignals.Add(1)
		}
	}
	*env.agentGuardBody = `{"data":{"id":"destructive-block","policy_version":"v1","mode":"strict","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"strict","action":"block","scope_type":"tenant"}}}`
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`

	first := httptest.NewRecorder()
	env.router.ServeHTTP(first, newMCPTestRequest(body))
	if atomic.LoadInt32(env.upstreamHits) != 0 || atomic.LoadInt32(env.agentGuardFetches) != 1 {
		t.Fatalf("initial block was not enforced: upstream=%d fetches=%d body=%s", atomic.LoadInt32(env.upstreamHits), atomic.LoadInt32(env.agentGuardFetches), first.Body.String())
	}

	time.Sleep(15 * time.Millisecond)
	*env.agentGuardStatus = http.StatusInternalServerError
	*env.agentGuardBody = `{"error":"temporary"}`
	stale := httptest.NewRecorder()
	env.router.ServeHTTP(stale, newMCPTestRequest(body))
	if atomic.LoadInt32(env.upstreamHits) != 0 || atomic.LoadInt32(env.agentGuardFetches) != 2 {
		t.Fatalf("refresh failure did not enforce stale block: upstream=%d fetches=%d body=%s", atomic.LoadInt32(env.upstreamHits), atomic.LoadInt32(env.agentGuardFetches), stale.Body.String())
	}
	if staleFailureSignals.Load() != 1 || !strings.Contains(failureLog.String(), "AgentGuard policy refresh failed") {
		t.Fatalf("missing refresh failure signal: %s", failureLog.String())
	}

	noSnapshot := newMCPTestEnv(t, false, policy)
	var noSnapshotFailureSignals atomic.Int32
	noSnapshot.handler.toolRiskClient.agentGuardPolicyFailureHook = func(_ context.Context, _ *modelrouter.RequestEnvelope, _ error, staleAvailable bool) {
		if !staleAvailable {
			noSnapshotFailureSignals.Add(1)
		}
	}
	*noSnapshot.agentGuardStatus = http.StatusInternalServerError
	*noSnapshot.agentGuardBody = `{"error":"temporary"}`
	allowed := httptest.NewRecorder()
	noSnapshot.router.ServeHTTP(allowed, newMCPTestRequest(body))
	if atomic.LoadInt32(noSnapshot.upstreamHits) != 1 || atomic.LoadInt32(noSnapshot.agentGuardFetches) != 1 || noSnapshotFailureSignals.Load() != 1 {
		t.Fatalf("no-snapshot failure must keep system record behavior: upstream=%d fetches=%d body=%s", atomic.LoadInt32(noSnapshot.upstreamHits), atomic.LoadInt32(noSnapshot.agentGuardFetches), allowed.Body.String())
	}

	*env.agentGuardStatus = http.StatusOK
	*env.agentGuardBody = `{"data":{"id":"destructive-alert","policy_version":"v2","mode":"light","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"alert_allow","scope_type":"tenant"}}}`
	recovered := httptest.NewRecorder()
	env.router.ServeHTTP(recovered, newMCPTestRequest(body))
	if atomic.LoadInt32(env.upstreamHits) != 1 || atomic.LoadInt32(env.agentGuardFetches) != 3 {
		t.Fatalf("recovered alert policy must forward once: upstream=%d fetches=%d body=%s", atomic.LoadInt32(env.upstreamHits), atomic.LoadInt32(env.agentGuardFetches), recovered.Body.String())
	}
	if *env.upstreamRequestBody != body {
		t.Fatalf("recovered request body changed: got=%s want=%s", *env.upstreamRequestBody, body)
	}
}
