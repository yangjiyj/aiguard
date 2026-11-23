package handler

// W1 测试夹具：假 control-plane 按 tool_name 返回策略，假上游记录收到的原始请求体。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

type ws1Env struct {
	// agentGuardData 是假控制面返回的 AgentGuard 有效策略 data（JSON），空为 null；
	// 用来给 MCP 防护项配动作。
	agentGuardData string
	handler        *MCPProxyHandler
	router         *chi.Mux
	upstreamHits   *int32
	policyFetches  *int32
	mu             sync.Mutex
	upstreamBodies []string
	policyTargets  []string
	toolLogs       []map[string]any
	upstreamBody   string
	upstreamCT     string
	policyStatus   int
	controlPlane   *httptest.Server
	upstream       *httptest.Server
}

func (e *ws1Env) bodies() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.upstreamBodies...)
}

func (e *ws1Env) targets() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.policyTargets...)
}

func (e *ws1Env) logs() []map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]map[string]any(nil), e.toolLogs...)
}

func ws1ApprovedPolicy(p MCPEffectivePolicy) MCPEffectivePolicy {
	if p.SupplyChainStatus == "" {
		p.SupplyChainStatus = "approved"
		p.ServerAdmissionStatus = "approved"
		p.ToolAdmissionStatus = "approved"
		p.SupplyChainRevision = "revision-test"
		if p.ToolID == "" {
			p.ToolID = "tool-test"
		}
		p.RouteHash = strings.Repeat("a", 64)
		p.ApprovedRouteHash = p.RouteHash
		p.ApprovedSchemaHash = strings.Repeat("b", 64)
	}
	return p
}

// newWS1Env：policyFn 按 control-plane 收到的 tool_name（及 target_kind）给出策略。
func newWS1Env(t *testing.T, auditOnly bool, policyFn func(toolName, kind string) MCPEffectivePolicy) *ws1Env {
	t.Helper()
	env := &ws1Env{upstreamHits: new(int32), policyFetches: new(int32), policyStatus: http.StatusOK,
		upstreamBody: `{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}]}}`,
		upstreamCT:   "application/json"}
	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(env.upstreamHits, 1)
		raw, _ := io.ReadAll(r.Body)
		env.mu.Lock()
		env.upstreamBodies = append(env.upstreamBodies, string(raw))
		body, ct := env.upstreamBody, env.upstreamCT
		env.mu.Unlock()
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(env.upstream.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/internal/system/settings", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"security_audit_only": fmt.Sprintf("%v", auditOnly)})
	})
	mux.HandleFunc("/admin/v1/internal/mcp/effective-policy", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(env.policyFetches, 1)
		name, kind := r.URL.Query().Get("tool_name"), r.URL.Query().Get("target_kind")
		env.mu.Lock()
		env.policyTargets = append(env.policyTargets, kind+"|"+name)
		status := env.policyStatus
		env.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(ws1ApprovedPolicy(policyFn(name, kind)))
	})
	mux.HandleFunc("/admin/v1/internal/agentguard/effective-policy", func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		data := env.agentGuardData
		env.mu.Unlock()
		if data == "" {
			data = "null"
		}
		_, _ = w.Write([]byte(`{"data":` + data + `}`))
	})
	mux.HandleFunc("/admin/v1/internal/agentguard/confirmations", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"confirmation_id":"agcf-test","invocation_id":"mcpinv-test","status":"pending","execution_status":"pending","retry_after_ms":10}`))
	})
	mux.HandleFunc("/admin/v1/internal/tools/logs", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		env.mu.Lock()
		env.toolLogs = append(env.toolLogs, payload)
		n := len(env.toolLogs)
		env.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"id": fmt.Sprintf("tool-log-%d", n)})
	})
	env.controlPlane = httptest.NewServer(mux)
	t.Cleanup(env.controlPlane.Close)

	client := NewToolRiskClient(env.controlPlane.URL, "test-secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: auditOnly})
	env.handler = NewMCPProxyHandler(nil, client, false)
	useMCPTestUpstream(env.handler, env.upstream)
	env.handler.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo",
		ServerURL: env.upstream.URL, Status: "active", AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})
	env.router = chi.NewRouter()
	env.router.Route("/mcp", func(r chi.Router) { env.handler.Register(r) })
	return env
}

func (e *ws1Env) post(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, newMCPTestRequest(body))
	return w
}

// blockTool 只对指定工具名返回 strict/block，其余 allow。
func blockTool(blocked string) func(string, string) MCPEffectivePolicy {
	return func(name, kind string) MCPEffectivePolicy {
		if name == blocked {
			return MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_block_" + blocked, Mode: "strict", Action: "block"}
		}
		return MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}
	}
}

func rpcErrorCode(t *testing.T, body string) int {
	t.Helper()
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil || resp.Error == nil {
		return 0
	}
	return resp.Error.Code
}

// ws1SetAgentGuardPolicy 缓存一条租户 AgentGuard 策略（含 2.9.22 防护项配置）。
func ws1SetAgentGuardPolicy(env *ws1Env, policy *agentguard.EffectivePolicy) {
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant_test", ProjectID: "project_test", UserID: "user_test", KeyPrefix: "sk-test", EndpointType: "proxy"}
	env.handler.toolRiskClient.agentGuardPolicyCache.set(agentGuardPolicyScopeCacheKey(envelope), policy)
}

// blockingProtections 把给定分组里允许阻断的防护项全部配成阻断：2.9.22 起这些不再是
// 内置底线，用例要“照拦”必须显式配置。
func blockingProtections(groups ...protection.Group) protection.Settings {
	settings := protection.Settings{}
	for _, item := range protection.All() {
		for _, group := range groups {
			if item.Group == group && item.Allows(protection.ActionBlock) {
				settings[item.Key] = protection.Setting{Action: protection.ActionBlock}
			}
		}
	}
	return settings
}
