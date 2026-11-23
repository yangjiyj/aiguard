package handler

// W1 1.12：参数条件策略（arg_chain）在网关按 tools/call arguments 求值。
// 控制面下发「不看参数的胜出者 + 排在它前面的带条件策略」，参数不出网关。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
)

// ws1ArgChainEnv 在 newWS1Env 之上替换生效策略端点：返回 winner + arg_chain；其余路径转发给原假控制面。
func ws1ArgChainEnv(t *testing.T, winner MCPEffectivePolicy, chain []map[string]any, status *atomic.Int32) *ws1Env {
	t.Helper()
	env := newWS1Env(t, false, allowAll)
	target, _ := url.Parse(env.controlPlane.URL)
	fallback := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/mcp/effective-policy" {
			fallback.ServeHTTP(w, r)
			return
		}
		if status != nil && status.Load() != http.StatusOK {
			w.WriteHeader(int(status.Load()))
			return
		}
		raw, _ := json.Marshal(ws1ApprovedPolicy(winner))
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if len(chain) > 0 {
			body["arg_chain"] = chain
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	client := NewToolRiskClient(srv.URL, "test-secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: false})
	env.handler.toolRiskClient = client
	return env
}

func ws1WriteCall(args string) string {
	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fs_write","arguments":` + args + `}}`
}

func ws1ExpectBlocked(t *testing.T, env *ws1Env, args string, blocked bool) {
	t.Helper()
	before := atomic.LoadInt32(env.upstreamHits)
	w := env.post(t, ws1WriteCall(args))
	forwarded := atomic.LoadInt32(env.upstreamHits) > before
	if blocked && (forwarded || rpcErrorCode(t, w.Body.String()) != -32000) {
		t.Fatalf("args %s must be blocked: forwarded=%v body=%s", args, forwarded, w.Body.String())
	}
	if !blocked && (!forwarded || rpcErrorCode(t, w.Body.String()) != 0) {
		t.Fatalf("args %s must be forwarded: forwarded=%v body=%s", args, forwarded, w.Body.String())
	}
}

var ws1BlockEtcChain = []map[string]any{{
	"policy_id": "mcppol_block_etc", "mode": "strict", "action": "block", "scope_type": "user", "priority": 0,
	"arg_conditions": []map[string]any{{"path": "$.path", "op": "prefix", "value": "/etc/"}},
}}

func TestWS1ArgChainBlockOnlyWhenArgumentsMatch(t *testing.T) {
	env := ws1ArgChainEnv(t, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow"}, ws1BlockEtcChain, nil)
	ws1ExpectBlocked(t, env, `{"path":"/etc/cron.d/x","content":"y"}`, true)
	ws1ExpectBlocked(t, env, `{"path":"/tmp/x","content":"y"}`, false)
	ws1ExpectBlocked(t, env, `{"content":"no path"}`, false)
}

func TestWS1ArgChainAllowNeedsEveryValue(t *testing.T) {
	// 胜出者 block；allow 例外要求数组里每个路径都在 /tmp/ 下——混入一个诱饵值不能放行。
	chain := []map[string]any{{
		"policy_id": "mcppol_allow_tmp", "mode": "strict", "action": "allow", "scope_type": "user", "priority": 0,
		"arg_conditions": []map[string]any{{"path": "$.paths[*]", "op": "prefix", "value": "/tmp/"}},
	}}
	env := ws1ArgChainEnv(t, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_block", Mode: "strict", Action: "block"}, chain, nil)
	ws1ExpectBlocked(t, env, `{"paths":["/tmp/a","/tmp/b"]}`, false)
	ws1ExpectBlocked(t, env, `{"paths":["/tmp/a","/etc/passwd"]}`, true)
	ws1ExpectBlocked(t, env, `{"paths":[]}`, true)
}

func TestWS1ArgChainSurvivesControlPlaneOutage(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	env := ws1ArgChainEnv(t, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow"}, ws1BlockEtcChain, &status)
	ws1ExpectBlocked(t, env, `{"path":"/etc/a"}`, true)
	status.Store(http.StatusBadGateway)
	// D1：拉不到时沿用最近一次成功的策略，包括其参数条件。
	ws1ExpectBlocked(t, env, `{"path":"/etc/b"}`, true)
	ws1ExpectBlocked(t, env, `{"path":"/tmp/b"}`, false)
}
