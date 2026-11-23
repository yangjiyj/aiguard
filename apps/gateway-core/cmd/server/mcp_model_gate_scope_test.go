package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
)

// 评估结论（见提交说明）：MCP 数据面不应被「个人模型使用权限」约束。
// 模型使用权限回答的是「这个账号能调用哪些模型」，MCP tools/call 不涉及模型选择；
// 它有自己的六元组策略（租户/server/工具/主体/…）、红线与准入。部门分配模式为 emergency/service 的账号
// ChatAllowed=false，原先会在到达 MCP 策略之前被 forbidden_model 拒绝，MCP 自己的策略反而没机会判定。
// 这是 3277be16c 把 MCP 路由挂到共享的 dataPlaneAuth 链上、而 21b3d0c26 又往该链里加入 userModels 造成的连带。
func TestMCPDataPlaneChainSkipsPersonalModelGateButKeepsAuthAndIntegrationPolicy(t *testing.T) {
	var calls []string
	mk := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	chain := newDataPlaneChains(mk("authentication"), mk("user-model"), mk("integration"))

	proxy := handler.NewMCPProxyHandler(nil, nil, false)
	router := chi.NewRouter()
	registerMCPRoutes(router, chain.mcp, proxy)
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp/server-1", nil))
	if got := calls; len(got) < 2 || got[0] != "authentication" || got[1] != "integration" {
		t.Fatalf("MCP 链应是 认证 → 集成策略，实际 %v", got)
	}
	for _, c := range calls {
		if c == "user-model" {
			t.Fatalf("MCP 不应经过个人模型使用权限门: %v", calls)
		}
	}

	// 模型类数据面（Chat/Responses/Embeddings/Images…）仍然必须带模型门，且顺序不变。
	calls = nil
	r2 := chi.NewRouter()
	r2.Route("/v1", func(r chi.Router) {
		r.Use(chain.model)
		r.Post("/chat/completions", func(http.ResponseWriter, *http.Request) {})
	})
	r2.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	want := []string{"authentication", "user-model", "integration"}
	if len(calls) != 3 || calls[0] != want[0] || calls[1] != want[1] || calls[2] != want[2] {
		t.Fatalf("模型类数据面链必须保持 认证 → 个人模型 → 集成策略: %v", calls)
	}
}
