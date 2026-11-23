package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// 现场 P3-9 的生产接线回归：中间件挂在 chi 的 /v1 子路由上，未命中的 /v1/v1/...
// 仍会先经过它（所以现场看到 401）。这里用真实的 AuthMiddleware 验证：
// 重复前缀返回 404 提示，正常路径的未鉴权行为保持 401。
func TestDuplicateV1PrefixHintReachesClientsThroughRuntimeRoutes(t *testing.T) {
	router := chi.NewRouter()
	// db / redis / 审计客户端均为 nil：只要代码走到密钥查询就会 panic，
	// 因此测试同时证明重复前缀请求没有触发任何后端调用。
	authenticate := auth.NewAuthMiddleware(nil, nil, nil).Middleware(&config.Config{})
	reached := false
	endpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	registerRuntimeRoutes(router, authenticate, nil, endpoint, endpoint, endpoint, endpoint, endpoint, endpoint)
	registerGeminiRuntimeRoutes(router, authenticate, nil, endpoint, endpoint, nil)

	hint := func(method, path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return recorder
	}

	anthropic := hint(http.MethodPost, "/v1/v1/messages")
	if anthropic.Code != http.StatusNotFound || !strings.Contains(anthropic.Body.String(), `"not_found_error"`) ||
		!strings.Contains(anthropic.Body.String(), "ANTHROPIC_BASE_URL") {
		t.Fatalf("/v1/v1/messages status=%d body=%s", anthropic.Code, anthropic.Body.String())
	}
	openai := hint(http.MethodPost, "/v1/v1/chat/completions")
	if openai.Code != http.StatusNotFound || !strings.Contains(openai.Body.String(), "base_url_duplicate_v1_prefix") {
		t.Fatalf("/v1/v1/chat/completions status=%d body=%s", openai.Code, openai.Body.String())
	}
	gemini := hint(http.MethodPost, "/v1/v1beta/models/m:generateContent")
	if gemini.Code != http.StatusNotFound || !strings.Contains(gemini.Body.String(), "NOT_FOUND") {
		t.Fatalf("/v1/v1beta/... status=%d body=%s", gemini.Code, gemini.Body.String())
	}
	if reached {
		t.Fatal("重复前缀的请求不应到达任何业务处理器")
	}

	// 正常路径的未鉴权行为不变：仍是 401，且不带重复前缀提示。
	for _, path := range []string{"/v1/messages", "/v1/chat/completions"} {
		recorder := hint(http.MethodPost, path)
		if recorder.Code != http.StatusUnauthorized || strings.Contains(recorder.Body.String(), "多了一层") {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
}
