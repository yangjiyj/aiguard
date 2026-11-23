package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// TestMiddleware_KeylessRequestRejected 验证「fail-closed 免 Key 收敛」（需求#3 / 设计 §3.D、§4）：
// 无 API Key 的请求即使全局 PROXY_ENABLED=true，也必须被拒绝（401），
// 不得再走「免 Key 模型代理」旁路直达下游 handler。
//
// 范围说明：本测试只针对「无 Key 直调模型」这一与反向代理重复的旁路入口；
// 带合法 API-Key 的反向代理主链路、正向代理出口均不在此范围、保持不变。
func TestMiddleware_KeylessRequestRejected(t *testing.T) {
	// db / redis 传 nil：免 Key 路径在校验 Key 之前即返回，不会触达数据库。
	a := auth.NewAuthMiddleware(nil, nil, nil)
	cfg := &config.Config{ProxyEnabled: true}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := a.Middleware(cfg)(next)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatalf("免 Key 请求绝不能到达下游 handler（无 Key 旁路必须关闭）")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("免 Key 请求必须被拒绝并返回 401，实际得到 %d", rec.Code)
	}
}
