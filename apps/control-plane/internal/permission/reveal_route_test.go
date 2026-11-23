package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// key-reveal：GET /admin/v1/keys/{id}/reveal 必须解析为 api_keys:read（挂受保护 session 组），
// 不得因未注册路由表而 fail-closed 到 platform_admin。同时验证 normalize 不把结尾 reveal 误判成 {id}。
func TestResolveRevealKeyRoute(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/keys/key_abc123/reveal", nil)
	got := Resolve(r)
	if got.Resource != "api_keys" || got.Action != "read" || got.ScopeType != "tenant" {
		t.Fatalf("resolve = {resource:%q action:%q scope:%q}, want api_keys/read/tenant", got.Resource, got.Action, got.ScopeType)
	}
	if got.RequirePlatformAdmin {
		t.Error("reveal 路由应命中路由表，不应 fail-closed 到 platform_admin")
	}
}
