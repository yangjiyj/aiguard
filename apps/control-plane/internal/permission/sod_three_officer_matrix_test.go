package permission

// SoD 项：放开三员的控制台登录，不能扩大任何数据访问面。登录只回答「能不能进来」；进来后能做什么，仍由
// SoD 守卫（本包）与 RBAC 中间件决定。这里把「安全员能读写 MCP 策略与红线、不能管用户、不能看审计与导出；
// 审计员只读审计、不能改任何策略」按矩阵钉死，并确认 SoDGuard 在 HTTP 层真的执行。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// sodRouterFromTable 按真实的 sodRouteTable 注册全部受保护路由（处理器恒返回 200），再套 SoDGuard：
// 测的是生产里的路由→类别映射本身，而不是手写的几条路由。
func sodRouterFromTable(role string) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				u := &repository.User{ID: "u1", Role: role}
				next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), auth.UserKey, u)))
			})
		})
		r.Use(SoDGuard(nil))
		ok := func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) }
		for key := range sodRouteTable {
			parts := strings.SplitN(key, " ", 2)
			r.MethodFunc(parts[0], parts[1], ok)
		}
	})
	return r
}

func TestThreeOfficerAccessMatrixAfterConsoleLoginIsOpened(t *testing.T) {
	type c struct {
		role, method, path string
		code               int
	}
	cases := []c{
		// 安全员：安全策略、MCP、红线、告警——放行
		{"security_officer", "GET", "/admin/v1/mcp-policies", 200},
		{"security_officer", "POST", "/admin/v1/mcp-policies", 200},
		{"security_officer", "PUT", "/admin/v1/mcp-policies/p1", 200},
		{"security_officer", "DELETE", "/admin/v1/mcp-policies/p1", 200},
		{"security_officer", "GET", "/admin/v1/mcp-redline-settings", 200},
		{"security_officer", "PUT", "/admin/v1/mcp-redline-settings", 200},
		{"security_officer", "POST", "/admin/v1/mcp-servers/s1/allowlist-template", 200},
		{"security_officer", "POST", "/admin/v1/mcp-servers/s1/admission", 200},
		{"security_officer", "GET", "/admin/v1/mcp-servers", 200},
		{"security_officer", "POST", "/admin/v1/agentguard/policies", 200},
		{"security_officer", "GET", "/admin/v1/security/alert-occurrences", 200},
		{"security_officer", "GET", "/admin/v1/protection-settings", 200},
		{"security_officer", "PUT", "/admin/v1/protection-settings", 200},
		// 安全员：用户、系统配置、审计、导出、登录历史、密钥、解锁、重置 TOTP——拒绝
		{"security_officer", "GET", "/admin/v1/users", 403},
		{"security_officer", "POST", "/admin/v1/users", 403},
		{"security_officer", "PUT", "/admin/v1/system/settings", 403},
		{"security_officer", "GET", "/admin/v1/system/audit-operations", 403},
		{"security_officer", "GET", "/admin/v1/mcp-audit/export", 403}, // 审计导出（SoDAuditExport）只归审计员
		{"security_officer", "GET", "/admin/v1/audit/login-history", 403},
		{"security_officer", "DELETE", "/admin/v1/keys/k1", 403},
		{"security_officer", "POST", "/admin/v1/users/u1/unlock-login", 403},
		{"security_officer", "POST", "/admin/v1/users/u1/reset-totp", 403},
		// 审计员：只读审计——放行；任何策略写入、用户、系统——拒绝
		{"auditor", "GET", "/admin/v1/system/audit-operations", 200},
		{"auditor", "GET", "/admin/v1/audit/login-history", 200},
		{"auditor", "GET", "/admin/v1/security/alert-occurrences", 200},
		{"auditor", "GET", "/admin/v1/mcp-audit/export", 200}, // 审计员可导出审计数据
		{"auditor", "POST", "/admin/v1/mcp-policies", 403},
		{"auditor", "PUT", "/admin/v1/mcp-policies/p1", 403},
		{"auditor", "DELETE", "/admin/v1/mcp-policies/p1", 403},
		{"auditor", "PUT", "/admin/v1/mcp-redline-settings", 403},
		// 防护项设置属于安全配置：SoD 表里 GET 是 SoDSecurityConfigRead，审计员不在放行名单，读写都拒绝
		{"auditor", "GET", "/admin/v1/protection-settings", 403},
		{"auditor", "PUT", "/admin/v1/protection-settings", 403},
		{"auditor", "POST", "/admin/v1/mcp-servers/s1/allowlist-template", 403},
		{"auditor", "POST", "/admin/v1/mcp-servers/s1/admission", 403},
		{"auditor", "POST", "/admin/v1/agentguard/policies", 403},
		{"auditor", "GET", "/admin/v1/users", 403},
		{"auditor", "PUT", "/admin/v1/system/settings", 403},
		{"auditor", "DELETE", "/admin/v1/keys/k1", 403},
		{"auditor", "POST", "/admin/v1/users/u1/unlock-login", 403},
		{"auditor", "POST", "/admin/v1/users/u1/reset-totp", 403},
	}
	r := func(role string) http.Handler { return sodRouterFromTable(role) }
	for _, k := range cases {
		rec := httptest.NewRecorder()
		r(k.role).ServeHTTP(rec, httptest.NewRequest(k.method, k.path, nil))
		if rec.Code != k.code {
			t.Errorf("%s %s %s: code %d want %d", k.role, k.method, k.path, rec.Code, k.code)
		}
	}
}
