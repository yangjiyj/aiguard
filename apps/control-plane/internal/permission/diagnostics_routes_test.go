package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 运维诊断机器人的 8 个路由：
//   - 发起 / 查看 / 追问 / 列表 / 读设置 / 红点：SoDCommon + diagnostics:read，员工角色都能用；
//   - 诊断包导出、改设置：SoDSystem + diagnostics:write，只有管理员角色持有。

var diagnosticsCommonRoutes = []struct{ method, path string }{
	{"POST", "/admin/v1/diagnostics/sessions"},
	{"GET", "/admin/v1/diagnostics/sessions"},
	{"GET", "/admin/v1/diagnostics/sessions/{id}"},
	{"POST", "/admin/v1/diagnostics/sessions/{id}/messages"},
	{"GET", "/admin/v1/diagnostics/settings"},
	{"GET", "/admin/v1/diagnostics/badge"},
}

var diagnosticsAdminRoutes = []struct{ method, path string }{
	{"GET", "/admin/v1/diagnostics/sessions/{id}/bundle"},
	{"PUT", "/admin/v1/diagnostics/settings"},
}

// 员工角色：控制台里没有管理职责、只应使用诊断助手查自己的问题。
var diagnosticsEmployeeRoles = []string{"developer", "viewer", "dept_manager", "team_member", "team_owner", "project_owner", "project_developer", "project_viewer"}

func roleHasPermission(role, resource, action string) bool {
	for _, p := range permissionMatrix[role] {
		if r, a, ok := splitResourceAction(p); ok && r == resource && a == action {
			return true
		}
	}
	return false
}

func TestDiagnosticsRoutesAreRegisteredWithExpectedClassAndPermission(t *testing.T) {
	for _, c := range diagnosticsCommonRoutes {
		key := c.method + " " + c.path
		if got := sodRouteTable[key]; got != SoDCommon {
			t.Errorf("%s: SoD 类别=%q，want common", key, got)
		}
		if p, ok := routeTable[key]; !ok || p.Resource != "diagnostics" || p.Action != "read" || p.ScopeType != "tenant" {
			t.Errorf("%s: RBAC=%+v(登记=%v)，want diagnostics:read/tenant", key, p, ok)
		}
	}
	for _, c := range diagnosticsAdminRoutes {
		key := c.method + " " + c.path
		if got := sodRouteTable[key]; got != SoDSystem {
			t.Errorf("%s: SoD 类别=%q，want system", key, got)
		}
		if p, ok := routeTable[key]; !ok || p.Resource != "diagnostics" || p.Action != "write" || p.ScopeType != "tenant" {
			t.Errorf("%s: RBAC=%+v(登记=%v)，want diagnostics:write/tenant", key, p, ok)
		}
	}
}

// 真实请求路径（带具体会话 ID）也必须解析到登记的权限，而不是落到“未登记路径只允许平台管理员”。
func TestDiagnosticsConcretePathsResolveToRegisteredPermissions(t *testing.T) {
	cases := []struct {
		method, path, resource, action string
	}{
		{"POST", "/admin/v1/diagnostics/sessions", "diagnostics", "read"},
		{"GET", "/admin/v1/diagnostics/sessions/dgs_0123456789abcdef01234567", "diagnostics", "read"},
		{"POST", "/admin/v1/diagnostics/sessions/dgs_0123456789abcdef01234567/messages", "diagnostics", "read"},
		{"GET", "/admin/v1/diagnostics/sessions/dgs_0123456789abcdef01234567/bundle", "diagnostics", "write"},
		{"PUT", "/admin/v1/diagnostics/settings", "diagnostics", "write"},
		{"GET", "/admin/v1/diagnostics/badge", "diagnostics", "read"},
	}
	for _, c := range cases {
		got := Resolve(httptest.NewRequest(c.method, c.path, nil))
		if got.RequirePlatformAdmin || got.Resource != c.resource || got.Action != c.action || got.ScopeType != "tenant" {
			t.Errorf("%s %s => %+v，want %s:%s", c.method, c.path, got, c.resource, c.action)
		}
	}
}

// 员工能走完 SoDCommon 的诊断接口：SoD 闸门不拒绝，RBAC 矩阵里有 diagnostics:read。
func TestEmployeeRolesCanReachCommonDiagnosticsRoutes(t *testing.T) {
	for _, role := range diagnosticsEmployeeRoles {
		if !roleHasPermission(role, "diagnostics", "read") {
			t.Errorf("%s 缺少 diagnostics:read，enforce 模式下员工用不了诊断助手", role)
		}
		for _, c := range diagnosticsCommonRoutes {
			class := SoDClassFor(c.method, c.path)
			if got := DecideSoD(role, class, false); got == SoDDeny {
				t.Errorf("%s %s %s 被 SoD 闸门拒绝", role, c.method, c.path)
			}
		}
	}
}

// 员工不能导出诊断包、不能改设置：RBAC 矩阵里没有 diagnostics:write。
func TestEmployeeRolesCannotReachBundleOrSettingsWrite(t *testing.T) {
	for _, role := range diagnosticsEmployeeRoles {
		if roleHasPermission(role, "diagnostics", "write") {
			t.Errorf("%s 不应持有 diagnostics:write", role)
		}
	}
	// 同时直接走 HTTP：SoD 闸门之后由 RBAC 决定；这里验证 SoD 对管理员路由不放行三员中的安全员和审计员。
	for _, c := range diagnosticsAdminRoutes {
		class := SoDClassFor(c.method, c.path)
		for _, role := range []string{"security_officer", "auditor"} {
			if got := DecideSoD(role, class, false); got != SoDDeny {
				t.Errorf("%s %s %s 对 %s 应被 SoD 拒绝，实际 %v", c.method, c.path, role, role, got)
			}
		}
		if got := DecideSoD("platform_admin", class, false); got != SoDDefer {
			t.Errorf("%s %s 对 platform_admin 应交给 RBAC，实际 %v", c.method, c.path, got)
		}
	}
}

// 管理员角色持有读写两项；安全员、审计员只有读（诊断助手对所有登录角色可见，但不能改设置）。
func TestAdminRolesHoldDiagnosticsReadAndWrite(t *testing.T) {
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		for _, action := range []string{"read", "write"} {
			if !roleHasPermission(role, "diagnostics", action) {
				t.Errorf("%s 应持有 diagnostics:%s", role, action)
			}
		}
	}
	for _, role := range []string{"security_officer", "auditor"} {
		if !roleHasPermission(role, "diagnostics", "read") {
			t.Errorf("%s 应持有 diagnostics:read", role)
		}
		if roleHasPermission(role, "diagnostics", "write") {
			t.Errorf("%s 不应持有 diagnostics:write", role)
		}
	}
}

// 通过 SoD 闸门的真实 HTTP 行为：三员中的安全员与审计员能用公共接口，改设置被拒。
func TestDiagnosticsRoutesThroughSoDGuardHTTP(t *testing.T) {
	cases := []struct {
		role, method, path string
		code               int
	}{
		{"auditor", "GET", "/admin/v1/diagnostics/badge", http.StatusOK},
		{"security_officer", "POST", "/admin/v1/diagnostics/sessions", http.StatusOK},
		{"developer", "GET", "/admin/v1/diagnostics/settings", http.StatusOK},
		{"auditor", "PUT", "/admin/v1/diagnostics/settings", http.StatusForbidden},
		{"security_officer", "GET", "/admin/v1/diagnostics/sessions/s1/bundle", http.StatusForbidden},
		{"platform_admin", "GET", "/admin/v1/diagnostics/sessions/s1/bundle", http.StatusOK},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		diagnosticsSoDRouter(c.role).ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.code {
			t.Errorf("%s %s %s: code %d want %d", c.role, c.method, c.path, rec.Code, c.code)
		}
	}
}

// diagnosticsSoDRouter 挂上 SoDGuard 与 8 条诊断路由（handler 为空桩），用于验证闸门的真实 HTTP 行为。
func diagnosticsSoDRouter(role string) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				u := &repository.User{ID: "u1", TenantID: "t1", Role: role}
				next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), auth.UserKey, u)))
			})
		})
		r.Use(SoDGuard(nil))
		ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
		r.Post("/admin/v1/diagnostics/sessions", ok)
		r.Get("/admin/v1/diagnostics/sessions", ok)
		r.Get("/admin/v1/diagnostics/sessions/{id}", ok)
		r.Post("/admin/v1/diagnostics/sessions/{id}/messages", ok)
		r.Get("/admin/v1/diagnostics/sessions/{id}/bundle", ok)
		r.Get("/admin/v1/diagnostics/settings", ok)
		r.Put("/admin/v1/diagnostics/settings", ok)
		r.Get("/admin/v1/diagnostics/badge", ok)
	})
	return r
}
