package permission

import "testing"

// 消息中心折叠视图与管理员批量已读的路由登记：
//   - 折叠列表/折叠明细是读接口，与现有消息中心列表同口径（所有登录角色，含安全员与审计员）；
//   - 类别汇总 / 批量已读预览 / 批量已读是管理员专用：SoD 归系统类，安全员与审计员在闸门处就被拒绝，
//     handler 里再用 roles.IsConsoleAdministrator 兜一层。
func TestInboxFoldRoutesAreRegisteredWithExpectedClassesAndPermissions(t *testing.T) {
	cases := []struct {
		route    string
		class    SoDClass
		resource string
		action   string
	}{
		{"GET /admin/v1/alerts/inbox/folded", SoDCommon, "alert_inbox", "read"},
		{"GET /admin/v1/alerts/inbox/folded/items", SoDCommon, "alert_inbox", "read"},
		{"GET /admin/v1/alerts/inbox/type-summary", SoDSystem, "alert_inbox", "read"},
		{"GET /admin/v1/alerts/inbox/bulk-read/preview", SoDSystem, "alert_inbox", "read"},
		{"POST /admin/v1/alerts/inbox/bulk-read", SoDSystem, "alert_inbox", "write"},
	}
	for _, c := range cases {
		got, ok := sodRouteTable[c.route]
		if !ok || got != c.class {
			t.Errorf("%s: SoD 类别=%q(登记=%v)，want %q", c.route, got, ok, c.class)
		}
		perm, ok := routeTable[c.route]
		if !ok || perm.Resource != c.resource || perm.Action != c.action || perm.ScopeType != "tenant" {
			t.Errorf("%s: RBAC=%+v(登记=%v)，want %s:%s/tenant", c.route, perm, ok, c.resource, c.action)
		}
	}
}

func TestBulkReadRoutesAreDeniedToSecurityOfficerAndAuditorAtTheSoDGate(t *testing.T) {
	adminOnly := []struct{ method, path string }{
		{"GET", "/admin/v1/alerts/inbox/type-summary"},
		{"GET", "/admin/v1/alerts/inbox/bulk-read/preview"},
		{"POST", "/admin/v1/alerts/inbox/bulk-read"},
	}
	for _, r := range adminOnly {
		class := SoDClassFor(r.method, r.path)
		for _, role := range []string{"security_officer", "auditor"} {
			if got := DecideSoD(role, class, false); got != SoDDeny {
				t.Errorf("%s %s 对 %s 应在 SoD 闸门被拒绝，实际 %v", r.method, r.path, role, got)
			}
		}
		if got := DecideSoD("platform_admin", class, false); got != SoDDefer {
			t.Errorf("%s %s 对 platform_admin 应交给后续权限判定，实际 %v", r.method, r.path, got)
		}
	}
	for _, path := range []string{"/admin/v1/alerts/inbox/folded", "/admin/v1/alerts/inbox/folded/items"} {
		class := SoDClassFor("GET", path)
		for _, role := range []string{"security_officer", "auditor"} {
			if got := DecideSoD(role, class, false); got != SoDAllow {
				t.Errorf("GET %s 对 %s 应放行（与现有消息中心列表一致），实际 %v", path, role, got)
			}
		}
	}
}
