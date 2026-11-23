package permission

import (
	"net/http/httptest"
	"testing"
)

// W8 导出路由必须登记，否则非平台管理员（审计员、租户管理员）全部 403。
func TestWS8ExportRoutesResolveToExportPermissions(t *testing.T) {
	cases := []struct{ path, resource, action string }{
		{"/admin/v1/system/audit-operations/export", "audit_chain", "export"},
		{"/admin/v1/security/block-records/export", "security_events", "export"},
		{"/admin/v1/alerts/inbox/export", "alert_inbox", "read"},
	}
	for _, c := range cases {
		got := Resolve(httptest.NewRequest("GET", c.path, nil))
		if got.RequirePlatformAdmin || got.Resource != c.resource || got.Action != c.action {
			t.Errorf("%s => %+v, want %s:%s", c.path, got, c.resource, c.action)
		}
	}
}
