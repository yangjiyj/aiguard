package permission

import "testing"

func TestRawEvidenceClassOnlySystemAdminAndSecurityOfficer(t *testing.T) {
	want := map[string]SoDDecision{
		"platform_admin": SoDAllow, "admin": SoDAllow, "security_officer": SoDAllow,
		"auditor": SoDDeny, "tenant_admin": SoDDeny, "tenant_owner": SoDDeny,
		"developer": SoDDeny, "viewer": SoDDeny, "dept_manager": SoDDeny, "chat_user": SoDDeny,
	}
	for role, decision := range want {
		if got := DecideSoD(role, SoDRawEvidence, false); got != decision {
			t.Errorf("%s: got %v want %v", role, got, decision)
		}
	}
	for _, route := range []string{"GET /admin/v1/audit/raw-evidence", "POST /admin/v1/audit/raw-evidence/{id}/reveal",
		"GET /admin/v1/audit/raw-evidence/settings", "PUT /admin/v1/audit/raw-evidence/settings"} {
		if sodRouteTable[route] != SoDRawEvidence {
			t.Errorf("%s must be class raw_evidence", route)
		}
	}
	// 修改全局开关是写操作（审查 I-4），其余三个是读。
	for route, action := range map[string]string{
		"GET /admin/v1/audit/raw-evidence": "read", "POST /admin/v1/audit/raw-evidence/{id}/reveal": "read",
		"GET /admin/v1/audit/raw-evidence/settings": "read", "PUT /admin/v1/audit/raw-evidence/settings": "write",
	} {
		if got := routeTable[route].Action; got != action {
			t.Errorf("%s action=%q want %q", route, got, action)
		}
	}
}
