package handler

import "testing"

// isFullTenantRole 的口径必须与 resolveUsageScope(usage.go) 的 FullTenant 分支一致：
// 只有 platform_admin / tenant_owner / tenant_admin 三档可见整租户；dept_manager 及其它一律不是。
func TestIsFullTenantRole(t *testing.T) {
	full := []string{"platform_admin", "tenant_owner", "tenant_admin"}
	for _, r := range full {
		if !isFullTenantRole(r) {
			t.Errorf("%q 应为整租户档", r)
		}
	}
	notFull := []string{"dept_manager", "team_owner", "team_member", "auditor", "operator", "", "admin"}
	for _, r := range notFull {
		if isFullTenantRole(r) {
			t.Errorf("%q 不应为整租户档（会绕过本部门收窄）", r)
		}
	}
}
