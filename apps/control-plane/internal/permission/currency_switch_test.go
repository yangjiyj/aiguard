package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCurrencySwitchRouteRegistration(t *testing.T) {
	const key = "POST /admin/v1/billing/currency-switch"
	if sodRouteTable[key] != SoDSystem {
		t.Fatalf("币种切换必须登记系统配置职责：%v", sodRouteTable[key])
	}
	p := Resolve(httptest.NewRequest(http.MethodPost, "/admin/v1/billing/currency-switch?tenant_id=t", nil))
	if p.Resource != "billing_currency" || p.Action != "write" {
		t.Fatalf("权限登记错误：%+v", p)
	}
}

// 币种切换会把全部钱包按原数字改标并作废其他币种价格，影响面等同资金调账：
// 只有 platform_admin 持有 billing_currency:write，与 billingAdmin 保持一致。
func TestCurrencySwitchBuiltinRoleGrants(t *testing.T) {
	has := func(role string) bool {
		for _, grant := range permissionMatrix[role] {
			if grant == "billing_currency:write" {
				return true
			}
		}
		return false
	}
	if !has("platform_admin") {
		t.Error("platform_admin 缺少币种切换授权")
	}
	for _, role := range []string{"admin", "tenant_owner", "tenant_admin", "developer", "auditor", "security_officer", "platform_connector", "team_owner", "dept_manager"} {
		if has(role) {
			t.Errorf("%s 不应获得币种切换授权", role)
		}
	}
	// 除 platform_admin 外，任何内置角色都不能持有该授权。
	for role := range permissionMatrix {
		if role != "platform_admin" && has(role) {
			t.Errorf("内置角色 %s 不应持有 billing_currency:write", role)
		}
	}
}

func TestEmployeeBillingSettingsDedicatedReadPermission(t *testing.T) {
	p := Resolve(httptest.NewRequest(http.MethodGet, "/admin/v1/billing/employee-settings?tenant_id=t", nil))
	if p.Resource != "billing_settings" || p.Action != "read" || p.ScopeType != "tenant" {
		t.Fatalf("系统币种读取权限错误：%+v", p)
	}
	for _, role := range []string{"platform_admin", "admin", "tenant_owner", "tenant_admin"} {
		found := false
		for _, grant := range permissionMatrix[role] {
			if grant == "billing_settings:read" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s 缺少设置读取授权", role)
		}
	}
	for _, role := range []string{"developer", "auditor", "security_officer", "platform_connector"} {
		for _, grant := range permissionMatrix[role] {
			if grant == "billing_settings:read" {
				t.Errorf("%s 不应获得设置读取授权", role)
			}
		}
	}
}
