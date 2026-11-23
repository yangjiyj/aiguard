package handler

// 复审「权限」项：三员分立模式下 security_officer 按 SoD 对 SecurityWrite/SecurityConfigRead 类路由是 SoDAllow，
// 但 17 个 AgentGuard/MCP/Skill 的 handler 又用 canManageAgentGuard（只认 platform_admin/tenant_owner/tenant_admin/admin）
// 二次拦截，导致安全员管不了红线、白名单模板、MCP 策略、准入等安全设置。而规则、检测器、内容安全、工具风险、回复策略
// 等同类 handler 早已用 roles.CanManageSecurityPolicy（platform_admin + security_officer）。
// 统一：凡 SoD 表定义为 SecurityWrite/SecurityConfigRead 的操作，handler 层都放行 security_officer；
// 同时保持原有放行的角色不变，对 auditor、developer、viewer、dept_manager 等其他角色继续拒绝。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestSecurityOfficerPassesTheAgentGuardAndMCPAdminCheck(t *testing.T) {
	allowed := []string{"platform_admin", "admin", "tenant_owner", "tenant_admin", "security_officer"}
	for _, role := range allowed {
		if !canManageAgentGuard(role) {
			t.Fatalf("%s 必须能管理 AgentGuard/MCP 安全设置", role)
		}
	}
	denied := []string{"auditor", "developer", "viewer", "dept_manager", "chat_user", "operator", "platform_connector", ""}
	for _, role := range denied {
		if canManageAgentGuard(role) {
			t.Fatalf("%s 不应通过 canManageAgentGuard", role)
		}
	}
}

// 一致性：SoD 对 security_officer 放行的 SecurityWrite 操作，其 handler 层的角色判断不得比 SoD 更严。
func TestHandlerRoleCheckIsNotStricterThanSoDForSecurityOfficer(t *testing.T) {
	for _, class := range []permission.SoDClass{permission.SoDSecurityWrite, permission.SoDSecurityConfigRead} {
		if permission.DecideSoD("security_officer", class, false) != permission.SoDAllow {
			t.Fatalf("前提：SoD 应放行 security_officer 的 %s", class)
		}
	}
	if !canManageAgentGuard("security_officer") {
		t.Fatalf("SoD 放行但 handler 拒绝：安全员会在 SoD 通过后被 handler 二次拦截")
	}
	// 审计员边界不变：SoD 与 handler 双重拒绝
	if permission.DecideSoD("auditor", permission.SoDSecurityWrite, false) != permission.SoDDeny || canManageAgentGuard("auditor") {
		t.Fatalf("auditor 不得获得安全写权限")
	}
}

type officerFakeRedlineStore struct{ upserts int }

func (f *officerFakeRedlineStore) List(context.Context, string) ([]repository.MCPRedlineSetting, error) {
	return nil, nil
}
func (f *officerFakeRedlineStore) Actions(context.Context, string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (f *officerFakeRedlineStore) Upsert(_ context.Context, _, _ string, a map[string]string) (map[string]string, error) {
	f.upserts++
	return a, nil
}

// 真实 handler：安全员写红线设置成功，审计员/开发者被 403。
func TestSecurityOfficerCanWriteRedlineSettingsAndOthersCannot(t *testing.T) {
	for role, want := range map[string]int{
		"security_officer": http.StatusOK, "platform_admin": http.StatusOK, "tenant_admin": http.StatusOK,
		"auditor": http.StatusForbidden, "developer": http.StatusForbidden, "viewer": http.StatusForbidden, "dept_manager": http.StatusForbidden,
	} {
		store := &officerFakeRedlineStore{}
		req := ws1RedlineRequest(http.MethodPut, "/admin/v1/mcp-redline-settings", "tenant-a", role,
			map[string]any{"actions": map[string]string{"cloud_metadata": "block"}})
		w := httptest.NewRecorder()
		UpdateMCPRedlineSettings(&Dependencies{}, store)(w, req)
		if w.Code != want {
			t.Fatalf("%s 写红线设置：期望 %d，实际 %d %s", role, want, w.Code, w.Body.String())
		}
		if (want == http.StatusOK) != (store.upserts == 1) {
			t.Fatalf("%s：写入次数 %d 与结果 %d 不一致", role, store.upserts, w.Code)
		}
	}
}

// 管理员判断是对所有同类 handler 共用的：用 helper 直接覆盖准入、白名单模板、Skill 准入、AgentGuard 的入口检查。
func TestSecurityOfficerPassesSharedAdminHelpers(t *testing.T) {
	user := func(role string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		ctx := context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "tenant-a", Role: role})
		return r.WithContext(ctx)
	}
	for role, want := range map[string]bool{"security_officer": true, "tenant_admin": true, "auditor": false, "developer": false} {
		w := httptest.NewRecorder()
		got := mcpAdmissionAdmin(w, user(role)) != nil
		if got != want {
			t.Fatalf("%s mcpAdmissionAdmin = %v want %v", role, got, want)
		}
		w = httptest.NewRecorder()
		got = skillAdmin(user(role), w) != nil
		if got != want {
			t.Fatalf("%s skillAdmin = %v want %v", role, got, want)
		}
	}
}
