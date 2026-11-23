package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// decodeErrorCode 解析统一错误响应体，取出 error.code，供角色白名单校验断言使用。
func decodeErrorCode(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("解析错误响应失败: %v; body=%s", err, body)
	}
	return parsed.Error.Code
}

func platformAdminContext(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "admin-1",
		TenantID: "tenant-1",
		Role:     "platform_admin",
		Status:   "active",
	}))
}

// M3：创建用户默认角色应为仅 Chat 的 chat_user，而非旧的非法值 operator。
func TestCreateUserDefaultsToChatUser(t *testing.T) {
	events := []string{}
	provisioner := &handlerLocalIdentityProvisioner{events: &events}
	deps := &Dependencies{
		LocalIdentityProvisioner: provisioner,
		LocalIdentityClient:      &handlerLocalIdentityClient{events: &events, createOut: "subject-1"},
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
		}},
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/users",
		strings.NewReader(`{"username":"u","password":"secret123","department_id":"dept-1"}`))
	req = platformAdminContext(req)
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if provisioner.provisioned.Role == "" {
		t.Fatalf("用户未被创建")
	}
	if provisioner.provisioned.Role != "chat_user" {
		t.Fatalf("默认角色 = %q, want chat_user", provisioner.provisioned.Role)
	}
}

// M3：显式传入的合法平台角色应原样落库。
func TestCreateUserAcceptsWhitelistedRoles(t *testing.T) {
	for _, role := range []string{"platform_admin", "tenant_admin", "dept_manager", "developer", "viewer", "chat_user"} {
		t.Run(role, func(t *testing.T) {
			events := []string{}
			provisioner := &handlerLocalIdentityProvisioner{events: &events}
			deps := &Dependencies{
				LocalIdentityProvisioner: provisioner,
				LocalIdentityClient:      &handlerLocalIdentityClient{events: &events, createOut: "subject-1"},
				DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
					"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
				}},
			}

			req := httptest.NewRequest(http.MethodPost, "/admin/v1/users",
				strings.NewReader(`{"username":"u","password":"secret123","role":"`+role+`","department_id":"dept-1"}`))
			req = platformAdminContext(req)
			w := httptest.NewRecorder()

			CreateUser(deps).ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			if provisioner.provisioned.Role != role {
				t.Fatalf("落库角色 = %v, want %q", provisioner.provisioned.Role, role)
			}
		})
	}
}

// M3：非法角色（含旧值 operator/admin 及任意串）必须 400 invalid_role，且不落库。
func TestCreateUserRejectsInvalidRole(t *testing.T) {
	// W4: auditor is a real platform role again, so it is no longer rejected here.
	for _, role := range []string{"operator", "admin", "root", "superuser"} {
		t.Run(role, func(t *testing.T) {
			store := &licenseUserStore{users: map[string]*repository.User{}}
			deps := &Dependencies{UserStore: store}

			req := httptest.NewRequest(http.MethodPost, "/admin/v1/users",
				strings.NewReader(`{"username":"u","password":"secret123","role":"`+role+`"}`))
			req = platformAdminContext(req)
			w := httptest.NewRecorder()

			CreateUser(deps).ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if code := decodeErrorCode(t, w.Body.String()); code != "invalid_role" {
				t.Fatalf("error.code = %q, want invalid_role", code)
			}
			if store.created != nil {
				t.Fatalf("非法角色不应落库, got %+v", store.created)
			}
		})
	}
}

// M3：更新用户传非法角色必须 400 invalid_role，且不触发落库。
func TestUpdateUserRejectsInvalidRole(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: "developer", Status: "active"},
	}}
	deps := &Dependencies{UserStore: store}

	req := httptest.NewRequest(http.MethodPut, "/admin/v1/users/u1",
		strings.NewReader(`{"role":"operator"}`))
	req = platformAdminContext(req)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "u1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	UpdateUser(deps).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if code := decodeErrorCode(t, w.Body.String()); code != "invalid_role" {
		t.Fatalf("error.code = %q, want invalid_role", code)
	}
	if store.updated != nil {
		t.Fatalf("非法角色不应触发落库, got %+v", store.updated)
	}
}

// M3：更新用户传合法角色应成功落库。
// C1 后：developer -> viewer 走 tenantRoleTransition 路径，由 BindingService
// 在事务内更新 users.role，因此断言改为验证 TransitionTenantRole 被调用
// 且传入角色正确（service 层 PG 测试 TestTransitionTenantRoleSyncsGrantsAuditOutbox
// 已覆盖真实落库）。
func TestUpdateUserAcceptsWhitelistedRole(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: "developer", Status: "active"},
	}}
	binding := &fakeIdentityBindingServiceForRoleTransition{}
	deps := &Dependencies{UserStore: store, IdentityBindingService: binding}

	req := httptest.NewRequest(http.MethodPut, "/admin/v1/users/u1",
		strings.NewReader(`{"role":"viewer"}`))
	req = platformAdminContext(req)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "u1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	UpdateUser(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !binding.tenantRoleCalled {
		t.Fatalf("TransitionTenantRole 未被调用")
	}
	if binding.tenantRoleRole != "viewer" {
		t.Fatalf("落库角色 = %q, want viewer", binding.tenantRoleRole)
	}
}

// M3 关键铁律：只校验写入，不影响读取既有非法数据。
// 既有用户 role=operator（历史遗留），更新时不带 role（只改其他字段）必须放行，且角色保持不变。
func TestUpdateUserDoesNotRejectExistingLegacyRoleWhenRoleUnchanged(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: "operator", Status: "active"},
	}}
	deps := &Dependencies{UserStore: store}

	req := httptest.NewRequest(http.MethodPut, "/admin/v1/users/u1",
		strings.NewReader(`{"phone":"13800000000"}`))
	req = platformAdminContext(req)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "u1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	UpdateUser(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if store.updated == nil || store.updated.Role != "operator" {
		t.Fatalf("既有非法角色不应被改动, got %v", store.updated)
	}
}

// decodeErrorMessage 解析统一错误响应体，取出 error.message。
func decodeErrorMessage(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("解析错误响应失败: %v; body=%s", err, body)
	}
	return parsed.Error.Message
}

// M9：非法角色文案不能是乱码（UTF-8 字节被破坏成 ASCII ? 序列）。
// 必须是合法中文，且明确列出五个合法角色名。
func TestCreateUserInvalidRoleMessageIsNotMojibake(t *testing.T) {
	for _, role := range []string{"operator", "superuser"} {
		t.Run(role, func(t *testing.T) {
			deps := &Dependencies{UserStore: &licenseUserStore{users: map[string]*repository.User{}}}
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/users",
				strings.NewReader(`{"username":"u","password":"secret123","role":"`+role+`"}`))
			req = platformAdminContext(req)
			w := httptest.NewRecorder()
			CreateUser(deps).ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			msg := decodeErrorMessage(t, w.Body.String())
			// 乱码特征：连续的 ? 序列（中文字节被破坏）
			if strings.Contains(msg, "????") {
				t.Fatalf("非法角色文案是乱码: %q", msg)
			}
			// 文案必须提到五个合法角色
			for _, want := range []string{"platform_admin", "tenant_admin", "dept_manager", "developer", "viewer", "chat_user"} {
				if !strings.Contains(msg, want) {
					t.Fatalf("非法角色文案缺失 %q: %q", want, msg)
				}
			}
		})
	}
}
