package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakePermissionAuthorizerForRoleTransition 记录 InvalidateUserCache 调用，
// 供 C1 非应急角色变化路径断言缓存失效。
type fakePermissionAuthorizerForRoleTransition struct {
	invalidated []string
}

func (f *fakePermissionAuthorizerForRoleTransition) HasPermission(context.Context, string, string, string, string, string, string) (bool, error) {
	return false, nil
}

func (f *fakePermissionAuthorizerForRoleTransition) InvalidateUserCache(userID string) {
	f.invalidated = append(f.invalidated, userID)
}

// fakeIdentityBindingServiceForRoleTransition 同时满足 IdentityBindingService
// 接口与 tenantRoleTransitioner 类型断言，供 handler 测试断言
// viewer -> tenant_admin 时调用 TransitionTenantRole。
type fakeIdentityBindingServiceForRoleTransition struct {
	tenantRoleCalled      bool
	tenantRoleTenantID    string
	tenantRoleUserID      string
	tenantRoleRole        string
	tenantRoleActorID     string
	tenantRoleReturnError error
}

func (f *fakeIdentityBindingServiceForRoleTransition) BindAndResolve(context.Context, identitybinding.ExternalIdentity) (identitybinding.Resolution, error) {
	return identitybinding.Resolution{}, nil
}
func (f *fakeIdentityBindingServiceForRoleTransition) AssignManually(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeIdentityBindingServiceForRoleTransition) AssignManyManually(context.Context, string, []string, string, string, string) error {
	return nil
}
func (f *fakeIdentityBindingServiceForRoleTransition) SetAutomatic(context.Context, string, string, string) error {
	return nil
}
func (f *fakeIdentityBindingServiceForRoleTransition) Unassign(context.Context, string, string, string) error {
	return nil
}
func (f *fakeIdentityBindingServiceForRoleTransition) TransitionTenantRole(_ context.Context, tenantID, userID, role, actorID string) error {
	f.tenantRoleCalled = true
	f.tenantRoleTenantID = tenantID
	f.tenantRoleUserID = userID
	f.tenantRoleRole = role
	f.tenantRoleActorID = actorID
	return f.tenantRoleReturnError
}

// C1：viewer -> tenant_admin 这种非应急的纯角色变化必须走事务化路径，
// 调用 BindingService.TransitionTenantRole（事务内同步 users.role +
// permission_grants + audit + outbox），并在 commit 后失效 permission cache。
// 旧实现只 UPDATE users 单表，permission_grants.role 仍是旧角色，
// enforce 中间件认旧角色，UI 显示新角色实际权限是旧角色。
func TestUpdateUserRoleChangeNonEmergencyInvokesTransitionTenantRole(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {
			ID: "u1", TenantID: "tenant-1", Username: "u1",
			Role: "viewer", Status: "active",
			DepartmentAssignmentMode: "manual",
		},
	}}
	binding := &fakeIdentityBindingServiceForRoleTransition{}
	perm := &fakePermissionAuthorizerForRoleTransition{}
	deps := &Dependencies{
		UserStore:              store,
		IdentityBindingService: binding,
		PermissionChecker:      perm,
	}

	req := httptest.NewRequest(http.MethodPut, "/admin/v1/users/u1",
		strings.NewReader(`{"role":"tenant_admin"}`))
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
		t.Fatalf("TransitionTenantRole 未被调用（C1 修复前只 UPDATE users 单表）")
	}
	if binding.tenantRoleRole != "tenant_admin" {
		t.Fatalf("TransitionTenantRole role = %q, want tenant_admin", binding.tenantRoleRole)
	}
	if binding.tenantRoleUserID != "u1" {
		t.Fatalf("TransitionTenantRole userID = %q, want u1", binding.tenantRoleUserID)
	}
	found := false
	for _, id := range perm.invalidated {
		if id == "u1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("InvalidateUserCache 未被调用，缓存未失效")
	}
}

// C1：username/email/phone 等非角色字段的更新不应触发 TransitionTenantRole。
func TestUpdateUserNonRoleFieldDoesNotInvokeTransitionTenantRole(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: "viewer", Status: "active"},
	}}
	binding := &fakeIdentityBindingServiceForRoleTransition{}
	deps := &Dependencies{
		UserStore:              store,
		IdentityBindingService: binding,
	}

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
	if binding.tenantRoleCalled {
		t.Fatalf("TransitionTenantRole 不应被调用（非角色字段更新）")
	}
}

// C1：角色相同（role=viewer 传 viewer）不应触发 TransitionTenantRole。
func TestUpdateUserSameRoleDoesNotInvokeTransitionTenantRole(t *testing.T) {
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: "viewer", Status: "active"},
	}}
	binding := &fakeIdentityBindingServiceForRoleTransition{}
	deps := &Dependencies{
		UserStore:              store,
		IdentityBindingService: binding,
	}

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
	if binding.tenantRoleCalled {
		t.Fatalf("TransitionTenantRole 不应被调用（角色未变）")
	}
}
