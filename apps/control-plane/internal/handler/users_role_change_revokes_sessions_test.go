package handler

// M-1：任何改变 users.role 的路径成功后都必须让该用户的全部会话失效（与 emergency 路径对齐）。
// 此前纯租户内的角色变化（auditor ↔ tenant_admin ↔ security_officer 等）没有删会话，旧会话继续带着新角色的权限。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// orderedSessionStore 记录 DeleteByUser 与 TransitionTenantRole 的相对顺序。
type orderedSessionStore struct {
	events  *[]string
	deleted []string
	err     error
}

func (s *orderedSessionStore) Create(context.Context, *repository.Session) error { return nil }
func (s *orderedSessionStore) Delete(context.Context, string) error              { return nil }
func (s *orderedSessionStore) DeleteByUser(_ context.Context, userID string) error {
	*s.events = append(*s.events, "delete_sessions")
	s.deleted = append(s.deleted, userID)
	return s.err
}

type orderedBindingService struct {
	fakeIdentityBindingServiceForRoleTransition
	events *[]string
}

func (b *orderedBindingService) TransitionTenantRole(ctx context.Context, tenantID, userID, role, actorID string) error {
	*b.events = append(*b.events, "transition_role")
	return b.fakeIdentityBindingServiceForRoleTransition.TransitionTenantRole(ctx, tenantID, userID, role, actorID)
}

func runRoleChange(t *testing.T, from, to string, sessions *orderedSessionStore, binding *orderedBindingService) *httptest.ResponseRecorder {
	t.Helper()
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: from, Status: "active", DepartmentAssignmentMode: "manual"},
	}}
	deps := &Dependencies{
		UserStore: store, IdentityBindingService: binding, SessionRepo: sessions,
		PermissionChecker: &fakePermissionAuthorizerForRoleTransition{},
	}
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/users/u1", strings.NewReader(`{"role":"`+to+`"}`))
	req = platformAdminContext(req)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "u1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, req)
	return w
}

// 三员与租户管理员及其他非 platform_admin 角色之间的全部互换（platform_admin 边界走 emergency 路径，已自带删会话）。
func TestEveryTenantRoleChangeRevokesTheUsersSessions(t *testing.T) {
	roles := []string{"security_officer", "auditor", "tenant_admin", "dept_manager", "developer", "viewer", "chat_user"}
	for _, from := range roles {
		for _, to := range roles {
			if from == to {
				continue
			}
			t.Run(from+"_to_"+to, func(t *testing.T) {
				var events []string
				sessions := &orderedSessionStore{events: &events}
				binding := &orderedBindingService{events: &events}
				w := runRoleChange(t, from, to, sessions, binding)
				if w.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
				if len(sessions.deleted) == 0 || sessions.deleted[0] != "u1" {
					t.Fatalf("角色 %s → %s 后必须删除该用户的全部会话，实际 %v", from, to, sessions.deleted)
				}
				// 先吊销会话再改角色（fail-closed），与 emergency 路径同序。
				if len(events) < 2 || events[0] != "delete_sessions" || events[1] != "transition_role" {
					t.Fatalf("顺序应为 先删会话 → 再改角色，实际 %v", events)
				}
			})
		}
	}
}

// 会话吊销失败时必须 fail-closed：不改角色，返回错误。
func TestRoleChangeFailsClosedWhenSessionRevocationFails(t *testing.T) {
	var events []string
	sessions := &orderedSessionStore{events: &events, err: errors.New("redis down")}
	binding := &orderedBindingService{events: &events}
	w := runRoleChange(t, "auditor", "security_officer", sessions, binding)
	if w.Code == http.StatusOK {
		t.Fatalf("会话吊销失败不得返回成功: %s", w.Body.String())
	}
	if binding.tenantRoleCalled {
		t.Fatalf("会话没删成功就不得改角色（否则旧会话带着新权限）")
	}
}

// 角色没变（只改资料）不应踢掉用户的会话。
func TestProfileOnlyUpdateKeepsSessions(t *testing.T) {
	var events []string
	sessions := &orderedSessionStore{events: &events}
	binding := &orderedBindingService{events: &events}
	store := &licenseUserStore{users: map[string]*repository.User{
		"u1": {ID: "u1", TenantID: "tenant-1", Username: "u1", Role: "auditor", Status: "active", DepartmentAssignmentMode: "manual"},
	}}
	deps := &Dependencies{UserStore: store, IdentityBindingService: binding, SessionRepo: sessions, PermissionChecker: &fakePermissionAuthorizerForRoleTransition{}}
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/users/u1", strings.NewReader(`{"email":"new@example.test"}`))
	req = platformAdminContext(req)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "u1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(sessions.deleted) != 0 {
		t.Fatalf("仅改资料不应删会话: %d deleted=%v", w.Code, sessions.deleted)
	}
}
