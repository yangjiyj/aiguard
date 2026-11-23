package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// withUserContext 把一个手工构造的 repository.User 注入请求 context，
// 让 callerTeamScope 等 dept 闸门函数能读到 department_assignment_mode / department_id。
// 不依赖任何 DB——纯逻辑闸门单测用。
func withUserContext(r *http.Request, u *repository.User) *http.Request {
	ctx := context.WithValue(r.Context(), auth.UserKey, u)
	return r.WithContext(ctx)
}

func deptAuthTestUser(id, tenantID, deptID, mode string) *repository.User {
	return &repository.User{
		ID:                       id,
		TenantID:                 tenantID,
		DepartmentID:             deptID,
		DepartmentAssignmentMode: mode,
	}
}

// TestCallerTeamScopeEmergencyReturnsEmpty 对应计划场景6：
// 应急管理员（assignment_mode=emergency）即便带了 department_id，通过 Chat 集成接口
// 取可见范围时必须拿到空集——模型列表必须为空，不能因为应急 department 有映射就放行。
func TestCallerTeamScopeEmergencyReturnsEmpty(t *testing.T) {
	emergency := deptAuthTestUser("u_emerg", "tenant_default", "dept_root", "emergency")
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/teams/x/models", nil)
	req = withUserContext(req, emergency)

	isFull, teamIDs, projectIDs := callerTeamScope(req, &Dependencies{})
	if isFull {
		t.Fatal("emergency user must NOT get full-tenant scope")
	}
	if len(teamIDs) != 0 || len(projectIDs) != 0 {
		t.Fatalf("emergency user must get empty scope, got teams=%v projects=%v", teamIDs, projectIDs)
	}
}

// TestCallerMayAccessTeamEmergencyDenies 对应场景6 的成员闸门：
// 应急管理员对任意 team 的成员校验必须 fail-closed 返回 false。
func TestCallerMayAccessTeamEmergencyDenies(t *testing.T) {
	emergency := deptAuthTestUser("u_emerg", "tenant_default", "dept_root", "emergency")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUserContext(req, emergency)

	if callerMayAccessTeam(req, &Dependencies{}, "dept_root") {
		t.Fatal("emergency user must be denied team access even for own dept")
	}
	if callerMayAccessTeam(req, &Dependencies{}, "any_other") {
		t.Fatal("emergency user must be denied team access for any team")
	}
}

// TestCallerSharesTeamWithUserEmergencyDenies 验证应急用户读取他人详情也被拒。
func TestCallerSharesTeamWithUserEmergencyDenies(t *testing.T) {
	emergency := deptAuthTestUser("u_emerg", "tenant_default", "dept_root", "emergency")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUserContext(req, emergency)

	if callerSharesTeamWithUser(req, &Dependencies{}, "u_other") {
		t.Fatal("emergency user must not share-team with anyone")
	}
	// 看自己仍允许（用户要看自己的基本信息）
	if !callerSharesTeamWithUser(req, &Dependencies{}, "u_emerg") {
		t.Fatal("emergency user reading own profile should be allowed")
	}
}

// TestCallerTeamScopeNonEmergencyNeedsRepo 对应场景1-3 的闸门侧：
// 非应急用户（dept_manager）必须走 repo 解析当前部门；repo 缺失时 fail-closed 到空集。
// 这保证"部门迁移后旧 team_members 残留行不能扩大权限"——闸门只认 department_id 的事实源。
func TestCallerTeamScopeNonEmergencyNeedsRepo(t *testing.T) {
	deptMgr := deptAuthTestUser("u_mgr", "tenant_default", "dept_A", "manual")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUserContext(req, deptMgr)

	// deps 无 repo：fail-closed 空集
	isFull, teamIDs, projectIDs := callerTeamScope(req, &Dependencies{})
	if isFull || len(teamIDs) != 0 || len(projectIDs) != 0 {
		t.Fatalf("missing repo must fail-closed to empty, got full=%v teams=%v projects=%v", isFull, teamIDs, projectIDs)
	}
}

// TestCallerTeamScopeFullTenantRoleBypassesDept 对应管理员档：
// platform_admin/tenant_admin 等不收窄到部门（应急除外），isFull=true。
// 注意：应急是 assignment_mode，与 role 正交——即便 role=tenant_admin 但被设为应急模式也要拒。
func TestCallerTeamScopeFullTenantRoleBypassesDept(t *testing.T) {
	admin := deptAuthTestUser("u_admin", "tenant_default", "dept_A", "manual")
	admin.Role = "tenant_admin"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUserContext(req, admin)

	isFull, _, _ := callerTeamScope(req, &Dependencies{})
	if !isFull {
		t.Fatal("tenant_admin with manual mode must get full scope")
	}

	// 同样的 role 但应急模式：必须收窄到空
	admin.DepartmentAssignmentMode = "emergency"
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2 = withUserContext(req2, admin)
	isFull2, _, _ := callerTeamScope(req2, &Dependencies{})
	if isFull2 {
		t.Fatal("emergency mode must override tenant_admin role to empty scope")
	}
}

// TestCallerTeamScopeNoUserFailClosed 无 context user 时 fail-closed。
func TestCallerTeamScopeNoUserFailClosed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	isFull, teamIDs, projectIDs := callerTeamScope(req, &Dependencies{})
	if isFull || len(teamIDs) != 0 || len(projectIDs) != 0 {
		t.Fatalf("no user in context must fail-closed, got full=%v teams=%v", isFull, teamIDs)
	}
}

// 编译期保证 context 注入路径可用。
var _ context.Context
