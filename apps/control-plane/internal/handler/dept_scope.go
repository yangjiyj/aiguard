package handler

import (
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// 部门主管(dept_manager)等非管理员角色的"本部门"收窄闸门。
// 背景（docs/specs/2026-07-06-rbac-blast-radius-audit.md 路线乙）：RBAC 中间件只判"该角色能否读这类
// resource"，无法把返回行收窄到某个 team（buildScopeCandidates 恒含 tenant scope）。因此团队级读接口
// 必须在 handler 里显式做成员校验——本文件提供统一原语，与 resolveUsageScope(usage.go) 的收窄口径一致。

// isFullTenantRole 报告某角色是否可见整租户（管理员档）。
// 与 resolveUsageScope 的 FullTenant 分支(usage.go)保持完全一致：改这里也要改那里。
func isFullTenantRole(role string) bool {
	// W4: the security officer handles alerts tenant-wide, so it is full-tenant.
	// The auditor is NOT: this gate also guards writes (quota, budget, keys), and
	// the auditor's tenant-wide read of security records is granted separately in
	// resolveUsageScope (usage.go) while the SoD guard blocks its writes.
	return role == "platform_admin" || role == "tenant_owner" || role == "tenant_admin" || roles.IsSecurityOfficer(role)
}

// callerMayAccessTeam 判定当前请求者能否读取指定 team 的数据。
// 管理员档(isFullTenantRole)可读本租户任意 team（团队详情 handler 已各自做过 tenant 校验）；
// 其它角色（如 dept_manager）必须是该 team 的成员。任何查不到/仓库缺失/出错一律 fail-closed 返回 false。
// 注意：本函数只做"成员归属"这一层；调用方仍需保留原有的 team.TenantID == user.TenantID 校验。
func callerMayAccessTeam(r *http.Request, deps *Dependencies, teamID string) bool {
	user := auth.GetUser(r.Context())
	if user == nil {
		return false
	}
	// 应急用户（assignment_mode=emergency）必须先于 role 判断被拒：
	// 即便 role=tenant_admin/platform_admin，应急态下所有部门收窄闸门 fail-closed（任务11场景6）。
	if user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	if isFullTenantRole(user.Role) {
		return true
	}
	if deps == nil || deps.TeamMemberRepo == nil {
		return false
	}
	teamIDs, err := deps.TeamMemberRepo.ListTeamIDsByUser(r.Context(), user.ID)
	if err != nil {
		return false
	}
	for _, t := range teamIDs {
		if t == teamID {
			return true
		}
	}
	return false
}

// callerMayAccessProject 判定请求者能否读取指定 project 的数据（项目级读接口的成员闸门）。
// 管理员档放行任意项目；其它角色仅当该 project 属于本人所在团队时放行。fail-closed。
func callerMayAccessProject(r *http.Request, deps *Dependencies, projectID string) bool {
	user := auth.GetUser(r.Context())
	if user == nil {
		return false
	}
	if user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	if isFullTenantRole(user.Role) {
		return true
	}
	if deps == nil || deps.TeamMemberRepo == nil {
		return false
	}
	projectIDs, err := deps.TeamMemberRepo.ListProjectIDsByUserTeams(r.Context(), user.TenantID, user.ID)
	if err != nil {
		return false
	}
	for _, p := range projectIDs {
		if p == projectID {
			return true
		}
	}
	return false
}

// callerTeamScope 给列表类读接口做"本部门"收窄。
// 返回 (isFull, teamIDs, projectIDs)：管理员档 isFull=true（切片为 nil，调用方直接放行全量）；
// 其它角色 isFull=false，teamIDs/projectIDs 为其所属团队及这些团队的项目集合，调用方据此过滤返回行。
// 口径与 resolveUsageScope(usage.go) 一致。出错/无用户时返回 isFull=false 且空切片（fail-closed 到空集）。
func callerTeamScope(r *http.Request, deps *Dependencies) (isFull bool, teamIDs []string, projectIDs []string) {
	user := auth.GetUser(r.Context())
	if user == nil {
		return false, nil, nil
	}
	// 应急用户：模型列表必须为空（任务11场景6）。先于 role 判断，确保即便
	// role=tenant_admin/platform_admin 的应急态用户也拿到空授权。
	if user.DepartmentAssignmentMode == "emergency" {
		return false, nil, nil
	}
	if isFullTenantRole(user.Role) {
		return true, nil, nil
	}
	if deps != nil && deps.TeamMemberRepo != nil {
		teamIDs, _ = deps.TeamMemberRepo.ListTeamIDsByUser(r.Context(), user.ID)
		projectIDs, _ = deps.TeamMemberRepo.ListProjectIDsByUserTeams(r.Context(), user.TenantID, user.ID)
	}
	return false, teamIDs, projectIDs
}

// callerSharesTeamWithUser 判定当前请求者能否读取"某个目标用户"的详情/登录历史/授权。
// 管理员档放行任意用户；看自己总是允许；其它角色仅当与目标用户至少同属一个 team 时放行。
// 由于 team 归属天然限定在本租户，本函数对非管理员也隐含"同租户"约束。fail-closed。
func callerSharesTeamWithUser(r *http.Request, deps *Dependencies, targetUserID string) bool {
	user := auth.GetUser(r.Context())
	if user == nil {
		return false
	}
	// 看自己总是允许（用户读自己基本信息），不因应急态被拒。
	if user.ID == targetUserID {
		return true
	}
	// 应急用户读他人：拒绝，先于 role 判断（任务11场景6）。
	if user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	if isFullTenantRole(user.Role) {
		return true
	}
	if deps == nil || deps.TeamMemberRepo == nil {
		return false
	}
	callerTeams, err := deps.TeamMemberRepo.ListTeamIDsByUser(r.Context(), user.ID)
	if err != nil || len(callerTeams) == 0 {
		return false
	}
	targetTeams, err := deps.TeamMemberRepo.ListTeamIDsByUser(r.Context(), targetUserID)
	if err != nil {
		return false
	}
	callerSet := make(map[string]struct{}, len(callerTeams))
	for _, t := range callerTeams {
		callerSet[t] = struct{}{}
	}
	for _, t := range targetTeams {
		if _, ok := callerSet[t]; ok {
			return true
		}
	}
	return false
}

// callerIsFullTenant 报告当前请求者是否为管理员档（整租户可见）。
// 供那些"聚合口径无法按 team 收窄"的读接口（如全局 savings/budgets 汇总）做管理员限定：
// 非管理员一律拒绝，避免部门主管读到全公司口径的数字。
func callerIsFullTenant(r *http.Request) bool {
	user := auth.GetUser(r.Context())
	return user != nil && isFullTenantRole(user.Role)
}

// containsStr 报告 v 是否在 ids 中。用于告警组等按 project 归属的 post-fetch 校验。
func containsStr(ids []string, v string) bool {
	for _, id := range ids {
		if id == v {
			return true
		}
	}
	return false
}

// filterByIDSet 是列表收窄的小工具：仅保留 id ∈ allow 的元素，保持顺序。
func stringSetFrom(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}
