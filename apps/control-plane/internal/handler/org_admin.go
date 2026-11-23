package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/go-chi/chi/v5"
)

// DeleteTenant DELETE /admin/v1/tenants/{id}
// 删除单位。安全：仅 platform_admin；不能删自己所在单位；不能删非空单位（仍有用户/应用）。
func DeleteTenant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can delete units")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "tenant id required")
			return
		}
		if id == user.TenantID {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "cannot delete your own unit")
			return
		}
		t, err := deps.TenantRepo.GetByID(r.Context(), id)
		if err != nil || t == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unit not found")
			return
		}
		// 非空校验：还有用户或应用时拒绝，避免误删数据。
		// 提示要说清阻塞项数量——只说“仍有用户或应用”会让管理员不知道该去清什么，
		// 实践中导致用户反复点删除却不明白为何失败。
		users, err := deps.UserRepo.List(r.Context(), id)
		if err != nil {
			writeError(w, "internal_error", "failed to verify unit users")
			return
		}
		projects, err := deps.ProjectRepo.List(r.Context(), id)
		if err != nil {
			writeError(w, "internal_error", "failed to verify unit projects")
			return
		}
		if len(users) > 0 || len(projects) > 0 {
			parts := make([]string, 0, 2)
			if len(users) > 0 {
				parts = append(parts, fmt.Sprintf("%d 个用户", len(users)))
			}
			if len(projects) > 0 {
				parts = append(parts, fmt.Sprintf("%d 个应用", len(projects)))
			}
			writeErrorWithStatus(w, http.StatusConflict, "unit_not_empty",
				fmt.Sprintf("该单位下仍有 %s，请先在该单位的「用户」「应用」标签页中清空后再删除", strings.Join(parts, "、")))
			return
		}
		if err := deps.TenantRepo.Delete(r.Context(), id); err != nil {
			writeError(w, "internal_error", "failed to delete unit")
			return
		}
		logAudit(r, deps, "delete_tenant", map[string]interface{}{"tenant_id": id}, "tenant", id)
		w.WriteHeader(http.StatusNoContent)
	}
}

type orgUnitStat struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	DeptCount    int    `json:"dept_count"`
	UserCount    int    `json:"user_count"`
	ProjectCount int    `json:"project_count"`
}

// GetOrgStats GET /admin/v1/stats/org
// 单位 / 部门统计：platform_admin 看全部单位，单位管理员看本单位，普通成员只看自己团队子树。
func GetOrgStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		tenants, err := deps.TenantRepo.List(r.Context()) // 已过滤 is_test
		if err != nil {
			writeError(w, "internal_error", "failed to list units")
			return
		}

		units := make([]orgUnitStat, 0, len(tenants))
		totalDepts, totalUsers := 0, 0
		for _, t := range tenants {
			if user.Role != "platform_admin" && t.ID != user.TenantID {
				continue
			}

			stat := orgUnitStat{ID: t.ID, Name: t.Name, Status: t.Status}
			if canViewFullOrgStats(user.Role) {
				teams, err := deps.TeamRepo.ListByTenant(r.Context(), t.ID)
				if err != nil {
					writeError(w, "internal_error", "failed to list departments")
					return
				}
				users, err := deps.UserRepo.List(r.Context(), t.ID)
				if err != nil {
					writeError(w, "internal_error", "failed to list users")
					return
				}
				projectCount, err := deps.ProjectRepo.CountByTenant(r.Context(), t.ID)
				if err != nil {
					writeError(w, "internal_error", "failed to count projects")
					return
				}
				stat.DeptCount = len(teams)
				stat.UserCount = len(users)
				stat.ProjectCount = projectCount
			} else {
				teamIDs, err := deps.TeamMemberRepo.ListTeamSubtreeIDsByUser(r.Context(), user.TenantID, user.ID)
				if err != nil {
					writeError(w, "internal_error", "failed to resolve department scope")
					return
				}
				if len(teamIDs) == 0 {
					continue
				}
				userCount, err := deps.TeamMemberRepo.CountUsersByTeams(r.Context(), user.TenantID, teamIDs)
				if err != nil {
					writeError(w, "internal_error", "failed to count scoped users")
					return
				}
				projectCount, err := deps.TeamMemberRepo.CountProjectsByTeams(r.Context(), user.TenantID, teamIDs)
				if err != nil {
					writeError(w, "internal_error", "failed to count scoped projects")
					return
				}
				stat.DeptCount = len(teamIDs)
				stat.UserCount = userCount
				stat.ProjectCount = projectCount
			}
			units = append(units, stat)
			totalDepts += stat.DeptCount
			totalUsers += stat.UserCount
		}
		writeTenantJSONData(w, map[string]any{
			"units":       units,
			"total_units": len(units),
			"total_depts": totalDepts,
			"total_users": totalUsers,
		})
	}
}

func canViewFullOrgStats(role string) bool {
	switch role {
	case "platform_admin", "tenant_owner", "tenant_admin", "admin":
		return true
	default:
		return false
	}
}
