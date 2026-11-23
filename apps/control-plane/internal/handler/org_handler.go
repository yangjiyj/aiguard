package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// linkUserToTeamDefaultApp 把用户关联到部门的"默认应用"(project_users)。
// 默认应用 = 该部门最早建的那个 project（一条龙自动建的原始应用）。
// 语义：员工挂进部门 → 自动关联本部门默认应用（能用它）；"做区分"再手工建新应用/调 project_users。
// 全 best-effort：部门无应用/失败只记日志、不阻断加成员。BindUserWithRole 幂等(ON CONFLICT)。
func linkUserToTeamDefaultApp(ctx context.Context, deps *Dependencies, tenantID, teamID, userID string) {
	if deps == nil || deps.ProjectUserRepo == nil {
		return
	}
	pr, ok := deps.ProjectRepo.(*repository.ProjectRepository)
	if !ok {
		return
	}
	projects, err := pr.ListByTeam(ctx, tenantID, teamID)
	if err != nil || len(projects) == 0 {
		return // 部门还没应用（如空部门）→ 无默认应用可关联，跳过
	}
	// ListByTeam 按 created_at DESC → 最后一个是最早建的（部门的原始/默认应用）
	def := projects[len(projects)-1]
	if err := deps.ProjectUserRepo.BindUserWithRole(ctx, def.ID, userID, "developer"); err != nil {
		log.Print("component=organization stage=default_app_user_bind error_code=project_user_bind_failed")
	}
}

func normalizeTeamMemberRole(role string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", "member":
		return "member", nil
	case "admin", "owner":
		return "owner", nil
	case "viewer":
		return "viewer", nil
	default:
		return "", errors.New("role must be admin, owner, member, or viewer")
	}
}

func writeIdentityBindingMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identitybinding.ErrNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user or department not found")
	case errors.Is(err, identitybinding.ErrConflict):
		writeErrorWithStatus(w, http.StatusConflict, "department_assignment_conflict", "department assignment is not allowed for this user")
	default:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to update department assignment")
	}
}

// CreateTeam handles POST /admin/v1/teams
func CreateTeam(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		var req struct {
			Name         string `json:"name"`
			ParentTeamID string `json:"parent_team_id"`
			// 一条龙：建部门时自动建专属应用（project，team_id=本部门），让部门主管开箱可见本部门用量/告警。
			CreateApp bool `json:"create_app"`
			// 专属应用名（选填，默认与部门同名）。
			AppName string `json:"app_name"`
			// 员工 SSO 部门值（选填）：填了就顺手建一条分组映射规则，把该部门员工路由到这个专属应用。
			SSODepartment string `json:"sso_department"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.Name == "" {
			writeError(w, "invalid_request", "name required")
			return
		}

		team := &repository.Team{
			ID:           "team_" + uuid.New().String()[:8],
			TenantID:     user.TenantID,
			Name:         req.Name,
			ParentTeamID: req.ParentTeamID,
		}

		parentPath := ""
		if req.ParentTeamID != "" {
			parent, err := deps.TeamRepo.GetByID(r.Context(), req.ParentTeamID)
			if err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
			if parent == nil {
				writeError(w, "not_found", "parent team not found")
				return
			}
			parentPath = parent.Path
		}

		if err := deps.TeamRepo.Create(r.Context(), team, parentPath); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		if err := deps.OrgService.ValidateTeamDepth(team.Path); err != nil {
			_ = deps.TeamRepo.Delete(r.Context(), team.ID)
			writeError(w, "invalid_request", err.Error())
			return
		}

		logAudit(r, deps, "team.create", map[string]any{
			"team_id":        team.ID,
			"name":           team.Name,
			"parent_team_id": team.ParentTeamID,
		}, "team", team.ID)

		// 一条龙：自动建该部门的专属应用（+可选分组映射规则）。全 best-effort——
		// 建部门本身已成功，这里任何一步失败都只记日志、不回滚、不阻断（管理员可事后手工补）。
		resp := map[string]any{"team": team}
		if req.CreateApp {
			if pr, ok := deps.ProjectRepo.(*repository.ProjectRepository); ok {
				appName := strings.TrimSpace(req.AppName)
				if appName == "" {
					appName = team.Name
				}
				proj := &repository.Project{
					TenantID:    user.TenantID,
					Name:        appName,
					Status:      "active",
					OwnerUserID: user.ID,
				}
				if err := pr.Create(r.Context(), proj); err != nil {
					log.Print("component=organization stage=team_default_app_create error_code=project_create_failed")
				} else if err := pr.UpdateTeam(r.Context(), user.TenantID, proj.ID, team.ID); err != nil {
					log.Print("component=organization stage=team_default_app_assign error_code=project_team_update_failed")
				} else {
					resp["app"] = map[string]any{"id": proj.ID, "name": proj.Name}
					logAudit(r, deps, "project.create", map[string]any{"project_id": proj.ID, "name": proj.Name, "team_id": team.ID, "auto": true}, "project", proj.ID)
					// 可选：SSO 部门值非空 → 建分组映射，把该部门员工路由到这个专属应用。
					if dept := strings.TrimSpace(req.SSODepartment); dept != "" && deps.GroupMappingRuleRepo != nil {
						rule := &repository.GroupMappingRule{
							TenantID:         user.TenantID,
							MatchType:        "department",
							MatchValue:       dept,
							MappedGroup:      team.Name,
							GatewayProjectID: proj.ID,
							GatewayTeamID:    team.ID,
							Priority:         100,
							Enabled:          true,
						}
						if err := deps.GroupMappingRuleRepo.Create(r.Context(), rule); err != nil {
							log.Print("component=organization stage=team_group_mapping_create error_code=group_mapping_create_failed")
						} else {
							resp["mapping_rule_id"] = rule.ID
							logAudit(r, deps, "group_mapping_rule.create", map[string]any{"rule_id": rule.ID, "match_value": dept, "project_id": proj.ID, "auto": true}, "group_mapping_rule", rule.ID)
						}
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ListTeams handles GET /admin/v1/teams
func ListTeams(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		teams, err := deps.TeamRepo.ListByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		// dept_manager 等非管理员：团队列表只保留本人所属的部门。
		if isFull, teamIDs, _ := callerTeamScope(r, deps); !isFull {
			allow := stringSetFrom(teamIDs)
			filtered := teams[:0:0]
			for _, t := range teams {
				if _, ok := allow[t.ID]; ok {
					filtered = append(filtered, t)
				}
			}
			teams = filtered
		}

		if teams == nil {
			teams = []*repository.Team{}
		}
		type response struct {
			Data []*repository.Team `json:"data"`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{Data: teams})
	}
}

// DeleteTeam handles DELETE /admin/v1/teams/{id}
func DeleteTeam(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		teamID := chi.URLParam(r, "id")
		if teamID == "" {
			writeError(w, "invalid_request", "team id required")
			return
		}

		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		// 先查占用：有成员（库里是 RESTRICT 外键）或下级部门时拒绝，并告诉管理员各有多少，
		// 而不是把数据库的外键报错原样甩到页面上，或者悄悄把下级部门提成一级部门。
		blockers, err := deps.TeamRepo.DeleteBlockers(r.Context(), user.TenantID, teamID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to inspect department references")
			return
		}
		if blockers.Members > 0 || blockers.ChildTeams > 0 {
			writeErrorWithStatusAndDetails(w, http.StatusConflict, "team_not_empty", formatTeamDeleteBlockers(blockers), blockers)
			return
		}

		if err := deps.TeamRepo.Delete(r.Context(), teamID); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				// 还有别的表（如员工密钥）引用这个部门：同样是“被占用”，不是服务器故障，也不外露库错误。
				writeErrorWithStatus(w, http.StatusConflict, "team_in_use", "该部门仍被其他数据引用，暂时无法删除")
				return
			}
			// 日志只写固定的有界字段（见 sensitive_logging_test.go），不带错误原文。
			log.Printf("component=org_handler stage=delete_team error_code=delete_team_failed")
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to delete team")
			return
		}

		logAudit(r, deps, "team.delete", map[string]any{
			"team_id": teamID,
		}, "team", teamID)

		w.WriteHeader(http.StatusNoContent)
	}
}

// formatTeamDeleteBlockers 用中性措辞（部门/单位的叫法可由管理员改名），前端会按当前叫法重写同一句话。
func formatTeamDeleteBlockers(b repository.TeamDeleteBlockers) string {
	parts := make([]string, 0, 2)
	if b.Members > 0 {
		parts = append(parts, fmt.Sprintf("%d 名成员", b.Members))
	}
	if b.ChildTeams > 0 {
		parts = append(parts, fmt.Sprintf("%d 个下级", b.ChildTeams))
	}
	return "还有 " + strings.Join(parts, "、") + "，请先移走成员、处理下级后再删除"
}

// AddTeamMember handles POST /admin/v1/teams/{id}/members
func AddTeamMember(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		teamID := chi.URLParam(r, "id")
		if teamID == "" {
			writeError(w, "invalid_request", "team id required")
			return
		}

		var req struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.UserID == "" {
			writeError(w, "invalid_request", "user_id required")
			return
		}
		role, err := normalizeTeamMemberRole(req.Role)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		req.Role = role

		// Verify team belongs to caller s tenant
		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		if deps.IdentityBindingService == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "department assignment service is not configured")
			return
		}
		if err := deps.IdentityBindingService.AssignManyManually(
			r.Context(), user.TenantID, []string{req.UserID}, teamID, req.Role, user.ID,
		); err != nil {
			writeIdentityBindingMutationError(w, err)
			return
		}

		logAudit(r, deps, "team.member.add", map[string]any{
			"team_id": teamID,
			"user_id": req.UserID,
			"role":    req.Role,
		}, "team", teamID)

		// 员工挂进部门 → 自动关联本部门默认应用（best-effort）。
		linkUserToTeamDefaultApp(r.Context(), deps, user.TenantID, teamID, req.UserID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id": teamID,
			"user_id": req.UserID,
			"role":    req.Role,
		})
	}
}

// RemoveTeamMember handles DELETE /admin/v1/teams/{id}/members/{user_id}
func RemoveTeamMember(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		teamID := chi.URLParam(r, "id")
		targetUserID := chi.URLParam(r, "user_id")
		if teamID == "" || targetUserID == "" {
			writeError(w, "invalid_request", "team id and user_id required")
			return
		}

		// Verify team belongs to caller s tenant
		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		if deps.IdentityBindingService == nil || deps.UserRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "department assignment service is not configured")
			return
		}
		target, err := deps.UserRepo.GetByID(r.Context(), targetUserID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get user")
			return
		}
		if target == nil || target.TenantID != user.TenantID || target.DepartmentID != teamID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team member not found")
			return
		}
		if err := deps.IdentityBindingService.Unassign(
			r.Context(), user.TenantID, targetUserID, user.ID,
		); err != nil {
			writeIdentityBindingMutationError(w, err)
			return
		}

		logAudit(r, deps, "team.member.remove", map[string]any{
			"team_id": teamID,
			"user_id": targetUserID,
		}, "team", teamID)

		w.WriteHeader(http.StatusNoContent)
	}
}
