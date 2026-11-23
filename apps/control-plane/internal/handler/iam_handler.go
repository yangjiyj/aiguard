package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ============================================================
// B3: BatchAddTeamMembers
// POST /admin/v1/teams/{id}/members/batch
// ============================================================

// BatchAddTeamMembers handles POST /admin/v1/teams/{id}/members/batch
func BatchAddTeamMembers(deps *Dependencies) http.HandlerFunc {
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
			UserIDs []string `json:"user_ids"`
			Role    string   `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if len(req.UserIDs) == 0 {
			writeError(w, "invalid_request", "user_ids required")
			return
		}
		role, err := normalizeTeamMemberRole(req.Role)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		req.Role = role

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
			r.Context(), user.TenantID, req.UserIDs, teamID, req.Role, user.ID,
		); err != nil {
			writeIdentityBindingMutationError(w, err)
			return
		}

		logAudit(r, deps, "team.members.batch_add", map[string]any{
			"team_id":  teamID,
			"user_ids": req.UserIDs,
			"role":     req.Role,
		}, "team", teamID)

		// 员工挂进部门 → 自动关联本部门默认应用（best-effort，逐个）。
		for _, uid := range req.UserIDs {
			linkUserToTeamDefaultApp(r.Context(), deps, user.TenantID, teamID, uid)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"added": len(req.UserIDs),
			"role":  req.Role,
		})
	}
}

// ListTeamMembers handles GET /admin/v1/teams/{id}/members
func ListTeamMembers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}
		// dept_manager 等非管理员：只能看本部门成员（越权读兄弟部门一律 404）。
		if !callerMayAccessTeam(r, deps, teamID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		members, err := deps.TeamMemberRepo.ListByTeam(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if members == nil {
			members = []*repository.TeamMember{}
		}

		type memberOut struct {
			UserID    string    `json:"user_id"`
			Username  string    `json:"username"`
			Role      string    `json:"role"`
			CreatedAt time.Time `json:"created_at"`
		}
		out := make([]memberOut, 0, len(members))
		for _, m := range members {
			mo := memberOut{
				UserID:    m.UserID,
				Role:      m.Role,
				CreatedAt: m.CreatedAt,
			}
			if u, err := deps.UserRepo.GetByID(r.Context(), m.UserID); err == nil && u != nil {
				mo.Username = u.Username
			}
			out = append(out, mo)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
	}
}

// ============================================================
// B3: PatchProjectTeam
// PATCH /admin/v1/projects/{id}/team
// ============================================================

// PatchProjectTeam handles PATCH /admin/v1/projects/{id}/team
func PatchProjectTeam(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		projectID := chi.URLParam(r, "id")

		var req struct {
			TeamID string `json:"team_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		proj, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if proj == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "project not found")
			return
		}

		if req.TeamID != "" {
			t, err := deps.TeamRepo.GetByID(r.Context(), req.TeamID)
			if err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
			if t == nil || t.TenantID != user.TenantID {
				writeError(w, "invalid_request", "team not found")
				return
			}
		}

		// 防回归：挂载会激活部门零信任层（governor 按 team_models 准入）。若目标 team 的
		// team_models 为空，用该 project 现有 model_policies 反向种一份（名→行ID；空策略=全放
		// →种全部），避免 enforce 模式下该部门所有模型被限流。逻辑放处理器、不动被复用的 repo。
		if req.TeamID != "" {
			existingTM, err := deps.TeamModelRepo.ListByTeam(r.Context(), req.TeamID)
			if err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
			hasAllowed := false
			for _, tm := range existingTM {
				if tm.Allowed {
					hasAllowed = true
					break
				}
			}
			if !hasAllowed {
				_, nameToID, err := buildModelIDNameMaps(r.Context(), deps, user.TenantID)
				if err != nil {
					writeError(w, "internal_error", err.Error())
					return
				}
				var seedNames []string
				if pol, _ := deps.ModelPolicyRepo.GetByProject(r.Context(), user.TenantID, projectID); pol != nil && len(pol.AllowList) > 0 {
					seedNames = pol.AllowList
				} else {
					// 空策略 = 全放 → 种全部模型，避免零信任层全拦
					for name := range nameToID {
						seedNames = append(seedNames, name)
					}
				}
				seedEntries := make([]*repository.TeamModel, 0, len(seedNames))
				for _, name := range seedNames {
					if id, ok := nameToID[name]; ok {
						seedEntries = append(seedEntries, &repository.TeamModel{
							TeamID: req.TeamID, ModelID: id, Allowed: true, GrantedBy: user.ID,
						})
					}
				}
				if len(seedEntries) > 0 {
					if err := deps.TeamModelRepo.UpsertBatch(r.Context(), req.TeamID, seedEntries); err != nil {
						writeError(w, "internal_error", err.Error())
						return
					}
				}
			} else {
				// 部门已有白名单 → 把它推给新挂的这个应用（行ID→名，覆盖写该 project 策略），
				// 免得"先存白名单、后挂应用"两边对不上（chat 读不到）。此刻 projects.team_id 尚未落，
				// 故直接按 projectID 写、不走 ListByTeam。
				idToName, _, err := buildModelIDNameMaps(r.Context(), deps, user.TenantID)
				if err != nil {
					writeError(w, "internal_error", err.Error())
					return
				}
				allowedNames := make([]string, 0, len(existingTM))
				for _, tm := range existingTM {
					if tm.Allowed {
						if name, ok := idToName[tm.ModelID]; ok {
							allowedNames = append(allowedNames, name)
						}
					}
				}
				var deny []string
				if existing, _ := deps.ModelPolicyRepo.GetByProject(r.Context(), user.TenantID, projectID); existing != nil {
					deny = existing.DenyList
				}
				if err := deps.ModelPolicyRepo.CreateOrUpdate(r.Context(), &repository.ModelPolicy{
					TenantID: user.TenantID, ProjectID: projectID, ScopeType: "project",
					AllowList: allowedNames, DenyList: deny,
				}); err != nil {
					writeError(w, "internal_error", err.Error())
					return
				}
			}
		}

		pr, ok := deps.ProjectRepo.(*repository.ProjectRepository)
		if !ok {
			writeError(w, "internal_error", "project repo type assertion failed")
			return
		}
		if err := pr.UpdateTeam(r.Context(), user.TenantID, projectID, req.TeamID); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "project.team.update", map[string]any{
			"project_id": projectID,
			"team_id":    req.TeamID,
		}, "project", projectID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"project_id": projectID,
			"team_id":    req.TeamID,
		})
	}
}

// GetTeamProjects handles GET /admin/v1/teams/{id}/projects
func GetTeamProjects(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}
		if !callerMayAccessTeam(r, deps, teamID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		pr, ok := deps.ProjectRepo.(*repository.ProjectRepository)
		if !ok {
			writeError(w, "internal_error", "project repo type assertion failed")
			return
		}
		projects, err := pr.ListByTeam(r.Context(), user.TenantID, teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if projects == nil {
			projects = []*repository.Project{}
		}

		// 返回小写 key DTO（repository.Project 无 json tag，直接序列化会是大写 Name/ID，
		// 前端 AppsTab 按小写 name/id 取会取不到、只剩图标；此处映射成前端约定的小写键）。
		type teamProjectDTO struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Code        string `json:"code"`
			Environment string `json:"environment"`
			Status      string `json:"status"`
			TeamID      string `json:"team_id"`
		}
		out := make([]teamProjectDTO, 0, len(projects))
		for _, p := range projects {
			out = append(out, teamProjectDTO{
				ID: p.ID, Name: p.Name, Code: p.Code,
				Environment: p.Environment, Status: p.Status, TeamID: p.TeamID,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}
}

// ============================================================
// B4: UpdateTeamBudget
// PUT /admin/v1/teams/{id}/budget
// ============================================================

// normalizeEnforcementMode 是 quota_policies.enforcement_mode 的白名单。
// 契约与同包 normalizeOverageAction（handler.go）对齐：空串取安全默认 soft（向后兼容
// 旧客户端），合法枚举透传，非法值返回 "" 交由调用方拒绝（400）——绝不静默降级。
// 枚举与 gateway-core governor decider 严格对应：bypass→放行、soft→仅监控告警、
// enforce→按 overage_action 处置。
func normalizeEnforcementMode(s string) string {
	switch s {
	case "", "soft":
		return "soft"
	case "enforce", "bypass":
		return s
	default:
		return ""
	}
}

// buildTeamQuotaPolicy 把团队预算请求映射为 quota_policies 行（scope_type=team）。
// enforcement_mode / overage_action 从请求读取，复用同包枚举白名单；非法取值返回
// error 交 handler 回 400（与 SetQuotaPolicy 一致），杜绝把垃圾配置静默降级成软限/放行；
// 空串向后兼容回退 soft/notify。取代此前硬编码的 soft/notify——否则团队预算无论
// 管理员意图如何都永远只监控、不拦截。
func buildTeamQuotaPolicy(tenantID, teamID string, monthly, daily float64, mode, action string) (*repository.QuotaPolicy, error) {
	em := normalizeEnforcementMode(mode)
	if em == "" {
		return nil, fmt.Errorf("invalid enforcement_mode: %q", mode)
	}
	oa := normalizeOverageAction(action)
	if oa == "" {
		return nil, fmt.Errorf("invalid overage_action: %q", action)
	}
	return &repository.QuotaPolicy{
		ID:                 "qpol_" + uuid.New().String()[:8],
		TenantID:           tenantID,
		ScopeType:          "team",
		ScopeRef:           teamID,
		MonthlyBudgetLimit: monthly,
		DailyBudgetLimit:   daily,
		OverageAction:      oa,
		EnforcementMode:    em,
		Status:             "active",
	}, nil
}

// buildUserQuotaPolicy 把个人月度预算请求映射为 quota_policies 行（scope_type=user）。
// 关键：填 UserID 不填 ScopeRef——gateway-core governor 的 user 维度按 user_id 列匹配
// （quota_cache.go: scope_type='user' AND user_id=$3）；写 ScopeRef 既匹配不上又会污染 team 匹配。
// enforcement_mode / overage_action 复用同包白名单（与 3.1 团队预算一致）：空串回退 soft/notify，
// 合法透传，非法返回 error 交 handler 回 400，绝不静默降级（个人预算同样不能 fail-open）。
func buildUserQuotaPolicy(tenantID, userID string, monthly float64, mode, action string) (*repository.QuotaPolicy, error) {
	em := normalizeEnforcementMode(mode)
	if em == "" {
		return nil, fmt.Errorf("invalid enforcement_mode: %q", mode)
	}
	oa := normalizeOverageAction(action)
	if oa == "" {
		return nil, fmt.Errorf("invalid overage_action: %q", action)
	}
	return &repository.QuotaPolicy{
		ID:                 "qpol_" + uuid.New().String()[:8],
		TenantID:           tenantID,
		ScopeType:          "user",
		UserID:             userID,
		MonthlyBudgetLimit: monthly,
		OverageAction:      oa,
		EnforcementMode:    em,
		Status:             "active",
	}, nil
}

// UpdateTeamBudget handles PUT /admin/v1/teams/{id}/budget
func UpdateTeamBudget(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		var req struct {
			MonthlyBudgetCNY float64 `json:"monthly_budget_cny"`
			DailyBudgetCNY   float64 `json:"daily_budget_cny"`
			EnforcementMode  string  `json:"enforcement_mode"`
			OverageAction    string  `json:"overage_action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		// 先校验护栏配置并构造策略（与 SetQuotaPolicy 一致：非法 enforcement_mode/overage_action
		// 直接 400 拒绝、不静默降级；也避免预算列已落库而策略校验失败的半更新）。
		policy, err := buildTeamQuotaPolicy(user.TenantID, teamID, req.MonthlyBudgetCNY, req.DailyBudgetCNY, req.EnforcementMode, req.OverageAction)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
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

		if err := deps.TeamRepo.UpdateBudget(r.Context(), teamID, req.MonthlyBudgetCNY, req.DailyBudgetCNY); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		// Sync to quota_policies (scope_type=team)；policy 已在入口校验并构造。
		if deps.QuotaPolicyRepo != nil {
			_ = deps.QuotaPolicyRepo.CreateOrUpdate(r.Context(), policy)
		}

		logAudit(r, deps, "team.budget.update", map[string]any{
			"team_id":            teamID,
			"monthly_budget_cny": req.MonthlyBudgetCNY,
			"daily_budget_cny":   req.DailyBudgetCNY,
		}, "team", teamID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":            teamID,
			"monthly_budget_cny": req.MonthlyBudgetCNY,
			"daily_budget_cny":   req.DailyBudgetCNY,
		})
	}
}

// ============================================================
// B4: Team Models CRUD
// ============================================================

// GetTeamModels handles GET /admin/v1/teams/{id}/models
func GetTeamModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}
		if !callerMayAccessTeam(r, deps, teamID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		models, err := deps.TeamModelRepo.ListByTeam(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if models == nil {
			models = []*repository.TeamModel{}
		}

		mode, configured, modeErr := deps.TeamModelRepo.GetAccessMode(r.Context(), user.TenantID, teamID)
		if modeErr != nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "无法读取部门模型配置")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": models, "model_access_mode": mode, "model_access_configured": configured})
	}
}

// PutTeamModels handles PUT /admin/v1/teams/{id}/models
func PutTeamModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		var req struct {
			Mode   string `json:"mode"`
			Models []struct {
				ModelID         string `json:"model_id"`
				Allowed         bool   `json:"allowed"`
				DailyTokenLimit *int64 `json:"daily_token_limit,omitempty"`
			} `json:"models"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
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

		if req.Mode == "" {
			req.Mode = "allowlist"
		}
		if req.Mode != "allowlist" && req.Mode != "all_active" && req.Mode != "deny_all" {
			writeError(w, "invalid_request", "请选择默认开放、指定名单或禁止全部模型")
			return
		}
		if req.Mode != "allowlist" && len(req.Models) > 0 {
			writeError(w, "invalid_request", "默认开放和全禁模式无需提交模型名单")
			return
		}
		entries := make([]*repository.TeamModel, 0, len(req.Models))
		for _, m := range req.Models {
			if m.ModelID == "" {
				continue
			}
			entries = append(entries, &repository.TeamModel{
				TeamID:          teamID,
				ModelID:         m.ModelID,
				Allowed:         m.Allowed,
				DailyTokenLimit: m.DailyTokenLimit,
				GrantedBy:       user.ID,
			})
		}

		// 校验模型存在 + 备翻译（team_models 存行ID，model_policies 存名）
		idToName, _, err := buildModelIDNameMaps(r.Context(), deps, user.TenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		for _, e := range entries {
			if _, ok := idToName[e.ModelID]; !ok {
				writeError(w, "invalid_request", "unknown model: "+e.ModelID)
				return
			}
		}

		// Default availability is independent of whitelist propagation. The
		// all-active and deny-all modes intentionally do not write project policies.
		defaultProjectID, err := portalDefaultProject(r.Context(), deps, user.TenantID, teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		var saveErr error
		if req.Mode == "allowlist" {
			saveErr = deps.TeamModelRepo.ReplaceAllowlist(r.Context(), teamID, entries)
		} else {
			saveErr = deps.TeamModelRepo.SetAccessMode(r.Context(), user.TenantID, teamID, req.Mode)
		}
		if err := saveErr; err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		// 写穿：行ID→名，覆盖该部门名下每个应用的 model_policies（chat 读的表）
		allowedNames := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.Allowed {
				allowedNames = append(allowedNames, idToName[e.ModelID])
			}
		}
		propagated := []string{}
		if req.Mode == "allowlist" {
			var err error
			propagated, err = writeTeamAllowlistToProjects(r.Context(), deps, user.TenantID, teamID, allowedNames)
			if err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
		}

		logAudit(r, deps, "team.models.update", map[string]any{
			"team_id":                teamID,
			"count":                  len(entries),
			"mode":                   req.Mode,
			"propagated_project_ids": propagated,
		}, "team", teamID)

		resp := map[string]any{"updated": len(entries), "propagated_project_ids": propagated}
		if defaultProjectID == "" {
			resp["warning"] = "该部门尚未配置默认应用；模型范围已保存，创建个人 Key 前请配置应用"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// DeleteTeamModel handles DELETE /admin/v1/teams/{id}/models/{model_id}
func DeleteTeamModel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")
		modelID := chi.URLParam(r, "model_id")

		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		if err := deps.TeamModelRepo.Delete(r.Context(), teamID, modelID); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ============================================================
// B4: GetTeamEffective
// GET /admin/v1/teams/{id}/effective
// ============================================================

// GetTeamEffective handles GET /admin/v1/teams/{id}/effective
func GetTeamEffective(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		teamWB, err := deps.TeamRepo.GetWithBudget(r.Context(), user.TenantID, teamID)
		if err != nil {
			writeError(w, "internal_error", "failed to get team budget")
			return
		}
		if teamWB == nil || teamWB.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}
		if !callerMayAccessTeam(r, deps, teamID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		members, err := deps.TeamMemberRepo.ListByTeam(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", "failed to list team members")
			return
		}
		if members == nil {
			members = []*repository.TeamMember{}
		}

		models, err := deps.TeamModelRepo.ListByTeam(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", "failed to list team models")
			return
		}
		if models == nil {
			models = []*repository.TeamModel{}
		}

		var projects []*repository.Project
		if pr, ok := deps.ProjectRepo.(*repository.ProjectRepository); ok {
			projects, _ = pr.ListByTeam(r.Context(), user.TenantID, teamID)
		}
		if projects == nil {
			projects = []*repository.Project{}
		}

		mode, configured, modeErr := deps.TeamModelRepo.GetAccessMode(r.Context(), user.TenantID, teamID)
		if modeErr != nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "无法读取部门模型配置")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team":                    teamWB,
			"members":                 members,
			"models":                  models,
			"model_access_mode":       mode,
			"model_access_configured": configured,
			"projects":                projects,
		})
	}
}

// ============================================================
// B4: GetTeamUsage
// GET /admin/v1/teams/{id}/usage?range=30d
// ============================================================

// GetTeamUsage handles GET /admin/v1/teams/{id}/usage
func GetTeamUsage(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		teamID := chi.URLParam(r, "id")

		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}
		if !callerMayAccessTeam(r, deps, teamID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found")
			return
		}

		since := rangeDays(r)
		db := deps.RequestLogRepo.DB()

		// Summary totals
		type summaryRow struct {
			TotalCost    float64
			TotalTokens  int64
			RequestCount int64
		}
		var summary summaryRow
		err = db.QueryRow(r.Context(),
			`SELECT COALESCE(SUM(total_cost),0), COALESCE(SUM(input_tokens+output_tokens),0), COUNT(*)
			FROM request_logs
			WHERE project_id IN (SELECT id FROM projects WHERE team_id=$1 AND tenant_id=$2)
			  AND created_at >= $3`,
			teamID, user.TenantID, since).Scan(
			&summary.TotalCost, &summary.TotalTokens, &summary.RequestCount)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		type dimRow struct {
			ID     string  `json:"id"`
			Label  string  `json:"label"`
			Cost   float64 `json:"cost"`
			Tokens int64   `json:"tokens"`
			Count  int64   `json:"count"`
		}

		rowsByUser := []dimRow{}
		urows, _ := db.Query(r.Context(),
			`SELECT COALESCE(rl.user_id,''), COALESCE(u.username, rl.user_id, 'unknown'),
			       SUM(rl.total_cost), SUM(rl.input_tokens+rl.output_tokens), COUNT(*)
			FROM request_logs rl
			LEFT JOIN users u ON rl.user_id=u.id
			WHERE rl.project_id IN (SELECT id FROM projects WHERE team_id=$1 AND tenant_id=$2)
			  AND rl.created_at >= $3
			GROUP BY rl.user_id, u.username ORDER BY SUM(rl.total_cost) DESC LIMIT 20`,
			teamID, user.TenantID, since)
		if urows != nil {
			defer urows.Close()
			for urows.Next() {
				var row dimRow
				_ = urows.Scan(&row.ID, &row.Label, &row.Cost, &row.Tokens, &row.Count)
				rowsByUser = append(rowsByUser, row)
			}
		}

		rowsByApp := []dimRow{}
		arows, _ := db.Query(r.Context(),
			`SELECT rl.project_id, COALESCE(p.name, rl.project_id),
			       SUM(rl.total_cost), SUM(rl.input_tokens+rl.output_tokens), COUNT(*)
			FROM request_logs rl
			LEFT JOIN projects p ON rl.project_id=p.id
			WHERE rl.project_id IN (SELECT id FROM projects WHERE team_id=$1 AND tenant_id=$2)
			  AND rl.created_at >= $3
			GROUP BY rl.project_id, p.name ORDER BY SUM(rl.total_cost) DESC LIMIT 20`,
			teamID, user.TenantID, since)
		if arows != nil {
			defer arows.Close()
			for arows.Next() {
				var row dimRow
				_ = arows.Scan(&row.ID, &row.Label, &row.Cost, &row.Tokens, &row.Count)
				rowsByApp = append(rowsByApp, row)
			}
		}

		rowsByModel := []dimRow{}
		mrows, _ := db.Query(r.Context(),
			`SELECT COALESCE(rl.model_id,''), COALESCE(m.model_label, m.model_name, rl.model_id, 'unknown'),
			       SUM(rl.total_cost), SUM(rl.input_tokens+rl.output_tokens), COUNT(*)
			FROM request_logs rl
			LEFT JOIN models m ON rl.model_id=m.id
			WHERE rl.project_id IN (SELECT id FROM projects WHERE team_id=$1 AND tenant_id=$2)
			  AND rl.created_at >= $3
			GROUP BY rl.model_id, m.model_label, m.model_name ORDER BY SUM(rl.total_cost) DESC LIMIT 20`,
			teamID, user.TenantID, since)
		if mrows != nil {
			defer mrows.Close()
			for mrows.Next() {
				var row dimRow
				_ = mrows.Scan(&row.ID, &row.Label, &row.Cost, &row.Tokens, &row.Count)
				rowsByModel = append(rowsByModel, row)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_cost":    summary.TotalCost,
			"total_tokens":  summary.TotalTokens,
			"request_count": summary.RequestCount,
			"by_member":     rowsByUser,
			"by_app":        rowsByApp,
			"by_model":      rowsByModel,
		})
	}
}

// ============================================================
// B5: PatchUserPersonalBudget
// PATCH /admin/v1/users/{id}/personal-budget
// ============================================================

// PatchUserPersonalBudget handles PATCH /admin/v1/users/{id}/personal-budget
func PatchUserPersonalBudget(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		targetUserID := chi.URLParam(r, "id")

		var req struct {
			PersonalMonthlyBudgetCNY *float64 `json:"personal_monthly_budget_cny"`
			EnforcementMode          string   `json:"enforcement_mode"`
			OverageAction            string   `json:"overage_action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		targetUser, err := deps.UserRepo.GetByID(r.Context(), targetUserID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if targetUser == nil || targetUser.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}

		// 先校验护栏配置并构造 user-scope 策略（与 SetQuotaPolicy/3.1 一致：非法 enforcement_mode/
		// overage_action 直接 400 拒绝、不静默降级；也避免预算列已落库而策略校验失败的半更新）。
		// nil（清空预算）→ monthly=0 → MonthlyBudgetLimit=0，governor 视为不约束(inert)。
		var monthly float64
		if req.PersonalMonthlyBudgetCNY != nil {
			monthly = *req.PersonalMonthlyBudgetCNY
		}
		policy, err := buildUserQuotaPolicy(user.TenantID, targetUserID, monthly, req.EnforcementMode, req.OverageAction)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		if err := deps.UserRepo.UpdatePersonalBudget(r.Context(), targetUserID, req.PersonalMonthlyBudgetCNY); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		// 同步到 quota_policies(scope_type=user)，让 gateway-core governor 能按 user_id 读取个人预算
		// （quota_cache.go: scope_type='user' AND user_id=$3）。policy 已在入口校验并构造。
		if deps.QuotaPolicyRepo != nil {
			_ = deps.QuotaPolicyRepo.CreateOrUpdate(r.Context(), policy)
		}

		logAudit(r, deps, "user.personal_budget.update", map[string]any{
			"user_id": targetUserID,
			"amount":  req.PersonalMonthlyBudgetCNY,
		}, "user", targetUserID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":                     targetUserID,
			"personal_monthly_budget_cny": req.PersonalMonthlyBudgetCNY,
		})
	}
}
