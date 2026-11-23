package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

// chat-portal 集成路由组：shared-secret 机器通道（PortalIntegrationAPIMiddleware 保护），
// 租户上下文一律取 X-JJDGuard-Tenant-Id 头（同 eval-integration 惯例，中间件不注入 user）。
const portalIntegrationTenantHeader = "X-JJDGuard-Tenant-Id"
const portalActorID = "portal-integration"
const portalIdentityBindingActor = identitybinding.ActorPortalUserSync
const maxPortalUserActiveKeys = repository.MaxPortalUserActiveKeys

func portalProjectAssigned(projectIDs []string, target string) bool {
	for _, projectID := range projectIDs {
		if projectID == target {
			return true
		}
	}
	return false
}

// portalDefaultProject only reads the current department's oldest active Chat
// application. Unassigned/conflicting identities share the existing Chat
// default application; this never provisions defaults or changes membership.
func portalDefaultProject(ctx context.Context, deps *Dependencies, tenantID, departmentID string) (string, error) {
	if deps == nil || deps.ProjectRepo == nil || departmentID == "" {
		return "", nil
	}
	projects, err := deps.ProjectRepo.List(ctx, tenantID)
	if err != nil {
		return "", err
	}
	find := func(teamID string) string {
		var selected *repository.Project
		for _, project := range projects {
			if project == nil || project.TenantID != tenantID || project.TeamID != teamID || project.Status != "active" {
				continue
			}
			if selected == nil || project.CreatedAt.Before(selected.CreatedAt) || (project.CreatedAt.Equal(selected.CreatedAt) && project.ID < selected.ID) {
				selected = project
			}
		}
		if selected == nil {
			return ""
		}
		return selected.ID
	}
	if projectID := find(departmentID); projectID != "" {
		return projectID, nil
	}
	if deps.TeamRepo == nil {
		return "", nil
	}
	department, err := deps.TeamRepo.GetBySystemKey(ctx, tenantID, "unassigned")
	if err != nil {
		return "", err
	}
	if department == nil || department.TenantID != tenantID || department.ID != departmentID {
		return "", nil
	}
	fallback, err := deps.TeamRepo.GetBySystemKey(ctx, tenantID, "chat_default")
	if err != nil {
		return "", err
	}
	if fallback == nil {
		return "", nil
	}
	return find(fallback.ID), nil
}

func portalEmployeeScopes(scopes []string) bool {
	for _, scope := range scopes {
		switch scope {
		case "chat", "models", "responses", "embeddings":
		default:
			return false
		}
	}
	return len(scopes) > 0
}

func portalActiveKeyCount(keys []*repository.InternalKey) int {
	count := 0
	for _, key := range keys {
		if key != nil && key.Status == "active" && !key.IsEmployee {
			count++
		}
	}
	return count
}

func portalTenantID(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID := strings.TrimSpace(r.Header.Get(portalIntegrationTenantHeader))
	if tenantID == "" {
		writeErrorWithStatus(w, http.StatusBadRequest, "tenant_required", "X-JJDGuard-Tenant-Id header is required")
		return "", false
	}
	return tenantID, true
}

func portalNotConfigured(w http.ResponseWriter, what string) {
	writeErrorWithStatus(w, http.StatusServiceUnavailable, "portal_integration_not_configured", what+" is not configured")
}

// GetPortalIntegrationHealth 门户后端连通性探活（中间件已验密钥，能进来即 ok）。
func GetPortalIntegrationHealth(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"status": "ok", "service": "portal-integration"})
	}
}

type CreatePortalKeyRequest struct {
	ModelAllowlist []string `json:"model_allowlist"`
	ProjectID      string   `json:"project_id"`
	UserID         string   `json:"user_id"`
	Scopes         []string `json:"scopes"`
	Name           string   `json:"name"`
	ExpiresAt      string   `json:"expires_at"`
}

// CreatePortalKey 门户侧代建数据面 key。与会话端 CreateKey 的两点刻意差异：
// scopes 必填非空（空 scopes 在数据面等于全放行，机器通道禁止）；
// user_id 留空即无归属（机器通道没有"当前用户"可默认）。
func CreatePortalKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req CreatePortalKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if len(req.Scopes) == 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "scopes_required", "portal keys must declare explicit scopes (e.g. [\"chat\",\"models\"])")
			return
		}
		scopes, err := normalizeRequestedKeyScopes(req.Scopes)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		if len(scopes) == 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "scopes_required", "portal keys must declare explicit scopes (e.g. [\"chat\",\"models\"])")
			return
		}
		name, err := normalizeKeyName(req.Name)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		expiresAt, err := parseKeyExpiresAt(req.ExpiresAt)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		if deps == nil || deps.ProjectRepo == nil || deps.KeyRepo == nil {
			portalNotConfigured(w, "repository")
			return
		}

		if req.UserID != "" {
			if deps.UserRepo == nil || deps.UserModelRepo == nil {
				portalNotConfigured(w, "user authorization repository")
				return
			}
			access, accessErr := deps.UserModelRepo.GetAccess(r.Context(), tenantID, req.UserID)
			if errors.Is(accessErr, pgx.ErrNoRows) {
				writeErrorWithStatus(w, 404, "not_found", "user not found in tenant")
				return
			}
			if accessErr != nil {
				writeErrorWithStatus(w, 503, "model_access_unavailable", "failed to read current user authorization")
				return
			}
			req.ModelAllowlist, accessErr = modelaccess.NormalizeKeyAllowlist(req.ModelAllowlist, access)
			if accessErr != nil {
				writeErrorWithStatus(w, 403, "key_model_not_authorized", "key models must be within current user authorization")
				return
			}
			if !access.ChatAllowed {
				writeErrorWithStatus(w, 403, "project_access_denied", "user has no current Chat application")
				return
			}
			req.ProjectID, accessErr = portalDefaultProject(r.Context(), deps, tenantID, access.DepartmentID)
			if accessErr != nil {
				writeErrorWithStatus(w, 503, "authorization_unavailable", "failed to read current Chat application")
				return
			}
			if req.ProjectID == "" {
				writeErrorWithStatus(w, 403, "project_access_denied", "user has no current Chat application")
				return
			}
		}
		project, err := deps.ProjectRepo.GetByID(r.Context(), tenantID, req.ProjectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			// 跨租户/不存在一律 404 掩蔽，不泄漏项目是否存在
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "project not found in tenant")
			return
		}
		if req.UserID != "" {
			if deps.UserRepo == nil || deps.ProjectUserRepo == nil {
				portalNotConfigured(w, "user project repository")
				return
			}
			targetUser, err := deps.UserRepo.GetByID(r.Context(), req.UserID)
			if err != nil {
				writeError(w, "internal_error", "failed to validate user")
				return
			}
			if targetUser == nil || targetUser.TenantID != tenantID {
				writeError(w, "invalid_request", "user not found in tenant")
				return
			}
			projectIDs, err := deps.ProjectUserRepo.GetProjectsByUser(r.Context(), req.UserID)
			if err != nil {
				writeError(w, "internal_error", "failed to validate user project access")
				return
			}
			if !portalProjectAssigned(projectIDs, req.ProjectID) {
				// Key issuance is the write boundary for local first use and
				// department moves. Recheck current identity here; never trust
				// the earlier BFF context or add an arbitrary membership.
				chatAllowed := targetUser.Status == "active" && targetUser.DepartmentAssignmentMode != identitybinding.ModeEmergency && targetUser.DepartmentAssignmentMode != "service"
				defaultProject, projectErr := portalDefaultProject(r.Context(), deps, tenantID, targetUser.DepartmentID)
				if projectErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to read current Chat application")
					return
				}
				if !chatAllowed || !portalEmployeeScopes(scopes) || defaultProject != req.ProjectID {
					writeErrorWithStatus(w, http.StatusForbidden, "project_access_denied", "user is not assigned to this project")
					return
				}
				bound, bindErr := deps.ProjectUserRepo.BindPortalDefaultProject(r.Context(), tenantID, req.UserID, req.ProjectID, targetUser.DepartmentID, targetUser.DepartmentVersion)
				if bindErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to prepare current Chat application")
					return
				}
				if !bound {
					writeErrorWithStatus(w, http.StatusForbidden, "project_access_denied", "Chat authorization changed; please retry")
					return
				}
			}
			keys, err := deps.KeyRepo.ListByUser(r.Context(), tenantID, req.UserID)
			if err != nil {
				writeError(w, "internal_error", "failed to enforce user key limit")
				return
			}
			if portalActiveKeyCount(keys) >= maxPortalUserActiveKeys {
				writeErrorWithStatus(w, http.StatusConflict, "key_limit_reached", "user already has the maximum number of active keys")
				return
			}
		}
		if req.UserID == "" && len(req.ModelAllowlist) > 0 {
			writeErrorWithStatus(w, 403, "key_model_not_authorized", "restricted keys require a user owner")
			return
		}
		rawKey := generateSecureKey()
		key := &repository.InternalKey{
			TenantID:       tenantID,
			ProjectID:      req.ProjectID,
			UserID:         req.UserID,
			Name:           name,
			Scopes:         scopes,
			ModelAllowlist: req.ModelAllowlist,
			ExpiresAt:      expiresAt,
			Status:         "active",
		}
		var createErr error
		if key.UserID != "" {
			createErr = deps.KeyRepo.CreatePortalOwned(r.Context(), key, rawKey)
		} else {
			createErr = deps.KeyRepo.Create(r.Context(), key, rawKey)
		}
		if errors.Is(createErr, repository.ErrOwnedKeyLimitReached) {
			writeErrorWithStatus(w, 409, "key_limit_reached", "user already has the maximum number of active keys")
			return
		}
		if errors.Is(createErr, repository.ErrOwnedKeyAuthorizationDenied) || errors.Is(createErr, pgx.ErrNoRows) {
			writeErrorWithStatus(w, 403, "project_access_denied", "current key authorization changed")
			return
		}
		if errors.Is(createErr, modelaccess.ErrKeyModelUnauthorized) {
			writeErrorWithStatus(w, 403, "key_model_not_authorized", "key models exceed current authorization")
			return
		}
		if createErr != nil {
			writeError(w, "internal_error", "failed to create key")
			return
		}
		portalLogAudit(r, deps, tenantID, "portal_create_key", map[string]interface{}{
			"key_id": key.ID, "project_id": key.ProjectID, "user_id": key.UserID, "name": name,
		}, "key", key.ID)
		resp := types.KeyInfo{
			ID: key.ID, ProjectID: key.ProjectID, UserID: key.UserID, Name: key.Name,
			KeyPrefix: key.KeyPrefix, Scopes: key.Scopes, FullKey: rawKey, Status: key.Status,
			CreatedAt: key.CreatedAt.Format(time.RFC3339),
		}
		if key.ExpiresAt != nil {
			resp.ExpiresAt = key.ExpiresAt.Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			types.KeyInfo
			ModelAllowlist []string `json:"model_allowlist"`
		}{resp, key.ModelAllowlist})
	}
}

// RevokePortalKey 吊销租户内 key；跨租户/不存在一律 404 掩蔽。
func RevokePortalKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		w.Header().Set("Cache-Control", "private, no-store")
		tenant, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		user := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if id == "" {
			writeError(w, "invalid_request", "key id is required")
			return
		}
		key, err := deps.KeyRepo.GetByID(r.Context(), tenant, id)
		if err != nil {
			writeError(w, "internal_error", "failed to load key")
			return
		}
		if key == nil || (key.UserID != "" && (user == "" || key.UserID != user)) || (key.UserID == "" && user != "") {
			writeErrorWithStatus(w, 404, "not_found", "key not found")
			return
		}
		if key.UserID != "" {
			found, err := deps.KeyRepo.RevokeOwned(r.Context(), tenant, id, user)
			if err != nil {
				writeErrorWithStatus(w, 503, "key_revoke_unavailable", "key revocation unavailable")
				return
			}
			if !found {
				writeErrorWithStatus(w, 404, "not_found", "key not found")
				return
			}
		} else {
			// Unowned service-Key management retains the existing integration contract.
			if err = deps.KeyRepo.Revoke(r.Context(), tenant, id); err != nil {
				writeError(w, "internal_error", "failed to revoke key")
				return
			}
			portalLogAudit(r, deps, tenant, "portal_revoke_key", map[string]interface{}{"key_id": id}, "key", id)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListPortalKeys 列项目下 key。project_id 必填：门户按项目管理，不给整租户全量。
func ListPortalKeys(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
		if projectID == "" {
			writeError(w, "invalid_request", "project_id is required")
			return
		}
		if deps == nil || deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}
		keys, err := deps.KeyRepo.List(r.Context(), tenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to list keys")
			return
		}
		data := make([]types.KeyInfo, len(keys))
		for i, k := range keys {
			data[i] = types.KeyInfo{
				ID:        k.ID,
				ProjectID: k.ProjectID,
				UserID:    k.UserID,
				Name:      k.Name,
				KeyPrefix: k.KeyPrefix,
				Scopes:    k.Scopes,
				Status:    k.Status,
				CreatedAt: k.CreatedAt.Format(time.RFC3339),
			}
			if k.ExpiresAt != nil {
				data[i].ExpiresAt = k.ExpiresAt.Format(time.RFC3339)
			}
		}
		writeJSON(w, types.KeyListResponse{Data: data, Total: len(data)})
	}
}

// GetPortalUsageByKey 按 key 维度用量。默认租户全量 scope（门户后端本身即租户级代理）；
// 可选 project_ids（逗号分隔）→ 服务端按项目收窄，供门户部门主管视图下推。
func GetPortalUsageByKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.UsageDailyRepo == nil {
			portalNotConfigured(w, "usage repository")
			return
		}
		startDate, endDate := parseUsageRange(r)
		scope := portalUsageScope(r, tenantID)
		items, err := deps.UsageDailyRepo.GetByKey(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage by key")
			return
		}
		writeJSON(w, mapCostDimensionRows(items))
	}
}

// GetPortalTeamModels 同 GetTeamModels，租户来源换 header；跨租户 404 掩蔽。
func GetPortalTeamModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		teamID := chi.URLParam(r, "id")
		if deps == nil || deps.TeamRepo == nil || deps.TeamModelRepo == nil {
			portalNotConfigured(w, "team repository")
			return
		}
		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if team == nil || team.TenantID != tenantID {
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
		writeJSON(w, map[string]any{"data": models})
	}
}

// GetPortalTeamEffective 同 GetTeamEffective，租户来源换 header。
func GetPortalTeamEffective(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		teamID := chi.URLParam(r, "id")
		if deps == nil || deps.TeamRepo == nil || deps.TeamMemberRepo == nil || deps.TeamModelRepo == nil {
			portalNotConfigured(w, "team repository")
			return
		}
		teamWB, err := deps.TeamRepo.GetWithBudget(r.Context(), tenantID, teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if teamWB == nil || teamWB.TenantID != tenantID {
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
		models, err := deps.TeamModelRepo.ListByTeam(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if models == nil {
			models = []*repository.TeamModel{}
		}
		var projects []*repository.Project
		if pr, isConcrete := deps.ProjectRepo.(*repository.ProjectRepository); isConcrete {
			projects, _ = pr.ListByTeam(r.Context(), tenantID, teamID)
		}
		if projects == nil {
			projects = []*repository.Project{}
		}
		writeJSON(w, map[string]any{
			"team":     teamWB,
			"members":  members,
			"models":   models,
			"projects": projects,
		})
	}
}

// GetPortalModelPolicy 同 GetModelPolicy，租户来源换 header；无策略时返默认空 allow/deny。
func GetPortalModelPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		projectID := r.URL.Query().Get("project_id")
		if projectID == "" {
			writeError(w, "invalid_request", "project_id is required")
			return
		}
		if deps == nil || deps.ModelPolicyRepo == nil {
			portalNotConfigured(w, "model policy repository")
			return
		}
		policy, err := deps.ModelPolicyRepo.GetByProject(r.Context(), tenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get model policy")
			return
		}
		if policy == nil {
			writeJSON(w, types.ModelPolicyInfo{
				ProjectID: projectID,
				AllowList: []string{},
				DenyList:  []string{},
			})
			return
		}
		writeJSON(w, types.ModelPolicyInfo{
			ID:        policy.ID,
			TenantID:  policy.TenantID,
			ProjectID: policy.ProjectID,
			AllowList: policy.AllowList,
			DenyList:  policy.DenyList,
		})
	}
}

// ListPortalModels 同 ListModels，租户来源换 header（复用其 repo 调用与响应结构）。
func ListPortalModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.ModelRepo == nil {
			portalNotConfigured(w, "model repository")
			return
		}
		models, err := deps.ModelRepo.List(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list models")
			return
		}
		data := make([]types.ModelInfo, len(models))
		for i, m := range models {
			data[i] = types.ModelInfo{
				ID:                 m.ID,
				ProviderID:         m.ProviderID,
				ModelName:          m.ModelName,
				ModelLabel:         m.ModelLabel,
				FallbackProviderID: getFallbackProviderID(m.Capabilities),
				ProxyConfig:        m.ProxyConfig,
				Capabilities:       m.Capabilities,
				Status:             m.Status,
				CreatedAt:          m.CreatedAt.Format(time.RFC3339),
			}
		}
		writeJSON(w, types.ModelListResponse{Data: data, Total: len(data)})
	}
}

// ListPortalProjects 列租户全部 project（租户取 header）。复用会话 ListProjects 的 repo 调用。
func ListPortalProjects(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.ProjectRepo == nil {
			portalNotConfigured(w, "project repository")
			return
		}
		projects, err := deps.ProjectRepo.List(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list projects")
			return
		}
		data := make([]types.ProjectInfo, len(projects))
		for i, p := range projects {
			data[i] = types.ProjectInfo{
				ID:        p.ID,
				Name:      p.Name,
				TenantID:  p.TenantID,
				Code:      p.Code,
				Status:    p.Status,
				CreatedAt: p.CreatedAt.Format(time.RFC3339),
			}
		}
		writeJSON(w, types.ProjectListResponse{Data: data, Total: len(data)})
	}
}

// ListPortalTeams 列租户全部 team（租户取 header）。复用会话 ListTeams 的 repo 调用。
func ListPortalTeams(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.TeamRepo == nil {
			portalNotConfigured(w, "team repository")
			return
		}
		teams, err := deps.TeamRepo.ListByTenant(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list teams")
			return
		}
		if teams == nil {
			teams = []*repository.Team{}
		}
		writeJSON(w, map[string]any{"data": teams})
	}
}

type CreatePortalProjectRequest struct {
	Name        string `json:"name"`
	Code        string `json:"code"`
	Environment string `json:"environment"`
	TeamID      string `json:"team_id"`
}

// CreatePortalProject 门户侧建 project（租户取 header）。与会话端 CreateProject 的差异：
// 无会话用户 → owner_user_id 落 NULL（repo 对空 owner 已转 NULL）；可选挂 team_id，
// 建前先校验 team 属本租户，跨租户/不存在一律 404 掩蔽。
func CreatePortalProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req CreatePortalProjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, "invalid_request", "name is required")
			return
		}
		if deps == nil || deps.ProjectRepo == nil {
			portalNotConfigured(w, "project repository")
			return
		}
		teamID := strings.TrimSpace(req.TeamID)
		if teamID != "" {
			if deps.TeamRepo == nil {
				portalNotConfigured(w, "team repository")
				return
			}
			team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
			if err != nil {
				writeError(w, "internal_error", "failed to validate team")
				return
			}
			// 跨租户/不存在一律 404 掩蔽，不泄漏团队是否存在
			if team == nil || team.TenantID != tenantID {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found in tenant")
				return
			}
		}
		project := &repository.Project{
			TenantID:    tenantID,
			Name:        req.Name,
			Code:        req.Code,
			Environment: req.Environment,
			Status:      "active",
			// OwnerUserID 留空：机器通道无当前用户，repo 将空 owner 转 NULL
		}
		if err := deps.ProjectRepo.Create(r.Context(), project); err != nil {
			writeError(w, "internal_error", "failed to create project")
			return
		}
		if teamID != "" {
			// 挂 team 需具体仓库的 UpdateTeam（接口未暴露，沿用 GetPortalTeamEffective 的断言惯例）
			pr, isConcrete := deps.ProjectRepo.(*repository.ProjectRepository)
			if !isConcrete {
				portalNotConfigured(w, "project repository (team assignment)")
				return
			}
			if err := pr.UpdateTeam(r.Context(), tenantID, project.ID, teamID); err != nil {
				writeError(w, "internal_error", "failed to assign team")
				return
			}
			project.TeamID = teamID
		}
		portalLogAudit(r, deps, tenantID, "portal_create_project", map[string]interface{}{
			"project_id": project.ID, "name": project.Name, "team_id": teamID,
		}, "project", project.ID)
		resp := types.ProjectInfo{
			ID:        project.ID,
			Name:      project.Name,
			TenantID:  project.TenantID,
			Code:      project.Code,
			Status:    project.Status,
			CreatedAt: project.CreatedAt.Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

type PortalModelPolicyRequest struct {
	ProjectID string   `json:"project_id"`
	AllowList []string `json:"allow_list"`
	DenyList  []string `json:"deny_list"`
}

// SetPortalModelPolicy 设 project 模型策略 allow/deny（租户取 header）。复用会话 SetModelPolicy
// 逻辑；项目跨租户/不存在一律 404 掩蔽（会话端返 not_found 400，机器通道统一真 404）。
func SetPortalModelPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req PortalModelPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		projectID := strings.TrimSpace(req.ProjectID)
		if projectID == "" {
			writeError(w, "invalid_request", "project_id is required")
			return
		}
		if deps == nil || deps.ProjectRepo == nil || deps.ModelPolicyRepo == nil {
			portalNotConfigured(w, "model policy repository")
			return
		}
		project, err := deps.ProjectRepo.GetByID(r.Context(), tenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "project not found in tenant")
			return
		}
		allowList := req.AllowList
		if allowList == nil {
			allowList = []string{}
		}
		denyList := req.DenyList
		if denyList == nil {
			denyList = []string{}
		}
		policy := &repository.ModelPolicy{
			TenantID:  tenantID,
			ProjectID: projectID,
			ScopeType: "project",
			AllowList: allowList,
			DenyList:  denyList,
		}
		if err := deps.ModelPolicyRepo.CreateOrUpdate(r.Context(), policy); err != nil {
			writeError(w, "internal_error", "failed to set model policy")
			return
		}
		portalLogAudit(r, deps, tenantID, "portal_set_model_policy", map[string]interface{}{
			"project_id": projectID, "allow_list": allowList, "deny_list": denyList,
		}, "model_policy", policy.ID)
		writeJSON(w, types.ModelPolicyInfo{
			ID:        policy.ID,
			TenantID:  policy.TenantID,
			ProjectID: policy.ProjectID,
			AllowList: policy.AllowList,
			DenyList:  policy.DenyList,
		})
	}
}

type CreatePortalTeamRequest struct {
	Name         string `json:"name"`
	ParentTeamID string `json:"parent_team_id"`
}

// CreatePortalTeam 门户侧建 team（租户取 header）。复用会话 CreateTeam 逻辑（含 ValidateTeamDepth
// 深度校验）；parent_team_id 跨租户/不存在一律 404 掩蔽（会话端返 not_found 400）。
func CreatePortalTeam(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req CreatePortalTeamRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, "invalid_request", "name is required")
			return
		}
		if deps == nil || deps.TeamRepo == nil || deps.OrgService == nil {
			portalNotConfigured(w, "team repository")
			return
		}
		parentPath := ""
		if req.ParentTeamID != "" {
			parent, err := deps.TeamRepo.GetByID(r.Context(), req.ParentTeamID)
			if err != nil {
				writeError(w, "internal_error", "failed to get parent team")
				return
			}
			// 跨租户/不存在一律 404 掩蔽
			if parent == nil || parent.TenantID != tenantID {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "parent team not found in tenant")
				return
			}
			parentPath = parent.Path
		}
		team := &repository.Team{
			ID:           "team_" + uuid.New().String()[:8],
			TenantID:     tenantID,
			Name:         req.Name,
			ParentTeamID: req.ParentTeamID,
		}
		if err := deps.TeamRepo.Create(r.Context(), team, parentPath); err != nil {
			writeError(w, "internal_error", "failed to create team")
			return
		}
		if err := deps.OrgService.ValidateTeamDepth(team.Path); err != nil {
			_ = deps.TeamRepo.Delete(r.Context(), team.ID)
			writeError(w, "invalid_request", err.Error())
			return
		}
		portalLogAudit(r, deps, tenantID, "portal_create_team", map[string]interface{}{
			"team_id": team.ID, "name": team.Name, "parent_team_id": team.ParentTeamID,
		}, "team", team.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(team)
	}
}

// portalSecurityEventFilterFromRequest 解析安全事件过滤参数。
// 与会话端 ListSecurityEvents 不同：机器通道轮询语义，强加默认 24h 有界时间窗防全表扫。
func portalSecurityEventFilterFromRequest(r *http.Request) (repository.SecurityEventFilter, error) {
	q := r.URL.Query()
	clientID := strings.TrimSpace(q.Get("client_id"))
	if clientID == "" {
		clientID = strings.TrimSpace(q.Get("key_id"))
	}
	filter := repository.SecurityEventFilter{
		AgentInstanceID: strings.TrimSpace(q.Get("agent_instance_id")),
		UserID:          strings.TrimSpace(q.Get("user_id")),
		ClientID:        clientID,
		Severity:        strings.TrimSpace(q.Get("severity")),
		EventType:       strings.TrimSpace(q.Get("event_type")),
		ProjectIDs:      parseCommaProjectIDs(q.Get("project_ids")),
	}
	start, end, err := defaultBoundedTimeWindow(r, 24*time.Hour)
	if err != nil {
		return filter, err
	}
	if filter.AgentInstanceID != "" && !validIntegrationAgentFilter(filter.AgentInstanceID) {
		return filter, errors.New("invalid agent_instance_id")
	}
	filter.StartTime = &start
	filter.EndTime = &end
	return filter, nil
}

// ListPortalAuditEvents (G3) 门户按 key/用户/严重度拉安全事件（脱敏摘要，不含原文）。
func ListPortalAuditEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		limit, err := parseEvalIntegrationLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_limit", err.Error())
			return
		}
		offset, err := parseEvalIntegrationCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_cursor", err.Error())
			return
		}
		filter, err := portalSecurityEventFilterFromRequest(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_time_range", err.Error())
			return
		}
		if deps == nil || deps.SecurityEventRepo == nil {
			portalNotConfigured(w, "security event repository")
			return
		}
		events, total, err := deps.SecurityEventRepo.ListFiltered(r.Context(), tenantID, filter, limit, offset)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "security_event_query_failed", "failed to query security events")
			return
		}
		data := make([]types.SecurityEventInfo, len(events))
		for i, e := range events {
			// 门户集成没有登录用户，按约定只给脱敏摘要：命中原文（2.9.22 起入库）一律剔除。
			data[i] = securityEventInfoForViewer(e, false)
		}
		writeJSON(w, types.SecurityEventListResponse{Data: data, Total: total})
	}
}

// portalLogAudit：shared-secret 组无 session user，logAudit 会静默丢；
// 这里直接写 audit_operations（user_id 空串经 NULLIF 落 NULL，actor 记在 detail），
// 复用 A1 的 CreateAuditOperation NULLIF 改造。
func portalLogAudit(r *http.Request, deps *Dependencies, tenantID, actionType string, detail map[string]interface{}, targetType, targetID string) {
	if deps == nil || deps.SystemRepo == nil {
		return
	}
	if detail == nil {
		detail = map[string]interface{}{}
	}
	detail["actor"] = portalActorID
	detail["tenant_id"] = tenantID
	op := &repository.AuditOperation{
		ID:           uuid.New().String(),
		UserID:       "",
		ActionType:   actionType,
		ActionDetail: detail,
		TargetType:   targetType,
		TargetID:     targetID,
		IPAddress:    r.RemoteAddr,
	}
	if err := deps.SystemRepo.CreateAuditOperation(r.Context(), op); err != nil {
		log.Print("component=portal_integration stage=audit_write error_code=audit_write_failed")
	}
	if deps.AuditAppender != nil {
		deps.AuditAppender.Enqueue(tenantID, "audit_op", op.ID, detail)
	}
}

// ========== Phase4：门户员工↔网关 user/team 打通（惰性、幂等、可开可关）==========

// EnsurePortalUserRequest 门户按稳定身份（issuer+source_type+subject）惰性建/绑定 user 的入参。
// 字段来源：已验证 OIDC token 的 iss/sub/departments/groups/preferred_username/email，由门户服务端注入；
// 浏览器 body 任何覆盖都被门户侧忽略——以控制面返回的 user_id/department_id/chat_allowed 为授权依据。
type EnsurePortalUserRequest struct {
	Issuer          string   `json:"issuer"`
	SourceType      string   `json:"source_type"`
	ExternalSubject string   `json:"external_subject"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	Departments     []string `json:"departments"`
	Groups          []string `json:"groups"`
}

// EnsurePortalUserResponse 冻结契约：
//   - user_id/department_id/chat_allowed 是门户授权依据（非 OIDC sub）；
//   - resolution 反映本次解析模式（automatic/manual/unassigned/emergency/conflict）。
type EnsurePortalUserResponse struct {
	UserID        string `json:"user_id"`
	DepartmentID  string `json:"department_id"`
	ProjectID     string `json:"project_id,omitempty"`
	ChatAllowed   bool   `json:"chat_allowed"`
	PortalAllowed bool   `json:"portal_allowed"`
	Resolution    string `json:"resolution"`
	Created       bool   `json:"created"`
	// DepartmentVersion 是 users.department_version 的单调授权 revision。
	// revision 变化时，门户必须丢弃旧授权并刷新。
	DepartmentVersion int64 `json:"department_version"`
}

// EnsurePortalUser 委托 identitybinding.Service.BindAndResolve 完成稳定身份绑定 + 部门解析。
// 稳定键 = (tenant+issuer+source_type+subject)：同 email 不同 subject 各自独立绑定，不自动合并；
// 同稳定键并发只创建一个绑定（事务内 CreateLinkOrGet 兜底）。配额闸只在真正可能新建前拦一道。
// 旧 users.external_subject 字段不再作为唯一事实源；兼容投影由 identitybinding 维护，本 handler 不再写入。
func EnsurePortalUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req EnsurePortalUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		issuer := strings.TrimSpace(req.Issuer)
		sourceType := strings.ToLower(strings.TrimSpace(req.SourceType))
		subject := strings.TrimSpace(req.ExternalSubject)
		username := strings.TrimSpace(req.Username)
		email := strings.TrimSpace(req.Email)
		// 兼容已发布的 portal-proxy 镜像：旧镜像只提交 external_subject/email，
		// issuer/source_type/username 由控制面按当前运行态补齐。source_id 仍只从服务端
		// active identity source 解析，绝不接受旧客户端传入的来源 ID。
		legacyPortalProxyRequest := issuer == "" && sourceType == ""
		if legacyPortalProxyRequest && deps != nil {
			issuer = strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL)
			sourceType = "oidc"
			if username == "" {
				username = email
			}
		}
		if issuer == "" {
			writeError(w, "invalid_request", "issuer is required")
			return
		}
		if sourceType == "" {
			writeError(w, "invalid_request", "source_type is required")
			return
		}
		if subject == "" {
			writeError(w, "invalid_request", "external_subject is required")
			return
		}
		if username == "" {
			writeError(w, "invalid_request", "username is required")
			return
		}
		if deps == nil || deps.IdentityBindingService == nil || deps.UserRepo == nil {
			portalNotConfigured(w, "identity binding service")
			return
		}
		// The employee portal is self-bootstrapping. This call is idempotent and
		// creates only missing Chat context; it never changes an administrator's
		// existing team/model/identity configuration. A deployment can therefore
		// be used immediately after the admin configures providers and models.
		if deps.ChatDefaultsEnsurer != nil {
			if err := deps.ChatDefaultsEnsurer.EnsureChatDefaults(r.Context(), tenantID); err != nil {
				log.Print("component=portal_integration stage=chat_defaults error_code=chat_defaults_unavailable")
				writeError(w, "internal_error", "failed to prepare Chat authorization")
				return
			}
		}

		// 配额闸前置：License MaxUsers>0 才生效，满则 402 降级，绝不进 BindAndResolve。
		// Source-scoped department mappings must use the server-side identity
		// source ID. Never accept a source_id from the portal/browser body.
		sourceID := ""
		if sourceType == "oidc" && deps.IdentitySourceLookup != nil {
			runtimeIssuer := strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL)
			if runtimeIssuer != "" && issuer != runtimeIssuer {
				writeErrorWithStatus(w, http.StatusBadRequest, "identity_issuer_not_runtime", "identity issuer does not match the configured runtime issuer")
				return
			}
			source, lookupErr := deps.IdentitySourceLookup.GetActive(r.Context(), tenantID)
			if lookupErr != nil {
				writeError(w, "internal_error", "failed to resolve identity source")
				return
			}
			// The runtime issuer also fronts local/LDAP/AD account-login. Those
			// identities remain valid when no enterprise OIDC source is active;
			// they simply cannot match source-scoped enterprise mappings.
			if source != nil {
				sourceID = strings.TrimSpace(source.ID)
			}
		}

		// 闸通过不代表必然新建（命中既有身份也会过闸但不建）；闸失败一律拒。
		if ok := enforceMaxUsersForActiveUser(w, r, deps); !ok {
			return
		}

		identity := identitybinding.ExternalIdentity{
			SourceID:        sourceID,
			TenantID:        tenantID,
			Issuer:          issuer,
			SourceType:      sourceType,
			ExternalSubject: subject,
			Username:        username,
			Email:           email,
			Departments:     req.Departments,
			Groups:          req.Groups,
		}
		resolution, err := deps.IdentityBindingService.BindAndResolve(r.Context(), identity)
		if err != nil {
			if errors.Is(err, identitybinding.ErrInvalidIdentity) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid external identity")
				return
			}
			if errors.Is(err, identitybinding.ErrNotFound) {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "identity_not_ready", "个人入口尚未配置完成，请管理员检查身份绑定与未分配部门")
				return
			}
			if errors.Is(err, identitybinding.ErrConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "identity_conflict", "用户名与已有身份冲突，请管理员在用户管理中合并账号或换绑身份")
				return
			}
			writeError(w, "internal_error", "failed to resolve identity")
			return
		}
		// 身份绑定完成后，把员工自动关联到 JJDGuard 管理的应用，并把同一
		// project_id 返回给 Chat JIT 签 key。这样模型权限只在 JJDGuard 配置。
		projectID := ""
		if resolution.ChatAllowed && deps.ProjectUserRepo != nil {
			candidate, projectErr := portalDefaultProject(r.Context(), deps, tenantID, resolution.DepartmentID)
			if projectErr == nil && candidate != "" {
				currentUser, readErr := deps.UserRepo.GetByID(r.Context(), resolution.UserID)
				if readErr == nil && currentUser != nil && bindEmployeeProject(r.Context(), deps, tenantID, currentUser, candidate) == nil {
					projectID = candidate
				}
			}
		}
		if deps.EmployeeKeyRepo != nil && resolution.ChatAllowed && resolution.PortalAllowed && projectID != "" && deps.ProjectUserRepo != nil {
			user, userErr := deps.UserRepo.GetByID(r.Context(), resolution.UserID)
			if userErr == nil && user != nil && user.TenantID == tenantID && user.Status == "active" {
				_, _, _ = ensureEmployeeCredential(r.Context(), deps, tenantID, user, projectID)
			}
		}
		portalLogAudit(r, deps, tenantID, "portal_ensure_user", map[string]interface{}{
			"user_id":       resolution.UserID,
			"department_id": resolution.DepartmentID,
			"resolution":    resolution.Mode,
			"chat_allowed":  resolution.ChatAllowed,
		}, "user", resolution.UserID)
		writeJSON(w, EnsurePortalUserResponse{
			UserID:        resolution.UserID,
			DepartmentID:  resolution.DepartmentID,
			ProjectID:     projectID,
			ChatAllowed:   resolution.ChatAllowed,
			PortalAllowed: resolution.PortalAllowed,
			Resolution:    resolution.Mode,
			Created: resolution.Changed && (resolution.Mode == identitybinding.ModeAutomatic ||
				resolution.Mode == identitybinding.ModeUnassigned ||
				resolution.Mode == identitybinding.ModeConflict),
			DepartmentVersion: resolution.DepartmentVersion,
		})
	}
}

// EnsureTeamMemberRequest 挂 user 到 team 的入参（team 取 URL {id}）。
type EnsureTeamMemberRequest struct {
	UserID string `json:"user_id"`
}

// EnsureTeamMemberResponse 冻结契约：回显 team_id/user_id/role。
type EnsureTeamMemberResponse struct {
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// EnsureTeamMember 幂等把 user 挂到 team（复用 TeamMemberRepo.Add 的 ON CONFLICT），
// 让网关「团队管理」看到部门成员。team 与 user 均须属本租户，跨租户/不存在一律 404 掩蔽。
// 幂等语义：首次与重复调用都返 200（非 201，不承诺"新建"）。
func EnsureTeamMember(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		teamID := strings.TrimSpace(chi.URLParam(r, "id"))
		if teamID == "" {
			writeError(w, "invalid_request", "team id is required")
			return
		}
		var req EnsureTeamMemberRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			writeError(w, "invalid_request", "user_id is required")
			return
		}
		if deps == nil || deps.TeamRepo == nil || deps.UserRepo == nil ||
			deps.IdentityBindingService == nil {
			portalNotConfigured(w, "team repository")
			return
		}

		// 校验 team 属本租户（跨租户/不存在一律 404 掩蔽）
		team, err := deps.TeamRepo.GetByID(r.Context(), teamID)
		if err != nil {
			writeError(w, "internal_error", "failed to get team")
			return
		}
		if team == nil || team.TenantID != tenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "team not found in tenant")
			return
		}

		// 校验 user 属本租户（避免把外租户 user 挂进来，跨租户 404 掩蔽）
		targetUser, err := deps.UserRepo.GetByID(r.Context(), userID)
		if err != nil {
			writeError(w, "internal_error", "failed to get user")
			return
		}
		if targetUser == nil || targetUser.TenantID != tenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found in tenant")
			return
		}

		const role = "member"
		if err := deps.IdentityBindingService.AssignManyManually(
			r.Context(), tenantID, []string{userID}, teamID, role, portalIdentityBindingActor,
		); err != nil {
			writeIdentityBindingMutationError(w, err)
			return
		}
		portalLogAudit(r, deps, tenantID, "portal_ensure_team_member", map[string]interface{}{
			"team_id": teamID, "user_id": userID, "role": role,
		}, "team", teamID)
		// 员工经 SSO 挂进部门 → 自动关联本部门默认应用（best-effort，与手工加成员口径一致）。
		linkUserToTeamDefaultApp(r.Context(), deps, tenantID, teamID, userID)
		writeJSON(w, EnsureTeamMemberResponse{TeamID: teamID, UserID: userID, Role: role})
	}
}

// GetPortalChatPortalStatus 只读返回 Chat/SSO 门户暴露开关（系统设置 chat_portal_enabled）。
// 供 portal-proxy 判断是否放行门户流量（chat-edge 整站门控 + 数据面兜底）。全局设置，不分租户。
// 读失败保守按 false（未启用/不暴露）返回，抖动由 portal-proxy 侧 stale 缓存兜。
func GetPortalChatPortalStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enabled := false
		if deps != nil && deps.SystemRepo != nil {
			v, err := deps.SystemRepo.GetBool(r.Context(), "chat_portal_enabled")
			if err != nil {
				// 读不到开关不等于开关关闭：答 false 会让门户整站显示「门户未启用」。
				// 返回 503，由门户沿用最近一次确定值或按自身策略处理。
				w.Header().Set("Retry-After", "3")
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_portal_status_unavailable", "门户开关暂时无法读取，请稍后重试")
				return
			}
			enabled = v
		}
		writeJSON(w, map[string]interface{}{"enabled": enabled})
	}
}

// GetPortalUserAuthorizationContext returns request-time authorization for one portal user.
func GetPortalUserAuthorizationContext(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.UserRepo == nil || deps.TeamModelRepo == nil {
			portalNotConfigured(w, "user authorization repository")
			return
		}
		userID := chi.URLParam(r, "id")
		user, err := deps.UserRepo.GetByID(r.Context(), userID)
		if err != nil {
			writeError(w, "internal_error", "failed to read user authorization")
			return
		}
		if user == nil || user.TenantID != tenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		// A bound proxy must prove that subject and user still refer to the
		// same existing runtime identity. No claims are reconstructed here.
		loginMode := r.URL.Query().Get("login_mode")
		if loginMode != "" && loginMode != "local" && loginMode != "oidc" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_login_mode", "invalid login mode")
			return
		}
		if r.URL.Query().Has("external_subject") || loginMode == "local" {
			subject := strings.TrimSpace(r.URL.Query().Get("external_subject"))
			if loginMode == "local" {
				if deps.ChatLoginTickets == nil {
					portalNotConfigured(w, "local identity binding lookup")
					return
				}
				localIdentity, identityErr := deps.ChatLoginTickets.CurrentIdentity(r.Context(), tenantID, user.ID,
					strings.TrimSuffix(strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL), "/"))
				if identityErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to read local login authorization")
					return
				}
				if r.URL.Query().Has("local_credential_version") && (localIdentity == nil || r.URL.Query().Get("local_credential_version") != strconv.FormatInt(localIdentity.LocalCredentialVersion, 10)) {
					writeErrorWithStatus(w, http.StatusForbidden, "authorization_denied", "local login credential has changed")
					return
				}
				if subject == "" || localIdentity == nil || localIdentity.ExternalSubject != subject {
					writeErrorWithStatus(w, http.StatusNotFound, "not_found", "local user identity not found")
					return
				}
			} else {
				issuer := strings.TrimSuffix(strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL), "/")
				reader, configured := deps.UserIdentityLinkLookup.(interface {
					GetByStableKey(context.Context, identitybinding.ExternalIdentity) (*identitybinding.UserIdentityLink, error)
				})
				if !configured || issuer == "" {
					portalNotConfigured(w, "identity binding lookup")
					return
				}
				sourceID := ""
				if deps.IdentitySourceLookup != nil {
					source, sourceErr := deps.IdentitySourceLookup.GetActive(r.Context(), tenantID)
					if sourceErr != nil {
						writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to read identity source")
						return
					}
					if source != nil {
						sourceID = source.ID
					}
				}
				link, linkErr := reader.GetByStableKey(r.Context(), identitybinding.ExternalIdentity{TenantID: tenantID, Issuer: issuer, SourceID: sourceID, SourceType: "oidc", ExternalSubject: subject})
				if linkErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to read identity binding")
					return
				}
				if subject == "" || link == nil || link.UserID != user.ID || link.TenantID != tenantID {
					writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user identity not found")
					return
				}
			}
		}
		modelNames := make([]string, 0)
		if user.DepartmentID != "" {
			modelNames, err = deps.TeamModelRepo.ListAllowedModelNames(r.Context(), tenantID, user.DepartmentID)
			if err != nil {
				writeError(w, "internal_error", "failed to read user authorization")
				return
			}
		}
		portalAllowed := user.Status == "active" && roles.CanLoginPortal(user.Role) && user.DepartmentAssignmentMode != "service"
		chatAllowed := portalAllowed && user.DepartmentAssignmentMode != identitybinding.ModeEmergency
		var modelAccessVersion int64
		var modelAccess *modelaccess.Access
		if deps.UserModelRepo != nil {
			access, accessErr := deps.UserModelRepo.GetAccess(r.Context(), tenantID, user.ID)
			if accessErr != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "model_access_unavailable", "failed to read user authorization")
				return
			}
			modelAccess = access
			modelNames = access.EffectiveModels
			modelAccessVersion = access.Version
			user.DepartmentID = access.DepartmentID
			user.DepartmentName = access.DepartmentName
			user.DepartmentVersion = access.DepartmentVersion
			chatAllowed = access.ChatAllowed
		}
		projectID := ""
		if chatAllowed {
			projectID, err = portalDefaultProject(r.Context(), deps, tenantID, user.DepartmentID)
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to read current Chat application")
				return
			}
		}
		localLoginAllowed := false
		localExternalSubject := ""
		var localCredentialVersion int64
		if deps.ChatLoginTickets != nil {
			localIdentity, identityErr := deps.ChatLoginTickets.CurrentIdentity(r.Context(), tenantID, user.ID,
				strings.TrimSuffix(strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL), "/"))
			if identityErr != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "failed to read local login authorization")
				return
			}
			if localIdentity != nil {
				localLoginAllowed = true
				localExternalSubject = localIdentity.ExternalSubject
				localCredentialVersion = localIdentity.LocalCredentialVersion
			}
		}
		modelAccessMode := modelaccess.Inherit
		departmentModels, personalAllowlist, staleModels := []string{}, []string{}, []string{}
		extraGrants := []modelaccess.ExtraGrant{}
		modelSources := map[string]string{}
		if modelAccess != nil {
			modelAccessMode = modelAccess.Mode
			departmentModels = modelAccess.DepartmentModels
			personalAllowlist = modelAccess.ModelNames
			extraGrants = modelAccess.ExtraGrants
			modelSources = modelAccess.ModelSources
			staleModels = modelAccess.StaleModels
		}

		historyUserIDs := []string{user.ID}
		if deps.UserAccountMergeRepo != nil {
			historyUserIDs, err = deps.UserAccountMergeRepo.HistoryUserIDs(r.Context(), tenantID, user.ID)
			if err != nil {
				writeErrorWithStatus(w, 503, "authorization_unavailable", "failed to read account attribution")
				return
			}
		}
		departmentVersion := user.DepartmentVersion
		writeJSON(w, map[string]any{"data": map[string]any{
			"user_id": user.ID, "department_id": user.DepartmentID, "project_id": projectID,
			"department_name": user.DepartmentName, "department_version": departmentVersion,
			"portal_allowed":           portalAllowed,
			"chat_allowed":             chatAllowed,
			"model_ids":                modelNames,
			"model_access_version":     modelAccessVersion,
			"model_access_mode":        modelAccessMode,
			"department_models":        departmentModels,
			"personal_allowlist":       personalAllowlist,
			"extra_grants":             extraGrants,
			"model_sources":            modelSources,
			"stale_models":             staleModels,
			"history_user_ids":         historyUserIDs,
			"local_login_allowed":      localLoginAllowed,
			"local_external_subject":   localExternalSubject,
			"local_credential_version": localCredentialVersion,
		}})
	}
}
