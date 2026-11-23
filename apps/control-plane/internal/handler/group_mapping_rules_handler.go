package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 分组映射规则（部门→网关项目）后台管理 + portal-proxy 读侧。从门户 SQLite 迁入网关。

type groupMappingRuleDTO struct {
	ID               string `json:"id"`
	MatchType        string `json:"match_type"`
	MatchValue       string `json:"match_value"`
	MappedGroup      string `json:"mapped_group"`
	GatewayProjectID string `json:"gateway_project_id"`
	GatewayTeamID    string `json:"gateway_team_id"`
	Priority         int    `json:"priority"`
	Enabled          bool   `json:"enabled"`
}

func toGMRDTO(g *repository.GroupMappingRule) groupMappingRuleDTO {
	return groupMappingRuleDTO{
		ID: g.ID, MatchType: g.MatchType, MatchValue: g.MatchValue, MappedGroup: g.MappedGroup,
		GatewayProjectID: g.GatewayProjectID, GatewayTeamID: g.GatewayTeamID, Priority: g.Priority, Enabled: g.Enabled,
	}
}

type gmrUpsertReq struct {
	MatchType        string `json:"match_type"`
	MatchValue       string `json:"match_value"`
	MappedGroup      string `json:"mapped_group"`
	GatewayProjectID string `json:"gateway_project_id"`
	GatewayTeamID    string `json:"gateway_team_id"`
	Priority         int    `json:"priority"`
	Enabled          *bool  `json:"enabled"`
}

func (req gmrUpsertReq) validate() string {
	if strings.TrimSpace(req.MatchValue) == "" {
		return "match_value is required"
	}
	if strings.TrimSpace(req.MappedGroup) == "" {
		return "mapped_group is required"
	}
	if strings.TrimSpace(req.GatewayProjectID) == "" {
		return "gateway_project_id is required"
	}
	if req.MatchType != "" && req.MatchType != "department" {
		return "match_type 目前仅支持 department"
	}
	return ""
}

func gmrEnabled(req gmrUpsertReq) bool {
	if req.Enabled == nil {
		return true
	}
	return *req.Enabled
}

// ListGroupMappingRules GET /admin/v1/group-mapping-rules
func ListGroupMappingRules(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		rules, err := deps.GroupMappingRuleRepo.ListByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		out := make([]groupMappingRuleDTO, 0, len(rules))
		for _, g := range rules {
			out = append(out, toGMRDTO(g))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}
}

// CreateGroupMappingRule POST /admin/v1/group-mapping-rules
func CreateGroupMappingRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要平台管理员权限")
			return
		}
		var req gmrUpsertReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if msg := req.validate(); msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		g := &repository.GroupMappingRule{
			TenantID: user.TenantID, MatchType: req.MatchType, MatchValue: strings.TrimSpace(req.MatchValue),
			MappedGroup: strings.TrimSpace(req.MappedGroup), GatewayProjectID: strings.TrimSpace(req.GatewayProjectID),
			GatewayTeamID: strings.TrimSpace(req.GatewayTeamID), Priority: req.Priority, Enabled: gmrEnabled(req),
		}
		if err := deps.GroupMappingRuleRepo.Create(r.Context(), g); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "group_mapping_rule.create", map[string]any{"id": g.ID, "match_value": g.MatchValue}, "group_mapping_rule", g.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toGMRDTO(g))
	}
}

// UpdateGroupMappingRule PATCH /admin/v1/group-mapping-rules/{id}
func UpdateGroupMappingRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要平台管理员权限")
			return
		}
		id := chi.URLParam(r, "id")
		existing, err := deps.GroupMappingRuleRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		var req gmrUpsertReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if msg := req.validate(); msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		existing.MatchType = req.MatchType
		existing.MatchValue = strings.TrimSpace(req.MatchValue)
		existing.MappedGroup = strings.TrimSpace(req.MappedGroup)
		existing.GatewayProjectID = strings.TrimSpace(req.GatewayProjectID)
		existing.GatewayTeamID = strings.TrimSpace(req.GatewayTeamID)
		existing.Priority = req.Priority
		existing.Enabled = gmrEnabled(req)
		if existing.MatchType == "" {
			existing.MatchType = "department"
		}
		if existing.Priority == 0 {
			existing.Priority = 100
		}
		if err := deps.GroupMappingRuleRepo.Update(r.Context(), existing); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "group_mapping_rule.update", map[string]any{"id": id}, "group_mapping_rule", id)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toGMRDTO(existing))
	}
}

// DeleteGroupMappingRule DELETE /admin/v1/group-mapping-rules/{id}
func DeleteGroupMappingRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要平台管理员权限")
			return
		}
		id := chi.URLParam(r, "id")
		if err := deps.GroupMappingRuleRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "group_mapping_rule.delete", map[string]any{"id": id}, "group_mapping_rule", id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// GetPortalGroupMappingRules GET /admin/v1/portal-integration/group-mapping-rules
// portal-proxy 读侧：租户取 header，返回全部规则（priority 升序）。
func GetPortalGroupMappingRules(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.GroupMappingRuleRepo == nil {
			portalNotConfigured(w, "group mapping rule repository")
			return
		}
		rules, err := deps.GroupMappingRuleRepo.ListByTenant(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list group mapping rules")
			return
		}
		out := make([]groupMappingRuleDTO, 0, len(rules))
		for _, g := range rules {
			out = append(out, toGMRDTO(g))
		}
		writeJSON(w, map[string]any{"data": out})
	}
}
