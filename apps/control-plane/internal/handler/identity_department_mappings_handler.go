// identity_department_mappings_handler.go implements the unified, customer-
// facing department mapping API. The endpoint surface intentionally uses
// domain language (source_type / external_group / department_id) and never
// exposes database table names, Keycloak realm ids, or LDAP bind DNs.
//
// The legacy /admin/v1/identity/dept-mappings endpoints (in
// identity_sources_handler.go) are kept as a thin read compat layer over the
// same identity_department_mappings table for one release.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// identityDepartmentMappingDTO is the wire shape for the unified API. Field
// names are customer-facing; database column names are never serialized.
type identityDepartmentMappingDTO struct {
	ID             string `json:"id"`
	SourceType     string `json:"source_type"`
	SourceID       string `json:"source_id"`
	ExternalGroup  string `json:"external_group"`
	MatchType      string `json:"match_type,omitempty"`
	DepartmentID   string `json:"department_id"`
	DepartmentName string `json:"department_name,omitempty"`
	Priority       int    `json:"priority"`
	Enabled        bool   `json:"enabled"`
}

type identityDepartmentMappingReq struct {
	SourceType    string `json:"source_type"`
	SourceID      string `json:"source_id"`
	ExternalGroup string `json:"external_group"`
	MatchType     string `json:"match_type"`
	DepartmentID  string `json:"department_id"`
	Priority      int    `json:"priority"`
	Enabled       *bool  `json:"enabled"`
}

var allowedSourceKinds = map[string]struct{}{
	"oidc": {},
	"ldap": {},
	"ad":   {},
}

var allowedMatchTypes = map[string]struct{}{
	"department": {},
	"ou":         {},
	"member_of":  {},
	"groups":     {},
}

func (req identityDepartmentMappingReq) normalize() (repository.IdentityDepartmentMapping, string) {
	var m repository.IdentityDepartmentMapping
	req.SourceType = strings.TrimSpace(req.SourceType)
	req.SourceID = strings.TrimSpace(req.SourceID)
	req.ExternalGroup = strings.TrimSpace(req.ExternalGroup)
	req.DepartmentID = strings.TrimSpace(req.DepartmentID)
	req.MatchType = strings.TrimSpace(req.MatchType)

	if req.ExternalGroup == "" {
		return m, "外部群组不能为空"
	}
	if req.DepartmentID == "" {
		return m, "目标部门不能为空"
	}
	if _, ok := allowedSourceKinds[req.SourceType]; !ok {
		return m, "身份源类型不支持"
	}
	matchType := req.MatchType
	if matchType == "" {
		matchType = "groups"
	}
	if _, ok := allowedMatchTypes[matchType]; !ok {
		return m, "匹配类型不支持"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	m = repository.IdentityDepartmentMapping{
		SourceKind:         req.SourceType,
		SourceID:           req.SourceID,
		MatchType:          matchType,
		MatchValue:         req.ExternalGroup,
		TargetDepartmentID: req.DepartmentID,
		Priority:           req.Priority,
		Enabled:            enabled,
	}
	return m, ""
}

// validateTargetDepartmentBelongsToTenant ensures the department id resolves to
// a non-system team owned by the acting tenant. Returns a non-empty message
// when the target is invalid; returns error only on infrastructure failure.
func validateTargetDepartmentBelongsToTenant(ctx context.Context, deps *Dependencies, tenantID, departmentID string) (string, error) {
	if deps.TeamRepo == nil {
		return "", errors.New("team repository unavailable")
	}
	team, err := deps.TeamRepo.GetByID(ctx, departmentID)
	if err != nil {
		return "", err
	}
	if team == nil || team.TenantID != tenantID {
		return "所选部门不属于当前租户", nil
	}
	return "", nil
}

func departmentNameByID(ctx context.Context, deps *Dependencies, departmentID string) string {
	if deps.TeamRepo == nil {
		return ""
	}
	team, err := deps.TeamRepo.GetByID(ctx, departmentID)
	if err != nil || team == nil {
		return ""
	}
	return team.Name
}

func toIdentityDepartmentMappingDTO(m repository.IdentityDepartmentMapping, deptName string) identityDepartmentMappingDTO {
	return identityDepartmentMappingDTO{
		ID:             m.ID,
		SourceType:     m.SourceKind,
		SourceID:       m.SourceID,
		ExternalGroup:  m.MatchValue,
		MatchType:      m.MatchType,
		DepartmentID:   m.TargetDepartmentID,
		DepartmentName: deptName,
		Priority:       m.Priority,
		Enabled:        m.Enabled,
	}
}

// ListIdentityDepartmentMappings GET /admin/v1/identity/department-mappings
func ListIdentityDepartmentMappings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		sourceKind := r.URL.Query().Get("source_type")
		sourceID := r.URL.Query().Get("source_id")
		mappings, err := deps.IdentityDepartmentMappingRepo.List(r.Context(), user.TenantID, sourceKind, sourceID)
		if err != nil {
			writeError(w, "internal_error", "获取部门映射失败")
			return
		}
		out := make([]identityDepartmentMappingDTO, 0, len(mappings))
		for _, m := range mappings {
			out = append(out, toIdentityDepartmentMappingDTO(*m, departmentNameByID(r.Context(), deps, m.TargetDepartmentID)))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}
}

// CreateIdentityDepartmentMapping POST /admin/v1/identity/department-mappings
func CreateIdentityDepartmentMapping(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		var req identityDepartmentMappingReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		m, msg := req.normalize()
		if msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		m.TenantID = user.TenantID
		if msg, err := validateTargetDepartmentBelongsToTenant(r.Context(), deps, user.TenantID, m.TargetDepartmentID); err != nil {
			writeError(w, "internal_error", "校验目标部门失败")
			return
		} else if msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		if err := deps.IdentityDepartmentMappingRepo.Upsert(r.Context(), &m); err != nil {
			if errors.Is(err, repository.ErrIdentityDepartmentMappingConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "conflict", "相同的外部群组映射已存在")
				return
			}
			writeError(w, "internal_error", "创建部门映射失败")
			return
		}
		logAudit(r, deps, "identity.department_mapping.created", map[string]any{
			"source_type":    m.SourceKind,
			"external_group": m.MatchValue,
		}, "identity_department_mapping", m.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toIdentityDepartmentMappingDTO(m, departmentNameByID(r.Context(), deps, m.TargetDepartmentID)))
	}
}

// UpdateIdentityDepartmentMapping PATCH /admin/v1/identity/department-mappings/{id}
func UpdateIdentityDepartmentMapping(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "缺少映射 ID")
			return
		}
		var req identityDepartmentMappingReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		m, msg := req.normalize()
		if msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		m.ID = id
		m.TenantID = user.TenantID
		if msg, err := validateTargetDepartmentBelongsToTenant(r.Context(), deps, user.TenantID, m.TargetDepartmentID); err != nil {
			writeError(w, "internal_error", "校验目标部门失败")
			return
		} else if msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		if err := deps.IdentityDepartmentMappingRepo.Upsert(r.Context(), &m); err != nil {
			switch {
			case errors.Is(err, repository.ErrIdentityDepartmentMappingNotFound):
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "部门映射不存在")
			case errors.Is(err, repository.ErrIdentityDepartmentMappingConflict):
				writeErrorWithStatus(w, http.StatusConflict, "conflict", "相同的外部群组映射已存在")
			default:
				writeError(w, "internal_error", "更新部门映射失败")
			}
			return
		}
		logAudit(r, deps, "identity.department_mapping.updated", map[string]any{
			"external_group": m.MatchValue,
		}, "identity_department_mapping", m.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toIdentityDepartmentMappingDTO(m, departmentNameByID(r.Context(), deps, m.TargetDepartmentID)))
	}
}

// DeleteIdentityDepartmentMapping DELETE /admin/v1/identity/department-mappings/{id}
func DeleteIdentityDepartmentMapping(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "缺少映射 ID")
			return
		}
		if err := deps.IdentityDepartmentMappingRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			if errors.Is(err, repository.ErrIdentityDepartmentMappingNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "部门映射不存在")
				return
			}
			writeError(w, "internal_error", "删除部门映射失败")
			return
		}
		logAudit(r, deps, "identity.department_mapping.deleted", nil, "identity_department_mapping", id)
		w.WriteHeader(http.StatusNoContent)
	}
}

type identityDepartmentPreviewReq struct {
	SourceType          string   `json:"source_type"`
	SourceID            string   `json:"source_id"`
	ExternalGroup       string   `json:"external_group"`
	ExternalGroups      []string `json:"external_groups"`
	ExternalDepartments []string `json:"external_departments"`
}

type identityDepartmentPreviewCandidate struct {
	DepartmentID   string `json:"department_id"`
	DepartmentName string `json:"department_name"`
}

type identityDepartmentPreviewResp struct {
	Matched              bool                                 `json:"matched"`
	Ambiguous            bool                                 `json:"ambiguous"`
	DepartmentID         string                               `json:"department_id,omitempty"`
	DepartmentName       string                               `json:"department_name,omitempty"`
	CandidateIDs         []string                             `json:"candidate_ids,omitempty"`
	CandidateDepartments []identityDepartmentPreviewCandidate `json:"candidate_departments,omitempty"`
}

// normalizePreviewValues follows the login resolver's trimming, deduplication,
// and empty-value handling before passing attributes to FindMatches.
func normalizePreviewValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// PreviewIdentityDepartmentMappings POST /admin/v1/identity/department-mappings/preview
//
// Resolves supplied department codes and groups without persisting state.
// external_group remains compatible with callers sending a single group.
// FindMatches applies source scoping and tenant defaults; as in login,
// only the lowest numeric priority participates in conflict resolution.
func PreviewIdentityDepartmentMappings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		var req identityDepartmentPreviewReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "请求格式错误")
			return
		}
		req.SourceType = strings.ToLower(strings.TrimSpace(req.SourceType))
		req.SourceID = strings.TrimSpace(req.SourceID)
		groups := normalizePreviewValues(append(req.ExternalGroups, req.ExternalGroup))
		departments := normalizePreviewValues(req.ExternalDepartments)
		if _, ok := allowedSourceKinds[req.SourceType]; !ok || len(groups)+len(departments) == 0 {
			writeError(w, "invalid_request", "请提供有效的身份源类型及部门编码或用户组")
			return
		}

		ext := identitybinding.ExternalIdentity{
			TenantID:    user.TenantID,
			SourceType:  req.SourceType,
			SourceID:    req.SourceID,
			Departments: departments,
			Groups:      groups,
		}
		matches, err := deps.IdentityDepartmentMappingRepo.FindMatches(r.Context(), ext)
		if err != nil {
			writeError(w, "internal_error", "预览部门映射失败")
			return
		}

		resp := identityDepartmentPreviewResp{CandidateIDs: []string{}}
		if len(matches) == 0 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp.Matched = true
		// FindMatches orders by priority ascending. Login uses the same minimum
		// priority after exact-source preference, so lower-ranked matches must
		// not turn a deterministic assignment into an apparent conflict.
		priority := matches[0].Priority
		seen := make(map[string]struct{}, len(matches))
		for _, mapping := range matches {
			if mapping.Priority == priority {
				seen[mapping.DepartmentID] = struct{}{}
			}
		}
		resp.Ambiguous = len(seen) > 1
		for id := range seen {
			resp.CandidateIDs = append(resp.CandidateIDs, id)
		}
		sort.Strings(resp.CandidateIDs)
		if resp.Ambiguous {
			for _, id := range resp.CandidateIDs {
				resp.CandidateDepartments = append(resp.CandidateDepartments, identityDepartmentPreviewCandidate{
					DepartmentID: id, DepartmentName: departmentNameByID(r.Context(), deps, id),
				})
			}
		} else {
			resp.DepartmentID = resp.CandidateIDs[0]
			resp.DepartmentName = departmentNameByID(r.Context(), deps, resp.DepartmentID)
			resp.CandidateIDs = resp.CandidateIDs[:0]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
