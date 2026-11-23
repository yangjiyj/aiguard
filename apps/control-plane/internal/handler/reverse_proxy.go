package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/go-chi/chi/v5"
)

type ReverseProxyRouteInfo struct {
	ID                 string   `json:"id"`
	TenantID           string   `json:"tenant_id"`
	Name               string   `json:"name"`
	PathPrefix         string   `json:"path_prefix"`
	TargetURL          string   `json:"target_url"`
	TargetPathPrefix   string   `json:"target_path_prefix"`
	AllowPrivateEgress bool     `json:"allow_private_egress"`
	PrivateEgressCIDRs []string `json:"private_egress_cidrs"`
	// EgressOverrides 是路由的高级出站放行（回环、链路本地、元数据、内部主机名）。
	EgressOverrides safetarget.EgressOverrides `json:"egress_overrides"`
	SecurityEnabled bool                       `json:"security_enabled"`
	StatsEnabled    bool                       `json:"stats_enabled"`
	Status          string                     `json:"status"`
	Description     string                     `json:"description"`
	CreatedAt       string                     `json:"created_at,omitempty"`
	UpdatedAt       string                     `json:"updated_at,omitempty"`
}

type ReverseProxyRouteCreateRequest struct {
	Name               string   `json:"name"`
	PathPrefix         string   `json:"path_prefix"`
	TargetURL          string   `json:"target_url"`
	TargetPathPrefix   string   `json:"target_path_prefix"`
	AllowPrivateEgress bool     `json:"allow_private_egress"`
	PrivateEgressCIDRs []string `json:"private_egress_cidrs"`
	// EgressOverrides 缺省为全部拒绝；按严格格式解析（未知键报错）。
	EgressOverrides json.RawMessage `json:"egress_overrides,omitempty"`
	SecurityEnabled bool            `json:"security_enabled"`
	StatsEnabled    bool            `json:"stats_enabled"`
	Status          string          `json:"status"`
	Description     string          `json:"description"`
}

type ReverseProxyRouteUpdateRequest struct {
	Name               *string   `json:"name,omitempty"`
	PathPrefix         *string   `json:"path_prefix,omitempty"`
	TargetURL          *string   `json:"target_url,omitempty"`
	TargetPathPrefix   *string   `json:"target_path_prefix,omitempty"`
	AllowPrivateEgress *bool     `json:"allow_private_egress,omitempty"`
	PrivateEgressCIDRs *[]string `json:"private_egress_cidrs,omitempty"`
	// EgressOverrides 省略 = 保持不变；传了就整体替换。
	EgressOverrides json.RawMessage `json:"egress_overrides,omitempty"`
	SecurityEnabled *bool           `json:"security_enabled,omitempty"`
	StatsEnabled    *bool           `json:"stats_enabled,omitempty"`
	Status          *string         `json:"status,omitempty"`
	Description     *string         `json:"description,omitempty"`
}

func mapReverseProxyRouteToInfo(entry *repository.ReverseProxyRoute) ReverseProxyRouteInfo {
	return ReverseProxyRouteInfo{
		ID:                 entry.ID,
		TenantID:           entry.TenantID,
		Name:               entry.Name,
		PathPrefix:         entry.PathPrefix,
		TargetURL:          entry.TargetURL,
		TargetPathPrefix:   entry.TargetPathPrefix,
		AllowPrivateEgress: entry.AllowPrivateEgress,
		PrivateEgressCIDRs: append([]string{}, entry.PrivateEgressCIDRs...),
		EgressOverrides:    entry.EgressOverrides,
		SecurityEnabled:    entry.SecurityEnabled,
		StatsEnabled:       entry.StatsEnabled,
		Status:             entry.Status,
		Description:        entry.Description,
		CreatedAt:          entry.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:          entry.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func ListReverseProxyRoutes(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		entries, err := deps.ReverseProxyRouteRepo.List(r.Context(), user.TenantID)
		if err != nil {
			log.Printf("ListReverseProxyRoutes error: %v", err)
			writeError(w, "internal_error", "failed to list reverse proxy routes")
			return
		}

		data := make([]ReverseProxyRouteInfo, len(entries))
		for i, entry := range entries {
			data[i] = mapReverseProxyRouteToInfo(&entry)
		}

		resp := map[string]interface{}{
			"data":  data,
			"total": len(data),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func CreateReverseProxyRoute(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can create reverse proxy routes")
			return
		}

		var req ReverseProxyRouteCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		entry, err := buildReverseProxyRouteForCreate(user.TenantID, req)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		if err := deps.ReverseProxyRouteRepo.Create(r.Context(), entry); err != nil {
			log.Printf("CreateReverseProxyRoute error: %v", err)
			writeError(w, "internal_error", "failed to create reverse proxy route")
			return
		}

		logAudit(r, deps, "create_reverse_proxy_route", map[string]interface{}{
			"name":                 entry.Name,
			"path_prefix":          entry.PathPrefix,
			"target_url":           entry.TargetURL,
			"allow_private_egress": entry.AllowPrivateEgress,
			"private_egress_cidrs": append([]string(nil), entry.PrivateEgressCIDRs...),
			"egress_overrides":     entry.EgressOverrides.Enabled(),
		}, "reverse_proxy_route", entry.ID)
		auditEgressOverrideEnable(r, deps, "reverse_proxy_route", entry.ID, safetarget.EgressOverrides{}, entry.EgressOverrides)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(mapReverseProxyRouteToInfo(entry))
	}
}

func UpdateReverseProxyRoute(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can update reverse proxy routes")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id is required")
			return
		}

		var req ReverseProxyRouteUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		existing, err := deps.ReverseProxyRouteRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			log.Printf("UpdateReverseProxyRoute fetch error: %v", err)
			writeError(w, "internal_error", "failed to get reverse proxy route")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "reverse proxy route not found")
			return
		}

		entry, err := buildReverseProxyRouteForUpdate(existing, req)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		if err := deps.ReverseProxyRouteRepo.Update(r.Context(), entry); err != nil {
			log.Printf("UpdateReverseProxyRoute error: %v", err)
			writeError(w, "internal_error", "failed to update reverse proxy route")
			return
		}

		logAudit(r, deps, "update_reverse_proxy_route", map[string]interface{}{
			"route_id":                      entry.ID,
			"path_prefix":                   entry.PathPrefix,
			"target_url":                    entry.TargetURL,
			"target_state":                  entry.Status,
			"previous_allow_private_egress": existing.AllowPrivateEgress,
			"previous_private_egress_cidrs": append([]string(nil), existing.PrivateEgressCIDRs...),
			"allow_private_egress":          entry.AllowPrivateEgress,
			"private_egress_cidrs":          append([]string(nil), entry.PrivateEgressCIDRs...),
			"previous_egress_overrides":     existing.EgressOverrides.Enabled(),
			"egress_overrides":              entry.EgressOverrides.Enabled(),
		}, "reverse_proxy_route", entry.ID)
		auditEgressOverrideEnable(r, deps, "reverse_proxy_route", entry.ID, existing.EgressOverrides, entry.EgressOverrides)

		updated, err := deps.ReverseProxyRouteRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil || updated == nil {
			writeError(w, "internal_error", "failed to get updated reverse proxy route")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mapReverseProxyRouteToInfo(updated))
	}
}

func DeleteReverseProxyRoute(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can delete reverse proxy routes")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id is required")
			return
		}

		existing, err := deps.ReverseProxyRouteRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			log.Printf("DeleteReverseProxyRoute fetch error: %v", err)
			writeError(w, "internal_error", "failed to get reverse proxy route")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "reverse proxy route not found")
			return
		}

		if err := deps.ReverseProxyRouteRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			log.Printf("DeleteReverseProxyRoute error: %v", err)
			writeError(w, "internal_error", "failed to delete reverse proxy route")
			return
		}

		logAudit(r, deps, "delete_reverse_proxy_route", map[string]interface{}{
			"route_id":             id,
			"path_prefix":          existing.PathPrefix,
			"target_url":           existing.TargetURL,
			"allow_private_egress": existing.AllowPrivateEgress,
			"private_egress_cidrs": append([]string(nil), existing.PrivateEgressCIDRs...),
		}, "reverse_proxy_route", id)

		w.WriteHeader(http.StatusNoContent)
	}
}

func buildReverseProxyRouteForCreate(tenantID string, req ReverseProxyRouteCreateRequest) (*repository.ReverseProxyRoute, error) {
	name, pathPrefix, targetURL, targetPathPrefix, status, description, err := validateReverseProxyRouteFields(
		req.Name,
		req.PathPrefix,
		req.TargetURL,
		req.TargetPathPrefix,
		req.Status,
		req.Description,
	)
	if err != nil {
		return nil, err
	}
	privateEgressCIDRs, err := normalizePrivateEgressCIDRs(req.AllowPrivateEgress, req.PrivateEgressCIDRs)
	if err != nil {
		return nil, err
	}
	overrides, err := parseReverseProxyEgressOverrides(req.EgressOverrides)
	if err != nil {
		return nil, err
	}

	return &repository.ReverseProxyRoute{
		EgressOverrides:    overrides,
		TenantID:           tenantID,
		Name:               name,
		PathPrefix:         pathPrefix,
		TargetURL:          targetURL,
		TargetPathPrefix:   targetPathPrefix,
		AllowPrivateEgress: req.AllowPrivateEgress,
		PrivateEgressCIDRs: privateEgressCIDRs,
		SecurityEnabled:    req.SecurityEnabled,
		StatsEnabled:       req.StatsEnabled,
		Status:             status,
		Description:        description,
	}, nil
}

func buildReverseProxyRouteForUpdate(existing *repository.ReverseProxyRoute, req ReverseProxyRouteUpdateRequest) (*repository.ReverseProxyRoute, error) {
	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}
	pathPrefix := existing.PathPrefix
	if req.PathPrefix != nil {
		pathPrefix = *req.PathPrefix
	}
	targetURL := existing.TargetURL
	if req.TargetURL != nil {
		targetURL = *req.TargetURL
	}
	targetPathPrefix := existing.TargetPathPrefix
	if req.TargetPathPrefix != nil {
		targetPathPrefix = *req.TargetPathPrefix
	}
	status := existing.Status
	if req.Status != nil {
		status = *req.Status
	}
	description := existing.Description
	if req.Description != nil {
		description = *req.Description
	}
	allowPrivateEgress := existing.AllowPrivateEgress
	if req.AllowPrivateEgress != nil {
		allowPrivateEgress = *req.AllowPrivateEgress
	}
	privateEgressCIDRs := append([]string(nil), existing.PrivateEgressCIDRs...)
	if req.PrivateEgressCIDRs != nil {
		privateEgressCIDRs = *req.PrivateEgressCIDRs
	}

	name, pathPrefix, targetURL, targetPathPrefix, status, description, err := validateReverseProxyRouteFields(
		name,
		pathPrefix,
		targetURL,
		targetPathPrefix,
		status,
		description,
	)
	if err != nil {
		return nil, err
	}
	privateEgressCIDRs, err = normalizePrivateEgressCIDRs(allowPrivateEgress, privateEgressCIDRs)
	if err != nil {
		return nil, err
	}

	updated := *existing
	if len(req.EgressOverrides) > 0 {
		overrides, err := parseReverseProxyEgressOverrides(req.EgressOverrides)
		if err != nil {
			return nil, err
		}
		updated.EgressOverrides = overrides
	}
	updated.Name = name
	updated.PathPrefix = pathPrefix
	updated.TargetURL = targetURL
	updated.TargetPathPrefix = targetPathPrefix
	updated.Status = status
	updated.Description = description
	updated.AllowPrivateEgress = allowPrivateEgress
	updated.PrivateEgressCIDRs = privateEgressCIDRs
	if req.SecurityEnabled != nil {
		updated.SecurityEnabled = *req.SecurityEnabled
	}
	if req.StatsEnabled != nil {
		updated.StatsEnabled = *req.StatsEnabled
	}

	return &updated, nil
}

func validateReverseProxyRouteFields(name, pathPrefix, targetURL, targetPathPrefix, status, description string) (string, string, string, string, string, string, error) {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 128 {
		return "", "", "", "", "", "", errInvalidReverseProxyRoute("name must be between 1 and 128 characters")
	}

	pathPrefix = normalizeProxyPrefix(pathPrefix)
	if len(pathPrefix) == 0 || len(pathPrefix) > 256 || !strings.HasPrefix(pathPrefix, "/") {
		return "", "", "", "", "", "", errInvalidReverseProxyRoute("path_prefix must start with / and be between 1 and 256 characters")
	}

	targetURL = strings.TrimSpace(targetURL)
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Host == "" ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.User != nil {
		return "", "", "", "", "", "", errInvalidReverseProxyRoute("target_url must be a valid absolute URL")
	}

	targetPathPrefix = normalizeProxyPrefix(targetPathPrefix)
	if targetPathPrefix != "" && !strings.HasPrefix(targetPathPrefix, "/") {
		return "", "", "", "", "", "", errInvalidReverseProxyRoute("target_path_prefix must start with / when provided")
	}
	if len(targetPathPrefix) > 256 {
		return "", "", "", "", "", "", errInvalidReverseProxyRoute("target_path_prefix must be 256 characters or less")
	}

	status = strings.TrimSpace(status)
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "disabled" {
		return "", "", "", "", "", "", errInvalidReverseProxyRoute("status must be active or disabled")
	}

	description = strings.TrimSpace(description)
	return name, pathPrefix, targetURL, targetPathPrefix, status, description, nil
}

func normalizeProxyPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return prefix
	}
	return strings.TrimRight(prefix, "/")
}

func normalizePrivateEgressCIDRs(allowPrivateEgress bool, values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, errInvalidReverseProxyRoute("private_egress_cidrs must contain valid CIDR prefixes")
		}
		canonical := prefix.Masked().String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	if allowPrivateEgress && len(normalized) == 0 {
		return nil, errInvalidReverseProxyRoute("private_egress_cidrs is required when allow_private_egress is true")
	}
	if normalized == nil {
		normalized = []string{}
	}
	return normalized, nil
}

// parseReverseProxyEgressOverrides 严格解析路由的高级出站放行；证书与重定向三项只对 MCP
// 服务有效，出现在路由上直接报错，免得管理员以为生效了。
func parseReverseProxyEgressOverrides(raw json.RawMessage) (safetarget.EgressOverrides, error) {
	overrides, err := safetarget.ParseEgressOverrides(raw)
	if err != nil {
		return safetarget.EgressOverrides{}, errInvalidReverseProxyRoute("egress_overrides is invalid: " + err.Error())
	}
	if overrides != overrides.ForReverseProxy() {
		return safetarget.EgressOverrides{}, errInvalidReverseProxyRoute("egress_overrides: trusted_ca_pem, insecure_skip_verify and allow_same_host_redirect only apply to MCP servers")
	}
	return overrides, nil
}

func errInvalidReverseProxyRoute(message string) error {
	return &reverseProxyValidationError{message: message}
}

type reverseProxyValidationError struct {
	message string
}

func (e *reverseProxyValidationError) Error() string {
	return e.message
}
