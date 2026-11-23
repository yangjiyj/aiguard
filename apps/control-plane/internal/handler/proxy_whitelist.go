package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type ProxyWhitelistInfo struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	HostPattern  string `json:"host_pattern"`
	Port         int    `json:"port"`
	AuditEnabled bool   `json:"audit_enabled"`
	Description  string `json:"description"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type ProxyWhitelistCreateRequest struct {
	HostPattern  string `json:"host_pattern"`
	Port         int    `json:"port"`
	AuditEnabled bool   `json:"audit_enabled"`
	Description  string `json:"description,omitempty"`
}

type ProxyWhitelistUpdateRequest struct {
	HostPattern  string `json:"host_pattern,omitempty"`
	Port         int    `json:"port,omitempty"`
	AuditEnabled bool   `json:"audit_enabled,omitempty"`
	Description  string `json:"description,omitempty"`
}

func mapProxyWhitelistToInfo(e *repository.ProxyWhitelist) ProxyWhitelistInfo {
	return ProxyWhitelistInfo{
		ID:           e.ID,
		TenantID:     e.TenantID,
		HostPattern:  e.HostPattern,
		Port:         e.Port,
		AuditEnabled: e.AuditEnabled,
		Description:  e.Description,
		CreatedAt:    e.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    e.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func GetProxyWhitelist(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		entries, err := deps.ProxyWhitelistRepo.List(r.Context(), user.TenantID)
		if err != nil {
			log.Printf("GetProxyWhitelist error: %v", err)
			writeError(w, "internal_error", "failed to list proxy whitelist")
			return
		}

		data := make([]ProxyWhitelistInfo, len(entries))
		for i, e := range entries {
			data[i] = mapProxyWhitelistToInfo(&e)
		}

		resp := map[string]interface{}{
			"data":  data,
			"total": len(data),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func CreateProxyWhitelist(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can create whitelist entries")
			return
		}

		var req ProxyWhitelistCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.HostPattern == "" {
			writeError(w, "invalid_request", "host_pattern is required")
			return
		}

		if req.Port == 0 {
			req.Port = 443
		}

		entry := &repository.ProxyWhitelist{
			TenantID:     user.TenantID,
			HostPattern:  req.HostPattern,
			Port:         req.Port,
			AuditEnabled: req.AuditEnabled,
			Description:  req.Description,
		}

		if err := deps.ProxyWhitelistRepo.Create(r.Context(), entry); err != nil {
			log.Printf("CreateProxyWhitelist error: %v", err)
			writeError(w, "internal_error", "failed to create whitelist entry")
			return
		}

		detail := map[string]interface{}{
			"host_pattern":  req.HostPattern,
			"audit_enabled": req.AuditEnabled,
		}
		logAudit(r, deps, "create_proxy_whitelist", detail, "proxy_whitelist", entry.ID)

		resp := mapProxyWhitelistToInfo(entry)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

func UpdateProxyWhitelist(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can update whitelist entries")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id is required")
			return
		}

		var req ProxyWhitelistUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		existing, err := deps.ProxyWhitelistRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			log.Printf("UpdateProxyWhitelist error fetching: %v", err)
			writeError(w, "internal_error", "failed to get whitelist entry")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "whitelist entry not found")
			return
		}

		hostPattern := req.HostPattern
		if hostPattern == "" {
			hostPattern = existing.HostPattern
		}
		port := req.Port
		if port == 0 {
			port = existing.Port
		}
		description := req.Description
		if description == "" {
			description = existing.Description
		}
		auditEnabled := req.AuditEnabled

		entry := &repository.ProxyWhitelist{
			ID:           id,
			TenantID:     user.TenantID,
			HostPattern:  hostPattern,
			Port:         port,
			AuditEnabled: auditEnabled,
			Description:  description,
		}

		if err := deps.ProxyWhitelistRepo.Update(r.Context(), entry); err != nil {
			log.Printf("UpdateProxyWhitelist error: %v", err)
			writeError(w, "internal_error", "failed to update whitelist entry")
			return
		}

		detail := map[string]interface{}{
			"entry_id":      id,
			"host_pattern":  hostPattern,
			"audit_enabled": auditEnabled,
		}
		logAudit(r, deps, "update_proxy_whitelist", detail, "proxy_whitelist", id)

		updated, err := deps.ProxyWhitelistRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil || updated == nil {
			writeError(w, "internal_error", "failed to get updated whitelist entry")
			return
		}

		resp := mapProxyWhitelistToInfo(updated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func DeleteProxyWhitelist(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can delete whitelist entries")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id is required")
			return
		}

		existing, err := deps.ProxyWhitelistRepo.GetByID(r.Context(), user.TenantID, id)
		if err != nil {
			log.Printf("DeleteProxyWhitelist error fetching: %v", err)
			writeError(w, "internal_error", "failed to get whitelist entry")
			return
		}
		if existing == nil {
			writeError(w, "not_found", "whitelist entry not found")
			return
		}

		if err := deps.ProxyWhitelistRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			log.Printf("DeleteProxyWhitelist error: %v", err)
			writeError(w, "internal_error", "failed to delete whitelist entry")
			return
		}

		detail := map[string]interface{}{
			"entry_id":     id,
			"host_pattern": existing.HostPattern,
		}
		logAudit(r, deps, "delete_proxy_whitelist", detail, "proxy_whitelist", id)

		w.WriteHeader(http.StatusNoContent)
	}
}