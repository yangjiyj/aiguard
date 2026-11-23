package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// GetOrgLabels GET /admin/v1/settings/org-labels — 任意登录用户可读
func GetOrgLabels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.GetUser(r.Context()) == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		m, err := deps.AppSettingsRepo.GetMany(r.Context(), []string{"org_tier1_label", "org_tier2_label"})
		if err != nil {
			writeError(w, "internal_error", "failed to read settings")
			return
		}
		tier1, tier2 := m["org_tier1_label"], m["org_tier2_label"]
		if tier1 == "" {
			tier1 = "单位"
		}
		if tier2 == "" {
			tier2 = "部门"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
			"org_tier1_label": tier1, "org_tier2_label": tier2,
		}})
	}
}

// PutOrgLabels PUT /admin/v1/settings/org-labels — 仅 platform_admin
func PutOrgLabels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can change org labels")
			return
		}
		var req struct {
			OrgTier1Label string `json:"org_tier1_label"`
			OrgTier2Label string `json:"org_tier2_label"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.OrgTier1Label == "" || req.OrgTier2Label == "" {
			writeError(w, "invalid_request", "labels must not be empty")
			return
		}
		if err := deps.AppSettingsRepo.Set(r.Context(), "org_tier1_label", req.OrgTier1Label); err != nil {
			writeError(w, "internal_error", "failed to save")
			return
		}
		if err := deps.AppSettingsRepo.Set(r.Context(), "org_tier2_label", req.OrgTier2Label); err != nil {
			writeError(w, "internal_error", "failed to save")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
			"org_tier1_label": req.OrgTier1Label, "org_tier2_label": req.OrgTier2Label,
		}})
	}
}
