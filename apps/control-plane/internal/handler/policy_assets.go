package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/go-chi/chi/v5"
)

type policyAssetResponse struct {
	Data             []repository.PolicyAsset `json:"data"`
	TotalAssets      int                      `json:"total_assets"`
	ApplicableAssets int                      `json:"applicable_assets"`
	ExecutableAssets int                      `json:"executable_assets"`
}

func ListPolicyAssets(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		tenant, err := deps.TenantRepo.GetByID(r.Context(), user.TenantID)
		if err != nil || tenant == nil {
			log.Printf("ListPolicyAssets tenant lookup failed: %v", err)
			writeError(w, "internal_error", "failed to load policy inventory")
			return
		}
		assets, err := deps.RuleRepo.ListPolicyAssets(r.Context(), user.TenantID, normalizeIndustry(tenant.Industry))
		if err != nil {
			log.Printf("ListPolicyAssets error: %v", err)
			writeError(w, "internal_error", "failed to load policy inventory")
			return
		}
		response := policyAssetResponse{Data: make([]repository.PolicyAsset, 0, len(assets)), TotalAssets: len(assets)}
		for _, asset := range assets {
			if asset.Applicable {
				response.ApplicableAssets++
				if asset.Executable && asset.Enabled {
					response.ExecutableAssets++
				}
			}
			if roles.CanManageSecurityPolicy(user.Role) || asset.Applicable {
				response.Data = append(response.Data, asset)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

type updatePolicyAssetRequest struct {
	Action string `json:"action"`
}

func UpdatePolicyAsset(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can update policy assets")
			return
		}
		var req updatePolicyAssetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			(req.Action != "audit" && req.Action != "mask" && req.Action != "block") {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_action", "action must be audit, mask, or block")
			return
		}
		ruleID := chi.URLParam(r, "id")
		tenant, err := deps.TenantRepo.GetByID(r.Context(), user.TenantID)
		if err != nil || tenant == nil {
			writeError(w, "internal_error", "failed to load tenant policy context")
			return
		}
		assets, err := deps.RuleRepo.ListPolicyAssets(r.Context(), user.TenantID, normalizeIndustry(tenant.Industry))
		if err != nil {
			writeError(w, "internal_error", "failed to load policy inventory")
			return
		}
		var target *repository.PolicyAsset
		for i := range assets {
			if assets[i].ID == ruleID && assets[i].Source == "industry" && assets[i].Applicable && assets[i].Executable {
				target = &assets[i]
				break
			}
		}
		if target == nil {
			writeErrorWithStatus(w, http.StatusConflict, "policy_not_configurable", "this policy is not executable for the current tenant")
			return
		}
		if err := deps.RuleRepo.UpsertBuiltinRuleAction(r.Context(), user.TenantID, ruleID, req.Action); err != nil {
			if errors.Is(err, repository.ErrRuleNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "policy asset not found")
				return
			}
			log.Printf("UpdatePolicyAsset error: %v", err)
			writeError(w, "internal_error", "failed to save policy action")
			return
		}
		target.Action = req.Action
		logAudit(r, deps, "update_builtin_policy_action", map[string]interface{}{"action": req.Action}, "policy_asset", ruleID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(target)
	}
}
