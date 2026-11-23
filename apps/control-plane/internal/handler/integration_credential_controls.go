package handler

import (
	"encoding/json"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/go-chi/chi/v5"
	"net/http"
)

func GetAgentCredential(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		id := chi.URLParam(r, "id")
		if !ai.ValidID(id) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		key, err := deps.IntegrationRepo.GetCredential(r.Context(), user.TenantID, id)
		if err != nil {
			integrationError(w, err)
			return
		}
		integrationWriteJSON(w, 200, key)
	}
}

func UpdateAgentCredential(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		id := chi.URLParam(r, "id")
		if !ai.ValidID(id) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		var req struct {
			ModelAllowlist json.RawMessage `json:"model_allowlist"`
			Enforcement    json.RawMessage `json:"enforcement"`
			DLPEnforcement json.RawMessage `json:"dlp_enforcement"`
		}
		if !integrationDecode(w, r, &req) {
			return
		}
		var update ai.CredentialUpdate
		for _, field := range []json.RawMessage{req.ModelAllowlist, req.Enforcement, req.DLPEnforcement} {
			if string(field) == "null" {
				integrationError(w, ai.ErrInvalid)
				return
			}
		}
		if req.ModelAllowlist != nil {
			var v []string
			if json.Unmarshal(req.ModelAllowlist, &v) != nil {
				integrationError(w, ai.ErrInvalid)
				return
			}
			update.ModelAllowlist = &v
		}
		if req.Enforcement != nil {
			var v string
			if json.Unmarshal(req.Enforcement, &v) != nil {
				integrationError(w, ai.ErrInvalid)
				return
			}
			update.Enforcement = &v
		}
		if req.DLPEnforcement != nil {
			var v string
			if json.Unmarshal(req.DLPEnforcement, &v) != nil {
				integrationError(w, ai.ErrInvalid)
				return
			}
			update.DLPEnforcement = &v
		}
		key, err := deps.IntegrationRepo.UpdateCredential(r.Context(), user.TenantID, id, update)
		if err != nil {
			integrationError(w, err)
			return
		}
		logAudit(r, deps, "integration.credential.update", map[string]any{"key_id": key.KeyID, "model_allowlist_changed": update.ModelAllowlist != nil, "enforcement_changed": update.Enforcement != nil, "dlp_enforcement_changed": update.DLPEnforcement != nil}, "key", key.KeyID)
		integrationWriteJSON(w, 200, key)
	}
}
