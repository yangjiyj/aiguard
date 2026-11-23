package handler

import (
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"net/http"
	"sort"
	"time"
)

func integrationDLPEffectiveAction(policy repository.SecurityPolicy, keys []ai.Credential, auditOnly bool) string {
	if !policy.Enabled {
		return "audit"
	}
	if !auditOnly {
		return policy.Action
	}
	if !policy.Authoring.IsAgentShield() || policy.Action != "block" || policy.SubjectBinding == nil || len(policy.SubjectBinding.KeyIDs) == 0 || len(keys) != len(policy.SubjectBinding.KeyIDs) {
		return "audit"
	}
	byID := map[string]ai.Credential{}
	for _, key := range keys {
		byID[key.KeyID] = key
	}
	for _, id := range policy.SubjectBinding.KeyIDs {
		key, ok := byID[id]
		if !ok || key.AgentInstanceID == "" || key.Status != "active" || (key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now())) || ai.EffectiveEnforcement(key.DLPEnforcement, true) != "block" {
			return "audit"
		}
	}
	return "block"
}

func GetIntegrationDLPStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		if deps.RuleRepo == nil {
			integrationError(w, errors.New("策略仓储不可用"))
			return
		}
		securityPoliciesHandlerFromDependencies(deps).integrationDLPStatus(w, r, user)
	}
}

func (h *securityPoliciesHandler) integrationDLPStatus(w http.ResponseWriter, r *http.Request, user *repository.User) {
	id := r.URL.Query().Get("policy_id")
	if !ai.ValidID(id) {
		integrationError(w, ai.ErrInvalid)
		return
	}
	policy, err := h.store.GetSecurityPolicy(r.Context(), user.TenantID, id)
	if errors.Is(err, repository.ErrSecurityPolicyNotFound) {
		integrationError(w, ai.ErrNotFound)
		return
	}
	if err != nil {
		integrationError(w, err)
		return
	}
	keyIDs := []string{}
	keys := []ai.Credential{}
	if policy.SubjectBinding != nil {
		keyIDs = append(keyIDs, policy.SubjectBinding.KeyIDs...)
	}
	for _, keyID := range keyIDs {
		key, err := h.deps.IntegrationRepo.GetCredential(r.Context(), user.TenantID, keyID)
		if err != nil {
			if errors.Is(err, ai.ErrNotFound) {
				continue
			}
			integrationError(w, err)
			return
		}
		keys = append(keys, *key)
	}
	auditOnly, auditOnlySource := resolveSecurityExecutionMode(r.Context(), h.deps)
	proof, err := h.runtimeProof(r.Context(), user.TenantID)
	if err != nil {
		proof = unavailableSecurityPolicyRuntimeProof()
	}
	_, active := proof.ActivePolicyIDs[id]
	verified := proof.complete() && active && policy.Enabled
	categories := []string{}
	for _, capability := range policy.Capabilities {
		categories = append(categories, capability.Category)
	}
	sort.Strings(keyIDs)
	sort.Strings(categories)
	integrationWriteJSON(w, 200, map[string]any{
		"policy_id": id, "enabled": policy.Enabled, "configured_action": policy.Action,
		"effective_action": integrationDLPEffectiveAction(*policy, keys, auditOnly),
		"audit_only":       auditOnly, "audit_only_source": integrationAuditOnlySourceLabel(auditOnlySource),
		"key_ids": keyIDs, "capability_categories": categories,
		"runtime_active": verified, "runtime_verified": verified, "rule_pack_version": proof.RulePackVersion,
	})
}
