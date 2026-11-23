package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	securityrules "github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/go-chi/chi/v5"
)

// ListRules returns all rules for a rule set
func ListRules(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		ruleSetID := strings.TrimSpace(r.URL.Query().Get("rule_set_id"))
		if ruleSetID == "" || ruleSetID == "ruleset_default" {
			ruleSetID = tenantDefaultRuleSetID(user.TenantID)
		}

		rules, err := deps.RuleSetRepo.ListRules(r.Context(), user.TenantID, ruleSetID)
		if err != nil {
			if errors.Is(err, repository.ErrRuleSetNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule set not found")
				return
			}
			log.Printf("ListRules error: %v", err)
			writeError(w, "internal_error", "failed to list rules")
			return
		}

		data := make([]types.RuleInfo, len(rules))
		for i, rule := range rules {
			data[i] = mapRuleToInfo(rule)
		}

		resp := types.RuleListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// CreateRule creates a new rule
func CreateRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can create rules")
			return
		}

		var req types.CreateRuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		req.RuleSetID = strings.TrimSpace(req.RuleSetID)
		if req.RuleSetID == "" || req.RuleSetID == "ruleset_default" {
			req.RuleSetID = tenantDefaultRuleSetID(user.TenantID)
		}
		req.RuleType = strings.TrimSpace(req.RuleType)
		req.Name = strings.TrimSpace(req.Name)
		if req.RuleType == "" || req.Name == "" {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_rule", "rule_type and name cannot be blank")
			return
		}

		// Default values
		severity := req.Severity
		if severity == "" {
			severity = "medium"
		}
		action := req.Action
		if action == "" {
			action = "block"
		}
		if !validRuleSeverity(severity) || !validRuleAction(action) || !validRulePriority(req.Priority) {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_rule", "severity, action, or priority is outside the supported range")
			return
		}

		var scopeJSON, matchConfigJSON []byte
		var err error

		if req.ScopeJSON != nil {
			scopeJSON, err = json.Marshal(req.ScopeJSON)
			if err != nil {
				writeError(w, "invalid_request", "invalid scope_json")
				return
			}
		}
		if req.MatchConfigJSON != nil {
			matchConfigJSON, err = json.Marshal(req.MatchConfigJSON)
			if err != nil {
				writeError(w, "invalid_request", "invalid match_config_json")
				return
			}
		}

		rule := &repository.Rule{
			RuleSetID:       req.RuleSetID,
			RuleType:        req.RuleType,
			Name:            req.Name,
			Priority:        req.Priority,
			Severity:        severity,
			ScopeJSON:       scopeJSON,
			MatchConfigJSON: matchConfigJSON,
			Action:          action,
			Enabled:         true,
		}
		if !repository.RuleHasSupportedMatcher(rule) {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "no_supported_matcher", "a runtime rule requires regex, keywords, or field_names")
			return
		}

		if err := deps.RuleRepo.Create(r.Context(), user.TenantID, rule); err != nil {
			if errors.Is(err, repository.ErrRuleSetNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule set not found")
				return
			}
			log.Printf("CreateRule error: %v", err)
			writeError(w, "internal_error", "failed to create rule")
			return
		}

		detail := map[string]interface{}{
			"rule_set_id": req.RuleSetID,
			"rule_type":   req.RuleType,
			"name":        req.Name,
		}
		logAudit(r, deps, "create_rule", detail, "rule", rule.ID)

		resp := mapRuleToInfo(rule)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateRule updates a rule
func UpdateRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can update rules")
			return
		}

		ruleID := chi.URLParam(r, "id")
		if ruleID == "" {
			writeError(w, "invalid_request", "rule id is required")
			return
		}

		var req types.UpdateRuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		// Fetch existing rule to merge updates
		existing, err := deps.RuleRepo.GetByID(r.Context(), user.TenantID, ruleID)
		if err != nil {
			log.Printf("UpdateRule error fetching rule: %v", err)
			writeError(w, "internal_error", "failed to get rule")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		if repository.RuleIsManagedSecurityPolicy(existing) {
			writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
			return
		}
		if !repository.RuleHasSupportedMatcher(existing) {
			writeErrorWithStatus(w, http.StatusConflict, "no_runtime_matcher", "add a supported matcher before changing runtime settings")
			return
		}

		// Apply updates for non-nil fields
		name := existing.Name
		if req.Name != nil {
			name = strings.TrimSpace(*req.Name)
		}
		severity := existing.Severity
		if req.Severity != nil {
			severity = *req.Severity
		}
		action := existing.Action
		if req.Action != nil {
			action = *req.Action
		}
		priority := existing.Priority
		if req.Priority != nil {
			priority = *req.Priority
		}
		enabled := existing.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if name == "" || !validRuleSeverity(severity) || !validRuleAction(action) || !validRulePriority(priority) {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_rule", "name, severity, action, or priority is outside the supported range")
			return
		}

		if err := deps.RuleRepo.Update(r.Context(), user.TenantID, ruleID, action, severity, priority, enabled, name); err != nil {
			if errors.Is(err, repository.ErrManagedSecurityPolicyReadOnly) {
				writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
				return
			}
			if errors.Is(err, repository.ErrRuleNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
				return
			}
			log.Printf("UpdateRule error: %v", err)
			writeError(w, "internal_error", "failed to update rule")
			return
		}

		detail := map[string]interface{}{
			"rule_id": ruleID,
			"name":    name,
		}
		logAudit(r, deps, "update_rule", detail, "rule", ruleID)

		// Return updated rule
		updated, err := deps.RuleRepo.GetByID(r.Context(), user.TenantID, ruleID)
		if err != nil || updated == nil {
			writeError(w, "internal_error", "failed to get updated rule")
			return
		}

		resp := mapRuleToInfo(updated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// DeleteRule deletes a rule
func DeleteRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can delete rules")
			return
		}

		ruleID := chi.URLParam(r, "id")
		if ruleID == "" {
			writeError(w, "invalid_request", "rule id is required")
			return
		}

		existing, err := deps.RuleRepo.GetByID(r.Context(), user.TenantID, ruleID)
		if err != nil {
			log.Printf("DeleteRule error fetching rule: %v", err)
			writeError(w, "internal_error", "failed to get rule")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		if repository.RuleIsManagedSecurityPolicy(existing) {
			if !strings.HasPrefix(existing.PolicyCode, "custom.") {
				writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
				return
			}
			if err := deps.RuleRepo.DeleteSecurityPolicy(r.Context(), user.TenantID, ruleID); err != nil {
				if errors.Is(err, repository.ErrSecurityPolicyNotFound) {
					writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
					return
				}
				if errors.Is(err, repository.ErrSecurityPolicyNotDeletable) {
					writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
					return
				}
				log.Printf("DeleteRule custom policy error: %v", err)
				writeError(w, "internal_error", "failed to delete rule")
				return
			}
			logAudit(r, deps, "delete_rule", map[string]interface{}{"rule_id": ruleID}, "rule", ruleID)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := deps.RuleRepo.Delete(r.Context(), user.TenantID, ruleID); err != nil {
			log.Printf("DeleteRule error: %v", err)
			if errors.Is(err, repository.ErrRuleNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
				return
			}
			if errors.Is(err, repository.ErrManagedSecurityPolicyReadOnly) {
				writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
				return
			}
			writeError(w, "internal_error", "failed to delete rule")
			return
		}

		logAudit(r, deps, "delete_rule", map[string]interface{}{"rule_id": ruleID}, "rule", ruleID)

		w.WriteHeader(http.StatusNoContent)
	}
}

// ToggleRule toggles the enabled state of a rule
func ToggleRule(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can toggle rules")
			return
		}

		ruleID := chi.URLParam(r, "id")
		if ruleID == "" {
			writeError(w, "invalid_request", "rule id is required")
			return
		}

		existing, err := deps.RuleRepo.GetByID(r.Context(), user.TenantID, ruleID)
		if err != nil {
			log.Printf("ToggleRule error fetching rule: %v", err)
			writeError(w, "internal_error", "failed to get rule")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		if repository.RuleIsManagedSecurityPolicy(existing) {
			writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
			return
		}
		if !repository.RuleHasSupportedMatcher(existing) {
			writeErrorWithStatus(w, http.StatusConflict, "no_runtime_matcher", "add a supported matcher before changing runtime settings")
			return
		}

		newEnabled, err := deps.RuleRepo.ToggleEnabled(r.Context(), user.TenantID, ruleID)
		if err != nil {
			if errors.Is(err, repository.ErrManagedSecurityPolicyReadOnly) {
				writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change this policy")
				return
			}
			if errors.Is(err, repository.ErrRuleNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule not found")
				return
			}
			if errors.Is(err, repository.ErrNoRuntimeRules) {
				writeErrorWithStatus(w, http.StatusConflict, "no_runtime_matcher", "add a supported matcher before changing runtime settings")
				return
			}
			log.Printf("ToggleRule error: %v", err)
			writeError(w, "internal_error", "failed to toggle rule")
			return
		}

		detail := map[string]interface{}{
			"rule_id":     ruleID,
			"name":        existing.Name,
			"enabled_old": !newEnabled,
			"enabled_new": newEnabled,
		}
		logAudit(r, deps, "toggle_rule", detail, "rule", ruleID)

		// Return updated rule
		existing.Enabled = newEnabled
		resp := mapRuleToInfo(existing)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// BatchUpdateDetector batch-updates all rules of a given type
func BatchUpdateDetector(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can update rules")
			return
		}

		var req types.BatchUpdateDetectorRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.RuleType == "" {
			writeError(w, "invalid_request", "rule_type is required")
			return
		}
		req.RuleType = strings.TrimSpace(req.RuleType)
		if req.RuleType == "" {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_rule", "rule_type cannot be blank")
			return
		}
		if req.Action != nil && !validRuleAction(*req.Action) {
			writeErrorWithStatus(w, http.StatusUnprocessableEntity, "invalid_rule", "action is not supported")
			return
		}

		ruleSetID := tenantDefaultRuleSetID(user.TenantID)
		if err := deps.RuleRepo.BatchUpdateByType(r.Context(), user.TenantID, ruleSetID, req.RuleType, req.Enabled, req.Action, req.ReplyMessage); err != nil {
			if errors.Is(err, repository.ErrManagedSecurityPolicyReadOnly) {
				writeErrorWithStatus(w, http.StatusConflict, "security_policy_read_only", "use the security policy center to change managed policies")
				return
			}
			if errors.Is(err, repository.ErrRuleSetNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "rule set not found")
				return
			}
			if errors.Is(err, repository.ErrNoRuntimeRules) {
				writeErrorWithStatus(w, http.StatusConflict, "no_runtime_rules", "no runtime-capable rules exist for this detector type")
				return
			}
			log.Printf("BatchUpdateDetector error: %v", err)
			writeError(w, "internal_error", "failed to update detector")
			return
		}

		detail := map[string]interface{}{
			"rule_type": req.RuleType,
			"rule_set":  ruleSetID,
		}
		if req.Enabled != nil {
			detail["enabled"] = *req.Enabled
		}
		if req.Action != nil {
			detail["action"] = *req.Action
		}
		logAudit(r, deps, "batch_update_detector", detail, "rule_set", ruleSetID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	}
}

func validRuleSeverity(value string) bool {
	switch value {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validRuleAction(value string) bool {
	return securityrules.IsSupportedRuntimeRuleAction(value)
}

func validRulePriority(value int) bool {
	return value >= 0 && value <= 10000
}

// mapRuleToInfo converts a repository.Rule to types.RuleInfo
func mapRuleToInfo(rule *repository.Rule) types.RuleInfo {
	info := types.RuleInfo{
		ID:          rule.ID,
		RuleSetID:   rule.RuleSetID,
		RuleType:    rule.RuleType,
		Name:        rule.Name,
		Priority:    rule.Priority,
		Severity:    rule.Severity,
		Action:      rule.Action,
		Enabled:     rule.Enabled,
		Description: rule.Description,
		CreatedAt:   rule.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if rule.ScopeJSON != nil {
		var scopeMap map[string]interface{}
		if err := json.Unmarshal(rule.ScopeJSON, &scopeMap); err == nil {
			info.ScopeJSON = scopeMap
		}
	}

	if rule.MatchConfigJSON != nil {
		var matchConfigMap map[string]interface{}
		if err := json.Unmarshal(rule.MatchConfigJSON, &matchConfigMap); err == nil {
			info.MatchConfigJSON = matchConfigMap
		}
	}

	return info
}

// InitDetectors seeds all default sub-rules into the default rule set
func InitDetectors(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can init detectors")
			return
		}

		ruleSetID := tenantDefaultRuleSetID(user.TenantID)
		defaultRuleSet := &repository.RuleSet{
			ID:         ruleSetID,
			TenantID:   user.TenantID,
			Name:       "默认安全策略",
			Version:    "1.0.0",
			SourceType: "system",
			Published:  true,
			CreatedBy:  user.ID,
		}
		if _, _, err := deps.RuleSetRepo.Ensure(r.Context(), user.TenantID, defaultRuleSet); err != nil {
			log.Printf("InitDetectors error ensuring default rule set: %v", err)
			writeError(w, "internal_error", "failed to create default rule set")
			return
		}

		created, err := deps.RuleRepo.SeedDefaultSubRules(r.Context(), user.TenantID, ruleSetID)
		if err != nil {
			log.Printf("InitDetectors error: %v", err)
			writeError(w, "internal_error", "failed to seed rules")
			return
		}

		logAudit(r, deps, "init_detectors",
			map[string]interface{}{"rules_created": created},
			"rule_set", ruleSetID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"rules_created": created,
		})
	}
}
