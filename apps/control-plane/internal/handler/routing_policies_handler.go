package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ListRoutingPolicies handles GET /admin/v1/routing-policies?scope_type=&scope_ref=
func ListRoutingPolicies(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		scopeType := r.URL.Query().Get("scope_type")
		scopeRef := r.URL.Query().Get("scope_ref")

		var policies []*repository.RoutingPolicy
		var err error
		if scopeType == "" && scopeRef == "" {
			// No scope filter: list all policies for the tenant
			policies, err = deps.RoutingPolicyRepo.ListByTenant(r.Context(), user.TenantID)
		} else {
			policies, err = deps.RoutingPolicyRepo.ListByScope(r.Context(), user.TenantID, scopeType, scopeRef)
		}
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if policies == nil {
			policies = []*repository.RoutingPolicy{}
		}

		type response struct {
			Data []*repository.RoutingPolicy `json:"data"`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{Data: policies})
	}
}

// UpsertRoutingPolicy handles PUT /admin/v1/routing-policies
func UpsertRoutingPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		var req struct {
			ID        string         `json:"id"`
			ScopeType string         `json:"scope_type"`
			ScopeRef  string         `json:"scope_ref"`
			Layer     string         `json:"layer"`
			Strategy  string         `json:"strategy"`
			Config    map[string]any `json:"config"`
			Enabled   *bool          `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.ScopeType == "" || req.Layer == "" || req.Strategy == "" {
			writeError(w, "invalid_request", "scope_type, layer, and strategy are required")
			return
		}

		if req.ID == "" {
			req.ID = "rp_" + uuid.New().String()[:8]
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if req.Config == nil {
			req.Config = map[string]any{}
		}

		p := &repository.RoutingPolicy{
			ID:         req.ID,
			TenantID:   user.TenantID,
			ScopeType:  req.ScopeType,
			ScopeRef:   req.ScopeRef,
			Layer:      req.Layer,
			Strategy:   req.Strategy,
			ConfigJSON: req.Config,
			Enabled:    enabled,
		}

		if err := deps.RoutingPolicyRepo.Upsert(r.Context(), p); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "routing_policy.update", map[string]any{
			"policy_id":  p.ID,
			"scope_type": p.ScopeType,
			"scope_ref":  p.ScopeRef,
			"layer":      p.Layer,
			"strategy":   p.Strategy,
			"enabled":    p.Enabled,
		}, "routing_policy", p.ID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(p)
	}
}

// DeleteRoutingPolicy handles DELETE /admin/v1/routing-policies/{id}
func DeleteRoutingPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		// Verify ownership before delete
		existing, err := deps.RoutingPolicyRepo.GetByID(r.Context(), id)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if existing == nil {
			writeError(w, "not_found", "routing policy not found")
			return
		}
		if existing.TenantID != user.TenantID {
			writeError(w, "forbidden", "not allowed to delete this policy")
			return
		}

		if err := deps.RoutingPolicyRepo.Delete(r.Context(), id); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "routing_policy.delete", map[string]any{
			"policy_id":  id,
			"scope_type": existing.ScopeType,
			"scope_ref":  existing.ScopeRef,
			"layer":      existing.Layer,
		}, "routing_policy", id)

		w.WriteHeader(http.StatusNoContent)
	}
}

// TestRoutingPolicy handles POST /admin/v1/routing-policies/test
// It simulates the prompt_aware scoring without importing gateway-core.
// For non-prompt_aware strategies it returns config validation only.
func TestRoutingPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		var req struct {
			PromptTokens int            `json:"prompt_tokens"`
			Text         string         `json:"text"`
			Strategy     string         `json:"strategy"`
			Config       map[string]any `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.Strategy == "" {
			writeError(w, "invalid_request", "strategy is required")
			return
		}
		if req.Config == nil {
			req.Config = map[string]any{}
		}

		switch req.Strategy {
		case "prompt_aware":
			result := previewPromptAware(req.PromptTokens, req.Text, req.Config)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(result)
		default:
			explain, valid := validateStrategyConfig(req.Strategy, req.Config)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"valid":    valid,
				"strategy": req.Strategy,
				"explain":  explain,
			})
		}
	}
}

// previewPromptAware replicates the modelrouter scorer logic without importing gateway-core.
func previewPromptAware(promptTokens int, text string, cfg map[string]any) map[string]any {
	lowThreshold := getConfigFloat(cfg, "low_threshold", 0.3)
	highThreshold := getConfigFloat(cfg, "high_threshold", 0.7)
	tokenWeight := getConfigFloat(cfg, "token_weight", 0.5)
	keywordWeight := getConfigFloat(cfg, "keyword_weight", 0.5)
	maxTokensForNorm := int(getConfigFloat(cfg, "max_tokens_for_norm", 10000))
	highKeywords := getConfigStringSlice(cfg, "high_keywords")
	lowKeywords := getConfigStringSlice(cfg, "low_keywords")
	highModel := getConfigString(cfg, "high_model", "")
	midModel := getConfigString(cfg, "mid_model", "")
	lowModel := getConfigString(cfg, "low_model", "")

	if maxTokensForNorm <= 0 {
		maxTokensForNorm = 10000
	}
	tokenScore := float64(promptTokens) / float64(maxTokensForNorm)
	if tokenScore > 1 {
		tokenScore = 1
	}

	var matchedHigh, matchedLow []string
	for _, kw := range highKeywords {
		if kw != "" && strings.Contains(text, kw) {
			matchedHigh = append(matchedHigh, kw)
		}
	}
	for _, kw := range lowKeywords {
		if kw != "" && strings.Contains(text, kw) {
			matchedLow = append(matchedLow, kw)
		}
	}

	keywordScore := 0.5
	if len(matchedHigh) > 0 {
		keywordScore = 1.0
	}
	if len(matchedLow) > 0 && len(matchedHigh) == 0 {
		keywordScore = 0.0
	}

	value := tokenWeight*tokenScore + keywordWeight*keywordScore
	tier := "mid"
	targetModel := midModel
	if value < lowThreshold {
		tier = "low"
		targetModel = lowModel
	} else if value >= highThreshold {
		tier = "high"
		targetModel = highModel
	}

	return map[string]any{
		"tier":         tier,
		"score":        value,
		"target_model": targetModel,
		"factors": map[string]any{
			"tokens":        promptTokens,
			"token_score":   tokenScore,
			"keyword_score": keywordScore,
			"matched_high":  matchedHigh,
			"matched_low":   matchedLow,
		},
		"thresholds": map[string]any{
			"low":  lowThreshold,
			"high": highThreshold,
		},
	}
}

// validateStrategyConfig checks that required config keys exist for a given strategy.
func validateStrategyConfig(strategy string, cfg map[string]any) (string, bool) {
	switch strategy {
	case "fallback":
		chain, _ := cfg["provider_chain"].([]any)
		if len(chain) == 0 {
			return "fallback strategy requires provider_chain as non-empty array", false
		}
		return "valid fallback config", true
	case "lb":
		wp, _ := cfg["weighted_providers"].([]any)
		if len(wp) == 0 {
			return "lb strategy requires weighted_providers as non-empty array", false
		}
		return "valid lb config", true
	case "canary":
		canary := getConfigString(cfg, "canary_provider", "")
		if canary == "" {
			return "canary strategy requires canary_provider", false
		}
		return "valid canary config", true
	case "conditional":
		return "valid conditional config", true
	case "model_param":
		return "valid model_param config; uses X-UAG-Route header for routing", true
	case "single":
		return "single strategy: uses default provider", true
	default:
		return "unknown strategy: " + strategy, false
	}
}

// --- config helpers ---

func getConfigFloat(cfg map[string]any, key string, def float64) float64 {
	v, ok := cfg[key]
	if !ok {
		return def
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	}
	return def
}

func getConfigString(cfg map[string]any, key, def string) string {
	v, ok := cfg[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	return s
}

func getConfigStringSlice(cfg map[string]any, key string) []string {
	v, ok := cfg[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
