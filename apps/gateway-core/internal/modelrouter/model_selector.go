package modelrouter

import (
	"strings"
)

// ModelSelector selects the target model based on routing policy strategy.
type ModelSelector struct{}

// NewModelSelector creates a new ModelSelector.
func NewModelSelector() *ModelSelector {
	return &ModelSelector{}
}

// Select chooses the target model for a request given an optional routing policy.
// Returns a ModelDecision with the target model name, strategy used, and decision factors.
func (s *ModelSelector) Select(env RequestEnvelope, policy *RoutingPolicy) ModelDecision {
	if policy == nil || !policy.Enabled {
		return ModelDecision{
			TargetModel: env.Model,
			Strategy:    "default",
		}
	}

	switch policy.Strategy {
	case "prompt_aware":
		return s.selectPromptAware(env, policy)
	case "conditional":
		return s.selectConditional(env, policy)
	case "model_param":
		return s.selectModelParam(env, policy)
	default:
		return ModelDecision{
			TargetModel: env.Model,
			Strategy:    "default",
		}
	}
}

func (s *ModelSelector) selectPromptAware(env RequestEnvelope, policy *RoutingPolicy) ModelDecision {
	cfg := policy.Config

	// Parse scorer config from policy.Config
	scorerCfg := ScorerConfig{
		LowThreshold:  getFloat64(cfg, "low_threshold", 0.3),
		HighThreshold: getFloat64(cfg, "high_threshold", 0.7),
		TokenWeight:   getFloat64(cfg, "token_weight", 0.5),
		KeywordWeight: getFloat64(cfg, "keyword_weight", 0.5),
		MaxTokensForNorm: int(getFloat64(cfg, "max_tokens_for_norm", 10000)),
		HighKeywords:  toStringSlice(cfg["high_keywords"]),
		LowKeywords:   toStringSlice(cfg["low_keywords"]),
	}

	// Build text from content segments
	var sb strings.Builder
	for _, seg := range env.ContentSegments {
		if seg.Type == "text" {
			sb.WriteString(seg.Content)
			sb.WriteString(" ")
		}
	}
	text := sb.String()

	score := ComputeScore(env.PromptTokens, text, scorerCfg)

	var targetModel string
	switch score.Tier {
	case "high":
		targetModel = getString(cfg, "high_model", env.Model)
	case "low":
		targetModel = getString(cfg, "low_model", env.Model)
	default:
		targetModel = getString(cfg, "mid_model", env.Model)
	}

	reason := make(map[string]any, len(score.Factors)+1)
	for k, v := range score.Factors {
		reason[k] = v
	}
	reason["tier"] = score.Tier

	return ModelDecision{
		TargetModel: targetModel,
		Strategy:    "prompt_aware",
		Reason:      reason,
	}
}

func (s *ModelSelector) selectConditional(env RequestEnvelope, policy *RoutingPolicy) ModelDecision {
	cfg := policy.Config
	defaultModel := getString(cfg, "default_model", env.Model)

	rules, _ := cfg["rules"].([]any)
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		field := getString(rule, "field", "")
		op := getString(rule, "op", "eq")
		value := getString(rule, "value", "")
		targetModel := getString(rule, "target_model", "")

		var fieldValue string
		switch field {
		case "agent_type":
			fieldValue = env.AgentType
		case "user_id":
			fieldValue = env.UserID
		case "model":
			fieldValue = env.Model
		default:
			continue
		}

		matched := false
		switch op {
		case "eq":
			matched = fieldValue == value
		case "prefix":
			matched = strings.HasPrefix(fieldValue, value)
		}

		if matched && targetModel != "" {
			return ModelDecision{
				TargetModel: targetModel,
				Strategy:    "conditional",
				Reason: map[string]any{
					"matched_field": field,
					"matched_value": value,
					"op":            op,
				},
			}
		}
	}

	return ModelDecision{
		TargetModel: defaultModel,
		Strategy:    "conditional",
		Reason:      map[string]any{"matched_field": "none", "used_default": true},
	}
}

func (s *ModelSelector) selectModelParam(env RequestEnvelope, policy *RoutingPolicy) ModelDecision {
	cfg := policy.Config
	defaultModel := getString(cfg, "default_model", env.Model)

	if env.RouteHint == "" {
		return ModelDecision{
			TargetModel: defaultModel,
			Strategy:    "model_param",
			Reason:      map[string]any{"route_hint": "", "used_default": true},
		}
	}

	// Check allowed_routes
	allowed := toStringSlice(cfg["allowed_routes"])
	isAllowed := false
	for _, r := range allowed {
		if r == env.RouteHint {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		return ModelDecision{
			TargetModel: defaultModel,
			Strategy:    "model_param",
			Reason:      map[string]any{"route_hint": env.RouteHint, "allowed": false, "used_default": true},
		}
	}

	// Look up route_map
	routeMap, _ := cfg["route_map"].(map[string]any)
	if routeMap == nil {
		return ModelDecision{
			TargetModel: defaultModel,
			Strategy:    "model_param",
			Reason:      map[string]any{"route_hint": env.RouteHint, "route_map_missing": true},
		}
	}
	if mappedModel, ok := routeMap[env.RouteHint].(string); ok && mappedModel != "" {
		return ModelDecision{
			TargetModel: mappedModel,
			Strategy:    "model_param",
			Reason:      map[string]any{"route_hint": env.RouteHint, "mapped_model": mappedModel},
		}
	}

	return ModelDecision{
		TargetModel: defaultModel,
		Strategy:    "model_param",
		Reason:      map[string]any{"route_hint": env.RouteHint, "mapping_not_found": true},
	}
}

// --- helpers ---

func getFloat64(m map[string]any, key string, def float64) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return def
}

func getString(m map[string]any, key string, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func toStringSlice(v any) []string {
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
