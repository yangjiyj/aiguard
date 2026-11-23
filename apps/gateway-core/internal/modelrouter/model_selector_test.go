package modelrouter

import (
	"testing"
)

func TestModelSelectorDefault(t *testing.T) {
	sel := NewModelSelector()
	env := RequestEnvelope{Model: "gpt-4"}

	// nil policy → default
	dec := sel.Select(env, nil)
	if dec.TargetModel != "gpt-4" || dec.Strategy != "default" {
		t.Errorf("nil policy: got target=%s strategy=%s", dec.TargetModel, dec.Strategy)
	}

	// disabled policy → default
	policy := &RoutingPolicy{Strategy: "prompt_aware", Enabled: false}
	dec = sel.Select(env, policy)
	if dec.Strategy != "default" {
		t.Errorf("disabled policy: expected default, got %s", dec.Strategy)
	}
}

func TestModelSelectorModelParam(t *testing.T) {
	sel := NewModelSelector()
	env := RequestEnvelope{
		Model:     "gpt-4",
		RouteHint: "fast",
	}
	policy := &RoutingPolicy{
		Strategy: "model_param",
		Enabled:  true,
		Config: map[string]any{
			"default_model":  "gpt-4",
			"allowed_routes": []any{"fast", "smart"},
			"route_map": map[string]any{
				"fast":  "gpt-3.5-turbo",
				"smart": "gpt-4-turbo",
			},
		},
	}

	dec := sel.Select(env, policy)
	if dec.TargetModel != "gpt-3.5-turbo" {
		t.Errorf("model_param fast: expected gpt-3.5-turbo, got %s", dec.TargetModel)
	}
	if dec.Strategy != "model_param" {
		t.Errorf("strategy: expected model_param, got %s", dec.Strategy)
	}

	// disallowed hint → default
	env.RouteHint = "unknown"
	dec = sel.Select(env, policy)
	if dec.TargetModel != "gpt-4" {
		t.Errorf("disallowed hint: expected default gpt-4, got %s", dec.TargetModel)
	}
}

func TestModelSelectorPromptAwareHighComplexity(t *testing.T) {
	sel := NewModelSelector()
	env := RequestEnvelope{
		Model:        "gpt-3.5-turbo",
		PromptTokens: 9000,
		ContentSegments: []ContentSegment{
			{Type: "text", Content: "analyze this complex problem"},
		},
	}
	policy := &RoutingPolicy{
		Strategy: "prompt_aware",
		Enabled:  true,
		Config: map[string]any{
			"low_threshold":     0.3,
			"high_threshold":    0.7,
			"token_weight":      float64(1.0),
			"keyword_weight":    float64(0.0),
			"max_tokens_for_norm": float64(10000),
			"low_model":         "gpt-3.5-turbo",
			"mid_model":         "gpt-4",
			"high_model":        "gpt-4-turbo",
			"high_keywords":     []any{"analyze"},
			"low_keywords":      []any{},
		},
	}

	dec := sel.Select(env, policy)
	if dec.TargetModel != "gpt-4-turbo" {
		t.Errorf("high complexity: expected gpt-4-turbo, got %s", dec.TargetModel)
	}
	if dec.Strategy != "prompt_aware" {
		t.Errorf("strategy: expected prompt_aware, got %s", dec.Strategy)
	}
	if dec.Reason == nil {
		t.Error("reason should not be nil")
	}
	if dec.Reason["tier"] != "high" {
		t.Errorf("tier in reason: expected high, got %v", dec.Reason["tier"])
	}
}

func TestModelSelectorConditionalAgentType(t *testing.T) {
	sel := NewModelSelector()
	env := RequestEnvelope{
		Model:     "gpt-4",
		AgentType: "coder",
	}
	policy := &RoutingPolicy{
		Strategy: "conditional",
		Enabled:  true,
		Config: map[string]any{
			"default_model": "gpt-4",
			"rules": []any{
				map[string]any{
					"field":        "agent_type",
					"op":           "eq",
					"value":        "coder",
					"target_model": "claude-3-5-sonnet",
				},
			},
		},
	}

	dec := sel.Select(env, policy)
	if dec.TargetModel != "claude-3-5-sonnet" {
		t.Errorf("conditional agent_type=coder: expected claude-3-5-sonnet, got %s", dec.TargetModel)
	}
	if dec.Strategy != "conditional" {
		t.Errorf("strategy: expected conditional, got %s", dec.Strategy)
	}
	if dec.Reason["matched_field"] != "agent_type" {
		t.Errorf("reason matched_field: expected agent_type, got %v", dec.Reason["matched_field"])
	}

	// Non-matching agent type falls back to default
	env.AgentType = "assistant"
	dec = sel.Select(env, policy)
	if dec.TargetModel != "gpt-4" {
		t.Errorf("conditional no-match: expected default gpt-4, got %s", dec.TargetModel)
	}
}
