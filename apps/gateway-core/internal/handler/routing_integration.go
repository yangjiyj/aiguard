package handler

import (
	"context"
	"os"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// SetRouting injects the routing layer components (ModelSelector, ProviderSelector, PolicyCache).
// Call once during server startup. All three must be non-nil to enable routing; passing nil
// for any disables the routing layer (fail-open: requests use default model/provider).
func (h *ChatCompletionsHandler) SetRouting(
	ms *modelrouter.ModelSelector,
	ps *modelrouter.ProviderSelector,
	pc *modelrouter.PolicyCache,
	v2 ...modelrouter.Engine,
) {
	h.modelSelector = ms
	h.providerSelector = ps
	h.policyCache = pc
	if len(v2) > 0 {
		h.modelRouteEngine = v2[0]
	}
}

// resolveModelLayer runs before the governor to pick the target model.
// Returns nil when routing is disabled or encounters an error (fail-open).
// When a non-empty TargetModel is returned the envelope.Model is updated in-place.
func (h *ChatCompletionsHandler) resolveModelLayer(ctx context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
	if h.policyCache == nil || h.modelSelector == nil {
		return nil // routing not enabled
	}
	if os.Getenv("UAG_ROUTING_DISABLED") == "true" {
		return nil
	}

	// Use model name as scope_ref for model-layer lookup.
	policy, err := h.policyCache.GetPolicy(ctx, env.TenantID, "model", env.Model, "model")
	if err != nil {
		return nil // fail-open
	}

	dec := h.modelSelector.Select(*env, policy)
	if dec.TargetModel != "" && dec.TargetModel != env.Model {
		env.Model = dec.TargetModel
		// Keep ModelID unchanged — governor/downgrade may further update it.
	}
	return &dec
}

// resolveProviderLayer runs after the governor to pick the upstream provider.
// Returns nil when routing is disabled or encounters an error (fail-open).
// The returned ProviderDecision.ProviderID should override the default provider.
func (h *ChatCompletionsHandler) resolveProviderLayer(ctx context.Context, env *modelrouter.RequestEnvelope, defaultProviderID string) *modelrouter.ProviderDecision {
	if h.policyCache == nil || h.providerSelector == nil {
		return nil // routing not enabled
	}
	if os.Getenv("UAG_ROUTING_DISABLED") == "true" {
		return nil
	}

	// Use model name as scope_ref for provider-layer lookup.
	policy, err := h.policyCache.GetPolicy(ctx, env.TenantID, "model", env.Model, "provider")
	if err != nil {
		return nil // fail-open
	}

	dec := h.providerSelector.Select(env.Model, defaultProviderID, *env, policy)
	return &dec
}
