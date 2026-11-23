package modelrouter

import (
	"crypto/sha256"
	"encoding/binary"
)

// ProviderSelector chooses a provider for a given model request based on routing policy.
type ProviderSelector struct{}

// NewProviderSelector creates a new ProviderSelector.
func NewProviderSelector() *ProviderSelector {
	return &ProviderSelector{}
}

// Select picks the provider to use for a request.
// defaultProviderID is the fallback if no policy applies.
func (s *ProviderSelector) Select(targetModel, defaultProviderID string, env RequestEnvelope, policy *RoutingPolicy) ProviderDecision {
	if policy == nil || !policy.Enabled {
		return ProviderDecision{
			ProviderID: defaultProviderID,
			Strategy:   "single",
		}
	}

	switch policy.Strategy {
	case "lb":
		return s.selectLB(defaultProviderID, env, policy)
	case "fallback":
		return s.selectFallback(defaultProviderID, policy)
	case "canary":
		return s.selectCanary(defaultProviderID, env, policy)
	default:
		// strategy == "single" or unknown
		return ProviderDecision{
			ProviderID: defaultProviderID,
			Strategy:   "single",
		}
	}
}

// selectLB selects a provider using consistent hash over weighted providers.
func (s *ProviderSelector) selectLB(defaultProviderID string, env RequestEnvelope, policy *RoutingPolicy) ProviderDecision {
	cfg := policy.Config
	wpRaw, ok := cfg["weighted_providers"].([]any)
	if !ok || len(wpRaw) == 0 {
		return ProviderDecision{ProviderID: defaultProviderID, Strategy: "lb"}
	}

	type weightedProvider struct {
		id     string
		weight int
	}

	providers := make([]weightedProvider, 0, len(wpRaw))
	totalWeight := 0
	for _, raw := range wpRaw {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id := getString(m, "id", "")
		weight := int(getFloat64(m, "weight", 0))
		if id == "" || weight <= 0 {
			continue
		}
		providers = append(providers, weightedProvider{id: id, weight: weight})
		totalWeight += weight
	}

	if len(providers) == 0 || totalWeight == 0 {
		return ProviderDecision{ProviderID: defaultProviderID, Strategy: "lb"}
	}

	// Stable hash of RequestID -> [0, totalWeight). The modulo result is bounded
	// by the positive int totalWeight, so the conversion back to int is safe.
	sum := sha256.Sum256([]byte(env.RequestID))
	bucket64 := binary.BigEndian.Uint64(sum[:8]) % uint64(totalWeight)
	bucket := int(bucket64) // #nosec G115 -- bucket64 is < totalWeight and totalWeight is an int.

	cumulative := 0
	selected := providers[len(providers)-1]
	for _, p := range providers {
		cumulative += p.weight
		if bucket < cumulative {
			selected = p
			break
		}
	}

	return ProviderDecision{
		ProviderID: selected.id,
		Strategy:   "lb",
		Reason: map[string]any{
			"selected_weight": selected.weight,
			"total_weight":    totalWeight,
		},
	}
}

// selectFallback returns the first provider in chain as the primary, with full chain for retry.
func (s *ProviderSelector) selectFallback(defaultProviderID string, policy *RoutingPolicy) ProviderDecision {
	cfg := policy.Config
	chainRaw, ok := cfg["provider_chain"].([]any)
	if !ok || len(chainRaw) == 0 {
		return ProviderDecision{ProviderID: defaultProviderID, Strategy: "fallback"}
	}

	chain := make([]string, 0, len(chainRaw))
	for _, raw := range chainRaw {
		if s, ok := raw.(string); ok && s != "" {
			chain = append(chain, s)
		}
	}
	if len(chain) == 0 {
		return ProviderDecision{ProviderID: defaultProviderID, Strategy: "fallback"}
	}

	return ProviderDecision{
		ProviderID:    chain[0],
		Strategy:      "fallback",
		FallbackChain: chain,
		Reason: map[string]any{
			"chain_length": len(chain),
		},
	}
}

// selectCanary routes a fraction of traffic to the canary provider by request ID.
func (s *ProviderSelector) selectCanary(defaultProviderID string, env RequestEnvelope, policy *RoutingPolicy) ProviderDecision {
	cfg := policy.Config
	stableProvider := getString(cfg, "stable_provider", defaultProviderID)
	canaryProvider := getString(cfg, "canary_provider", "")
	canaryRatio := int(getFloat64(cfg, "canary_ratio", 0))

	if canaryProvider == "" {
		return ProviderDecision{ProviderID: stableProvider, Strategy: "canary",
			Reason: map[string]any{"canary_provider_missing": true}}
	}

	if CanaryHit(env.RequestID, canaryRatio) {
		return ProviderDecision{
			ProviderID: canaryProvider,
			Strategy:   "canary",
			Reason: map[string]any{
				"bucket":       "canary",
				"canary_ratio": canaryRatio,
				"canary_hit":   true,
			},
		}
	}

	return ProviderDecision{
		ProviderID: stableProvider,
		Strategy:   "canary",
		Reason: map[string]any{
			"bucket":       "stable",
			"canary_ratio": canaryRatio,
			"canary_hit":   false,
		},
	}
}
