package modelrouter

import (
	"fmt"
	"testing"
)

func TestProviderSelectorSingle(t *testing.T) {
	sel := NewProviderSelector()
	env := RequestEnvelope{RequestID: "req-1"}

	// nil policy → single
	dec := sel.Select("gpt-4", "provider-a", env, nil)
	if dec.ProviderID != "provider-a" || dec.Strategy != "single" {
		t.Errorf("nil policy: got provider=%s strategy=%s", dec.ProviderID, dec.Strategy)
	}

	// disabled policy → single
	policy := &RoutingPolicy{Strategy: "lb", Enabled: false}
	dec = sel.Select("gpt-4", "provider-a", env, policy)
	if dec.Strategy != "single" {
		t.Errorf("disabled policy: expected single, got %s", dec.Strategy)
	}

	// explicit single strategy
	policy = &RoutingPolicy{Strategy: "single", Enabled: true, Config: map[string]any{}}
	dec = sel.Select("gpt-4", "provider-a", env, policy)
	if dec.ProviderID != "provider-a" || dec.Strategy != "single" {
		t.Errorf("explicit single: got provider=%s strategy=%s", dec.ProviderID, dec.Strategy)
	}
}

func TestProviderSelectorLBDistribution(t *testing.T) {
	sel := NewProviderSelector()
	policy := &RoutingPolicy{
		Strategy: "lb",
		Enabled:  true,
		Config: map[string]any{
			"weighted_providers": []any{
				map[string]any{"id": "provider-a", "weight": float64(80)},
				map[string]any{"id": "provider-b", "weight": float64(20)},
			},
		},
	}

	total := 1000
	hits := map[string]int{}
	for i := 0; i < total; i++ {
		env := RequestEnvelope{RequestID: fmt.Sprintf("request-%d", i)}
		dec := sel.Select("gpt-4", "provider-a", env, policy)
		hits[dec.ProviderID]++
	}

	// Expect provider-a ~80%, provider-b ~20% — allow ±10%
	pctA := float64(hits["provider-a"]) / float64(total) * 100
	pctB := float64(hits["provider-b"]) / float64(total) * 100

	if pctA < 70 || pctA > 90 {
		t.Errorf("LB provider-a: expected 70%%–90%%, got %.1f%%", pctA)
	}
	if pctB < 10 || pctB > 30 {
		t.Errorf("LB provider-b: expected 10%%–30%%, got %.1f%%", pctB)
	}
}

func TestProviderSelectorFallback(t *testing.T) {
	sel := NewProviderSelector()
	env := RequestEnvelope{RequestID: "req-1"}
	policy := &RoutingPolicy{
		Strategy: "fallback",
		Enabled:  true,
		Config: map[string]any{
			"provider_chain": []any{"provider-a", "provider-b", "provider-c"},
		},
	}

	dec := sel.Select("gpt-4", "default-provider", env, policy)
	if dec.ProviderID != "provider-a" {
		t.Errorf("fallback primary: expected provider-a, got %s", dec.ProviderID)
	}
	if dec.Strategy != "fallback" {
		t.Errorf("strategy: expected fallback, got %s", dec.Strategy)
	}
	if len(dec.FallbackChain) != 3 {
		t.Errorf("fallback chain length: expected 3, got %d", len(dec.FallbackChain))
	}
	if dec.FallbackChain[0] != "provider-a" || dec.FallbackChain[2] != "provider-c" {
		t.Errorf("fallback chain order: got %v", dec.FallbackChain)
	}
}

func TestProviderSelectorCanary(t *testing.T) {
	sel := NewProviderSelector()
	policy := &RoutingPolicy{
		Strategy: "canary",
		Enabled:  true,
		Config: map[string]any{
			"stable_provider": "provider-stable",
			"canary_provider": "provider-canary",
			"canary_ratio":    float64(20),
		},
	}

	total := 1000
	canaryHits := 0
	for i := 0; i < total; i++ {
		env := RequestEnvelope{RequestID: fmt.Sprintf("canary-req-%d", i)}
		dec := sel.Select("gpt-4", "provider-stable", env, policy)
		if dec.ProviderID == "provider-canary" {
			canaryHits++
		}
		if dec.Strategy != "canary" {
			t.Fatalf("strategy: expected canary, got %s", dec.Strategy)
		}
	}

	pct := float64(canaryHits) / float64(total) * 100
	if pct < 14 || pct > 26 {
		t.Errorf("canary ratio=20: expected 14%%–26%% hits, got %.1f%%", pct)
	}
}
