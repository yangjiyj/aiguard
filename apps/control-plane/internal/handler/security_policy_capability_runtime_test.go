package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

func runtimeCapability(category string) rules.CompiledPolicyCapability {
	return rules.CompiledPolicyCapability{Category: category}
}

func TestActivePolicyIDsWithCapabilityHealthHonorsAnyAndAll(t *testing.T) {
	pack := &rules.RulePack{
		Policies: []rules.CompiledPolicy{
			{PolicyID: "semantic-only", BindingMode: "any", Capabilities: []rules.CompiledPolicyCapability{runtimeCapability("semantic_roleplay")}},
			{PolicyID: "mixed-any", BindingMode: "any", Capabilities: []rules.CompiledPolicyCapability{runtimeCapability("keyword_roleplay"), runtimeCapability("semantic_roleplay")}},
			{PolicyID: "mixed-all", BindingMode: "all", Capabilities: []rules.CompiledPolicyCapability{runtimeCapability("keyword_roleplay"), runtimeCapability("semantic_roleplay")}},
			{PolicyID: "static-only", BindingMode: "any", Capabilities: []rules.CompiledPolicyCapability{runtimeCapability("keyword_roleplay")}},
			{PolicyID: "matcher-policy", MatcherRuleID: "matcher-source"},
		},
		Rules: []rules.CompiledRule{{RuleID: "legacy-matcher"}},
	}
	catalog := []repository.SecurityPolicyCapability{
		{Category: "semantic_roleplay", Component: semanticDetectorComponent},
		{Category: "keyword_roleplay", Component: "security-engine.static-detectors"},
	}

	active := activePolicyIDsWithCapabilityHealth(
		pack,
		catalog,
		map[string]struct{}{semanticDetectorComponent: {}},
	)

	for _, id := range []string{"mixed-any", "static-only", "matcher-policy", "legacy-matcher"} {
		if _, ok := active[id]; !ok {
			t.Fatalf("active ids missing %q: %v", id, active)
		}
	}
	for _, id := range []string{"semantic-only", "mixed-all"} {
		if _, ok := active[id]; ok {
			t.Fatalf("unavailable semantic component left %q active: %v", id, active)
		}
	}
}

func TestActivePolicyIDsWithCapabilityHealthRestoresRecoveredComponent(t *testing.T) {
	pack := &rules.RulePack{Policies: []rules.CompiledPolicy{{
		PolicyID: "semantic-only", BindingMode: "any",
		Capabilities: []rules.CompiledPolicyCapability{runtimeCapability("semantic_instruction_override")},
	}}}
	catalog := []repository.SecurityPolicyCapability{{
		Category: "semantic_instruction_override", Component: semanticDetectorComponent,
	}}

	active := activePolicyIDsWithCapabilityHealth(pack, catalog, map[string]struct{}{})

	if _, ok := active["semantic-only"]; !ok {
		t.Fatalf("recovered semantic component was not restored: %v", active)
	}
}

func TestActivePolicyIDsWithCapabilityHealthFailsClosedForUnknownCategory(t *testing.T) {
	pack := &rules.RulePack{Policies: []rules.CompiledPolicy{{
		PolicyID: "unknown-only", BindingMode: "any",
		Capabilities: []rules.CompiledPolicyCapability{runtimeCapability("missing_catalog_entry")},
	}}}

	active := activePolicyIDsWithCapabilityHealth(pack, nil, map[string]struct{}{})

	if _, ok := active["unknown-only"]; ok {
		t.Fatalf("unknown capability was guessed active: %v", active)
	}
}

func TestSemanticDetectorRuntimeReadyRequiresEnabledHealthyAppliedEngine(t *testing.T) {
	healthy := semanticRuntimeComponentStatus{
		Component: semanticEngineComponent,
		Status:    semanticRuntimeStatusApplied,
		Fresh:     true, ConfigLoaded: true,
		ActiveNodes: 1, AppliedNodes: 1,
		JudgeRequired: true, JudgeOperational: true,
	}
	enabled := map[string]any{
		"semantic_enabled":        true,
		"semantic_input_enabled":  true,
		"semantic_output_enabled": false,
	}
	if !semanticDetectorRuntimeReady(enabled, healthy) {
		t.Fatal("healthy enabled semantic detector was not ready")
	}

	disabled := map[string]any{
		"semantic_enabled":        false,
		"semantic_input_enabled":  true,
		"semantic_output_enabled": true,
	}
	if semanticDetectorRuntimeReady(disabled, healthy) {
		t.Fatal("disabled semantic detector was reported ready")
	}

	agentOnly := map[string]any{
		"semantic_enabled":        true,
		"semantic_input_enabled":  false,
		"semantic_output_enabled": false,
		"semantic_agent_enabled":  true,
	}
	if semanticDetectorRuntimeReady(agentOnly, healthy) {
		t.Fatal("agent-only stage cannot back input/output policy capabilities")
	}

	unhealthy := healthy
	unhealthy.JudgeOperational = false
	unhealthy.Status = semanticRuntimeStatusDegraded
	if semanticDetectorRuntimeReady(enabled, unhealthy) {
		t.Fatal("unavailable semantic judge was reported ready")
	}
}
