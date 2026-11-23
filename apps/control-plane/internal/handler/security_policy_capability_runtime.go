package handler

import (
	"context"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

const semanticDetectorComponent = "security-engine.semantic"

func semanticDetectorRuntimeReady(
	config map[string]any,
	component semanticRuntimeComponentStatus,
) bool {
	master, _ := config["semantic_enabled"].(bool)
	input, _ := config["semantic_input_enabled"].(bool)
	output, _ := config["semantic_output_enabled"].(bool)
	if !master || (!input && !output) {
		return false
	}
	return component.Component == semanticEngineComponent &&
		component.Status == semanticRuntimeStatusApplied &&
		component.Fresh && component.ConfigLoaded &&
		component.ActiveNodes > 0 &&
		component.AppliedNodes == component.ActiveNodes &&
		component.JudgeRequired && component.JudgeOperational
}

func unavailableSecurityPolicyCapabilityComponents(
	ctx context.Context,
	deps *Dependencies,
) map[string]struct{} {
	unavailable := map[string]struct{}{semanticDetectorComponent: {}}
	configs, err := buildSemanticComponentConfigs(ctx, deps)
	if err != nil {
		return unavailable
	}
	runtime := buildSemanticRuntimeStatus(semanticDesiredRevisions{
		Engine: configs.EngineRevision, Gateway: configs.GatewayRevision,
		EngineJudgeRequired: semanticEngineJudgeRequired(configs.Engine),
	}, time.Now().UTC())
	for _, component := range runtime.Components {
		if semanticDetectorRuntimeReady(configs.Engine, component) {
			delete(unavailable, semanticDetectorComponent)
			break
		}
	}
	return unavailable
}

// activePolicyIDsWithCapabilityHealth starts from the identities proven by a
// complete rule-pack receipt, then removes capability policies whose detector
// component is not currently operational. Matcher policies and legacy matcher
// rules remain governed by the rule-pack receipt itself.
func activePolicyIDsWithCapabilityHealth(
	pack *rules.RulePack,
	catalog []repository.SecurityPolicyCapability,
	unavailableComponents map[string]struct{},
) map[string]struct{} {
	active := activeSecurityPolicyIDs(pack)
	componentByCategory := make(map[string]string, len(catalog))
	for _, capability := range catalog {
		category := strings.TrimSpace(capability.Category)
		component := strings.TrimSpace(capability.Component)
		if category != "" && component != "" {
			componentByCategory[category] = component
		}
	}
	for _, policy := range pack.Policies {
		if len(policy.Capabilities) == 0 {
			continue
		}
		available := 0
		for _, capability := range policy.Capabilities {
			component, known := componentByCategory[strings.TrimSpace(capability.Category)]
			if !known {
				continue
			}
			if _, unavailable := unavailableComponents[component]; !unavailable {
				available++
			}
		}
		satisfied := available > 0
		if policy.BindingMode == "all" {
			satisfied = available == len(policy.Capabilities)
		}
		if !satisfied {
			delete(active, strings.TrimSpace(policy.PolicyID))
		}
	}
	return active
}
