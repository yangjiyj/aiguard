package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type chatRoutingDecisionInput struct {
	ctx              context.Context
	envelope         *modelrouter.RequestEnvelope
	modelRecord      *modelrouter.ModelRecord
	providerCaller   ProviderCaller
	fallbackProvider *FallbackProviderPlan
	modelDecision    *modelrouter.ModelDecision
	governorOverride map[string]any
	providerDecision *modelrouter.ProviderDecision
}

type chatRoutingDecisionResult struct {
	providerCaller   ProviderCaller
	fallbackProvider *FallbackProviderPlan
}

func (h *ChatCompletionsHandler) applyChatRoutingDecision(input chatRoutingDecisionInput) chatRoutingDecisionResult {
	result := chatRoutingDecisionResult{
		providerCaller:   input.providerCaller,
		fallbackProvider: input.fallbackProvider,
	}
	provDec := input.providerDecision

	if provDec != nil && provDec.ProviderID != "" && provDec.ProviderID != input.envelope.ProviderID {
		// Routing policy overrides the default provider; update envelope + recreate adapter.
		input.envelope.ProviderID = provDec.ProviderID
		if providerRecord, providerErr := h.modelResolver.GetProvider(input.ctx, input.envelope.TenantID, provDec.ProviderID); providerErr == nil && providerRecord != nil {
			input.envelope.Provider = providerRecord.ProviderType
			if newKey, err := h.modelResolver.GetProviderCredential(input.ctx, provDec.ProviderID); err == nil && newKey != "" {
				newRecord := *input.modelRecord
				newRecord.ProviderID = providerRecord.ID
				newRecord.ProviderType = providerRecord.ProviderType
				newRecord.ProviderBaseURL = providerRecord.BaseURL
				newRecord.ProviderAuthMode = providerRecord.AuthMode
				newRecord.UpstreamProxyURL = providerRecord.UpstreamProxyURL
				result.providerCaller = h.providerAdapterFactory.CreateAdapter(&newRecord, newKey)
			}
		}
	}

	fallbackRetries := 0
	if chainPlan := buildFallbackChainPlan(input.ctx, h.modelResolver, h.providerAdapterFactory, input.envelope.TenantID, input.modelRecord, provDec); chainPlan != nil {
		result.fallbackProvider = chainPlan
		fallbackRetries = fallbackChainLength(chainPlan)
	}

	input.envelope.RoutingDecision = &modelrouter.RoutingDecision{
		ModelLayer:       input.modelDecision,
		GovernorOverride: input.governorOverride,
		ProviderLayer:    provDec,
		FallbackRetries:  fallbackRetries,
	}

	return result
}
