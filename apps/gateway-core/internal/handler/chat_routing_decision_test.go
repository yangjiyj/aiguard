package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestApplyChatRoutingDecisionProviderOverrideReplacesCaller(t *testing.T) {
	primaryCaller := &MockProviderCaller{}
	canaryCaller := &MockProviderCaller{}
	handler := &ChatCompletionsHandler{
		modelResolver: &MockModelResolver{},
		providerAdapterFactory: &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
			"provider-canary": canaryCaller,
		}},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", Model: "gpt-4", ProviderID: "provider-primary", Provider: "openai"}
	modelRecord := &modelrouter.ModelRecord{ID: "model-1", ProviderID: "provider-primary", ProviderType: "openai"}
	providerDecision := &modelrouter.ProviderDecision{ProviderID: "provider-canary", Strategy: "canary"}
	modelDecision := &modelrouter.ModelDecision{TargetModel: "gpt-4", Strategy: "single"}

	result := handler.applyChatRoutingDecision(chatRoutingDecisionInput{
		ctx:              context.Background(),
		envelope:         envelope,
		modelRecord:      modelRecord,
		providerCaller:   primaryCaller,
		modelDecision:    modelDecision,
		providerDecision: providerDecision,
	})

	if result.providerCaller != canaryCaller {
		t.Fatalf("expected provider override to replace caller")
	}
	if envelope.ProviderID != "provider-canary" {
		t.Fatalf("expected envelope provider override, got %q", envelope.ProviderID)
	}
	if envelope.RoutingDecision == nil {
		t.Fatal("expected routing decision to be populated")
	}
	if envelope.RoutingDecision.ModelLayer != modelDecision || envelope.RoutingDecision.ProviderLayer != providerDecision {
		t.Fatalf("routing decision lost layers: %+v", envelope.RoutingDecision)
	}
	if envelope.RoutingDecision.FallbackRetries != 0 {
		t.Fatalf("expected no fallback retries, got %d", envelope.RoutingDecision.FallbackRetries)
	}
}

func TestApplyChatRoutingDecisionProviderOverrideUsesOverrideMetadata(t *testing.T) {
	canaryCaller := &MockProviderCaller{}
	providerFactory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
		"provider-canary": canaryCaller,
	}}
	handler := &ChatCompletionsHandler{
		modelResolver: &MockModelResolver{ProvidersByID: map[string]*modelrouter.ProviderRecord{
			"provider-canary": {
				ID:           "provider-canary",
				ProviderType: "anthropic",
				BaseURL:      "https://anthropic.example.com",
				AuthMode:     "x-api-key",
				Status:       "active",
			},
		}},
		providerAdapterFactory: providerFactory,
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", Model: "claude-3", ProviderID: "provider-primary", Provider: "openai"}
	modelRecord := &modelrouter.ModelRecord{ID: "model-1", ProviderID: "provider-primary", ProviderType: "openai", ProviderBaseURL: "https://openai.example.com", ProviderAuthMode: "bearer"}
	providerDecision := &modelrouter.ProviderDecision{
		ProviderID: "provider-canary",
		Strategy:   "canary",
		Reason: map[string]any{
			"provider_type": "anthropic",
			"base_url":      "https://anthropic.example.com",
			"auth_mode":     "x-api-key",
		},
	}

	result := handler.applyChatRoutingDecision(chatRoutingDecisionInput{
		ctx:              context.Background(),
		envelope:         envelope,
		modelRecord:      modelRecord,
		providerCaller:   &MockProviderCaller{},
		providerDecision: providerDecision,
	})

	if result.providerCaller != canaryCaller {
		t.Fatalf("expected provider override to replace caller")
	}
	if len(providerFactory.CreatedRecords) != 1 {
		t.Fatalf("expected one adapter creation, got %d", len(providerFactory.CreatedRecords))
	}
	created := providerFactory.CreatedRecords[0]
	if created.ProviderID != "provider-canary" || created.ProviderType != "anthropic" || created.ProviderBaseURL != "https://anthropic.example.com" || created.ProviderAuthMode != "x-api-key" {
		t.Fatalf("override adapter used wrong provider metadata: %+v", created)
	}
	if envelope.Provider != "anthropic" || envelope.ProviderID != "provider-canary" {
		t.Fatalf("envelope provider metadata not updated: provider=%q provider_id=%q", envelope.Provider, envelope.ProviderID)
	}
}

func TestApplyChatRoutingDecisionBuildsFallbackChain(t *testing.T) {
	primaryCaller := &MockProviderCaller{}
	fallbackB := &MockProviderCaller{}
	fallbackC := &MockProviderCaller{}
	handler := &ChatCompletionsHandler{
		modelResolver: &MockModelResolver{},
		providerAdapterFactory: &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
			"provider-b": fallbackB,
			"provider-c": fallbackC,
		}},
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", Model: "gpt-4", ProviderID: "provider-primary", Provider: "openai"}
	modelRecord := &modelrouter.ModelRecord{ID: "model-1", ProviderID: "provider-primary", ProviderType: "openai"}
	providerDecision := &modelrouter.ProviderDecision{ProviderID: "provider-primary", Strategy: "fallback", FallbackChain: []string{"provider-primary", "provider-b", "provider-c"}}

	result := handler.applyChatRoutingDecision(chatRoutingDecisionInput{
		ctx:              context.Background(),
		envelope:         envelope,
		modelRecord:      modelRecord,
		providerCaller:   primaryCaller,
		providerDecision: providerDecision,
	})

	if result.providerCaller != primaryCaller {
		t.Fatalf("expected primary caller to remain selected before fallback attempt")
	}
	if result.fallbackProvider == nil {
		t.Fatal("expected fallback chain")
	}
	if result.fallbackProvider.ProviderID != "provider-b" || result.fallbackProvider.Caller != fallbackB {
		t.Fatalf("unexpected first fallback hop: %+v", result.fallbackProvider)
	}
	if result.fallbackProvider.Next == nil || result.fallbackProvider.Next.ProviderID != "provider-c" || result.fallbackProvider.Next.Caller != fallbackC {
		t.Fatalf("unexpected second fallback hop: %+v", result.fallbackProvider.Next)
	}
	if envelope.RoutingDecision == nil || envelope.RoutingDecision.FallbackRetries != 2 {
		t.Fatalf("expected two fallback retries in routing decision, got %+v", envelope.RoutingDecision)
	}
}
