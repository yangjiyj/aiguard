package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

type selectiveNilFactory struct{ fallback ProviderCaller }

func (f selectiveNilFactory) CreateAdapter(record *modelrouter.ModelRecord, _ string) ProviderCaller {
	if record.ProviderID == "p1" {
		return nil
	}
	return f.fallback
}

func TestV2DecisionRecordsPlanActualAttemptsAndFallbackReason(t *testing.T) {
	primary := route("p1", "openai", "https://one.example", "one")
	primary.ProviderName = "供应商甲"
	fallback := route("p2", "openai", "https://two.example", "two")
	fallback.ProviderName = "供应商乙"
	decision := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{
		SchemaVersion:  2,
		RequestedModel: "logical/model",
		PlannedRoute:   modelrouter.RouteIdentity{ProviderName: "供应商甲", RouteRef: "线路 1"},
	}}
	engine := &executionTestEngine{applied: true, plan: modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}, Decision: decision}}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
		"p1": &executionTestCaller{err: transportFailure()},
		"p2": &executionTestCaller{response: []byte(`{"ok":true}`)},
	}}
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "one", "p2": "two"}, Factory: factory, Envelope: env, SecuredBody: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	v2 := env.RoutingDecision.ModelRouteV2
	if len(v2.Attempts) != 2 || v2.Attempts[0].Result != "failed" || v2.Attempts[1].Result != "success" {
		t.Fatalf("attempt chain missing: %#v", v2.Attempts)
	}
	if !v2.FallbackUsed || v2.FallbackReason == "" || v2.ActualRoute.ProviderName != "供应商乙" {
		t.Fatalf("actual route/fallback missing: %#v", v2)
	}
}

func TestV2DecisionClassifiesPreCallIneligibleRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		configure  func(*executionTestEngine) (providerCredentialResolver, ProviderAdapterFactory)
	}{
		{name: "missing credential", want: "missing_credential", configure: func(_ *executionTestEngine) (providerCredentialResolver, ProviderAdapterFactory) {
			return executionCredentialResolver{"p2": "two"}, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p2": &executionTestCaller{response: []byte(`{}`)}}}
		}},
		{name: "nil adapter", want: "unsupported_provider_type", configure: func(_ *executionTestEngine) (providerCredentialResolver, ProviderAdapterFactory) {
			return executionCredentialResolver{"p1": "one", "p2": "two"}, selectiveNilFactory{fallback: &executionTestCaller{response: []byte(`{}`)}}
		}},
		{name: "health gate", want: "health_gate_refused", configure: func(e *executionTestEngine) (providerCredentialResolver, ProviderAdapterFactory) {
			e.allow = map[string]bool{"p1": false, "p2": true}
			return executionCredentialResolver{"p1": "one", "p2": "two"}, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": &executionTestCaller{}, "p2": &executionTestCaller{response: []byte(`{}`)}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p1, p2 := route("p1", "openai", "one", "one"), route("p2", "openai", "two", "two")
			p1.ProviderName = "一号"
			p2.ProviderName = "二号"
			decision := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "logical/model", PlannedRoute: modelrouter.RouteIdentity{ProviderName: "一号", RouteRef: "线路 1"}, Candidates: []modelrouter.RouteCandidateDecision{{ProviderName: "一号", RouteRef: "线路 1"}, {ProviderName: "二号", RouteRef: "线路 2"}}}}
			engine := &executionTestEngine{applied: true, plan: modelrouter.RoutePlan{Primary: p1, Fallbacks: []modelrouter.ModelRecord{p2}, Decision: decision}}
			resolver, factory := tc.configure(engine)
			env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
			_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: resolver, Factory: factory, Envelope: env, SecuredBody: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			v2 := decision.ModelRouteV2
			if len(v2.Attempts) != 1 || v2.Candidates[0].ExclusionReason != tc.want || v2.FallbackReason != "planned_route_ineligible" || !v2.FallbackUsed {
				t.Fatalf("classification mismatch: %#v", v2)
			}
		})
	}
}

func TestReorderedWeightedAndSmartPlansKeepProviderIdentityWhenPrimaryUnsupported(t *testing.T) {
	for _, strategy := range []string{"weighted", "smart"} {
		t.Run(strategy, func(t *testing.T) {
			originalFirst := route("p1", "openai", "one", "one")
			reorderedPrimary := route("p2", "anthropic", "two", "two")
			originalFirst.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Embeddings: true}
			reorderedPrimary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Embeddings: true}
			originalFirst.ProviderName = "同名供应商"
			reorderedPrimary.ProviderName = "同名供应商"
			decision := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "logical/model", Strategy: strategy, PlannedRoute: modelrouter.RouteIdentity{ProviderName: "同名供应商", RouteRef: "线路 2"}, Candidates: []modelrouter.RouteCandidateDecision{{ProviderName: "同名供应商", RouteRef: "线路 1"}, {ProviderName: "同名供应商", RouteRef: "线路 2"}}}}
			engine := &executionTestEngine{applied: true, plan: modelrouter.RoutePlan{Primary: reorderedPrimary, Fallbacks: []modelrouter.ModelRecord{originalFirst}, Decision: decision, RouteIdentities: map[string]modelrouter.RouteIdentity{"p1": {ProviderName: "同名供应商", RouteRef: "线路 1"}, "p2": {ProviderName: "同名供应商", RouteRef: "线路 2"}}}}
			unsupported := &executionTestCaller{err: fmt.Errorf("%w: embeddings", provider.ErrEndpointNotSupported)}
			supported := &executionTestCaller{response: []byte(`{}`)}
			factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p2": unsupported, "p1": supported}}
			env := &modelrouter.RequestEnvelope{TenantID: "t", Model: "logical/model", EndpointType: "embeddings"}
			_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "one", "p2": "two"}, Factory: factory, Envelope: env, SecuredBody: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			v2 := decision.ModelRouteV2
			if v2.Candidates[0].ExclusionReason != "" || v2.Candidates[1].ExclusionReason != "endpoint_not_supported" {
				t.Fatalf("wrong candidate marked: %#v", v2.Candidates)
			}
			if len(v2.Attempts) != 1 || v2.Attempts[0].Route.RouteRef != "线路 1" || v2.ActualRoute.RouteRef != "线路 1" || v2.PlannedRoute.RouteRef != "线路 2" {
				t.Fatalf("route refs diverged: %#v", v2)
			}
		})
	}
}
