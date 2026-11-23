package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func TestMessagesPropagatesModelRoutingEngine(t *testing.T) {
	engine := &executionTestEngine{}
	h := NewMessagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{}, nil, nil)
	h.SetModelRoutingEngine(engine)
	chat := h.newChatHandler()
	if chat.modelRouteEngine != engine {
		t.Fatal("messages temporary chat handler did not inherit the shared engine")
	}
}

func TestResponsesPropagatesModelRoutingEngine(t *testing.T) {
	engine := &executionTestEngine{}
	h := NewResponsesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{}, nil, nil)
	h.SetModelRoutingEngine(engine)
	chat := h.newChatHandler()
	if chat.modelRouteEngine != engine {
		t.Fatal("responses temporary chat handler did not inherit the shared engine")
	}
}

func TestEmbeddingsUsesSameModelRouting(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	route := modelrouter.ModelRecord{ID: "model-p2", ModelName: "logical/model", ProviderID: "p2", ProviderType: "openai", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Embeddings: true}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: route}}
	caller := &MockProviderCaller{}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p2": caller}}
	h := NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory)
	h.SetModelRoutingEngine(engine)
	body, _ := json.Marshal(EmbeddingsRequest{Model: "logical/model", Input: "hello"})
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if engine.planCalls != 1 || len(caller.CallEnvelopes) != 1 || caller.CallEnvelopes[0].ProviderID != "p2" || caller.CallEnvelopes[0].EndpointType != "embeddings" {
		t.Fatalf("embeddings did not execute shared route: plans=%d envelopes=%+v", engine.planCalls, caller.CallEnvelopes)
	}
}

func TestEmbeddingsUsesNextCapableRouteWithoutPenalizingUnsupportedCandidate(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	chatOnly := modelrouter.ModelRecord{ID: "model-chat", ModelName: "logical/model", ProviderID: "chat-only", ProviderType: "anthropic", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}}
	embeddingsCapable := modelrouter.ModelRecord{ID: "model-embeddings", ModelName: "logical/model", ProviderID: "embeddings", ProviderType: "openai", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Embeddings: true}}
	chatOnly.ProviderName = "Anthropic"
	embeddingsCapable.ProviderName = "OpenAI"
	decision := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "logical/model", PlannedRoute: modelrouter.RouteIdentity{ProviderName: "Anthropic", RouteRef: "线路 1"}, Candidates: []modelrouter.RouteCandidateDecision{{ProviderName: "Anthropic", RouteRef: "线路 1", ExclusionReason: "selected_primary"}, {ProviderName: "OpenAI", RouteRef: "线路 2"}}}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: chatOnly, Fallbacks: []modelrouter.ModelRecord{embeddingsCapable}, Decision: decision}}
	unsupported := &MockProviderCaller{TransformRequestError: fmt.Errorf("%w: embeddings", provider.ErrEndpointNotSupported)}
	supported := &MockProviderCaller{}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"chat-only": unsupported, "embeddings": supported}}
	h := NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory)
	h.SetModelRoutingEngine(engine)
	body, _ := json.Marshal(EmbeddingsRequest{Model: "logical/model", Input: "hello"})
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(unsupported.CallCalls) != 0 || len(supported.CallCalls) != 1 {
		t.Fatalf("calls unsupported=%d supported=%d", len(unsupported.CallCalls), len(supported.CallCalls))
	}
	if len(engine.recordedKeys) != 1 || engine.recordedKeys[0].ProviderID != "embeddings" || !engine.recorded[0].Success {
		t.Fatalf("unsupported candidate changed health metrics: keys=%+v results=%+v", engine.recordedKeys, engine.recorded)
	}
	if supported.CallEnvelopes[0].Model != "logical/model" || supported.CallEnvelopes[0].EndpointType != "embeddings" {
		t.Fatalf("logical model or endpoint changed: %+v", supported.CallEnvelopes[0])
	}
	v2 := decision.ModelRouteV2
	if len(v2.Attempts) != 1 || v2.Attempts[0].Route.ProviderName != "OpenAI" || v2.ActualRoute.ProviderName != "OpenAI" {
		t.Fatalf("endpoint skip counted as attempt or wrong actual route: %#v", v2)
	}
	if !v2.FallbackUsed || v2.FallbackReason != "endpoint_not_supported" || v2.Candidates[0].ExclusionReason != "endpoint_not_supported" {
		t.Fatalf("ineligible planned route not explained: %#v", v2)
	}
}

func TestEmbeddingsRealFactoryPreflightsAnthropicBeforeClaim(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	var upstreamCalls atomic.Int32
	openAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("unexpected upstream path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1]}],"model":"logical/model","usage":{"prompt_tokens":1,"total_tokens":1}}`))
	}))
	defer openAI.Close()
	chatOnly := modelrouter.ModelRecord{ID: "model-anthropic", ModelName: "logical/model", ProviderID: "anthropic", ProviderType: "anthropic", ProviderBaseURL: "http://127.0.0.1:1", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}}
	embeddingsCapable := modelrouter.ModelRecord{ID: "model-openai", ModelName: "logical/model", ProviderID: "openai", ProviderType: "openai", ProviderBaseURL: openAI.URL, Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Embeddings: true}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: chatOnly, Fallbacks: []modelrouter.ModelRecord{embeddingsCapable}}}
	h := NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &RealProviderAdapterFactory{})
	h.SetModelRoutingEngine(engine)
	body, _ := json.Marshal(EmbeddingsRequest{Model: "logical/model", Input: "hello"})
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls=%d want 1", upstreamCalls.Load())
	}
	if len(engine.allowedKeys) != 1 || engine.allowedKeys[0].ProviderID != "openai" {
		t.Fatalf("unsupported anthropic route was claimed: %+v", engine.allowedKeys)
	}
	if len(engine.recordedKeys) != 1 || engine.recordedKeys[0].ProviderID != "openai" || !engine.recorded[0].Success {
		t.Fatalf("unsupported anthropic route affected health: keys=%+v results=%+v", engine.recordedKeys, engine.recorded)
	}
}

func TestMessagesExecutesPropagatedModelRouting(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	route := modelrouter.ModelRecord{ID: "model-p2", ModelName: "logical/model", ProviderID: "p2", ProviderType: "openai", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: route}}
	caller := &MockProviderCaller{}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p2": caller}}
	h := NewMessagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	h.SetModelRoutingEngine(engine)
	body := []byte(`{"model":"logical/model","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK || engine.planCalls != 1 || len(caller.CallEnvelopes) != 1 || caller.CallEnvelopes[0].ProviderID != "p2" || caller.CallEnvelopes[0].EndpointType != "messages" {
		t.Fatalf("messages route failed: status=%d plans=%d calls=%d body=%s", response.Code, engine.planCalls, len(caller.CallEnvelopes), response.Body.String())
	}
}

func TestResponsesExecutesPropagatedModelRouting(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "false")
	route := modelrouter.ModelRecord{ID: "model-p2", ModelName: "logical/model", ProviderID: "p2", ProviderType: "openai", Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: route}}
	caller := &MockProviderCaller{}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p2": caller}}
	resolver := &MockModelResolver{ModelRecord: &route}
	h := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	h.SetModelRoutingEngine(engine)
	body := []byte(`{"model":"logical/model","input":"hello"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	response := httptest.NewRecorder()
	h.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK || engine.planCalls != 1 || len(caller.CallEnvelopes) != 1 || caller.CallEnvelopes[0].ProviderID != "p2" || caller.CallEnvelopes[0].EndpointType != "responses" {
		t.Fatalf("responses route failed: status=%d plans=%d calls=%d body=%s", response.Code, engine.planCalls, len(caller.CallEnvelopes), response.Body.String())
	}
}
