package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

type executionTestEngine struct {
	plan             modelrouter.RoutePlan
	applied          bool
	planErr          error
	hasPolicy        bool
	hasPolicyErr     error
	policyByRef      map[string]bool
	hasRefs          []string
	hasErrorsByCall  map[int]error
	hasResultsByCall map[int]bool
	health           *modelrouter.RouteHealth
	allow            map[string]bool
	allowedKeys      []modelrouter.RouteKey
	releasedKeys     []modelrouter.RouteKey
	recorded         []modelrouter.AttemptResult
	recordedKeys     []modelrouter.RouteKey
	planCalls        int
	ledgerStarted    []modelrouter.RouteAttemptLedgerEntry
	ledgerFinished   []modelrouter.RouteAttemptLedgerEntry
}

func (e *executionTestEngine) StartRouteAttempt(_ context.Context, entry modelrouter.RouteAttemptLedgerEntry) error {
	e.ledgerStarted = append(e.ledgerStarted, entry)
	return nil
}

func (e *executionTestEngine) FinishRouteAttempt(_ context.Context, entry modelrouter.RouteAttemptLedgerEntry) error {
	e.ledgerFinished = append(e.ledgerFinished, entry)
	return nil
}

func (e *executionTestEngine) HasV2Policy(_ context.Context, _, modelRef string) (bool, error) {
	e.hasRefs = append(e.hasRefs, modelRef)
	if err := e.hasErrorsByCall[len(e.hasRefs)]; err != nil {
		return false, err
	}
	if result, ok := e.hasResultsByCall[len(e.hasRefs)]; ok {
		return result, nil
	}
	if e.hasPolicyErr != nil {
		return false, e.hasPolicyErr
	}
	if e.policyByRef != nil {
		return e.policyByRef[modelRef], nil
	}
	return e.hasPolicy, nil
}
func (e *executionTestEngine) Plan(context.Context, modelrouter.RequestEnvelope) (modelrouter.RoutePlan, bool, error) {
	e.planCalls++
	return e.plan, e.applied, e.planErr
}
func (e *executionTestEngine) AllowAttempt(key modelrouter.RouteKey) bool {
	e.allowedKeys = append(e.allowedKeys, key)
	if e.health != nil {
		return e.health.Allow(key)
	}
	if e.allow == nil {
		return true
	}
	return e.allow[key.ProviderID]
}
func (e *executionTestEngine) RecordAttempt(key modelrouter.RouteKey, result modelrouter.AttemptResult) {
	e.recordedKeys = append(e.recordedKeys, key)
	e.recorded = append(e.recorded, result)
	if e.health != nil {
		e.health.Record(key, result)
	}
}

func (e *executionTestEngine) ReleaseAttempt(key modelrouter.RouteKey) {
	e.releasedKeys = append(e.releasedKeys, key)
}

type executionCredentialResolver map[string]string

func (r executionCredentialResolver) GetProviderCredential(_ context.Context, providerID string) (string, error) {
	if key := r[providerID]; key != "" {
		return key, nil
	}
	return "", errors.New("missing credential")
}

type executionGovernor struct{ decision governor.Decision }

func (g executionGovernor) Decide(context.Context, governor.ScopeRef) governor.Decision {
	return g.decision
}

type recordingGovernor struct {
	decision governor.Decision
	events   *[]string
}

func (g recordingGovernor) Decide(_ context.Context, ref governor.ScopeRef) governor.Decision {
	*g.events = append(*g.events, "governor:"+ref.ModelName)
	return g.decision
}

func transportFailure() error { return &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET} }

type executionTestCaller struct {
	err             error
	response        []byte
	called          int
	envelopes       []modelrouter.RequestEnvelope
	bodies          [][]byte
	mutateTransform bool
	ttftMS          int64
}

func (c *executionTestCaller) TransformRequest(env *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	if c.mutateTransform && len(body) > 0 {
		body[0] = 'X'
	}
	c.envelopes = append(c.envelopes, *env)
	c.bodies = append(c.bodies, append([]byte(nil), body...))
	return append([]byte(nil), body...), nil
}
func (c *executionTestCaller) Call(_ context.Context, env *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	c.called++
	if c.ttftMS > 0 && env.UpstreamTTFTMs == nil {
		ttftMS := c.ttftMS
		env.UpstreamTTFTMs = &ttftMS
	}
	c.envelopes = append(c.envelopes, *env)
	c.bodies = append(c.bodies, append([]byte(nil), body...))
	return c.response, c.err
}
func (c *executionTestCaller) CallStreaming(ctx context.Context, env *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	return c.Call(ctx, env, body)
}
func (c *executionTestCaller) TransformResponse(body []byte) ([]byte, error) { return body, nil }

type transientUpstreamFailureCaller struct {
	calls     int
	succeedOn int
}

func (c *transientUpstreamFailureCaller) TransformRequest(_ *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	return append([]byte(nil), body...), nil
}
func (c *transientUpstreamFailureCaller) Call(_ context.Context, _ *modelrouter.RequestEnvelope, _ []byte) ([]byte, error) {
	c.calls++
	if c.succeedOn == 0 || c.calls < c.succeedOn {
		return nil, &provider.UpstreamHTTPError{StatusCode: http.StatusBadGateway}
	}
	return []byte("{\"ok\":true}"), nil
}
func (c *transientUpstreamFailureCaller) CallStreaming(ctx context.Context, env *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	return c.Call(ctx, env, body)
}
func (c *transientUpstreamFailureCaller) TransformResponse(body []byte) ([]byte, error) {
	return body, nil
}

type panicProviderCaller struct{}

func (panicProviderCaller) TransformRequest(_ *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	return body, nil
}
func (panicProviderCaller) Call(context.Context, *modelrouter.RequestEnvelope, []byte) ([]byte, error) {
	panic("adapter panic")
}
func (panicProviderCaller) CallStreaming(ctx context.Context, env *modelrouter.RequestEnvelope, body []byte) ([]byte, error) {
	return panicProviderCaller{}.Call(ctx, env, body)
}
func (panicProviderCaller) TransformResponse(body []byte) ([]byte, error) { return body, nil }

func route(providerID, providerType, baseURL, upstream string) modelrouter.ModelRecord {
	return modelrouter.ModelRecord{ID: "model-" + providerID, ProviderID: providerID, ProviderType: providerType, ProviderBaseURL: baseURL, ProviderAuthMode: "bearer", ModelName: "logical/model", UpstreamModelID: upstream, Status: "active", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}}
}

func executeFixture(t *testing.T, routes []modelrouter.ModelRecord, callers map[string]ProviderCaller) (*executionTestEngine, *MockProviderAdapterFactory, *modelRouteExecutionResult, error) {
	t.Helper()
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	factory := &MockProviderAdapterFactory{CallersByProviderID: callers}
	env := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant-a", Model: "logical/model", ModelID: "initial-model", ProviderID: "initial-provider", Provider: "initial-type", EndpointType: "chat"}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "key-1", "p2": "key-2", "p3": "key-3", "p4": "key-4"}, Factory: factory, Envelope: env, SecuredBody: []byte(`{"model":"logical/model"}`)})
	return engine, factory, result, err
}

func executeFixtureWithBody(t *testing.T, routes []modelrouter.ModelRecord, callers map[string]ProviderCaller, body []byte) (*executionTestEngine, *MockProviderAdapterFactory, *modelRouteExecutionResult, error) {
	t.Helper()
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	factory := &MockProviderAdapterFactory{CallersByProviderID: callers}
	env := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "key-1", "p2": "key-2"}, Factory: factory, Envelope: env, SecuredBody: body})
	return engine, factory, result, err
}

func TestV2RouteUsesTargetProvidersOwnModelRecordAndAdapter(t *testing.T) {
	c1 := &executionTestCaller{err: transportFailure()}
	c2 := &executionTestCaller{response: []byte(`{"ok":true}`)}
	routes := []modelrouter.ModelRecord{route("p1", "openai", "https://one.example", "up-one"), route("p2", "anthropic", "https://two.example", "up-two")}
	_, factory, result, err := executeFixture(t, routes, map[string]ProviderCaller{"p1": c1, "p2": c2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Caller != c2 || result.Envelope.ProviderID != "p2" || result.Envelope.Provider != "anthropic" || result.Envelope.UpstreamModelID != "up-two" {
		t.Fatalf("wrong final route: %+v", result.Envelope)
	}
	if len(factory.CreatedRecords) != 2 || factory.CreatedRecords[1].ProviderBaseURL != "https://two.example" || factory.CreatedRecords[1].ProviderType != "anthropic" || factory.CreatedAPIKeys[1] != "key-2" {
		t.Fatalf("adapter did not use target route: records=%+v keys=%v", factory.CreatedRecords, factory.CreatedAPIKeys)
	}
}

func TestLateEndpointUnsupportedReleasesClaimWithoutAttemptOrHealthPenalty(t *testing.T) {
	unsupported := &executionTestCaller{err: fmt.Errorf("%w: late adapter check", provider.ErrEndpointNotSupported)}
	supported := &executionTestCaller{response: []byte(`{"ok":true}`)}
	routes := []modelrouter.ModelRecord{route("p1", "custom", "https://one.example", "up-one"), route("p2", "openai", "https://two.example", "up-two")}
	engine, _, result, err := executeFixture(t, routes, map[string]ProviderCaller{"p1": unsupported, "p2": supported})
	if err != nil {
		t.Fatal(err)
	}
	if result.Attempts != 1 || result.Envelope.ProviderID != "p2" {
		t.Fatalf("result=%+v", result)
	}
	if len(engine.releasedKeys) != 1 || engine.releasedKeys[0].ProviderID != "p1" {
		t.Fatalf("late unsupported claim was not released: %+v", engine.releasedKeys)
	}
	if len(engine.recordedKeys) != 1 || engine.recordedKeys[0].ProviderID != "p2" {
		t.Fatalf("late unsupported affected health: %+v", engine.recordedKeys)
	}
}

func TestResponsesRouteSkipsNonNativePrimaryAndUsesNativeFallback(t *testing.T) {
	primary := route("p1", "openai", "https://one.example", "up-one")
	fallback := route("p2", "openai", "https://two.example", "up-two")
	fallback.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	fallback.ResponsesNative = true
	c1 := &executionTestCaller{response: []byte(`{"wrong":true}`)}
	c2 := &executionTestCaller{response: []byte(`{"id":"resp_ok"}`)}
	engine := &executionTestEngine{
		applied:   true,
		hasPolicy: true,
		plan:      modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}},
	}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": c1, "p2": c2}}
	env := &modelrouter.RequestEnvelope{
		RequestID: "r1", TenantID: "tenant-a", Model: "logical/model", EndpointType: "responses",
	}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p1": "key-1", "p2": "key-2"},
		Factory:            factory,
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","input":"hello"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if c1.called != 0 || c2.called != 1 {
		t.Fatalf("primary calls=%d fallback calls=%d", c1.called, c2.called)
	}
	if result.Envelope.ProviderID != "p2" || !result.UsedFallback {
		t.Fatalf("unexpected route result: %+v", result)
	}
}

func TestRouteExecutionFiltersExplicitEndpointCapabilitiesBeforeAdapter(t *testing.T) {
	primary := route("p-chat", "custom", "https://chat.example", "vendor-chat")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Embeddings: true}
	fallback := route("p-messages", "anthropic", "https://messages.example", "vendor-messages")
	fallback.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	chatCaller := &executionTestCaller{response: []byte(`{"wrong":"chat route"}`)}
	messagesCaller := &executionTestCaller{response: []byte(`{"ok":"messages route"}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-messages", TenantID: "tenant-a", Model: "customer-coding-prod", EndpointType: "messages"}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p-chat": "chat-key", "p-messages": "messages-key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-chat": chatCaller, "p-messages": messagesCaller}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"customer-coding-prod","messages":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if chatCaller.called != 0 || messagesCaller.called != 1 || result.Envelope.ProviderID != "p-messages" {
		t.Fatalf("incompatible route was invoked: chat=%d messages=%d result=%+v", chatCaller.called, messagesCaller.called, result.Envelope)
	}
}

func TestRouteExecutionAdmitsChatThroughResponsesBridge(t *testing.T) {
	primary := route("p-responses", "openai", "https://responses.example", "vendor-model")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true, ChatResponsesBridge: true}
	caller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-chat-bridge", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p-responses": "key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-responses": caller}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","messages":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if caller.called != 1 || result.Envelope.ProviderID != "p-responses" {
		t.Fatalf("Responses bridge route was not executed: called=%d envelope=%+v", caller.called, result.Envelope)
	}
}

func TestRouteExecutionAdmitsChatThroughResponsesBridgeForCustomProvider(t *testing.T) {
	primary := route("p-custom", "custom", "https://responses.example", "vendor-model")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true, ChatResponsesBridge: true}
	caller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-chat-custom-bridge", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p-custom": "key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-custom": caller}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","messages":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if caller.called != 1 || result.Envelope.ProviderID != "p-custom" {
		t.Fatalf("custom Responses bridge route was not executed: called=%d envelope=%+v", caller.called, result.Envelope)
	}
}

func TestRouteExecutionSelectsResponsesForVerifiedDualProtocolAgentRequest(t *testing.T) {
	primary := route("p-dual", "openai", "https://dual.example", "vendor-model")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{
		Explicit: true, Verified: true, ChatCompletions: true, ResponsesNative: true,
	}
	caller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-dual-agent", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	body := []byte(`{"model":"logical/model","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"ok"},{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"}}]}],"tools":[{"type":"function","function":{"name":"shell"}}]}`)

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-dual": "key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-dual": caller}},
		Envelope: env, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.UpstreamProtocol != "responses" || caller.called != 1 {
		t.Fatalf("complex dual-protocol request did not choose Responses: result=%+v calls=%d", result.Envelope, caller.called)
	}
	if len(caller.envelopes) == 0 || caller.envelopes[0].UpstreamProtocol != "responses" {
		t.Fatalf("adapter did not receive per-attempt protocol: %+v", caller.envelopes)
	}
}

func TestRouteExecutionKeepsSimpleChatOnVerifiedDualProtocolRoute(t *testing.T) {
	primary := route("p-dual", "openai", "https://dual.example", "vendor-model")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{
		Explicit: true, Verified: true, ChatCompletions: true, ResponsesNative: true,
	}
	caller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-dual-simple", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-dual": "key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-dual": caller}},
		Envelope: env, SecuredBody: []byte(`{"model":"logical/model","messages":[{"role":"user","content":"hello"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.UpstreamProtocol != "chat" {
		t.Fatalf("simple Chat request should remain native Chat: %+v", result.Envelope)
	}
}

func TestRouteExecutionRecomputesProtocolForSemanticFallback(t *testing.T) {
	primary := route("p-chat", "openai", "https://chat.example", "chat-model")
	fallback := route("p-dual", "openai", "https://dual.example", "responses-model")
	fallback.ProtocolCapabilities = modelrouter.ProtocolCapabilities{
		Explicit: true, Verified: true, ChatCompletions: true, ResponsesNative: true,
	}
	primaryCaller := &executionTestCaller{err: transportFailure()}
	fallbackCaller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-semantic-fallback", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	body := []byte(`{"model":"logical/model","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"ok"}]}`)

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-chat": "key-1", "p-dual": "key-2"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-chat": primaryCaller, "p-dual": fallbackCaller}},
		Envelope: env, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsedFallback || result.Envelope.ProviderID != "p-dual" || result.Envelope.UpstreamProtocol != "responses" {
		t.Fatalf("fallback did not retain semantic protocol selection: %+v", result)
	}
}

func TestRouteExecutionSkipsExplicitlyUnsupportedRequestFeature(t *testing.T) {
	primary := route("p-no-vision", "openai", "https://text.example", "text-model")
	primary.ProtocolCapabilities = modelrouter.ParseProtocolCapabilities([]byte(`{"protocols":{"chat_completions":true,"vision":false}}`))
	fallback := route("p-vision", "openai", "https://vision.example", "vision-model")
	fallback.ProtocolCapabilities = modelrouter.ParseProtocolCapabilities([]byte(`{"protocols":{"chat_completions":true,"vision":true}}`))
	primaryCaller := &panicProviderCaller{}
	fallbackCaller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-vision-fallback", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	body := []byte(`{"model":"logical/model","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"}}]}]}`)

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-no-vision": "key-1", "p-vision": "key-2"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-no-vision": primaryCaller, "p-vision": fallbackCaller}},
		Envelope: env, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.ProviderID != "p-vision" || fallbackCaller.called != 1 {
		t.Fatalf("vision-incompatible route was not skipped: %+v", result)
	}
}

func TestWorkBuddyComplexShapeExecutesThroughResponsesOnDualProtocolRoute(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_workbuddy","object":"response","status":"completed","model":"gpt-5.6-sol","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}],"usage":{"input_tokens":100,"output_tokens":2,"total_tokens":102}}`))
	}))
	defer server.Close()

	messages := make([]map[string]any, 0, 27)
	messages = append(messages, map[string]any{"role": "system", "content": "coding agent policy"})
	for index := 0; index < 12; index++ {
		callID := fmt.Sprintf("call_%d", index)
		messages = append(messages,
			map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{"id": callID, "type": "function", "function": map[string]any{"name": "shell", "arguments": `{"cmd":"pwd"}`}}}},
			map[string]any{"role": "tool", "tool_call_id": callID, "content": map[string]any{"ok": true, "index": index}},
		)
	}
	imageContent := []any{map[string]any{"type": "text", "text": "inspect screenshots"}}
	for index := 0; index < 3; index++ {
		imageContent = append(imageContent, map[string]any{"type": "image_url", "image_url": map[string]any{"url": fmt.Sprintf("data:image/png;base64,AA%d", index)}})
	}
	messages = append(messages,
		map[string]any{"role": "user", "content": imageContent},
		map[string]any{"role": "user", "content": "continue the unfinished task"},
	)
	body, err := json.Marshal(map[string]any{
		"model": "logical/model", "messages": messages,
		"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "shell", "parameters": map[string]any{"type": "object"}, "strict": true}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	routeRecord := route("p-dual", "openai", server.URL, "gpt-5.6-sol")
	routeRecord.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true, ResponsesNative: true}
	decision := &modelrouter.RoutingDecision{}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routeRecord, Decision: decision}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-workbuddy-shape", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	adapter := &provider.OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-dual": "test-key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-dual": adapter}},
		Envelope: envelope, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.UpstreamProtocol != "responses" || gotPath != "/v1/responses" {
		t.Fatalf("WorkBuddy shape selected wrong protocol/path: protocol=%q path=%q", result.Envelope.UpstreamProtocol, gotPath)
	}
	if decision.IngressProtocol != "chat" || decision.UpstreamProtocol != "responses" || !strings.Contains(strings.Join(decision.RequestFeatures, ","), "tool_results") || !strings.Contains(strings.Join(decision.RequestFeatures, ","), "vision") {
		t.Fatalf("routing audit fingerprint missing: %+v", decision)
	}
	if gotBody["input"] == nil || gotBody["messages"] != nil || gotBody["model"] != "gpt-5.6-sol" {
		t.Fatalf("WorkBuddy shape was not converted to typed Responses input: %#v", gotBody)
	}
	tools := gotBody["tools"].([]any)
	if tools[0].(map[string]any)["strict"] != true {
		t.Fatalf("tool strict contract was lost: %#v", tools[0])
	}
}

func TestWorkBuddyClaudeComplexShapeExecutesThroughAnthropicMessages(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_workbuddy","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"done"}],"stop_reason":"end_turn","usage":{"input_tokens":100,"output_tokens":2}}`))
	}))
	defer server.Close()

	messages := make([]map[string]any, 0, 27)
	messages = append(messages, map[string]any{"role": "system", "content": "coding agent policy"})
	for index := 0; index < 12; index++ {
		callID := fmt.Sprintf("call_%d", index)
		messages = append(messages,
			map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{"id": callID, "type": "function", "function": map[string]any{"name": "shell", "arguments": `{"cmd":"pwd"}`}}}},
			map[string]any{"role": "tool", "tool_call_id": callID, "content": map[string]any{"ok": true, "index": index}},
		)
	}
	imageContent := []any{map[string]any{"type": "text", "text": "inspect screenshots"}}
	for index := 0; index < 3; index++ {
		imageContent = append(imageContent, map[string]any{"type": "image_url", "image_url": map[string]any{"url": fmt.Sprintf("data:image/png;base64,AA%d", index)}})
	}
	messages = append(messages,
		map[string]any{"role": "user", "content": imageContent},
		map[string]any{"role": "user", "content": "continue the unfinished task"},
	)
	body, err := json.Marshal(map[string]any{
		"model": "logical/model", "messages": messages, "reasoning_effort": "high",
		"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "shell", "parameters": map[string]any{"type": "object"}, "strict": true}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	routeRecord := route("p-messages", "custom", server.URL, "claude-opus-5")
	routeRecord.ProviderAuthMode = "bearer"
	routeRecord.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true, AnthropicMessages: true}
	decision := &modelrouter.RoutingDecision{}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routeRecord, Decision: decision}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-workbuddy-claude-shape", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	adapter := &provider.AnthropicAdapter{BaseURL: server.URL, APIKey: "test-key", AuthMode: "bearer"}

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-messages": "test-key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-messages": adapter}},
		Envelope: envelope, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.UpstreamProtocol != "messages" || gotPath != "/v1/messages" {
		t.Fatalf("WorkBuddy Claude shape selected wrong protocol/path: protocol=%q path=%q", result.Envelope.UpstreamProtocol, gotPath)
	}
	if decision.IngressProtocol != "chat" || decision.UpstreamProtocol != "messages" || !strings.Contains(strings.Join(decision.RequestFeatures, ","), "reasoning") || !strings.Contains(strings.Join(decision.RequestFeatures, ","), "tool_results") || !strings.Contains(strings.Join(decision.RequestFeatures, ","), "vision") {
		t.Fatalf("routing audit fingerprint missing: %+v", decision)
	}
	outputConfig, _ := gotBody["output_config"].(map[string]any)
	if outputConfig["effort"] != "high" || gotBody["messages"] == nil || gotBody["model"] != "claude-opus-5" {
		t.Fatalf("WorkBuddy Claude shape was not converted to Anthropic Messages with reasoning: %#v", gotBody)
	}
	convertedMessages := gotBody["messages"].([]any)
	if len(convertedMessages) < 26 {
		t.Fatalf("tool/image history was truncated: got %d messages", len(convertedMessages))
	}
}

func TestRouteExecutionSelectsMessagesFromCapabilitiesWithoutModelNameRule(t *testing.T) {
	routeRecord := route("p-messages", "custom", "https://messages.example", "vendor-model-without-claude-prefix")
	routeRecord.ProtocolCapabilities = modelrouter.ProtocolCapabilities{
		Explicit: true, Verified: true, ChatCompletions: true, AnthropicMessages: true,
	}
	caller := &executionTestCaller{response: []byte(`{"ok":true}`)}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routeRecord}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r-messages-capability", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	body := []byte(`{"model":"logical/model","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":{"ok":true}},{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"}}]}]}`)

	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p-messages": "key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-messages": caller}},
		Envelope: envelope, SecuredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.UpstreamProtocol != "messages" || caller.called != 1 {
		t.Fatalf("capability-gated Messages route was not selected: %+v", result.Envelope)
	}
}

func TestRealProviderFactoryUsesMessagesAdapterFromCapabilities(t *testing.T) {
	record := &modelrouter.ModelRecord{
		ModelName: "customer-model", ProviderType: "custom", ProviderBaseURL: "https://messages.example", ProviderAuthMode: "x-api-key",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true},
	}
	caller := (&RealProviderAdapterFactory{}).CreateAdapter(record, "test-key")
	adapter, ok := caller.(*provider.AnthropicAdapter)
	if !ok {
		t.Fatalf("capability-gated Messages route created %T, want Anthropic adapter", caller)
	}
	if adapter.AuthMode != "x-api-key" {
		t.Fatalf("provider auth mode was not preserved: %q", adapter.AuthMode)
	}
}

func TestProtocolSelectionNamesEveryExplicitAdapterFamily(t *testing.T) {
	tests := []struct {
		providerType string
		caps         modelrouter.ProtocolCapabilities
		want         string
	}{
		{providerType: "openai", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}, want: "chat"},
		{providerType: "anthropic", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}, want: "messages"},
		{providerType: "gemini", caps: modelrouter.ProtocolCapabilities{Explicit: true, Gemini: true}, want: "gemini"},
		{providerType: "vertex", caps: modelrouter.ProtocolCapabilities{Explicit: true, Gemini: true}, want: "gemini"},
		{providerType: "bedrock", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}, want: "bedrock_converse"},
		{providerType: "custom", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, Gemini: true}, want: "chat"},
	}
	for _, tc := range tests {
		t.Run(tc.providerType, func(t *testing.T) {
			routeRecord := route("provider", tc.providerType, "https://provider.example", "vendor-model")
			routeRecord.ProtocolCapabilities = tc.caps
			got, decision := selectModelRouteProtocol(routeRecord, relay.RequestFeatures{IngressProtocol: "chat"})
			if !decision.Eligible || got != tc.want {
				t.Fatalf("protocol=%q decision=%+v want=%q", got, decision, tc.want)
			}
		})
	}
}

func TestMessagesIngressProtocolSelectionMatrix(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		caps         modelrouter.ProtocolCapabilities
		wantProtocol string
		wantEligible bool
	}{
		{
			name: "native anthropic", providerType: "anthropic",
			caps:         modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true},
			wantProtocol: "messages", wantEligible: true,
		},
		{
			name: "openai prefers responses", providerType: "openai",
			caps:         modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, ResponsesNative: true},
			wantProtocol: "responses", wantEligible: true,
		},
		{
			name: "openai chat fallback", providerType: "openai",
			caps:         modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true},
			wantProtocol: "chat", wantEligible: true,
		},
		{
			name: "custom with explicit native responses", providerType: "custom",
			caps:         modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, ResponsesNative: true},
			wantProtocol: "responses", wantEligible: true,
		},
		{
			name: "declared compatible bridge", providerType: "custom",
			caps:         modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, ChatResponsesBridge: true},
			wantProtocol: "chat", wantEligible: true,
		},
		{
			name: "verified custom Chat supports Messages conversion", providerType: "custom",
			caps:         modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true},
			wantProtocol: "chat", wantEligible: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := route("provider", tc.providerType, "https://provider.example", "vendor-model")
			record.ProtocolCapabilities = tc.caps
			got, decision := selectModelRouteProtocol(record, relay.RequestFeatures{
				IngressProtocol: "messages", Tools: true, ToolResults: true, Vision: true,
			})
			if decision.Eligible != tc.wantEligible || got != tc.wantProtocol {
				t.Fatalf("protocol=%q decision=%+v want_protocol=%q want_eligible=%v", got, decision, tc.wantProtocol, tc.wantEligible)
			}
		})
	}
}

func TestRouteExecutionRejectsImplicitChatResponsesBridge(t *testing.T) {
	primary := route("p-responses", "openai", "https://responses.example", "vendor-model")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	caller := &panicProviderCaller{}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-chat-no-bridge", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}

	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p-responses": "key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-responses": caller}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","messages":[]}`),
	})
	if !errors.Is(err, errModelRouteUnavailable) {
		t.Fatalf("implicit Chat bridge error=%v, want model_route_unavailable", err)
	}
}

func TestRouteExecutionRejectsResponsesBridgeForAnthropicProvider(t *testing.T) {
	primary := route("p-anthropic", "anthropic", "https://responses.example", "vendor-model")
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	caller := &panicProviderCaller{}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: primary}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-chat-anthropic-bridge", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}

	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p-anthropic": "key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-anthropic": caller}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","messages":[]}`),
	})
	if err == nil || !errors.Is(err, errModelRouteUnavailable) {
		t.Fatalf("Anthropic Responses-only route should be rejected before call: %v", err)
	}
}

func TestResponsesRouteFailsClosedWhenNoNativeRouteExists(t *testing.T) {
	primary := route("p1", "openai", "https://one.example", "up-one")
	c1 := &executionTestCaller{response: []byte(`{"wrong":true}`)}
	engine := &executionTestEngine{
		applied:   true,
		hasPolicy: true,
		plan:      modelrouter.RoutePlan{Primary: primary},
	}
	env := &modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "tenant-a", Model: "logical/model", EndpointType: "responses"}
	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p1": "key-1"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": c1}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","input":"hello"}`),
	})
	if !errors.Is(err, errResponsesNativeUnavailable) {
		t.Fatalf("err=%v want=%v", err, errResponsesNativeUnavailable)
	}
	if c1.called != 0 {
		t.Fatalf("non-native route called %d times", c1.called)
	}
}

func TestExecuteModelRoutePlanUsesPreparedPlanWithoutReplanning(t *testing.T) {
	native := route("p-native", "openai", "https://native.example", "gpt-native")
	native.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	native.ResponsesNative = true
	caller := &executionTestCaller{response: []byte(`{"id":"resp_ok"}`)}
	engine := &executionTestEngine{
		applied: true,
		plan: modelrouter.RoutePlan{
			Primary: route("p-stale", "openai", "https://stale.example", "gpt-stale"),
		},
	}
	prepared := modelrouter.RoutePlan{Primary: native}
	env := &modelrouter.RequestEnvelope{
		RequestID: "r1", TenantID: "tenant-a", Model: "logical/model", EndpointType: "responses",
	}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p-native": "key-native"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p-native": caller}},
		Envelope:           env,
		SecuredBody:        []byte(`{"model":"logical/model","input":"hello"}`),
		PreparedPlan:       &prepared,
	})
	if err != nil {
		t.Fatal(err)
	}
	if engine.planCalls != 0 {
		t.Fatalf("prepared route was replanned %d times", engine.planCalls)
	}
	if result.Envelope.ProviderID != "p-native" || caller.called != 1 {
		t.Fatalf("wrong prepared route result=%+v calls=%d", result, caller.called)
	}
}

func TestV2RouteHandlerExecutesPlannedFallbackAfterSecurity(t *testing.T) {
	primary := &MockProviderCaller{CallError: transportFailure()}
	fallback := &MockProviderCaller{}
	routes := []modelrouter.ModelRecord{route("p1", "openai", "https://one.example", "up-one"), route("p2", "anthropic", "https://two.example", "up-two")}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": primary, "p2": fallback}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	h.SetRouting(nil, nil, nil, engine)
	body, _ := json.Marshal(ChatCompletionRequest{Model: "logical/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(primary.CallCalls) != 1 || len(fallback.CallCalls) != 1 {
		t.Fatalf("v2 request not executed end-to-end: status=%d body=%s primary=%d fallback=%d", w.Code, w.Body.String(), len(primary.CallCalls), len(fallback.CallCalls))
	}
	if got := w.Header().Get("X-JJDGuard-Provider-ID"); got != "p2" {
		t.Fatalf("final provider header=%q", got)
	}
	if got := w.Header().Get("X-JJDGuard-Fallback-Used"); got != "true" {
		t.Fatalf("fallback header=%q", got)
	}
}

func TestV2FallbackKeepsRequestedLogicalModel(t *testing.T) {
	c1 := &executionTestCaller{err: transportFailure()}
	c2 := &executionTestCaller{response: []byte(`{"ok":true}`)}
	_, _, result, err := executeFixture(t, []modelrouter.ModelRecord{route("p1", "openai", "one", "vendor-a"), route("p2", "openai", "two", "vendor-b")}, map[string]ProviderCaller{"p1": c1, "p2": c2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope.Model != "logical/model" {
		t.Fatalf("logical model changed: %q", result.Envelope.Model)
	}
	if len(c2.envelopes) == 0 || c2.envelopes[0].Model != "logical/model" || c2.envelopes[0].UpstreamModelID != "vendor-b" {
		t.Fatalf("wrong fallback envelope: %+v", c2.envelopes)
	}
}

func TestRouteAttemptLedgerCorrelatesLogicalRequestAndUnknownResult(t *testing.T) {
	primary := &executionTestCaller{err: transportFailure()}
	fallback := &executionTestCaller{response: []byte(`{}`)}
	routes := []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "logical-1", ClientRetryID: "retry-safe", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "key", "p2": "key"},
		Factory:  &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": primary, "p2": fallback}},
		Envelope: envelope, SecuredBody: []byte(`{}`),
	})
	if err != nil || result == nil || len(engine.ledgerStarted) != 2 || len(engine.ledgerFinished) != 2 {
		t.Fatalf("result=%+v started=%+v finished=%+v err=%v", result, engine.ledgerStarted, engine.ledgerFinished, err)
	}
	if engine.ledgerStarted[0].AttemptID == engine.ledgerStarted[1].AttemptID || engine.ledgerStarted[0].LogicalRequestID != "logical-1" || engine.ledgerStarted[0].ClientRetryID != "retry-safe" {
		t.Fatalf("attempt identities=%+v", engine.ledgerStarted)
	}
	if engine.ledgerFinished[0].UpstreamOutcome != "network_error" || !engine.ledgerFinished[0].ResultUnknown || engine.ledgerFinished[1].UpstreamOutcome != "success" {
		t.Fatalf("attempt outcomes=%+v", engine.ledgerFinished)
	}
}

func TestV2FallbackRetriesRouteFailuresAndCapacityErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"408", &provider.UpstreamHTTPError{StatusCode: http.StatusRequestTimeout}},
		{"429", &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests}},
		{"network", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}},
		{"timeout", context.DeadlineExceeded},
		{"5xx", &provider.UpstreamHTTPError{StatusCode: http.StatusServiceUnavailable}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := &executionTestCaller{err: tc.err}, &executionTestCaller{response: []byte(`{}`)}
			_, _, _, err := executeFixture(t, []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}, map[string]ProviderCaller{"p1": c1, "p2": c2})
			if err != nil || c2.called != 1 {
				t.Fatalf("expected retry, err=%v calls=%d", err, c2.called)
			}
		})
	}
}

func TestV2FallbackRejectsRouteAndCapacityStatuses(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusRequestEntityTooLarge,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			primary := &executionTestCaller{err: &provider.UpstreamHTTPError{StatusCode: status}}
			fallback := &executionTestCaller{response: []byte(`{}`)}
			_, _, _, err := executeFixture(t,
				[]modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")},
				map[string]ProviderCaller{"p1": primary, "p2": fallback},
			)
			if err == nil || fallback.called != 0 {
				t.Fatalf("status %d fell back: err=%v fallback_calls=%d", status, err, fallback.called)
			}
		})
	}
}

func TestSingleRouteRetriesTransientUpstreamFailure(t *testing.T) {
	caller := &transientUpstreamFailureCaller{succeedOn: 2}
	engine, _, result, err := executeFixture(t, []modelrouter.ModelRecord{
		route("p1", "openai", "one", "vendor-model"),
	}, map[string]ProviderCaller{"p1": caller})
	if err != nil || result == nil {
		t.Fatalf("single route transient failure was not retried: result=%+v err=%v calls=%d", result, err, caller.calls)
	}
	if caller.calls != 2 || result.Attempts != 2 {
		t.Fatalf("single route retry count=%d result attempts=%d, want two", caller.calls, result.Attempts)
	}
	if result.UsedFallback || len(engine.recorded) != 2 || len(engine.allowedKeys) != 2 {
		t.Fatalf("same-route retry was classified as fallback or skipped accounting: result=%+v recorded=%d allowed=%d", result, len(engine.recorded), len(engine.allowedKeys))
	}
}

func TestSingleRouteRetriesTransientUpstreamFailureOnlyOnce(t *testing.T) {
	caller := &transientUpstreamFailureCaller{}
	_, _, result, err := executeFixture(t, []modelrouter.ModelRecord{
		route("p1", "openai", "one", "vendor-model"),
	}, map[string]ProviderCaller{"p1": caller})
	if err == nil || result != nil || caller.calls != 2 {
		t.Fatalf("single route retry exceeded one retry: result=%+v err=%v calls=%d", result, err, caller.calls)
	}
}

func TestSingleRouteDoesNotRetryNonTransientUpstreamErrors(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			caller := &executionTestCaller{err: &provider.UpstreamHTTPError{StatusCode: status}}
			_, _, _, err := executeFixture(t, []modelrouter.ModelRecord{
				route("p1", "openai", "one", "vendor-model"),
			}, map[string]ProviderCaller{"p1": caller})
			if err == nil || caller.called != 1 {
				t.Fatalf("status %d was retried on the same route: err=%v calls=%d", status, err, caller.called)
			}
		})
	}
}

func TestSingleRouteDoesNotRetryCommittedResponse(t *testing.T) {
	caller := &transientUpstreamFailureCaller{succeedOn: 2}
	engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: route("p1", "openai", "one", "vendor-model")}}
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	tracker := &relay.CommitTracker{}
	if err := tracker.Transition(relay.CommitHeadersCommitted); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Transition(relay.CommitFirstEventFlushed); err != nil {
		t.Fatal(err)
	}
	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p1": "key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": caller}},
		Envelope:           env,
		SecuredBody:        []byte("{\"model\":\"logical/model\"}"),
		Streaming:          true,
		CommitTracker:      tracker,
	})
	if err == nil || caller.calls != 1 {
		t.Fatalf("committed response was retried on the same route: err=%v calls=%d", err, caller.calls)
	}
}

func TestModelRouteReachableClientErrorsAreRecordedWithoutFallbackPenalty(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusConflict,
		http.StatusUnprocessableEntity,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			engine := &executionTestEngine{}
			key := modelrouter.RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "p1"}
			caller := &executionTestCaller{err: &provider.UpstreamHTTPError{StatusCode: status}}
			envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", ProviderID: "p1"}

			_, err := callAndRecordModelRouteAttempt(context.Background(), engine, key, caller, envelope, []byte(`{}`), false)

			if upstream := provider.GetUpstreamHTTPError(err); upstream == nil || upstream.StatusCode != status {
				t.Fatalf("err=%v want upstream %d", err, status)
			}
			if len(engine.recorded) != 1 || len(engine.releasedKeys) != 0 {
				t.Fatalf("status %d accounting recorded=%d released=%d", status, len(engine.recorded), len(engine.releasedKeys))
			}
			if engine.recorded[0].Retryable || engine.recorded[0].HealthNeutral {
				t.Fatalf("status %d result=%+v want reachable non-failure", status, engine.recorded[0])
			}
		})
	}
}

func TestModelRouteCapacityErrorsRetryWithoutOpeningCircuit(t *testing.T) {
	for _, status := range []int{http.StatusRequestEntityTooLarge, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
			health := modelrouter.NewRouteHealth(func() time.Time { return now })
			engine := &executionTestEngine{health: health}
			key := modelrouter.RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "p1"}
			caller := &executionTestCaller{err: &provider.UpstreamHTTPError{StatusCode: status}}
			envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", ProviderID: "p1"}

			for i := 0; i < 3; i++ {
				if !engine.AllowAttempt(key) {
					t.Fatalf("status %d attempt %d was blocked by a hard circuit", status, i+1)
				}
				_, err := callAndRecordModelRouteAttempt(context.Background(), engine, key, caller, envelope, []byte(`{}`), false)
				if upstream := provider.GetUpstreamHTTPError(err); upstream == nil || upstream.StatusCode != status {
					t.Fatalf("attempt %d err=%v want upstream %d", i+1, err, status)
				}
			}
			if !health.Closed(key) {
				t.Fatalf("three upstream %d responses opened the 30-second hard circuit", status)
			}
			if len(engine.recorded) != 3 || len(engine.releasedKeys) != 0 {
				t.Fatalf("status %d accounting recorded=%d released=%d", status, len(engine.recorded), len(engine.releasedKeys))
			}
			for _, result := range engine.recorded {
				wantRetryable := status == http.StatusTooManyRequests
				if result.Retryable != wantRetryable || !result.HealthNeutral {
					t.Fatalf("status %d result=%+v want retryable=%v health-neutral", status, result, wantRetryable)
				}
			}
		})
	}
}

func TestShouldRetryModelRouteUsesExplicitTransportClassesOnly(t *testing.T) {
	cases := []struct {
		name string
		err  error
		ctx  context.Context
		want bool
	}{
		{"net_error", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, context.Background(), true},
		{"legacy_plain_connection_refused", errors.New("connection refused"), context.Background(), true},
		{"wrapped_connection_reset", fmt.Errorf("upstream read: %w", syscall.ECONNRESET), context.Background(), true},
		{"deadline", context.DeadlineExceeded, context.Background(), true},
		{"401", &provider.UpstreamHTTPError{StatusCode: 401}, context.Background(), false},
		{"403", &provider.UpstreamHTTPError{StatusCode: 403}, context.Background(), false},
		{"404", &provider.UpstreamHTTPError{StatusCode: 404}, context.Background(), false},
		{"408", &provider.UpstreamHTTPError{StatusCode: 408}, context.Background(), true},
		{"413", &provider.UpstreamHTTPError{StatusCode: 413}, context.Background(), false},
		{"429", &provider.UpstreamHTTPError{StatusCode: 429}, context.Background(), true},
		{"500", &provider.UpstreamHTTPError{StatusCode: 500}, context.Background(), true},
		{"wrapped_429", fmt.Errorf("wrapped: %w", &provider.UpstreamHTTPError{StatusCode: 429}), context.Background(), true},
		{"wrapped_503", fmt.Errorf("wrapped: %w", &provider.UpstreamHTTPError{StatusCode: 503}), context.Background(), true},
		{"stream_idle", provider.ErrUpstreamStreamIdleTimeout, context.Background(), false},
		{"cancel", context.Canceled, context.Background(), false},
		{"request_context_done", context.DeadlineExceeded, canceledContext(), false},
		{"400", &provider.UpstreamHTTPError{StatusCode: 400}, context.Background(), false},
		{"409", &provider.UpstreamHTTPError{StatusCode: 409}, context.Background(), false},
		{"422", &provider.UpstreamHTTPError{StatusCode: 422}, context.Background(), false},
		{"security", errModelRouteSecurityRejected, context.Background(), false},
		{"validation", errors.New("invalid request model"), context.Background(), false},
		{"adapter_config", errors.New("invalid provider base URL"), context.Background(), false},
		{"url_config", &url.Error{Op: "Post", URL: "://bad", Err: errors.New("unsupported protocol scheme")}, context.Background(), false},
		{"x509_unknown_authority", x509.UnknownAuthorityError{}, context.Background(), true},
		{"x509_hostname", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "wrong.example"}, context.Background(), true},
		{"tls_record", tls.RecordHeaderError{}, context.Background(), true},
		{"dns_not_found", &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true}, context.Background(), true},
		{"dns_timeout", &net.DNSError{Err: "timeout", Name: "slow.example", IsTimeout: true}, context.Background(), true},
		{"unknown_net_op", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("permanent address/config failure")}, context.Background(), true},
		{"protocol_parse", errors.New("malformed upstream protocol"), context.Background(), false},
		{"unknown_internal", errors.New("unexpected internal failure"), context.Background(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRetryModelRoute(tc.ctx, tc.err); got != tc.want {
				t.Fatalf("retry=%v want=%v err=%T %v", got, tc.want, tc.err, tc.err)
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestV2FallbackNeverRetriesSecurityOrClient4xx(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"400", &provider.UpstreamHTTPError{StatusCode: http.StatusBadRequest}}, {"409", &provider.UpstreamHTTPError{StatusCode: http.StatusConflict}}, {"422", &provider.UpstreamHTTPError{StatusCode: http.StatusUnprocessableEntity}}, {"client_cancel", context.Canceled}, {"security_reject", errModelRouteSecurityRejected}} {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := &executionTestCaller{err: tc.err}, &executionTestCaller{response: []byte(`{}`)}
			_, _, _, err := executeFixture(t, []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}, map[string]ProviderCaller{"p1": c1, "p2": c2})
			if !errors.Is(err, tc.err) || c2.called != 0 {
				t.Fatalf("unexpected retry: err=%v calls=%d", err, c2.called)
			}
		})
	}
}

func TestV2SecurityRejectNeverPlansOrCallsUpstream(t *testing.T) {
	engine := &executionTestEngine{hasPolicy: true, applied: true}
	factory := &MockProviderAdapterFactory{}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{InputAction: "block"}, &MockAuditWriter{}, factory, nil, nil)
	h.SetRouting(nil, nil, nil, engine)
	body, _ := json.Marshal(ChatCompletionRequest{Model: "logical/model", Messages: []Message{{Role: "user", Content: jsonQuote("blocked")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || engine.planCalls != 0 || len(factory.CreatedRecords) != 0 {
		t.Fatalf("security must stop before routing: status=%d plans=%d adapters=%d", w.Code, engine.planCalls, len(factory.CreatedRecords))
	}
}

func TestHasV2PolicyErrorFailsClosedWithoutLegacyOrDetailLeak(t *testing.T) {
	engine := &executionTestEngine{hasPolicyErr: errors.New("database password=secret unavailable")}
	legacyCalls := 0
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(context.Context, *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		legacyCalls++
		return &modelrouter.ModelDecision{TargetModel: "wrong-model"}
	}
	body, _ := json.Marshal(ChatCompletionRequest{Model: "logical/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "model_route_unavailable") || strings.Contains(w.Body.String(), "password=secret") {
		t.Fatalf("fail-closed response wrong: status=%d body=%s", w.Code, w.Body.String())
	}
	if legacyCalls != 0 {
		t.Fatalf("legacy ran after v2 lookup error: %d", legacyCalls)
	}
}

func TestOriginalNoV2GovernorFinalModelSelectsV2AfterLegacyModel(t *testing.T) {
	finalModel := "governed/model"
	r := route("p1", "openai", "https://one.example", "vendor")
	r.ModelName = finalModel
	engine := &executionTestEngine{policyByRef: map[string]bool{finalModel: true}, applied: true, plan: modelrouter.RoutePlan{Primary: r}}
	legacyCalls := 0
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": &MockProviderCaller{}}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	h.modelRouteEngine = engine
	h.SetGovernor(executionGovernor{decision: governor.Decision{Action: governor.ActionDowngradeMod, DowngradeTo: finalModel}})
	h.legacyModelResolver = func(context.Context, *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		legacyCalls++
		return nil
	}
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(engine.hasRefs) != 2 || engine.hasRefs[0] != "original/model" || engine.hasRefs[1] != finalModel || legacyCalls != 1 {
		t.Fatalf("final model not used for v2: status=%d refs=%v legacy=%d body=%s", w.Code, engine.hasRefs, legacyCalls, w.Body.String())
	}
}

func TestOriginalV2GovernorFinalModelWithoutV2FailsClosed(t *testing.T) {
	finalModel := "legacy/model"
	engine := &executionTestEngine{policyByRef: map[string]bool{"original/model": true}}
	legacyCalls := 0
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	h.modelRouteEngine = engine
	h.SetGovernor(executionGovernor{decision: governor.Decision{Action: governor.ActionDowngradeMod, DowngradeTo: finalModel}})
	h.legacyModelResolver = func(_ context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		legacyCalls++
		return &modelrouter.ModelDecision{TargetModel: env.Model, Strategy: "legacy"}
	}
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || len(engine.hasRefs) != 2 || engine.hasRefs[0] != "original/model" || engine.hasRefs[1] != finalModel || legacyCalls != 0 || !strings.Contains(w.Body.String(), "model_route_unavailable") {
		t.Fatalf("unsafe v2-to-legacy transition: status=%d refs=%v legacy=%d body=%s", w.Code, engine.hasRefs, legacyCalls, w.Body.String())
	}
}

func TestRoutingDisabledPreservesLegacyModelBeforeGovernor(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	events := []string{}
	engine := &executionTestEngine{hasPolicy: true}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(_ context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		events = append(events, "legacy-model")
		env.Model = "legacy-selected"
		return &modelrouter.ModelDecision{TargetModel: env.Model}
	}
	h.SetGovernor(recordingGovernor{events: &events})
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(engine.hasRefs) != 0 || fmt.Sprint(events) != "[legacy-model governor:legacy-selected]" {
		t.Fatalf("disabled legacy order changed: status=%d refs=%v events=%v", w.Code, engine.hasRefs, events)
	}
}

func TestNoV2PreservesLegacyModelBeforeGovernorAndProvider(t *testing.T) {
	events := []string{}
	engine := &executionTestEngine{policyByRef: map[string]bool{}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(_ context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		events = append(events, "legacy-model")
		env.Model = "legacy-selected"
		return &modelrouter.ModelDecision{TargetModel: env.Model}
	}
	h.legacyProviderResolver = func(context.Context, *modelrouter.RequestEnvelope, string) *modelrouter.ProviderDecision {
		events = append(events, "legacy-provider")
		return nil
	}
	h.SetGovernor(recordingGovernor{events: &events})
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || fmt.Sprint(engine.hasRefs) != "[original/model legacy-selected]" || fmt.Sprint(events) != "[legacy-model governor:legacy-selected legacy-provider]" {
		t.Fatalf("no-v2 legacy order changed: status=%d refs=%v events=%v", w.Code, engine.hasRefs, events)
	}
}

func TestUnchangedFinalModelReusesFirstPolicySnapshot(t *testing.T) {
	engine := &executionTestEngine{hasResultsByCall: map[int]bool{1: false, 2: true}}
	legacyCalls := 0
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(_ context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		legacyCalls++
		return &modelrouter.ModelDecision{TargetModel: env.Model}
	}
	body, _ := json.Marshal(ChatCompletionRequest{Model: "same/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(engine.hasRefs) != 1 || legacyCalls != 1 {
		t.Fatalf("unchanged model mixed policy snapshots: status=%d refs=%v legacy=%d body=%s", w.Code, engine.hasRefs, legacyCalls, w.Body.String())
	}
}

func TestOriginalV2SkipsLegacyModelBeforeGovernor(t *testing.T) {
	events := []string{}
	r := route("p1", "openai", "one", "vendor")
	r.ModelName = "original/model"
	engine := &executionTestEngine{policyByRef: map[string]bool{"original/model": true}, applied: true, plan: modelrouter.RoutePlan{Primary: r}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": &MockProviderCaller{}}}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(context.Context, *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		events = append(events, "legacy-model")
		return nil
	}
	h.SetGovernor(recordingGovernor{events: &events})
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || fmt.Sprint(events) != "[governor:original/model]" || fmt.Sprint(engine.hasRefs) != "[original/model]" {
		t.Fatalf("original v2 ran legacy: status=%d refs=%v events=%v", w.Code, engine.hasRefs, events)
	}
}

func TestSecondHasV2PolicyErrorFailsClosedAfterLegacyAndGovernor(t *testing.T) {
	events := []string{}
	engine := &executionTestEngine{hasErrorsByCall: map[int]error{2: errors.New("second db failure")}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(_ context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		events = append(events, "legacy-model")
		env.Model = "legacy-selected"
		return nil
	}
	h.legacyProviderResolver = func(context.Context, *modelrouter.RequestEnvelope, string) *modelrouter.ProviderDecision {
		events = append(events, "legacy-provider")
		return nil
	}
	h.SetGovernor(recordingGovernor{events: &events})
	body, _ := json.Marshal(ChatCompletionRequest{Model: "original/model", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || fmt.Sprint(events) != "[legacy-model governor:legacy-selected]" || strings.Contains(w.Body.String(), "second db failure") {
		t.Fatalf("second lookup did not fail closed: status=%d refs=%v events=%v body=%s", w.Code, engine.hasRefs, events, w.Body.String())
	}
}

func TestV2RouteCapsAttemptsAtThree(t *testing.T) {
	callers := map[string]ProviderCaller{}
	routes := make([]modelrouter.ModelRecord, 0, 4)
	for i, id := range []string{"p1", "p2", "p3", "p4"} {
		routes = append(routes, route(id, "openai", id, id))
		callers[id] = &executionTestCaller{err: transportFailure()}
		_ = i
	}
	engine, factory, _, err := executeFixture(t, routes, callers)
	if err == nil || len(factory.CreatedRecords) != 3 || len(engine.recorded) != 3 {
		t.Fatalf("attempt cap failed: err=%v created=%d recorded=%d", err, len(factory.CreatedRecords), len(engine.recorded))
	}
}

func TestV2PolicySkipsLegacyModelChangingPolicy(t *testing.T) {
	engine := &executionTestEngine{hasPolicy: true}
	useV2, err := selectModelRoutingMode(context.Background(), engine, "tenant-a", "logical/model")
	if err != nil || !useV2 {
		t.Fatalf("expected v2 mode: useV2=%v err=%v", useV2, err)
	}
}

func TestNoV2PolicyPreservesLegacyBehavior(t *testing.T) {
	engine := &executionTestEngine{hasPolicy: false}
	useV2, err := selectModelRoutingMode(context.Background(), engine, "tenant-a", "logical/model")
	if err != nil || useV2 {
		t.Fatalf("expected legacy mode: useV2=%v err=%v", useV2, err)
	}
}

func TestV2RouteClaimsHalfOpenImmediatelyBeforeCallAndReleasesOnCancel(t *testing.T) {
	c1, c2 := &executionTestCaller{response: []byte(`should-not-run`)}, &executionTestCaller{err: context.Canceled}
	routes := []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}
	engine := &executionTestEngine{applied: true, hasPolicy: true, allow: map[string]bool{"p1": false, "p2": true}, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": c1, "p2": c2}}
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "one", "p2": "two"}, Factory: factory, Envelope: env, SecuredBody: []byte(`{}`)})
	if !errors.Is(err, context.Canceled) || c1.called != 0 || c2.called != 1 {
		t.Fatalf("claim behavior wrong: err=%v p1=%d p2=%d", err, c1.called, c2.called)
	}
	if len(engine.recorded) != 1 || engine.recorded[0].Retryable || engine.recorded[0].Success {
		t.Fatalf("cancel lease not released with neutral result: %+v", engine.recorded)
	}
}

func TestHalfOpenAdapterPanicRecordsOnceReleasesAndRepanics(t *testing.T) {
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	health := modelrouter.NewRouteHealth(func() time.Time { return now })
	key := modelrouter.RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "p1"}
	for range 3 {
		health.Record(key, modelrouter.AttemptResult{Retryable: true})
	}
	now = now.Add(30 * time.Second)
	r := route("p1", "openai", "one", "vendor")
	engine := &executionTestEngine{applied: true, health: health, plan: modelrouter.RoutePlan{Primary: r}}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": panicProviderCaller{}}}
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "key"}, Factory: factory, Envelope: env, SecuredBody: []byte(`{}`)})
	}()
	if recovered != "adapter panic" || len(engine.recorded) != 1 || !engine.recorded[0].Retryable {
		t.Fatalf("panic was swallowed or recorded incorrectly: recovered=%v records=%+v", recovered, engine.recorded)
	}
	now = now.Add(30 * time.Second)
	if !health.Allow(key) {
		t.Fatal("half-open probe lease remained stuck after adapter panic")
	}
}

func TestEachRouteTransformsIndependentSecuredBodyCopy(t *testing.T) {
	body := []byte(`{"model":"logical/model"}`)
	primary := &executionTestCaller{err: transportFailure(), mutateTransform: true}
	fallback := &executionTestCaller{response: []byte(`{}`)}
	_, _, _, err := executeFixtureWithBody(t, []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}, map[string]ProviderCaller{"p1": primary, "p2": fallback}, body)
	if err != nil {
		t.Fatal(err)
	}
	if body[0] != '{' || len(fallback.bodies) == 0 || fallback.bodies[0][0] != '{' {
		t.Fatalf("primary transform polluted fallback body: original=%q fallback=%q", body, fallback.bodies)
	}
}

func TestV2RouteUnavailableHasStableCodeAndNeverChangesModel(t *testing.T) {
	engine := &executionTestEngine{applied: true, planErr: errors.New("no healthy route")}
	env := &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model"}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{}, Factory: &MockProviderAdapterFactory{}, Envelope: env, SecuredBody: []byte(`{}`)})
	if !errors.Is(err, errModelRouteUnavailable) || modelRouteErrorCode(err) != "model_route_unavailable" {
		t.Fatalf("unstable error: %v", err)
	}
	if result != nil || env.Model != "logical/model" {
		t.Fatalf("must not switch model: result=%+v model=%q", result, env.Model)
	}
}

func TestV2StreamingRetriesBeforeCommitAndEmitsFallbackOnce(t *testing.T) {
	primary := &MockProviderCaller{CallError: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}
	fallback := &MockProviderCaller{CallResponse: []byte(`{"id":"second","object":"chat.completion","created":1,"model":"logical/model","choices":[{"index":0,"message":{"role":"assistant","content":"only-second-route"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)}
	routes := []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": primary, "p2": fallback}}, nil, nil)
	h.modelRouteEngine = engine
	body, _ := json.Marshal(ChatCompletionRequest{Model: "logical/model", Stream: true, Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(setAuthInfo(context.Background(), "tenant-a", "project-a", "user-a", "key-a", ""))
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	h.Handler().ServeHTTP(w, req)
	if len(primary.CallCalls) != 1 || len(fallback.CallCalls) != 1 || strings.Count(w.Body.String(), "only-second-route") != 1 || strings.Contains(w.Body.String(), "first-route") {
		t.Fatalf("buffered stream output wrong: primary=%d fallback=%d body=%s", len(primary.CallCalls), len(fallback.CallCalls), w.Body.String())
	}
}

func TestV2StreamingRecordsTTFTPerAttempt(t *testing.T) {
	primary := &executionTestCaller{err: transportFailure(), ttftMS: 11}
	fallback := &executionTestCaller{response: []byte(`{}`), ttftMS: 37}
	routes := []modelrouter.ModelRecord{
		route("p1", "openai", "https://one.example", "up-one"),
		route("p2", "openai", "https://two.example", "up-two"),
	}
	for i := range routes {
		routes[i].ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	}
	engine := &executionTestEngine{
		hasPolicy: true,
		applied:   true,
		plan:      modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]},
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "r-ttft", TenantID: "tenant-a", Model: "logical/model", EndpointType: "messages",
	}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "key-1", "p2": "key-2"},
		Factory: &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
			"p1": primary,
			"p2": fallback,
		}},
		Envelope: envelope, SecuredBody: []byte(`{"model":"logical/model"}`), Streaming: true,
	})
	if err != nil || result == nil || !result.UsedFallback {
		t.Fatalf("streaming fallback result=%+v err=%v", result, err)
	}
	if len(engine.recorded) != 2 {
		t.Fatalf("attempt results=%+v", engine.recorded)
	}
	if engine.recorded[0].TTFT != 11*time.Millisecond || engine.recorded[1].TTFT != 37*time.Millisecond {
		t.Fatalf("TTFT leaked across attempts: %+v", engine.recorded)
	}
}

func TestV2StreamingSharedTrackerDoesNotExecuteFallbackAfterFirstEvent(t *testing.T) {
	primary := &MockProviderCaller{}
	fallback := &MockProviderCaller{}
	routes := []modelrouter.ModelRecord{route("p1", "openai", "one", "a"), route("p2", "openai", "two", "b")}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	tracker := &relay.CommitTracker{}
	_, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine:             engine,
		CredentialResolver: executionCredentialResolver{"p1": "key", "p2": "key"},
		Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": primary, "p2": fallback}},
		Envelope:           &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"},
		SecuredBody:        []byte(`{"model":"logical/model"}`),
		Streaming:          true,
		CommitTracker:      tracker,
		StreamSink: func(context.Context, ProviderCaller, *modelrouter.RequestEnvelope, []byte) (bool, error) {
			if err := tracker.Transition(relay.CommitHeadersCommitted); err != nil {
				return true, err
			}
			if err := tracker.Transition(relay.CommitFirstEventFlushed); err != nil {
				return true, err
			}
			_ = tracker.Abort()
			return true, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
		},
	})
	if err == nil || len(fallback.CallCalls) != 0 || tracker.State() != relay.CommitAborted {
		t.Fatalf("committed stream retried: err=%v fallback=%d state=%s", err, len(fallback.CallCalls), tracker.State())
	}
}

func TestV2MessagesAndResponsesStreamingWithoutSinkRemainBuffered(t *testing.T) {
	tests := []struct {
		endpoint string
		caps     modelrouter.ProtocolCapabilities
	}{
		{endpoint: "messages", caps: modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}},
		{endpoint: "responses", caps: modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			routeRecord := route("p1", "openai", "one", "vendor-model")
			routeRecord.ProtocolCapabilities = tt.caps
			caller := &executionTestCaller{response: []byte(`{"buffered":true}`)}
			engine := &executionTestEngine{applied: true, hasPolicy: true, plan: modelrouter.RoutePlan{Primary: routeRecord}}
			result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
				Engine:             engine,
				CredentialResolver: executionCredentialResolver{"p1": "key"},
				Factory:            &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": caller}},
				Envelope:           &modelrouter.RequestEnvelope{TenantID: "tenant-a", Model: "logical/model", EndpointType: tt.endpoint},
				SecuredBody:        []byte(`{"model":"logical/model"}`),
				Streaming:          true,
			})
			if err != nil || result == nil || result.LiveStream || string(result.ResponseBody) != `{"buffered":true}` || caller.called != 1 {
				t.Fatalf("result=%+v calls=%d err=%v", result, caller.called, err)
			}
		})
	}
}

func TestMessagesGeminiBridgeAdmitsCanonicalVerifiedChatCapability(t *testing.T) {
	for _, typ := range []string{"gemini", "vertex"} {
		record := route("provider", typ, "https://provider.example", "vendor-model")
		record.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true}
		protocol, decision := selectModelRouteProtocol(record, relay.RequestFeatures{IngressProtocol: "messages", Tools: true, ToolResults: true, Stream: true})
		if !decision.Eligible || protocol != "gemini" {
			t.Fatalf("%s canonical Chat capability did not admit Messages bridge: protocol=%s decision=%+v", typ, protocol, decision)
		}
	}
}

// Claude Code 等 Messages 客户端每个请求都带 cache_control 缓存断点。它只是性能提示，
// 桥接到 OpenAI 协议时会被忽略，不应因此判定“无可用上游路由”。
func TestMessagesBridgeToOpenAIAdmitsCacheControlHint(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		caps         modelrouter.ProtocolCapabilities
		wantProtocol string
	}{
		{name: "openai responses bridge", providerType: "openai", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, ResponsesNative: true}, wantProtocol: "responses"},
		{name: "custom responses bridge", providerType: "custom", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true, ResponsesNative: true}, wantProtocol: "responses"},
		{name: "openai chat bridge", providerType: "openai", caps: modelrouter.ProtocolCapabilities{Explicit: true, ChatCompletions: true}, wantProtocol: "chat"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := route("provider", tc.providerType, "https://provider.example", "vendor-model")
			record.ProtocolCapabilities = tc.caps
			got, decision := selectModelRouteProtocol(record, relay.RequestFeatures{
				IngressProtocol: "messages", Tools: true, ToolResults: true, Stream: true, CacheTokens: true,
			})
			if !decision.Eligible || got != tc.wantProtocol {
				t.Fatalf("protocol=%q decision=%+v want=%q eligible", got, decision, tc.wantProtocol)
			}
		})
	}
}

// 原生 Anthropic 上游仍然原样透传缓存断点；Gemini/Bedrock 没有等价语义，保持拒绝。
func TestMessagesCacheControlKeepsNativeAndRejectsNonOpenAIBridges(t *testing.T) {
	native := route("provider", "anthropic", "https://provider.example", "vendor-model")
	native.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	if got, decision := selectModelRouteProtocol(native, relay.RequestFeatures{IngressProtocol: "messages", CacheTokens: true}); !decision.Eligible || got != "messages" {
		t.Fatalf("native Anthropic must admit cache_control: protocol=%q decision=%+v", got, decision)
	}
	gem := route("provider", "gemini", "https://provider.example", "vendor-model")
	gem.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, ChatCompletions: true}
	if _, decision := selectModelRouteProtocol(gem, relay.RequestFeatures{IngressProtocol: "messages", CacheTokens: true}); decision.Eligible {
		t.Fatalf("Gemini bridge must keep rejecting cache_control: %+v", decision)
	}
}

// 探测得来的端点状态（未验证、探测失败）不拦截：按入口协议原样转发给上游。
func TestProbeDerivedUnknownEndpointsPassThroughInsteadOfRejecting(t *testing.T) {
	digest := modelrouter.ProviderConfigDigest("openai", "https://one.example", "bearer")
	raw := []byte(`{"chat":{"state":"unknown","source":"none"},"responses":{"state":"unsupported","source":"probe","provider_config_digest":"` + digest + `"},"messages":{"state":"unknown","source":"none"}}`)
	record := route("p1", "custom", "https://one.example", "up-one")
	record.ProtocolCapabilities = modelrouter.ApplyEffectiveEndpointCapabilities(modelrouter.ProtocolCapabilities{}, raw, digest, time.Now())
	for _, ingress := range []string{"chat", "messages", "embeddings"} {
		got, decision := selectModelRouteProtocol(record, relay.RequestFeatures{IngressProtocol: ingress})
		if !decision.Eligible || got != ingress {
			t.Fatalf("%s: protocol=%q decision=%+v", ingress, got, decision)
		}
	}
	blocked := []byte(`{"chat":{"state":"unsupported","source":"administrator_override","is_override":true}}`)
	record.ProtocolCapabilities = modelrouter.ApplyEffectiveEndpointCapabilities(modelrouter.ProtocolCapabilities{}, blocked, digest, time.Now())
	if _, decision := selectModelRouteProtocol(record, relay.RequestFeatures{IngressProtocol: "chat"}); decision.Eligible {
		t.Fatalf("administrator override must still block: %+v", decision)
	}
}
