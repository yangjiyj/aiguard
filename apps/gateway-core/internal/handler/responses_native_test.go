package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func newNativeResponsesTestHandler(caller *MockProviderCaller, security *MockSecurityChecker, audit *MockAuditWriter, native bool) *ResponsesHandler {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active",
		ResponsesNative: native,
	}}
	factory := &MockProviderAdapterFactory{MockProviderCaller: caller}
	return NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, security, audit, factory, nil, nil)
}

func nativeResponsesRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123")
	return req.WithContext(ctx)
}

func TestNativeResponsesNonStreamPreservesAdvancedRequestAndResponse(t *testing.T) {
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"done","annotations":[]}]}],"usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18},"unknown_response_field":{"keep":true}}`)
	caller := &MockProviderCaller{CallResponse: upstream}
	security := &MockSecurityChecker{}
	audit := &MockAuditWriter{}
	handler := newNativeResponsesTestHandler(caller, security, audit, true)
	requestBody := []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":false,"tools":[{"type":"custom","name":"shell_command","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}}],"tool_choice":"auto","reasoning":{"effort":"high"},"unknown_request_field":{"keep":1}}`)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, requestBody))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), upstream) {
		t.Fatalf("native response changed\nwant=%s\n got=%s", upstream, w.Body.Bytes())
	}
	if len(caller.TransformRequestCalls) != 1 || len(caller.CallCalls) != 1 {
		t.Fatalf("transform=%d calls=%d", len(caller.TransformRequestCalls), len(caller.CallCalls))
	}
	var sent map[string]any
	if err := json.Unmarshal(caller.CallCalls[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent["unknown_request_field"] == nil || sent["reasoning"] == nil {
		t.Fatalf("advanced fields lost: %s", caller.CallCalls[0])
	}
	tools, _ := sent["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["type"] != "custom" {
		t.Fatalf("custom tool lost: %v", sent["tools"])
	}
	if caller.TransformRequestCalls[0].Envelope.UpstreamModelID != "gpt-5.6" {
		t.Fatalf("upstream model id=%q", caller.TransformRequestCalls[0].Envelope.UpstreamModelID)
	}
	if len(caller.CallEnvelopes) != 1 || caller.CallEnvelopes[0].EndpointType != "responses" {
		t.Fatalf("endpoint=%v", caller.CallEnvelopes)
	}
	if len(security.OutputCheckCalls) != 1 || security.OutputCheckCalls[0].Content != "done" {
		t.Fatalf("native output did not enter security: %+v", security.OutputCheckCalls)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit finalizes=%+v", audit.RequestLogFinalizes)
	}
}

func TestNativeResponsesHandlerUsesRealHTTPAdapterAndRewritesModel(t *testing.T) {
	upstreamResponse := []byte(`{"id":"resp_http","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":2,"output_tokens":0,"total_tokens":2}}`)
	var receivedPath, receivedAuthorization string
	var receivedBody map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(upstreamResponse)
	}))
	defer upstream.Close()

	resolver := &MockModelResolver{
		ProviderAPIKey: "upstream-secret",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-http", ProviderID: "provider-http", ModelName: "gpt-5.6-sol",
			UpstreamModelID: "gpt-5.6", ProviderType: "openai",
			ProviderBaseURL: upstream.URL, ProviderAuthMode: "bearer",
			Status: "active", ResponsesNative: true,
		},
	}
	handler := NewResponsesHandler(
		&config.Config{},
		resolver,
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		&MockAuditWriter{},
		&RealProviderAdapterFactory{},
		nil,
		nil,
	)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","reasoning":{"effort":"high"}}`)))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), upstreamResponse) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if receivedPath != "/v1/responses" {
		t.Fatalf("upstream path=%q", receivedPath)
	}
	if receivedAuthorization != "Bearer upstream-secret" {
		t.Fatalf("authorization=%q", receivedAuthorization)
	}
	if receivedBody["model"] != "gpt-5.6" || receivedBody["reasoning"] == nil {
		t.Fatalf("upstream body=%v", receivedBody)
	}
}

func TestNativeResponsesStreamPreservesUnknownEventsAndOrder(t *testing.T) {
	raw := "event: response.created\nid: first\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\n" +
		"event: response.opaque\ndata: {\"type\":\"response.opaque\",\"extension\":{\"keep\":1}}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-5.6\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"done\"}]}],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"
	caller := &MockProviderCaller{CallResponse: []byte(raw)}
	security := &MockSecurityChecker{}
	audit := &MockAuditWriter{}
	handler := newNativeResponsesTestHandler(caller, security, audit, true)
	body := []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true,"client_metadata":{"client":"codex"}}`)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type=%q", got)
	}
	if w.Body.String() != raw {
		t.Fatalf("SSE changed\nwant=%q\n got=%q", raw, w.Body.String())
	}
	if len(security.OutputCheckCalls) != 1 {
		t.Fatalf("output security calls=%d", len(security.OutputCheckCalls))
	}
}

func TestNativeResponsesStreamUpstreamHTTPErrorUsesHTTPStatus(t *testing.T) {
	upstreamBody := []byte(`{"error":{"message":"temporary failure","type":"server_error"}}`)
	audit := &MockAuditWriter{}
	handler := newNativeResponsesTestHandler(&MockProviderCaller{
		CallError: &provider.UpstreamHTTPError{
			StatusCode: http.StatusBadGateway,
			Body:       upstreamBody,
			Message:    "temporary failure",
		},
	}, &MockSecurityChecker{}, audit, true)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true}`)))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if !strings.Contains(w.Body.String(), "upstream_error") || bytes.Contains(w.Body.Bytes(), []byte("temporary failure")) {
		t.Fatalf("body = %q, want sanitized error", w.Body.Bytes())
	}
	if strings.Contains(w.Body.String(), "response.failed") {
		t.Fatalf("pre-response upstream failure must not be encoded as an SSE failure: %q", w.Body.String())
	}
	if len(audit.RequestLogFinalizes) != 1 {
		t.Fatalf("request log finalizes = %d, want 1", len(audit.RequestLogFinalizes))
	}
	if got := audit.RequestLogFinalizes[0].AuditResult; got == nil || got.ResponseMetadata["error_message"] != "temporary failure" {
		t.Fatalf("missing retained diagnostic: %+v", got)
	}
	if got := audit.RequestLogFinalizes[0]; got.Status != "provider_error" || got.StatusCode != http.StatusBadGateway {
		t.Fatalf("request audit = (%q, %d), want (provider_error, %d)", got.Status, got.StatusCode, http.StatusBadGateway)
	}
}

func TestNativeResponsesIncompleteStreamPassesThroughAndAuditsUsage(t *testing.T) {
	raw := "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"incomplete\",\"model\":\"gpt-5.6\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"partial\"}]}],\"usage\":{\"input_tokens\":4,\"output_tokens\":2,\"total_tokens\":6}}}\n\n"
	caller := &MockProviderCaller{CallResponse: []byte(raw)}
	security := &MockSecurityChecker{}
	audit := &MockAuditWriter{}
	handler := newNativeResponsesTestHandler(caller, security, audit, true)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Body.String() != raw {
		t.Fatalf("incomplete stream changed: %q", w.Body.String())
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "incomplete" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
	if input, output := responseUsageTokens(audit.RequestLogFinalizes[0].RespBody); input != 4 || output != 2 {
		t.Fatalf("usage=%d/%d", input, output)
	}
}

func TestNativeResponsesBlockedStreamUsesResponsesFailureEvents(t *testing.T) {
	raw := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-5.6\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"secret-output\"}]}]}}\n\n"
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "secret", Severity: "high", Action: "block"}}}
	handler := newNativeResponsesTestHandler(&MockProviderCaller{CallResponse: []byte(raw)}, security, &MockAuditWriter{}, true)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true}`)))
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type=%q body=%s", got, w.Body.String())
	}
	events := parseResponsesSSE(t, w.Body.String())
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" {
		t.Fatalf("events=%s", got)
	}
	if strings.Contains(w.Body.String(), "secret-output") {
		t.Fatalf("blocked stream leaked output: %s", w.Body.String())
	}
}

func TestNativeResponsesTruncatedStreamUsesResponsesFailureEvents(t *testing.T) {
	raw := "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"half\"}\n\n"
	handler := newNativeResponsesTestHandler(&MockProviderCaller{CallResponse: []byte(raw)}, &MockSecurityChecker{}, &MockAuditWriter{}, true)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true}`)))
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type=%q body=%s", got, w.Body.String())
	}
	events := parseResponsesSSE(t, w.Body.String())
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" {
		t.Fatalf("events=%s", got)
	}
}

func TestResponsesAdvancedToolsFailClosedWithoutNativeCapability(t *testing.T) {
	caller := &MockProviderCaller{}
	handler := newNativeResponsesTestHandler(caller, &MockSecurityChecker{}, &MockAuditWriter{}, false)
	body := []byte(`{"model":"gpt-5.6-sol","input":"inspect","tools":[{"type":"custom","name":"shell_command"}]}`)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "responses_native_unavailable") {
		t.Fatalf("wrong error body: %s", w.Body.String())
	}
	if len(caller.CallCalls) != 0 {
		t.Fatalf("compatibility upstream was called %d times", len(caller.CallCalls))
	}
}

func TestResponsesAdvancedToolsStreamFailsWithResponsesEventsWithoutNativeCapability(t *testing.T) {
	caller := &MockProviderCaller{}
	handler := newNativeResponsesTestHandler(caller, &MockSecurityChecker{}, &MockAuditWriter{}, false)
	body := []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true,"tools":[{"type":"custom","name":"shell_command"}]}`)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))

	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type=%q body=%s", got, w.Body.String())
	}
	events := parseResponsesSSE(t, w.Body.String())
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" {
		t.Fatalf("events=%s body=%s", got, w.Body.String())
	}
	if len(caller.CallCalls) != 0 {
		t.Fatalf("compatibility upstream was called %d times", len(caller.CallCalls))
	}
}

func TestResponsesV2UsesCapabilityFromPreparedPlanInsteadOfLegacyLookup(t *testing.T) {
	legacy := &modelrouter.ModelRecord{
		ID: "legacy-row", ProviderID: "legacy-provider", ModelName: "gpt-5.6-sol",
		ProviderType: "openai", ProviderBaseURL: "https://legacy.example/v1",
		Status: "active", ResponsesNative: false,
	}
	nativeRoute := route("native-provider", "openai", "https://native.example/v1", "gpt-5.6")
	nativeRoute.ModelName = "gpt-5.6-sol"
	nativeRoute.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	nativeRoute.ResponsesNative = true
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)
	caller := &MockProviderCaller{CallResponse: upstream}
	engine := &executionTestEngine{
		hasPolicy: true,
		applied:   true,
		plan:      modelrouter.RoutePlan{Primary: nativeRoute},
	}
	resolver := &MockModelResolver{ModelRecord: legacy}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"native-provider": caller}}
	handler := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	handler.SetModelRoutingEngine(engine)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","reasoning":{"effort":"high"}}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), upstream) {
		t.Fatalf("native response changed: %s", w.Body.String())
	}
	if len(caller.CallCalls) != 1 || engine.planCalls != 1 {
		t.Fatalf("native calls=%d plan calls=%d", len(caller.CallCalls), engine.planCalls)
	}
}

func TestResponsesV2DoesNotTrustNativeCapabilityFromLegacyLookup(t *testing.T) {
	legacy := &modelrouter.ModelRecord{
		ID: "legacy-row", ProviderID: "legacy-provider", ModelName: "gpt-5.6-sol",
		ProviderType: "openai", ProviderBaseURL: "https://legacy.example/v1",
		Status: "active", ResponsesNative: true,
	}
	nonNativeRoute := route("chat-provider", "openai", "https://chat.example/v1", "gpt-5.6")
	nonNativeRoute.ModelName = "gpt-5.6-sol"
	caller := &MockProviderCaller{}
	engine := &executionTestEngine{
		hasPolicy: true,
		applied:   true,
		plan:      modelrouter.RoutePlan{Primary: nonNativeRoute},
	}
	resolver := &MockModelResolver{ModelRecord: legacy}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"chat-provider": caller}}
	handler := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	handler.SetModelRoutingEngine(engine)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","reasoning":{"effort":"high"}}`)))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "responses_native_unavailable") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(caller.CallCalls) != 0 || engine.planCalls != 1 {
		t.Fatalf("non-native calls=%d plan calls=%d", len(caller.CallCalls), engine.planCalls)
	}
}

func TestLegacyNativeResponsesRetriesOnlyNativeCapableFallback(t *testing.T) {
	primary := &MockProviderCaller{CallError: transportFailure()}
	fallbackResponse := []byte(`{"id":"resp_fallback","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)
	fallback := &MockProviderCaller{CallResponse: fallbackResponse}
	record := &modelrouter.ModelRecord{
		ID: "model-primary", ProviderID: "provider-primary", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://primary.example/v1", Status: "active",
		ResponsesNative:    true,
		FallbackProviderID: "provider-fallback", FallbackProviderType: "openai",
		FallbackProviderBaseURL: "https://fallback.example/v1",
		FallbackModelID:         "model-fallback", FallbackUpstreamModelID: "gpt-5.6-fallback",
		FallbackResponsesNative:      true,
		ProtocolCapabilities:         modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true},
		FallbackProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true},
	}
	resolver := &MockModelResolver{ModelRecord: record}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
		"provider-primary": primary, "provider-fallback": fallback,
	}}
	handler := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","reasoning":{"effort":"high"}}`)))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), fallbackResponse) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(primary.CallCalls) != 1 || len(fallback.CallCalls) != 1 {
		t.Fatalf("primary=%d fallback=%d", len(primary.CallCalls), len(fallback.CallCalls))
	}
	if len(fallback.CallEnvelopes) != 1 ||
		fallback.CallEnvelopes[0].ModelID != "model-fallback" ||
		fallback.CallEnvelopes[0].UpstreamModelID != "gpt-5.6-fallback" {
		t.Fatalf("fallback envelope=%+v", fallback.CallEnvelopes)
	}
	if w.Header().Get("X-JJDGuard-Provider-ID") != "provider-fallback" || w.Header().Get("X-JJDGuard-Fallback-Used") != "true" {
		t.Fatalf("routing headers=%v", w.Header())
	}
}

func TestLegacyNativeResponsesDoesNotCallNonNativeFallback(t *testing.T) {
	primary := &MockProviderCaller{CallError: transportFailure()}
	fallback := &MockProviderCaller{}
	record := &modelrouter.ModelRecord{
		ID: "model-primary", ProviderID: "provider-primary", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://primary.example/v1", Status: "active",
		ResponsesNative:    true,
		FallbackProviderID: "provider-fallback", FallbackProviderType: "openai",
		FallbackProviderBaseURL: "https://fallback.example/v1",
		FallbackResponsesNative: false,
	}
	resolver := &MockModelResolver{ModelRecord: record}
	factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
		"provider-primary": primary, "provider-fallback": fallback,
	}}
	handler := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","reasoning":{"effort":"high"}}`)))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(fallback.CallCalls) != 0 {
		t.Fatalf("non-native fallback was called %d times", len(fallback.CallCalls))
	}
}

func TestLegacyNativeCapabilityRequiresUnchangedModelAndProvider(t *testing.T) {
	record := &modelrouter.ModelRecord{
		ModelName: "gpt-5.6-sol", ProviderID: "provider-primary", ResponsesNative: true,
	}
	if !legacyRouteSupportsNativeResponses(record, &modelrouter.RequestEnvelope{Model: "gpt-5.6-sol", ProviderID: "provider-primary"}) {
		t.Fatal("unchanged route should preserve native capability")
	}
	if legacyRouteSupportsNativeResponses(record, &modelrouter.RequestEnvelope{Model: "gpt-5.6-sol", ProviderID: "provider-canary"}) {
		t.Fatal("provider override reused native capability")
	}
	if legacyRouteSupportsNativeResponses(record, &modelrouter.RequestEnvelope{Model: "gpt-other", ProviderID: "provider-primary"}) {
		t.Fatal("model override reused native capability")
	}
}

func TestNativeResponsesOutputBlockDoesNotLeakBufferedBody(t *testing.T) {
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"secret-output"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "secret", Severity: "high", Action: "block"}}}
	caller := &MockProviderCaller{CallResponse: upstream}
	audit := &MockAuditWriter{}
	handler := newNativeResponsesTestHandler(caller, security, audit, true)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect"}`)))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secret-output") {
		t.Fatalf("blocked output leaked: %s", w.Body.String())
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "security_blocked" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestNativeResponsesCustomToolCallEntersAgentGuardAndBlocks(t *testing.T) {
	var toolLogReceived bool
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-native","name":"阻断系统工具","policy_version":"v1","mode":"strict","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[{"id":"block-system","tool_pattern":"system.*","action":"block","enabled":true}],"exceptions":[]}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			toolLogReceived = true
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected control-plane path: %s", r.URL.Path)
		}
	}))
	defer controlPlane.Close()

	toolRiskClient := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, toolRiskClient, false, false)
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active",
		ResponsesNative: true,
	}}
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"call_1","type":"custom_tool_call","call_id":"call_1","name":"shell_command","input":"rm -rf /"}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	handler := NewResponsesHandler(
		&config.Config{SecurityAuditOnly: false},
		resolver,
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		&MockAuditWriter{},
		&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: upstream}},
		toolRiskClient,
		nil,
	)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect"}`)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "msg_jjdguard_safety") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// 阻断提示写命令骨架；被拦下的工具调用本身（custom_tool_call 及其 input 原文）不外泄。
	if strings.Contains(w.Body.String(), "custom_tool_call") || strings.Contains(w.Body.String(), `"input":"rm -rf /"`) {
		t.Fatalf("blocked tool arguments leaked: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "命中内容：shell_command · 删除文件：rm -rf /") {
		t.Fatalf("阻断提示应写命令骨架: %s", w.Body.String())
	}
	if !toolLogReceived {
		t.Fatal("native custom tool call did not reach AgentGuard audit")
	}
}

func TestNativeResponsesInputMaskRewritesOnlyUserContent(t *testing.T) {
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)
	security := &MockSecurityChecker{InputAction: "mask", InputMasked: "[MASKED]"}
	caller := &MockProviderCaller{CallResponse: upstream}
	handler := newNativeResponsesTestHandler(caller, security, &MockAuditWriter{}, true)
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"role":"user","content":"secret-input"}],"unknown":{"keep":true}}`)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(caller.CallCalls) != 1 {
		t.Fatalf("calls=%d", len(caller.CallCalls))
	}
	sent := string(caller.CallCalls[0])
	if strings.Contains(sent, "secret-input") || !strings.Contains(sent, "[MASKED]") || !strings.Contains(sent, `"unknown":{"keep":true}`) {
		t.Fatalf("masked native request is wrong: %s", sent)
	}
}

func TestNativeResponsesToolOutputMaskDoesNotLeakOriginal(t *testing.T) {
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)
	security := &MockSecurityChecker{InputAction: "mask", InputMasked: "[TOOL-MASKED]"}
	caller := &MockProviderCaller{CallResponse: upstream}
	handler := newNativeResponsesTestHandler(caller, security, &MockAuditWriter{}, true)
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"type":"custom_tool_call_output","call_id":"call_1","output":"SECRET-TOOL-RESULT"}]}`)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(caller.CallCalls) != 1 {
		t.Fatalf("calls=%d", len(caller.CallCalls))
	}
	sent := string(caller.CallCalls[0])
	if strings.Contains(sent, "SECRET-TOOL-RESULT") || !strings.Contains(sent, "[TOOL-MASKED]") {
		t.Fatalf("tool output masking failed: %s", sent)
	}
}

func TestExtractNativeResponsesFinalFromSSE(t *testing.T) {
	raw := []byte("event: response.opaque\ndata: {\"type\":\"response.opaque\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[]}}\n\n")
	final, err := extractNativeResponsesFinal(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(final) != `{"id":"resp_1","status":"completed","output":[]}` {
		t.Fatalf("final=%s", final)
	}
}

func TestExtractNativeResponsesFinalRejectsFailedTerminalEvent(t *testing.T) {
	raw := []byte("event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"failed\",\"error\":{\"message\":\"bad upstream\"}}}\n\n")
	if _, err := extractNativeResponsesFinal(raw, true); err == nil {
		t.Fatal("failed terminal Responses event must not be treated as success")
	}
}

func TestNativeResponsesSecurityViewIncludesCustomToolCall(t *testing.T) {
	final := []byte(`{"id":"resp_1","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"ctc_1","type":"custom_tool_call","call_id":"call_1","name":"shell_command","input":"{\"command\":\"pwd\"}"}]}`)
	view, err := nativeResponsesSecurityView(final)
	if err != nil {
		t.Fatal(err)
	}
	var chat ChatCompletionResponse
	if err := json.Unmarshal(view, &chat); err != nil {
		t.Fatal(err)
	}
	if len(chat.Choices) != 1 || len(chat.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("tool calls missing from security view: %s", view)
	}
	call := chat.Choices[0].Message.ToolCalls[0]
	if call.ID != "call_1" || call.Function.Name != "shell_command" || call.Function.Arguments != `{"command":"pwd"}` {
		t.Fatalf("tool call=%+v", call)
	}
}

func TestNativeResponsesSecurityViewWrapsRawShellInput(t *testing.T) {
	final := []byte(`{"id":"resp_1","object":"response","status":"completed","output":[{"id":"ctc_1","type":"custom_tool_call","name":"shell_command","input":"pwd"}]}`)
	view, err := nativeResponsesSecurityView(final)
	if err != nil {
		t.Fatal(err)
	}
	var chat ChatCompletionResponse
	if err := json.Unmarshal(view, &chat); err != nil {
		t.Fatal(err)
	}
	got := chat.Choices[0].Message.ToolCalls[0].Function.Arguments
	if got != `{"command":"pwd"}` {
		t.Fatalf("arguments=%s", got)
	}
}

func TestConvertNativeCustomToolOutputProvidesSecurityPreflightMessage(t *testing.T) {
	handler := &ResponsesHandler{}
	req := &ResponsesRequest{
		Model: "gpt-5.6-sol",
		Input: []interface{}{
			map[string]interface{}{
				"type": "custom_tool_call_output", "call_id": "call_shell_1",
				"output": map[string]interface{}{"stdout": "dev-host", "exit_code": 0},
			},
		},
	}
	chat, err := handler.convertToChatRequest(req)
	if err != nil {
		t.Fatalf("custom tool output must be accepted for the next native turn: %v", err)
	}
	if len(chat.Messages) != 1 || chat.Messages[0].Role != "tool" || chat.Messages[0].ToolCallID != "call_shell_1" {
		t.Fatalf("preflight messages=%+v", chat.Messages)
	}
	if !strings.Contains(messageText(chat.Messages[0].Content), "dev-host") {
		t.Fatalf("tool output content=%s", chat.Messages[0].Content)
	}
}

func TestNativeResponsesUsageTokens(t *testing.T) {
	input, output := responseUsageTokens([]byte(`{"usage":{"input_tokens":5,"output_tokens":7,"total_tokens":12}}`))
	if input != 5 || output != 7 {
		t.Fatalf("tokens=%d/%d", input, output)
	}
}
