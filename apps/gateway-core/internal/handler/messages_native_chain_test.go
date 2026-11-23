package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestNativeMessagesV2BridgesToOpenAIResponses(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != "/v1/responses" {
			t.Errorf("upstream path = %q", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		if request["model"] != "gpt-upstream" || request["input"] == nil {
			t.Errorf("upstream request = %#v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"resp_bridge","object":"response","status":"completed","model":"gpt-upstream",
			"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"bridge-ok"}]}],
			"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}
		}`))
	}))
	defer upstream.Close()

	// Production registers this OpenAI-compatible upstream as provider_type=custom
	// and proves Responses support through explicit model capabilities.
	record := route("p-openai", "custom", upstream.URL+"/v1", "gpt-upstream")
	record.ModelName = "customer-coding"
	record.ProviderAuthMode = "bearer"
	record.ProtocolCapabilities = modelrouter.ProtocolCapabilities{
		Explicit: true, ChatCompletions: true, ResponsesNative: true,
	}
	engine := &executionTestEngine{
		hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: record},
	}
	handler := NewMessagesHandler(
		&config.Config{}, &MockModelResolver{ProviderAPIKey: "provider-secret", ModelRecord: &record},
		&MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{},
		&RealProviderAdapterFactory{}, nil, nil,
	)
	handler.SetModelRoutingEngine(engine)

	response := serveNativeMessages(
		t, handler, "/v1/messages",
		[]byte(`{"model":"customer-coding","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`),
		nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode gateway response: %v body=%s", err, response.Body.String())
	}
	if body["type"] != "message" || body["model"] != "customer-coding" {
		t.Fatalf("gateway response = %#v", body)
	}
	content := body["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "bridge-ok" {
		t.Fatalf("gateway content = %#v", content)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d", upstreamCalls.Load())
	}
}

func TestNativeMessagesV2FallsBackWhenPrimarySSEIsTruncated(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_partial\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"kiro-opus-1m\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n" +
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n",
		))
	}))
	defer primary.Close()

	complete := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fallback\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"kiro-opus-1m\",\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"fallback-ok\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(complete))
	}))
	defer fallback.Close()

	routes := []modelrouter.ModelRecord{
		route("p1", "openai", primary.URL, "kiro-opus-1m"),
		route("p2", "openai", fallback.URL, "kiro-opus-1m"),
	}
	for i := range routes {
		routes[i].ModelName = "claude-opus-1m"
		routes[i].ProviderAuthMode = "bearer"
		routes[i].ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	}
	engine := &executionTestEngine{
		hasPolicy: true,
		applied:   true,
		plan:      modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]},
	}
	resolver := &MockModelResolver{ProviderAPIKey: "provider-secret", ModelRecord: &routes[0]}
	handler := NewMessagesHandler(
		&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil,
	)
	handler.SetModelRoutingEngine(engine)

	response := serveNativeMessages(
		t,
		handler,
		"/v1/messages",
		[]byte(`{"model":"claude-opus-1m","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"hello"}]}`),
		nil,
	)

	if response.Code != http.StatusOK || response.Body.String() != complete {
		t.Fatalf("fallback response status=%d body=%q", response.Code, response.Body.String())
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("primary calls=%d fallback calls=%d", primaryCalls.Load(), fallbackCalls.Load())
	}
	if len(engine.recorded) != 2 || engine.recorded[0].Success || !engine.recorded[0].Retryable || !engine.recorded[1].Success {
		t.Fatalf("route health outcomes=%+v", engine.recorded)
	}
}

func TestNativeMessagesV2FallsBackWhenPrimaryReturnsInvalid200JSON(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer primary.Close()

	want := []byte(`{"id":"msg_fallback_json","type":"message","role":"assistant","model":"kiro-opus-1m","content":[{"type":"text","text":"fallback-json-ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":2,"output_tokens":1}}`)
	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(want)
	}))
	defer fallback.Close()

	routes := []modelrouter.ModelRecord{
		route("p1", "openai", primary.URL, "kiro-opus-1m"),
		route("p2", "openai", fallback.URL, "kiro-opus-1m"),
	}
	for i := range routes {
		routes[i].ModelName = "claude-opus-1m"
		routes[i].ProviderAuthMode = "bearer"
		routes[i].ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	}
	engine := &executionTestEngine{
		hasPolicy: true,
		applied:   true,
		plan:      modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]},
	}
	resolver := &MockModelResolver{ProviderAPIKey: "provider-secret", ModelRecord: &routes[0]}
	handler := NewMessagesHandler(
		&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil,
	)
	handler.SetModelRoutingEngine(engine)

	response := serveNativeMessages(
		t,
		handler,
		"/v1/messages",
		[]byte(`{"model":"claude-opus-1m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`),
		nil,
	)

	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), want) {
		t.Fatalf("fallback response status=%d body=%s", response.Code, response.Body.String())
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("primary calls=%d fallback calls=%d", primaryCalls.Load(), fallbackCalls.Load())
	}
	if len(engine.recorded) != 2 || engine.recorded[0].Success || !engine.recorded[0].Retryable || !engine.recorded[1].Success {
		t.Fatalf("route health outcomes=%+v", engine.recorded)
	}
}

func TestNativeMessagesFortyMiBBoFlowChain(t *testing.T) {
	boflowURL := os.Getenv("JJD_NATIVE_CHAIN_BOFLOW_URL")
	if boflowURL == "" {
		t.Skip("set JJD_NATIVE_CHAIN_BOFLOW_URL via deploy/tests/test_native_anthropic_messages_chain.sh")
	}
	t.Setenv("UAG_ROUTING_DISABLED", "true")

	resolver := &MockModelResolver{
		ProviderAPIKey: "boflow-provider-secret",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-chain", ModelName: "claude-opus-1m",
			ProviderID: "provider-boflow", ProviderType: "openai",
			ProviderBaseURL: boflowURL, ProviderAuthMode: "bearer",
			UpstreamModelID: "boflow-public-opus", Status: "active",
		},
	}
	handler := NewMessagesHandler(
		&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil,
	)
	headers := http.Header{
		"Anthropic-Version":         {"2023-06-01"},
		"Anthropic-Beta":            {"feature-a", "feature-b"},
		"Authorization":             {"Bearer inbound-client-secret"},
		"X-Api-Key":                 {"inbound-anthropic-secret"},
		"Cookie":                    {"private=cookie"},
		"X-JJDGuard-Internal-Token": {"private-internal"},
	}

	largeText := strings.Repeat("0123456789abcdef", (40*1024*1024)/16)
	digest := sha256.Sum256([]byte(largeText))
	requestBody, err := json.Marshal(map[string]any{
		"model": "claude-opus-1m", "max_tokens": 1,
		"messages": []any{map[string]any{"role": "user", "content": largeText}},
		"thinking": map[string]any{"type": "enabled", "budget_tokens": 4096},
		"unknown":  map[string]any{"keep": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := serveNativeMessages(
		t, handler, "/v1/messages?scenario=json&beta=one&beta=two", requestBody, headers,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("40 MiB chain status=%d body=%s", response.Code, response.Body.String())
	}
	var message struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Unknown map[string]any `json:"unknown"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &message); err != nil {
		t.Fatal(err)
	}
	wantDigest := fmt.Sprintf("sha256:%x", digest)
	if len(message.Content) != 1 || message.Content[0].Text != wantDigest || message.Unknown["keep"] != true {
		t.Fatalf("40 MiB chain response mismatch: %#v", message)
	}
	if response.Header().Get("Anthropic-Request-Id") != "kiro-chain-json" {
		t.Fatalf("Kiro response metadata was lost: %#v", response.Header())
	}

	sseBody := []byte(`{"model":"claude-opus-1m","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"sse"}]}`)
	sseResponse := serveNativeMessages(
		t, handler, "/v1/messages?scenario=sse&beta=one&beta=two", sseBody, headers,
	)
	if sseResponse.Code != http.StatusOK {
		t.Fatalf("SSE chain status=%d body=%s", sseResponse.Code, sseResponse.Body.String())
	}
	wantSSE := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_chain_sse\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"kiro-opus-1m\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"chain-ok\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	if sseResponse.Body.String() != wantSSE {
		t.Fatalf("native SSE changed across chain: got=%q want=%q", sseResponse.Body.String(), wantSSE)
	}

	errorBody := []byte(`{"model":"claude-opus-1m","max_tokens":8,"messages":[{"role":"user","content":"bad"}]}`)
	errorResponse := serveNativeMessages(
		t, handler, "/v1/messages?scenario=bad&beta=one&beta=two", errorBody, headers,
	)
	wantError := []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"chain bad request"},"request_id":"kiro-chain-400"}`)
	if errorResponse.Code != http.StatusBadRequest || !bytes.Equal(errorResponse.Body.Bytes(), wantError) {
		t.Fatalf("400 chain changed: status=%d body=%s", errorResponse.Code, errorResponse.Body.String())
	}
	if errorResponse.Header().Get("Retry-After") != "3" ||
		errorResponse.Header().Get("Anthropic-Request-Id") != "kiro-chain-400" ||
		errorResponse.Header().Get("Set-Cookie") != "" {
		t.Fatalf("400 response headers changed or leaked: %#v", errorResponse.Header())
	}
}
