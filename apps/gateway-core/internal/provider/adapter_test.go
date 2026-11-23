package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestBuiltinAdapterEndpointCapabilities(t *testing.T) {
	openAI := &OpenAIAdapter{}
	if !openAI.SupportsEndpoint("chat") || !openAI.SupportsEndpoint("embeddings") || !openAI.SupportsEndpoint("responses") || !openAI.SupportsEndpoint("images") || !openAI.SupportsEndpoint("messages") {
		t.Fatal("openai endpoint capabilities are incorrect")
	}
	anthropic := &AnthropicAdapter{}
	if !anthropic.SupportsEndpoint("chat") || !anthropic.SupportsEndpoint("messages") || anthropic.SupportsEndpoint("embeddings") || anthropic.SupportsEndpoint("responses") {
		t.Fatal("anthropic endpoint capabilities are incorrect")
	}
}

// TestOpenAIAdapterTransformRequest verifies OpenAI request transformation
func TestOpenAIAdapterTransformRequest(t *testing.T) {
	adapter := &OpenAIAdapter{}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-123",
		Model:     "gpt-4",
	}

	rawBody := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`)

	result, err := adapter.TransformRequest(envelope, rawBody)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	// OpenAI adapter should pass through unchanged
	if string(result) != string(rawBody) {
		t.Errorf("Expected unchanged body, got %s", string(result))
	}
}

// TestOpenAIAdapterCall verifies OpenAI provider call behavior
func TestOpenAIAdapterCall(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type header")
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("Expected Authorization header with test-key")
		}

		// Return mock response
		resp := map[string]interface{}{
			"id":      "chatcmpl-123",
			"object":  "chat.completion",
			"created": 1716399600,
			"model":   "gpt-4",
			"choices": []interface{}{
				map[string]interface{}{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": "Hello! How can I help?",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     10,
				"completion_tokens": 20,
				"total_tokens":      30,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	resp, err := adapter.Call(ctx, envelope, payload)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	// Verify response is valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed["id"] != "chatcmpl-123" {
		t.Errorf("Expected id='chatcmpl-123'")
	}
}

func TestOpenAIAdapterCallBaseURLAlreadyContainsV1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("Expected path /v1/chat/completions, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-contains-v1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL + "/v1",
		APIKey:  "test-key",
	}

	resp, err := adapter.Call(context.Background(), &modelrouter.RequestEnvelope{EndpointType: "chat"}, []byte(`{"model":"kimi-k2.5","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("Expected non-empty response")
	}
}

func TestOpenAIAdapterResponsesPreservesPayloadAndUsesResponsesPath(t *testing.T) {
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path=%s want=/v1/responses", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("authorization header missing")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type=%q", r.Header.Get("Content-Type"))
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed","output":[]}`))
	}))
	defer server.Close()

	original := []byte(`{"model":"logical-gpt","input":[{"role":"user","content":[{"type":"input_text","text":"read it"}]}],"instructions":"system","tools":[{"type":"custom","name":"shell_command","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}}],"tool_choice":"auto","parallel_tool_calls":true,"reasoning":{"effort":"high"},"text":{"verbosity":"low"},"include":["reasoning.encrypted_content"],"client_metadata":{"client":"codex"},"prompt_cache_key":"cache-a","store":false,"stream":false,"unknown_extension":{"keep":1}}`)
	adapter := &OpenAIAdapter{BaseURL: server.URL + "/v1", APIKey: "test-key"}
	env := &modelrouter.RequestEnvelope{EndpointType: "responses", Model: "logical-gpt", UpstreamModelID: "vendor-gpt"}

	transformed, err := adapter.TransformRequest(env, original)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := adapter.Call(context.Background(), env, transformed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(resp, []byte(`"id":"resp_1"`)) {
		t.Fatalf("response changed: %s", resp)
	}

	var want, got map[string]any
	if err := json.Unmarshal(original, &want); err != nil {
		t.Fatal(err)
	}
	want["model"] = "vendor-gpt"
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("upstream body invalid: %v body=%s", err, gotBody)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatalf("payload changed\nwant=%s\n got=%s", wantJSON, gotJSON)
	}
}

func TestOpenAIResponsesModelRewritePreservesUnknownNumberLexemes(t *testing.T) {
	adapter := &OpenAIAdapter{}
	raw := []byte(`{"model":"logical","stream":true,"unknown_big":9007199254740993123456789,"unknown_decimal":0.12345678901234567890123456789}`)
	got, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{Model: "logical", UpstreamModelID: "vendor"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(got, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["unknown_big"]) != "9007199254740993123456789" {
		t.Fatalf("big integer changed: %s", fields["unknown_big"])
	}
	if string(fields["unknown_decimal"]) != "0.12345678901234567890123456789" {
		t.Fatalf("decimal changed: %s", fields["unknown_decimal"])
	}
}

func TestReadResponseBodyWithLimitRejectsOversize(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("123456"))}
	if _, err := readResponseBodyWithLimit(resp, 5); err == nil {
		t.Fatal("oversized non-stream response must fail")
	}
}

func TestOpenAIResponsesNonStreamingRejectsFailedTerminalBeforeRouteSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_failed","object":"response","status":"failed","error":{"message":"native upstream failed"}}`))
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "test"}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "responses", Model: "gpt-5.6"}
	_, err := adapter.Call(context.Background(), envelope, []byte(`{"model":"gpt-5.6","input":"hello"}`))
	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil || upstreamErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("error=%T %v", err, err)
	}
	if !strings.Contains(upstreamErr.Message, "native upstream failed") {
		t.Fatalf("message=%q", upstreamErr.Message)
	}
}

// TestOpenAIAdapterCallWithoutKey verifies error when no API key
func TestOpenAIAdapterCallWithoutKey(t *testing.T) {
	adapter := &OpenAIAdapter{
		BaseURL: "https://api.openai.com",
		APIKey:  "", // Empty key
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Error("Expected error when API key is empty")
	}
	if err.Error() != "openai provider is not configured with an API key" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

// TestOpenAIAdapterTransformResponse verifies OpenAI response transformation
func TestOpenAIAdapterTransformResponse(t *testing.T) {
	adapter := &OpenAIAdapter{}

	respBody := []byte(`{"id":"chatcmpl-123","choices":[{"message":{"content":"Hello"}}]}`)

	result, err := adapter.TransformResponse(respBody)
	if err != nil {
		t.Fatalf("TransformResponse failed: %v", err)
	}

	// OpenAI adapter should pass through unchanged
	if string(result) != string(respBody) {
		t.Errorf("Expected unchanged response, got %s", string(result))
	}
}

// TestAnthropicAdapterTransformRequest verifies Anthropic request transformation
func TestAnthropicAdapterTransformRequest(t *testing.T) {
	adapter := &AnthropicAdapter{}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-123",
		Model:     "claude-3-sonnet",
	}

	// OpenAI format input
	openaiBody := []byte(`{
		"model": "claude-3-sonnet",
		"messages": [
			{"role": "system", "content": "Be helpful"},
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 1024
	}`)

	result, err := adapter.TransformRequest(envelope, openaiBody)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	// Parse transformed request
	var anthropicReq map[string]interface{}
	if err := json.Unmarshal(result, &anthropicReq); err != nil {
		t.Fatalf("Failed to parse transformed request: %v", err)
	}

	// Verify model
	if anthropicReq["model"] != "claude-3-sonnet" {
		t.Errorf("Expected model='claude-3-sonnet'")
	}

	// Verify max_tokens (Anthropic requires it)
	if anthropicReq["max_tokens"].(float64) != 1024 {
		t.Errorf("Expected max_tokens=1024")
	}

	// Verify system prompt extracted
	if anthropicSystemText(anthropicReq["system"]) != "Be helpful" {
		t.Errorf("Expected system='Be helpful'")
	}

	// Verify messages (should not include system)
	messages, ok := anthropicReq["messages"].([]interface{})
	if !ok || len(messages) != 1 {
		t.Errorf("Expected 1 message (user only, system extracted)")
	}

	// Verify message structure
	if len(messages) > 0 {
		msg := messages[0].(map[string]interface{})
		if msg["role"] != "user" {
			t.Errorf("Expected role='user'")
		}
		if anthropicMessageText(msg["content"]) != "Hello" {
			t.Errorf("Expected content='Hello'")
		}
	}
}

// TestAnthropicAdapterTransformRequestDefaultMaxTokens verifies default max_tokens
func TestAnthropicAdapterTransformRequestDefaultMaxTokens(t *testing.T) {
	adapter := &AnthropicAdapter{}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-123",
		Model:     "claude-3-sonnet",
	}

	// OpenAI format without max_tokens
	openaiBody := []byte(`{
		"model": "claude-3-sonnet",
		"messages": [{"role": "user", "content": "Hello"}]
	}`)

	result, err := adapter.TransformRequest(envelope, openaiBody)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	var anthropicReq map[string]interface{}
	if err := json.Unmarshal(result, &anthropicReq); err != nil {
		t.Fatalf("Failed to parse transformed request: %v", err)
	}

	// Should have default max_tokens
	if anthropicReq["max_tokens"].(float64) != 4096 {
		t.Errorf("Expected default max_tokens=4096, got %v", anthropicReq["max_tokens"])
	}
}

// TestAnthropicAdapterCall verifies Anthropic provider call behavior
func TestAnthropicAdapterCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Anthropic-specific headers
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("Expected anthropic-version header")
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("Expected x-api-key header")
		}

		// Return mock Anthropic response
		resp := map[string]interface{}{
			"id":    "msg-123",
			"type":  "message",
			"role":  "assistant",
			"model": "claude-3-sonnet",
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "Hello! How can I help?",
				},
			},
			"usage": map[string]interface{}{
				"input_tokens":  10,
				"output_tokens": 20,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	adapter := &AnthropicAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"claude-3-sonnet","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	resp, err := adapter.Call(ctx, envelope, payload)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed["id"] != "msg-123" {
		t.Errorf("Expected id='msg-123'")
	}
}

// TestAnthropicAdapterCallWithoutKey verifies error when no API key
func TestAnthropicAdapterCallWithoutKey(t *testing.T) {
	adapter := &AnthropicAdapter{
		BaseURL: "https://api.anthropic.com",
		APIKey:  "",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"claude-3-sonnet","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Error("Expected error when API key is empty")
	}
	if err.Error() != "anthropic provider is not configured with an API key" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

// TestAnthropicAdapterTransformResponse verifies Anthropic to OpenAI response transformation
func TestAnthropicAdapterTransformResponse(t *testing.T) {
	adapter := &AnthropicAdapter{}

	anthropicResp := []byte(`{
		"id": "msg-123",
		"type": "message",
		"role": "assistant",
		"model": "claude-3-sonnet",
		"content": [
			{"type": "text", "text": "Hello! How can I help?"}
		],
		"usage": {
			"input_tokens": 10,
			"cache_read_input_tokens": 6,
			"cache_creation_input_tokens": 4,
			"output_tokens": 20
		}
	}`)

	result, err := adapter.TransformResponse(anthropicResp)
	if err != nil {
		t.Fatalf("TransformResponse failed: %v", err)
	}

	var openaiResp map[string]interface{}
	if err := json.Unmarshal(result, &openaiResp); err != nil {
		t.Fatalf("Failed to parse transformed response: %v", err)
	}

	// Verify OpenAI format structure
	if openaiResp["id"] != "msg-123" {
		t.Errorf("Expected id='msg-123'")
	}
	if openaiResp["object"] != "chat.completion" {
		t.Errorf("Expected object='chat.completion'")
	}
	if openaiResp["model"] != "claude-3-sonnet" {
		t.Errorf("Expected model='claude-3-sonnet'")
	}

	// Verify choices
	choices, ok := openaiResp["choices"].([]interface{})
	if !ok || len(choices) != 1 {
		t.Errorf("Expected 1 choice")
	}

	if len(choices) > 0 {
		choice := choices[0].(map[string]interface{})
		// JSON numbers are float64
		if choice["index"].(float64) != 0 {
			t.Errorf("Expected index=0")
		}

		message := choice["message"].(map[string]interface{})
		if message["role"] != "assistant" {
			t.Errorf("Expected message.role='assistant'")
		}
		if message["content"] != "Hello! How can I help?" {
			t.Errorf("Expected message.content='Hello! How can I help?'")
		}
		if choice["finish_reason"] != "stop" {
			t.Errorf("Expected finish_reason='stop'")
		}
	}

	// Verify usage
	usage := openaiResp["usage"].(map[string]interface{})
	if usage["prompt_tokens"].(float64) != 20 {
		t.Errorf("Expected prompt_tokens=20")
	}
	if usage["completion_tokens"].(float64) != 20 {
		t.Errorf("Expected completion_tokens=20")
	}
	if usage["total_tokens"].(float64) != 40 {
		t.Errorf("Expected total_tokens=40")
	}
	if usage["cache_read_input_tokens"].(float64) != 6 {
		t.Errorf("Expected cache_read_input_tokens=6")
	}
	if usage["cache_creation_input_tokens"].(float64) != 4 {
		t.Errorf("Expected cache_creation_input_tokens=4")
	}
	details := usage["prompt_tokens_details"].(map[string]interface{})
	if details["cached_tokens"].(float64) != 6 || details["cache_creation_input_tokens"].(float64) != 4 {
		t.Errorf("Unexpected prompt token details: %#v", details)
	}
}

// TestGetAdapter verifies adapter lookup by name
func TestGetAdapter(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		expectedName string
	}{
		{"openai", "openai", "openai"},
		{"anthropic", "anthropic", "anthropic"},
		{"unknown_is_not_silently_openai", "unknown", ""},
		{"empty_is_not_silently_openai", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := GetAdapter(tt.providerType)
			if tt.expectedName == "" {
				if adapter != nil {
					t.Fatalf("provider %q unexpectedly selected %s", tt.providerType, adapter.Name())
				}
				return
			}
			if adapter.Name() != tt.expectedName {
				t.Errorf("Expected adapter name='%s', got '%s'", tt.expectedName, adapter.Name())
			}
		})
	}
}

// TestGetAdapterWithConfig verifies adapter with custom configuration
func TestGetAdapterWithConfig(t *testing.T) {
	config := ProviderConfig{
		BaseURL: "https://custom.api.example.com",
		APIKey:  "custom-key",
	}

	tests := []struct {
		name         string
		providerType string
	}{
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"unknown_is_not_silently_openai", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := GetAdapterWithConfig(tt.providerType, config)
			if tt.providerType == "unknown" {
				if adapter != nil {
					t.Fatalf("unknown provider unexpectedly selected %s", adapter.Name())
				}
				return
			}

			// Verify configuration is applied
			switch a := adapter.(type) {
			case *OpenAIAdapter:
				if a.BaseURL != config.BaseURL {
					t.Errorf("Expected BaseURL='%s', got '%s'", config.BaseURL, a.BaseURL)
				}
				if a.APIKey != config.APIKey {
					t.Errorf("Expected APIKey='%s', got '%s'", config.APIKey, a.APIKey)
				}
			case *AnthropicAdapter:
				if a.BaseURL != config.BaseURL {
					t.Errorf("Expected BaseURL='%s', got '%s'", config.BaseURL, a.BaseURL)
				}
				if a.APIKey != config.APIKey {
					t.Errorf("Expected APIKey='%s', got '%s'", config.APIKey, a.APIKey)
				}
			}
		})
	}
}

// TestProviderCallHTTPError verifies provider call handles HTTP errors
func TestProviderCallHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": {"message": "internal server error"}}`))
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Fatal("Expected UpstreamHTTPError for 500 response, got nil")
	}

	// Check that error is UpstreamHTTPError
	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil {
		t.Fatalf("Expected UpstreamHTTPError, got: %v", err)
	}

	// Verify error details
	if upstreamErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected StatusCode=500, got %d", upstreamErr.StatusCode)
	}
	if upstreamErr.Message != "internal server error" {
		t.Errorf("Expected Message='internal server error', got '%s'", upstreamErr.Message)
	}
}

// TestProviderCallHTTPError400 verifies provider call handles 4xx errors
func TestProviderCallHTTPError400(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": {"message": "invalid request: model not found"}}`))
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Fatal("Expected UpstreamHTTPError for 400 response, got nil")
	}

	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil {
		t.Fatalf("Expected UpstreamHTTPError, got: %v", err)
	}

	if upstreamErr.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected StatusCode=400, got %d", upstreamErr.StatusCode)
	}
	if upstreamErr.Message != "invalid request: model not found" {
		t.Errorf("Expected Message='invalid request: model not found', got '%s'", upstreamErr.Message)
	}
}

// TestProviderCallHTTPErrorWithoutMessage verifies provider call handles errors without JSON message
func TestProviderCallHTTPErrorWithoutMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service temporarily unavailable"))
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Fatal("Expected UpstreamHTTPError for 503 response, got nil")
	}

	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil {
		t.Fatalf("Expected UpstreamHTTPError, got: %v", err)
	}

	if upstreamErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected StatusCode=503, got %d", upstreamErr.StatusCode)
	}
	// Message should be the raw body since it's not JSON
	if upstreamErr.Message != "service temporarily unavailable" {
		t.Errorf("Expected Message='service temporarily unavailable', got '%s'", upstreamErr.Message)
	}
}

// TestIsUpstreamHTTPError verifies error type checking
func TestIsUpstreamHTTPError(t *testing.T) {
	upstreamErr := &UpstreamHTTPError{
		StatusCode: 500,
		Body:       []byte(`{"error": "test"}`),
		Message:    "test error",
	}

	if !IsUpstreamHTTPError(upstreamErr) {
		t.Error("Expected IsUpstreamHTTPError to return true")
	}

	// Test with non-UpstreamHTTPError
	regularErr := errors.New("regular error")
	if IsUpstreamHTTPError(regularErr) {
		t.Error("Expected IsUpstreamHTTPError to return false for regular error")
	}
}

// TestProviderCallNetworkError verifies provider call handles network errors
func TestProviderCallNetworkError(t *testing.T) {
	adapter := &OpenAIAdapter{
		BaseURL: "http://invalid-host-that-does-not-exist",
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Error("Expected network error for invalid host")
	}
}

// TestProviderCallContextCancel verifies provider call respects context cancellation
func TestProviderCallContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response - check if context is done
		ctx := r.Context()
		select {
		case <-ctx.Done():
			return
		default:
		}
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	payload := []byte(`{"model":"gpt-4","messages":[]}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Error("Expected context canceled error")
	}
}

// TestOpenAIAdapterEmbeddingsEndpoint verifies OpenAI adapter routes to correct endpoint for embeddings
func TestOpenAIAdapterEmbeddingsEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request path is /v1/embeddings, not /v1/chat/completions
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("Expected path /v1/embeddings, got %s", r.URL.Path)
		}

		// Return mock embeddings response
		resp := map[string]interface{}{
			"object": "list",
			"data": []interface{}{
				map[string]interface{}{
					"object":    "embedding",
					"index":     0,
					"embedding": []float64{0.1, 0.2, 0.3},
				},
			},
			"model": "text-embedding-ada-002",
			"usage": map[string]interface{}{
				"prompt_tokens": 10,
				"total_tokens":  10,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{
		BaseURL: server.URL,
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"text-embedding-ada-002","input":"Hello"}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "embeddings"}

	resp, err := adapter.Call(ctx, envelope, payload)
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if parsed["object"] != "list" {
		t.Errorf("Expected object='list'")
	}
}

// TestAnthropicAdapterUnsupportedEndpoint verifies Anthropic rejects embeddings requests
func TestAnthropicAdapterUnsupportedEndpoint(t *testing.T) {
	adapter := &AnthropicAdapter{
		BaseURL: "https://api.anthropic.com",
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"claude-3","input":"Hello"}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "embeddings"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Error("Expected error for unsupported embeddings endpoint")
	}
	// Check that error is properly wrapped with ErrEndpointNotSupported
	if err != nil && !IsEndpointNotSupported(err) {
		t.Errorf("Expected ErrEndpointNotSupported error, got: %v", err)
	}
}

// TestOpenAIAdapterUnsupportedEndpoint verifies OpenAI rejects unknown endpoint types
func TestOpenAIAdapterUnsupportedEndpoint(t *testing.T) {
	adapter := &OpenAIAdapter{
		BaseURL: "https://api.openai.com",
		APIKey:  "test-key",
	}

	ctx := context.Background()
	payload := []byte(`{"model":"gpt-4","input":"Hello"}`)
	envelope := &modelrouter.RequestEnvelope{EndpointType: "unknown"}

	_, err := adapter.Call(ctx, envelope, payload)
	if err == nil {
		t.Error("Expected error for unsupported endpoint type")
	}
	// Check that error is properly wrapped with ErrEndpointNotSupported
	if err != nil && !IsEndpointNotSupported(err) {
		t.Errorf("Expected ErrEndpointNotSupported error, got: %v", err)
	}
}

func TestIdempotencyHeaderRequiresExplicitVerifiedCapability(t *testing.T) {
	tests := []struct {
		name string
		caps modelrouter.ProtocolCapabilities
		want string
	}{
		{name: "verified", caps: modelrouter.ProtocolCapabilities{Explicit: true, Verified: true, Idempotent: true}, want: "retry_safe"},
		{name: "unverified", caps: modelrouter.ProtocolCapabilities{Explicit: true, Idempotent: true}},
		{name: "unsupported", caps: modelrouter.ProtocolCapabilities{Explicit: true, Verified: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://upstream.example/v1/chat/completions", nil)
			setVerifiedIdempotencyHeader(req, &modelrouter.RequestEnvelope{ClientRetryID: "retry_safe", ProtocolCapabilities: tt.caps})
			if got := req.Header.Get("Idempotency-Key"); got != tt.want {
				t.Fatalf("Idempotency-Key=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestAnthropicChatConversionPreservesCacheControlBlock(t *testing.T) {
	body, _, err := transformOpenAIChatToAnthropic(nil, []byte("{\"model\":\"claude\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hello\",\"cache_control\":{\"type\":\"ephemeral\"}}]}]}"))
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	messages := request["messages"].([]any)
	content := messages[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if content["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Fatalf("cache_control dropped from Anthropic request: %s", body)
	}
}

// anthropicSystemText 取转换后 system 的文本：开启提示缓存时 system 是带断点的文本块数组。
func anthropicSystemText(value any) any {
	if blocks, ok := value.([]any); ok && len(blocks) == 1 {
		if block, ok := blocks[0].(map[string]any); ok && block["type"] == "text" {
			return block["text"]
		}
	}
	return value
}

// anthropicMessageText 取单个文本块消息的文本：最后一条消息会被打上缓存断点而变成块数组。
func anthropicMessageText(value any) any {
	if blocks, ok := value.([]any); ok && len(blocks) == 1 {
		if block, ok := blocks[0].(map[string]any); ok && block["type"] == "text" {
			return block["text"]
		}
	}
	return value
}
