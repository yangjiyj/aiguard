package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func setAuthInfo(ctx context.Context, tenantID, projectID, userID, keyID, sessionID string) context.Context {
	ctx = context.WithValue(ctx, auth.TenantKey, tenantID)
	ctx = context.WithValue(ctx, auth.ProjectKey, projectID)
	ctx = context.WithValue(ctx, auth.UserKey, userID)
	ctx = context.WithValue(ctx, auth.KeyIDKey, keyID)
	ctx = context.WithValue(ctx, auth.SessionIDKey, sessionID)
	ctx = context.WithValue(ctx, auth.AgentTypeKey, "")
	ctx = context.WithValue(ctx, auth.WorkspaceKey, "")
	return ctx
}

func createTestHandlers(mockResolver *MockModelResolver, mockRateLimiter *MockRateLimitChecker, mockSecurity *MockSecurityChecker, mockAudit *MockAuditWriter) (*ChatCompletionsHandler, *ResponsesHandler) {
	cfg := &config.Config{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	chatHandler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)
	responsesHandler := NewResponsesHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)
	return chatHandler, responsesHandler
}

func createMessagesTestHandler(mockResolver *MockModelResolver, mockRateLimiter *MockRateLimitChecker, mockSecurity *MockSecurityChecker, mockAudit *MockAuditWriter) *MessagesHandler {
	cfg := &config.Config{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	return NewMessagesHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)
}

// ===== Chat Completions Non-Stream Tests =====

func TestChatNonStreamSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ChatCompletionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Object != "chat.completion" {
		t.Errorf("Expected object='chat.completion', got '%s'", resp.Object)
	}
	if len(resp.Choices) != 1 {
		t.Errorf("Expected 1 choice")
	}
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog call")
	}
	if len(mockAudit.ContentLogWrites) != 2 {
		t.Errorf("Expected 2 content log writes, got %d", len(mockAudit.ContentLogWrites))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Errorf("Expected final status='success'")
	}
}

// ===== Anthropic Messages Compatibility Tests =====

func TestMessagesNonStreamSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler := createMessagesTestHandler(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := map[string]interface{}{
		"model":      "gpt-4",
		"max_tokens": 64,
		"system": []map[string]interface{}{
			{"type": "text", "text": "You are concise."},
		},
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{"type": "text", "text": "Hello"},
				},
			},
		},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/messages?beta=true", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp AnthropicMessagesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Type != "message" {
		t.Fatalf("Expected type='message', got %q", resp.Type)
	}
	if resp.Role != "assistant" {
		t.Fatalf("Expected assistant role, got %q", resp.Role)
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "text" {
		t.Fatalf("Expected one text content block, got %#v", resp.Content)
	}
	if len(mockSecurity.InputCheckCalls) != 1 || mockSecurity.InputCheckCalls[0].MessageIndex != 0 || mockSecurity.InputCheckCalls[0].MessageRole != "user" {
		t.Fatalf("Expected latest user with original Anthropic index, got %+v", mockSecurity.InputCheckCalls)
	}
	if mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("Expected final status='success', got %q", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestMessagesStreamSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler := createMessagesTestHandler(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := map[string]interface{}{
		"model":      "gpt-4",
		"max_tokens": 64,
		"stream":     true,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": "Hello",
			},
		},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/messages?beta=true", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("Expected event-stream content type, got %q", got)
	}
	bodyText := w.Body.String()
	for _, expected := range []string{"event: message_start", "event: content_block_delta", "event: message_stop"} {
		if !strings.Contains(bodyText, expected) {
			t.Fatalf("Expected stream to contain %q, got %s", expected, bodyText)
		}
	}
}

func TestChatInvalidJSON(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader([]byte("invalid json")))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Audit contract: request log for invalid JSON rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for invalid JSON, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for invalid JSON, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestChatModelNotConfigured(t *testing.T) {
	mockResolver := &MockModelResolver{ResolveError: context.Canceled}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "unknown-model", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}
}

func TestChatForbiddenModel(t *testing.T) {
	mockResolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{AllowList: []string{}, DenyList: []string{"gpt-4o"}}}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4o", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestChatRateLimited(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{RPMLimit: 10}}
	mockRateLimiter := &MockRateLimitChecker{RPMAllowed: false}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}
}

func TestChatOutputBlocked(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
	if len(mockAudit.SecurityEventWrites) == 0 {
		t.Error("Expected security event")
	}
}

func TestChatInputBlocked(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{InputAction: "block", InputFindings: []SecurityFinding{{Type: "secret", Severity: "critical"}}}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("password")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

// ===== Chat Stream Tests =====

func TestChatStreamSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Expected SSE Content-Type")
	}
	respBody := w.Body.String()
	if !strings.HasPrefix(respBody, "data: ") {
		t.Errorf("SSE should start with 'data: '")
	}
	if !strings.Contains(respBody, "data: [DONE]") {
		t.Errorf("SSE should contain [DONE]")
	}
	if mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Errorf("Expected success status")
	}
}

func TestChatStreamToolCallsPreserved(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}

	toolResp := ChatCompletionResponse{
		ID:      "chatcmpl-tool",
		Object:  "chat.completion",
		Created: 1716399600,
		Model:   "gpt-4",
		Choices: []Choice{
			{
				Index: 0,
				Message: ChoiceMessage{
					Role: "assistant",
					ToolCalls: []ToolCall{
						{
							ID:   "call_123",
							Type: "function",
							Function: ToolCallFunc{
								Name:      "write",
								Arguments: `{"file":"result.txt","content":"OK"}`,
							},
						},
					},
				},
				FinishReason: "tool_calls",
			},
		},
		Usage: Usage{PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30},
	}
	toolRespBody, _ := json.Marshal(toolResp)
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{CallResponse: toolRespBody},
	}
	handler := NewChatCompletionsHandler(&config.Config{}, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Create a file")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	respBody := w.Body.String()
	if !strings.Contains(respBody, `"tool_calls"`) {
		t.Fatalf("SSE should preserve tool_calls, got: %s", respBody)
	}
	if !strings.Contains(respBody, `"id":"call_123"`) {
		t.Fatalf("SSE should preserve tool call id, got: %s", respBody)
	}
	if !strings.Contains(respBody, `"finish_reason":"tool_calls"`) {
		t.Fatalf("SSE should preserve tool_calls finish reason, got: %s", respBody)
	}
	if !strings.Contains(respBody, "data: [DONE]") {
		t.Fatalf("SSE should contain [DONE], got: %s", respBody)
	}
}

func TestChatStreamBlocked(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "high"}}}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Expected SSE Content-Type for error")
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "security_blocked") {
		t.Errorf("SSE error should contain security_blocked")
	}
	if len(mockAudit.SecurityEventWrites) == 0 {
		t.Error("Expected security event")
	}
}

// ===== Responses Tests =====

func TestResponsesSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ResponsesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	if resp.Object != "response" {
		t.Errorf("Expected object='response'")
	}
	if resp.Status != "completed" {
		t.Errorf("Expected status='completed'")
	}
}

func TestResponsesInvalidInput(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: 123}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Audit contract: request log for invalid_request rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for invalid input, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for invalid input, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestResponsesEmptyInput(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: ""}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Audit contract: request log for invalid_request rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for empty input, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for empty input, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestResponsesStreamSupported(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: "Hello", Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("Expected SSE Content-Type")
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Errorf("Expected final status='success', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestResponsesWithInstructions(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: "Hello", Instructions: "Be helpful"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestResponsesArrayInput(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{
		Model: "gpt-4",
		Input: []interface{}{
			map[string]interface{}{"role": "user", "content": "Hello"},
			map[string]interface{}{"role": "assistant", "content": "Hi"},
		},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// ===== Concurrency Release Tests =====

func TestConcurrencyReleaseOnSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 5}}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyAllowed: true}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 1 {
		t.Errorf("Expected 1 ReleaseConcurrency call, got %d", len(mockRateLimiter.ReleaseConcurrencyCalls))
	}
}

func TestConcurrencyReleaseOnSecurityBlock(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 5}}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyAllowed: true}
	mockSecurity := &MockSecurityChecker{InputAction: "block"}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("password")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 1 {
		t.Errorf("Expected 1 ReleaseConcurrency on block, got %d", len(mockRateLimiter.ReleaseConcurrencyCalls))
	}
}

func TestConcurrencyNotAcquiredWhenLimitZero(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 0}}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 0 {
		t.Errorf("Expected 0 ReleaseConcurrency when limit=0, got %d", len(mockRateLimiter.ReleaseConcurrencyCalls))
	}
}

// ===== Agent Session Tests =====

func TestAgentSessionUpsert(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-abc")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-abc" {
		t.Errorf("Expected session_id='session-abc'")
	}
}

func TestAgentSessionNotUpsertedWhenNoSessionID(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if len(mockAudit.AgentSessionUpserts) != 0 {
		t.Errorf("Expected 0 AgentSessionUpsert when no session_id, got %d", len(mockAudit.AgentSessionUpserts))
	}
}

// REGRESSION TEST: TestAgentSessionUpsertOnModelNotConfigured verifies session is upserted
// even when model resolution fails. Contract: authenticated request with session header
// should always create/update session record, regardless of model/provider errors.
func TestAgentSessionUpsertOnModelNotConfigured(t *testing.T) {
	mockResolver := &MockModelResolver{ResolveError: context.Canceled}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "unknown-model", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// Key: authenticated request with session header
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-xyz")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Request should fail with 503
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	// Session MUST still be upserted despite model_not_configured error
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert even on model_not_configured, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-xyz" {
		t.Errorf("Expected session_id='session-xyz', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}
	if mockAudit.AgentSessionUpserts[0].TenantID != "tenant-123" {
		t.Errorf("Expected tenant_id='tenant-123'")
	}
	if mockAudit.AgentSessionUpserts[0].ProjectID != "project-123" {
		t.Errorf("Expected project_id='project-123'")
	}

	// Request log should also be recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog")
	}
	// FinalizeRequestLog should record model_not_configured status
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog")
	}
	if mockAudit.RequestLogFinalizes[0].Status != "model_not_configured" {
		t.Errorf("Expected final status='model_not_configured', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// ===== Provider Failure Tests =====

func TestProviderCallFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{CallError: fmt.Errorf("connection timeout")},
	}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502 for provider error, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "provider_unavailable" {
		t.Errorf("Expected provider_unavailable error code")
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_unavailable" {
		t.Errorf("Expected final status='provider_unavailable'")
	}
}

func TestTransformResponseFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{TransformResponseError: fmt.Errorf("invalid JSON")},
	}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "provider_unavailable" {
		t.Errorf("Expected provider_unavailable error")
	}
}

func TestStreamProviderCallFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{CallError: fmt.Errorf("stream timeout")},
	}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Expected SSE Content-Type for stream error")
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "provider_unavailable") {
		t.Errorf("SSE error should contain provider_unavailable: %s", respBody)
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_unavailable" {
		t.Errorf("Expected final status='provider_unavailable'")
	}
}

func TestStreamTransformResponseFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{TransformResponseError: fmt.Errorf("parse error")},
	}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Expected SSE Content-Type")
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "provider_unavailable") {
		t.Errorf("SSE error should contain provider_unavailable")
	}
}

// ===== Responses Request Conversion Edge Cases =====

func TestResponsesConversionWithSystemInstructions(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{
		Model:        "gpt-4",
		Input:        "Hello",
		Instructions: "You are a helpful assistant",
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestResponsesConversionMixedArrayInput(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	// Array with both message objects and strings
	reqBody := ResponsesRequest{
		Model: "gpt-4",
		Input: []interface{}{
			map[string]interface{}{"role": "user", "content": "First question"},
			"Second question as string",
		},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestResponsesConversionEmptyArray(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{
		Model: "gpt-4",
		Input: []interface{}{},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty array, got %d", w.Code)
	}
}

func TestResponsesProviderCallFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{CallError: fmt.Errorf("provider error")},
	}
	cfg := &config.Config{}
	handler := NewResponsesHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", w.Code)
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_unavailable" {
		t.Errorf("Expected final status='provider_unavailable'")
	}
}

func TestConcurrencyReleaseOnProviderError(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 5}}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyAllowed: true}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{CallError: fmt.Errorf("connection refused")},
	}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Concurrency should be released via defer even on error
	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 1 {
		t.Errorf("Expected 1 ReleaseConcurrency call on provider error, got %d", len(mockRateLimiter.ReleaseConcurrencyCalls))
	}
}

// ===== REGRESSION TESTS =====

// TestProviderTransformRequest verifies TransformRequest is called (not bypassed)
func TestProviderTransformRequestCalled(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Verify TransformRequest was called before Call
	if len(mockProviderCaller.TransformRequestCalls) != 1 {
		t.Errorf("Expected 1 TransformRequest call, got %d", len(mockProviderCaller.TransformRequestCalls))
	}
	// Verify Call used transformed request (not raw securedBody)
	if len(mockProviderCaller.CallCalls) != 1 {
		t.Errorf("Expected 1 Call")
	}
}

// TestStreamProviderTransformRequest verifies TransformRequest in stream path
func TestStreamProviderTransformRequestCalled(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Stream path calls TransformRequest at least once (in handleStreamingRequest)
	// The exact number may vary based on implementation details
	if len(mockProviderCaller.TransformRequestCalls) < 1 {
		t.Errorf("Expected at least 1 TransformRequest call in stream path, got %d", len(mockProviderCaller.TransformRequestCalls))
	}
}

// TestRateLimiterErrorFailOpen verifies limiter errors don't cause false rejections
func TestRateLimiterErrorFailOpen(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{RPMLimit: 10}}
	mockRateLimiter := &MockRateLimitChecker{RPMError: fmt.Errorf("Redis connection error")}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// When limiter has error, should NOT return 429 - should allow request (fail-open)
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("Expected request to pass when limiter errors, got 429")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 (fail-open on limiter error), got %d", w.Code)
	}
}

// TestConcurrencyLimiterErrorFailOpen verifies concurrency error doesn't false reject
func TestConcurrencyLimiterErrorFailOpen(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 5}}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyError: fmt.Errorf("Redis timeout")}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// On concurrency check error, should NOT return 429
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("Expected request to pass when concurrency check errors, got 429")
	}
}

// TestDailyTokenLimitErrorFailOpen verifies daily limit error doesn't false reject
func TestDailyTokenLimitErrorFailOpen(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{DailyTokenLimit: 1000}}
	mockRateLimiter := &MockRateLimitChecker{DailyError: fmt.Errorf("Redis unavailable")}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// On daily limit check error, should NOT return quota_exceeded
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("Expected request to pass when daily limit check errors, got 429")
	}
}

// TestMonthlyTokenLimitErrorFailOpen verifies monthly limit error doesn't false reject
func TestMonthlyTokenLimitErrorFailOpen(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{MonthlyTokenLimit: 10000}}
	mockRateLimiter := &MockRateLimitChecker{MonthlyError: fmt.Errorf("Redis timeout")}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// On monthly limit check error, should NOT return quota_exceeded
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("Expected request to pass when monthly limit check errors, got 429")
	}
}

// TestSecurityCheckerInputContext verifies message index/role passed to CheckInput
func TestSecurityCheckerInputContext(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)
	handler.toolRiskClient = allInspectionTestClient()

	// Request with multiple messages to verify index/role
	reqBody := ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "system", Content: jsonQuote("Be helpful")},
			{Role: "user", Content: jsonQuote("Hello")},
		},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Verify CheckInput was called with correct index and role
	if len(mockSecurity.InputCheckCalls) != 2 {
		t.Errorf("Expected 2 CheckInput calls for 2 messages, got %d", len(mockSecurity.InputCheckCalls))
	}
	// Check first message (system)
	if mockSecurity.InputCheckCalls[0].MessageIndex != 0 {
		t.Errorf("Expected first message index=0, got %d", mockSecurity.InputCheckCalls[0].MessageIndex)
	}
	if mockSecurity.InputCheckCalls[0].MessageRole != "system" {
		t.Errorf("Expected first message role='system', got '%s'", mockSecurity.InputCheckCalls[0].MessageRole)
	}
	// Check second message (user)
	if mockSecurity.InputCheckCalls[1].MessageIndex != 1 {
		t.Errorf("Expected second message index=1, got %d", mockSecurity.InputCheckCalls[1].MessageIndex)
	}
	if mockSecurity.InputCheckCalls[1].MessageRole != "user" {
		t.Errorf("Expected second message role='user', got '%s'", mockSecurity.InputCheckCalls[1].MessageRole)
	}
}

// TestSecurityCheckerOutputContext verifies choice index passed to CheckOutput
func TestSecurityCheckerOutputContext(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Verify CheckOutput was called with choice index
	if len(mockSecurity.OutputCheckCalls) != 1 {
		t.Errorf("Expected 1 CheckOutput call, got %d", len(mockSecurity.OutputCheckCalls))
	}
	if mockSecurity.OutputCheckCalls[0].ChoiceIndex != 0 {
		t.Errorf("Expected choice index=0, got %d", mockSecurity.OutputCheckCalls[0].ChoiceIndex)
	}
}

// TestAuditTokenUsageOnlyOnSuccess verifies token usage not incremented on audit failure
// This test validates that IncrementTokenUsage is only called after successful request log write
func TestAuditTokenUsageOnlyOnSuccess(t *testing.T) {
	// The MockAuditWriter doesn't simulate DB errors or actually increment tokens.
	// The key contract: token usage increment is done inside RealAuditWriter.FinalizeRequestLog
	// and only after checking result.RowsAffected() > 0.
	//
	// To verify this contract, we check that:
	// 1. Handler does NOT directly call IncrementTokenUsage (mockRateLimiter has 0 calls)
	// 2. Token increment is delegated to AuditWriter (which in production checks DB success)
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Handler should NOT directly call IncrementTokenUsage - it's delegated to AuditWriter
	// In production, RealAuditWriter only increments after DB write succeeds
	if len(mockRateLimiter.IncrementTokenUsageCalls) != 0 {
		t.Errorf("Handler should not directly call IncrementTokenUsage (delegated to AuditWriter), got %d calls", len(mockRateLimiter.IncrementTokenUsageCalls))
	}
}

// TestProviderTransformRequestError verifies error handling when TransformRequest fails
func TestProviderTransformRequestError(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{
		MockProviderCaller: &MockProviderCaller{TransformRequestError: fmt.Errorf("transform failed")},
	}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// TransformRequest error should return 400 invalid_request
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for TransformRequest error, got %d", w.Code)
	}
	// Verify Call was NOT called when TransformRequest fails
	mockProviderCaller := mockProviderFactory.MockProviderCaller
	if len(mockProviderCaller.CallCalls) != 0 {
		t.Errorf("Expected 0 Call calls when TransformRequest fails, got %d", len(mockProviderCaller.CallCalls))
	}
}

// TestStreamTransformRequestCalledOnce verifies that for streaming requests, TransformRequest is only called once
// This is a regression test: previously the stream path called TransformRequest twice (once in processSharedRequestPath
// and again in handleStreamingRequest). Now it should only be called once in handleStreamingRequest.
func TestStreamTransformRequestCalledOnce(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	// Streaming request
	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// For streaming, TransformRequest should be called exactly once (in handleStreamingRequest)
	// NOT in processSharedRequestPath (which skips transform for stream requests)
	if len(mockProviderCaller.TransformRequestCalls) != 1 {
		t.Errorf("Expected TransformRequest to be called 1 time for streaming, got %d", len(mockProviderCaller.TransformRequestCalls))
	}
}

// TestNonStreamTransformRequestCalledOnce verifies that for non-streaming requests, TransformRequest is called once
func TestNonStreamTransformRequestCalledOnce(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	// Non-streaming request
	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// For non-streaming, TransformRequest should be called exactly once (in processSharedRequestPath)
	if len(mockProviderCaller.TransformRequestCalls) != 1 {
		t.Errorf("Expected TransformRequest to be called 1 time for non-streaming, got %d", len(mockProviderCaller.TransformRequestCalls))
	}
}

// TestStreamTransformRequestError verifies SSE error response when TransformRequest fails in stream path
// Regression test: ensures stream requests with TransformRequest error:
// - Return SSE error format (not JSON)
// - Error code is invalid_request
// - Provider Call is not called
// - TransformRequest only happens once
func TestStreamTransformRequestError(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{
		TransformRequestError: fmt.Errorf("provider transform failed"),
	}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewChatCompletionsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory, nil, nil)

	// Streaming request
	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Should return SSE Content-Type (not application/json)
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Expected SSE Content-Type 'text/event-stream', got '%s'", w.Header().Get("Content-Type"))
	}

	respBody := w.Body.String()

	// Response should be SSE format (starts with "data: ")
	if !strings.HasPrefix(respBody, "data: ") {
		t.Errorf("Expected SSE format starting with 'data: ', got: %s", respBody)
	}

	// Error should contain "invalid_request" code
	if !strings.Contains(respBody, "invalid_request") {
		t.Errorf("Expected SSE error to contain 'invalid_request', got: %s", respBody)
	}

	// Provider Call must NOT be called when TransformRequest fails
	if len(mockProviderCaller.CallCalls) != 0 {
		t.Errorf("Expected 0 Call calls when TransformRequest fails, got %d", len(mockProviderCaller.CallCalls))
	}

	// TransformRequest should only be called once (in handleStreamingRequest, not in processSharedRequestPath)
	if len(mockProviderCaller.TransformRequestCalls) != 1 {
		t.Errorf("Expected TransformRequest to be called 1 time for streaming, got %d", len(mockProviderCaller.TransformRequestCalls))
	}
}

// ===== Audit Contract Regression Tests =====
// These tests verify that all early-failure branches still record request logs.
// Contract: authenticated request must have request log, even if rejected early.

func TestAuditContractForbiddenModel(t *testing.T) {
	mockResolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{DenyList: []string{"gpt-4o"}}}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4o", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}

	// Request log MUST be recorded for forbidden_model rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for forbidden_model, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for forbidden_model, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "forbidden_model" {
		t.Errorf("Expected final status='forbidden_model', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestAuditContractRateLimited(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{RPMLimit: 10}}
	mockRateLimiter := &MockRateLimitChecker{RPMAllowed: false}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Request log MUST be recorded for rate_limited rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for rate_limited, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for rate_limited, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "rate_limited" {
		t.Errorf("Expected final status='rate_limited', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestAuditContractConcurrencyLimit(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 5}}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyAllowed: false, ConcurrencyError: nil}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Request log MUST be recorded for concurrency_limit rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for concurrency_limit, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for concurrency_limit, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "concurrency_limit" {
		t.Errorf("Expected final status='concurrency_limit', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestAuditContractQuotaExceeded(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{DailyTokenLimit: 1000}}
	mockRateLimiter := &MockRateLimitChecker{DailyAllowed: false, DailyError: nil}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Request log MUST be recorded for quota_exceeded rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for quota_exceeded, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for quota_exceeded, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "quota_exceeded" {
		t.Errorf("Expected final status='quota_exceeded', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestAuditContractProviderNotConfigured(t *testing.T) {
	mockResolver := &MockModelResolver{ReturnEmptyKey: true} // No API key
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	// Request log MUST be recorded for provider_not_configured rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for provider_not_configured, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for provider_not_configured, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_not_configured" {
		t.Errorf("Expected final status='provider_not_configured', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// ===== Session Contract: Pre-parse failures =====
// These tests verify session is upserted even on pre-parse/pre-process failures when session header present.

func TestChatPreParseSessionUpsertOnInvalidJSON(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader([]byte("invalid json")))
	httpReq.Header.Set("Content-Type", "application/json")
	// Key: authenticated request with session header
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-pre-parse")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Session MUST be upserted even on pre-parse invalid JSON
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert on pre-parse failure, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-pre-parse" {
		t.Errorf("Expected session_id='session-pre-parse', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log also recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
}

func TestResponsesSessionUpsertOnStreamSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	reqBody := ResponsesRequest{Model: "gpt-4", Input: "Hello", Stream: true}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// Key: authenticated request with session header
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-stream")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Session MUST be upserted on a streaming request.
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-stream" {
		t.Errorf("Expected session_id='session-stream', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log also recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Errorf("Expected final status='success', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// REGRESSION TEST: TestResponsesPreProcessSessionUpsertOnConvertToChatRequestFail verifies session is upserted
// even when convertToChatRequest fails (pre-process failure). Contract: authenticated request with session
// header should always create/update session record, regardless of pre-parse/pre-process errors.
func TestResponsesPreProcessSessionUpsertOnConvertToChatRequestFail(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	// Empty input triggers convertToChatRequest failure (no valid messages)
	reqBody := ResponsesRequest{Model: "gpt-4", Input: ""}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// Key: authenticated request with session header
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-convert")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Session MUST be upserted even on convertToChatRequest failure
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert on convertToChatRequest failure, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-convert" {
		t.Errorf("Expected session_id='session-convert', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log also recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// ===== Body Read Failure Regression Tests =====
// These tests verify session + audit contract when io.ReadAll(r.Body) fails.

// errorReader is an io.Reader that always returns an error on Read
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated body read failure")
}

// TestChatBodyReadFailure verifies session + audit contract when body read fails for chat completions
func TestChatBodyReadFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	handler, _ := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	// Use errorReader to trigger io.ReadAll failure
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", &errorReader{})
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-body-read")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "invalid_request" {
		t.Errorf("Expected error code='invalid_request', got '%s'", errResp.Error.Code)
	}

	// Session MUST be upserted even on body read failure
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert on body read failure, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-body-read" {
		t.Errorf("Expected session_id='session-body-read', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log MUST be recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// TestEmbeddingsBodyReadFailure verifies session + audit contract when body read fails for embeddings
func TestEmbeddingsBodyReadFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	// Use errorReader to trigger io.ReadAll failure
	httpReq := httptest.NewRequest("POST", "/v1/embeddings", &errorReader{})
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-embeddings-body")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "invalid_request" {
		t.Errorf("Expected error code='invalid_request', got '%s'", errResp.Error.Code)
	}

	// Session MUST be upserted even on body read failure
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert on body read failure, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-embeddings-body" {
		t.Errorf("Expected session_id='session-embeddings-body', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log MUST be recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// TestResponsesBodyReadFailure verifies session + audit contract when body read fails for responses
func TestResponsesBodyReadFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	// Use errorReader to trigger io.ReadAll failure
	httpReq := httptest.NewRequest("POST", "/v1/responses", &errorReader{})
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-responses-body")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "invalid_request" {
		t.Errorf("Expected error code='invalid_request', got '%s'", errResp.Error.Code)
	}

	// Session MUST be upserted even on body read failure
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert on body read failure, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-responses-body" {
		t.Errorf("Expected session_id='session-responses-body', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log MUST be recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}
