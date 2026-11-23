package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestResponsesConvertFunctionToolsAndOutputs(t *testing.T) {
	h := &ResponsesHandler{}
	strict := true
	req := &ResponsesRequest{
		Model: "gpt-5.5",
		Input: []interface{}{
			map[string]interface{}{"type": "message", "role": "user", "content": "run pwd"},
			map[string]interface{}{"type": "function_call", "call_id": "call_1", "name": "shell", "arguments": `{"command":"pwd"}`},
			map[string]interface{}{"type": "function_call_output", "call_id": "call_1", "output": "/workspace"},
		},
		Tools: []ResponsesTool{{
			Type: "function", Name: "shell", Description: "run shell",
			Parameters: json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"}}}`),
			Strict:     &strict,
		}},
		ToolChoice: map[string]interface{}{"type": "function", "name": "shell"},
	}
	got, err := h.convertToChatRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tools) != 1 || got.Tools[0].Function.Name != "shell" {
		t.Fatalf("tools=%+v", got.Tools)
	}
	if got.Tools[0].Function.Strict == nil || !*got.Tools[0].Function.Strict {
		t.Fatalf("strict=%v", got.Tools[0].Function.Strict)
	}
	choice, ok := got.ToolChoice.(map[string]interface{})
	function, nested := choice["function"].(map[string]interface{})
	if !ok || !nested || choice["type"] != "function" || function["name"] != "shell" {
		t.Fatalf("tool_choice=%#v", got.ToolChoice)
	}
	if len(got.Messages) != 3 {
		t.Fatalf("messages=%+v", got.Messages)
	}
	if len(got.Messages[1].ToolCalls) != 1 || got.Messages[1].ToolCalls[0].ID != "call_1" {
		t.Fatalf("assistant function call=%+v", got.Messages[1])
	}
	if got.Messages[2].Role != "tool" || got.Messages[2].ToolCallID != "call_1" || messageText(got.Messages[2].Content) != "/workspace" {
		t.Fatalf("function output=%+v", got.Messages[2])
	}
}

func TestResponsesInputTextBecomesScannableChatText(t *testing.T) {
	req := &ResponsesRequest{
		Model: "gpt-5.5",
		Input: []interface{}{map[string]interface{}{
			"type": "message", "role": "user",
			"content": []interface{}{map[string]interface{}{"type": "input_text", "text": "scan this repo"}},
		}},
	}
	got, err := (&ResponsesHandler{}).convertToChatRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if text := messageText(got.Messages[0].Content); text != "scan this repo" {
		t.Fatalf("messageText=%q raw=%s", text, got.Messages[0].Content)
	}
	if strings.Contains(string(got.Messages[0].Content), `"input_text"`) {
		t.Fatalf("Responses content type was not converted: %s", got.Messages[0].Content)
	}
}

func TestResponsesStreamSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	_, handler := createTestHandlers(mockResolver, mockRateLimiter, mockSecurity, mockAudit)

	body, _ := json.Marshal(ResponsesRequest{Model: "gpt-5.5", Input: "Hello", Stream: true})
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = httpReq.WithContext(setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("Content-Type=%q", got)
	}
	events := parseResponsesSSE(t, w.Body.String())
	types := strings.Join(eventTypes(events), ",")
	if !strings.Contains(types, "response.output_text.delta") || !strings.HasSuffix(types, "response.completed") {
		t.Fatalf("events=%s", types)
	}
	completed := events[len(events)-1]["response"].(map[string]interface{})
	usage := completed["usage"].(map[string]interface{})
	if usage["total_tokens"] != float64(30) {
		t.Fatalf("usage=%v", usage)
	}
	if len(mockAudit.RequestLogFinalizes) != 1 || mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit=%+v", mockAudit.RequestLogFinalizes)
	}
}

func TestTransformChatToolCallToResponsesFunctionCall(t *testing.T) {
	chatBody, _ := json.Marshal(ChatCompletionResponse{
		ID: "chatcmpl_tool", Model: "gpt-5.5",
		Choices: []Choice{{
			Index: 0,
			Message: ChoiceMessage{Role: "assistant", ToolCalls: []ToolCall{{
				ID: "call_1", Type: "function",
				Function: ToolCallFunc{Name: "shell", Arguments: `{"command":"pwd"}`},
			}}},
			FinishReason: "tool_calls",
		}},
		Usage: Usage{PromptTokens: 5, CompletionTokens: 3, TotalTokens: 8},
	})
	got := (&ResponsesHandler{}).transformChatToResponsesResponse(chatBody, "request-1")
	if len(got.Output) != 1 {
		t.Fatalf("output=%+v", got.Output)
	}
	item := got.Output[0]
	if item.Type != "function_call" || item.CallID != "call_1" || item.Name != "shell" || item.Arguments != `{"command":"pwd"}` {
		t.Fatalf("item=%+v", item)
	}
}

func TestResponsesStreamProviderFailureUsesErrorEvents(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := NewResponsesHandler(
		&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{},
		&MockSecurityChecker{}, mockAudit,
		&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallError: fmt.Errorf("provider down")}},
		nil, nil,
	)
	body, _ := json.Marshal(ResponsesRequest{Model: "gpt-5.5", Input: "Hello", Stream: true})
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, req)

	events := parseResponsesSSE(t, w.Body.String())
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" {
		t.Fatalf("events=%s body=%s", got, w.Body.String())
	}
}
