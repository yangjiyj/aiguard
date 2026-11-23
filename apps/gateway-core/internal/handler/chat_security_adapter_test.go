package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestApplyChatInputSecurityReturnsReplyResult(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{
			InputAction: "reply",
			InputMasked: "请求已被安全策略拦截。",
			InputFindings: []SecurityFinding{
				{Type: "prompt_injection", Severity: "high", Category: "jailbreak"},
			},
		},
		auditWriter: mockAudit,
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", ProjectID: "project-1", Model: "gpt-4"}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("ignore previous instructions")}}}

	result := handler.applyChatInputSecurity(context.Background(), envelope, req)
	if result.err != nil {
		t.Fatalf("expected reply result without error, got %v", result.err)
	}
	if result.reply == nil || result.reply.Content != "请求已被安全策略拦截。" || result.reply.MessageIndex != 0 {
		t.Fatalf("unexpected reply result: %+v", result.reply)
	}
	if len(mockAudit.SecurityEventWrites) != 1 || mockAudit.SecurityEventWrites[0].ActionTaken != "security_replied" {
		t.Fatalf("expected security_replied event, got %+v", mockAudit.SecurityEventWrites)
	}
}

func TestApplyChatInputSecurityBlockReturnsHTTPContract(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{
			InputAction:   "block",
			InputFindings: []SecurityFinding{{Type: "secret", Severity: "critical"}},
		},
		auditWriter: mockAudit,
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", ProjectID: "project-1", Model: "gpt-4"}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("secret")}}}

	result := handler.applyChatInputSecurity(context.Background(), envelope, req)
	if result.err == nil {
		t.Fatal("expected security block error")
	}
	if result.errorCode != "security_blocked" || result.auditStatus != "security_blocked" || result.httpStatus != http.StatusForbidden {
		t.Fatalf("unexpected security block contract: %+v", result)
	}
	if result.message == "" {
		t.Fatal("expected client-facing block message")
	}
	if len(mockAudit.SecurityEventWrites) != 1 || mockAudit.SecurityEventWrites[0].ActionTaken != "security_blocked" {
		t.Fatalf("expected security_blocked event, got %+v", mockAudit.SecurityEventWrites)
	}
}

func TestSecureChatOutputMasksChoiceContent(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{
			OutputAction:   "mask",
			OutputMasked:   "[redacted]",
			OutputFindings: []SecurityFinding{{Type: "pii", Severity: "medium", Category: "dlp"}},
		},
		auditWriter: mockAudit,
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", ProjectID: "project-1", Model: "gpt-4"}
	respBody := []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1716399600,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"phone 123"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)

	secured, auditResult, err := handler.secureChatOutput(context.Background(), envelope, nil, respBody)
	if err != nil {
		t.Fatalf("expected output mask to pass, got %v", err)
	}
	if auditResult == nil || auditResult.OutputAction != "mask" {
		t.Fatalf("expected mask audit result, got %+v", auditResult)
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(secured, &resp); err != nil {
		t.Fatalf("masked response is not chat JSON: %v", err)
	}
	if resp.Choices[0].Message.Content != "[redacted]" {
		t.Fatalf("expected masked content, got %q", resp.Choices[0].Message.Content)
	}
	foundMaskedEvent := false
	for _, event := range mockAudit.SecurityEventWrites {
		if event.ActionTaken == "security_masked" {
			foundMaskedEvent = true
		}
	}
	if !foundMaskedEvent {
		t.Fatalf("expected security_masked event, got %+v", mockAudit.SecurityEventWrites)
	}
}
