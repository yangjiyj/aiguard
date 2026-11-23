package handler

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 检测异常一律放行并记录（2026-09-23 客户现场定案）：控制台没有任何把"检测失败"
// 配置成阻断的入口，只有控制台里显式配置为阻断的策略可以中断业务。
// GUARDRAIL_FAILURE_MODE / guardrail_failure_mode 不再生效，事件统一标注 failure_mode=open。

func newFailModeEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{
		RequestID: "req-failmode",
		TenantID:  "tenant-1",
		Model:     "glm-5",
	}
}

func TestApplyInputSecurityConfiguredFailCloseStillAllowsOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "close"},
		securityClient: &MockSecurityChecker{InputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	req := &ChatCompletionRequest{
		Model:    "glm-5",
		Messages: []Message{{Role: "user", Content: jsonQuote("hello")}},
	}
	_, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req)
	if err != nil {
		t.Fatalf("检测异常必须放行，got %v", err)
	}
	found := false
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_check_failed" && strings.Contains(ev.Summary, "failure_mode=open") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应记录 security_check_failed 事件并标注 failure_mode=open，got %#v", audit.SecurityEventWrites)
	}
}

func TestApplyInputSecurityFailOpenAllowsOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "open"},
		securityClient: &MockSecurityChecker{InputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	req := &ChatCompletionRequest{
		Model:    "glm-5",
		Messages: []Message{{Role: "user", Content: jsonQuote("hello")}},
	}
	_, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req)
	if err != nil {
		t.Fatalf("open 模式下引擎报错应放行，got err=%v", err)
	}
	if len(audit.SecurityEventWrites) == 0 {
		t.Fatal("open 模式仍应记录 security_check_failed 事件")
	}
}

func TestApplyOutputSecurityConfiguredFailCloseStillAllowsOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "close"},
		securityClient: &MockSecurityChecker{OutputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	respBody := mustMarshalChatResponse(t, ChatCompletionResponse{
		ID:     "chatcmpl-failmode",
		Object: "chat.completion",
		Model:  "glm-5",
		Choices: []Choice{{
			Index:   0,
			Message: ChoiceMessage{Role: "assistant", Content: "some output text"},
		}},
	})
	_, _, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, respBody)
	if err != nil {
		t.Fatalf("输出检测异常必须放行，got %v", err)
	}
}

func TestApplyOutputSecurityFailOpenAllowsOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "open"},
		securityClient: &MockSecurityChecker{OutputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	respBody := mustMarshalChatResponse(t, ChatCompletionResponse{
		ID:     "chatcmpl-failmode",
		Object: "chat.completion",
		Model:  "glm-5",
		Choices: []Choice{{
			Index:   0,
			Message: ChoiceMessage{Role: "assistant", Content: "some output text"},
		}},
	})
	_, _, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, respBody)
	if err != nil {
		t.Fatalf("open 模式下应放行，got err=%v", err)
	}
}

func TestApplyOutputSecurityAuditOnlyOverridesFailCloseOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{SecurityAuditOnly: true, GuardrailFailureMode: "close"},
		securityClient: &MockSecurityChecker{OutputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	respBody := mustMarshalChatResponse(t, ChatCompletionResponse{
		ID: "chatcmpl-audit-failmode", Object: "chat.completion", Model: "glm-5",
		Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: "some output text"}}},
	})

	secured, result, err := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, respBody)
	if err != nil {
		t.Fatalf("audit-only must not fail-close output engine errors: %v", err)
	}
	if string(secured) != string(respBody) {
		t.Fatalf("audit-only changed output: got=%s want=%s", secured, respBody)
	}
	if result == nil || result.OutputAction != "audit" {
		t.Fatalf("audit-only result=%+v", result)
	}
	if !hasSecurityEvent(audit, "security_output_check_failed") {
		t.Fatalf("missing output check failure audit: %+v", audit.SecurityEventWrites)
	}
}

// TestEmbeddingsApplyInputSecurityFailCloseRejectsOnEngineError 覆盖 embeddings 入口的 fail-close。
func TestEmbeddingsApplyInputSecurityConfiguredFailCloseStillAllowsOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &EmbeddingsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "close"},
		securityClient: &MockSecurityChecker{InputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	req := &EmbeddingsRequest{
		Model: "text-embedding-3",
		Input: "embed this",
	}
	err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req)
	if err != nil {
		t.Fatalf("embeddings 检测异常必须放行，got %v", err)
	}
}

func TestEmbeddingsApplyInputSecurityFailOpenAllowsOnEngineError(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &EmbeddingsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "open"},
		securityClient: &MockSecurityChecker{InputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	req := &EmbeddingsRequest{
		Model: "text-embedding-3",
		Input: "embed this",
	}
	err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req)
	if err != nil {
		t.Fatalf("open 模式下 embeddings 应放行，got err=%v", err)
	}
}

func TestApplyInputSecurityFailOpenRecordsOnePipelineEventPerRequest(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{GuardrailFailureMode: "open"},
		securityClient: &MockSecurityChecker{InputError: errors.New("engine down")},
		auditWriter:    audit,
	}
	req := &ChatCompletionRequest{
		Model: "glm-5",
		Messages: []Message{
			{Role: "system", Content: jsonQuote("system")},
			{Role: "user", Content: jsonQuote("first")},
			{Role: "assistant", Content: jsonQuote("second")},
			{Role: "user", Content: jsonQuote("third")},
		},
	}
	if _, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req); err != nil {
		t.Fatalf("open mode should allow request: %v", err)
	}
	count := 0
	for _, event := range audit.SecurityEventWrites {
		if event.ActionTaken == "security_check_failed" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("security_check_failed events=%d, want one request-level pipeline event; writes=%#v", count, audit.SecurityEventWrites)
	}
}

func TestGuardrailFailureModeIsAlwaysOpen(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{name: "auto enforce", cfg: &config.Config{GuardrailFailureMode: "auto", OutputSecurityMode: "stream_enforce"}, want: "open"},
		{name: "auto strict", cfg: &config.Config{GuardrailFailureMode: "auto", OutputSecurityMode: "strict_buffered"}, want: "open"},
		{name: "auto audit", cfg: &config.Config{GuardrailFailureMode: "auto", OutputSecurityMode: "stream_audit"}, want: "open"},
		{name: "explicit close", cfg: &config.Config{GuardrailFailureMode: "close", OutputSecurityMode: "stream_enforce"}, want: "open"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolvedGuardrailFailureMode(context.Background(), tc.cfg, nil); got != tc.want {
				t.Fatalf("mode=%q want=%q", got, tc.want)
			}
		})
	}
}
