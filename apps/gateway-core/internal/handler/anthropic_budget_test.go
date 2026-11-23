package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Anthropic 原生 /v1/messages：预算断流的 429 同时要让 Anthropic SDK 能识别（type=error, rate_limit_error）
// 并且保留 budget_exhausted 业务码与中文提示。
func TestFlushNativeMessagesPreflightErrorKeepsBudgetExhaustedCode(t *testing.T) {
	buffered := newNativePreflightWriter()
	writeErrorResponseWithStatus(buffered, budgetExhaustedCode, "本月部门预算已用完（研发部，已用 ¥5,000.00 / ¥5,000.00），11 月 1 日自动恢复，如需追加请联系管理员", "req-1", http.StatusTooManyRequests)
	buffered.Header().Set("Retry-After", "86400")
	recorder := httptest.NewRecorder()
	flushNativeMessagesPreflightError(recorder, buffered, "req-1")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", recorder.Code)
	}
	var body struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Type != "error" || body.Error.Type != "rate_limit_error" || body.Error.Code != budgetExhaustedCode ||
		body.Error.Message == "" || body.RequestID != "req-1" {
		t.Fatalf("anthropic body = %s", recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") != "86400" {
		t.Fatalf("Retry-After lost: %v", recorder.Header())
	}
}

// 普通（非业务码）错误保持原有形状，不多出 code 字段。
func TestFlushNativeMessagesPreflightErrorOtherErrorsKeepLegacyShape(t *testing.T) {
	buffered := newNativePreflightWriter()
	writeErrorResponseWithStatus(buffered, "invalid_request", "bad", "req-2", http.StatusBadRequest)
	recorder := httptest.NewRecorder()
	flushNativeMessagesPreflightError(recorder, buffered, "req-2")
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	errBody, _ := body["error"].(map[string]any)
	if _, has := errBody["code"]; has {
		t.Fatalf("legacy anthropic error shape must not gain a code field: %s", recorder.Body.String())
	}
}
