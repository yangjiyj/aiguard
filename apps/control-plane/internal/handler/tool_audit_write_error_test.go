package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// 客户现场：约束违约（SQLSTATE 23514）曾每小时 5897 次，旧实现一律回 400 internal_error，
// 网关当成"可重试的暂时失败"，随会话轮次无限重投。确定性错误必须回可区分的状态，让调用方丢弃。

func decodeErrorEnvelope(t *testing.T, body []byte) (code, message string) {
	t.Helper()
	var envelope struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode error envelope: %v (%s)", err, body)
	}
	return envelope.Error.Code, envelope.Error.Message
}

func TestToolLogWriteConstraintViolationIsRejectedNotRetryable(t *testing.T) {
	buf := captureToolAuditLog(t)
	pgErr := &pgconn.PgError{
		Code: "23514", ConstraintName: "tool_call_logs_execution_fact_check",
		Message: "new row violates check constraint",
		// 现场 DETAIL 带整行数据（用户内容），日志里绝不能出现。
		Detail: "Failing row contains (secret-user-data-should-never-be-logged)",
	}
	response := httptest.NewRecorder()
	respondToolLogWriteError(response, "tenant-reject-1", fmt.Errorf("upsert: %w", pgErr))

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", response.Code)
	}
	if code, _ := decodeErrorEnvelope(t, response.Body.Bytes()); code != "tool_log_rejected" {
		t.Fatalf("error code=%q, want tool_log_rejected", code)
	}
	out := buf.String()
	for _, want := range []string{
		"event=tool_log_write_rejected", "reason=check_violation:tool_call_logs_execution_fact_check",
		"tenant=tenant-reject-1", "action=drop_no_retry",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "secret-user-data") || strings.Contains(out, "Failing row") {
		t.Fatalf("log leaks row content: %q", out)
	}
}

func TestToolLogWriteTransientErrorStaysRetryable(t *testing.T) {
	buf := captureToolAuditLog(t)
	for _, err := range []error{
		errors.New("context deadline exceeded"),
		&pgconn.PgError{Code: "53300", Message: "too many clients already"},
	} {
		response := httptest.NewRecorder()
		respondToolLogWriteError(response, "tenant-transient-1", err)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("transient error status=%d, want 400（响应契约不变，调用方照旧可重试）", response.Code)
		}
		code, message := decodeErrorEnvelope(t, response.Body.Bytes())
		if code != "internal_error" || message != "failed to create tool call log" {
			t.Fatalf("envelope = %q / %q，必须与改造前一致", code, message)
		}
	}
	if !strings.Contains(buf.String(), "event=tool_log_write_failed") {
		t.Fatalf("暂时性失败也应有限频日志，实际: %q", buf.String())
	}
}

func TestToolLogWriteRejectionLogIsRateLimited(t *testing.T) {
	buf := captureToolAuditLog(t)
	pgErr := &pgconn.PgError{Code: "23514", ConstraintName: "tool_call_logs_execution_fact_check"}
	for i := 0; i < 250; i++ {
		respondToolLogWriteError(httptest.NewRecorder(), "tenant-ratelimit-1", pgErr)
	}
	// ratelog.New(100)：首条 + 第 100、200 条，共 3 行，而不是 250 行。
	if lines := strings.Count(buf.String(), "event=tool_log_write_rejected"); lines != 3 {
		t.Fatalf("250 次拒绝应只打 3 行限频日志，实际 %d 行", lines)
	}
}
