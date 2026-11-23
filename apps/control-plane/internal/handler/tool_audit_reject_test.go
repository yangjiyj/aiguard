package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func captureToolAuditLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}

func postInternalToolLog(t *testing.T, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	buf := captureToolAuditLog(t)
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/tools/logs", strings.NewReader(body))
	request.Header.Set("X-Tenant-ID", "tenant-1")
	response := httptest.NewRecorder()
	CreateToolCallLogInternal(&Dependencies{}).ServeHTTP(response, request)
	return response, buf.String()
}

func TestToolLogRejectionLogsReasonForInvalidJSON(t *testing.T) {
	response, out := postInternalToolLog(t, `{"tool_name": "read_file", "parameters": {"password":"hunter2"`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
	for _, want := range []string{"tool_log_rejected", "reason=invalid_json", "tenant=tenant-1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "read_file") {
		t.Fatalf("log leaks request content: %q", out)
	}
}

func TestToolLogRejectionDistinguishesMissingToolName(t *testing.T) {
	response, out := postInternalToolLog(t, `{"tool_name":"","tool_type":"file","parameters":{"secret":"s3cr3t"}}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
	if !strings.Contains(out, "reason=missing_tool_name") || strings.Contains(out, "missing_tool_type") {
		t.Fatalf("log=%q", out)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("log leaks content: %q", out)
	}
}

func TestToolLogRejectionDistinguishesMissingToolType(t *testing.T) {
	_, out := postInternalToolLog(t, `{"tool_name":"read_file","tool_type":""}`)
	if !strings.Contains(out, "reason=missing_tool_type") {
		t.Fatalf("log=%q", out)
	}
}

func TestToolLogRejectionReportsBothMissingFields(t *testing.T) {
	_, out := postInternalToolLog(t, `{}`)
	if !strings.Contains(out, "reason=missing_tool_name_and_type") {
		t.Fatalf("log=%q", out)
	}
}

// 兼容性：响应状态码与消息保持不变（旧网关依赖 400 + 原消息）。
func TestToolLogRejectionResponseContractUnchanged(t *testing.T) {
	cases := map[string]string{
		`{bad`:                            "invalid JSON format",
		`{"tool_name":"","tool_type":""}`: "tool_name and tool_type are required",
	}
	for body, wantMessage := range cases {
		response, _ := postInternalToolLog(t, body)
		var envelope struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		if response.Code != 400 || envelope.Error.Code != "invalid_request" || envelope.Error.Message != wantMessage {
			t.Fatalf("body=%s code=%d envelope=%+v", body, response.Code, envelope)
		}
	}
}

// 洪峰（单秒数百次 400）下日志必须限频，但计数要准确。
func TestToolLogRejectionLogIsRateLimitedUnderFlood(t *testing.T) {
	buf := captureToolAuditLog(t)
	for i := 0; i < 562; i++ {
		request := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"tool_name":"","tool_type":"file"}`))
		request.Header.Set("X-Tenant-ID", "tenant-flood")
		CreateToolCallLogInternal(&Dependencies{}).ServeHTTP(httptest.NewRecorder(), request)
	}
	lines := strings.Count(buf.String(), "tool_log_rejected")
	if lines == 0 || lines > 20 {
		t.Fatalf("log lines=%d, want 1..20 for 562 rejections", lines)
	}
	if !strings.Contains(buf.String(), "total=500") {
		t.Fatalf("累计计数缺失:\n%s", buf.String())
	}
}

// 不收紧：纯空白名在改造前能入库，改造后不能因为这次改动开始被 400（旧网关发空白名时不能丢审计）。
func TestToolLogRejectionDoesNotTightenForWhitespaceNames(t *testing.T) {
	buf := captureToolAuditLog(t)
	request := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"tool_name":"   ","tool_type":"file"}`))
	request.Header.Set("X-Tenant-ID", "tenant-1")
	response := httptest.NewRecorder()
	defer func() { _ = recover() }() // 通过校验后会访问空依赖(nil 仓储)而 panic，这里只关心没有走拒绝分支
	CreateToolCallLogInternal(&Dependencies{}).ServeHTTP(response, request)
	if response.Code == http.StatusBadRequest || strings.Contains(buf.String(), "tool_log_rejected") {
		t.Fatalf("whitespace name now rejected: code=%d log=%q", response.Code, buf.String())
	}
}
