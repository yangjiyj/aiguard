package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func captureUpstreamTestLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	previous := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return buf
}

func resetQuotaOverrunLogState(t *testing.T) {
	t.Helper()
	quotaOverrunLogState.Lock()
	quotaOverrunLogState.day, quotaOverrunLogState.counts = "", map[string]int64{}
	quotaOverrunLogState.Unlock()
}

// 结算已经按 actual 入账之后才返回 overrun 错误：日志不能再写 "failed"，并且按天限频。
func TestQuotaFinalizeOverrunLogIsNotReportedAsFailureAndIsThrottled(t *testing.T) {
	resetQuotaOverrunLogState(t)
	quotaOverrunNow = func() time.Time { return time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { quotaOverrunNow = time.Now })
	buf := captureUpstreamTestLog(t)
	envelope := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", Model: "claude-opus-5", RequestID: "req-0"}

	for i := 1; i <= 25; i++ {
		envelope.RequestID = fmt.Sprintf("req-%d", i)
		logQuotaFinalizeError(envelope, &governor.AdmissionOverrunError{RequestID: envelope.RequestID, EstimatedTokens: 119400, ActualTokens: 139803})
	}
	out := buf.String()
	if strings.Contains(out, "failed") {
		t.Fatalf("预占超出不应再被写成 failed:\n%s", out)
	}
	// 25 次超出内只有第 1 次和第 10 次是里程碑（第 100 次还没到）。
	if lines := strings.Count(out, "预占超出告警"); lines != 2 {
		t.Fatalf("25 次超出应只记 2 行(第1次、第10次)，实际 %d 行:\n%s", lines, out)
	}
	for _, want := range []string{"结算已成功", "已按实际用量入账", "预占=119400", "实际=139803", "超出=20403", "当日第1次", "当日第10次", "claude-opus-5"} {
		if !strings.Contains(out, want) {
			t.Fatalf("日志缺少 %q:\n%s", want, out)
		}
	}
	// 跨天后重新计数，第一条重新记。
	quotaOverrunNow = func() time.Time { return time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC) }
	buf.Reset()
	logQuotaFinalizeError(envelope, &governor.AdmissionOverrunError{RequestID: "req-next-day", EstimatedTokens: 10, ActualTokens: 20})
	if !strings.Contains(buf.String(), "当日第1次") {
		t.Fatalf("跨天后应重新记第 1 次: %s", buf.String())
	}
}

func TestQuotaFinalizeNonOverrunErrorsStillLogAsFailed(t *testing.T) {
	resetQuotaOverrunLogState(t)
	buf := captureUpstreamTestLog(t)
	envelope := &modelrouter.RequestEnvelope{TenantID: "t", RequestID: "req-redis"}
	for i := 0; i < 3; i++ {
		logQuotaFinalizeError(envelope, &governor.AdmissionRuntimeError{Metric: "runtime_fault", RequestID: "req-redis", Err: errors.New("redis unavailable")})
	}
	if strings.Count(buf.String(), "finalize request_id=req-redis failed") != 3 {
		t.Fatalf("真正的结算失败必须每次都记 failed（不限频）:\n%s", buf.String())
	}
}

func TestQuotaFinalizeCostOverrunUsesSameWording(t *testing.T) {
	resetQuotaOverrunLogState(t)
	buf := captureUpstreamTestLog(t)
	envelope := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", Model: "m", RequestID: "req-cost"}
	logQuotaFinalizeError(envelope, &governor.AdmissionCostOverrunError{RequestID: "req-cost", EstimatedMicros: 100, ActualMicros: 250})
	out := buf.String()
	if strings.Contains(out, "failed") || !strings.Contains(out, "金额微单位") || !strings.Contains(out, "超出=150") {
		t.Fatalf("金额超出日志不对:\n%s", out)
	}
}

func TestIsLogMilestone(t *testing.T) {
	want := map[int64]bool{1: true, 2: false, 9: false, 10: true, 11: false, 20: false, 99: false, 100: true, 1000: true, 1001: false}
	for count, expected := range want {
		if got := isLogMilestone(count); got != expected {
			t.Fatalf("isLogMilestone(%d)=%v want %v", count, got, expected)
		}
	}
}

func TestQuotaOverrunLogStateIsBoundedAndConcurrencySafe(t *testing.T) {
	resetQuotaOverrunLogState(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				quotaOverrunLogOccurrence(fmt.Sprintf("k-%d-%d", worker, i), "2026-10-23")
			}
		}(worker)
	}
	wg.Wait()
	quotaOverrunLogState.Lock()
	size := len(quotaOverrunLogState.counts)
	quotaOverrunLogState.Unlock()
	if size > quotaOverrunLogMaxKeys {
		t.Fatalf("限频表无界增长: %d", size)
	}
}

// ---- 上游 4xx 留痕 ----

func resetUpstreamRejectLog(t *testing.T) {
	t.Helper()
	upstreamRejectLogState.Lock()
	upstreamRejectLogState.last, upstreamRejectLogState.suppressed = map[string]time.Time{}, map[string]int64{}
	upstreamRejectLogState.Unlock()
	t.Cleanup(func() { upstreamRejectLogNow = time.Now })
}

func TestUpstreamRejectionAuditResultKeepsSanitizedTypeAndReason(t *testing.T) {
	resetUpstreamRejectLog(t)
	buf := captureUpstreamTestLog(t)
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-400", Model: "claude-opus-5"}
	upstreamErr := &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error",
		"prompt is too long: 215000 tokens > 200000 maximum, see https://relay.internal.example.com:8443/v1/messages key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 from 10.1.2.3")}

	result := upstreamRejectionAuditResult(envelope, upstreamErr, "upstream_response")

	metadata := result.ResponseMetadata
	if metadata["upstream_status_code"] != 400 || metadata["upstream_error_type"] != "invalid_request_error" || metadata["error_stage"] != "upstream_response" {
		t.Fatalf("metadata=%v", metadata)
	}
	reason, _ := metadata["error_message"].(string)
	if !strings.Contains(reason, "prompt is too long: 215000 tokens > 200000 maximum") {
		t.Fatalf("应保留可行动的原因: %q", reason)
	}
	for _, leak := range []string{"relay.internal.example.com", "8443", "https://", "sk-ant-api03", "10.1.2.3"} {
		if strings.Contains(reason, leak) || strings.Contains(buf.String(), leak) {
			t.Fatalf("泄露 %q: reason=%q log=%s", leak, reason, buf.String())
		}
	}
	for _, want := range []string{"[upstream.reject]", "request_id=req-400", "model=claude-opus-5", "upstream_status=400", "error_type=invalid_request_error", "prompt is too long"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("网关日志缺少 %q:\n%s", want, buf.String())
		}
	}
}

// 原先整句丢弃的余额、额度、429、5xx 现在都留存，只遮盖具体密钥与地址。
func TestUpstreamRejectionAuditResultKeepsAccountAndServerReasons(t *testing.T) {
	cases := []struct {
		status int
		body   []byte
		want   string
	}{
		{400, upstreamAnthropicBody("invalid_request_error", "Your credit balance is too low to access the API"), "Your credit balance is too low to access the API"},
		{400, upstreamAnthropicBody("invalid_request_error", "monthly quota exceeded for organization org-abc123"), "monthly quota exceeded for organization <redacted:secret>"},
		{429, upstreamAnthropicBody("rate_limit_error", "rate limit for key sk-ant-xyz"), "rate limit for key <redacted:secret>"},
		{500, upstreamAnthropicBody("api_error", "internal error at 10.0.0.9"), "internal error at <ip>"},
		{400, []byte("plain failure at 10.0.0.9"), "plain failure at <ip>"},
		{400, []byte("<html><title>Bad request</title><body>lb-7 10.0.0.9</body></html>"), "Bad request"},
		{400, nil, "上游返回 400，上游未提供可解析的错误原因"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			resetUpstreamRejectLog(t)
			buf := captureUpstreamTestLog(t)
			result := upstreamRejectionAuditResult(nil, &provider.UpstreamHTTPError{StatusCode: tc.status, Body: tc.body, Message: "不得使用无来源的 Message"}, "upstream_response")
			if result.ResponseMetadata["error_message"] != tc.want {
				t.Fatalf("留存错误：%v", result.ResponseMetadata)
			}
			if !strings.Contains(buf.String(), fmt.Sprintf("reason=%q", tc.want)) {
				t.Fatalf("日志与审计原因不一致：%s", buf.String())
			}
		})
	}
}

func TestUpstreamErrorTypeOnlyAcceptsShortIdentifiers(t *testing.T) {
	for body, want := range map[string]string{
		`{"type":"error","error":{"type":"invalid_request_error","message":"x"}}`: "invalid_request_error",
		`{"error":{"type":"Please contact billing at 10.0.0.9","message":"x"}}`:   "",
		`{"error":{"type":"","message":"x"}}`:                                     "",
		`{"error":"not an object"}`:                                               "",
		`not json`:                                                                "",
		``:                                                                        "",
	} {
		if got := upstreamErrorTypeFromBody([]byte(body)); got != want {
			t.Fatalf("body=%q type=%q want %q", body, got, want)
		}
	}
}

func TestUpstreamRejectionLogIsThrottledPerModelStatusAndType(t *testing.T) {
	resetUpstreamRejectLog(t)
	buf := captureUpstreamTestLog(t)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	upstreamRejectLogNow = func() time.Time { return now }
	envelope := &modelrouter.RequestEnvelope{RequestID: "r", Model: "claude-opus-5"}
	err400 := &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "max_tokens: 200000 > 128000")}
	for i := 0; i < 50; i++ {
		upstreamRejectionAuditResult(envelope, err400, "upstream_response")
	}
	if got := strings.Count(buf.String(), "[upstream.reject]"); got != 1 {
		t.Fatalf("窗口内同键应只记 1 行，实际 %d", got)
	}
	// 不同状态码/类型/模型各自独立。
	upstreamRejectionAuditResult(envelope, &provider.UpstreamHTTPError{StatusCode: 413, Body: upstreamAnthropicBody("request_too_large", "too big")}, "upstream_response")
	upstreamRejectionAuditResult(&modelrouter.RequestEnvelope{RequestID: "r2", Model: "claude-sonnet-5-5"}, err400, "upstream_response")
	if got := strings.Count(buf.String(), "[upstream.reject]"); got != 3 {
		t.Fatalf("不同键应各记一行，共 3 行，实际 %d", got)
	}
	// 窗口过后再记一行，并带上被压掉的条数。
	now = now.Add(upstreamRejectLogMinInterval + time.Second)
	buf.Reset()
	upstreamRejectionAuditResult(envelope, err400, "upstream_response")
	if !strings.Contains(buf.String(), "suppressed_since_last=49") {
		t.Fatalf("应报告被压掉的 49 条:\n%s", buf.String())
	}
}

// 端到端：原生 /v1/messages 遇到上游 400，请求审计里必须带上类型和净化后的原因，
// 客户端响应和之前的行为（状态码、透传文案）不变。
func TestNativeMessagesUpstream400LeavesReasonInRequestAudit(t *testing.T) {
	resetUpstreamRejectLog(t)
	buf := captureUpstreamTestLog(t)
	errorBody := []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"input length and max_tokens exceed context limit: 180000 + 32000 > 200000, see https://relay.corp.example.com/v1/messages"},"request_id":"kiro-400"}`)
	caller := &MockProviderCaller{CallError: &provider.UpstreamHTTPError{StatusCode: http.StatusBadRequest, Body: errorBody}}
	audit := &MockAuditWriter{}
	h := nativeMessagesTestHandler(caller, nil, audit)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32000,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "input length and max_tokens exceed context limit") {
		t.Fatalf("客户端响应不应变化: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var finalized *AuditResult
	for _, item := range audit.RequestLogFinalizes {
		if item.Status == "provider_error" {
			finalized = item.AuditResult
		}
	}
	if finalized == nil || finalized.ResponseMetadata == nil {
		t.Fatalf("provider_error 的审计没有带结果: %+v", audit.RequestLogFinalizes)
	}
	metadata := finalized.ResponseMetadata
	reason, _ := metadata["error_message"].(string)
	if metadata["upstream_error_type"] != "invalid_request_error" || metadata["upstream_status_code"] != http.StatusBadRequest ||
		!strings.Contains(reason, "180000 + 32000 > 200000") || strings.Contains(reason, "relay.corp.example.com") {
		t.Fatalf("审计 metadata 不对: %v", metadata)
	}
	if strings.Contains(fmt.Sprint(metadata), "hello") {
		t.Fatalf("审计不得写入请求内容: %v", metadata)
	}
	if !strings.Contains(buf.String(), "[upstream.reject] request_id=") || !strings.Contains(buf.String(), "upstream_status=400") {
		t.Fatalf("缺少限频网关日志:\n%s", buf.String())
	}
}

// 真实 SQL 路径：metadata 经 FinalizeRequestLog 落到 output_audit_result 的 response_metadata，
// 控制台"错误详情"读取的正是 output_audit_result #>> '{response_metadata,error_message}'。
func TestRealAuditWriterPersistsUpstreamRejectionMetadata(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-persist", TenantID: "t", ProjectID: "p", EndpointType: "messages", Model: "claude-opus-5"}
	resetUpstreamRejectLog(t)
	_ = captureUpstreamTestLog(t)
	auditResult := upstreamRejectionAuditResult(envelope, &provider.UpstreamHTTPError{StatusCode: 400, Body: upstreamAnthropicBody("invalid_request_error", "messages.3.content: tool_use ids must be unique")}, "upstream_response")

	writer.FinalizeRequestLog(context.Background(), envelope, nil, "provider_error", 400, 5, auditResult)

	if mockDB.execCalls < 1 {
		t.Fatal("没有写 request_logs")
	}
	found := false
	for _, arg := range mockDB.args[0] {
		if raw, ok := arg.([]byte); ok && strings.Contains(string(raw), `"error_message":"messages.3.content: tool_use ids must be unique"`) &&
			strings.Contains(string(raw), `"upstream_error_type":"invalid_request_error"`) && strings.Contains(string(raw), `"response_metadata"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("output_audit_result 里没有找到 response_metadata.error_message: %v", mockDB.args[0])
	}
}
