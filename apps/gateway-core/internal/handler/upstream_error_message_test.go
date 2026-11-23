package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func TestParseUpstreamError(t *testing.T) {
	for _, tc := range []struct{ body, message, typ, code string }{
		{`{"error":{"message":"nested","type":"invalid_request_error","code":"context_length_exceeded"},"message":"top"}`, "nested", "invalid_request_error", "context_length_exceeded"},
		{`{"message":"top","type":"bad_request","code":123}`, "top", "bad_request", "123"},
		{`{"error":"string error"}`, "string error", "", ""},
		{`{"detail":"detail text"}`, "detail text", "", ""},
		{`{"detail":{"message":"detail object"}}`, "detail object", "", ""},
		{`{"msg":"msg text"}`, "msg text", "", ""},
		{`{"errors":[{"message":"first"},{"message":"second"}]}`, "first", "", ""},
		{"plain <b>failure</b>", "plain failure", "", ""},
		{"<!DOCTYPE html><html><title>502 Bad &amp; Gateway</title><body>secret body</body></html>", "502 Bad & Gateway", "", ""},
		{"<html><body>secret body</body></html>", "", "", ""},
		{`{"request":{"prompt":"不得留存"}}`, "", "", ""},
	} {
		t.Run(tc.body, func(t *testing.T) {
			got := parseUpstreamError([]byte(tc.body))
			if got.Message != tc.message || got.Type != tc.typ || got.Code != tc.code {
				t.Fatalf("解析结果不符：%+v", got)
			}
		})
	}
}

func TestUpstreamErrorRetentionAndHints(t *testing.T) {
	for _, tc := range []struct {
		status             int
		body, reason, hint string
	}{
		{400, `{"message":"prompt is too long: 1002476 tokens > 1000000 maximum","code":"context_length_exceeded"}`, "prompt is too long: 1002476 tokens > 1000000 maximum", "对话上下文超过模型上限（本次 1002476 token，上限 1000000），请压缩上下文或新开对话"},
		{429, `{"message":"rate limit quota for organization org-abc"}`, "rate limit quota for organization <redacted:secret>", "上游请求过于频繁，请稍后重试"},
		{402, `{"message":"insufficient balance quota"}`, "insufficient balance quota", "上游账号额度不足，请联系管理员"},
		{401, `{"message":"invalid key sk-abc from 10.0.0.1"}`, "invalid key <redacted:secret> from <ip>", "上游凭据无效，请联系管理员"},
		{403, `{"message":"permission denied"}`, "permission denied", "上游模型不存在或无访问权限，请联系管理员"},
		{404, `{"error":{"message":"model not found","code":"model_not_found"}}`, "model not found", "上游模型不存在或无访问权限，请联系管理员"},
		{400, `{"error":{"message":"rejected","code":"content_filter"}}`, "rejected", "上游内容审核拒绝了本次请求，请调整内容后重试"},
		{400, `{"detail":"unsupported parameter temperature"}`, "unsupported parameter temperature", "请求参数不受上游模型支持，请检查参数后重试"},
		{529, `{"error":{"message":"busy","type":"overloaded_error"}}`, "busy", "上游服务暂时不可用、超时或过载，请稍后重试"},
		{502, "<html><title>Bad Gateway</title><body>private</body></html>", "Bad Gateway", "上游服务暂时不可用、超时或过载，请稍后重试"},
		{500, "failed at https://relay.internal/x?key=abc 10.0.0.1 Bearer abcdefghijklmnop", "failed at <url> <ip> <redacted:secret>", "上游服务暂时不可用、超时或过载，请稍后重试"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			err := &provider.UpstreamHTTPError{StatusCode: tc.status, Body: []byte(tc.body)}
			metadata := upstreamRejectionAuditResult(nil, err, "upstream_response").ResponseMetadata
			if metadata["error_message"] != tc.reason || metadata["upstream_error_hint"] != tc.hint {
				t.Fatalf("留存结果不符：%v", metadata)
			}
			if strings.Contains(tc.body, "1002476") {
				if metadata["upstream_error_code"] != "context_length_exceeded" {
					t.Fatal(metadata)
				}
				if got := clientUpstreamErrorMessage(err, "fallback"); got != tc.reason {
					t.Fatal(got)
				}
			}
			if tc.status == 401 || tc.status == 402 || tc.status == 403 || tc.status == 429 {
				if got := clientUpstreamErrorMessage(err, "fallback"); got != tc.hint {
					t.Fatalf("客户端应只拿到中文解释：%q", got)
				}
			}
		})
	}
}

func TestUpstreamAuditReasonBounded(t *testing.T) {
	raw, _ := json.Marshal(map[string]string{"message": strings.Repeat("字", 5000)})
	result := upstreamRejectionAuditResult(nil, &provider.UpstreamHTTPError{StatusCode: 500, Body: raw}, "upstream_response")
	message := result.ResponseMetadata["error_message"].(string)
	if len([]rune(message)) > 1000 || len([]rune(message)) < 990 {
		t.Fatalf("截断长度不符：%d", len([]rune(message)))
	}
}

func TestUpstreamAuditMasksShortBearerAndErrorCode(t *testing.T) {
	body := []byte(`{"message":"quota exceeded Bearer abc at [2001:db8::1]:443 relay.corp https://relay.corp/x?token=secret","code":"sk-secret"}`)
	metadata := upstreamRejectionAuditResult(nil, &provider.UpstreamHTTPError{StatusCode: 429, Body: body}, "upstream_response").ResponseMetadata
	raw, _ := json.Marshal(metadata)
	for _, leak := range []string{"Bearer abc", "2001:db8", "relay.corp", "token=secret", "sk-secret"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("定点遮盖遗漏 %q：%s", leak, raw)
		}
	}
	if !strings.Contains(metadata["error_message"].(string), "quota exceeded") {
		t.Fatal(metadata)
	}
}

func TestUpstreamErrorHintContextCountsAndQuotaPriority(t *testing.T) {
	for _, tc := range []struct {
		status int
		detail upstreamErrorDetail
		want   string
	}{
		{400, upstreamErrorDetail{Message: "maximum context length is 8192 tokens. However, you requested 9000 tokens"}, "对话上下文超过模型上限（本次 9000 token，上限 8192），请压缩上下文或新开对话"},
		{400, upstreamErrorDetail{Code: "context_length_exceeded"}, "对话上下文超过模型上限，请压缩上下文或新开对话"},
		{429, upstreamErrorDetail{Message: "quota balance exhausted", Code: "insufficient_quota"}, "上游账号额度不足，请联系管理员"},
		{408, upstreamErrorDetail{Message: "request timed out"}, "上游服务暂时不可用、超时或过载，请稍后重试"},
	} {
		if got := upstreamErrorHint(tc.status, tc.detail); got != tc.want {
			t.Fatalf("中文解释错误：%q，预期 %q", got, tc.want)
		}
	}
}
