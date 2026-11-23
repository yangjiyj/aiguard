package handler

// 复审 M-1：未鉴权的 /health 不得暴露 mcp_redline.last_error 原文（含控制面内部主机名、端口、路径）。
// /health 只保留最小存活信息；运行状态（生效执行模式、来源、env 兜底值、红线拉取失败次数与类别）放到
// 需要内部密钥的 /admin/v1/internal/runtime-status。错误原文只写日志。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const internalSecretHeader = "X-JJDGuard-Internal-Secret"

func newRuntimeStatusFixture(t *testing.T) (*ToolRiskClient, *MCPProxyHandler) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	c := NewToolRiskClient("http://control-plane.internal.corp:8081", "x")
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: true, SecurityExecutionModeManaged: true})
	h := NewMCPProxyHandler(nil, c, false)
	// 模拟红线配置拉取失败，错误原文含内部主机名/端口/路径
	h.recordRedlineFetchFailureForTest("tenant-a", "Get \"http://control-plane.internal.corp:8081/admin/v1/internal/mcp/redline-settings\": dial tcp 10.1.2.3:8081: connect: connection refused")
	return c, h
}

func TestM1_HealthPayloadIsMinimalAndLeaksNothingInternal(t *testing.T) {
	c, h := newRuntimeStatusFixture(t)
	payload := GatewayHealthPayload("ok", "ok", http.StatusOK)
	raw, _ := json.Marshal(payload)
	body := string(raw)
	for _, forbidden := range []string{"control-plane", "internal.corp", "10.1.2.3", "8081", "redline-settings", "last_error", "execution_mode", "env_security_audit_only", "mcp_redline"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("/health 不得暴露 %q: %s", forbidden, body)
		}
	}
	// 兼容性：compose healthcheck 只看 HTTP 状态；既有字段保持不变
	for _, k := range []string{"status", "service", "database", "redis"} {
		if _, ok := payload[k]; !ok {
			t.Fatalf("/health 必须保留既有字段 %s: %v", k, payload)
		}
	}
	_, _ = c, h
}

func TestM1_RuntimeStatusRequiresInternalSecretAndFailsClosed(t *testing.T) {
	c, h := newRuntimeStatusFixture(t)
	handler := RuntimeStatusHandler("s3cret", c, h)

	for name, header := range map[string]string{"无密钥": "", "错误密钥": "wrong"} {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/runtime-status", nil)
		if header != "" {
			req.Header.Set(internalSecretHeader, header)
		}
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s 必须 401，实际 %d", name, w.Code)
		}
	}
	// 未配置内部密钥时一律拒绝（fail-closed），即便请求带了空头
	open := RuntimeStatusHandler("", c, h)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/runtime-status", nil)
	req.Header.Set(internalSecretHeader, "")
	w := httptest.NewRecorder()
	open(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("未配置内部密钥必须 fail-closed: %d", w.Code)
	}
}

func TestM1_RuntimeStatusReturnsModeAndRedlineCategoryButNeverTheRawError(t *testing.T) {
	c, h := newRuntimeStatusFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/runtime-status", nil)
	req.Header.Set(internalSecretHeader, "s3cret")
	w := httptest.NewRecorder()
	RuntimeStatusHandler("s3cret", c, h)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("带正确密钥应 200: %d %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["execution_mode"] != "record" || got["execution_mode_source"] != "signed" || got["env_security_audit_only"] != false {
		t.Fatalf("应返回生效模式与来源: %v", got)
	}
	red, _ := got["mcp_redline"].(map[string]any)
	if red["fetch_failures"] != float64(1) {
		t.Fatalf("应返回失败次数: %v", red)
	}
	if red["last_error_category"] != "connection_refused" {
		t.Fatalf("应返回失败类别而非原文: %v", red)
	}
	if strings.Contains(w.Body.String(), "internal.corp") || strings.Contains(w.Body.String(), "10.1.2.3") || strings.Contains(w.Body.String(), "last_error\"") {
		t.Fatalf("即便鉴权通过也不应回显错误原文: %s", w.Body.String())
	}
}

func TestM1_RedlineErrorCategoryIsCoarseAndBounded(t *testing.T) {
	cases := map[string]string{
		"dial tcp 10.0.0.1:8081: connect: connection refused": "connection_refused",
		"context deadline exceeded":                           "timeout",
		"Client.Timeout exceeded while awaiting headers":      "timeout",
		"no such host":                   "dns",
		"status 404":                     "http_404",
		"status 503":                     "http_5xx",
		"some other thing with 10.9.9.9": "other",
		"":                               "",
	}
	for in, want := range cases {
		if got := classifyRedlineFetchError(in); got != want {
			t.Fatalf("classify(%q)=%q want %q", in, got, want)
		}
	}
}

func TestM1_FailureDetailStillGoesToTheLog(t *testing.T) {
	buf := captureLog(t)
	_, h := newRuntimeStatusFixture(t)
	_ = h
	if !strings.Contains(buf.String(), "redline-settings") {
		t.Fatalf("错误原文应写入日志供运维排查: %q", buf.String())
	}
}
