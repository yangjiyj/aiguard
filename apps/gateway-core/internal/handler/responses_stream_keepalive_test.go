package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

const (
	responsesKeepalivePath       = "/v1/responses"
	responsesKeepaliveStreamBody = `{"model":"gpt-5.6-sol","input":"inspect","stream":true}`
	responsesKeepalivePlainBody  = `{"model":"gpt-5.6-sol","input":"inspect","stream":false}`
	compatKeepaliveStreamBody    = `{"model":"gpt-5.5","input":"Hello","stream":true}`
	compatKeepalivePlainBody     = `{"model":"gpt-5.5","input":"Hello","stream":false}`
	nativeResponsesText          = "native-ok"
)

// nativeResponsesSSE 是原生上游返回的完整 Responses SSE，慢请求最终必须原样续写出来。
const nativeResponsesSSE = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\n" +
	"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-5.6\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"native-ok\"}]}],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"

const nativeResponsesJSON = `{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"native-ok","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`

func newResponsesKeepaliveHandler(caller ProviderCaller, security SecurityChecker, audit *MockAuditWriter, cfg *config.Config, native bool) *ResponsesHandler {
	if security == nil {
		security = &MockSecurityChecker{}
	}
	if audit == nil {
		audit = &MockAuditWriter{}
	}
	var resolver *MockModelResolver
	if native {
		resolver = &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
			ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
			UpstreamModelID: "gpt-5.6", ProviderType: "openai",
			ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
		}}
	} else {
		resolver = &MockModelResolver{}
	}
	return NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, security, audit, fixedAdapterFactory{caller: caller}, nil, nil)
}

func setResponsesBlockMode(h *ResponsesHandler, mode string) {
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	client.runtimeCache.setSecurityAuditOnly(false)
	client.setBlockNoticeSettings(blockNoticeSettings{Mode: mode, Template: DefaultBlockNoticeTemplate})
	h.toolRiskClient = client
}

// stripKeepalive 去掉保活注释，便于用 parseResponsesSSE 解析剩余事件。
func stripKeepalive(body string) string { return strings.ReplaceAll(body, ": keepalive\n\n", "") }

func nativeKeepaliveCaller(delay time.Duration, response string) *delayedProviderCaller {
	c := &delayedProviderCaller{delay: delay}
	c.CallResponse = []byte(response)
	return c
}

// ===== 原生路径 =====

func TestResponsesNativeKeepaliveSlowStreamHeadersEarlyThenFullEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	h := newResponsesKeepaliveHandler(nativeKeepaliveCaller(260*time.Millisecond, nativeResponsesSSE), nil, audit, &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond}, true)

	res := doKeepaliveHTTP(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	if res.headerAt >= 240*time.Millisecond {
		t.Fatalf("headers arrived after %v, keepalive did not start early", res.headerAt)
	}
	if res.status != http.StatusOK || !strings.Contains(res.header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status=%d ct=%q", res.status, res.header.Get("Content-Type"))
	}
	if res.header.Get("X-Request-Id") == "" {
		t.Fatalf("committed headers must carry X-Request-ID: %#v", res.header)
	}
	if strings.Count(res.body, ": keepalive\n\n") < 2 {
		t.Fatalf("expected repeated keepalive comments, got %q", res.body)
	}
	if got := stripKeepalive(res.body); got != nativeResponsesSSE {
		t.Fatalf("upstream SSE must be replayed byte-for-byte after keepalive\nwant=%q\n got=%q", nativeResponsesSSE, got)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesNativeKeepaliveFastStreamByteIdenticalToDisabled(t *testing.T) {
	run := func(interval time.Duration) *httptest.ResponseRecorder {
		h := newResponsesKeepaliveHandler(nativeKeepaliveCaller(0, nativeResponsesSSE), nil, nil, &config.Config{StreamKeepaliveInterval: interval}, true)
		return serveKeepalivePlain(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)
	}
	off, on := run(0), run(time.Hour)
	assertSameKeepaliveResponse(t, off, on)
	if strings.Contains(on.Body.String(), "keepalive") {
		t.Fatalf("fast request must not carry keepalive: %q", on.Body.String())
	}
}

func TestResponsesNativeKeepaliveSlowUpstream429UsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	upstreamErr := &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited", Body: []byte(`{"error":{"message":"rate limited"}}`)}
	caller.CallError = upstreamErr
	h := newResponsesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, true)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" {
		t.Fatalf("events=%s body=%q", got, body)
	}
	if events[0]["code"] != "upstream_error" || events[0]["message"] != clientUpstreamErrorMessage(upstreamErr, "upstream request failed") {
		t.Fatalf("error event=%v", events[0])
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_error" || audit.RequestLogFinalizes[0].StatusCode != http.StatusTooManyRequests {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesNativeKeepaliveSlowTransportErrorUsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = errors.New("connection reset by peer") // 非 HTTP 类故障走 provider_unavailable 分支
	h := newResponsesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, true)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	events := parseResponsesSSE(t, stripKeepalive(w.body()))
	if w.code() != http.StatusOK || strings.Join(eventTypes(events), ",") != "error,response.failed" || events[0]["code"] != "provider_unavailable" {
		t.Fatalf("code=%d body=%q", w.code(), w.body())
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_unavailable" || audit.RequestLogFinalizes[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesNativeKeepaliveSlowOutputBlockUsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "secret", Severity: "high", Action: "block"}}}
	h := newResponsesKeepaliveHandler(nativeKeepaliveCaller(120*time.Millisecond, nativeResponsesSSE), security, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, true)
	setResponsesBlockMode(h, blockResponseModeError)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	if strings.Contains(body, nativeResponsesText) {
		t.Fatalf("blocked content leaked: %q", body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" || events[0]["code"] != "security_blocked" {
		t.Fatalf("events=%s body=%q", got, body)
	}
	if !strings.Contains(body, "evt_") {
		t.Fatalf("block id must be visible in the failure message: %q", body)
	}
	found := false
	for _, f := range audit.RequestLogFinalizes {
		if f.Status == "security_blocked" && f.StatusCode == http.StatusForbidden {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit must still record security_blocked/403: %+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesNativeKeepaliveSlowOutputBlockMessageModeKeepsEventSequence(t *testing.T) {
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "secret", Severity: "high", Action: "block"}}}

	fastHandler := newResponsesKeepaliveHandler(nativeKeepaliveCaller(0, nativeResponsesSSE), security, nil, &config.Config{}, true)
	setResponsesBlockMode(fastHandler, blockResponseModeMessage)
	fast := serveKeepalivePlain(t, fastHandler.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	slowHandler := newResponsesKeepaliveHandler(nativeKeepaliveCaller(120*time.Millisecond, nativeResponsesSSE), security, nil, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, true)
	setResponsesBlockMode(slowHandler, blockResponseModeMessage)
	slow := serveKeepaliveFlush(t, slowHandler.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	slowBody := slow.body()
	if !strings.HasPrefix(slowBody, ": keepalive\n\n") {
		t.Fatalf("expected keepalive first: %q", slowBody)
	}
	slowTypes := strings.Join(eventTypes(parseResponsesSSE(t, stripKeepalive(slowBody))), ",")
	fastTypes := strings.Join(eventTypes(parseResponsesSSE(t, fast.Body.String())), ",")
	if slowTypes != fastTypes || !strings.HasSuffix(slowTypes, "response.completed") {
		t.Fatalf("event sequence differs\nslow=%s\nfast=%s", slowTypes, fastTypes)
	}
	if strings.Contains(slowBody, nativeResponsesText) || !strings.Contains(slowBody, "JJDGuard") {
		t.Fatalf("expected the block notice instead of the model output: %q", slowBody)
	}
}

func TestResponsesNativeKeepaliveNonStreamUnaffected(t *testing.T) {
	h := newResponsesKeepaliveHandler(nativeKeepaliveCaller(120*time.Millisecond, nativeResponsesJSON), nil, nil, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, true)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepalivePlainBody)

	if w.body() != nativeResponsesJSON || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("non-stream response changed: ct=%q body=%q", w.Header().Get("Content-Type"), w.body())
	}
}

func TestResponsesNativeKeepaliveCoversSlowOutputScan(t *testing.T) {
	security := slowOutputSecurity{MockSecurityChecker: &MockSecurityChecker{}, delay: 200 * time.Millisecond}
	h := newResponsesKeepaliveHandler(nativeKeepaliveCaller(0, nativeResponsesSSE), security, nil, &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond}, true)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	if !strings.Contains(w.body(), ": keepalive") || stripKeepalive(w.body()) != nativeResponsesSSE {
		t.Fatalf("slow output scan must be covered by keepalive: %q", w.body())
	}
}

func TestResponsesNativeKeepaliveCoversLiveStreamFallbackToBuffered(t *testing.T) {
	cfg := &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond, UpstreamStreaming: true}
	h := newResponsesKeepaliveHandler(nativeKeepaliveCaller(160*time.Millisecond, nativeResponsesSSE), nil, nil, cfg, true)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	if !strings.Contains(w.body(), ": keepalive") || stripKeepalive(w.body()) != nativeResponsesSSE {
		t.Fatalf("buffered fallback must keep the connection alive: %q", w.body())
	}
}

func TestResponsesNativeKeepaliveV2RouteSlowStream(t *testing.T) {
	for _, upstreamStreaming := range []bool{false, true} {
		caller := nativeKeepaliveCaller(150*time.Millisecond, nativeResponsesSSE)
		nativeRoute := route("native-provider", "openai", "https://native.example/v1", "gpt-5.6")
		nativeRoute.ModelName = "gpt-5.6-sol"
		nativeRoute.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
		nativeRoute.ResponsesNative = true
		engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: nativeRoute}}
		cfg := &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond, UpstreamStreaming: upstreamStreaming}
		h := NewResponsesHandler(cfg, &MockModelResolver{ModelRecord: &nativeRoute}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{},
			&MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"native-provider": caller}}, nil, nil)
		h.SetModelRoutingEngine(engine)

		w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

		if !strings.Contains(w.body(), ": keepalive") || stripKeepalive(w.body()) != nativeResponsesSSE {
			t.Fatalf("v2 native route (live=%v) slow stream not covered: %q", upstreamStreaming, w.body())
		}
	}
}

// ===== 兼容转换路径（chat 上游 -> responses） =====

func TestResponsesCompatKeepaliveSlowStreamHeadersEarlyThenFullEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	h := newResponsesKeepaliveHandler(&delayedProviderCaller{delay: 260 * time.Millisecond}, nil, audit, &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond}, false)

	res := doKeepaliveHTTP(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	if res.headerAt >= 240*time.Millisecond {
		t.Fatalf("headers arrived after %v, keepalive did not start early", res.headerAt)
	}
	if res.status != http.StatusOK || !strings.Contains(res.header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status=%d ct=%q", res.status, res.header.Get("Content-Type"))
	}
	if strings.Count(res.body, ": keepalive\n\n") < 2 {
		t.Fatalf("expected repeated keepalive comments, got %q", res.body)
	}
	events := parseResponsesSSE(t, stripKeepalive(res.body))
	types := strings.Join(eventTypes(events), ",")
	if !strings.Contains(types, "response.output_text.delta") || !strings.HasSuffix(types, "response.completed") {
		t.Fatalf("events=%s", types)
	}
	if !strings.Contains(res.body, "Hello! How can I help?") {
		t.Fatalf("answer lost: %q", res.body)
	}
	if strings.Index(res.body, ": keepalive") > strings.Index(res.body, "event: response.created") {
		t.Fatalf("keepalive must precede response events: %q", res.body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesCompatKeepaliveFastStreamByteIdenticalToDisabled(t *testing.T) {
	run := func(interval time.Duration) *httptest.ResponseRecorder {
		h := newResponsesKeepaliveHandler(&delayedProviderCaller{}, nil, nil, &config.Config{StreamKeepaliveInterval: interval}, false)
		return serveKeepalivePlain(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)
	}
	off, on := run(0), run(time.Hour)
	// 完整响应头 + 状态码 + 正文；响应 ID 由请求 ID 派生、每次不同，归一化后其余逐字节一致。
	assertSameKeepaliveResponse(t, off, on)
	if strings.Contains(on.Body.String(), "keepalive") {
		t.Fatalf("fast request must not carry keepalive: %q", on.Body.String())
	}
}

func TestResponsesCompatKeepaliveSlowUpstream429UsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	upstreamErr := &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited", Body: []byte(`{"error":{"message":"rate limited"}}`)}
	caller.CallError = upstreamErr
	h := newResponsesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, false)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" {
		t.Fatalf("events=%s body=%q", got, body)
	}
	if events[0]["code"] != "upstream_error" || events[0]["message"] != clientUpstreamErrorMessage(upstreamErr, "upstream request failed") {
		t.Fatalf("error event=%v", events[0])
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_error" || audit.RequestLogFinalizes[0].StatusCode != http.StatusTooManyRequests {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesCompatKeepaliveSlowOutputBlockUsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	h := newResponsesKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, security, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, false)
	setResponsesBlockMode(h, blockResponseModeError)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	if strings.Contains(body, "Hello! How can I help?") {
		t.Fatalf("blocked content leaked: %q", body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" || events[0]["code"] != "security_blocked" {
		t.Fatalf("events=%s body=%q", got, body)
	}
	if !strings.Contains(body, "evt_") {
		t.Fatalf("block id must be visible: %q", body)
	}
	found := false
	for _, f := range audit.RequestLogFinalizes {
		if f.Status == "security_blocked" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit must still record security_blocked: %+v", audit.RequestLogFinalizes)
	}
}

// 头已发出后输出检测不可用（fail-closed）：流内 failure，审计仍记 security_blocked/503，内容不放出。
func TestResponsesCompatKeepaliveCommittedDetectionUnavailable(t *testing.T) {
	audit := &MockAuditWriter{}
	security := &MockSecurityChecker{OutputError: errors.New("engine down")}
	h := newResponsesKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, security, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, false)
	h.toolRiskClient = failClosedClient(t, false, true)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" || events[0]["code"] != guardrailDetectionUnavailableCode {
		t.Fatalf("events=%s body=%q", got, body)
	}
	if strings.Contains(body, "Hello! How can I help?") {
		t.Fatalf("content leaked without inspection: %q", body)
	}
	found := false
	for _, f := range audit.RequestLogFinalizes {
		if f.Status == "security_blocked" && f.StatusCode == http.StatusServiceUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit must record security_blocked/503: %+v", audit.RequestLogFinalizes)
	}
}

func TestResponsesCompatKeepaliveNonStreamUnaffected(t *testing.T) {
	h := newResponsesKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, nil, nil, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, false)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepalivePlainBody)

	if strings.Contains(w.body(), "keepalive") || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("non-stream response changed: ct=%q body=%q", w.Header().Get("Content-Type"), w.body())
	}
}

func TestResponsesCompatKeepaliveCoversSlowOutputScan(t *testing.T) {
	security := slowOutputSecurity{MockSecurityChecker: &MockSecurityChecker{}, delay: 200 * time.Millisecond}
	h := newResponsesKeepaliveHandler(&delayedProviderCaller{}, security, nil, &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond}, false)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	if !strings.Contains(w.body(), ": keepalive") || !strings.Contains(w.body(), "response.completed") {
		t.Fatalf("slow output scan must be covered by keepalive: %q", w.body())
	}
}

func TestResponsesCompatKeepaliveV2RouteSlowStream(t *testing.T) {
	caller := &delayedProviderCaller{delay: 150 * time.Millisecond}
	chatRoute := route("chat-provider", "openai", "https://chat.example/v1", "gpt-5.5")
	chatRoute.ModelName = "gpt-5.5"
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: chatRoute}}
	cfg := &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}
	h := NewResponsesHandler(cfg, &MockModelResolver{ModelRecord: &chatRoute}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{},
		&MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"chat-provider": caller}}, nil, nil)
	h.SetModelRoutingEngine(engine)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	if !strings.Contains(w.body(), ": keepalive") || !strings.Contains(w.body(), "response.completed") {
		t.Fatalf("v2 compat route slow stream not covered: %q", w.body())
	}
}

// 间隔与上游耗时同量级，反复触发提交/收尾边界，配合 -race 检查 Finish 之后才写 w。
func TestResponsesKeepaliveRaceStress(t *testing.T) {
	type scenario struct {
		name        string
		native      bool
		caller      func() *delayedProviderCaller
		security    SecurityChecker
		wantFailure bool // 失败/拦截：流以 response.failed 收尾
	}
	nativeOK := func() *delayedProviderCaller { return nativeKeepaliveCaller(6*time.Millisecond, nativeResponsesSSE) }
	compatOK := func() *delayedProviderCaller { return &delayedProviderCaller{delay: 6 * time.Millisecond} }
	failing := func() *delayedProviderCaller {
		c := &delayedProviderCaller{delay: 6 * time.Millisecond}
		c.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "x"}
		return c
	}
	block := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	scenarios := []scenario{
		{"native_success", true, nativeOK, nil, false}, {"native_error", true, failing, nil, true}, {"native_blocked", true, nativeOK, block, true},
		{"compat_success", false, compatOK, nil, false}, {"compat_error", false, failing, nil, true}, {"compat_blocked", false, compatOK, block, true},
	}
	for _, sc := range scenarios {
		body := compatKeepaliveStreamBody
		if sc.native {
			body = responsesKeepaliveStreamBody
		}
		for i := 0; i < 40; i++ {
			h := newResponsesKeepaliveHandler(sc.caller(), sc.security, nil, &config.Config{StreamKeepaliveInterval: time.Duration(1+i%4) * time.Millisecond}, sc.native)
			w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, body)
			out := w.body()
			// 间隔 1-4ms 对 6ms 的上游：有的轮次头已提前发出，有的没有。无论哪种，响应都必须是完整、自洽的。
			// 流式响应以 response.completed（成功）或 response.failed（失败/拦截）收尾；
			// 头未发出的失败保持原来的 JSON 错误和真实状态码。
			wantTail := "response.completed"
			if sc.wantFailure {
				wantTail = "response.failed"
			}
			if strings.Contains(out, "event: ") {
				types := eventTypes(parseResponsesSSE(t, stripKeepalive(out)))
				if w.code() != http.StatusOK || len(types) == 0 || types[len(types)-1] != wantTail {
					t.Fatalf("%s #%d: committed stream must end with %q, code=%d body=%q", sc.name, i, wantTail, w.code(), out)
				}
			} else if !sc.wantFailure || w.code() < http.StatusBadRequest || !strings.Contains(out, `"error"`) {
				t.Fatalf("%s #%d: uncommitted response is not self-consistent, code=%d body=%q", sc.name, i, w.code(), out)
			}
		}
	}
}

// 构造 v2 双路由（都支持原生 Responses）：第一条路由慢返回 429，第二条实现 StreamAdapter。
func newResponsesNativeDualRouteHandler(second *liveRouteCaller, interval time.Duration) *ResponsesHandler {
	primary := route("p1", "openai", "https://native-1.example/v1", "gpt-5.6")
	primary.ModelName = "gpt-5.6-sol"
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	primary.ResponsesNative = true
	fallback := route("p2", "openai", "https://native-2.example/v1", "gpt-5.6")
	fallback.ModelName = "gpt-5.6-sol"
	fallback.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true}
	fallback.ResponsesNative = true
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}}}
	cfg := &config.Config{StreamKeepaliveInterval: interval, UpstreamStreaming: true}
	h := NewResponsesHandler(cfg, &MockModelResolver{ModelRecord: &primary}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{},
		&MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
			"p1": firstRouteTooManyRequests(150 * time.Millisecond),
			"p2": second,
		}}, nil, nil)
	h.SetModelRoutingEngine(engine)
	return h
}

// 保活先提交了头（第一条路由慢返回 429），路由层再尝试第二条（实现了 OpenStream 的）路由时，
// tryLive 必须看到 Stop()==true、不再尝试实时流。删掉 tryLive 里
// `if keepalive.Stop() { keepalive.Start(); return false, nil }` 后，这个用例会失败：
// OpenStream 被调用 1 次，-race 下还会报 DATA RACE。
func TestResponsesNativeKeepaliveV2DualRouteDoesNotGoLiveAfterHeadersCommitted(t *testing.T) {
	second := &liveRouteCaller{body: []byte(nativeResponsesSSE)}
	h := newResponsesNativeDualRouteHandler(second, 30*time.Millisecond)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	body := w.body()
	if n := second.openStreams.Load(); n != 0 {
		t.Fatalf("OpenStream called %d times after keepalive committed the headers, want 0", n)
	}
	if second.callCount.Load() != 1 {
		t.Fatalf("second route must be served through the buffered call exactly once, got %d", second.callCount.Load())
	}
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	if got := stripKeepalive(body); got != nativeResponsesSSE {
		t.Fatalf("expected the complete buffered result\nwant=%q\n got=%q", nativeResponsesSSE, got)
	}
}

// 同上，但第二条路由也失败 -> 头已发出后客户端收到的是流内 failure 事件，OpenStream 同样 0 次。
func TestResponsesNativeKeepaliveV2DualRouteLiveRouteErrorAfterCommitUsesFailureEvents(t *testing.T) {
	second := &liveRouteCaller{}
	second.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusServiceUnavailable, Message: "overloaded"}
	h := newResponsesNativeDualRouteHandler(second, 30*time.Millisecond)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	if n := second.openStreams.Load(); n != 0 {
		t.Fatalf("OpenStream called %d times after keepalive committed the headers, want 0", n)
	}
	events := parseResponsesSSE(t, stripKeepalive(w.body()))
	if got := strings.Join(eventTypes(events), ","); w.code() != http.StatusOK || got != "error,response.failed" || events[0]["code"] != "upstream_error" {
		t.Fatalf("code=%d events=%s body=%q", w.code(), got, w.body())
	}
}

// Responses 兼容路径，头已发出后上游返回的 chat 响应无法解析 -> 流内 failure 事件（provider_unavailable），审计 502。
func TestResponsesCompatKeepaliveSlowUnparsableResponseUsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.TransformResponseError = errors.New("cannot parse upstream body")
	h := newResponsesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, false)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" || events[0]["code"] != "provider_unavailable" || events[0]["message"] != "failed to parse response" {
		t.Fatalf("events=%s body=%q", got, body)
	}
	if strings.Contains(body, "Hello! How can I help?") {
		t.Fatalf("model output must not leak: %q", body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_unavailable" || audit.RequestLogFinalizes[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// Responses 兼容路径，头已发出后遇到 provider_timeout（context.DeadlineExceeded）。
func TestResponsesCompatKeepaliveSlowDeadlineExceededUsesFailureEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = context.DeadlineExceeded
	h := newResponsesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, false)

	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, compatKeepaliveStreamBody)

	events := parseResponsesSSE(t, stripKeepalive(w.body()))
	if got := strings.Join(eventTypes(events), ","); w.code() != http.StatusOK || got != "error,response.failed" || events[0]["code"] != "provider_timeout" {
		t.Fatalf("code=%d events=%s body=%q", w.code(), got, w.body())
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_timeout" || audit.RequestLogFinalizes[0].StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// nativeSafeResultBuildFailureField 是塞进终态 response 的一个额外字段，用来让"安全结果重建"这一步失败：
// 它是合法 JSON，nativeResponsesSecurityView 用结构体解析、只取需要的字段，会直接跳过它，所以安全检查照常进行并判 block；
// 失败发生在随后的 secureNativeResponsesOutput（responses_destructive.go）：它把 final 解析成 map[string]interface{}，
// 1e999 超出 float64 范围，json.Unmarshal 报错，handler 走到 "failed to build a safe Responses result" 分支。
const nativeSafeResultBuildFailureField = `,"overflow_probe":1e999`

// newNativeBlockedToolCallHandler 复刻 TestNativeResponsesCustomToolCallEntersAgentGuardAndBlocks 的 AgentGuard 夹具：
// 上游返回一个危险的自定义工具调用，输出阶段被判 block，随后要用 secureNativeResponsesOutput 重建安全结果。
// extraField 用来在终态 response 里塞一个额外字段：结构体解析会跳过它，重建时的 map 解析会因 float64 溢出而失败。
func newNativeBlockedToolCallHandler(t *testing.T, audit *MockAuditWriter, interval, delay time.Duration, extraField string) *ResponsesHandler {
	t.Helper()
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-native","name":"阻断系统工具","policy_version":"v1","mode":"strict","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[{"id":"block-system","tool_pattern":"system.*","action":"block","enabled":true}],"exceptions":[]}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(controlPlane.Close)
	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)

	final := `{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"call_1","type":"custom_tool_call","call_id":"call_1","name":"shell_command","input":"rm -rf /"}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}` + extraField + `}`
	upstream := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + final + "}\n\n"
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	return NewResponsesHandler(&config.Config{SecurityAuditOnly: false, StreamKeepaliveInterval: interval}, resolver, &MockRateLimitChecker{},
		&MockSecurityChecker{}, audit, fixedAdapterFactory{caller: nativeKeepaliveCaller(delay, upstream)}, client, nil)
}

// 原生路径，AgentGuard 判 block 后用 secureNativeResponsesOutput 重建安全结果失败：
// - 快请求（头未发出）保持原样：JSON 错误，不是 200 SSE；
// - 慢请求（头已发出）：流内 failure 事件，不能把 JSON 混进 SSE；原始工具参数不泄露；审计仍记 provider_unavailable/502。
func TestResponsesNativeKeepaliveSlowSafeResultBuildFailureUsesFailureEvents(t *testing.T) {

	// 先确认夹具确实命中了"重建失败"分支：快请求头未发出 -> 与改造前一致的 JSON 错误。
	fastAudit := &MockAuditWriter{}
	fast := serveKeepalivePlain(t, newNativeBlockedToolCallHandler(t, fastAudit, time.Hour, 0, nativeSafeResultBuildFailureField).Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)
	if fast.Code == http.StatusOK || !strings.Contains(fast.Header().Get("Content-Type"), "application/json") ||
		!strings.Contains(fast.Body.String(), "failed to build a safe Responses result") {
		t.Fatalf("fixture must hit the safe-result build failure on the fast path: code=%d ct=%q body=%q", fast.Code, fast.Header().Get("Content-Type"), fast.Body.String())
	}

	audit := &MockAuditWriter{}
	h := newNativeBlockedToolCallHandler(t, audit, 30*time.Millisecond, 120*time.Millisecond, nativeSafeResultBuildFailureField)
	w := serveKeepaliveFlush(t, h.Handler(), responsesKeepalivePath, responsesKeepaliveStreamBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	events := parseResponsesSSE(t, stripKeepalive(body))
	if got := strings.Join(eventTypes(events), ","); got != "error,response.failed" ||
		events[0]["code"] != "provider_unavailable" || events[0]["message"] != "failed to build a safe Responses result" {
		t.Fatalf("expected failure events, got %s body=%q", got, body)
	}
	if strings.Contains(body, "rm -rf") || strings.Contains(body, "shell_command") || strings.Contains(body, "overflow_probe") {
		t.Fatalf("raw upstream content leaked into the stream: %q", body)
	}
	if strings.Contains(body, "{\"error\"") {
		t.Fatalf("a JSON error body must not be mixed into the SSE stream: %q", body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_unavailable" || audit.RequestLogFinalizes[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 保活开启 + 实时流成功：上游立刻返回合法事件流，tryLive 走通实时流，不应出现任何保活字节，
// 状态码、完整响应头、正文与关闭保活时一致（实时流的随机 ID 先归一化）。
func TestResponsesNativeKeepaliveLiveStreamSuccessMatchesKeepaliveDisabled(t *testing.T) {
	const sse = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-live\"}}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"live-hello\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-live\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-live\",\"output\":[{\"id\":\"msg-live\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"live-hello\"}]}],\"usage\":{\"input_tokens\":3,\"output_tokens\":1,\"total_tokens\":4}}}\n\n"
	run := func(interval time.Duration) (*httptest.ResponseRecorder, int32) {
		var opened atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			opened.Add(1)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, sse)
			w.(http.Flusher).Flush()
		}))
		defer upstream.Close()
		resolver := &MockModelResolver{ProviderAPIKey: "provider-key", ModelRecord: &modelrouter.ModelRecord{
			ID: "model-live", ProviderID: "provider-live", ModelName: "gpt-live", UpstreamModelID: "gpt-live",
			ProviderType: "openai", ProviderBaseURL: upstream.URL, ProviderAuthMode: "bearer", Status: "active", ResponsesNative: true,
		}}
		cfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit", StreamKeepaliveInterval: interval}
		h := NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil)
		return serveKeepalivePlain(t, h.Handler(), responsesKeepalivePath, `{"model":"gpt-live","input":"inspect","stream":true}`), opened.Load()
	}

	off, offOpened := run(0)
	on, onOpened := run(30 * time.Millisecond)

	if offOpened != 1 || onOpened != 1 {
		t.Fatalf("live stream must open the upstream stream exactly once: off=%d on=%d", offOpened, onOpened)
	}
	if strings.Contains(on.Body.String(), "keepalive") || !strings.Contains(on.Body.String(), "live-hello") {
		t.Fatalf("live stream must carry the answer and no keepalive bytes: %q", on.Body.String())
	}
	assertSameKeepaliveResponse(t, off, on)
}
