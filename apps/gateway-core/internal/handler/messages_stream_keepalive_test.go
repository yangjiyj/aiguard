package handler

import (
	"context"
	"encoding/json"
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
	messagesKeepalivePath  = "/v1/messages"
	messagesKeepaliveBody  = `{"model":"claude-opus-5","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hello"}]}`
	messagesKeepaliveBody0 = `{"model":"claude-opus-5","max_tokens":32,"stream":false,"messages":[{"role":"user","content":"hello"}]}`
	mockMessagesAnswer     = "Hello! How can I help?"
)

// delayedProviderCaller 在 Call / CallStreaming 之前先等 delay，模拟上游生成很久。
type delayedProviderCaller struct {
	MockProviderCaller
	delay time.Duration
}

func (d *delayedProviderCaller) wait(ctx context.Context) error {
	select {
	case <-time.After(d.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *delayedProviderCaller) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	if err := d.wait(ctx); err != nil {
		return nil, err
	}
	return d.MockProviderCaller.Call(ctx, envelope, providerReq)
}

func (d *delayedProviderCaller) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	if err := d.wait(ctx); err != nil {
		return nil, err
	}
	return d.MockProviderCaller.CallStreaming(ctx, envelope, providerReq)
}

func newMessagesKeepaliveHandler(caller ProviderCaller, security SecurityChecker, audit *MockAuditWriter, cfg *config.Config) *MessagesHandler {
	if security == nil {
		security = &MockSecurityChecker{}
	}
	if audit == nil {
		audit = &MockAuditWriter{}
	}
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
		ProviderType: "openai", ProviderBaseURL: "https://boflow.example",
		UpstreamModelID: "kiro-opus", Status: "active",
	}}
	return NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, security, audit, fixedAdapterFactory{caller: caller}, nil, nil)
}

func setMessagesBlockMode(h *MessagesHandler, mode string) {
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	client.runtimeCache.setSecurityAuditOnly(false)
	client.setBlockNoticeSettings(blockNoticeSettings{Mode: mode, Template: DefaultBlockNoticeTemplate})
	h.toolRiskClient = client
}

// kaEventNames 返回 body 里所有 `event: xxx` 的事件名（按出现顺序）。
func kaEventNames(body string) []string {
	var names []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "event: ") {
			names = append(names, strings.TrimPrefix(line, "event: "))
		}
	}
	return names
}

// kaFindEvent 解析指定名字的第一个 SSE 事件的 data JSON。
func kaFindEvent(t *testing.T, body, name string) map[string]any {
	t.Helper()
	marker := "event: " + name + "\ndata: "
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("event %q not found in %q", name, body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, "\n\n")
	if end < 0 {
		end = len(rest)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rest[:end]), &payload); err != nil {
		t.Fatalf("event %q data is not JSON: %v (%q)", name, err, rest[:end])
	}
	return payload
}

// 慢请求：响应头在上游返回前就到达客户端，之后是保活注释，最后是完整的 Anthropic 事件序列。
func TestMessagesKeepaliveSlowStreamHeadersEarlyThenFullEvents(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 260 * time.Millisecond}
	h := newMessagesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond})

	res := doKeepaliveHTTP(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	if res.headerAt >= 240*time.Millisecond {
		t.Fatalf("headers arrived after %v, keepalive did not start early", res.headerAt)
	}
	if res.status != http.StatusOK || !strings.Contains(res.header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status=%d ct=%q", res.status, res.header.Get("Content-Type"))
	}
	if res.header.Get("X-Request-Id") == "" {
		t.Fatalf("committed headers must carry X-Request-Id: %#v", res.header)
	}
	if strings.Count(res.body, ": keepalive\n\n") < 2 {
		t.Fatalf("expected repeated keepalive comments, got %q", res.body)
	}
	names := strings.Join(kaEventNames(res.body), ",")
	if !strings.HasPrefix(names, "message_start") || !strings.HasSuffix(names, "message_stop") {
		t.Fatalf("expected message_start..message_stop, got %s", names)
	}
	if strings.Index(res.body, ": keepalive") > strings.Index(res.body, "event: message_start") {
		t.Fatalf("keepalive must precede message events: %q", res.body)
	}
	if !strings.Contains(res.body, mockMessagesAnswer) {
		t.Fatalf("answer lost: %q", res.body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 快请求：与关闭保活（间隔 0）时状态码、完整响应头、正文逐字节一致。
func TestMessagesKeepaliveFastStreamByteIdenticalToDisabled(t *testing.T) {
	run := func(interval time.Duration) *httptest.ResponseRecorder {
		h := newMessagesKeepaliveHandler(&delayedProviderCaller{}, nil, nil, &config.Config{StreamKeepaliveInterval: interval})
		return serveKeepalivePlain(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)
	}
	off, on := run(0), run(time.Hour)
	assertSameKeepaliveResponse(t, off, on)
	if strings.Contains(on.Body.String(), ": keepalive") {
		t.Fatalf("fast request must not carry keepalive: %q", on.Body.String())
	}
}

// 慢请求 + 上游 429：头已发出后改发 event: error，审计仍记 provider_error/429。
func TestMessagesKeepaliveSlowUpstream429UsesSSEErrorEvent(t *testing.T) {
	audit := &MockAuditWriter{}
	upstreamErr := &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited", Body: []byte(`{"error":{"message":"rate limited"}}`)}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = upstreamErr
	h := newMessagesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	payload := kaFindEvent(t, body, "error")
	errObj, _ := payload["error"].(map[string]any)
	if payload["type"] != "error" || errObj["type"] != "rate_limit_error" {
		t.Fatalf("expected rate_limit_error event, got %v", payload)
	}
	if errObj["message"] != clientUpstreamErrorMessage(upstreamErr, "upstream Messages request failed") {
		t.Fatalf("message differs from the JSON error body: %v", errObj["message"])
	}
	if payload["request_id"] == "" || payload["request_id"] == nil {
		t.Fatalf("request_id missing: %v", payload)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_error" || audit.RequestLogFinalizes[0].StatusCode != http.StatusTooManyRequests {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 慢请求 + 非 HTTP 类上游故障（provider_unavailable）。
func TestMessagesKeepaliveSlowTransportErrorUsesSSEErrorEvent(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = errors.New("connection reset by peer")
	h := newMessagesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	payload := kaFindEvent(t, body, "error")
	errObj, _ := payload["error"].(map[string]any)
	if w.code() != http.StatusOK || errObj["type"] != "api_error" || errObj["message"] != "upstream Messages request failed" {
		t.Fatalf("code=%d payload=%v", w.code(), payload)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_unavailable" || audit.RequestLogFinalizes[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 慢请求 + 输出被拦截（error 模式）：流内 permission_error，内容不泄露，block_id 可见。
func TestMessagesKeepaliveSlowOutputBlockErrorModeUsesSSEErrorEvent(t *testing.T) {
	audit := &MockAuditWriter{}
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	h := newMessagesKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, security, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})
	setMessagesBlockMode(h, blockResponseModeError)

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	if strings.Contains(body, mockMessagesAnswer) {
		t.Fatalf("blocked content leaked: %q", body)
	}
	payload := kaFindEvent(t, body, "error")
	errObj, _ := payload["error"].(map[string]any)
	if errObj["type"] != "permission_error" {
		t.Fatalf("expected permission_error, got %v", payload)
	}
	if blockID, _ := errObj["block_id"].(string); !strings.HasPrefix(blockID, "evt_") {
		t.Fatalf("block_id must be visible in the error event: %v", errObj)
	}
	if msg, _ := errObj["message"].(string); !strings.Contains(msg, "JJDGuard") {
		t.Fatalf("message must carry the block notice: %v", errObj)
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

// 慢请求 + 输出被拦截（message 模式）：头已发出后事件序列与快请求相同，阻断说明作为助手消息展示。
func TestMessagesKeepaliveSlowOutputBlockMessageModeKeepsEventSequence(t *testing.T) {
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}

	fastHandler := newMessagesKeepaliveHandler(&delayedProviderCaller{}, security, nil, &config.Config{})
	setMessagesBlockMode(fastHandler, blockResponseModeMessage)
	fast := serveKeepalivePlain(t, fastHandler.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	slowHandler := newMessagesKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, security, nil, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})
	setMessagesBlockMode(slowHandler, blockResponseModeMessage)
	slow := serveKeepaliveFlush(t, slowHandler.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	slowBody := slow.body()
	if !strings.HasPrefix(slowBody, ": keepalive\n\n") {
		t.Fatalf("expected keepalive before block notice: %q", slowBody)
	}
	if got, want := strings.Join(kaEventNames(slowBody), ","), strings.Join(kaEventNames(fast.Body.String()), ","); got != want || got == "" {
		t.Fatalf("event sequence differs\nslow=%s\nfast=%s", got, want)
	}
	if strings.Contains(slowBody, mockMessagesAnswer) {
		t.Fatalf("blocked content leaked: %q", slowBody)
	}
	if !strings.Contains(slowBody, "JJDGuard") {
		t.Fatalf("block notice missing: %q", slowBody)
	}
	// 头已发出后不能再有第二个状态码或第二套 error 事件。
	if strings.Contains(slowBody, "event: error") {
		t.Fatalf("message mode must not emit an error event: %q", slowBody)
	}
}

// 上游返回的不是合法 Messages 流：头已发出后改发 event: error（502 / api_error），审计 provider_unavailable。
func TestMessagesKeepaliveSlowInvalidPayloadUsesSSEErrorEvent(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallResponse = []byte("this is not an SSE stream")
	h := newMessagesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	payload := kaFindEvent(t, w.body(), "error")
	errObj, _ := payload["error"].(map[string]any)
	if errObj["type"] != "api_error" || errObj["message"] != "upstream returned an invalid Messages payload" {
		t.Fatalf("payload=%v", payload)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_unavailable" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 非流式请求不受影响：没有保活字节，JSON 照旧。
func TestMessagesKeepaliveNonStreamUnaffected(t *testing.T) {
	h := newMessagesKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, nil, nil, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody0)

	body := w.body()
	if strings.Contains(body, "keepalive") {
		t.Fatalf("non-stream request must not carry keepalive: %q", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%q", ct)
	}
	var message map[string]any
	if err := json.Unmarshal([]byte(body), &message); err != nil || message["type"] != "message" {
		t.Fatalf("expected plain JSON message, got %q (%v)", body, err)
	}
}

// 输出扫描很慢（上游很快）：扫描期间同样要保活。
func TestMessagesKeepaliveCoversSlowOutputScan(t *testing.T) {
	security := slowOutputSecurity{MockSecurityChecker: &MockSecurityChecker{}, delay: 200 * time.Millisecond}
	h := newMessagesKeepaliveHandler(&delayedProviderCaller{}, security, nil, &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond})

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("slow output scan must be covered by keepalive: %q", body)
	}
	if !strings.Contains(body, mockMessagesAnswer) || !strings.HasSuffix(strings.TrimSpace(body), `{"type":"message_stop"}`) {
		t.Fatalf("expected full answer, got %q", body)
	}
}

// 开了上游实时流、但本次只能回退先攒后发（适配器不支持实时流）：回退期间也要保活。
func TestMessagesKeepaliveCoversLiveStreamFallbackToBuffered(t *testing.T) {
	cfg := &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond, UpstreamStreaming: true}
	h := newMessagesKeepaliveHandler(&delayedProviderCaller{delay: 160 * time.Millisecond}, nil, nil, cfg)

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("buffered fallback must keep the connection alive: %q", body)
	}
	if !strings.Contains(body, mockMessagesAnswer) || !strings.Contains(body, "event: message_stop") {
		t.Fatalf("expected full answer, got %q", body)
	}
}

// v2 路由路径：StreamSink 回退缓冲时同样保活。
func TestMessagesKeepaliveV2RouteSlowStream(t *testing.T) {
	for _, upstreamStreaming := range []bool{false, true} {
		caller := &delayedProviderCaller{delay: 150 * time.Millisecond}
		record := route("p1", "openai", "https://boflow.example", "kiro-opus")
		record.ModelName = "claude-opus-5"
		record.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
		engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: record}}
		cfg := &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond, UpstreamStreaming: upstreamStreaming}
		h := NewMessagesHandler(cfg, &MockModelResolver{ModelRecord: &record}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{},
			&MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": caller}}, nil, nil)
		h.SetModelRoutingEngine(engine)

		w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

		body := w.body()
		if !strings.Contains(body, ": keepalive") || !strings.Contains(body, "event: message_stop") || !strings.Contains(body, mockMessagesAnswer) {
			t.Fatalf("v2 route (live=%v) slow stream not covered: %q", upstreamStreaming, body)
		}
	}
}

// 间隔与上游耗时同量级时反复触发提交/收尾的边界，配合 -race 检查 Finish 之后才写 w。
func TestMessagesKeepaliveRaceStress(t *testing.T) {
	scenarios := []struct {
		name     string
		caller   func() *delayedProviderCaller
		security SecurityChecker
		wantTail string // 每个响应都必须以它收尾：成功是 message_stop，失败/拦截是 error 事件
	}{
		{"success", func() *delayedProviderCaller { return &delayedProviderCaller{delay: 6 * time.Millisecond} }, nil, "message_stop"},
		{"upstream_error", func() *delayedProviderCaller {
			c := &delayedProviderCaller{delay: 6 * time.Millisecond}
			c.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "x"}
			return c
		}, nil, "error"},
		{"blocked", func() *delayedProviderCaller { return &delayedProviderCaller{delay: 6 * time.Millisecond} },
			&MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}, "error"},
	}
	for _, sc := range scenarios {
		for i := 0; i < 40; i++ {
			h := newMessagesKeepaliveHandler(sc.caller(), sc.security, nil, &config.Config{StreamKeepaliveInterval: time.Duration(1+i%4) * time.Millisecond})
			w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)
			body := w.body()
			names := kaEventNames(body)
			// 间隔 1-4ms 对 6ms 的上游：有的轮次头已提前发出（200 + 流内事件），有的轮次没有（真实状态码 + JSON）。
			// 无论哪种，响应都必须是完整、自洽的，不能是空响应、半截流或混进第二个状态码。
			switch {
			case strings.Contains(body, "event: "):
				if w.code() != http.StatusOK || len(names) == 0 || names[len(names)-1] != sc.wantTail {
					t.Fatalf("%s #%d: committed stream must end with %q, code=%d body=%q", sc.name, i, sc.wantTail, w.code(), body)
				}
			case sc.wantTail == "message_stop":
				t.Fatalf("%s #%d: success must always carry the message events, code=%d body=%q", sc.name, i, w.code(), body)
			default: // 头未发出的失败/拦截：保持原来的 JSON 错误和真实状态码
				if w.code() < http.StatusBadRequest || !strings.Contains(body, `"type":"error"`) {
					t.Fatalf("%s #%d: uncommitted failure must keep the JSON error, code=%d body=%q", sc.name, i, w.code(), body)
				}
			}
		}
	}
}

// 构造 v2 双路由：第一条路由慢返回 429（可重试），让保活先提交头；第二条路由实现 StreamAdapter。
func newMessagesDualRouteHandler(second *liveRouteCaller, interval time.Duration, security SecurityChecker) *MessagesHandler {
	primary := route("p1", "openai", "https://boflow-1.example", "kiro-opus")
	primary.ModelName = "claude-opus-5"
	primary.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	fallback := route("p2", "openai", "https://boflow-2.example", "kiro-opus")
	fallback.ModelName = "claude-opus-5"
	fallback.ProtocolCapabilities = modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: primary, Fallbacks: []modelrouter.ModelRecord{fallback}}}
	if security == nil {
		security = &MockSecurityChecker{}
	}
	cfg := &config.Config{StreamKeepaliveInterval: interval, UpstreamStreaming: true}
	h := NewMessagesHandler(cfg, &MockModelResolver{ModelRecord: &primary}, &MockRateLimitChecker{}, security, &MockAuditWriter{},
		&MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{
			"p1": firstRouteTooManyRequests(150 * time.Millisecond),
			"p2": second,
		}}, nil, nil)
	h.SetModelRoutingEngine(engine)
	return h
}

// 保活先提交了头（第一条路由慢返回 429），路由层再尝试第二条（实现了 OpenStream 的）路由时，
// tryLive 必须看到 Stop()==true、不再尝试实时流（否则会和保活 goroutine 并发写 w，并写出第二个状态码）。
// 删掉 tryLive 里 `if keepalive.Stop() { keepalive.Start(); return false, nil }` 后，这个用例会失败：
// OpenStream 被调用 1 次，-race 下还会报 DATA RACE。
func TestMessagesKeepaliveV2DualRouteDoesNotGoLiveAfterHeadersCommitted(t *testing.T) {
	second := &liveRouteCaller{}
	h := newMessagesDualRouteHandler(second, 30*time.Millisecond, nil)

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	if n := second.openStreams.Load(); n != 0 {
		t.Fatalf("OpenStream called %d times after keepalive committed the headers, want 0", n)
	}
	if second.callCount.Load() != 1 {
		t.Fatalf("second route must be served through the buffered Call exactly once, got %d", second.callCount.Load())
	}
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	names := strings.Join(kaEventNames(body), ",")
	if !strings.HasPrefix(names, "message_start") || !strings.HasSuffix(names, "message_stop") || !strings.Contains(body, mockMessagesAnswer) {
		t.Fatalf("expected the complete buffered result, got events=%s body=%q", names, body)
	}
	if strings.Contains(body, "event: error") {
		t.Fatalf("unexpected error event: %q", body)
	}
}

// 同上，但第二条路由也失败 -> 头已发出后客户端收到的是流内错误，OpenStream 同样 0 次。
func TestMessagesKeepaliveV2DualRouteLiveRouteErrorAfterCommitUsesSSEError(t *testing.T) {
	second := &liveRouteCaller{}
	second.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusServiceUnavailable, Message: "overloaded"}
	h := newMessagesDualRouteHandler(second, 30*time.Millisecond, nil)

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	if n := second.openStreams.Load(); n != 0 {
		t.Fatalf("OpenStream called %d times after keepalive committed the headers, want 0", n)
	}
	payload := kaFindEvent(t, w.body(), "error")
	if errObj, _ := payload["error"].(map[string]any); w.code() != http.StatusOK || errObj["type"] != "api_error" {
		t.Fatalf("code=%d payload=%v", w.code(), payload)
	}
}

// 头已发出后的 provider_timeout（context.DeadlineExceeded）-> 流内 api_error，审计仍记 504。
func TestMessagesKeepaliveSlowDeadlineExceededUsesSSEErrorEvent(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = context.DeadlineExceeded
	h := newMessagesKeepaliveHandler(caller, nil, audit, &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond})

	w := serveKeepaliveFlush(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody)

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	payload := kaFindEvent(t, body, "error")
	errObj, _ := payload["error"].(map[string]any)
	if errObj["type"] != "api_error" || errObj["message"] != "upstream provider timed out" || payload["request_id"] == nil {
		t.Fatalf("payload=%v", payload)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_timeout" || audit.RequestLogFinalizes[0].StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 保活开启 + 实时流成功：上游立刻返回合法事件流，tryLive 走通实时流，不应出现任何保活字节，
// 状态码、完整响应头、正文与关闭保活时一致（实时流的随机 ID 先归一化）。
func TestMessagesKeepaliveLiveStreamSuccessMatchesKeepaliveDisabled(t *testing.T) {
	const sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-live\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5\",\"content\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"live-hello\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
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
			ID: "model-live", ProviderID: "provider-live", ModelName: "claude-opus-5", UpstreamModelID: "claude-opus-5",
			ProviderType: "anthropic", ProviderBaseURL: upstream.URL, Status: "active",
		}}
		cfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit", StreamKeepaliveInterval: interval}
		h := NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &RealProviderAdapterFactory{}, nil, nil)
		return serveKeepalivePlain(t, h.Handler(), messagesKeepalivePath, messagesKeepaliveBody), opened.Load()
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
