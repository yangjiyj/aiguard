package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

const (
	geminiKeepaliveStreamPath = "/v1beta/models/gpt-4:streamGenerateContent?alt=sse"
	geminiKeepalivePlainPath  = "/v1beta/models/gpt-4:generateContent"
	geminiKeepaliveBody       = `{"contents":[{"role":"user","parts":[{"text":"Hello"}]}]}`
	geminiMockAnswer          = "Hello! How can I help?"
)

func newGeminiKeepaliveHandler(caller ProviderCaller, security SecurityChecker, audit *MockAuditWriter, interval time.Duration) (*GeminiIngressHandler, *ChatCompletionsHandler) {
	if security == nil {
		security = &MockSecurityChecker{}
	}
	if audit == nil {
		audit = &MockAuditWriter{}
	}
	// 内层 chat 的配置也开着保活：它拿到的是不支持 Flush 的 geminiCapture，保活应当不会在内层启动。
	chat := NewChatCompletionsHandler(&config.Config{StreamKeepaliveInterval: interval}, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit,
		fixedAdapterFactory{caller: caller}, nil, nil)
	return NewGeminiIngressHandler(&config.Config{StreamKeepaliveInterval: interval}, chat.Handler()), chat
}

// geminiDataFrames 取出正文里所有 `data: {...}` 帧的 JSON。
func geminiDataFrames(t *testing.T, body string) []map[string]any {
	t.Helper()
	var frames []map[string]any
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
			t.Fatalf("data frame is not JSON: %v (%q)", err, line)
		}
		frames = append(frames, payload)
	}
	return frames
}

// geminiKeepaliveLeading 返回第一帧 data 之前的内容；Gemini 的保活只能是空行，不能出现 SSE 注释。
func geminiKeepaliveLeading(body string) string {
	idx := strings.Index(body, "data: ")
	if idx < 0 {
		return body
	}
	return body[:idx]
}

func TestGeminiKeepaliveSlowStreamHeadersEarlyThenCandidates(t *testing.T) {
	audit := &MockAuditWriter{}
	h, _ := newGeminiKeepaliveHandler(&delayedProviderCaller{delay: 260 * time.Millisecond}, nil, audit, 40*time.Millisecond)

	res := doKeepaliveHTTP(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)

	if res.headerAt >= 240*time.Millisecond {
		t.Fatalf("headers arrived after %v, keepalive did not start early", res.headerAt)
	}
	if res.status != http.StatusOK || !strings.Contains(res.header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status=%d ct=%q", res.status, res.header.Get("Content-Type"))
	}
	if res.header.Get("Cache-Control") != "no-store" || res.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("committed headers must match the success path: %#v", res.header)
	}
	if strings.Contains(res.body, ": keepalive") || strings.Contains(res.body, ":keepalive") {
		t.Fatalf("Gemini clients reject SSE comments, got %q", res.body)
	}
	leading := geminiKeepaliveLeading(res.body)
	if len(leading) < 2 || strings.Trim(leading, "\n") != "" {
		t.Fatalf("expected repeated bare newlines before the first data frame, got %q", leading)
	}
	frames := geminiDataFrames(t, res.body)
	if len(frames) != 1 {
		t.Fatalf("expected exactly one data frame, got %q", res.body)
	}
	candidates, _ := frames[0]["candidates"].([]any)
	if len(candidates) != 1 || !strings.Contains(res.body, geminiMockAnswer) {
		t.Fatalf("candidates missing: %q", res.body)
	}
	if !strings.HasSuffix(res.body, "\n\n") {
		t.Fatalf("data frame must end with a blank line: %q", res.body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 用 flushRecorder 也走一遍（保活 goroutine 与 handler 同时写 w，-race 下检查）。
func TestGeminiKeepaliveSlowStreamWithFlushRecorder(t *testing.T) {
	h, _ := newGeminiKeepaliveHandler(&delayedProviderCaller{delay: 150 * time.Millisecond}, nil, nil, 30*time.Millisecond)

	w := serveKeepaliveFlush(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)

	body := w.body()
	if w.code() != http.StatusOK || strings.Contains(body, ":") && strings.Contains(geminiKeepaliveLeading(body), ":") {
		t.Fatalf("code=%d body=%q", w.code(), body)
	}
	if strings.Trim(geminiKeepaliveLeading(body), "\n") != "" || len(geminiKeepaliveLeading(body)) == 0 {
		t.Fatalf("expected leading newlines: %q", body)
	}
	if len(geminiDataFrames(t, body)) != 1 {
		t.Fatalf("body=%q", body)
	}
}

func TestGeminiKeepaliveFastStreamByteIdenticalToDisabled(t *testing.T) {
	run := func(interval time.Duration) *httptest.ResponseRecorder {
		h, _ := newGeminiKeepaliveHandler(&delayedProviderCaller{}, nil, nil, interval)
		return serveKeepalivePlain(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)
	}
	off, on := run(0), run(time.Hour)
	// 完整响应头 + 状态码 + 正文；responseId 由请求 ID 派生、每次不同，归一化后其余逐字节一致。
	assertSameKeepaliveResponse(t, off, on)
	if !strings.HasPrefix(on.Body.String(), "data: ") {
		t.Fatalf("fast request must start with the data frame: %q", on.Body.String())
	}
}

func TestGeminiKeepaliveSlowUpstream429UsesStreamErrorFrame(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	upstreamErr := &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited", Body: []byte(`{"error":{"message":"rate limited"}}`)}
	caller.CallError = upstreamErr
	h, _ := newGeminiKeepaliveHandler(caller, nil, audit, 30*time.Millisecond)

	w := serveKeepaliveFlush(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)

	body := w.body()
	if w.code() != http.StatusOK || strings.Trim(geminiKeepaliveLeading(body), "\n") != "" || len(geminiKeepaliveLeading(body)) == 0 {
		t.Fatalf("expected committed stream with newline keepalive, code=%d body=%q", w.code(), body)
	}
	frames := geminiDataFrames(t, body)
	if len(frames) != 1 {
		t.Fatalf("expected one error frame, got %q", body)
	}
	errObj, _ := frames[0]["error"].(map[string]any)
	if errObj["code"] != float64(429) || errObj["status"] != "RESOURCE_EXHAUSTED" || errObj["message"] == "" || errObj["message"] == nil {
		t.Fatalf("error frame=%v", frames[0])
	}
	if strings.Contains(body, "candidates") {
		t.Fatalf("an error stream must not carry candidates: %q", body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_error" || audit.RequestLogFinalizes[0].StatusCode != http.StatusTooManyRequests {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

func TestGeminiKeepaliveSlowTransportErrorUsesStreamErrorFrame(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &delayedProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = errors.New("connection reset by peer")
	h, _ := newGeminiKeepaliveHandler(caller, nil, audit, 30*time.Millisecond)

	w := serveKeepaliveFlush(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)

	frames := geminiDataFrames(t, w.body())
	if w.code() != http.StatusOK || len(frames) != 1 {
		t.Fatalf("code=%d body=%q", w.code(), w.body())
	}
	errObj, _ := frames[0]["error"].(map[string]any)
	if errObj["code"] != float64(502) || errObj["status"] != "UNAVAILABLE" {
		t.Fatalf("error frame=%v", frames[0])
	}
}

func TestGeminiKeepaliveSlowOutputBlockUsesStreamErrorFrame(t *testing.T) {
	audit := &MockAuditWriter{}
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	h, chat := newGeminiKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, security, audit, 30*time.Millisecond)
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	client.runtimeCache.setSecurityAuditOnly(false)
	client.setBlockNoticeSettings(blockNoticeSettings{Mode: blockResponseModeError, Template: DefaultBlockNoticeTemplate})
	chat.toolRiskClient = client

	w := serveKeepaliveFlush(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)

	body := w.body()
	if w.code() != http.StatusOK || len(geminiKeepaliveLeading(body)) == 0 {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	if strings.Contains(body, geminiMockAnswer) || strings.Contains(body, "candidates") {
		t.Fatalf("blocked content leaked: %q", body)
	}
	frames := geminiDataFrames(t, body)
	if len(frames) != 1 {
		t.Fatalf("expected one error frame, got %q", body)
	}
	errObj, _ := frames[0]["error"].(map[string]any)
	if errObj["code"] != float64(403) || errObj["status"] != "PERMISSION_DENIED" {
		t.Fatalf("error frame=%v", frames[0])
	}
	if msg, _ := errObj["message"].(string); !strings.Contains(msg, "evt_") || !strings.Contains(msg, "JJDGuard") {
		t.Fatalf("block notice with block id must be visible: %v", errObj)
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

func TestGeminiKeepaliveNonStreamUnaffected(t *testing.T) {
	h, _ := newGeminiKeepaliveHandler(&delayedProviderCaller{delay: 120 * time.Millisecond}, nil, nil, 30*time.Millisecond)

	w := serveKeepaliveFlush(t, h.Handler(), geminiKeepalivePlainPath, geminiKeepaliveBody)

	body := w.body()
	if strings.HasPrefix(body, "\n") || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("non-stream response must be plain JSON: ct=%q body=%q", w.Header().Get("Content-Type"), body)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil || payload["candidates"] == nil {
		t.Fatalf("expected plain Gemini JSON, got %q (%v)", body, err)
	}
}

// 内层 chat 拿到的是不支持 Flush 的 geminiCapture，保活不会在内层启动（只有 Gemini 外层这一处在写 w）。
func TestGeminiKeepaliveInnerChatDoesNotStartOwnKeepalive(t *testing.T) {
	var sawFlusher bool
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawFlusher = w.(http.Flusher)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-x","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	})
	h := NewGeminiIngressHandler(&config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}, probe)

	w := serveKeepaliveFlush(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)

	if sawFlusher {
		t.Fatalf("inner chat handler must see a non-Flusher writer")
	}
	if len(geminiDataFrames(t, w.body())) != 1 {
		t.Fatalf("body=%q", w.body())
	}
}

// 间隔与上游耗时同量级，反复触发提交/收尾边界，配合 -race 检查 Finish 之后才写 w。
func TestGeminiKeepaliveRaceStress(t *testing.T) {
	block := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	scenarios := []struct {
		name     string
		caller   func() *delayedProviderCaller
		security SecurityChecker
	}{
		{"success", func() *delayedProviderCaller { return &delayedProviderCaller{delay: 6 * time.Millisecond} }, nil},
		{"upstream_error", func() *delayedProviderCaller {
			c := &delayedProviderCaller{delay: 6 * time.Millisecond}
			c.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "x"}
			return c
		}, nil},
		{"blocked", func() *delayedProviderCaller { return &delayedProviderCaller{delay: 6 * time.Millisecond} }, block},
	}
	for _, sc := range scenarios {
		for i := 0; i < 40; i++ {
			h, _ := newGeminiKeepaliveHandler(sc.caller(), sc.security, nil, time.Duration(1+i%4)*time.Millisecond)
			w := serveKeepaliveFlush(t, h.Handler(), geminiKeepaliveStreamPath, geminiKeepaliveBody)
			body := w.body()
			// 间隔 1-4ms 对 6ms 的上游：有的轮次头已提前发出（200 + 换行保活 + 一帧 data），
			// 有的轮次没有（成功是 200 + 一帧 data，失败/拦截是真实状态码 + JSON 错误）。
			// 无论哪种，响应都必须恰好带一帧终结 data（成功是 candidates，失败是 error），不能是空响应或多帧。
			frames := geminiDataFrames(t, body)
			switch {
			case strings.HasPrefix(strings.TrimLeft(body, "\n"), "data: "):
				if strings.Trim(geminiKeepaliveLeading(body), "\n") != "" {
					t.Fatalf("%s #%d: only blank-line keepalives may precede the terminal frame, body=%q", sc.name, i, body)
				}
				if w.code() != http.StatusOK || len(frames) != 1 {
					t.Fatalf("%s #%d: committed stream must carry exactly one terminal frame, code=%d body=%q", sc.name, i, w.code(), body)
				}
				if _, isError := frames[0]["error"]; isError != (sc.name != "success") {
					t.Fatalf("%s #%d: wrong terminal frame kind: %v", sc.name, i, frames[0])
				}
			default:
				if sc.name == "success" || w.code() < http.StatusBadRequest || !strings.Contains(body, `"error"`) {
					t.Fatalf("%s #%d: uncommitted response is not self-consistent, code=%d body=%q", sc.name, i, w.code(), body)
				}
			}
		}
	}
}

// 生产里 Gemini 处理器外面还有 GeminiAuthentication 的 geminiAuthResponse（带 Flush，4xx 会被拦截重写）。
// 走这一层、用真实 HTTP，确认保活、成功帧和头已发出后的流内错误帧都能穿过去，且状态码保持 200。
func TestGeminiKeepaliveThroughAuthenticationWrapper(t *testing.T) {
	passThrough := func(next http.Handler) http.Handler { return next }
	build := func(caller ProviderCaller) http.Handler {
		h, _ := newGeminiKeepaliveHandler(caller, nil, nil, 30*time.Millisecond)
		return GeminiAuthentication(passThrough, h.Handler(), false)
	}

	ok := doKeepaliveHTTP(t, build(&delayedProviderCaller{delay: 200 * time.Millisecond}), geminiKeepaliveStreamPath, geminiKeepaliveBody)
	if ok.headerAt >= 190*time.Millisecond || ok.status != http.StatusOK || len(geminiKeepaliveLeading(ok.body)) == 0 || len(geminiDataFrames(t, ok.body)) != 1 {
		t.Fatalf("success through wrapper: headerAt=%v status=%d body=%q", ok.headerAt, ok.status, ok.body)
	}

	failing := &delayedProviderCaller{delay: 120 * time.Millisecond}
	failing.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited"}
	bad := doKeepaliveHTTP(t, build(failing), geminiKeepaliveStreamPath, geminiKeepaliveBody)
	frames := geminiDataFrames(t, bad.body)
	if bad.status != http.StatusOK || len(frames) != 1 {
		t.Fatalf("error through wrapper: status=%d body=%q", bad.status, bad.body)
	}
	if errObj, _ := frames[0]["error"].(map[string]any); errObj["code"] != float64(429) || errObj["status"] != "RESOURCE_EXHAUSTED" {
		t.Fatalf("error frame=%v", frames[0])
	}
}
