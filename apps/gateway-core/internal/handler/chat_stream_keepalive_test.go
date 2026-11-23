package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// slowProviderCaller 模拟上游生成很久才返回（先攒后发路径的 Call）。
type slowProviderCaller struct {
	MockProviderCaller
	delay time.Duration
}

func (s *slowProviderCaller) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.MockProviderCaller.Call(ctx, envelope, providerReq)
}

func (s *slowProviderCaller) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	return s.Call(ctx, envelope, providerReq)
}

func keepaliveTestRequest(t *testing.T) *http.Request {
	t.Helper()
	body, _ := json.Marshal(ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}},
		Stream:   true,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))
}

// fixedAdapterFactory 对任意模型都返回同一个上游模拟器。
type fixedAdapterFactory struct{ caller ProviderCaller }

func (f fixedAdapterFactory) CreateAdapter(*modelrouter.ModelRecord, string) ProviderCaller {
	return f.caller
}

func newKeepaliveTestHandler(caller ProviderCaller, security *MockSecurityChecker, audit *MockAuditWriter, interval time.Duration) *ChatCompletionsHandler {
	cfg := &config.Config{StreamKeepaliveInterval: interval}
	return NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit, fixedAdapterFactory{caller: caller}, nil, nil)
}

// 间隔为 0 时，行为与改造前一致：只在攒完后才写响应头。
func TestStreamKeepaliveDisabledKeepsBufferedBehavior(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{delay: 120 * time.Millisecond}
	h := newKeepaliveTestHandler(caller, &MockSecurityChecker{}, audit, 0)

	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if strings.Contains(w.Body.String(), ": keepalive") {
		t.Fatalf("keepalive must not be written when disabled: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Hello! How can I help?") || !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("expected buffered answer, got %q", w.Body.String())
	}
}

// 快请求（在第一个间隔前就攒完）不发保活，响应和以前一模一样。
func TestStreamKeepaliveFastRequestUnchanged(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{delay: 0}
	h := newKeepaliveTestHandler(caller, &MockSecurityChecker{}, audit, 200*time.Millisecond)

	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	if strings.Contains(w.Body.String(), ": keepalive") {
		t.Fatalf("fast request must not carry keepalive: %q", w.Body.String())
	}
	if !strings.HasPrefix(w.Body.String(), "data: ") {
		t.Fatalf("expected plain SSE body, got %q", w.Body.String())
	}
}

// 快请求被上游 4xx 拒绝时仍是原来的 JSON 错误 + 原状态码。
func TestStreamKeepaliveFastUpstreamErrorKeepsHTTPStatus(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{}
	caller.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusBadRequest, Message: "bad model", Body: []byte(`{"error":{"message":"bad model"}}`)}
	h := newKeepaliveTestHandler(caller, &MockSecurityChecker{}, audit, 200*time.Millisecond)

	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%q", ct)
	}
}

// 慢请求：攒的过程中每个间隔写一行 SSE 注释，最终完整回放答案。
func TestStreamKeepaliveSlowRequestWritesCommentsThenAnswer(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{delay: 260 * time.Millisecond}
	h := newKeepaliveTestHandler(caller, &MockSecurityChecker{}, audit, 50*time.Millisecond)

	inner := h.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r.WithContext(setAuthInfo(r.Context(), "tenant-123", "project-123", "user-123", "key-123", "")))
	}))
	defer srv.Close()
	body, _ := json.Marshal(ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}, Stream: true})
	httpReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// 走真实 HTTP，确认首字节在上游返回前就已到达客户端。
	start := time.Now()
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	headerAt := time.Since(start)
	if headerAt >= 250*time.Millisecond {
		t.Fatalf("headers arrived after %v, keepalive did not start early", headerAt)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var lines []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	got := strings.Join(lines, "\n")
	if strings.Count(got, ": keepalive") < 2 {
		t.Fatalf("expected repeated keepalive comments, got %q", got)
	}
	if !strings.Contains(got, "Hello! How can I help?") || !strings.Contains(got, "data: [DONE]") {
		t.Fatalf("expected full answer after keepalive, got %q", got)
	}
	if idx := strings.Index(got, ": keepalive"); idx > strings.Index(got, "data: ") {
		t.Fatalf("keepalive must precede data frames: %q", got)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// 慢请求输出被拦截：内容不放出，用 SSE 错误帧告知，审计仍记 security_blocked。
func TestStreamKeepaliveSlowRequestBlockedUsesSSEErrorFrame(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{delay: 160 * time.Millisecond}
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	h := newKeepaliveTestHandler(caller, security, audit, 40*time.Millisecond)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if w.code() != http.StatusOK {
		t.Fatalf("headers already committed, status must stay 200, got %d", w.code())
	}
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected keepalive before block: %q", body)
	}
	if strings.Contains(body, "Hello! How can I help?") {
		t.Fatalf("blocked content leaked: %q", body)
	}
	if !strings.Contains(body, `"code":"security_blocked"`) || !strings.Contains(body, `"block_id":"evt_`) {
		t.Fatalf("expected SSE security_blocked frame with block_id, got %q", body)
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

// 慢请求上游报错：已发头后改用 SSE 错误帧，不再尝试写状态码。
func TestStreamKeepaliveSlowUpstreamErrorUsesSSEErrorFrame(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{delay: 120 * time.Millisecond}
	caller.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited", Body: []byte(`{"error":{"message":"rate limited"}}`)}
	h := newKeepaliveTestHandler(caller, &MockSecurityChecker{}, audit, 30*time.Millisecond)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if w.code() != http.StatusOK {
		t.Fatalf("status=%d", w.code())
	}
	if !strings.Contains(body, `"code":"upstream_error"`) || !strings.Contains(body, `"upstream_status":429`) {
		t.Fatalf("expected upstream_error frame with status, got %q", body)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "provider_error" {
		t.Fatalf("audit=%+v", audit.RequestLogFinalizes)
	}
}

// flushRecorder 是并发安全的 ResponseRecorder（保活 goroutine 与 handler 同时写）。
type flushRecorder struct {
	mu  sync.Mutex
	rec *httptest.ResponseRecorder
}

func newFlushRecorder() *flushRecorder { return &flushRecorder{rec: httptest.NewRecorder()} }

func (f *flushRecorder) Header() http.Header { return f.rec.Header() }
func (f *flushRecorder) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rec.Write(b)
}
func (f *flushRecorder) WriteHeader(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec.WriteHeader(code)
}
func (f *flushRecorder) Flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec.Flush()
}
func (f *flushRecorder) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rec.Body.String()
}
func (f *flushRecorder) code() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rec.Code
}

// 开了上游实时流、但本次只能回退先攒后发（上游适配器不支持实时流，脱敏/DLP 同理）：回退期间也要保活。
func TestStreamKeepaliveCoversLiveStreamFallbackToBuffered(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{delay: 160 * time.Millisecond}
	cfg := &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond, UpstreamStreaming: true}
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, fixedAdapterFactory{caller: caller}, nil, nil)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("buffered fallback must keep the connection alive: %q", body)
	}
	if !strings.Contains(body, "Hello! How can I help?") || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("expected full answer, got %q", body)
	}
}

// slowOutputSecurity 让输出扫描本身很慢（上游很快返回）。
type slowOutputSecurity struct {
	*MockSecurityChecker
	delay time.Duration
}

func (s slowOutputSecurity) CheckOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (string, string, []SecurityFinding, error) {
	time.Sleep(s.delay)
	return s.MockSecurityChecker.CheckOutput(ctx, envelope, content, choiceIndex)
}

// 上游快、输出扫描慢：扫描期间同样要保活（评审必须修项）。
func TestStreamKeepaliveCoversSlowOutputScan(t *testing.T) {
	audit := &MockAuditWriter{}
	caller := &slowProviderCaller{}
	security := slowOutputSecurity{MockSecurityChecker: &MockSecurityChecker{}, delay: 200 * time.Millisecond}
	cfg := &config.Config{StreamKeepaliveInterval: 40 * time.Millisecond}
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit, fixedAdapterFactory{caller: caller}, nil, nil)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("slow output scan must be covered by keepalive: %q", body)
	}
	if !strings.Contains(body, "Hello! How can I help?") || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("expected full answer, got %q", body)
	}
}

func newKeepaliveBlockModeHandler(t *testing.T, security SecurityChecker, audit *MockAuditWriter, mode string, interval time.Duration, delay time.Duration) *ChatCompletionsHandler {
	t.Helper()
	cfg := &config.Config{StreamKeepaliveInterval: interval}
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit, fixedAdapterFactory{caller: &slowProviderCaller{delay: delay}}, nil, nil)
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	client.runtimeCache.setSecurityAuditOnly(false)
	client.setBlockNoticeSettings(blockNoticeSettings{Mode: mode, Template: DefaultBlockNoticeTemplate})
	h.toolRiskClient = client
	return h
}

// message 模式：头已提交后拦截提示与快请求逐字节相同的帧（以助手消息展示，Dify 不报错直接显示阻断说明）。
func TestStreamKeepaliveMessageModeBlockMatchesFastRequestFrames(t *testing.T) {
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}

	fast := httptest.NewRecorder()
	newKeepaliveBlockModeHandler(t, security, &MockAuditWriter{}, blockResponseModeMessage, 0, 0).Handler().ServeHTTP(fast, keepaliveTestRequest(t))

	slow := newFlushRecorder()
	newKeepaliveBlockModeHandler(t, security, &MockAuditWriter{}, blockResponseModeMessage, 30*time.Millisecond, 120*time.Millisecond).Handler().ServeHTTP(slow, keepaliveTestRequest(t))

	slowBody := slow.body()
	if !strings.HasPrefix(slowBody, ": keepalive\n\n") {
		t.Fatalf("expected keepalive before block notice: %q", slowBody)
	}
	stripped := strings.ReplaceAll(slowBody, ": keepalive\n\n", "")
	normalize := func(s string) string {
		// 阻断编号/请求 ID/时间戳每次不同，按帧结构比较。
		var frames []string
		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
				frames = append(frames, line)
				continue
			}
			var chunk SSEChunk
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk); err != nil || len(chunk.Choices) != 1 {
				frames = append(frames, "unparsed:"+line)
				continue
			}
			c := chunk.Choices[0]
			frames = append(frames, c.Delta.Role+"|"+c.FinishReason+"|"+strings.SplitN(c.Delta.Content, "\n", 2)[0])
		}
		return strings.Join(frames, "\n")
	}
	if normalize(stripped) != normalize(fast.Body.String()) {
		t.Fatalf("message-mode frames differ\nslow=%q\nfast=%q", stripped, fast.Body.String())
	}
	if strings.Contains(slowBody, "Hello! How can I help?") {
		t.Fatalf("blocked content leaked: %q", slowBody)
	}
}

// 头已提交后输出检测不可用（管理员显式开启 fail-closed 时）：SSE 错误帧告知，审计仍记 security_blocked/503，内容不放出。
func TestStreamKeepaliveCommittedDetectionUnavailable(t *testing.T) {
	audit := &MockAuditWriter{}
	cfg := &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond}
	security := &MockSecurityChecker{OutputError: errors.New("engine down")}
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit,
		fixedAdapterFactory{caller: &slowProviderCaller{delay: 120 * time.Millisecond}}, nil, nil)
	h.toolRiskClient = failClosedClient(t, false, true)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if w.code() != http.StatusOK || !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed stream, code=%d body=%q", w.code(), body)
	}
	if !strings.Contains(body, `"code":"`+guardrailDetectionUnavailableCode+`"`) {
		t.Fatalf("expected detection-unavailable frame: %q", body)
	}
	if strings.Contains(body, "Hello! How can I help?") {
		t.Fatalf("content leaked without inspection: %q", body)
	}
	var found bool
	for _, f := range audit.RequestLogFinalizes {
		if f.Status == "security_blocked" && f.StatusCode == http.StatusServiceUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit must record security_blocked/503: %+v", audit.RequestLogFinalizes)
	}
}

// 关闭与"间隔大到用不上"两种情况下，快请求的状态码、关键头、正文逐字节一致。
func TestStreamKeepaliveFastRequestByteIdenticalToDisabled(t *testing.T) {
	run := func(interval time.Duration) *httptest.ResponseRecorder {
		h := newKeepaliveTestHandler(&slowProviderCaller{}, &MockSecurityChecker{}, &MockAuditWriter{}, interval)
		w := httptest.NewRecorder()
		h.Handler().ServeHTTP(w, keepaliveTestRequest(t))
		return w
	}
	off, on := run(0), run(time.Hour)
	if off.Code != on.Code {
		t.Fatalf("status differs: off=%d on=%d", off.Code, on.Code)
	}
	for _, k := range []string{"Content-Type", "Cache-Control", "X-Security-Action", "X-JJDGuard-Provider-ID"} {
		if off.Header().Get(k) != on.Header().Get(k) {
			t.Fatalf("header %s differs: off=%q on=%q", k, off.Header().Get(k), on.Header().Get(k))
		}
	}
	if off.Body.String() != on.Body.String() {
		t.Fatalf("body differs\noff=%q\non=%q", off.Body.String(), on.Body.String())
	}
}

// 头已由保活提交时，输出阶段的 mask 无法再写进 X-Security-Action，改随末帧扩展字段带出。
func TestStreamKeepaliveCarriesFinalSecurityActionInStream(t *testing.T) {
	security := &MockSecurityChecker{OutputAction: "mask", OutputMasked: "Hello! [MASKED]", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "medium"}}}
	cfg := &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond, SecurityActionHeader: true}
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, security, &MockAuditWriter{},
		fixedAdapterFactory{caller: &slowProviderCaller{delay: 120 * time.Millisecond}}, nil, nil)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("expected committed keepalive: %q", body)
	}
	if !strings.Contains(body, `"`+streamSecurityActionField+`":"mask"`) {
		t.Fatalf("final security action must ride in the stream: %q", body)
	}

	// 快请求仍走响应头，帧里不出现扩展字段（与改造前逐字节一致）。
	fast := httptest.NewRecorder()
	cfg2 := &config.Config{StreamKeepaliveInterval: time.Hour, SecurityActionHeader: true}
	h2 := NewChatCompletionsHandler(cfg2, &MockModelResolver{}, &MockRateLimitChecker{}, security, &MockAuditWriter{}, fixedAdapterFactory{caller: &slowProviderCaller{}}, nil, nil)
	h2.Handler().ServeHTTP(fast, keepaliveTestRequest(t))
	if fast.Header().Get(SecurityActionHeader) != "mask" || strings.Contains(fast.Body.String(), streamSecurityActionField) {
		t.Fatalf("fast request must keep header-only action: header=%q body=%q", fast.Header().Get(SecurityActionHeader), fast.Body.String())
	}
}

// message 模式慢请求被拦截：头已提交，block 改随 [DONE] 前一帧 choices 为空的扩展字段带出，
// 否则门户读不到 X-Security-Action，会把阻断说明当正常回答落库并带进下一轮上下文。
func TestStreamKeepaliveMessageModeBlockCarriesActionInStream(t *testing.T) {
	security := &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "critical"}}}
	run := func(interval, delay time.Duration, headerOn bool) (string, string) {
		h := newKeepaliveBlockModeHandler(t, security, &MockAuditWriter{}, blockResponseModeMessage, interval, delay)
		h.cfg.SecurityActionHeader = headerOn
		w := newFlushRecorder()
		h.Handler().ServeHTTP(w, keepaliveTestRequest(t))
		return w.body(), w.Header().Get(SecurityActionHeader)
	}

	body, _ := run(30*time.Millisecond, 120*time.Millisecond, true)
	if !strings.HasPrefix(body, ": keepalive\n\n") {
		t.Fatalf("expected committed keepalive: %q", body)
	}
	fieldFrame := `"choices":[],"created"`
	if !strings.Contains(body, `"`+streamSecurityActionField+`":"block"`) || !strings.Contains(body, fieldFrame) {
		t.Fatalf("message-mode block must carry action in an empty-choices frame: %q", body)
	}
	if idx := strings.Index(body, streamSecurityActionField); idx < 0 || idx > strings.Index(body, "data: [DONE]") {
		t.Fatalf("action frame must precede [DONE]: %q", body)
	}

	// 开关关闭（含审计只读下的默认开关）时不写字段，与 X-Security-Action 同一口径。
	if body, _ := run(30*time.Millisecond, 120*time.Millisecond, false); strings.Contains(body, streamSecurityActionField) {
		t.Fatalf("action field must follow the header switch: %q", body)
	}

	// 快请求仍只走响应头。
	fastBody, fastHeader := run(time.Hour, 0, true)
	if fastHeader != "block" || strings.Contains(fastBody, streamSecurityActionField) {
		t.Fatalf("fast request must keep header-only action: header=%q body=%q", fastHeader, fastBody)
	}
}

// 审计只读且安全动作头为默认开启时，末帧扩展字段与响应头一样不写。
func TestStreamKeepaliveAuditOnlyDefaultedHeaderOmitsActionField(t *testing.T) {
	security := &MockSecurityChecker{OutputAction: "mask", OutputMasked: "Hello! [MASKED]", OutputFindings: []SecurityFinding{{Type: "pii", Severity: "medium"}}}
	cfg := &config.Config{StreamKeepaliveInterval: 30 * time.Millisecond, SecurityActionHeader: true, SecurityActionHeaderDefaulted: true, SecurityAuditOnly: true}
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, security, &MockAuditWriter{},
		fixedAdapterFactory{caller: &slowProviderCaller{delay: 120 * time.Millisecond}}, nil, nil)

	w := newFlushRecorder()
	h.Handler().ServeHTTP(w, keepaliveTestRequest(t))

	body := w.body()
	if !strings.Contains(body, ": keepalive") || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("expected committed stream: %q", body)
	}
	if strings.Contains(body, streamSecurityActionField) {
		t.Fatalf("audit-only defaulted header must not expose action in stream: %q", body)
	}
}

// 直接测保活器本身：nil 安全、Finish 幂等、写失败自行退出。
func TestStreamKeepaliveHelperLifecycle(t *testing.T) {
	var nilK *streamKeepalive
	if nilK.Finish() {
		t.Fatal("nil keepalive must report not committed")
	}
	if startStreamKeepalive(httptest.NewRecorder(), 0, false, nil) != nil {
		t.Fatal("interval 0 must not start keepalive")
	}
	if startStreamKeepalive(nonFlusherWriter{httptest.NewRecorder()}, time.Second, false, nil) != nil {
		t.Fatal("writer without Flush must not start keepalive")
	}
	fw := &failingWriter{header: http.Header{}}
	k := startStreamKeepalive(fw, 10*time.Millisecond, false, nil)
	time.Sleep(60 * time.Millisecond)
	if !k.Finish() {
		t.Fatal("headers were written before the write failure")
	}
	if fw.writes != 1 {
		t.Fatalf("keepalive must stop after the first failed write, writes=%d", fw.writes)
	}
}

type nonFlusherWriter struct{ http.ResponseWriter }

type failingWriter struct {
	header http.Header
	writes int
	code   int
}

func (f *failingWriter) Header() http.Header  { return f.header }
func (f *failingWriter) WriteHeader(code int) { f.code = code }
func (f *failingWriter) Write([]byte) (int, error) {
	f.writes++
	return 0, http.ErrHandlerTimeout
}
func (f *failingWriter) Flush() {}
