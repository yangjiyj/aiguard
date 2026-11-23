package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 三条协议（Messages / Responses / Gemini）保活测试共用的小工具。

type keepaliveHTTPResult struct {
	status   int
	header   http.Header
	headerAt time.Duration // 客户端从发请求到收到响应头的耗时
	body     string
}

// doKeepaliveHTTP 走真实 HTTP（httptest.Server），能测出"响应头在上游返回前就已到达客户端"。
func doKeepaliveHTTP(t *testing.T, h http.Handler, path, body string) keepaliveHTTPResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(setAuthInfo(r.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123")))
	}))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second} // 保活失效时别让测试无限挂住
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	headerAt := time.Since(start)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return keepaliveHTTPResult{status: resp.StatusCode, header: resp.Header, headerAt: headerAt, body: string(raw)}
}

// serveKeepaliveFlush 用并发安全且支持 Flush 的 recorder 跑一次请求（保活 goroutine 与 handler 会同时写）。
func serveKeepaliveFlush(t *testing.T, h http.Handler, path, body string) *flushRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123"))
	w := newFlushRecorder()
	h.ServeHTTP(w, req)
	return w
}

// serveKeepalivePlain 用普通 recorder 跑一次请求（快请求的逐字节对比用）。
func serveKeepalivePlain(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

var (
	kaUUIDPattern      = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	kaHex32Pattern     = regexp.MustCompile(`[0-9a-f]{32}`)
	kaEvtPattern       = regexp.MustCompile(`evt_[0-9a-zA-Z]+`)
	kaCreatedPattern   = regexp.MustCompile(`"(created|created_at)":\s*\d+`)
	kaTimestampPattern = regexp.MustCompile(`\b1[6-9]\d{8}\b`)
)

// normalizeKeepaliveRandom 把每次请求都会变的随机内容归一化：uuid、32 位 hex、evt_ 前缀的阻断编号、时间戳。
// 其余内容仍逐字节比较。
func normalizeKeepaliveRandom(s string) string {
	s = kaUUIDPattern.ReplaceAllString(s, "<uuid>")
	s = kaEvtPattern.ReplaceAllString(s, "evt_<id>")
	s = kaHex32Pattern.ReplaceAllString(s, "<hex32>")
	s = kaCreatedPattern.ReplaceAllString(s, `"$1":<ts>`)
	s = kaTimestampPattern.ReplaceAllString(s, "<ts>")
	return s
}

// canonicalHeader 把完整 Header() 排序后展开成稳定文本；值里的随机内容同样归一化。
func canonicalHeader(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		values := append([]string(nil), h[k]...)
		sort.Strings(values)
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\n", k, normalizeKeepaliveRandom(v))
		}
	}
	return b.String()
}

// assertSameKeepaliveResponse 断言快请求在"关闭保活"和"间隔大到用不上"两种配置下，
// 状态码、完整响应头（排序后）、正文逐字节一致；随机 ID 与时间戳先归一化。
func assertSameKeepaliveResponse(t *testing.T, off, on *httptest.ResponseRecorder) {
	t.Helper()
	if off.Code != on.Code {
		t.Fatalf("status differs: off=%d on=%d", off.Code, on.Code)
	}
	if offH, onH := canonicalHeader(off.Header()), canonicalHeader(on.Header()); offH != onH {
		t.Fatalf("headers differ\n--- off ---\n%s--- on ---\n%s", offH, onH)
	}
	if offB, onB := normalizeKeepaliveRandom(off.Body.String()), normalizeKeepaliveRandom(on.Body.String()); offB != onB {
		t.Fatalf("body differs\noff=%q\non=%q", offB, onB)
	}
}

// liveRouteCaller 是 v2 路由里"第二条路由"：实现 provider.StreamAdapter。
// 保活已提交头之后，路由层不应再让它走实时流；openStreams 记录 OpenStream 被调用的次数。
type liveRouteCaller struct {
	MockProviderCaller
	openStreams atomic.Int32
	callCount   atomic.Int32
	body        []byte
}

func (c *liveRouteCaller) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	c.callCount.Add(1)
	if c.body != nil {
		return c.body, nil
	}
	return c.MockProviderCaller.Call(ctx, envelope, providerReq)
}

func (c *liveRouteCaller) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	c.callCount.Add(1)
	if c.body != nil {
		return c.body, nil
	}
	// 与 MockProviderCaller.CallStreaming 一致：messages 流式默认返回完整 Anthropic SSE，其余走 Call 的默认响应。
	return c.MockProviderCaller.CallStreaming(ctx, envelope, providerReq)
}

// OpenStream 一旦被调用，路由层就会走实时流：它会往 w 里写（与保活 goroutine 并发写同一个 w），
// 也会再写一次响应头和状态码。这里返回一个真实可读的流，让"不该走实时流却走了"的实现
// 不只被计数器抓住，-race 下还会因两个 goroutine 同时写 w 而报 DATA RACE。
func (c *liveRouteCaller) OpenStream(context.Context, *modelrouter.RequestEnvelope, []byte) (relay.StreamReader, provider.StreamResponseMeta, error) {
	c.openStreams.Add(1)
	return &liveRelayReader{events: []relay.StreamEvent{
		{Type: relay.EventMessageStart, ID: "msg_live", Model: "claude-opus-5",
			Raw: []byte(`{"type":"message_start","message":{"id":"msg_live","type":"message","role":"assistant","model":"claude-opus-5","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}`)},
		{Type: relay.EventTextDelta, Index: 0, Delta: "live-output", Raw: []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"live-output"}}`)},
		{Type: relay.EventMessageEnd, FinishReason: "stop"},
	}}, provider.StreamResponseMeta{StatusCode: http.StatusOK}, nil
}

// firstRouteTooManyRequests 是 v2 双路由里"第一条路由"：慢返回 429（可重试），让保活先提交头，
// 路由层随后才尝试第二条路由。
func firstRouteTooManyRequests(delay time.Duration) *delayedProviderCaller {
	c := &delayedProviderCaller{delay: delay}
	c.CallError = &provider.UpstreamHTTPError{StatusCode: http.StatusTooManyRequests, Message: "rate limited"}
	return c
}
