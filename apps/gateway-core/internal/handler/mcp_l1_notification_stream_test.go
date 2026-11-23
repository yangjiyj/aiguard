package handler

// L-1：只含通知的 POST，上游若回了 text/event-stream，网关不转发这条流（通知没有响应体），但必须留下痕迹：
// 日志说明「通知收到了非预期的响应流」并记录丢弃的消息数；流里有服务端反向请求（server→client request）时，
// 审计按现有 server_request 口径记成「已丢弃」（blocked、未转发），并替客户端向上游回一条拒绝，避免上游一直等待。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type sseNotificationUpstream struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newSSENotificationUpstream(t *testing.T, events string) *sseNotificationUpstream {
	u := &sseNotificationUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, string(raw))
		first := len(u.bodies) == 1
		u.mu.Unlock()
		if !first { // 之后网关发来的拒绝回执
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, events)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *sseNotificationUpstream) posted() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bodies...)
}

const sseNotifStream = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n\n" +
	"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n" +
	"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}\n\n"

func TestL1_NotificationSSEResponseIsDiscardedLoggedAndCounted(t *testing.T) {
	buf := captureLog(t)
	up := newSSENotificationUpstream(t, sseNotifStream)
	env := newGzipProxyEnv(t, up.srv.URL)
	w := env.do(t, http.MethodPost, notifInitialized, nil)
	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatalf("流不得转发给下游，通知仍回 202 空体: %d %q", w.Code, w.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, "通知收到了非预期的响应流") {
		t.Fatalf("必须记日志说明通知收到了非预期的响应流: %q", out)
	}
	if !strings.Contains(out, "已丢弃 3 条消息") || !strings.Contains(out, "服务端反向请求 1 条") {
		t.Fatalf("日志必须记录丢弃的消息数与反向请求数: %q", out)
	}
}

func TestL1_ReverseRequestsInADiscardedStreamAreAuditedAsDiscardedAndRejectedUpstream(t *testing.T) {
	up := newSSENotificationUpstream(t, sseNotifStream)
	env := newGzipProxyEnv(t, up.srv.URL)
	_ = env.do(t, http.MethodPost, notifInitialized, nil)
	var found bool
	for _, l := range env.logs() {
		name, _ := l["tool_name"].(string)
		if strings.Contains(name, "method:sampling/createMessage") {
			found = true
			if l["execution_forwarded"] != false {
				t.Fatalf("被丢弃的反向请求必须记 execution_forwarded=false: %#v", l)
			}
			if l["status"] != "blocked" {
				t.Fatalf("被丢弃的反向请求按现有口径记 blocked: %#v", l)
			}
		}
	}
	if !found {
		t.Fatalf("反向请求必须有审计行: %#v", env.logs())
	}
	// 上游收到了对 id=77 的拒绝回执，不会一直等待客户端响应
	var replied bool
	for _, b := range up.posted()[1:] {
		if strings.Contains(b, `"id":77`) && strings.Contains(b, `"error"`) {
			replied = true
		}
	}
	if !replied {
		t.Fatalf("应向上游回拒绝（id=77）: %v", up.posted())
	}
}

func TestL1_PlainStreamWithoutReverseRequestsStillLogsAndSendsNoRejection(t *testing.T) {
	buf := captureLog(t)
	up := newSSENotificationUpstream(t, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
	env := newGzipProxyEnv(t, up.srv.URL)
	w := env.do(t, http.MethodPost, notifInitialized, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d", w.Code)
	}
	if !strings.Contains(buf.String(), "已丢弃 1 条消息") || !strings.Contains(buf.String(), "服务端反向请求 0 条") {
		t.Fatalf("应记录 1 条消息、0 条反向请求: %q", buf.String())
	}
	if len(up.posted()) != 1 {
		t.Fatalf("没有反向请求时不应向上游发任何回执: %v", up.posted())
	}
}

// 非通知（带 id 的请求）的 SSE 响应照常透传，不受本项影响。
func TestL1_RequestsWithIdStillStreamTheirSSEResponse(t *testing.T) {
	up := newSSENotificationUpstream(t, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n")
	env := newGzipProxyEnv(t, up.srv.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"tools"`) {
		t.Fatalf("带 id 请求的 SSE 响应应透传: %d %q", w.Code, w.Body.String())
	}
}

// 无限长的流也不能拖死网关：读取有上限与超时，之后照常回 202。
func TestL1_EndlessNotificationStreamIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < 100000; i++ {
			if _, err := io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n"); err != nil {
				return
			}
			if fl != nil && i%200 == 0 {
				fl.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	env := newGzipProxyEnv(t, srv.URL)
	w := env.do(t, http.MethodPost, notifInitialized, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("无限流应被截断后回 202: %d", w.Code)
	}
}
