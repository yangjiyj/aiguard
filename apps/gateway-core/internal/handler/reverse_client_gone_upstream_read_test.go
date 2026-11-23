package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 反向代理流式输出：上游已回 200，客户端随后断开。上游请求绑在请求 ctx 上，之后读流
// （reader.Next）或排空持有帧（pending 的 ctx 检查）都会拿到 Canceled——这不是上游断流，
// 不能记 output_stream_incomplete / failed，不入重试队列、不写终止帧，也不放出持有帧。
// 对照组 TestReverseClientGoneUpstreamTruncatedIsStillIncomplete：请求仍活着时上游真的断流，行为不变。

// rcgCancelOnHeader 在网关写出响应头（即上游 200 已到）时取消请求 ctx，模拟客户端此刻断开。
type rcgCancelOnHeader struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w rcgCancelOnHeader) WriteHeader(code int) {
	w.ResponseRecorder.WriteHeader(code)
	w.cancel()
}

func TestReverseClientGoneDuringUpstreamStreamRead(t *testing.T) {
	cases := []struct {
		name  string
		first string // 上游在响应头之后、挂起之前先发的内容
	}{
		{"headers_only", ""}, // 必定落在 reader.Next 读流的取消点
		{"first_chunk", rcgSSEChunk(rcgMarkerSmall)},
	}
	for _, tc := range cases {
		for _, cfg := range rcgConfigs {
			t.Run(tc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, rcgScenario{name: "upstream_read_gone", kind: rcgKindBlock}, cfg, "/none/", "text/event-stream", "")
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, tc.first)
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
					case <-time.After(10 * time.Second):
					}
				}))
				t.Cleanup(upstream.Close)
				e.route.TargetURL = upstream.URL + "/v1/chat/completions"
				e.h.resolveEgressTarget = testEgressResolver(upstream.URL)

				r := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(rcgChatRequest)).WithContext(e.ctx)
				r.Header.Set("Content-Type", "application/json")
				w := rcgCancelOnHeader{ResponseRecorder: httptest.NewRecorder(), cancel: e.cancel}
				if err := e.h.forwardRequest(e.ctx, e.route, w, r); err != nil {
					t.Errorf("断开应干净结束, forwardRequest err=%v", err)
				}
				rec := e.lastRecord()
				if rec.Status != "cancelled" {
					t.Errorf("审计状态=%s, want cancelled", rec.Status)
				}
				if rec.OutputSemanticStatus == "incomplete" || len(e.audit.securityEvents) != 0 {
					t.Errorf("客户端断开不应记 output_stream_incomplete: status=%q reason=%q events=%+v", rec.OutputSemanticStatus, rec.OutputSemanticReason, e.audit.securityEvents)
				}
				if body := w.Body.String(); body != "" {
					t.Errorf("断开不应写终止帧或放出持有帧: %q", body)
				}
				e.requireNoRetryQueued()
				e.requireDetachedAuditWrites()
			})
		}
	}
}

// 反向用例：请求 ctx 因总超时到期（DeadlineExceeded）而读流失败，不是客户端断开，仍记 output_stream_incomplete。
func TestReverseUpstreamStreamReadDeadlineIsStillIncomplete(t *testing.T) {
	e := newRCGEnv(t, rcgScenario{name: "upstream_read_deadline", kind: rcgKindBlock}, rcgConfigs[0], "/none/", "text/event-stream", "")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	t.Cleanup(upstream.Close)
	e.route.TargetURL = upstream.URL + "/v1/chat/completions"
	e.h.resolveEgressTarget = testEgressResolver(upstream.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(rcgChatRequest)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	_ = e.h.forwardRequest(ctx, e.route, httptest.NewRecorder(), r)
	rec := e.lastRecord()
	if rec.Status == "cancelled" {
		t.Fatalf("总超时到期被误判为客户端断开")
	}
	if got := e.incompleteEvents("output"); got != 1 {
		t.Errorf("总超时到期应记 1 条 output incomplete, got %d (status=%s reason=%q)", got, rec.Status, rec.OutputSemanticReason)
	}
}
