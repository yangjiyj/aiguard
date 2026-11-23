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

// 反向代理非流式：上游已回响应头，客户端在读响应体期间断开。上游请求绑在请求 ctx 上，
// io.ReadAll 必然失败——这是客户端断开，不是上游读失败，应记 cancelled/408，不记 failed。
// 对照组 TestReverseUpstreamBodyReadDeadlineIsStillFailed：请求仍活着时（总超时到期）读失败照旧记 failed。
func TestReverseClientGoneDuringUpstreamBodyRead(t *testing.T) {
	for _, cfg := range rcgConfigs {
		t.Run(cfg.name, func(t *testing.T) {
			e := newRCGEnv(t, rcgScenario{name: "body_read_gone", kind: rcgKindBlock}, cfg, "/none/", "application/json", "")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"id":"partial"`)
				w.(http.Flusher).Flush()
				e.cancel()
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
			}))
			t.Cleanup(upstream.Close)
			e.route.TargetURL = upstream.URL + "/v1/chat/completions"
			e.h.resolveEgressTarget = testEgressResolver(upstream.URL)

			w, err := e.forward(rcgChatRequest)
			if err != nil {
				t.Errorf("断开应干净结束, forwardRequest err=%v", err)
			}
			rec := e.lastRecord()
			if rec.Status != "cancelled" || rec.StatusCode != http.StatusRequestTimeout {
				t.Errorf("审计=%s/%d, want cancelled/408", rec.Status, rec.StatusCode)
			}
			if len(e.audit.securityEvents) != 0 {
				t.Errorf("断开不应写安全事件: %+v", e.audit.securityEvents)
			}
			if strings.Contains(w.Body.String(), "partial") {
				t.Errorf("未读完的上游正文不应写给客户端: %q", w.Body.String())
			}
			e.requireNoRetryQueued()
			e.requireDetachedAuditWrites()
		})
	}
}

func TestReverseUpstreamBodyReadDeadlineIsStillFailed(t *testing.T) {
	e := newRCGEnv(t, rcgScenario{name: "body_read_deadline", kind: rcgKindBlock}, rcgConfigs[0], "/none/", "application/json", "")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"partial"`)
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
	if err := e.h.forwardRequest(ctx, e.route, httptest.NewRecorder(), r); err == nil {
		t.Errorf("总超时到期读失败应返回错误")
	}
	if rec := e.lastRecord(); rec.Status != "failed" {
		t.Errorf("总超时到期被误判为客户端断开: status=%s", rec.Status)
	}
}
