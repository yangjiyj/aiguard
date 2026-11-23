package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// 流末 checkStreamInspection 的窗口循环里「前面窗口先出结果、后面窗口扫描期间断开」。
// copyGuardedReverseSSE 会带着前面窗口合并出的 decision 返回断开哨兵，流式收尾要区分：
//   - engine_500：前面窗口真实检测失败（已入重试队列、合并出 incomplete，fail-closed 下还有 block）。
//     不能对已中止的请求再写 security_check_failed 或无命中的 security_blocked，已入队的任务照常保留。
//   - real_finding：前面窗口真实命中。命中是留证，断开也照常落安全事件。
func TestReverseClientGoneStreamFinalScanEarlierWindowThenGone(t *testing.T) {
	sse := rcgSSEChunk(strings.Repeat("a", 40000)) + rcgSSEDone // 32768 窗口 + 1024 重叠 => 流末 2 个窗口
	cases := []struct {
		name       string
		window0    func(w http.ResponseWriter)
		wantQueued int
		wantEvents int
	}{
		{"engine_500", func(w http.ResponseWriter) { http.Error(w, "engine exploded", http.StatusInternalServerError) }, 1, 0},
		{"real_finding", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"action":"audit","inspection_status":"completed","engine_build":"rcg","findings":[{"rule_id":"rcg-1","severity":"high","type":"prompt_injection"}]}`)
		}, 0, 1},
	}
	for _, tc := range cases {
		for _, cfg := range rcgConfigs {
			t.Run(tc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, rcgScenario{name: tc.name, kind: rcgKindBlock}, cfg, "/none/", "text/event-stream", sse)
				var once sync.Once
				engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					switch {
					case strings.Contains(string(body), `"output_window_start":0`):
						tc.window0(w)
						return
					case strings.Contains(string(body), `"output_window_start"`):
						once.Do(e.cancel)
						select {
						case <-r.Context().Done():
						case <-time.After(10 * time.Second):
						}
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, rcgAllowJSON)
				}))
				t.Cleanup(engine.Close)
				e.h.securityURL = engine.URL

				w, err := e.forward(rcgChatRequest)
				if err != nil {
					t.Errorf("断开应干净结束, forwardRequest err=%v", err)
				}
				rec := e.lastRecord()
				if rec.Status != "cancelled" {
					t.Errorf("审计状态=%s, want cancelled", rec.Status)
				}
				if rec.OutputSemanticStatus == "incomplete" || e.incompleteEvents("output") != 0 {
					t.Errorf("断开收尾不应带入此前窗口的 incomplete: status=%q events=%+v", rec.OutputSemanticStatus, e.audit.securityEvents)
				}
				if got := len(e.audit.securityEvents); got != tc.wantEvents {
					t.Errorf("安全事件 %d 条, want %d（失败不留事件、真实命中照常留证）: %+v", got, tc.wantEvents, e.audit.securityEvents)
				}
				for _, ev := range e.audit.securityEvents {
					if len(ev.findings) == 0 {
						t.Errorf("断开收尾不应写无命中的安全事件: %+v", ev)
					}
				}
				if rcgHasTerminationFrame(w.Body.String()) {
					t.Errorf("断开不应写拦截/终止帧: %q", w.Body.String())
				}
				if got := e.queue.count(); got != tc.wantQueued {
					t.Errorf("重试队列 %d 次, want %d", got, tc.wantQueued)
				}
				if len(rec.OutputRetryIDs) != tc.wantQueued {
					t.Errorf("已入队的重试任务应照常记在审计上, OutputRetryIDs=%v", rec.OutputRetryIDs)
				}
				e.requireDetachedAuditWrites()
			})
		}
	}
}
