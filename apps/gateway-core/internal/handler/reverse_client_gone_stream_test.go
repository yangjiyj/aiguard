package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 反向代理流式输出（copyGuardedReverseSSE）：客户端在输出扫描期间断开。
// 流式分支在扫描前就已写出 200 头，所以这里断言的是审计状态与客户端实际收到的字节：
// 断开 -> status cancelled，不写 incomplete，不写拦截/终止帧，不 flush 持有帧，不入重试队列；
// 对照组 -> 原行为（incomplete 事件、入队、fail-closed 终止帧）。

const (
	rcgMarkerBig   = "aaaaaaaaaaaaaaaa" // BigSSE 的 delta 内容片段
	rcgMarkerSmall = "hello stream"     // SmallSSE 的 delta 内容
)

func rcgHasTerminationFrame(body string) bool {
	return strings.Contains(body, guardrailDetectionUnavailableCode) || strings.Contains(body, "output_security_blocked")
}

type rcgStreamCase struct {
	name   string
	sse    string
	marker string
}

// mid_stream_scan：单个 delta 超过 1021 字节，流中立刻触发增量扫描；
// final_scan：delta 太短，只有流末 checkStreamInspection 会扫。
var rcgStreamCases = []rcgStreamCase{
	{"mid_stream_scan", rcgBigSSE(), rcgMarkerBig},
	{"final_scan", rcgSmallSSE(), rcgMarkerSmall},
}

// 经 forwardRequest 的完整路径：校验审计状态、客户端字节、事件、重试队列。
func TestReverseClientGoneStreamMatrix(t *testing.T) {
	for _, tc := range rcgStreamCases {
		for _, sc := range rcgScenarios {
			for _, cfg := range rcgConfigs {
				t.Run(tc.name+"/"+sc.name+"/"+cfg.name, func(t *testing.T) {
					e := newRCGEnv(t, sc, cfg, "/check-output/", "text/event-stream", tc.sse)
					w, err := e.forward(rcgChatRequest)
					rec := e.lastRecord()
					body := w.Body.String()
					if sc.gone {
						if err != nil {
							t.Errorf("断开应干净结束, forwardRequest err=%v", err)
						}
						if rec.Status != "cancelled" {
							t.Errorf("审计状态=%s, want cancelled", rec.Status)
						}
						if rec.StatusCode != http.StatusOK {
							t.Errorf("流式分支 200 头已写出, 审计 status_code=%d, want 200", rec.StatusCode)
						}
						if rec.OutputSemanticStatus == "incomplete" || e.incompleteEvents("output") != 0 || len(e.audit.securityEvents) != 0 {
							t.Errorf("断开不应记 incomplete/安全事件: status=%q events=%+v", rec.OutputSemanticStatus, e.audit.securityEvents)
						}
						if rcgHasTerminationFrame(body) {
							t.Errorf("断开不应写拦截/终止帧: %q", body)
						}
						if strings.Contains(body, tc.marker) {
							t.Errorf("断开不应 flush 持有帧: %q", body)
						}
						e.requireNoRetryQueued()
						e.requireDetachedAuditWrites()
						return
					}
					if got := e.incompleteEvents("output"); got != 1 {
						t.Errorf("对照组应写 1 条 output incomplete 事件, got %d", got)
					}
					if got := e.queue.count(); got != 1 {
						t.Errorf("对照组应入重试队列 1 次, got %d", got)
					}
					if cfg.enforcing() {
						if rec.Status != "blocked" || !strings.Contains(body, guardrailDetectionUnavailableCode) {
							t.Errorf("fail-closed 对照组应 blocked + 终止帧: status=%s body=%q", rec.Status, body)
						}
						if strings.Contains(body, tc.marker) {
							t.Errorf("fail-closed 对照组不应放出持有帧: %q", body)
						}
						return
					}
					if rec.Status != "success" || !strings.Contains(body, tc.marker) || rcgHasTerminationFrame(body) {
						t.Errorf("非 fail-closed 对照组应放行并释放持有帧: status=%s body=%q", rec.Status, body)
					}
				})
			}
		}
	}
}

// 直接驱动 copyGuardedReverseSSE：断开时返回断开哨兵，不是拦截、不是检测失败，也不向客户端写任何字节。
func TestReverseClientGoneStreamDirect(t *testing.T) {
	for _, tc := range rcgStreamCases {
		for _, sc := range rcgScenarios {
			for _, cfg := range rcgConfigs {
				t.Run(tc.name+"/"+sc.name+"/"+cfg.name, func(t *testing.T) {
					e := newRCGEnv(t, sc, cfg, "/check-output/", "text/event-stream", "")
					w, _, d, blocked, err := e.stream(tc.sse)
					if sc.gone {
						if !errors.Is(err, errClientGoneDuringSecurity) {
							t.Fatalf("err=%v, want errClientGoneDuringSecurity", err)
						}
						if blocked {
							t.Errorf("断开不是拦截, blocked=true")
						}
						if d.SemanticStatus == "incomplete" || d.DetectionFailed || len(d.RetryTaskIDs) != 0 || d.RetryUnavailable || !d.Allowed {
							t.Errorf("断开的 decision 必须干净: %+v", d)
						}
						if body := w.Body.String(); body != "" {
							t.Errorf("断开不应向客户端写任何字节: %q", body)
						}
						e.requireNoRetryQueued()
						return
					}
					if cfg.enforcing() && !blocked {
						t.Errorf("fail-closed 对照组应 blocked: blocked=%v err=%v", blocked, err)
					}
					if d.SemanticStatus != "incomplete" {
						t.Errorf("对照组 decision 应 incomplete: %+v", d)
					}
				})
			}
		}
	}
}

// 流末 checkStreamInspection 的窗口循环：断开后只扫第一个窗口就返回；对照组两个窗口都扫。
func TestReverseClientGoneStreamInspectionWindows(t *testing.T) {
	text := strings.Repeat("a", 40000) // 32768 窗口 + 1024 重叠 => 2 个窗口
	for _, sc := range rcgScenarios {
		t.Run(sc.name, func(t *testing.T) {
			e := newRCGEnv(t, sc, rcgConfigs[0], "/check-output/", "text/event-stream", "")
			d, err := e.h.checkStreamInspection(e.ctx, "req-rcg", text, "", "api.openai.com", "/v1/chat/completions")
			if sc.gone {
				if !errors.Is(err, errClientGoneDuringSecurity) {
					t.Fatalf("err=%v, want errClientGoneDuringSecurity", err)
				}
				if got := e.engine.calls("/check-output/"); got != 1 {
					t.Errorf("断开后应只扫第一个窗口, 引擎被调用 %d 次", got)
				}
				if d.SemanticStatus == "incomplete" || d.DetectionFailed || !d.Allowed {
					t.Errorf("断开的 decision 必须干净: %+v", d)
				}
				return
			}
			if err != nil {
				t.Fatalf("对照组不应返回错误: %v", err)
			}
			if got := e.engine.calls("/check-output/"); got != 2 {
				t.Errorf("对照组两个窗口都应被扫描, 引擎被调用 %d 次", got)
			}
			if d.SemanticStatus != "incomplete" {
				t.Errorf("对照组应 incomplete: %+v", d)
			}
		})
	}
}

// 引擎调用本身：断开时返回干净 decision + 哨兵，不入队；对照组 DetectionFailed + 入队。
func TestReverseClientGoneCheckSecurityWithExtras(t *testing.T) {
	for _, sc := range rcgScenarios {
		for _, path := range []string{"/check-input/", "/check-output/"} {
			t.Run(sc.name+path, func(t *testing.T) {
				e := newRCGEnv(t, sc, rcgConfigs[1], path, "application/json", "")
				d, err := e.h.checkSecurityWithExtras(e.ctx, "req-rcg", path, []byte("payload"), "payload", "text/plain", "api.openai.com", "/v1/chat/completions", "", nil)
				if sc.gone {
					if !errors.Is(err, errClientGoneDuringSecurity) || !errors.Is(err, context.Canceled) {
						t.Fatalf("err=%v, want 包装 errClientGoneDuringSecurity（且 Is context.Canceled）", err)
					}
					if !strings.Contains(err.Error(), path) {
						t.Errorf("哨兵错误应带上下文(path): %v", err)
					}
					if !d.Allowed || d.Action != "allow" || d.DetectionFailed || d.SemanticStatus != "" || d.RetryUnavailable || len(d.RetryTaskIDs) != 0 || string(d.Body) != "payload" {
						t.Errorf("断开的 decision 必须是干净 allow: %+v", d)
					}
					e.requireNoRetryQueued()
					return
				}
				if err == nil || errors.Is(err, errClientGoneDuringSecurity) {
					t.Fatalf("对照组应返回原始检测错误, got %v", err)
				}
				if !d.DetectionFailed || d.SemanticStatus != "incomplete" || d.Allowed {
					t.Errorf("对照组 fail-closed 下应 DetectionFailed/incomplete/!Allowed: %+v", d)
				}
				if len(d.RetryTaskIDs) != 1 || e.queue.count() != 1 {
					t.Errorf("对照组应入队 1 次: ids=%v queued=%d", d.RetryTaskIDs, e.queue.count())
				}
			})
		}
	}
}

// 反向用例（单元级）：请求 ctx 只是到期（DeadlineExceeded，等价于 30 分钟总超时）时，
// 不能被当成客户端断开；引擎自己 cancel 而请求 ctx 仍然存活时同理。
func TestReverseClientGoneNotMisjudged(t *testing.T) {
	t.Run("request_ctx_deadline", func(t *testing.T) {
		e := newRCGEnv(t, rcgScenario{name: "deadline", kind: rcgKindBlock}, rcgConfigs[1], "/check-output/", "application/json", "")
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		d, err := e.h.checkSecurityWithExtras(ctx, "req-rcg", "/check-output/", []byte("p"), "p", "text/plain", "api.openai.com", "/v1/chat/completions", "", nil)
		if err == nil || errors.Is(err, errClientGoneDuringSecurity) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("总超时到期必须仍是检测失败: err=%v", err)
		}
		if !d.DetectionFailed || d.SemanticStatus != "incomplete" || e.queue.count() != 1 {
			t.Errorf("总超时应按检测失败处理并入队: %+v queued=%d", d, e.queue.count())
		}
	})
	t.Run("engine_internal_cancel_ctx_alive", func(t *testing.T) {
		e := newRCGEnv(t, rcgScenario{name: "internal", kind: rcgKindInternalCancel}, rcgConfigs[1], "/check-output/", "application/json", "")
		d, err := e.h.checkSecurityWithExtras(e.ctx, "req-rcg", "/check-output/", []byte("p"), "p", "text/plain", "api.openai.com", "/v1/chat/completions", "", nil)
		if err == nil || errors.Is(err, errClientGoneDuringSecurity) {
			t.Fatalf("请求 ctx 存活时不得判为断开: %v", err)
		}
		if !d.DetectionFailed || e.queue.count() != 1 {
			t.Errorf("引擎内部 cancel 应按检测失败处理并入队: %+v queued=%d", d, e.queue.count())
		}
	})
}

// 对照组：上游自己断流而请求 ctx 存活，仍是 output_stream_incomplete，不能被误判为客户端断开。
func TestReverseClientGoneUpstreamTruncatedIsStillIncomplete(t *testing.T) {
	for _, cfg := range rcgConfigs {
		t.Run(cfg.name, func(t *testing.T) {
			e := newRCGEnv(t, rcgScenario{name: "truncated", kind: rcgKindBlock}, cfg, "/none/", "text/event-stream", "")
			cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(rcgSSEChunk("first chunk")))
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			}))
			t.Cleanup(cut.Close)
			e.route.TargetURL = cut.URL + "/v1/chat/completions"
			e.h.resolveEgressTarget = testEgressResolver(cut.URL)
			_, _ = e.forward(rcgChatRequest)
			rec := e.lastRecord()
			if rec.Status == "cancelled" {
				t.Fatalf("上游断流被误判为客户端断开")
			}
			if got := e.incompleteEvents("output"); got != 1 {
				t.Errorf("上游断流应记 1 条 output incomplete, got %d (status=%s)", got, rec.Status)
			}
		})
	}
}
