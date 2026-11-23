package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// 反向代理输入侧：客户端在安全检测期间断开。
// 断开 -> cancelled/408，不转发上游，不入重试队列，不写 incomplete 事件，fail-closed 下也不是 503；
// 对照组（引擎 500 / 连接拒绝 / 检测超时 / 引擎内部 cancel 而请求 ctx 存活）仍是检测失败。

func TestReverseClientGoneInputMatrix(t *testing.T) {
	for _, sc := range rcgScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, sc, cfg, "/check-input/", "application/json", rcgChatResponse)
				w, err := e.forward(rcgChatRequest)
				if sc.gone {
					e.requireCleanGone(w, err)
					e.requireNothingForwarded()
					e.requireDetachedAuditWrites()
					return
				}
				e.requireFailureUnchanged(w, err, "input", 1)
				wantUpstream := int64(1)
				if cfg.enforcing() {
					wantUpstream = 0 // fail-closed：检测失败时转发前就 503
				}
				if got := e.upstreamCalls.Load(); got != wantUpstream {
					t.Errorf("对照组 upstream calls=%d, want %d", got, wantUpstream)
				}
			})
		}
	}
}

// 多分组 chat 请求（system + user 两组）：断开后只扫第一组就返回，不吞错继续扫下一组。
func TestReverseClientGoneInputStopsAfterFirstGroup(t *testing.T) {
	for _, sc := range rcgScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, sc, cfg, "/check-input/", "application/json", rcgChatResponse)
				w, err := e.forward(rcgMultiRequest)
				if sc.gone {
					e.requireCleanGone(w, err)
					e.requireNothingForwarded()
					if got := e.engine.calls("/check-input/"); got != 1 {
						t.Errorf("断开后应只扫第一组, 引擎被调用 %d 次", got)
					}
					return
				}
				// 对照组：检测失败不终止循环，两组都要尝试，各自入队。
				if got := e.engine.calls("/check-input/"); got != 2 {
					t.Errorf("对照组两组都应被扫描, 引擎被调用 %d 次", got)
				}
				e.requireFailureUnchanged(w, err, "input", 2)
			})
		}
	}
}

// 协议解析失败分支（整包按 unknown 送检）会覆写 SemanticStatus=incomplete，断开时不能被它盖掉。
func TestReverseClientGoneInputProtocolParseFailed(t *testing.T) {
	const badBody = `{"model":"m","messages":"not-an-array"}`
	for _, sc := range rcgScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, sc, cfg, "/check-input/", "application/json", rcgChatResponse)
				w, err := e.forward(badBody)
				if sc.gone {
					e.requireCleanGone(w, err)
					e.requireNothingForwarded()
					return
				}
				e.requireFailureUnchanged(w, err, "input", 1)
			})
		}
	}
}

// 非 chat 端点走通用整包送检（checkRequestSecurityWithAttachments）。
func TestReverseClientGoneInputGenericEndpoint(t *testing.T) {
	for _, sc := range rcgScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, sc, cfg, "/check-input/", "application/json", `{"ok":true}`)
				e.setTargetPath("/api/v1/data")
				w, err := e.forward(`{"query":"hello client gone"}`)
				if sc.gone {
					e.requireCleanGone(w, err)
					e.requireNothingForwarded()
					return
				}
				e.requireFailureUnchanged(w, err, "input", 1)
			})
		}
	}
}

// 仅因 30 分钟总超时到期（这里调成 150ms）：错误是 DeadlineExceeded，不是客户端断开，
// 仍按检测失败处理——fail-closed 照常 503，入重试队列，写 incomplete 事件。
func TestReverseClientGoneTotalTimeoutIsNotClientGone(t *testing.T) {
	old := reverseProxyStreamTimeout
	reverseProxyStreamTimeout = 150 * time.Millisecond
	t.Cleanup(func() { reverseProxyStreamTimeout = old })
	sc := rcgScenario{name: "total_timeout", kind: rcgKindBlock}
	for _, cfg := range rcgConfigs {
		t.Run(cfg.name, func(t *testing.T) {
			e := newRCGEnv(t, sc, cfg, "/check-input/", "application/json", rcgChatResponse)
			w, err := e.forward(rcgChatRequest)
			rec := e.lastRecord()
			if rec.Status == "cancelled" || w.Code == http.StatusRequestTimeout {
				t.Fatalf("总超时被当成客户端断开: status=%s http=%d", rec.Status, w.Code)
			}
			if got := e.incompleteEvents("input"); got != 1 {
				t.Errorf("总超时应记 1 条 input incomplete 事件, got %d", got)
			}
			if got := e.queue.count(); got != 1 {
				t.Errorf("总超时应入重试队列, queued=%d", got)
			}
			if cfg.enforcing() {
				if err != nil || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
					t.Errorf("fail-closed 下总超时仍应 503: err=%v http=%d body=%q", err, w.Code, w.Body.String())
				}
				return
			}
			// 非 fail-closed：检测失败放行，随后总超时让上游调用失败，记 failed（不是 cancelled）。
			if rec.Status != "failed" {
				t.Errorf("审计状态=%s, want failed", rec.Status)
			}
		})
	}
}
