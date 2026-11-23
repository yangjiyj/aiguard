package handler

import (
	"strings"
	"testing"
)

// 反向代理非流式输出：客户端在输出扫描期间断开。
// 断开 -> cancelled/408，响应正文不写给客户端，不写 incomplete，fail-closed 下不是 503，不入重试队列；
// 审计记录沿用 blocked 分支的参数形态（带 respBody，留证不比以前少）。

func TestReverseClientGoneOutputMatrix(t *testing.T) {
	for _, sc := range rcgScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, sc, cfg, "/check-output/", "application/json", rcgChatResponse)
				w, err := e.forward(rcgChatRequest)
				if sc.gone {
					e.requireCleanGone(w, err)
					e.requireNoRetryQueued()
					e.requireDetachedAuditWrites()
					if strings.Contains(w.Body.String(), "upstream answer text") {
						t.Errorf("断开后上游响应正文不应写给客户端: %q", w.Body.String())
					}
					if got := e.upstreamCalls.Load(); got != 1 {
						t.Errorf("请求本应已转发上游一次, upstream calls=%d", got)
					}
					if rec := e.lastRecord(); rec.ResponseBytes != int64(len(rcgChatResponse)) {
						t.Errorf("审计应沿用 blocked 分支带上 respBody 的形态: ResponseBytes=%d want %d", rec.ResponseBytes, len(rcgChatResponse))
					}
					return
				}
				e.requireFailureUnchanged(w, err, "output", 1)
				if !cfg.enforcing() && !strings.Contains(w.Body.String(), "upstream answer text") {
					t.Errorf("对照组（放行）应把响应正文写给客户端: %q", w.Body.String())
				}
				if cfg.enforcing() && strings.Contains(w.Body.String(), "upstream answer text") {
					t.Errorf("对照组 fail-closed 不应泄露响应正文: %q", w.Body.String())
				}
			})
		}
	}
}

// 非 chat 端点的输出走通用整包送检（checkResponseSecurity）。
func TestReverseClientGoneOutputGenericEndpoint(t *testing.T) {
	for _, sc := range rcgScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newRCGEnv(t, sc, cfg, "/check-output/", "application/json", `{"ok":true,"data":"generic upstream text"}`)
				e.setTargetPath("/api/v1/data")
				w, err := e.forward(`{"query":"hello"}`)
				if sc.gone {
					e.requireCleanGone(w, err)
					e.requireNoRetryQueued()
					if strings.Contains(w.Body.String(), "generic upstream text") {
						t.Errorf("断开后上游响应正文不应写给客户端: %q", w.Body.String())
					}
					return
				}
				e.requireFailureUnchanged(w, err, "output", 1)
			})
		}
	}
}
