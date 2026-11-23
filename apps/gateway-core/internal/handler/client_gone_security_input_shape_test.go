package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// 输入扫描期间客户端断开：除了收尾状态是 client_canceled/408，响应形态也必须是「请求已取消」，
// 而不是拦截通知。processSharedRequestPath 里 inputSecurity.auditStatus == "client_canceled" 的专用分支
// 负责这件事；若它被删掉，后面的通用拦截分支虽然也用同样的 auditStatus/httpStatus 收尾，
// 但会带上拦截通知、X-Security-Action: block 头，并按 errorCode 取状态码（request_canceled 未登记，落到 500），
// 在 message 模式下还会把它当作 SecurityReply 回给客户端。这条用例钉住专用分支的响应形态。
func TestChatInputScanClientGoneResponseIsCancellationNotBlockNotice(t *testing.T) {
	for _, cfg := range goneConfigs {
		for _, mode := range []string{blockResponseModeMessage, "error"} {
			t.Run(cfg.name+"/"+mode, func(t *testing.T) {
				e := newGoneEnv(t, goneScenarios[0], cfg, "input")
				h := newGoneChatHandler(e, &config.Config{SecurityActionHeader: true})
				e.client.setBlockNoticeSettings(blockNoticeSettings{Mode: mode, Template: DefaultBlockNoticeTemplate})

				w := newFlushRecorder()
				h.Handler().ServeHTTP(w, goneChatRequest(e.ctx, false))

				if w.code() != http.StatusRequestTimeout {
					t.Errorf("响应状态码=%d, want 408（请求已取消；500 说明落进了通用拦截分支）body=%q", w.code(), w.body())
				}
				var body ErrorResponse
				if err := json.Unmarshal([]byte(w.body()), &body); err != nil || body.Error.Code != "request_canceled" {
					t.Errorf("响应应为 request_canceled 错误, got %q err=%v", w.body(), err)
				}
				if strings.Contains(w.body(), "JJDGuard 安全网关") || strings.Contains(w.body(), "阻断") {
					t.Errorf("客户端断开不应回拦截通知文案: %q", w.body())
				}
				if got := w.Header().Get(SecurityActionHeader); got != "" {
					t.Errorf("客户端断开不应带 %s 头, got %q", SecurityActionHeader, got)
				}
				for _, f := range e.db.finalizes() {
					if f.status != "client_canceled" || f.code != http.StatusRequestTimeout {
						t.Errorf("收尾=%s/%d, want client_canceled/408", f.status, f.code)
					}
				}
			})
		}
	}
}
