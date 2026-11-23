package handler

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 实时流路径的计费口径（abort 收尾带的是累加器 body）：
//   - final：上游已发完、usage 已进累加器，扫描期间断开按真实 usage 结算（1800/300）；
//   - mid：流中增量扫描时断开，上游还没发完，只有已送达的输出可算，按已送达输出估算（沿用实时流中途取消的既有口径，
//     与改前 Record 模式下该场景一致），不会退回按预占的 max_tokens（32000）估算。
func TestLiveChatStreamClientGoneSettlement(t *testing.T) {
	for _, cfg := range goneConfigs {
		for _, stage := range liveStages[:2] {
			t.Run(stage.name+"/"+cfg.name, func(t *testing.T) {
				e := newBillingGoneEnv(t, goneScenarios[0], cfg)
				e.sec.outputMatch = liveGoneMatch
				e.sec.outputSkip = stage.skip

				envelope := &modelrouter.RequestEnvelope{RequestID: "req-live-bill-" + stage.name + "-" + cfg.name, TenantID: "tenant-123", ProjectID: "project-123", UserID: "user-123", Model: "test"}
				billingGoneReserve(t, e, envelope)
				events := []relay.StreamEvent{
					{Type: relay.EventTextDelta, Index: 0, Delta: liveGoneDelta},
					{Type: relay.EventUsageFinal, Usage: &relay.Usage{InputTokens: billingGonePromptTokens, OutputTokens: billingGoneCompletionTokens}},
					{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
				}
				caller := &liveRelayCaller{reader: &liveRelayReader{events: events}}
				h := &ChatCompletionsHandler{
					cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", OutputStreamScanBatchBytes: 12},
					toolRiskClient: e.client, securityClient: e.sec, auditWriter: e.audit, relayMetrics: e.metrics,
				}
				w := httptest.NewRecorder()
				attempted, err := h.tryLiveChatStream(e.ctx, w, envelope, caller, []byte("{}"), time.Now(), "", &relay.CommitTracker{})
				if !attempted {
					t.Fatalf("实时流没有被尝试: err=%v", err)
				}
				e.check(t, goneResult{httpCode: w.Code, body: w.Body.String()}, goneExpect{metricGone: true})

				got := e.cp.last(t)
				if stage.name == "final" {
					e.checkSettlement(t)
					return
				}
				if got.outputTok >= 32000 {
					t.Errorf("流中途断开不应按预占的 max_tokens 估算: 结算 usage=%d/%d", got.promptTok, got.outputTok)
				}
			})
		}
	}
}
