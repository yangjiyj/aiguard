package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 实时流（GATEWAY_UPSTREAM_STREAMING=true）路径：扫描发生在边收边发的过程中。
// 断开可能落在三个时点，三处都必须记 client_canceled，不写 check_failed 类事件，
// 不累加 security_check_failed 指标，也不往已断开的连接写拦截帧：
//   - mid：流中增量扫描（checkStreamOutput，经 streamInspectionFailure 记 output_scan_incomplete 与指标）；
//   - final：流末整体输出扫描（applyOutputSecurity，原来硬编码记 security_blocked/403）；
//   - terminal：responses 原生的终态快照扫描（checkNativeResponsesTerminal，仅非只审计模式）。

const (
	liveGoneDelta = "live-gone-marker"
	liveGoneMatch = "live-gone" // 增量扫描窗口（只含 delta 前缀）与流末整体扫描都包含它
)

type liveProtocol struct {
	name     string
	terminal bool // 是否有终态快照扫描阶段
	events   func() []relay.StreamEvent
	run      func(e *goneEnv, cfg *config.Config, caller *liveRelayCaller) (*httptest.ResponseRecorder, bool, error)
}

func liveGoneEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{RequestID: "req-live-gone", TenantID: "tenant-123", ProjectID: "project-123", UserID: "user-123", Model: "test"}
}

var liveProtocols = []liveProtocol{
	{
		name: "chat",
		events: func() []relay.StreamEvent {
			return []relay.StreamEvent{
				{Type: relay.EventTextDelta, Index: 0, Delta: liveGoneDelta},
				{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
			}
		},
		run: func(e *goneEnv, cfg *config.Config, caller *liveRelayCaller) (*httptest.ResponseRecorder, bool, error) {
			h := &ChatCompletionsHandler{cfg: cfg, toolRiskClient: e.client, securityClient: e.sec, auditWriter: e.writer, relayMetrics: e.metrics}
			w := httptest.NewRecorder()
			attempted, err := h.tryLiveChatStream(e.ctx, w, liveGoneEnvelope(), caller, []byte("{}"), time.Now(), "", &relay.CommitTracker{})
			return w, attempted, err
		},
	},
	{
		name: "messages_native",
		events: func() []relay.StreamEvent {
			return []relay.StreamEvent{
				{Type: relay.EventTextDelta, Index: 0, Delta: liveGoneDelta,
					Raw: []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + liveGoneDelta + `"}}`)},
				{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop", Raw: []byte(`{"type":"message_stop"}`)},
			}
		},
		run: func(e *goneEnv, cfg *config.Config, caller *liveRelayCaller) (*httptest.ResponseRecorder, bool, error) {
			h := &MessagesHandler{cfg: cfg, toolRiskClient: e.client, securityClient: e.sec, auditWriter: e.writer, relayMetrics: e.metrics}
			w := httptest.NewRecorder()
			attempted, err := h.tryLiveNativeMessagesStream(e.ctx, w, liveGoneEnvelope(), caller, []byte("{}"), time.Now(), "", &relay.CommitTracker{}, nil)
			return w, attempted, err
		},
	},
	{
		name:     "responses_native",
		terminal: true,
		events: func() []relay.StreamEvent {
			return []relay.StreamEvent{
				{Type: relay.EventTextDelta, Index: 0, Delta: liveGoneDelta,
					Raw: []byte(`{"type":"response.output_text.delta","delta":"` + liveGoneDelta + `"}`)},
				{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop",
					Raw: []byte(`{"type":"response.completed","response":{"id":"resp-live-gone","object":"response","status":"completed","output":[{"id":"msg-1","type":"message","role":"assistant","content":[{"type":"output_text","text":"` + liveGoneDelta + `"}]}]}}`)},
			}
		},
		run: func(e *goneEnv, cfg *config.Config, caller *liveRelayCaller) (*httptest.ResponseRecorder, bool, error) {
			h := &ResponsesHandler{cfg: cfg, toolRiskClient: e.client, securityClient: e.sec, auditWriter: e.writer, relayMetrics: e.metrics}
			w := httptest.NewRecorder()
			attempted, err := h.tryLiveNativeResponsesStream(e.ctx, w, liveGoneEnvelope(), caller, []byte("{}"), time.Now(), "", &relay.CommitTracker{}, nil)
			return w, attempted, err
		},
	},
}

// skip 是钩子触发前先放行的、内容匹配 liveGoneMatch 的 CheckOutput 次数：
// 第 1 次是流中增量扫描，第 2 次是流末整体扫描（applyOutputSecurity），第 3 次是 responses 的终态快照扫描。
var liveStages = []struct {
	name string
	skip int
}{{"mid", 0}, {"final", 1}, {"terminal", 2}}

// liveControl 是对照组（真正的检测失败）原本的收尾：实时流还没写任何字节，
// protect + fail-closed 是 security_blocked；其余放行并记失败标记事件。
// responses 原生的终态快照扫描失败 + fail-closed，现状是 security_blocked/403
// （checkNativeResponsesTerminal 把已判 block 的失败当成裁决），不是 503。这是修复前就有的行为，
// 本任务不改，测试只钉住「原行为不变」。
func liveControl(cfg goneConfig, stage string) goneExpect {
	want := goneExpect{status: "success", code: http.StatusOK,
		anyOf: []string{"output_scan_incomplete", "security_output_check_failed"}}
	if cfg.failClosed && !cfg.auditOnly {
		want.status, want.code = "security_blocked", http.StatusServiceUnavailable
		if stage == "terminal" {
			want.code = http.StatusForbidden
		}
	}
	return want
}

func TestLiveStreamOutputScanClientGone(t *testing.T) {
	for _, proto := range liveProtocols {
		for _, stage := range liveStages {
			if stage.name == "terminal" && !proto.terminal {
				continue
			}
			t.Run(proto.name+"/"+stage.name, func(t *testing.T) {
				configs := goneConfigs
				if stage.name == "terminal" {
					// 只审计模式走 stream_audit，不做终态快照扫描。
					configs = []goneConfig{goneConfigs[0], goneConfigs[1]}
				}
				runGoneMatrix(t, "output", configs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
					e.sec.outputMatch = liveGoneMatch
					e.sec.outputSkip = stage.skip
					// 扫描批次调小到 12 字节，让 16 字节的增量在流中就触发一次扫描。
					runCfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", OutputStreamScanBatchBytes: 12}
					caller := &liveRelayCaller{reader: &liveRelayReader{events: proto.events()}}
					w, attempted, err := proto.run(e, runCfg, caller)
					if !attempted {
						t.Fatalf("实时流没有被尝试: err=%v body=%q", err, w.Body.String())
					}
					want := liveControl(cfg, stage.name)
					want.metricGone = true
					want.metricControl = stage.name == "mid"
					e.check(t, goneResult{httpCode: w.Code, body: w.Body.String()}, want)
					// 断开后不应再向已断开的连接写入拦截/失败帧。
					if e.scenario.gone {
						body := w.Body.String()
						for _, bad := range []string{"security_blocked", guardrailDetectionUnavailableCode} {
							if strings.Contains(body, bad) {
								t.Errorf("客户端断开后不应写入 %q 帧: %q", bad, body)
							}
						}
					}
				})
			})
		}
	}
}
