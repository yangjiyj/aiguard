package handler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// messages 原生：扫描期间断开时，收尾带的是只含 usage 的最小载体。
// 上游没给 usage 时，不能把载体写成「上游报了 0 token」（{"usage":{"input_tokens":0,"output_tokens":0}} 会被
// 判成 state=upstream），否则配额按 0 结算、计费按 0 记；应回落到按预占估算。
// 上游确实给了 usage 时，仍按真实 usage 结算（1800/300）。

func billingGoneMessagesResponseNoUsage() []byte {
	return []byte(`{"id":"msg_nousage","type":"message","role":"assistant","model":"claude-opus-5",` +
		`"content":[{"type":"text","text":"Hello! How can I help?"}],"stop_reason":"end_turn","stop_sequence":null}`)
}

func billingGoneMessagesSSENoUsage() []byte {
	return []byte("event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_nousage\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-opus-5\"}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello! How can I help?\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

// goneQuota 记录配额路径收尾时的结算：actualTokens 与是否 settle。
type goneQuota struct {
	mu       sync.Mutex
	terminal []quotaTerminalCall
	reserved int64
}

func (q *goneQuota) Admit(_ context.Context, request governor.AdmissionRequest) (*governor.AdmissionLease, error) {
	q.mu.Lock()
	q.reserved = request.EstimatedTokens
	q.mu.Unlock()
	return &governor.AdmissionLease{
		TenantID: request.Ref.TenantID, RequestID: request.RequestID, LeaseID: request.RequestID,
		EstimatedTokens: request.EstimatedTokens, State: "acquired",
		ExpiresAt: time.Now().Add(time.Hour), LeaseTTLMillis: time.Hour.Milliseconds(),
	}, nil
}
func (*goneQuota) Heartbeat(_ context.Context, _ *governor.AdmissionLease) error { return nil }
func (q *goneQuota) Settle(_ context.Context, _ *governor.AdmissionLease, actual, cost int64, costActual bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.terminal = append(q.terminal, quotaTerminalCall{actual: actual, cost: cost, costActual: costActual, settle: true})
	return nil
}
func (q *goneQuota) Release(_ context.Context, _ *governor.AdmissionLease, actual, cost int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.terminal = append(q.terminal, quotaTerminalCall{actual: actual, cost: cost})
	return nil
}
func (q *goneQuota) last(t *testing.T) quotaTerminalCall {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.terminal) == 0 {
		t.Fatal("配额没有收到结算/释放")
	}
	return q.terminal[len(q.terminal)-1]
}

func TestMessagesNativeClientGoneUsageCarrier(t *testing.T) {
	type upstreamCase struct {
		name      string
		stream    bool
		body      []byte
		hasUsage  bool
		wantPromp int64
		wantOut   int64
	}
	cases := []upstreamCase{
		{"non_stream_with_usage", false, billingGoneMessagesResponse(), true, billingGonePromptTokens, billingGoneCompletionTokens},
		{"stream_with_usage", true, billingGoneMessagesSSE(), true, billingGonePromptTokens, billingGoneCompletionTokens},
		{"non_stream_without_usage", false, billingGoneMessagesResponseNoUsage(), false, 0, 0},
		{"stream_without_usage", true, billingGoneMessagesSSENoUsage(), false, 0, 0},
	}
	for _, uc := range cases {
		for _, cfg := range []goneConfig{goneConfigs[0], goneConfigs[2]} { // protect / record
			t.Run(uc.name+"/"+cfg.name, func(t *testing.T) {
				e := newBillingGoneEnv(t, goneScenarios[0], cfg)
				quota := &goneQuota{}
				resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
					ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
					ProviderType: "openai", ProviderBaseURL: "https://boflow.example", UpstreamModelID: "kiro-opus", Status: "active",
				}}
				h := NewMessagesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, e.sec, e.audit,
					fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: uc.body}}, e.client, nil)
				h.SetRelayMetrics(e.metrics)
				h.SetBillingPreflight(e.billing)
				h.SetQuotaAdmission(quota)

				res := serveGone(h.Handler(), goneMessagesRequestWithMax(e.ctx, uc.stream, 32000))

				e.check(t, res, controlForNative(cfg, "security_output_check_failed"))
				settled := e.cp.last(t)
				q := quota.last(t)

				if uc.hasUsage {
					if settled.promptTok != uc.wantPromp || settled.outputTok != uc.wantOut || settled.estimated {
						t.Errorf("上游有 usage：计费应按真实 %d/%d 结算, got %d/%d estimated=%v", uc.wantPromp, uc.wantOut, settled.promptTok, settled.outputTok, settled.estimated)
					}
					if q.actual != uc.wantPromp+uc.wantOut {
						t.Errorf("上游有 usage：配额 actualTokens 应为 %d, got %d", uc.wantPromp+uc.wantOut, q.actual)
					}
					return
				}
				// 上游没给 usage：不能被伪造成「上游报了 0」。
				if settled.promptTok == 0 && settled.outputTok == 0 {
					t.Errorf("上游缺 usage：计费不应结算成 0/0（伪造了上游 0 token）, got %d/%d estimated=%v", settled.promptTok, settled.outputTok, settled.estimated)
				}
				if !settled.estimated {
					t.Errorf("上游缺 usage：计费应标记为估算 (estimated=true), got estimated=%v 结算=%d/%d", settled.estimated, settled.promptTok, settled.outputTok)
				}
				if q.actual == 0 {
					t.Errorf("上游缺 usage：配额 actualTokens 不应为 0（应按预占估算 %d）, got %d", quota.reserved, q.actual)
				}
			})
		}
	}
}
