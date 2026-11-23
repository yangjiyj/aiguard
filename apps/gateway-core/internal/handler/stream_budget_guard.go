package handler

import (
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// Streaming output caps are derived from the current monetary allowance or
// configured wallet. If an upstream ignores its bound, stop forwarding once
// the local estimate clearly exceeds it, then drain authoritative usage.
// Missing upstream usage is settled from delivered output conservatively,
// bounded by the admitted cap, and marked estimated for the billing statement.
const (
	streamBudgetCheckEveryEvents = 8
	streamBudgetCheckInterval    = time.Second
	// 本地估算偏大（ASCII 按 3 字节 1 token、中文按 1.5 token/字），兜底阈值留 50% + 32 的余量。
	streamBudgetSlackNumerator   = 3
	streamBudgetSlackDenominator = 2
	streamBudgetSlackTokens      = 32
	// 停止转发后最多再等上游这么久，等不到结束事件就放弃取权威用量。
	streamBudgetDrainTimeout = 60 * time.Second
	// Finalize turns this marker into estimated_incomplete with capped usage.
	streamBudgetUsageUnavailable = "budget_truncated_usage_unavailable"
	// streamBudgetTruncatedNotice 是截断时附在 OpenAI 流末尾的中文说明。
	streamBudgetTruncatedNotice = "\n\n（预算额度已用尽，本次回答已被截断。如需继续使用请联系管理员。）"
)

// streamBudgetProvider 由 BillingClient 实现：返回准入时下发的输出上限和本次输入 token 估算。
type streamBudgetProvider interface {
	StreamBudget(requestID string) (outputTokenCap int64, promptTokens int64, ok bool)
}

type streamBudgetGuard struct {
	outputCap  int64
	threshold  int64
	produced   int64
	sinceCheck int
	lastCheck  time.Time
	now        func() time.Time
}

func newStreamBudgetGuard(preflight BillingPreflight, requestID string) *streamBudgetGuard {
	provider, ok := preflight.(streamBudgetProvider)
	if !ok || provider == nil {
		return nil
	}
	outputCap, _, ok := provider.StreamBudget(requestID)
	if !ok {
		return nil
	}
	now := time.Now()
	return &streamBudgetGuard{outputCap: outputCap, threshold: streamBudgetThreshold(outputCap), now: time.Now, lastCheck: now}
}

func streamBudgetThreshold(outputCap int64) int64 {
	if outputCap < 0 {
		outputCap = 0
	}
	return outputCap*streamBudgetSlackNumerator/streamBudgetSlackDenominator + streamBudgetSlackTokens
}

// observe 累计一个上游事件产出的 token；upstreamOutput 是上游已报告的输出 token（取较大值）。
// 返回 true 表示上游明显没有遵守输出上限、应当停止转发。只在每 N 个事件或每 1 秒做一次对比。
func (g *streamBudgetGuard) observe(event relay.StreamEvent, upstreamOutput int64) bool {
	if g == nil {
		return false
	}
	switch event.Type {
	case relay.EventTextDelta, relay.EventReasoningDelta, relay.EventToolArgumentsDelta:
		g.produced += estimateTextTokens(event.Delta)
	case relay.EventToolCallStart:
		if event.ToolCall != nil {
			g.produced += estimateTextTokens(event.ToolCall.Name) + estimateTextTokens(event.ToolCall.Arguments)
		}
	default:
		return false
	}
	if upstreamOutput > g.produced {
		g.produced = upstreamOutput
	}
	g.sinceCheck++
	now := g.now()
	if g.sinceCheck < streamBudgetCheckEveryEvents && now.Sub(g.lastCheck) < streamBudgetCheckInterval {
		return false
	}
	g.sinceCheck, g.lastCheck = 0, now
	return g.produced >= g.threshold
}

// absorbDrainedEvent 处理停止转发后从上游读到的事件：只收集 usage 和结束信号，内容不再进入累加器。
func absorbDrainedEvent(accumulator *liveStreamAccumulator, event relay.StreamEvent) {
	if accumulator == nil {
		return
	}
	if event.Usage != nil {
		accumulator.mergeUsage(event.Usage, event.Type == relay.EventUsageDelta)
	}
	if event.CacheUsage != nil {
		accumulator.mergeUsage(&relay.Usage{
			CacheReadInputTokens:     event.CacheUsage.ReadTokens,
			CacheCreationInputTokens: event.CacheUsage.CreationTokens,
		}, false)
	}
	if event.Type == relay.EventMessageEnd {
		accumulator.sawTerminal = true
	}
}

// finishTruncatedAccumulator 把累加器收尾成“因输出上限停止”：每个 choice 的结束原因为 length。
func finishTruncatedAccumulator(accumulator *liveStreamAccumulator) {
	if accumulator == nil {
		return
	}
	if len(accumulator.choices) == 0 {
		accumulator.choice(0)
	}
	for _, choice := range accumulator.choices {
		choice.finishReason = "length"
	}
	accumulator.sawTerminal = true
}

// streamBudgetDrain 在停止转发后限时读上游：超时关闭上游连接，Next 随之返回错误。
type streamBudgetDrain struct {
	timer    *time.Timer
	timedOut bool
}

func startStreamBudgetDrain(closeReader func()) *streamBudgetDrain {
	drain := &streamBudgetDrain{}
	drain.timer = time.AfterFunc(streamBudgetDrainTimeout, func() {
		drain.timedOut = true
		closeReader()
	})
	return drain
}

func (d *streamBudgetDrain) stop() {
	if d != nil && d.timer != nil {
		d.timer.Stop()
	}
}

// liveUpstreamOutputTokens 是上游在流中已报告的输出 token（没有时为 0）。
func liveUpstreamOutputTokens(accumulator *liveStreamAccumulator) int64 {
	if accumulator == nil || accumulator.usage == nil {
		return 0
	}
	return positiveLiveInt64(accumulator.usage.OutputTokens)
}

// writeStreamBudgetNotice 在 OpenAI 流的结束事件前补一条中文说明 chunk。
func writeStreamBudgetNotice(w http.ResponseWriter, tracker *relay.CommitTracker, encoder *relay.ChatEncoder, response ChatCompletionResponse, prepareHeaders func()) error {
	index := 0
	if len(response.Choices) > 0 {
		index = response.Choices[0].Index
	}
	payload, err := encoder.Encode(relay.StreamEvent{Type: relay.EventTextDelta, Index: index, Delta: streamBudgetTruncatedNotice})
	if err != nil || len(payload) == 0 {
		return err
	}
	return writeLiveChatSSE(w, tracker, payload, prepareHeaders, false)
}

// markStreamBudgetTruncated records the reason; Finalize settles a conservative
// estimate when usageAvailable is false instead of leaving a TTL-only hold.
func markStreamBudgetTruncated(envelope *modelrouter.RequestEnvelope, auditResult *AuditResult, usageAvailable bool) string {
	if auditResult != nil {
		if auditResult.ResponseMetadata == nil {
			auditResult.ResponseMetadata = map[string]interface{}{}
		}
		auditResult.ResponseMetadata["stream_budget_truncated"] = true
		if !usageAvailable {
			auditResult.ResponseMetadata["stream_budget_usage_unavailable"] = true
		}
	}
	if envelope != nil && !usageAvailable {
		envelope.BillingUsageSource = streamBudgetUsageUnavailable
	}
	return "incomplete"
}

// drainedUsageAvailable 判断停止转发后是否拿到了上游的结束事件与输出用量。
func drainedUsageAvailable(accumulator *liveStreamAccumulator, sawUpstreamTerminal bool) bool {
	return sawUpstreamTerminal && accumulator != nil && accumulator.usage != nil && accumulator.usage.OutputTokens > 0
}
