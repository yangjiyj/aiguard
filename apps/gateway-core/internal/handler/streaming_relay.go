package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

const (
	// Keep a bounded response copy for final security, evidence, and billing.
	maxLiveOutputAuditBytes   = 4 << 20
	maxLiveOutputScanBytes    = 64 << 10
	maxLiveOutputTailBytes    = 16 << 10
	maxLiveToolBytes          = 1 << 20
	maxLiveChoices            = 32
	maxLiveToolsPerChoice     = 64
	maxLiveTerminalBytes      = 1 << 20
	maxLiveOutputFindings     = 1024
	maxLiveOutputFindingBytes = 1 << 20
)

var errLiveStreamOutputBlocked = errors.New("live stream output blocked by security policy")

type liveStreamTerminalError struct {
	err error
}

func (e *liveStreamTerminalError) Error() string {
	if e == nil || e.err == nil {
		return "live stream terminated"
	}
	return e.err.Error()
}

func (e *liveStreamTerminalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func isLiveStreamTerminalError(err error) bool {
	var terminal *liveStreamTerminalError
	return errors.As(err, &terminal)
}

type boundedLiveText struct {
	value     strings.Builder
	limit     int
	total     int
	truncated bool
}

func newBoundedLiveText(limit int) boundedLiveText {
	if limit <= 0 {
		limit = maxLiveOutputAuditBytes
	}
	return boundedLiveText{limit: limit}
}

func (b *boundedLiveText) append(value string) {
	if b == nil || value == "" {
		return
	}
	b.total += len(value)
	if b.value.Len() >= b.limit {
		b.truncated = true
		return
	}
	remaining := b.limit - b.value.Len()
	if len(value) > remaining {
		b.value.WriteString(value[:liveUTF8Prefix(value, remaining)])
		b.truncated = true
		return
	}
	b.value.WriteString(value)
}

func (b *boundedLiveText) String() string {
	if b == nil {
		return ""
	}
	return b.value.String()
}

func (b *boundedLiveText) incomplete() bool {
	return b != nil && b.truncated
}

type liveToolState struct {
	id    string
	name  string
	index int
	args  boundedLiveText
	// providerExecuted：这个工具块由模型服务方执行（Anthropic server_tool_use、mcp_tool_use），一旦见过就保持。
	providerExecuted bool
}

type liveChoiceState struct {
	index        int
	content      boundedLiveText
	reasoning    boundedLiveText
	scanTail     string
	finishReason string
	tools        map[string]*liveToolState
	toolByIndex  map[int]*liveToolState
	toolOrder    []string
	toolOverflow bool
	overflowTool *liveToolState
}

type liveStreamAccumulator struct {
	billingToolCounts     map[string]int64
	billingToolIDs        map[string]string
	id                    string
	model                 string
	terminalRaw           []byte
	terminalType          string
	usageRaw              []byte
	choices               map[int]*liveChoiceState
	usage                 *relay.Usage
	outputFindings        []map[string]interface{}
	outputFindingKeys     map[string]struct{}
	outputFindingBytes    int
	outputFindingsDropped int
	choiceOverflow        bool
	overflowChoice        *liveChoiceState
	sawTerminal           bool
	outputScanIncomplete  bool
	outputScanReason      string
	totalOutputBytes      int
}

func newLiveStreamAccumulator() *liveStreamAccumulator {
	return &liveStreamAccumulator{
		choices:           make(map[int]*liveChoiceState),
		outputFindingKeys: make(map[string]struct{}),
	}
}

func (a *liveStreamAccumulator) rememberOutputFindings(choiceIndex int, findings []SecurityFinding) {
	if a == nil {
		return
	}
	for _, item := range securityFindingsToAuditMaps(findings) {
		item["choice_index"] = choiceIndex
		keyBytes, err := json.Marshal(item)
		if err != nil {
			continue
		}
		if len(a.outputFindings) >= maxLiveOutputFindings || a.outputFindingBytes+len(keyBytes) > maxLiveOutputFindingBytes {
			a.outputFindingsDropped++
			continue
		}
		key := string(keyBytes)
		if _, exists := a.outputFindingKeys[key]; exists {
			continue
		}
		a.outputFindingKeys[key] = struct{}{}
		a.outputFindingBytes += len(keyBytes)
		a.outputFindings = append(a.outputFindings, item)
	}
}

func (a *liveStreamAccumulator) auditResult(action string) *AuditResult {
	if a == nil {
		return &AuditResult{OutputFindings: []map[string]interface{}{}, OutputAction: action}
	}
	findings := make([]map[string]interface{}, len(a.outputFindings))
	copy(findings, a.outputFindings)
	result := &AuditResult{OutputFindings: findings, OutputAction: action}
	a.annotateFindingLimit(result)
	return result
}

func (a *liveStreamAccumulator) auditResultWithFindings(result *AuditResult, action string) *AuditResult {
	if result == nil {
		return a.auditResult(action)
	}
	if len(a.outputFindings) > 0 {
		existing := make(map[string]struct{}, len(result.OutputFindings))
		for _, finding := range result.OutputFindings {
			keyBytes, err := json.Marshal(finding)
			if err == nil {
				existing[string(keyBytes)] = struct{}{}
			}
		}
		for _, finding := range a.outputFindings {
			keyBytes, err := json.Marshal(finding)
			if err != nil {
				continue
			}
			key := string(keyBytes)
			if _, exists := existing[key]; exists {
				continue
			}
			existing[key] = struct{}{}
			result.OutputFindings = append(result.OutputFindings, finding)
		}
	}
	a.annotateFindingLimit(result)
	return result
}

func (a *liveStreamAccumulator) choice(index int) *liveChoiceState {
	if a.choices == nil {
		a.choices = make(map[int]*liveChoiceState)
	}
	choice, ok := a.choices[index]
	if ok {
		return choice
	}
	if len(a.choices) >= maxLiveChoices {
		a.choiceOverflow = true
		if a.overflowChoice == nil {
			a.overflowChoice = &liveChoiceState{
				index:       index,
				content:     newBoundedLiveText(maxLiveOutputAuditBytes),
				reasoning:   newBoundedLiveText(maxLiveOutputAuditBytes),
				tools:       make(map[string]*liveToolState),
				toolByIndex: make(map[int]*liveToolState),
			}
		}
		return a.overflowChoice
	}
	choice = &liveChoiceState{
		index:       index,
		content:     newBoundedLiveText(maxLiveOutputAuditBytes),
		reasoning:   newBoundedLiveText(maxLiveOutputAuditBytes),
		tools:       make(map[string]*liveToolState),
		toolByIndex: make(map[int]*liveToolState),
	}
	a.choices[index] = choice
	return choice
}

func (a *liveStreamAccumulator) observeEvent(event relay.StreamEvent) (previousTail, scanWindow string, scanIncomplete bool) {
	a.observeBillingTools(event)
	if a == nil {
		return "", "", false
	}
	if a.id == "" && event.ID != "" {
		a.id = event.ID
	}
	if a.model == "" && event.Model != "" {
		a.model = event.Model
	}
	switch event.Type {
	case relay.EventTextDelta, relay.EventReasoningDelta:
		a.totalOutputBytes += len(event.Delta)
		choice := a.choice(event.Index)
		previousTail = choice.scanTail
		scanWindow, scanIncomplete = liveScanWindow(previousTail, event.Delta)
		choice.scanTail = appendLiveTail(previousTail+event.Delta, maxLiveOutputTailBytes)
		if event.Type == relay.EventReasoningDelta {
			choice.reasoning.append(event.Delta)
		} else {
			choice.content.append(event.Delta)
		}
		if choice.content.incomplete() || choice.reasoning.incomplete() {
			scanIncomplete = true
			if a.outputScanReason == "" {
				a.outputScanReason = "response_content_limit"
			}
		}
		if a.choiceOverflow {
			scanIncomplete = true
		}
	case relay.EventToolCallStart:
		argument := ""
		if event.ToolCall != nil {
			argument = event.ToolCall.Arguments
		}
		a.observeTool(event.Index, event.ToolCall, argument, false)
	case relay.EventToolArgumentsDelta:
		a.observeTool(event.Index, event.ToolCall, event.Delta, false)
	case relay.EventToolArgumentsDone:
		a.observeToolSnapshot(event.Index, event.ToolCall, event.Delta)
	case relay.EventMessageEnd:
		choice := a.choice(event.Index)
		if event.FinishReason != "" {
			choice.finishReason = event.FinishReason
		}
		if len(event.Raw) > 0 && len(event.Raw) <= maxLiveTerminalBytes {
			a.terminalRaw = append(a.terminalRaw[:0], event.Raw...)
			a.terminalType = responseEventType(event.Raw)
		} else if len(event.Raw) > maxLiveTerminalBytes {
			a.outputScanReason = "terminal_event_limit"
		}
		a.sawTerminal = true
	}
	if event.Usage != nil {
		a.mergeUsage(event.Usage, event.Type == relay.EventUsageDelta)
		if len(event.Raw) > 0 && len(event.Raw) <= maxLiveTerminalBytes && responseEventType(event.Raw) == "message_delta" {
			a.usageRaw = append(a.usageRaw[:0], event.Raw...)
		}
	}
	if event.CacheUsage != nil {
		if a.usage == nil {
			a.usage = &relay.Usage{}
		}
		a.usage.CacheReadInputTokens = positiveLiveInt64(event.CacheUsage.ReadTokens)
		a.usage.CacheCreationInputTokens = positiveLiveInt64(event.CacheUsage.CreationTokens)
	}
	return previousTail, scanWindow, scanIncomplete
}

func (a *liveStreamAccumulator) observeTool(choiceIndex int, call *relay.ToolCall, argument string, start bool) {
	choice := a.choice(choiceIndex)
	if call == nil {
		call = &relay.ToolCall{Index: len(choice.toolOrder)}
	}
	tool := choice.tool(call)
	beforeBytes := tool.args.total
	defer func() { a.totalOutputBytes += tool.args.total - beforeBytes }()
	if call.ID != "" && tool.id == "" { // 合并进已有工具时保留首个 id，不被后续块的 id 覆盖
		tool.id = call.ID
	}
	if call.Name != "" {
		tool.name = call.Name
	}
	tool.providerExecuted = tool.providerExecuted || call.ProviderExecuted
	if argument != "" {
		tool.args.append(argument)
		if tool.args.incomplete() {
			a.outputScanReason = "tool_argument_limit"
		}
	}
	if start && call.Arguments != "" {
		tool.args.append(call.Arguments)
		if tool.args.incomplete() {
			a.outputScanReason = "tool_argument_limit"
		}
	}
}

func (a *liveStreamAccumulator) observeToolSnapshot(choiceIndex int, call *relay.ToolCall, argument string) {
	choice := a.choice(choiceIndex)
	if call == nil {
		call = &relay.ToolCall{Index: len(choice.toolOrder)}
	}
	tool := choice.tool(call)
	beforeBytes := tool.args.total
	defer func() { a.totalOutputBytes += tool.args.total - beforeBytes }()
	if call.ID != "" && tool.id == "" { // 合并进已有工具时保留首个 id，不被后续块的 id 覆盖
		tool.id = call.ID
	}
	if call.Name != "" {
		tool.name = call.Name
	}
	tool.providerExecuted = tool.providerExecuted || call.ProviderExecuted
	if tool.args.total == 0 && argument != "" {
		tool.args.append(argument)
		if tool.args.incomplete() {
			a.outputScanReason = "tool_argument_limit"
		}
	}
}

func (c *liveChoiceState) tool(call *relay.ToolCall) *liveToolState {
	if call == nil {
		call = &relay.ToolCall{Index: len(c.toolOrder)}
	}
	if call.ID != "" {
		if existing := c.tools["id:"+call.ID]; existing != nil {
			return existing
		}
	}
	if existing := c.toolByIndex[call.Index]; existing != nil {
		// 同一 index 已有工具、新块没带 name：这是该工具的参数增量（部分兼容网关每块换新 id），并进已有工具，
		// 不另建无名工具，否则一次长参数流会产生数十个无名工具、触发数十次审计上报。
		// 真正的并行工具调用 index 各不相同；同 index 且带 name 的新 id 仍按新工具处理。
		if call.ID == "" || existing.id == "" || call.Name == "" {
			if call.ID != "" && existing.id == "" {
				existing.id = call.ID
				c.tools["id:"+call.ID] = existing
			}
			return existing
		}
	}
	if len(c.toolOrder) >= maxLiveToolsPerChoice {
		c.toolOverflow = true
		if c.overflowTool == nil {
			c.overflowTool = &liveToolState{index: call.Index, args: newBoundedLiveText(maxLiveToolBytes)}
		}
		return c.overflowTool
	}
	key := fmt.Sprintf("index:%d", call.Index)
	if call.ID != "" {
		key = "id:" + call.ID
	}
	tool := &liveToolState{index: call.Index, args: newBoundedLiveText(maxLiveToolBytes)}
	c.tools[key] = tool
	c.toolByIndex[call.Index] = tool
	c.toolOrder = append(c.toolOrder, key)
	return tool
}

func (a *liveStreamAccumulator) mergeUsage(next *relay.Usage, delta bool) {
	if next == nil {
		return
	}
	if a.usage == nil {
		a.usage = &relay.Usage{}
	}
	if delta {
		a.usage.InputTokens += positiveLiveInt64(next.InputTokens)
		a.usage.OutputTokens += positiveLiveInt64(next.OutputTokens)
		a.usage.ReasoningTokens += positiveLiveInt64(next.ReasoningTokens)
		a.usage.CacheReadInputTokens += positiveLiveInt64(next.CacheReadInputTokens)
		a.usage.CacheCreationInputTokens += positiveLiveInt64(next.CacheCreationInputTokens)
		a.usage.CacheMissInputTokens += positiveLiveInt64(next.CacheMissInputTokens)
		return
	}
	// Final and message snapshots are authoritative, not high-water marks.
	// Protocol readers have already carried forward fields omitted by the wire.
	snapshot := *next
	a.usage = &snapshot
}

func positiveLiveInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func maxLiveInt64(left, right int64) int64 {
	if right > left {
		return right
	}
	return left
}

func liveScanWindow(previousTail, current string) (string, bool) {
	previousTail = appendLiveTail(previousTail, maxLiveOutputTailBytes)
	allowedCurrent := maxLiveOutputScanBytes - len(previousTail)
	if allowedCurrent < 0 {
		previousTail = appendLiveTail(previousTail, maxLiveOutputScanBytes/2)
		allowedCurrent = maxLiveOutputScanBytes - len(previousTail)
	}
	raw := []byte(current)
	if len(raw) > allowedCurrent {
		return previousTail + current[:liveUTF8Prefix(current, allowedCurrent)], true
	}
	return previousTail + current, false
}

func appendLiveTail(value string, limit int) string {
	raw := []byte(value)
	if limit <= 0 || len(raw) <= limit {
		return value
	}
	start := len(raw) - limit
	for start < len(raw) && !utf8.RuneStart(raw[start]) {
		start++
	}
	return string(raw[start:])
}

// providerExecutedToolCalls：responseBody 组出的送检视图里，由模型服务方执行的工具的位置（与 responseBody 的
// choice、工具顺序一致）。
func (a *liveStreamAccumulator) providerExecutedToolCalls() providerExecutedToolCalls {
	if a == nil {
		return nil
	}
	indexes := make([]int, 0, len(a.choices))
	for index := range a.choices {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	var calls providerExecutedToolCalls
	for choicePosition, index := range indexes {
		choice := a.choices[index]
		for toolPosition, key := range choice.toolOrder {
			if tool := choice.tools[key]; tool != nil && tool.providerExecuted {
				if calls == nil {
					calls = make(providerExecutedToolCalls)
				}
				calls[[2]int{choicePosition, toolPosition}] = true
			}
		}
	}
	return calls
}

func (a *liveStreamAccumulator) responseBody(requestID string, includeCacheInPrompt ...bool) ([]byte, error) {
	if a == nil {
		return nil, errors.New("live stream accumulator is nil")
	}
	id := a.id
	if id == "" {
		id = "chatcmpl-" + requestID
	}
	model := a.model
	if model == "" {
		model = "unknown"
	}
	response := ChatCompletionResponse{
		ID: id, Object: "chat.completion", Created: time.Now().Unix(), Model: model,
	}
	indexes := make([]int, 0, len(a.choices))
	for index := range a.choices {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	response.Choices = make([]Choice, 0, len(indexes))
	for _, index := range indexes {
		choice := a.choices[index]
		message := ChoiceMessage{
			Role: "assistant", Content: choice.content.String(),
			ReasoningContent: choice.reasoning.String(),
		}
		for _, key := range choice.toolOrder {
			tool := choice.tools[key]
			message.ToolCalls = append(message.ToolCalls, ToolCall{
				ID: tool.id, Type: "function",
				Function: ToolCallFunc{Name: tool.name, Arguments: tool.args.String()},
			})
		}
		response.Choices = append(response.Choices, Choice{
			Index: index, Message: message,
			FinishReason: firstNonEmptyLive(choice.finishReason, "stop"),
		})
	}
	if a.usage != nil {
		promptTokens := positiveLiveInt64(a.usage.InputTokens)
		if len(includeCacheInPrompt) > 0 && includeCacheInPrompt[0] {
			promptTokens += positiveLiveInt64(a.usage.CacheReadInputTokens)
			promptTokens += positiveLiveInt64(a.usage.CacheCreationInputTokens)
		}
		response.Usage = Usage{
			PromptTokens:             int(promptTokens),
			CompletionTokens:         int(positiveLiveInt64(a.usage.OutputTokens)),
			TotalTokens:              int(promptTokens + positiveLiveInt64(a.usage.OutputTokens)),
			CompletionTokensDetails:  liveCompletionDetails(a.usage),
			CacheReadInputTokens:     int(positiveLiveInt64(a.usage.CacheReadInputTokens)),
			CacheCreationInputTokens: int(positiveLiveInt64(a.usage.CacheCreationInputTokens)),
			PromptCacheHitTokens:     int(positiveLiveInt64(a.usage.CacheReadInputTokens)),
			PromptCacheMissTokens:    int(positiveLiveInt64(a.usage.CacheMissInputTokens)),
		}
		if a.usage.CacheReadInputTokens > 0 || a.usage.CacheCreationInputTokens > 0 {
			response.Usage.PromptTokensDetails = &PromptTokensDetails{
				CachedTokens:             int(positiveLiveInt64(a.usage.CacheReadInputTokens)),
				CacheCreationInputTokens: int(positiveLiveInt64(a.usage.CacheCreationInputTokens)),
			}
		}
	}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	if a.usage == nil {
		// The response DTO always serializes a zero-value Usage. Such zeros are
		// synthetic, so remove them before billing interprets the audit response
		// as upstream-verified evidence. Actual zero usage remains authoritative.
		var object map[string]json.RawMessage
		if err := json.Unmarshal(body, &object); err != nil {
			return nil, err
		}
		delete(object, "usage")
		body, err = json.Marshal(object)
		if err != nil {
			return nil, err
		}
	}
	return addStreamBillingTools(body, a.billingToolCounts), nil
}

func livePromptIncludesCache(envelope *modelrouter.RequestEnvelope) bool {
	if envelope == nil {
		return false
	}
	// Anthropic Messages 的 input_tokens 不含缓存读写；上游走 messages 协议时（含 custom/openai
	// 类型供应商桥接到 Claude 的路由）都要把缓存计入 prompt，否则计费按未命中部分少算。
	return envelope.EndpointType == "messages" || strings.EqualFold(strings.TrimSpace(envelope.Provider), "anthropic") ||
		strings.EqualFold(strings.TrimSpace(envelope.UpstreamProtocol), "messages")
}

func liveCompletionDetails(usage *relay.Usage) *CompletionTokensDetails {
	if usage == nil || usage.ReasoningTokens <= 0 {
		return nil
	}
	return &CompletionTokensDetails{ReasoningTokens: int(usage.ReasoningTokens)}
}

func firstNonEmptyLive(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func responseEventType(raw []byte) string {
	var payload struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload.Type)
}

func (h *ChatCompletionsHandler) outputSecurityAuditOnly(ctx context.Context) bool {
	if h == nil {
		return false
	}
	if h.securityAuditOnly(ctx) {
		return true
	}
	return effectiveOutputSecurityMode(h.toolRiskClient, h.cfg) == relay.OutputSecurityStreamAudit
}

// liveStreamExitMode maps the resolved live-stream output posture to the
// securityexit mode: stream_audit (forced by record mode) never enforces.
func liveStreamExitMode(mode relay.OutputSecurityMode) securityexit.Mode {
	return securityexit.ModeFromAuditOnly(mode == relay.OutputSecurityStreamAudit)
}

func (h *ChatCompletionsHandler) tryLiveChatStream(
	ctx context.Context,
	w http.ResponseWriter,
	envelope *modelrouter.RequestEnvelope,
	caller ProviderCaller,
	providerReq []byte,
	startedAt time.Time,
	inputSecurityAction string,
	tracker *relay.CommitTracker,
	requestMessages ...[]Message,
) (attempted bool, err error) {
	if integrationDLPNeedsBufferedOutput(ctx) {
		return false, nil
	}
	if hasRequestRedaction(ctx, envelope) {
		return false, nil
	}
	// 需要加 AI 生成内容标识的回复改为先攒后发，由交付层统一加标识。
	if needsAIContentLabel(h.toolRiskClient, envelope) {
		return false, nil
	}
	if h == nil || envelope == nil || caller == nil || !h.upstreamStreamingEnabled() {
		return false, nil
	}
	// 一次请求只取一次输出检测方式快照，往下传给待发缓冲（2.9.22）。
	configuredMode := effectiveOutputSecurityMode(h.toolRiskClient, h.cfg)
	mode := configuredMode
	if h.securityAuditOnly(ctx) {
		mode = relay.OutputSecurityStreamAudit
	}
	streamCaller, ok := caller.(provider.StreamAdapter)
	if !ok {
		return false, nil
	}
	attempted = true
	if tracker == nil {
		return true, errors.New("stream commit tracker is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	upstreamStarted := time.Now()
	recordPreUpstreamTiming(envelope, upstreamStarted)
	reader, _, err := streamCaller.OpenStream(ctx, envelope, providerReq)
	if err != nil {
		return true, err
	}
	if reader == nil {
		return true, fmt.Errorf("provider returned an empty stream reader")
	}
	closeOnce := sync.Once{}
	closeReader := func() {
		closeOnce.Do(func() { _ = reader.Close() })
	}
	defer closeReader()
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeReader()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	if h.relayMetrics != nil {
		h.relayMetrics.StreamStarted()
		defer h.relayMetrics.StreamFinished()
	}

	accumulator := newLiveStreamAccumulator()
	pending := newLivePendingOutput(h, configuredMode)
	// 预算断流开启且控制面下发了输出上限时才有 guard；否则为 nil，转发行为与改造前一致。
	budgetGuard := newStreamBudgetGuard(h.billingPreflight, envelope.RequestID)
	budgetTruncated := false
	budgetUpstreamDone := false
	var budgetDrain *streamBudgetDrain
	defer func() { budgetDrain.stop() }()
	finalized := false
	firstDeltaSeen := false
	messages := []Message(nil)
	if len(requestMessages) > 0 {
		messages = requestMessages[0]
	}
	encoder := relay.NewChatEncoder(envelope.RequestID, envelope.Model)
	encoder.PromptIncludesCache = livePromptIncludesCache(envelope)
	liveSecurityAction := inputSecurityAction
	prepareHeaders := func() {
		setRoutingHeaders(w, envelope, false)
		setSecurityActionHeader(w, liveSecurityAction, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
	}
	finalizeRequest := func(status string, statusCode int, body []byte, auditResult *AuditResult) {
		if finalized {
			return
		}
		finalized = true
		if auditResult == nil {
			auditResult = &AuditResult{OutputFindings: []map[string]interface{}{}, OutputAction: "allow"}
		}
		if body != nil && h.auditWriter != nil {
			h.writeResponseContentLogs(context.WithoutCancel(ctx), envelope, body)
		}
		h.recordProxyUsageIfNeeded(context.WithoutCancel(ctx), envelope, body)
		if h.auditWriter != nil {
			h.auditWriter.FinalizeRequestLog(context.WithoutCancel(ctx), envelope, body, status, statusCode,
				int(time.Since(startedAt)/time.Millisecond), auditResult)
		}
		h.recordPromptCacheMetrics(body)
		if h.relayMetrics != nil {
			h.relayMetrics.Add("upstream_ms", durationMetricValue(time.Since(upstreamStarted)))
			h.relayMetrics.Add("total_ms", durationMetricValue(time.Since(startedAt)))
		}
	}
	abort := func(streamErr error, status string, statusCode int, auditResult *AuditResult) error {
		inspectionRejected := isGuardrailDetectionUnavailable(streamErr)
		if inspectionRejected {
			status, statusCode = streamInspectionRejectionStatus(tracker)
			accumulator.outputScanIncomplete = true
			if accumulator.outputScanReason == "" {
				accumulator.outputScanReason = securityexit.FailureReason(streamErr, "output_security_check_failed")
			}
		}
		body, bodyErr := accumulator.responseBody(envelope.RequestID, livePromptIncludesCache(envelope))
		if bodyErr != nil {
			body = nil
		}
		action := "allow"
		if status == "security_blocked" || inspectionRejected {
			action = "block"
			liveSecurityAction = "block"
		}
		auditResult = accumulator.auditResultWithFindings(auditResult, action)
		if accumulator.outputScanIncomplete {
			if auditResult.ResponseMetadata == nil {
				auditResult.ResponseMetadata = map[string]interface{}{}
			}
			auditResult.ResponseMetadata["output_scan_incomplete"] = true
			auditResult.ResponseMetadata["output_scan_incomplete_reason"] = accumulator.outputScanReason
		}
		finalizeRequest(status, statusCode, body, auditResult)
		if inspectionRejected && tracker.State() == relay.CommitNotStarted {
			writeGuardrailDetectionUnavailable(w, envelope.RequestID, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
			_ = tracker.Transition(relay.CommitHeadersCommitted)
			_ = tracker.Abort()
			return &liveStreamTerminalError{err: streamErr}
		}
		if h.auditWriter != nil && (status == "stream_aborted" || status == "client_canceled") {
			h.writeSecurityEvent(context.WithoutCancel(ctx), envelope, nil, "stream_aborted",
				fmt.Sprintf("live stream terminated with status=%s", status))
		}
		if tracker.State() == relay.CommitNotStarted && status == "client_canceled" {
			return &liveStreamTerminalError{err: streamErr}
		}
		if tracker.State() != relay.CommitCompleted && tracker.State() != relay.CommitAborted {
			payloads := [][]byte{[]byte("{\"error\":{\"message\":\"stream aborted\",\"type\":\"upstream_error\",\"code\":\"stream_aborted\"}}")}
			if inspectionRejected {
				payload, _ := json.Marshal(map[string]any{"error": map[string]any{"message": guardrailDetectionUnavailableMessage, "type": "security_error", "code": guardrailDetectionUnavailableCode}})
				payloads = [][]byte{payload}
			} else if status == "security_blocked" {
				notice := h.blockNoticeForResponse(context.WithoutCancel(ctx), envelope, "output", "live stream blocked by security policy")
				if tracker.State() == relay.CommitNotStarted {
					setBlockNoticeHeaders(w, notice)
				}
				payloads = liveChatBlockPayloads(envelope.RequestID, envelope.Model, notice)
			}
			for _, payload := range payloads {
				if writeErr := writeLiveChatSSE(w, tracker, payload, prepareHeaders, false); writeErr != nil {
					if streamErr == nil {
						streamErr = writeErr
					}
					break
				}
			}
			_ = tracker.Abort()
		}
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("stream_aborted")
			if status == "client_canceled" {
				h.relayMetrics.Inc("client_cancel")
				h.relayMetrics.Inc("upstream_cancel")
			}
		}
		return streamErr
	}
	recordScanIncomplete := func(reason string) error {
		if accumulator.outputScanIncomplete {
			if accumulator.outputScanReason == "" {
				accumulator.outputScanReason = reason
			}
			return nil
		}
		accumulator.outputScanIncomplete = true
		accumulator.outputScanReason = firstNonEmptyLive(reason, "scan_boundary")
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("output_scan_incomplete")
		}
		if h.auditWriter != nil {
			h.writeSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, nil,
				"output_scan_incomplete",
				fmt.Sprintf("live output exceeded bounded security scan (%s)", accumulator.outputScanReason))
		}
		// A scan boundary is an inspection gap, not a finding: recorded above,
		// never a reason to interrupt the stream.
		return nil
	}
	recordFirstDelta := func(event relay.StreamEvent) {
		if firstDeltaSeen {
			return
		}
		switch event.Type {
		case relay.EventTextDelta, relay.EventReasoningDelta, relay.EventToolCallStart,
			relay.EventToolArgumentsDelta, relay.EventToolArgumentsDone:
			firstDeltaSeen = true
			if h.relayMetrics != nil {
				h.relayMetrics.Add("ttft_ms", durationMetricValue(time.Since(upstreamStarted)))
			}
		}
	}
	emitImmediate := func(event relay.StreamEvent) error {
		if event.Type == relay.EventUnknown {
			return nil
		}
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("stream_events")
		}
		if event.Type == relay.EventStreamError {
			if event.Err != nil {
				return event.Err
			}
			return errors.New("upstream stream error")
		}
		if event.Type == relay.EventMessageEnd {
			accumulator.observeEvent(event)
			if accumulator.outputScanReason != "" && !accumulator.outputScanIncomplete {
				return recordScanIncomplete(accumulator.outputScanReason)
			}
			return nil
		}
		if event.Type == relay.EventToolCallStart || event.Type == relay.EventToolArgumentsDelta ||
			event.Type == relay.EventToolArgumentsDone {
			accumulator.observeEvent(event)
			recordFirstDelta(event)
			if liveToolArgumentsIncomplete(accumulator) {
				if scanErr := recordScanIncomplete("tool_argument_limit"); scanErr != nil {
					return scanErr
				}
			}
			return nil
		}
		if event.Type == relay.EventTextDelta || event.Type == relay.EventReasoningDelta {
			previousTail, scanWindow, scanIncomplete := accumulator.observeEvent(event)
			recordFirstDelta(event)
			if scanIncomplete {
				if scanErr := recordScanIncomplete("response_scan_window"); scanErr != nil {
					return scanErr
				}
			}
			if h.securityClient != nil && scanWindow != "" {
				checkStarted := time.Now()
				action, masked, findings, checkErr := h.checkStreamOutput(withOutputProjection(ctx), envelope, scanWindow, event.Index)
				recordSecurityTiming(envelope, h.relayMetrics, "output_security_ms", time.Since(checkStarted))
				if checkErr != nil {
					if h.relayMetrics != nil && !clientGoneDuring(ctx, checkErr) {
						h.relayMetrics.Inc("security_check_failed")
					}
					if failure := h.streamInspectionFailure(ctx, checkErr, recordScanIncomplete); failure != nil {
						return failure
					}
				} else {
					accumulator.rememberOutputFindings(event.Index, findings)
					if securityexit.Decide(liveStreamExitMode(mode), action, securityexit.RuleHit).Enforce {
						if h.auditWriter != nil {
							h.writeSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, findings,
								"security_blocked", fmt.Sprintf("blocked live output choice %d", event.Index))
						}
						return fmt.Errorf("%w: choice=%d", errLiveStreamOutputBlocked, event.Index)
					}
					switch strings.ToLower(strings.TrimSpace(action)) {
					case "mask":
						if mode == relay.OutputSecurityStreamEnforce {
							effective, ok := liveMaskedDelta(previousTail, event.Delta, masked)
							if !ok {
								// The configured action is "mask", not "block": forward
								// the original delta and raise an alert.
								if h.auditWriter != nil {
									h.writeSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), envelope, findings,
										"security_audit", fmt.Sprintf("live output mask could not be safely aligned (choice=%d); forwarded unmasked", event.Index))
								}
							} else {
								event.Delta = effective
							}
						}
					}
				}
			}
		} else {
			accumulator.observeEvent(event)
		}
		payload, encodeErr := encoder.Encode(event)
		if encodeErr != nil {
			return encodeErr
		}
		if len(payload) == 0 {
			return nil
		}
		if event.Type == relay.EventTextDelta || event.Type == relay.EventReasoningDelta {
			setSecurityActionHeader(w, strongerSecurityAction(inputSecurityAction, "allow"), securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		}
		return writeLiveChatSSE(w, tracker, payload, prepareHeaders, false)
	}

	writePending := func(event relay.StreamEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if liveIsText(event) && event.Delta == "" {
			return nil
		}
		payload, err := encoder.Encode(event)
		if err != nil || len(payload) == 0 {
			return err
		}
		return writeLiveChatSSE(w, tracker, payload, prepareHeaders, false)
	}
	checkPending := func(content string, index int) (bool, error) {
		if h.securityClient == nil {
			return false, nil
		}
		started := time.Now()
		action, _, findings, err := h.checkStreamOutput(withOutputProjection(ctx), envelope, content, index)
		recordSecurityTiming(envelope, h.relayMetrics, "output_security_ms", time.Since(started))
		if err != nil {
			if h.relayMetrics != nil && !clientGoneDuring(ctx, err) {
				h.relayMetrics.Inc("security_check_failed")
			}
			return false, h.streamInspectionFailure(ctx, err, recordScanIncomplete)
		}
		accumulator.rememberOutputFindings(index, findings)
		if securityexit.Decide(liveStreamExitMode(mode), action, securityexit.RuleHit).Enforce {
			if h.auditWriter != nil {
				h.writeSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, findings, "security_blocked", fmt.Sprintf("blocked pending output choice %d", index))
			}
			return false, fmt.Errorf("%w: choice=%d", errLiveStreamOutputBlocked, index)
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "mask":
			// Keep this lane pending until whole-response redaction can be aligned.
			return true, nil
		}
		return false, nil
	}
	emit := func(event relay.StreamEvent) error {
		if mode == relay.OutputSecurityStreamAudit {
			return emitImmediate(event)
		}
		if event.Type == relay.EventUnknown {
			return nil
		}
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("stream_events")
		}
		if event.Type == relay.EventStreamError {
			if event.Err != nil {
				return event.Err
			}
			return errors.New("upstream stream error")
		}
		accumulator.observeEvent(event)
		recordFirstDelta(event)
		if mode == relay.OutputSecurityStrictBuffered && accumulator.totalOutputBytes > pending.limit {
			return recordScanIncomplete("strict_output_budget")
		}
		// A scan batch is independently windowed by pending.add; provider delta size
		// alone is no longer an incomplete scan. Response and tool caps remain real.
		if accumulator.outputScanReason != "" || accumulator.choiceOverflow || liveToolArgumentsIncomplete(accumulator) {
			if err := recordScanIncomplete(firstNonEmptyLive(accumulator.outputScanReason, "response_content_limit")); err != nil {
				return err
			}
		}
		switch event.Type {
		case relay.EventMessageEnd, relay.EventToolCallStart, relay.EventToolArgumentsDelta, relay.EventToolArgumentsDone:
			return nil
		}
		return pending.add(ctx, event, checkPending, writePending, recordScanIncomplete)
	}

	for {
		event, nextErr := reader.Next(ctx)
		// 在终止事件或 EOF 当下冻结生成耗时，避免包含随后完整输出检测。
		if errors.Is(nextErr, io.EOF) || event.Type == relay.EventMessageEnd {
			recordGenerationTiming(envelope, upstreamStarted, time.Now())
		}
		if budgetTruncated {
			// 已停止向客户端转发：只从上游收集权威 usage，读到结束或出错就收尾。
			if nextErr == nil {
				absorbDrainedEvent(accumulator, event)
				if event.Type != relay.EventMessageEnd {
					continue
				}
				budgetUpstreamDone = true
			} else if errors.Is(nextErr, io.EOF) {
				budgetUpstreamDone = accumulator.sawTerminal
			}
			budgetDrain.stop()
			finishTruncatedAccumulator(accumulator)
			nextErr = io.EOF
		}
		if nextErr != nil {
			if errors.Is(nextErr, io.EOF) {
				if !accumulator.sawTerminal {
					truncatedErr := errors.New("upstream stream ended without terminal event")
					if tracker.State() == relay.CommitNotStarted {
						return true, truncatedErr
					}
					return true, abort(truncatedErr, "stream_aborted", http.StatusOK, nil)
				}
				rawBody, bodyErr := accumulator.responseBody(envelope.RequestID, livePromptIncludesCache(envelope))
				if bodyErr != nil {
					return true, abort(bodyErr, "stream_aborted", http.StatusOK, nil)
				}
				securedBody, auditResult, secureErr := h.applyOutputSecurity(
					withProviderExecutedToolCalls(ctx, accumulator.providerExecutedToolCalls()), envelope, messages, rawBody)
				if secureErr != nil {
					// 客户端在最终输出扫描期间已断开（Esc / 中断）：不是拦截，记 client_canceled/408。
					if clientGoneDuring(ctx, secureErr) {
						return true, abort(ctx.Err(), "client_canceled", http.StatusRequestTimeout, nil)
					}
					if auditResult == nil {
						auditResult = &AuditResult{OutputFindings: []map[string]interface{}{}, OutputAction: "block"}
					}
					if auditResult.ResponseMetadata == nil {
						auditResult.ResponseMetadata = map[string]interface{}{}
					}
					auditResult.ResponseMetadata["stream_aborted"] = true
					return true, abort(secureErr, "security_blocked", http.StatusForbidden, auditResult)
				}
				if auditResult == nil {
					auditResult = &AuditResult{OutputFindings: []map[string]interface{}{}, OutputAction: "allow"}
				}
				auditResult = accumulator.auditResultWithFindings(auditResult, auditResult.OutputAction)
				if accumulator.outputScanIncomplete {
					if auditResult.ResponseMetadata == nil {
						auditResult.ResponseMetadata = map[string]interface{}{}
					}
					auditResult.ResponseMetadata["output_scan_incomplete"] = true
					auditResult.ResponseMetadata["output_scan_incomplete_reason"] = accumulator.outputScanReason
				}
				if len(securedBody) == 0 {
					securedBody = rawBody
				}
				var securedResponse ChatCompletionResponse
				if err := json.Unmarshal(securedBody, &securedResponse); err != nil {
					return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
				}
				liveSecurityAction = strongerSecurityAction(inputSecurityAction, outputActionOf(auditResult))
				if mode == relay.OutputSecurityStreamEnforce || mode == relay.OutputSecurityStrictBuffered {
					if err := pending.finish(ctx, accumulator, securedResponse, auditResult, writePending); err != nil {
						status := "stream_aborted"
						code := http.StatusOK
						if errors.Is(err, errLiveStreamOutputBlocked) {
							status = "security_blocked"
							code = http.StatusForbidden
						}
						if ctx.Err() != nil {
							status = "client_canceled"
						}
						return true, abort(err, status, code, auditResult)
					}
					if pending.maskUnavailable {
						auditResult = markMaskUnavailable(auditResult)
						if h.auditWriter != nil {
							h.writeSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), envelope, nil,
								"security_audit", "live output mask could not be resolved; forwarded unmasked")
						}
					}
				}
				if budgetTruncated {
					if err := writeStreamBudgetNotice(w, tracker, encoder, securedResponse, prepareHeaders); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				}
				if err := emitFinalChatEvents(w, tracker, encoder, accumulator, securedResponse, prepareHeaders,
					!liveToolArgumentsIncomplete(accumulator)); err != nil {
					if h.relayMetrics != nil {
						h.relayMetrics.Inc("backpressure")
					}
					return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
				}
				if budgetTruncated {
					usable := drainedUsageAvailable(accumulator, budgetUpstreamDone)
					finalizeRequest(markStreamBudgetTruncated(envelope, auditResult, usable), http.StatusOK, securedBody, auditResult)
					return true, nil
				}
				finalizeRequest("success", http.StatusOK, securedBody, auditResult)
				return true, nil
			}
			if ctx.Err() != nil {
				return true, abort(ctx.Err(), "client_canceled", http.StatusRequestTimeout, nil)
			}
			if tracker.State() == relay.CommitNotStarted {
				return true, nextErr
			}
			return true, abort(nextErr, "stream_aborted", http.StatusOK, nil)
		}
		if emitErr := emit(event); emitErr != nil {
			if h.relayMetrics != nil {
				h.relayMetrics.Inc("backpressure")
			}
			if errors.Is(emitErr, errLiveStreamOutputBlocked) {
				return true, abort(emitErr, "security_blocked", http.StatusForbidden, &AuditResult{
					OutputFindings: []map[string]interface{}{},
					OutputAction:   "block",
				})
			}
			if ctx.Err() != nil {
				return true, abort(ctx.Err(), "client_canceled", http.StatusRequestTimeout, nil)
			}
			if tracker.State() == relay.CommitNotStarted {
				return true, emitErr
			}
			return true, abort(emitErr, "stream_aborted", http.StatusOK, nil)
		}
		if budgetGuard.observe(event, liveUpstreamOutputTokens(accumulator)) {
			// 上游没有遵守输出上限：停止转发，限时继续读上游拿权威 usage。
			budgetTruncated = true
			budgetDrain = startStreamBudgetDrain(closeReader)
		}
	}
}

func durationMetricValue(duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(duration / time.Millisecond)
}

func liveMaskedDelta(previousTail, rawDelta, maskedWindow string) (string, bool) {
	if maskedWindow == "" {
		return "", false
	}
	if strings.HasPrefix(maskedWindow, previousTail) {
		return strings.TrimPrefix(maskedWindow, previousTail), true
	}
	if previousTail == "" {
		return maskedWindow, true
	}
	if maskedWindow == rawDelta {
		return maskedWindow, true
	}
	return "", false
}

func liveToolArgumentsIncomplete(accumulator *liveStreamAccumulator) bool {
	if accumulator == nil {
		return false
	}
	if accumulator.choiceOverflow {
		return true
	}
	for _, choice := range accumulator.choices {
		if choice.toolOverflow {
			return true
		}
		for _, tool := range choice.tools {
			if tool.args.incomplete() {
				return true
			}
		}
	}
	return false
}

func hasLiveTextBeenCommitted(tracker *relay.CommitTracker, accumulator *liveStreamAccumulator) bool {
	if tracker == nil || accumulator == nil || tracker.State() == relay.CommitNotStarted {
		return false
	}
	for _, choice := range accumulator.choices {
		if choice.content.total > 0 || choice.reasoning.total > 0 {
			return true
		}
	}
	return false
}

func emitFinalChatEvents(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	encoder *relay.ChatEncoder,
	accumulator *liveStreamAccumulator,
	response ChatCompletionResponse,
	prepareHeaders func(),
	allowTools bool,
) error {
	for _, choice := range response.Choices {
		rawChoice := accumulator.choices[choice.Index]
		if rawChoice == nil {
			rawChoice = &liveChoiceState{}
		}
		if rawChoice.content.total == 0 && choice.Message.Content != "" {
			payload, err := encoder.Encode(relay.StreamEvent{Type: relay.EventTextDelta, Index: choice.Index, Delta: choice.Message.Content})
			if err != nil {
				return err
			}
			if err := writeLiveChatSSE(w, tracker, payload, prepareHeaders, false); err != nil {
				return err
			}
		}
		if rawChoice.reasoning.total == 0 && choice.Message.ReasoningContent != "" {
			payload, err := encoder.Encode(relay.StreamEvent{Type: relay.EventReasoningDelta, Index: choice.Index, Delta: choice.Message.ReasoningContent})
			if err != nil {
				return err
			}
			if err := writeLiveChatSSE(w, tracker, payload, prepareHeaders, false); err != nil {
				return err
			}
		}
		for index, tool := range choice.Message.ToolCalls {
			if !allowTools {
				break
			}
			call := &relay.ToolCall{ID: tool.ID, Name: tool.Function.Name, Index: index}
			payload, err := encoder.Encode(relay.StreamEvent{Type: relay.EventToolCallStart, Index: choice.Index, ToolCall: call})
			if err != nil {
				return err
			}
			if err := writeLiveChatSSE(w, tracker, payload, prepareHeaders, false); err != nil {
				return err
			}
			if tool.Function.Arguments != "" {
				payload, err = encoder.Encode(relay.StreamEvent{
					Type: relay.EventToolArgumentsDelta, Index: choice.Index, ToolCall: call, Delta: tool.Function.Arguments,
				})
				if err != nil {
					return err
				}
				if err := writeLiveChatSSE(w, tracker, payload, prepareHeaders, false); err != nil {
					return err
				}
			}
		}
		payload, err := encoder.Encode(relay.StreamEvent{
			Type: relay.EventMessageEnd, Index: choice.Index,
			FinishReason: firstNonEmptyLive(choice.FinishReason, "stop"),
			Usage:        relayUsageFromHandlerUsage(response.Usage),
		})
		if err != nil {
			return err
		}
		if err := writeLiveChatSSE(w, tracker, payload, prepareHeaders, false); err != nil {
			return err
		}
	}
	return writeLiveChatSSE(w, tracker, []byte("[DONE]"), prepareHeaders, true)
}

func relayUsageFromHandlerUsage(usage Usage) *relay.Usage {
	if usage.PromptTokens == 0 && usage.CompletionTokens == 0 && usage.CacheReadInputTokens == 0 &&
		usage.CacheCreationInputTokens == 0 && usage.PromptCacheMissTokens == 0 {
		return nil
	}
	reasoning := int64(0)
	if usage.CompletionTokensDetails != nil {
		reasoning = int64(usage.CompletionTokensDetails.ReasoningTokens)
	}
	return &relay.Usage{
		InputTokens: int64(usage.PromptTokens), OutputTokens: int64(usage.CompletionTokens),
		ReasoningTokens: reasoning, CacheReadInputTokens: maxLiveInt64(int64(usage.CacheReadInputTokens), int64(usage.PromptCacheHitTokens)),
		CacheCreationInputTokens: int64(usage.CacheCreationInputTokens),
		CacheMissInputTokens:     int64(usage.PromptCacheMissTokens),
	}
}

func (h *ChatCompletionsHandler) checkStreamOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (string, string, []SecurityFinding, error) {
	if h.securityClient == nil || content == "" {
		return "", content, nil, nil
	}
	return h.checkOutputWithStatus(ctx, envelope, content, choiceIndex, nil)
}

func (h *ChatCompletionsHandler) recordPromptCacheMetrics(response []byte) {
	if h == nil || h.relayMetrics == nil || len(response) == 0 {
		return
	}
	usage := normalizeBillingUsage(response)
	if usage["cached_input_tokens"] > 0 {
		h.relayMetrics.Inc("prompt_cache_hit")
	}
	if usage["cache_write_input_tokens"] > 0 {
		h.relayMetrics.Inc("prompt_cache_write")
	}
}

func writeLiveChatSSE(w http.ResponseWriter, tracker *relay.CommitTracker, payload []byte, prepareHeaders func(), terminal bool) error {
	if tracker == nil {
		return errors.New("stream commit tracker is required")
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return errors.New("streaming is not supported by the response writer")
	}
	if tracker.State() == relay.CommitNotStarted {
		if prepareHeaders != nil {
			prepareHeaders()
		}
		if err := tracker.Transition(relay.CommitHeadersCommitted); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
		_ = tracker.Abort()
		return err
	}
	flusher.Flush()
	if tracker.State() == relay.CommitHeadersCommitted {
		if err := tracker.Transition(relay.CommitFirstEventFlushed); err != nil {
			return err
		}
	}
	if terminal {
		if err := tracker.Transition(relay.CommitCompleted); err != nil {
			return err
		}
	}
	return nil
}

func (a *liveStreamAccumulator) annotateFindingLimit(result *AuditResult) {
	if a == nil || result == nil || a.outputFindingsDropped == 0 {
		return
	}
	if result.ResponseMetadata == nil {
		result.ResponseMetadata = map[string]interface{}{}
	}
	result.ResponseMetadata["output_findings_truncated"] = true
	result.ResponseMetadata["output_findings_dropped"] = a.outputFindingsDropped
}
