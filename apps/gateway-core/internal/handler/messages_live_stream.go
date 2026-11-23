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

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

func (h *MessagesHandler) tryLiveNativeMessagesStream(
	ctx context.Context,
	w http.ResponseWriter,
	envelope *modelrouter.RequestEnvelope,
	caller ProviderCaller,
	providerReq []byte,
	startedAt time.Time,
	inputSecurityAction string,
	tracker *relay.CommitTracker,
	requestMessages []Message,
) (attempted bool, err error) {
	if integrationDLPNeedsBufferedOutput(ctx) {
		return false, nil
	}
	// Native streaming forwards provider SSE frames. A protocol bridge must
	// complete conversion and output inspection before emitting Messages frames.
	if envelope != nil && envelope.UpstreamProtocol != "" && envelope.UpstreamProtocol != "messages" {
		return false, nil
	}
	if hasRequestRedaction(ctx, envelope) {
		return false, nil
	}
	// 需要加 AI 生成内容标识的回复改为先攒后发，由交付层统一加标识。
	if needsAIContentLabel(h.toolRiskClient, envelope) {
		return false, nil
	}
	if h == nil || h.cfg == nil || envelope == nil || caller == nil || !h.cfg.UpstreamStreaming {
		return false, nil
	}
	chatHandler := h.newChatHandler()
	// 一次请求只取一次输出检测方式快照，往下传给待发缓冲（2.9.22）。
	configuredMode := effectiveOutputSecurityMode(h.toolRiskClient, h.cfg)
	mode := configuredMode
	if configuredMode == relay.OutputSecurityStreamAudit || chatHandler.securityAuditOnly(ctx) {
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
	reader, meta, err := streamCaller.OpenStream(ctx, envelope, providerReq)
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
	pending := newLivePendingOutput(chatHandler, configuredMode)
	// 预算断流开启且控制面下发了输出上限时才有 guard；否则为 nil，转发行为与改造前一致。
	budgetGuard := newStreamBudgetGuard(chatHandler.billingPreflight, envelope.RequestID)
	budgetTruncated := false
	budgetUpstreamDone := false
	var budgetDrain *streamBudgetDrain
	defer func() { budgetDrain.stop() }()
	// openBlocks 只在启用截断时记录已开始未结束的内容块，截断时按序补发 content_block_stop。
	var openBlocks map[int]bool
	if budgetGuard != nil {
		openBlocks = map[int]bool{}
	}
	finalized := false
	liveSecurityAction := inputSecurityAction
	prepareHeaders := func() {
		setRoutingHeaders(w, envelope, false)
		setSecurityActionHeader(w, liveSecurityAction, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		copyNativeMessagesHeaders(w.Header(), provider.SafeAnthropicResponseHeaders(meta.Header))
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
		if body != nil && chatHandler.auditWriter != nil {
			chatHandler.writeResponseContentLogs(context.WithoutCancel(ctx), envelope, body)
		}
		chatHandler.recordProxyUsageIfNeeded(context.WithoutCancel(ctx), envelope, body)
		if chatHandler.auditWriter != nil {
			chatHandler.auditWriter.FinalizeRequestLog(context.WithoutCancel(ctx), envelope, body, status, statusCode,
				int(time.Since(startedAt)/time.Millisecond), auditResult)
		}
		chatHandler.recordPromptCacheMetrics(body)
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
		if chatHandler.auditWriter != nil && (status == "stream_aborted" || status == "client_canceled") {
			chatHandler.writeSecurityEvent(context.WithoutCancel(ctx), envelope, nil, "stream_aborted",
				fmt.Sprintf("live Messages stream terminated with status=%s", status))
		}
		if tracker.State() == relay.CommitNotStarted && status == "client_canceled" {
			return &liveStreamTerminalError{err: streamErr}
		}
		if tracker.State() != relay.CommitCompleted && tracker.State() != relay.CommitAborted {
			code := "stream_aborted"
			message := "stream aborted"
			if inspectionRejected {
				code, message = guardrailDetectionUnavailableCode, guardrailDetectionUnavailableMessage
			} else if status == "security_blocked" {
				// Already-started Messages streams close with an error event whose
				// message is the block notice (rule, detail, block number).
				code = "security_blocked"
				notice := chatHandler.blockNoticeForResponse(context.WithoutCancel(ctx), envelope, "output", "live Messages stream blocked by security policy")
				if tracker.State() == relay.CommitNotStarted {
					setBlockNoticeHeaders(w, notice)
				}
				message = notice.Text
			}
			if writeErr := writeLiveMessagesJSON(w, tracker, prepareHeaders, "error",
				map[string]interface{}{"type": "error", "error": map[string]interface{}{"type": "api_error", "message": message, "code": code}}, false); writeErr != nil && streamErr == nil {
				streamErr = writeErr
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
			return nil
		}
		accumulator.outputScanIncomplete = true
		accumulator.outputScanReason = firstNonEmptyLive(reason, "scan_boundary")
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("output_scan_incomplete")
		}
		if chatHandler.auditWriter != nil {
			chatHandler.writeSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, nil,
				"output_scan_incomplete",
				fmt.Sprintf("live Messages output exceeded bounded security scan (%s)", accumulator.outputScanReason))
		}
		// A scan boundary is an inspection gap, not a finding: recorded above,
		// never a reason to interrupt the stream.
		return nil
	}
	firstDeltaSeen := false
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
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("stream_events")
		}
		if event.Type == relay.EventStreamError {
			if event.Err != nil {
				return event.Err
			}
			return errors.New("upstream Messages stream error")
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
			effectiveDelta := event.Delta
			if chatHandler.securityClient != nil && scanWindow != "" {
				checkStarted := time.Now()
				action, masked, findings, checkErr := chatHandler.checkStreamOutput(withOutputProjection(ctx), envelope, scanWindow, event.Index)
				recordSecurityTiming(envelope, h.relayMetrics, "output_security_ms", time.Since(checkStarted))
				if checkErr != nil {
					if h.relayMetrics != nil && !clientGoneDuring(ctx, checkErr) {
						h.relayMetrics.Inc("security_check_failed")
					}
					if failure := chatHandler.streamInspectionFailure(ctx, checkErr, recordScanIncomplete); failure != nil {
						return failure
					}
				} else {
					accumulator.rememberOutputFindings(event.Index, findings)
					if securityexit.Decide(liveStreamExitMode(mode), action, securityexit.RuleHit).Enforce {
						if chatHandler.auditWriter != nil {
							chatHandler.writeSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, findings,
								"security_blocked", fmt.Sprintf("blocked live Messages output choice %d", event.Index))
						}
						return fmt.Errorf("%w: choice=%d", errLiveStreamOutputBlocked, event.Index)
					}
					switch strings.ToLower(strings.TrimSpace(action)) {
					case "mask":
						if mode == relay.OutputSecurityStreamEnforce {
							var aligned bool
							effectiveDelta, aligned = liveMaskedDelta(previousTail, event.Delta, masked)
							if !aligned {
								// The configured action is "mask", not "block": forward
								// the original delta and raise an alert.
								effectiveDelta = event.Delta
								if chatHandler.auditWriter != nil {
									chatHandler.writeSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), envelope, findings,
										"security_audit", fmt.Sprintf("live Messages output mask could not be safely aligned (choice=%d); forwarded unmasked", event.Index))
								}
							}
						}
					}
				}
			}
			raw := rewriteAnthropicDelta(event.Raw, effectiveDelta, event.Type == relay.EventReasoningDelta)
			if len(raw) == 0 {
				raw, _ = json.Marshal(map[string]interface{}{
					"type":  "content_block_delta",
					"index": event.Index,
					"delta": map[string]interface{}{
						"type": func() string {
							if event.Type == relay.EventReasoningDelta {
								return "thinking_delta"
							}
							return "text_delta"
						}(),
						"text": effectiveDelta,
					},
				})
			}
			return writeLiveMessagesRaw(w, tracker, prepareHeaders, raw, false)
		}
		if event.Type == relay.EventMessageStart {
			accumulator.observeEvent(event)
			return writeLiveMessagesRaw(w, tracker, prepareHeaders, event.Raw, false)
		}
		if event.Type == relay.EventUnknown {
			accumulator.observeEvent(event)
			if len(event.Raw) > maxLiveOutputScanBytes {
				if scanErr := recordScanIncomplete("opaque_event_limit"); scanErr != nil {
					return scanErr
				}
			}
			if nativeMessagesRawEventSafeToForward(event.Raw, accumulator) {
				return writeLiveMessagesRaw(w, tracker, prepareHeaders, event.Raw, false)
			}
			return nil
		}
		accumulator.observeEvent(event)
		return nil
	}

	writePending := func(event relay.StreamEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := event.Raw
		if liveIsText(event) {
			if event.Delta == "" {
				return nil
			}
			raw = rewriteAnthropicDelta(raw, event.Delta, event.Type == relay.EventReasoningDelta)
			if len(raw) == 0 {
				return errors.New("native message delta lacks its block identity")
			}
		}
		return writeLiveMessagesRaw(w, tracker, prepareHeaders, raw, false)
	}
	emit := newNativePendingEmitter(ctx, chatHandler, envelope, mode, accumulator, pending, emitImmediate, writePending, recordScanIncomplete, recordFirstDelta, func(event relay.StreamEvent) bool {
		if event.Type == relay.EventUnknown {
			return nativeMessagesRawEventSafeToForward(event.Raw, accumulator)
		}
		// message_delta stop/usage is emitted once, after the final tool decision.
		return event.Type != relay.EventUsageFinal && event.Type != relay.EventUsageDelta && event.Type != relay.EventCacheUsage
	})

	for {
		event, nextErr := reader.Next(ctx)
		// 在终止事件或 EOF 当下冻结生成耗时，避免包含随后完整输出检测。
		if errors.Is(nextErr, io.EOF) || event.Type == relay.EventMessageEnd {
			recordGenerationTiming(envelope, upstreamStarted, time.Now())
		}
		if budgetTruncated {
			// 已停止向客户端转发：只从上游收集权威 usage（message_delta / message_stop）。
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
					truncatedErr := errors.New("upstream Messages stream ended without message_stop")
					if tracker.State() == relay.CommitNotStarted {
						return true, truncatedErr
					}
					return true, abort(truncatedErr, "stream_aborted", http.StatusOK, nil)
				}
				rawChat, bodyErr := accumulator.responseBody(envelope.RequestID, livePromptIncludesCache(envelope))
				if bodyErr != nil {
					return true, abort(bodyErr, "stream_aborted", http.StatusOK, nil)
				}
				securedChat, auditResult, secureErr := chatHandler.applyOutputSecurity(
					withProviderExecutedToolCalls(ctx, accumulator.providerExecutedToolCalls()), envelope, requestMessages, rawChat)
				if secureErr != nil {
					// 客户端在最终输出扫描期间已断开（Esc / 中断）：不是拦截，记 client_canceled/408。
					if clientGoneDuring(ctx, secureErr) {
						return true, abort(ctx.Err(), "client_canceled", http.StatusRequestTimeout, nil)
					}
					if auditResult == nil {
						auditResult = &AuditResult{OutputFindings: []map[string]interface{}{}, OutputAction: "block"}
					}
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
				if len(securedChat) == 0 {
					securedChat = rawChat
				}
				var securedChatResponse ChatCompletionResponse
				if err := json.Unmarshal(securedChat, &securedChatResponse); err != nil {
					return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
				}
				liveSecurityAction = strongerSecurityAction(inputSecurityAction, outputActionOf(auditResult))
				if mode != relay.OutputSecurityStreamAudit {
					if err := pending.finish(ctx, accumulator, securedChatResponse, auditResult, writePending); err != nil {
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
					if pending.maskUnavailable || pending.maskUnavailableAlerted {
						auditResult = markMaskUnavailable(auditResult)
					}
					if pending.maskUnavailable && chatHandler.auditWriter != nil {
						chatHandler.writeSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), envelope, nil,
							"security_audit", "live Messages output mask could not be resolved; forwarded unmasked")
					}
				}
				if budgetTruncated {
					if err := closeOpenNativeBlocks(w, tracker, prepareHeaders, openBlocks); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				}
				textSent := hasLiveTextBeenCommitted(tracker, accumulator)
				terminalChat := securedChat
				if liveToolArgumentsIncomplete(accumulator) {
					terminalView := securedChatResponse
					for index := range terminalView.Choices {
						terminalView.Choices[index].Message.ToolCalls = nil
					}
					terminalChat, _ = json.Marshal(terminalView)
				}
				messagesResponse := h.transformChatToMessagesResponse(terminalChat, envelope.RequestID)
				if err := emitPendingNativeMessages(w, tracker, prepareHeaders, messagesResponse, textSent,
					!liveToolArgumentsIncomplete(accumulator)); err != nil {
					return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
				}
				if !budgetTruncated && mode == relay.OutputSecurityStreamAudit && string(securedChat) == string(rawChat) && outputActionOf(auditResult) != "block" &&
					!liveToolArgumentsIncomplete(accumulator) && len(accumulator.usageRaw) > 0 {
					if err := writeLiveMessagesRaw(w, tracker, prepareHeaders, accumulator.usageRaw, false); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				} else {
					if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "message_delta", map[string]interface{}{
						"type": "message_delta",
						"delta": map[string]interface{}{
							"stop_reason":   messagesResponse.StopReason,
							"stop_sequence": messagesResponse.StopSequence,
						},
						"usage": map[string]interface{}{"output_tokens": messagesResponse.Usage.OutputTokens},
					}, false); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				}
				if !budgetTruncated && mode == relay.OutputSecurityStreamAudit && string(securedChat) == string(rawChat) && outputActionOf(auditResult) != "block" &&
					!liveToolArgumentsIncomplete(accumulator) && len(accumulator.terminalRaw) > 0 {
					if err := writeLiveMessagesRaw(w, tracker, prepareHeaders, accumulator.terminalRaw, true); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				} else {
					if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "message_stop",
						map[string]interface{}{"type": "message_stop"}, true); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				}
				if budgetTruncated {
					usable := drainedUsageAvailable(accumulator, budgetUpstreamDone)
					finalizeRequest(markStreamBudgetTruncated(envelope, auditResult, usable), http.StatusOK, securedChat, auditResult)
					return true, nil
				}
				finalizeRequest("success", http.StatusOK, securedChat, auditResult)
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
		if openBlocks != nil {
			trackNativeBlock(openBlocks, event.Raw)
		}
		if budgetGuard.observe(event, liveUpstreamOutputTokens(accumulator)) {
			// 上游没有遵守 max_tokens：停止转发，限时继续读上游拿权威 usage。
			budgetTruncated = true
			budgetDrain = startStreamBudgetDrain(closeReader)
		}
	}
}

// trackNativeBlock 根据上游原始事件记录内容块的开始与结束。
func trackNativeBlock(open map[int]bool, raw []byte) {
	eventType := responseEventType(raw)
	if eventType != "content_block_start" && eventType != "content_block_stop" {
		return
	}
	var payload struct {
		Index *int `json:"index"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.Index == nil {
		return
	}
	index, ok := *payload.Index, true
	if !ok {
		return
	}
	if eventType == "content_block_start" {
		open[index] = true
	} else {
		delete(open, index)
	}
}

// closeOpenNativeBlocks 在预算截断时为仍打开的内容块补发 content_block_stop，保证事件序列合法。
func closeOpenNativeBlocks(w http.ResponseWriter, tracker *relay.CommitTracker, prepareHeaders func(), open map[int]bool) error {
	indexes := make([]int, 0, len(open))
	for index := range open {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	for _, index := range indexes {
		if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_stop",
			map[string]interface{}{"type": "content_block_stop", "index": index}, false); err != nil {
			return err
		}
	}
	return nil
}

func rewriteAnthropicDelta(raw []byte, delta string, reasoning bool) []byte {
	if len(raw) == 0 {
		return nil
	}
	var payload map[string]interface{}
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	nested, ok := payload["delta"].(map[string]interface{})
	if !ok {
		return nil
	}
	if reasoning {
		nested["thinking"] = delta
	} else {
		nested["text"] = delta
	}
	payload["delta"] = nested
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return encoded
}

func nativeMessagesRawEventSafeToForward(raw []byte, accumulator *liveStreamAccumulator) bool {
	eventType := responseEventType(raw)
	switch eventType {
	case "message_start", "ping":
		return true
	case "content_block_start":
		var payload map[string]interface{}
		if json.Unmarshal(raw, &payload) != nil {
			return false
		}
		block, _ := payload["content_block"].(map[string]interface{})
		blockType := nativeString(block["type"])
		return blockType == "text" || blockType == "thinking"
	case "content_block_stop":
		var payload map[string]interface{}
		if json.Unmarshal(raw, &payload) != nil {
			return false
		}
		index, ok := nativeJSONInt(payload["index"])
		if !ok {
			return false
		}
		if accumulator == nil {
			return false
		}
		choice := accumulator.choices[0]
		if choice == nil {
			return true
		}
		for _, tool := range choice.tools {
			if tool.index == index {
				return false
			}
		}
		return true
	default:
		if len(raw) == 0 || len(raw) > maxLiveOutputScanBytes {
			return false
		}
		var payload map[string]interface{}
		if json.Unmarshal(raw, &payload) != nil {
			return false
		}
		for _, key := range []string{"delta", "input", "content_block", "content"} {
			if _, present := payload[key]; present {
				return false
			}
		}
		return true
	}
}

func writeLiveMessagesRaw(w http.ResponseWriter, tracker *relay.CommitTracker, prepareHeaders func(), raw []byte, terminal bool) error {
	eventType := responseEventType(raw)
	if eventType == "" {
		eventType = "message"
	}
	return writeLiveResponsesPayload(w, tracker, prepareHeaders, eventType, raw, terminal)
}

func writeLiveMessagesJSON(w http.ResponseWriter, tracker *relay.CommitTracker, prepareHeaders func(), eventType string, payload map[string]interface{}, terminal bool) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return writeLiveResponsesPayload(w, tracker, prepareHeaders, eventType, raw, terminal)
}

func emitPendingNativeMessages(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	prepareHeaders func(),
	response *AnthropicMessagesResponse,
	textAlreadySent bool,
	allowTools bool,
) error {
	if response == nil {
		return nil
	}
	for index, block := range response.Content {
		if block.Type == "tool_use" {
			if !allowTools {
				continue
			}
			if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_start",
				map[string]interface{}{"type": "content_block_start", "index": index, "content_block": map[string]interface{}{
					"type": "tool_use", "id": block.ID, "name": block.Name, "input": map[string]interface{}{},
				}}, false); err != nil {
				return err
			}
			input, err := json.Marshal(block.Input)
			if err != nil {
				return err
			}
			if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_delta",
				map[string]interface{}{"type": "content_block_delta", "index": index, "delta": map[string]interface{}{
					"type": "input_json_delta", "partial_json": string(input),
				}}, false); err != nil {
				return err
			}
			if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_stop",
				map[string]interface{}{"type": "content_block_stop", "index": index}, false); err != nil {
				return err
			}
			continue
		}
		if textAlreadySent || block.Text == "" {
			continue
		}
		if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_start",
			map[string]interface{}{"type": "content_block_start", "index": index,
				"content_block": map[string]interface{}{"type": "text", "text": ""}}, false); err != nil {
			return err
		}
		if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_delta",
			map[string]interface{}{"type": "content_block_delta", "index": index, "delta": map[string]interface{}{
				"type": "text_delta", "text": block.Text,
			}}, false); err != nil {
			return err
		}
		if err := writeLiveMessagesJSON(w, tracker, prepareHeaders, "content_block_stop",
			map[string]interface{}{"type": "content_block_stop", "index": index}, false); err != nil {
			return err
		}
	}
	return nil
}
