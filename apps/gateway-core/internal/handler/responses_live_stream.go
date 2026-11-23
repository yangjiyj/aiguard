package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// tryLiveNativeResponsesStream keeps the native Responses wire shape while
// reusing the Chat security view. Tool events are withheld until the complete
// call has passed applyOutputSecurity.
func (h *ResponsesHandler) tryLiveNativeResponsesStream(
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
	if hasRequestRedaction(ctx, envelope) {
		return false, nil
	}
	// 需要加 AI 生成内容标识的回复改为先攒后发，由交付层统一加标识。
	if needsAIContentLabel(h.toolRiskClient, envelope) {
		return false, nil
	}
	if h == nil || envelope == nil || caller == nil || h.cfg == nil || !h.cfg.UpstreamStreaming {
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
	firstDeltaSeen := false
	finalized := false
	sequenceNumber := 0
	liveSecurityAction := inputSecurityAction
	prepareHeaders := func() {
		setRoutingHeaders(w, envelope, false)
		setSecurityActionHeader(w, liveSecurityAction, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		for name, values := range provider.SafeAnthropicResponseHeaders(meta.Header) {
			w.Header()[name] = append([]string(nil), values...)
		}
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
				fmt.Sprintf("live Responses stream terminated with status=%s", status))
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
				// Already-started Responses streams close with an error event whose
				// message is the block notice (rule, detail, block number).
				code = "security_blocked"
				notice := chatHandler.blockNoticeForResponse(context.WithoutCancel(ctx), envelope, "output", "live Responses stream blocked by security policy")
				if tracker.State() == relay.CommitNotStarted {
					setBlockNoticeHeaders(w, notice)
				}
				message = notice.Text
			}
			_, writeErr := writeLiveResponsesJSON(w, tracker, &sequenceNumber, prepareHeaders,
				"error", map[string]interface{}{"type": "error", "code": code, "message": message}, false)
			if writeErr != nil && streamErr == nil {
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
				fmt.Sprintf("live Responses output exceeded bounded security scan (%s)", accumulator.outputScanReason))
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
		if h.relayMetrics != nil {
			h.relayMetrics.Inc("stream_events")
		}
		if event.Type == relay.EventUnknown {
			accumulator.observeEvent(event)
			if len(event.Raw) > maxLiveOutputScanBytes {
				if scanErr := recordScanIncomplete("opaque_event_limit"); scanErr != nil {
					return scanErr
				}
			}
			if !nativeResponsesEventSafeToForward(event.Raw) {
				return nil
			}
			return writeLiveResponsesRaw(w, tracker, prepareHeaders, event.Raw, &sequenceNumber, false)
		}
		if event.Type == relay.EventStreamError {
			if event.Err != nil {
				return event.Err
			}
			return errors.New("upstream Responses stream error")
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
		effectiveDelta := event.Delta
		if event.Type == relay.EventTextDelta || event.Type == relay.EventReasoningDelta {
			previousTail, scanWindow, scanIncomplete := accumulator.observeEvent(event)
			recordFirstDelta(event)
			if scanIncomplete {
				if scanErr := recordScanIncomplete("response_scan_window"); scanErr != nil {
					return scanErr
				}
			}
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
										"security_audit", fmt.Sprintf("live Responses output mask could not be safely aligned (choice=%d); forwarded unmasked", event.Index))
								}
							}
						}
					}
				}
			}
		} else {
			accumulator.observeEvent(event)
		}
		if event.Type == relay.EventStreamStart || event.Type == relay.EventMessageStart {
			return writeLiveResponsesEvent(w, tracker, prepareHeaders, eventTypeForRelayEvent(event), event.Raw, &sequenceNumber, false)
		}
		if event.Type == relay.EventTextDelta || event.Type == relay.EventReasoningDelta {
			raw := rewriteResponsesDelta(event.Raw, effectiveDelta)
			if len(raw) == 0 {
				eventType := "response.output_text.delta"
				if event.Type == relay.EventReasoningDelta {
					eventType = "response.reasoning_summary_text.delta"
				}
				raw, _ = json.Marshal(map[string]interface{}{"type": eventType, "delta": effectiveDelta})
			}
			return writeLiveResponsesEvent(w, tracker, prepareHeaders, responseEventType(raw), raw, &sequenceNumber, false)
		}
		if event.Type == relay.EventUsageDelta || event.Type == relay.EventUsageFinal || event.Type == relay.EventCacheUsage {
			return writeLiveResponsesEvent(w, tracker, prepareHeaders, eventTypeForRelayEvent(event), event.Raw, &sequenceNumber, false)
		}
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
			raw = rewriteResponsesDelta(raw, event.Delta)
		}
		var payload map[string]interface{}
		if len(raw) == 0 || json.Unmarshal(raw, &payload) != nil {
			payload = map[string]interface{}{"type": eventTypeForRelayEvent(event)}
			if liveIsText(event) {
				payload["delta"] = event.Delta
			}
		}
		_, err := writeLiveResponsesJSON(w, tracker, &sequenceNumber, prepareHeaders, firstNonEmptyLive(responseEventType(raw), eventTypeForRelayEvent(event)), payload, false)
		return err
	}
	emit := newNativePendingEmitter(ctx, chatHandler, envelope, mode, accumulator, pending, emitImmediate, writePending, recordScanIncomplete, recordFirstDelta, func(event relay.StreamEvent) bool {
		if event.Type == relay.EventUnknown {
			switch responseEventType(event.Raw) {
			case "response.output_text.done", "response.content_part.done", "response.output_item.done", "response.reasoning_summary_text.done", "response.reasoning_text.done":
				return false
			}
			return nativeResponsesEventSafeToForward(event.Raw)
		}
		return true
	})

	for {
		event, nextErr := reader.Next(ctx)
		// 在终止事件或 EOF 当下冻结生成耗时，避免包含随后完整输出检测。
		if errors.Is(nextErr, io.EOF) || event.Type == relay.EventMessageEnd {
			recordGenerationTiming(envelope, upstreamStarted, time.Now())
		}
		if budgetTruncated {
			// 已停止向客户端转发：只从上游收集权威 usage（response.completed / response.incomplete）。
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
			// 原样回放的上游结束事件属于未转发的后半段输出，截断时一律用网关生成的 incomplete 结束事件。
			accumulator.terminalRaw = nil
			accumulator.terminalType = "response.incomplete"
			nextErr = io.EOF
		}
		if nextErr != nil {
			if errors.Is(nextErr, io.EOF) {
				if !accumulator.sawTerminal {
					truncatedErr := errors.New("upstream Responses stream ended without terminal event")
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
				terminalChecked := false
				if mode != relay.OutputSecurityStreamAudit && len(accumulator.terminalRaw) > 0 {
					terminalAudit, terminalErr := checkNativeResponsesTerminal(ctx, chatHandler, envelope, accumulator.terminalRaw, requestMessages)
					// 客户端在终态快照扫描期间已断开（Esc / 中断）：不是检测失败，记 client_canceled/408，
					// 不写 output_scan_incomplete（native_terminal_check_failed），也不继续回放终态帧。
					if clientGoneDuring(ctx, terminalErr) {
						return true, abort(ctx.Err(), "client_canceled", http.StatusRequestTimeout, nil)
					}
					if isGuardrailDetectionUnavailable(terminalErr) {
						return true, abort(terminalErr, "stream_aborted", http.StatusOK, terminalAudit)
					}
					if terminalErr != nil && errors.Is(terminalErr, errLiveStreamOutputBlocked) {
						return true, abort(terminalErr, "security_blocked", http.StatusForbidden, terminalAudit)
					}
					if terminalErr != nil {
						// The terminal snapshot could not be inspected: a coverage
						// gap in every mode, never a reason to stop the stream. The
						// raw terminal is not replayed verbatim (terminalChecked
						// stays false), the normalized one is emitted instead.
						if err := recordScanIncomplete("native_terminal_check_failed"); err != nil {
							return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
						}
						terminalAudit = nil
					}
					if terminalAudit != nil {
						auditResult.OutputFindings = append(auditResult.OutputFindings, terminalAudit.OutputFindings...)
						if terminalAudit.ResponseMetadata != nil && terminalAudit.ResponseMetadata["output_scan_incomplete"] == true {
							if auditResult.ResponseMetadata == nil {
								auditResult.ResponseMetadata = map[string]interface{}{}
							}
							auditResult.ResponseMetadata["output_scan_incomplete"] = true
							auditResult.ResponseMetadata["output_scan_incomplete_reason"] = "native_terminal_check_failed"
							if err := recordScanIncomplete("native_terminal_check_failed"); err != nil {
								return true, abort(err, "stream_aborted", http.StatusOK, terminalAudit)
							}
						}
					}
					terminalChecked = terminalErr == nil && !nativeTerminalNeedsRewrite(terminalAudit)
					if terminalErr == nil && nativeTerminalNeedsRewrite(terminalAudit) {
						// 终态快照按已脱敏的输出重建发出（下面 terminalChecked=false 走重建分支），记为脱敏。
						auditResult.OutputAction = strongerSecurityAction(auditResult.OutputAction, "mask")
					}
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
							"security_audit", "live Responses output mask could not be resolved; forwarded unmasked")
					}
				}
				terminalChat := securedChat
				if !liveToolArgumentsIncomplete(accumulator) {
					terminalChat = securedChat
				} else {
					terminalView := securedChatResponse
					for index := range terminalView.Choices {
						terminalView.Choices[index].Message.ToolCalls = nil
					}
					terminalChat, _ = json.Marshal(terminalView)
				}
				responsesResponse := h.transformChatToResponsesResponse(terminalChat, envelope.RequestID)
				if accumulator.terminalType == "response.incomplete" {
					responsesResponse.Status = "incomplete"
				}
				if budgetTruncated {
					responsesResponse.IncompleteDetails = &ResponsesIncompleteDetails{Reason: "max_output_tokens"}
				}
				if err := emitPendingNativeResponses(w, tracker, prepareHeaders, responsesResponse,
					hasLiveTextBeenCommitted(tracker, accumulator), !liveToolArgumentsIncomplete(accumulator), &sequenceNumber); err != nil {
					return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
				}
				if (mode == relay.OutputSecurityStreamAudit || terminalChecked) && string(securedChat) == string(rawChat) && outputActionOf(auditResult) != "block" &&
					!liveToolArgumentsIncomplete(accumulator) && len(accumulator.terminalRaw) > 0 {
					terminalType := firstNonEmptyLive(accumulator.terminalType, "response.completed")
					var terminalPayload map[string]interface{}
					_ = json.Unmarshal(accumulator.terminalRaw, &terminalPayload)
					if _, err := writeLiveResponsesJSON(w, tracker, &sequenceNumber, prepareHeaders, terminalType, terminalPayload, true); err != nil {
						return true, abort(err, "stream_aborted", http.StatusOK, auditResult)
					}
				} else {
					terminalType := "response.completed"
					if responsesResponse.Status == "incomplete" {
						terminalType = "response.incomplete"
					}
					payload := map[string]interface{}{"type": terminalType, "response": responsesResponse}
					if _, err := writeLiveResponsesJSON(w, tracker, &sequenceNumber, prepareHeaders, terminalType, payload, true); err != nil {
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
		if budgetGuard.observe(event, liveUpstreamOutputTokens(accumulator)) {
			// 上游没有遵守 max_output_tokens：停止转发，限时继续读上游拿权威 usage。
			budgetTruncated = true
			budgetDrain = startStreamBudgetDrain(closeReader)
		}
	}
}

func eventTypeForRelayEvent(event relay.StreamEvent) string {
	if event.Raw != nil {
		if eventType := responseEventType(event.Raw); eventType != "" {
			return eventType
		}
	}
	switch event.Type {
	case relay.EventStreamStart:
		return "response.created"
	case relay.EventMessageStart:
		return "response.in_progress"
	case relay.EventTextDelta:
		return "response.output_text.delta"
	case relay.EventReasoningDelta:
		return "response.reasoning_summary_text.delta"
	default:
		return "message"
	}
}

func rewriteResponsesDelta(raw []byte, delta string) []byte {
	if len(raw) == 0 {
		return nil
	}
	var payload map[string]interface{}
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	if _, ok := payload["delta"]; !ok {
		return nil
	}
	payload["delta"] = delta
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return encoded
}

func nativeResponsesEventSafeToForward(raw []byte) bool {
	switch responseEventType(raw) {
	case "response.created", "response.in_progress", "response.content_part.added",
		"response.output_text.delta", "response.reasoning_summary_text.delta",
		"response.reasoning_text.delta", "response.output_text.reasoning.delta":
		return true
	default:
		if len(raw) == 0 || len(raw) > maxLiveOutputScanBytes {
			return false
		}
		var payload map[string]interface{}
		if json.Unmarshal(raw, &payload) != nil {
			return false
		}
		for _, key := range []string{"delta", "arguments", "input", "output", "content"} {
			if _, present := payload[key]; present {
				return false
			}
		}
		return true
	}
}

func writeLiveResponsesRaw(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	prepareHeaders func(),
	raw []byte,
	sequenceNumber *int,
	terminal bool,
) error {
	return writeLiveResponsesEvent(w, tracker, prepareHeaders, responseEventType(raw), raw, sequenceNumber, terminal)
}

func writeLiveResponsesEvent(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	prepareHeaders func(),
	eventType string,
	raw []byte,
	sequenceNumber *int,
	terminal bool,
) error {
	if strings.TrimSpace(eventType) == "" {
		eventType = "message"
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if sequenceNumber != nil {
		*sequenceNumber++
	}
	return writeLiveResponsesPayload(w, tracker, prepareHeaders, eventType, raw, terminal)
}

func writeLiveResponsesJSON(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	sequenceNumber *int,
	prepareHeaders func(),
	eventType string,
	payload map[string]interface{},
	terminal bool,
) (int, error) {
	if sequenceNumber == nil {
		sequenceNumber = new(int)
	}
	payload["sequence_number"] = *sequenceNumber
	raw, err := json.Marshal(payload)
	if err != nil {
		return *sequenceNumber, err
	}
	*sequenceNumber++
	return *sequenceNumber, writeLiveResponsesPayload(w, tracker, prepareHeaders, eventType, raw, terminal)
}

func writeLiveResponsesPayload(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	prepareHeaders func(),
	eventType string,
	raw []byte,
	terminal bool,
) error {
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
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, raw); err != nil {
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
		return tracker.Transition(relay.CommitCompleted)
	}
	return nil
}

func emitPendingNativeResponses(
	w http.ResponseWriter,
	tracker *relay.CommitTracker,
	prepareHeaders func(),
	response *ResponsesResponse,
	textAlreadySent bool,
	allowTools bool,
	sequenceNumber *int,
) error {
	if response == nil {
		return nil
	}
	for outputIndex, item := range response.Output {
		if item.Type == "function_call" {
			if !allowTools {
				continue
			}
			added := item
			added.Status = "in_progress"
			added.Arguments = ""
			if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.output_item.added",
				map[string]interface{}{"type": "response.output_item.added", "output_index": outputIndex, "item": added}, false); err != nil {
				return err
			}
			if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.function_call_arguments.delta",
				map[string]interface{}{"type": "response.function_call_arguments.delta", "item_id": item.ID, "output_index": outputIndex, "delta": item.Arguments}, false); err != nil {
				return err
			}
			if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.function_call_arguments.done",
				map[string]interface{}{"type": "response.function_call_arguments.done", "item_id": item.ID, "output_index": outputIndex, "arguments": item.Arguments}, false); err != nil {
				return err
			}
			if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.output_item.done",
				map[string]interface{}{"type": "response.output_item.done", "output_index": outputIndex, "item": item}, false); err != nil {
				return err
			}
			continue
		}
		if textAlreadySent {
			continue
		}
		text := item.Text
		if len(item.Content) > 0 {
			text = item.Content[0].Text
		}
		if text == "" {
			continue
		}
		itemID := item.ID
		if itemID == "" {
			itemID = fmt.Sprintf("msg_live_%d", outputIndex)
		}
		if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.output_item.added",
			map[string]interface{}{"type": "response.output_item.added", "output_index": outputIndex,
				"item": map[string]interface{}{"id": itemID, "type": "message", "status": "in_progress", "role": "assistant", "content": []interface{}{}}}, false); err != nil {
			return err
		}
		if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.content_part.added",
			map[string]interface{}{"type": "response.content_part.added", "item_id": itemID, "output_index": outputIndex,
				"content_index": 0, "part": map[string]interface{}{"type": "output_text", "text": "", "annotations": []interface{}{}}}, false); err != nil {
			return err
		}
		if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.output_text.delta",
			map[string]interface{}{"type": "response.output_text.delta", "item_id": itemID, "output_index": outputIndex, "content_index": 0, "delta": text, "logprobs": []interface{}{}}, false); err != nil {
			return err
		}
		if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.output_text.done",
			map[string]interface{}{"type": "response.output_text.done", "item_id": itemID, "output_index": outputIndex, "content_index": 0, "text": text, "logprobs": []interface{}{}}, false); err != nil {
			return err
		}
		if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.content_part.done",
			map[string]interface{}{"type": "response.content_part.done", "item_id": itemID, "output_index": outputIndex,
				"content_index": 0, "part": map[string]interface{}{"type": "output_text", "text": text, "annotations": []interface{}{}}}, false); err != nil {
			return err
		}
		if _, err := writeLiveResponsesJSON(w, tracker, sequenceNumber, prepareHeaders, "response.output_item.done",
			map[string]interface{}{"type": "response.output_item.done", "output_index": outputIndex,
				"item": map[string]interface{}{"id": itemID, "type": "message", "status": "completed", "role": "assistant",
					"content": []interface{}{map[string]interface{}{"type": "output_text", "text": text, "annotations": []interface{}{}}}}}, false); err != nil {
			return err
		}
	}
	return nil
}
