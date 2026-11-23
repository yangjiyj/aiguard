package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func requiresNativeResponses(raw []byte) bool {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	// Compatibility only admits fields whose semantics are represented in the
	// normalized Chat request. Unknown extensions remain native-only rather
	// than silently disappearing during typed conversion.
	allowed := map[string]bool{"model": true, "input": true, "instructions": true, "max_output_tokens": true, "temperature": true, "top_p": true, "stream": true, "tools": true, "tool_choice": true, "metadata": true, "store": true, "parallel_tool_calls": true}
	for key := range body {
		if !allowed[key] {
			return true
		}
	}
	if store, ok := body["store"].(bool); ok && store {
		return true
	}
	if choice, exists := body["tool_choice"]; exists && choice != nil {
		if value, ok := choice.(string); ok {
			if value != "auto" && value != "none" && value != "required" {
				return true
			}
		} else {
			object, ok := choice.(map[string]any)
			if !ok || object["type"] != "function" || len(object) != 2 {
				return true
			}
			for key := range object {
				if key != "type" && key != "name" && key != "function" {
					return true
				}
			}
			name, _ := object["name"].(string)
			if nested, exists := object["function"]; exists {
				function, ok := nested.(map[string]any)
				if !ok || len(function) != 1 {
					return true
				}
				name, _ = function["name"].(string)
			}
			if name == "" {
				return true
			}
		}
	}

	if tools, ok := body["tools"].([]any); ok {
		for _, value := range tools {
			tool, _ := value.(map[string]any)
			typ, _ := tool["type"].(string)
			if typ != "function" {
				return true
			}
			for key := range tool {
				if key != "type" && key != "name" && key != "description" && key != "parameters" && key != "strict" {
					return true
				}
			}
		}
	}
	if input, ok := body["input"].([]any); ok {
		for _, value := range input {
			item, _ := value.(map[string]any)
			typ, _ := item["type"].(string)
			if typ != "" && typ != "message" && typ != "function_call" && typ != "function_call_output" {
				return true
			}
			allowedItem := map[string]bool{"type": true, "role": true, "content": true}
			if typ == "function_call" {
				allowedItem = map[string]bool{"type": true, "call_id": true, "name": true, "arguments": true}
			}
			if typ == "function_call_output" {
				allowedItem = map[string]bool{"type": true, "call_id": true, "output": true}
			}
			for key := range item {
				if !allowedItem[key] {
					return true
				}
			}

			if typ == "function_call_output" {
				if _, ok := item["output"].(string); !ok {
					return true
				}
			}
			if content, ok := item["content"].([]any); ok {
				for _, raw := range content {
					block, ok := raw.(map[string]any)
					if !ok {
						return true
					}
					kind, _ := block["type"].(string)
					if kind != "input_text" && kind != "output_text" && kind != "input_image" {
						return true
					}
					allowedContent := map[string]bool{"type": true, "text": true}
					if kind == "input_image" {
						allowedContent = map[string]bool{"type": true, "image_url": true}
					}
					for key := range block {
						if !allowedContent[key] {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func securedNativeResponsesBody(original, beforeChat []byte, securedChat *ChatCompletionRequest) ([]byte, error) {
	afterChat, err := json.Marshal(securedChat)
	if err != nil {
		return nil, err
	}
	if string(beforeChat) == string(afterChat) {
		return append([]byte(nil), original...), nil
	}

	var body map[string]any
	if err := json.Unmarshal(original, &body); err != nil {
		return nil, err
	}
	messageIndex := 0
	if _, ok := body["instructions"]; ok && messageIndex < len(securedChat.Messages) {
		if securedChat.Messages[messageIndex].Role == "system" {
			body["instructions"] = messageText(securedChat.Messages[messageIndex].Content)
			messageIndex++
		}
	}
	switch input := body["input"].(type) {
	case string:
		if messageIndex < len(securedChat.Messages) {
			body["input"] = messageText(securedChat.Messages[messageIndex].Content)
		}
	case []any:
		for i, value := range input {
			if messageIndex >= len(securedChat.Messages) {
				break
			}
			switch item := value.(type) {
			case string:
				input[i] = messageText(securedChat.Messages[messageIndex].Content)
				messageIndex++
			case map[string]any:
				itemType, _ := item["type"].(string)
				if itemType == "function_call_output" || strings.HasSuffix(itemType, "_call_output") {
					for messageIndex < len(securedChat.Messages) && securedChat.Messages[messageIndex].Role != "tool" {
						messageIndex++
					}
					if messageIndex >= len(securedChat.Messages) {
						break
					}
					item["output"] = messageText(securedChat.Messages[messageIndex].Content)
					messageIndex++
					continue
				}
				role, _ := item["role"].(string)
				if role == "" {
					continue
				}
				// 与 convertToChatRequest 对齐：只有 message 且 content 非空才会生成安全检查消息。
				// Codex 的 additional_tools 带 role 却没有 content，不能被回填出 content，否则上游报
				// Unknown parameter: 'input[0].content'，还会吃掉后面真实消息的文本造成错位。
				if itemType != "" && itemType != "message" {
					continue
				}
				switch content := item["content"].(type) {
				case string:
					if content == "" {
						continue
					}
				case []any:
					if len(content) == 0 {
						continue
					}
				default:
					continue
				}
				for messageIndex < len(securedChat.Messages) && securedChat.Messages[messageIndex].Role != role {
					messageIndex++
				}
				if messageIndex >= len(securedChat.Messages) {
					break
				}
				item["content"] = messageText(securedChat.Messages[messageIndex].Content)
				messageIndex++
			}
		}
		body["input"] = input
	}
	return json.Marshal(body)
}

func (h *ResponsesHandler) handleNativeResponses(
	ctx context.Context,
	w http.ResponseWriter,
	requestID string,
	startedAt time.Time,
	stream bool,
	securedBody []byte,
	request *ChatCompletionRequest,
	result *ProcessedRequestResult,
) {
	result.Envelope.EndpointType = "responses"
	result.Envelope.ResponsesCompatibility = false

	// 先攒后发期间的连接保活（GATEWAY_STREAM_KEEPALIVE_INTERVAL，0 关闭；只对流式请求生效）。
	// 保活从调上游之前一直覆盖到输出扫描结束；期间 handler 不写 w，Stop 返回后才独占 w。
	// 头已由保活发出（状态码固定 200）后，错误/拦截改走 Responses 的 SSE 失败事件。
	liveStreaming := stream && h.cfg != nil && h.cfg.UpstreamStreaming
	var keepalive *keepaliveSession
	if interval := streamKeepaliveIntervalOf(h.cfg); stream && interval > 0 {
		keepaliveAction := result.InputSecurityAction
		keepaliveActionHeader := securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient)
		keepalive = newKeepaliveSession(w, interval, defaultStreamKeepaliveSpec(), func() {
			w.Header().Set("X-Request-ID", requestID)
			setSecurityActionHeader(w, keepaliveAction, keepaliveActionHeader)
		})
	}
	defer keepalive.Stop()
	// 实时流尝试前停掉保活；头已由保活发出时不再尝试实时流，本次改走先攒后发。
	tryLive := func(streamCtx context.Context, caller ProviderCaller, streamEnvelope *modelrouter.RequestEnvelope, providerReq []byte, tracker *relay.CommitTracker) (bool, error) {
		if !liveStreaming {
			// 未开上游实时流：tryLiveNativeResponsesStream 本来就会在写 w 之前返回 not attempted；
			// 保活正在运行，这里直接返回，不去调用任何可能写 w 的函数。
			return false, nil
		}
		return keepalive.TryLive(func() (bool, error) {
			return h.tryLiveNativeResponsesStream(streamCtx, w, streamEnvelope, caller, providerReq,
				startedAt, result.InputSecurityAction, tracker, request.Messages)
		})
	}

	responseCaller := result.ProviderCaller
	fallbackUsed := false
	var respBody []byte
	var err error

	if result.UseV2ModelRouting {
		if !liveStreaming {
			keepalive.Start()
		}
		commitTracker := &relay.CommitTracker{}
		routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{
			Engine: h.modelRouteEngine, CredentialResolver: h.modelResolver,
			Factory: h.providerAdapterFactory, Envelope: result.Envelope,
			SecuredBody: securedBody, Streaming: stream,
			CommitTracker: commitTracker,
			StreamSink: func(streamCtx context.Context, caller ProviderCaller, streamEnvelope *modelrouter.RequestEnvelope, providerReq []byte) (bool, error) {
				return tryLive(streamCtx, caller, streamEnvelope, providerReq, commitTracker)
			},
			PreparedPlan: result.PreparedModelRoutePlan,
		})
		err = routeErr
		if routeResult != nil {
			if routeResult.LiveStream {
				return
			}
			responseCaller = routeResult.Caller
			respBody = routeResult.ResponseBody
			fallbackUsed = routeResult.UsedFallback
		}
		if err != nil && (!commitTracker.CanRetry() || isLiveStreamTerminalError(err)) {
			return
		}
	} else {
		if result.ModelRecord != nil && result.ModelRecord.ProtocolCapabilities.Explicit && !result.ModelRecord.SupportsConfiguredEndpoint("responses") {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "responses_native_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeNativeResponsesError(w, stream, requestID, "responses_native_unavailable", "configured upstream route does not support native Responses")
			return
		}
		providerReq, transformErr := responseCaller.TransformRequest(result.Envelope, securedBody)
		if transformErr != nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
			writeNativeResponsesError(w, stream, requestID, "invalid_request", "failed to transform native Responses request")
			return
		}
		// 预检和请求转换失败都在这之前写 w（保活尚未启动）；从这里起 handler 不再写 w，直到 Stop。
		if !liveStreaming {
			keepalive.Start()
		}
		if liveStreaming {
			commitTracker := &relay.CommitTracker{}
			liveAttempted, liveErr := tryLive(ctx, responseCaller, result.Envelope, providerReq, commitTracker)
			if liveAttempted {
				if liveErr == nil || !commitTracker.CanRetry() || isLiveStreamTerminalError(liveErr) {
					return
				}
				err = liveErr
			} else {
				respBody, err = callUpstream(ctx, responseCaller, result.Envelope, providerReq, stream)
			}
		} else {
			respBody, err = callUpstream(ctx, responseCaller, result.Envelope, providerReq, stream)
		}
		if err != nil {
			keepalive.Start() // 回退调用也可能很久
			fallbackResult := attemptFallbackCall(ctx, result.Envelope, securedBody, err, nativeResponsesFallbackPlan(result.FallbackProvider), stream)
			if fallbackResult.Attempted {
				recordFallbackEvent(ctx, h.auditWriter, result.Envelope, fallbackResult)
				if fallbackResult.Caller != nil {
					responseCaller = fallbackResult.Caller
				}
				respBody = fallbackResult.RespBody
				err = fallbackResult.Err
				fallbackUsed = fallbackResult.Err == nil
			}
		}
	}

	if err != nil {
		headersCommitted := keepalive.Stop() // 先停保活，之后才能写 w
		h.writeNativeResponsesUpstreamError(ctx, w, requestID, startedAt, stream, result.Envelope, err, headersCommitted)
		return
	}
	finalResponse, err := extractNativeResponsesFinal(respBody, stream)
	if err != nil {
		keepalive.Stop() // 流式请求下这里本来就写 SSE 失败事件，头是否已发出写法相同
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesError(w, stream, requestID, "provider_unavailable", "upstream returned an invalid Responses payload")
		return
	}
	securityView, providerCalls, err := nativeResponsesSecurityViewWithCalls(finalResponse)
	if err != nil {
		keepalive.Stop()
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesError(w, stream, requestID, "provider_unavailable", "failed to inspect upstream Responses payload")
		return
	}

	chatHandler := h.newChatHandler()
	securedView, auditResult, err := chatHandler.applyOutputSecurity(
		withProviderExecutedToolCalls(ctx, providerCalls), result.Envelope, request.Messages, securityView)
	// 输出扫描（含语义裁判）结束，保活停止；此后 handler 独占 w。
	headersCommitted := keepalive.Stop()
	if err != nil {
		// 客户端在输出扫描期间已断开（Esc / 中断）：没有响应可放行也没有响应可拦截，
		// 按 client_canceled 收尾，不记 security_blocked，不写拦截帧。上游响应已完整拿到，
		// 收尾带上它，让结算按真实 usage 走（正文只用于解析 usage，不写给客户端，不写内容日志，不落库）。
		if clientGoneDuring(ctx, err) {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, finalResponse, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
			writeNativeResponsesErrorWithStatus(w, stream, requestID, "request_canceled", "request was canceled", http.StatusRequestTimeout)
			return
		}
		notice := chatHandler.blockNoticeForResponse(ctx, result.Envelope, "output", err.Error())
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "security_blocked", blockHTTPStatus(notice), int(time.Since(startedAt)/time.Millisecond), auditResult)
		h.writeResponsesBlockResponse(w, chatHandler, result.Envelope, requestID, stream, notice)
		return
	}
	if outputActionOf(auditResult) == "mask" {
		// A native Responses payload cannot be rewritten in place. The configured
		// action is "mask", not "block": forward the original and raise an alert.
		auditResult = markMaskUnavailable(auditResult)
		if h.auditWriter != nil {
			h.auditWriter.WriteSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), result.Envelope, nil,
				"security_audit", "native Responses output could not be safely redacted; forwarded unmasked")
		}
	}
	outputBody := respBody
	auditBody := finalResponse
	if outputActionOf(auditResult) == "block" {
		securedFinal, secureErr := secureNativeResponsesOutput(finalResponse, securedView)
		if secureErr != nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), auditResult)
			// 头未发出时保持原有 JSON 错误；保活已发头时 JSON 会混进 SSE 流，改发 SSE 失败事件。
			writeNativeResponsesError(w, headersCommitted, requestID, "provider_unavailable", "failed to build a safe Responses result")
			return
		}
		outputBody = securedFinal
		auditBody = securedFinal
	}

	chatHandler.writeResponseContentLogs(ctx, result.Envelope, securedView)
	auditStatus := "success"
	if nativeResponsesStatus(finalResponse) == "incomplete" {
		auditStatus = "incomplete"
	}
	h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, auditBody, auditStatus, http.StatusOK, int(time.Since(startedAt)/time.Millisecond), auditResult)
	chatHandler.recordPromptCacheMetrics(auditBody)
	// 保活已发头时：状态码/响应头已固定，不再设置路由头和 X-Security-Action（慢请求拿不到输出阶段的安全动作与路由头）。
	if !headersCommitted {
		setRoutingHeaders(w, result.Envelope, fallbackUsed)
		setSecurityActionHeader(w, strongerSecurityAction(result.InputSecurityAction, outputActionOf(auditResult)), securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
	}
	if stream {
		if outputActionOf(auditResult) == "block" {
			var safeResponse ResponsesResponse
			if err := json.Unmarshal(outputBody, &safeResponse); err != nil {
				_ = writeResponsesStreamFailure(w, requestID, "provider_unavailable", "failed to encode safe Responses stream")
				return
			}
			_ = writeResponsesStream(w, &safeResponse)
			return
		}
		if !headersCommitted {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	// 保活已发头时 outputBody 本身就是完整的 SSE 字节，直接续写。
	writeGatewayJSONBody(w, deliverResponseBody(ctx, h.toolRiskClient, result.Envelope, outputBody))
}

func nativeResponsesFallbackPlan(plan *FallbackProviderPlan) *FallbackProviderPlan {
	var head, tail *FallbackProviderPlan
	for current := plan; current != nil; current = current.Next {
		if !current.ResponsesNative || current.Caller == nil {
			continue
		}
		hop := &FallbackProviderPlan{
			ProviderID:      current.ProviderID,
			ProviderType:    current.ProviderType,
			ModelID:         current.ModelID,
			UpstreamModelID: current.UpstreamModelID,
			Caller:          current.Caller,
			ResponsesNative: true,
			Route:           current.Route,
		}
		if head == nil {
			head = hop
		} else {
			tail.Next = hop
		}
		tail = hop
	}
	return head
}

func (h *ResponsesHandler) writeNativeResponsesUpstreamError(
	ctx context.Context,
	w http.ResponseWriter,
	requestID string,
	startedAt time.Time,
	stream bool,
	envelope *modelrouter.RequestEnvelope,
	err error,
	headersCommitted bool,
) {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesErrorWithStatus(w, stream, requestID, "request_canceled", "request was canceled", http.StatusRequestTimeout)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_timeout", http.StatusGatewayTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesErrorWithStatus(w, stream, requestID, "provider_timeout", "upstream provider timed out", http.StatusGatewayTimeout)
		return
	}
	if errors.Is(err, errResponsesNativeUnavailable) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "responses_native_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesError(w, stream, requestID, "responses_native_unavailable", "no usable upstream route supports native Responses")
		return
	}
	if errors.Is(err, errUserModelForbidden) {
		envelope.RejectReason = modelDenialRejectReason(ctx, envelope.Model)
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesError(w, stream, requestID, "forbidden_model", modelDeniedMessage(ctx, envelope.Model))
		return
	}
	if errors.Is(err, errModelRouteUnavailable) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
		writeNativeResponsesError(w, stream, requestID, "model_route_unavailable", routeUnavailableMessage(envelope))
		return
	}
	if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(startedAt)/time.Millisecond), &AuditResult{ResponseMetadata: map[string]interface{}{"error_message": retainedProviderErrorMessage(upstreamErr.Message)}})
		if headersCommitted {
			// 保活已把 200 + SSE 头发出，真实上游状态码无法再告知，只能改发 SSE 失败事件
			// （审计里的状态与状态码上面已按真实值记录）。
			logUpstreamHTTPError(requestID, "upstream_response", upstreamErr)
			_ = writeResponsesStreamFailure(w, "resp_"+strings.ReplaceAll(requestID, "-", ""), "upstream_error", clientUpstreamErrorMessage(upstreamErr, "upstream request failed"))
			return
		}
		// callUpstream returns before any native Responses bytes are written.  Returning
		// an SSE failure here would commit HTTP 200 and make clients report a broken
		// stream instead of handling the real upstream status.
		writeUpstreamErrorResponse(w, upstreamErr, requestID, "upstream_response")
		return
	}
	h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
	writeNativeResponsesError(w, stream, requestID, "provider_unavailable", "upstream provider is unavailable")
}

func writeNativeResponsesError(w http.ResponseWriter, stream bool, requestID, code, message string) {
	if stream {
		_ = writeResponsesStreamFailure(w, "resp_"+strings.ReplaceAll(requestID, "-", ""), code, message)
		return
	}
	writeErrorResponse(w, code, message, requestID)
}

func writeNativeResponsesErrorWithStatus(w http.ResponseWriter, stream bool, requestID, code, message string, status int) {
	if stream {
		_ = writeResponsesStreamFailure(w, "resp_"+strings.ReplaceAll(requestID, "-", ""), code, message)
		return
	}
	writeErrorResponseWithStatus(w, code, message, requestID, status)
}

func extractNativeResponsesFinal(raw []byte, stream bool) ([]byte, error) {
	if !stream {
		var response map[string]any
		if err := json.Unmarshal(raw, &response); err != nil {
			return nil, err
		}
		if response["object"] != "response" {
			return nil, fmt.Errorf("unexpected Responses object")
		}
		if status, _ := response["status"].(string); status != "completed" && status != "incomplete" {
			return nil, fmt.Errorf("native Responses terminal status is %q", status)
		}
		return append([]byte(nil), raw...), nil
	}

	normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, block := range strings.Split(normalized, "\n\n") {
		var dataLines []string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		var event map[string]json.RawMessage
		if json.Unmarshal([]byte(strings.Join(dataLines, "\n")), &event) != nil {
			continue
		}
		var typ string
		_ = json.Unmarshal(event["type"], &typ)
		if typ != "response.completed" && typ != "response.failed" && typ != "response.incomplete" {
			continue
		}
		if typ == "response.failed" {
			return nil, fmt.Errorf("native Responses terminal event is %s", typ)
		}
		if response := event["response"]; len(response) > 0 {
			return append([]byte(nil), response...), nil
		}
	}
	return nil, errors.New("native Responses SSE has no terminal response")
}

func nativeResponsesStatus(final []byte) string {
	var response struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(final, &response) != nil {
		return ""
	}
	return response.Status
}

func nativeResponsesSecurityView(final []byte) ([]byte, error) {
	view, _, err := nativeResponsesSecurityViewWithCalls(final)
	return view, err
}

// nativeResponsesSecurityViewWithCalls 同 nativeResponsesSecurityView，另返回由模型服务方执行的工具调用位置。
func nativeResponsesSecurityViewWithCalls(final []byte) ([]byte, providerExecutedToolCalls, error) {
	var response struct {
		ID     string `json:"id"`
		Model  string `json:"model"`
		Output []struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
			Input     any    `json:"input"`
			Action    any    `json:"action"`
			Content   any    `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(final, &response); err != nil {
		return nil, nil, err
	}
	inputTokens, outputTokens := responseUsageTokens(final)
	choice := Choice{Index: 0, Message: ChoiceMessage{Role: "assistant"}, FinishReason: "stop"}
	var textParts []string
	type callCandidate struct {
		call        ToolCall
		identity    string
		fingerprint string
		valid       bool
	}
	var candidates []callCandidate
	for _, item := range response.Output {
		textParts = append(textParts, responsesOutputText(item.Content)...)
		if !strings.Contains(item.Type, "call") {
			continue
		}
		name := item.Name
		if name == "" {
			name = item.Type
		}
		arguments := item.Arguments
		if arguments == "" && item.Input != nil {
			if value, ok := item.Input.(string); ok {
				var object map[string]any
				if json.Unmarshal([]byte(value), &object) == nil {
					arguments = value
				} else {
					key := "input"
					switch strings.ToLower(name) {
					case "shell_command", "run_shell", "local_shell_call":
						key = "command"
					case "apply_patch":
						key = "patch"
					}
					encoded, _ := json.Marshal(map[string]any{key: value})
					arguments = string(encoded)
				}
			} else if encoded, err := json.Marshal(item.Input); err == nil {
				arguments = string(encoded)
			}
		}
		if arguments == "" && item.Action != nil {
			if encoded, err := json.Marshal(item.Action); err == nil {
				arguments = string(encoded)
			}
		}
		identity, validIdentity := responsesToolIdentity(item.ID, item.CallID)
		candidates = append(candidates, callCandidate{
			identity:    identity,
			valid:       validIdentity,
			fingerprint: strings.Join([]string{item.Type, name, arguments}, "\x1f"),
			call: ToolCall{ID: item.CallID, Type: "function", OutputItemID: item.ID,
				Function:         ToolCallFunc{Name: name, Arguments: arguments},
				ProviderExecuted: !nativeResponsesClientExecutedCall(item.Type),
			},
		})
	}
	fingerprints := make(map[string]string, len(candidates))
	conflicts := make(map[string]bool)
	for _, candidate := range candidates {
		if !candidate.valid {
			continue
		}
		if previous, ok := fingerprints[candidate.identity]; ok && previous != candidate.fingerprint {
			conflicts[candidate.identity] = true
		} else {
			fingerprints[candidate.identity] = candidate.fingerprint
		}
	}
	for _, candidate := range candidates {
		candidate.call.ProtocolIdentityRejected = !candidate.valid || conflicts[candidate.identity]
		choice.Message.ToolCalls = append(choice.Message.ToolCalls, candidate.call)
	}
	choice.Message.Content = strings.Join(textParts, "\n")
	view := ChatCompletionResponse{
		ID: response.ID, Object: "chat.completion", Model: response.Model,
		Choices: []Choice{choice},
		Usage:   Usage{PromptTokens: inputTokens, CompletionTokens: outputTokens, TotalTokens: inputTokens + outputTokens},
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		return nil, nil, err
	}
	return encoded, providerExecutedToolCallsOf(view), nil
}

// nativeResponsesClientExecutedCall：由客户端在本机执行的调用项。其余带 call 的项（mcp_call、
// web_search_call 等）由模型服务方执行，参数会离开本机。
func nativeResponsesClientExecutedCall(itemType string) bool {
	switch itemType {
	case "function_call", "custom_tool_call", "local_shell_call":
		return true
	default:
		return false
	}
}

func responsesOutputText(content any) []string {
	var parts []any
	switch value := content.(type) {
	case []any:
		parts = value
	case map[string]any:
		parts = []any{value}
	default:
		return nil
	}
	texts := make([]string, 0, len(parts))
	for _, rawPart := range parts {
		part, ok := rawPart.(map[string]any)
		if !ok || part["type"] != "output_text" {
			continue
		}
		if text, ok := part["text"].(string); ok && text != "" {
			texts = append(texts, text)
		}
	}
	return texts
}

func responseUsageTokens(raw []byte) (int, int) {
	var response struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return 0, 0
	}
	return response.Usage.InputTokens, response.Usage.OutputTokens
}

// Keep native security projection item-aligned. Only after choosing the
// stateless bridge do adjacent function_call items become one assistant turn.
func coalesceResponsesToolCalls(raw []byte) ([]byte, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(body["messages"], &messages); err != nil {
		return nil, err
	}
	out := make([]map[string]json.RawMessage, 0, len(messages))
	for _, message := range messages {
		var role string
		_ = json.Unmarshal(message["role"], &role)
		if role == "assistant" && message["tool_calls"] != nil && len(out) > 0 {
			previous := out[len(out)-1]
			var previousRole string
			_ = json.Unmarshal(previous["role"], &previousRole)
			if previousRole == "assistant" && previous["tool_calls"] != nil && len(message["content"]) == 0 {
				var before, after []json.RawMessage
				if json.Unmarshal(previous["tool_calls"], &before) != nil || json.Unmarshal(message["tool_calls"], &after) != nil {
					return nil, errors.New("invalid function calls")
				}
				previous["tool_calls"], _ = json.Marshal(append(before, after...))
				continue
			}
		}
		out = append(out, message)
	}
	body["messages"], _ = json.Marshal(out)
	return json.Marshal(body)
}
