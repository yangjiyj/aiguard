package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/google/uuid"
)

type nativeJSONPath []any

type nativeInputBinding struct {
	messageIndex int
	path         nativeJSONPath
	original     string
	maskable     bool
}

type nativeMessagesDocument struct {
	raw      []byte
	root     map[string]any
	request  ChatCompletionRequest
	bindings []nativeInputBinding
}

type nativePreflightWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newNativePreflightWriter() *nativePreflightWriter {
	return &nativePreflightWriter{header: make(http.Header)}
}

func (w *nativePreflightWriter) Header() http.Header { return w.header }

func (w *nativePreflightWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *nativePreflightWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(body)
}

func (h *MessagesHandler) handleNativeMessagesRequest(w http.ResponseWriter, r *http.Request) {
	authInfo := auth.GetAuthInfo(r)
	requestID := strings.TrimSpace(authInfo.RequestID)
	if requestID == "" {
		requestID = uuid.New().String()
	}
	w.Header().Set("X-Request-Id", requestID)
	startedAt := time.Now()
	ctx := withBlockLedger(r.Context())

	if err := provider.ValidateAnthropicTransportQuery(r.URL.RawQuery); err != nil {
		h.recordNativeMessagesEarlyFailure(ctx, w, requestID, authInfo, "", startedAt, http.StatusBadRequest, "invalid_request", "credential query parameters are not allowed")
		return
	}

	bodyLimit := apiRequestBodyLimitBytes(h.cfg)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			logRequestBodyTooLarge(r, requestID, bodyLimit)
			h.recordNativeMessagesEarlyFailure(ctx, w, requestID, authInfo, "", startedAt, http.StatusRequestEntityTooLarge, "request_too_large", "request body too large")
			return
		}
		h.recordNativeMessagesEarlyFailure(ctx, w, requestID, authInfo, "", startedAt, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}

	document, err := parseNativeMessagesDocument(body)
	if err != nil {
		h.recordNativeMessagesEarlyFailure(ctx, w, requestID, authInfo, "", startedAt, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	document.request.EndpointType = "messages"

	metadata := &provider.AnthropicTransportMetadata{
		RequestHeaders: r.Header.Clone(),
		RawQuery:       r.URL.RawQuery,
	}
	ctx = provider.WithAnthropicTransportMetadata(ctx, metadata)
	chatHandler := h.newChatHandler()
	preflightWriter := newNativePreflightWriter()
	result, err := chatHandler.processSharedRequestPath(
		ctx, preflightWriter, r, requestID, authInfo, startedAt, &document.request, body,
	)
	if err != nil {
		flushNativeMessagesPreflightError(w, preflightWriter, requestID)
		return
	}
	if result.Envelope.ModelResolution == modelResolutionSuffixAlias {
		// 简写名已补全成全名：原始请求体里的 model 同步改成全名，
		// 上游、安全检查和计费看到的与客户端直接写全名完全一致。
		if rewritten, rewriteErr := rewriteRequestBodyModel(document.raw, result.Envelope.Model); rewriteErr == nil {
			document.raw = rewritten
			document.root["model"] = result.Envelope.Model
		}
	}
	if result.Envelope.QuotaHeartbeatStop != nil {
		defer result.Envelope.QuotaHeartbeatStop()
	}
	if result.ConcurrencyAcquired {
		defer h.rateLimiter.ReleaseConcurrency(ctx, result.Envelope.ProjectID)
	}
	result.Envelope.EndpointType = "messages"
	result.Envelope.Streaming = document.request.Stream
	if !result.UseV2ModelRouting && result.ModelRecord != nil && result.ModelRecord.ProtocolCapabilities.Explicit && !modelRouteSupportsEndpoint(*result.ModelRecord, "messages") {
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeAnthropicMessagesError(w, http.StatusBadRequest, "invalid_request", "configured upstream route does not support Anthropic Messages", requestID)
		return
	}

	if result.SecurityReply != nil {
		_ = chatHandler.finalizeSecurityReply(ctx, result)
		setRoutingHeaders(w, result.Envelope, false)
		setSecurityReplyHeaders(w, result.SecurityReply, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		writeNativeMessagesSecurityReply(w, requestID, result.Envelope.Model, result.SecurityReply.Content, document.request.Stream)
		return
	}

	securedBody, err := applyNativeMessagesInputSecurity(document)
	if err != nil {
		// A configured mask that cannot be projected back onto the native
		// request is forwarded unmasked with an alert; only "block" blocks.
		securedBody = document.raw
		if h.auditWriter != nil {
			h.auditWriter.WriteSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "input")), result.Envelope, nil,
				"security_audit", "native Messages input could not be safely redacted; forwarded unmasked")
		}
	}
	// 预算断流开启时收紧 max_tokens（只收紧不放大）；未下发上限时请求体逐字节不变。
	if limit, capped := billingOutputTokenCap(chatHandler.billingPreflight, result.Envelope.RequestID); capped {
		if cappedBody, changed, capErr := capMessagesRequestOutputTokens(securedBody, limit); capErr == nil && changed {
			securedBody = cappedBody
		}
	}

	// 先攒后发期间的连接保活（GATEWAY_STREAM_KEEPALIVE_INTERVAL，0 关闭；只对流式请求生效）。
	// 保活从调上游之前一直覆盖到输出扫描结束；期间 handler 不写 w，Stop 返回后才独占 w。
	// 头已由保活发出（状态码固定 200）后，错误/拦截改走 Anthropic SSE error 事件。
	liveStreaming := document.request.Stream && h.cfg != nil && h.cfg.UpstreamStreaming
	var keepalive *keepaliveSession
	if interval := streamKeepaliveIntervalOf(h.cfg); document.request.Stream && interval > 0 {
		keepaliveAction := result.InputSecurityAction
		keepaliveActionHeader := securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient)
		keepalive = newKeepaliveSession(w, interval, defaultStreamKeepaliveSpec(), func() {
			w.Header().Set("X-Request-Id", requestID)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			setSecurityActionHeader(w, keepaliveAction, keepaliveActionHeader)
		})
	}
	defer keepalive.Stop()
	// 实时流尝试前停掉保活；头已由保活发出时不再尝试实时流，本次改走先攒后发。
	tryLive := func(streamCtx context.Context, caller ProviderCaller, streamEnvelope *modelrouter.RequestEnvelope, providerReq []byte, tracker *relay.CommitTracker) (bool, error) {
		if !liveStreaming {
			// 未开上游实时流：tryLiveNativeMessagesStream 本来就会在写 w 之前返回 not attempted；
			// 保活正在运行，这里直接返回，不去调用任何可能写 w 的函数。
			return false, nil
		}
		return keepalive.TryLive(func() (bool, error) {
			return h.tryLiveNativeMessagesStream(streamCtx, w, streamEnvelope, caller, providerReq,
				startedAt, result.InputSecurityAction, tracker, document.request.Messages)
		})
	}
	if !liveStreaming {
		keepalive.Start()
	}

	responseCaller := result.ProviderCaller
	fallbackUsed := false
	var responseBody []byte
	if result.UseV2ModelRouting {
		commitTracker := &relay.CommitTracker{}
		routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{
			Engine: h.modelRouteEngine, CredentialResolver: h.modelResolver,
			Factory: h.providerAdapterFactory, Envelope: result.Envelope,
			SecuredBody: securedBody, Streaming: document.request.Stream,
			CommitTracker: commitTracker,
			StreamSink: func(streamCtx context.Context, caller ProviderCaller, streamEnvelope *modelrouter.RequestEnvelope, providerReq []byte) (bool, error) {
				return tryLive(streamCtx, caller, streamEnvelope, providerReq, commitTracker)
			},
		})
		err = routeErr
		if routeResult != nil {
			if routeResult.LiveStream {
				return
			}
			responseCaller = routeResult.Caller
			responseBody = routeResult.ResponseBody
			fallbackUsed = routeResult.UsedFallback
		}
		if err != nil && (!commitTracker.CanRetry() || isLiveStreamTerminalError(err)) {
			return
		}
	} else {
		var providerRequest []byte
		providerRequest, err = responseCaller.TransformRequest(result.Envelope, securedBody)
		if err == nil {
			if liveStreaming {
				commitTracker := &relay.CommitTracker{}
				liveAttempted, liveErr := tryLive(ctx, responseCaller, result.Envelope, providerRequest, commitTracker)
				if liveAttempted {
					if liveErr == nil || !commitTracker.CanRetry() || isLiveStreamTerminalError(liveErr) {
						return
					}
					err = liveErr
				} else {
					responseBody, err = callUpstream(ctx, responseCaller, result.Envelope, providerRequest, document.request.Stream)
				}
			} else {
				responseBody, err = callUpstream(ctx, responseCaller, result.Envelope, providerRequest, document.request.Stream)
			}
		}
		if err != nil {
			keepalive.Start() // 回退调用也可能很久
			fallbackResult := attemptFallbackCall(ctx, result.Envelope, securedBody, err, result.FallbackProvider, document.request.Stream)
			if fallbackResult.Attempted {
				recordFallbackEvent(ctx, h.auditWriter, result.Envelope, fallbackResult)
				if fallbackResult.Caller != nil {
					responseCaller = fallbackResult.Caller
				}
				responseBody = fallbackResult.RespBody
				err = fallbackResult.Err
				fallbackUsed = fallbackResult.Err == nil
			}
		}
	}
	if err != nil {
		headersCommitted := keepalive.Stop() // 先停保活，之后才能写 w
		h.writeNativeMessagesUpstreamError(ctx, w, requestID, startedAt, result.Envelope, err, headersCommitted)
		return
	}
	if result.Envelope.UpstreamProtocol != "" && !strings.EqualFold(result.Envelope.UpstreamProtocol, "messages") {
		responseBody, err = transformProviderResponse(responseCaller, result.Envelope, responseBody)
		if err != nil {
			headersCommitted := keepalive.Stop() // 先停保活，之后才能写 w
			h.writeNativeMessagesUpstreamError(ctx, w, requestID, startedAt, result.Envelope, err, headersCommitted)
			return
		}
	}

	securedResponse, securityView, auditBody, auditResult, err := inspectNativeMessagesOutput(
		ctx, chatHandler, result.Envelope, document.request.Messages, responseBody, document.request.Stream,
	)
	// 输出扫描（含语义裁判）结束，保活停止；此后 handler 独占 w。
	headersCommitted := keepalive.Stop()
	if err != nil {
		// 客户端在输出扫描期间已断开（Esc / 中断）：没有响应可放行也没有响应可拦截，
		// 按 client_canceled 收尾，不记 security_blocked，不写拦截帧。上游响应已完整拿到，
		// 收尾带上它的 usage 载体，让结算按真实 usage 走（只含 usage，不含正文；不写给客户端，不写内容日志，不落库）。
		if clientGoneDuring(ctx, err) {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, auditBody, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
			if headersCommitted {
				writeCommittedAnthropicStreamError(w, "api_error", "request was canceled", requestID)
			} else {
				writeAnthropicMessagesError(w, http.StatusRequestTimeout, "api_error", "request was canceled", requestID)
			}
			return
		}
		if auditResult == nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			if headersCommitted {
				writeCommittedAnthropicStreamError(w, "api_error", "upstream returned an invalid Messages payload", requestID)
				return
			}
			writeAnthropicMessagesError(w, http.StatusBadGateway, "api_error", "upstream returned an invalid Messages payload", requestID)
			return
		}
		notice := chatHandler.blockNoticeForResponse(ctx, result.Envelope, "output", "native Messages response blocked by security policy")
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "security_blocked", blockHTTPStatus(notice), int(time.Since(startedAt)/time.Millisecond), auditResult)
		if headersCommitted {
			writeCommittedMessagesBlock(w, requestID, result.Envelope.Model, notice)
			return
		}
		writeMessagesBlockResponse(w, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient), requestID, result.Envelope.Model, document.request.Stream, notice)
		return
	}

	chatHandler.writeResponseContentLogs(ctx, result.Envelope, securityView)
	chatHandler.recordProxyUsageIfNeeded(ctx, result.Envelope, securityView)
	h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, auditBody, "success", http.StatusOK, int(time.Since(startedAt)/time.Millisecond), auditResult)
	chatHandler.recordPromptCacheMetrics(auditBody)

	if !headersCommitted {
		copyNativeMessagesHeaders(w.Header(), metadata.ResponseHeaders)
		setRoutingHeaders(w, result.Envelope, fallbackUsed)
		setSecurityActionHeader(w, strongerSecurityAction(result.InputSecurityAction, outputActionOf(auditResult)), securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		if document.request.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	// 保活已发头时：状态码/响应头已固定，securedResponse 本身就是完整的 SSE 字节，直接续写。
	// 慢请求因此拿不到上游响应头、路由头和输出阶段的 X-Security-Action（头已发出，无法补）。
	writeGatewayJSONBody(w, deliverResponseBody(ctx, h.toolRiskClient, result.Envelope, securedResponse))
}

func (h *MessagesHandler) recordNativeMessagesEarlyFailure(
	ctx context.Context,
	w http.ResponseWriter,
	requestID string,
	authInfo *auth.AuthInfo,
	model string,
	startedAt time.Time,
	status int,
	auditStatus string,
	message string,
) {
	envelope := buildPartialEnvelope(requestID, authInfo, model, "messages")
	if envelope.SessionID != "" {
		h.auditWriter.UpsertAgentSession(ctx, envelope)
	}
	h.auditWriter.EnsureRequestLog(ctx, envelope)
	h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, auditStatus, status, int(time.Since(startedAt)/time.Millisecond), nil)
	writeAnthropicMessagesError(w, status, anthropicErrorTypeForStatus(status), message, requestID)
}

func (h *MessagesHandler) writeNativeMessagesUpstreamError(
	ctx context.Context,
	w http.ResponseWriter,
	requestID string,
	startedAt time.Time,
	envelope *modelrouter.RequestEnvelope,
	err error,
	headersCommitted bool,
) {
	// 审计口径（状态与状态码）始终按原来的写；headersCommitted=true 表示保活已把 200 + SSE 头发出，
	// 状态码改不了，只能把同样的错误类型和文案改发成 Anthropic SSE error 事件。
	emit := func(status int, errorType, message string) {
		if headersCommitted {
			writeCommittedAnthropicStreamError(w, errorType, message, requestID)
			return
		}
		writeAnthropicMessagesError(w, status, errorType, message, requestID)
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
		emit(http.StatusRequestTimeout, "api_error", "request was canceled")
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_timeout", http.StatusGatewayTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
		emit(http.StatusGatewayTimeout, "api_error", "upstream provider timed out")
		return
	}
	if errors.Is(err, errUserModelForbidden) {
		envelope.RejectReason = modelDenialRejectReason(ctx, envelope.Model)
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
		emit(http.StatusForbidden, "api_error", modelDeniedMessage(ctx, envelope.Model))
		return
	}
	if errors.Is(err, errModelRouteUnavailable) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
		emit(http.StatusServiceUnavailable, "api_error", routeUnavailableMessage(envelope))
		return
	}
	if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
		logUpstreamHTTPError(requestID, "upstream_response", upstreamErr)
		// 所有上游错误均留存定点遮盖后的响应原因和中文解释，不包含请求内容。
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(startedAt)/time.Millisecond), upstreamRejectionAuditResult(envelope, upstreamErr, "upstream_response"))
		if !headersCommitted {
			copyNativeMessagesHeaders(w.Header(), provider.SafeAnthropicResponseHeaders(upstreamErr.Headers))
			w.Header().Set("X-Request-ID", requestID)
			w.Header().Set("X-JJDGuard-Error-Stage", "upstream_response")
			if envelope.UpstreamProtocol != "" {
				w.Header().Set("X-JJDGuard-Upstream-Protocol", envelope.UpstreamProtocol)
			}
		}
		// 请求类白名单透传定点遮盖后的原文；账号和服务故障仅返回中文解释。
		emit(upstreamErr.StatusCode, anthropicErrorTypeForStatus(upstreamErr.StatusCode),
			clientUpstreamErrorMessage(upstreamErr, "upstream Messages request failed"))
		return
	}
	h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
	emit(http.StatusBadGateway, "api_error", "upstream Messages request failed")
}

// writeCommittedAnthropicStreamError 在保活已发出 200 + SSE 头后，把错误改发成 Anthropic SSE error 事件。
// message 与原 JSON 错误体一致，request_id 放在顶层（与 JSON 错误体同形）。不再写状态码和响应头。
func writeCommittedAnthropicStreamError(w http.ResponseWriter, errorType, message, requestID string) {
	writeAnthropicSSEEvent(w, "error", map[string]any{
		"type":       "error",
		"error":      map[string]string{"type": errorType, "message": message},
		"request_id": requestID,
	})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// writeCommittedMessagesBlock 是保活已发头后的输出拦截：
// error 模式改发 permission_error 的 SSE error 事件（带 block_id，内容不泄露）；
// message 模式本来就是 SSE，事件序列与快请求相同，阻断说明以助手消息展示。
func writeCommittedMessagesBlock(w http.ResponseWriter, requestID, model string, notice securityBlockNotice) {
	if notice.Mode == blockResponseModeMessage {
		writeNativeMessagesSecurityReply(w, requestID, model, notice.Text, true)
		return
	}
	detail := map[string]string{"type": "permission_error", "message": notice.Text}
	if notice.Attribution.BlockID != "" {
		detail["block_id"] = notice.Attribution.BlockID
	}
	if notice.Attribution.OperationID != "" {
		detail["operation_id"] = notice.Attribution.OperationID
	}
	writeAnthropicSSEEvent(w, "error", map[string]any{"type": "error", "error": detail, "request_id": requestID})
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func flushNativeMessagesPreflightError(w http.ResponseWriter, buffered *nativePreflightWriter, requestID string) {
	status := buffered.status
	if status == 0 || status < http.StatusBadRequest {
		status = http.StatusBadRequest
	}
	message := http.StatusText(status)
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(buffered.body.Bytes(), &payload) == nil && payload.Error.Message != "" {
		message = payload.Error.Message
	}
	// 预算断流的业务码需要原样带给 Anthropic 客户端，其余错误保持原有形状。
	businessCode := ""
	if payload.Error.Code == budgetExhaustedCode || payload.Error.Code == "billing_unavailable" || payload.Error.Code == requestStatusModelNotFound ||
		payload.Error.Code == "forbidden_model" || payload.Error.Code == "key_model_not_allowed" {
		businessCode = payload.Error.Code
	}
	for name, values := range buffered.header {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Content-Type") {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if businessCode != "" {
		writeAnthropicMessagesErrorWithCode(w, status, anthropicErrorTypeForStatus(status), businessCode, message, requestID)
		return
	}
	writeAnthropicMessagesError(w, status, anthropicErrorTypeForStatus(status), message, requestID)
}

func writeAnthropicMessagesErrorWithCode(w http.ResponseWriter, status int, errorType, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-Id", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":       "error",
		"error":      map[string]string{"type": errorType, "code": code, "message": message},
		"request_id": requestID,
	})
}

func writeAnthropicMessagesError(w http.ResponseWriter, status int, errorType, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-Id", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]string{
			"type":    errorType,
			"message": message,
		},
		"request_id": requestID,
	})
}

func anthropicErrorTypeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	default:
		if status >= http.StatusInternalServerError {
			return "api_error"
		}
		return "invalid_request_error"
	}
}

func writeNativeMessagesSecurityReply(w http.ResponseWriter, requestID, model, content string, stream bool) {
	response := &AnthropicMessagesResponse{
		ID: "msg_" + strings.ReplaceAll(requestID, "-", ""), Type: "message",
		Role: "assistant", Model: model,
		Content:    []AnthropicContentBlock{{Type: "text", Text: content}},
		StopReason: "end_turn", Usage: AnthropicUsage{},
	}
	if stream {
		writeAnthropicMessagesStream(w, response)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(response)
}

func copyNativeMessagesHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func parseNativeMessagesDocument(raw []byte) (*nativeMessagesDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid JSON format")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid JSON format")
	}
	if root == nil {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	model, ok := root["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return nil, fmt.Errorf("model must not be empty")
	}
	messages, ok := root["messages"].([]any)
	if !ok || len(messages) == 0 {
		return nil, fmt.Errorf("messages must not be empty")
	}

	document := &nativeMessagesDocument{raw: raw, root: root}
	document.request = ChatCompletionRequest{
		Model: model, PreserveOriginalBody: true, DeferProviderTransform: true,
		EndpointType: "messages",
	}
	if stream, exists := root["stream"]; exists {
		value, valid := stream.(bool)
		if !valid {
			return nil, fmt.Errorf("stream must be a boolean")
		}
		document.request.Stream = value
	}
	if maxTokens, exists := root["max_tokens"]; exists {
		value, valid := nativeJSONInt(maxTokens)
		if !valid || value < 0 {
			return nil, fmt.Errorf("max_tokens must be a non-negative integer")
		}
		document.request.MaxTokens = value
	}
	if temperature, exists := root["temperature"]; exists {
		value, valid := nativeJSONFloat(temperature)
		if !valid {
			return nil, fmt.Errorf("temperature must be a number")
		}
		document.request.Temperature = value
	}

	if err := validateNativeContentImages(root["system"]); err != nil {
		return nil, err
	}
	document.collectInputContent(root["system"], nativeJSONPath{"system"}, "system", "")
	for messageIndex, rawMessage := range messages {
		message, valid := rawMessage.(map[string]any)
		if !valid {
			return nil, fmt.Errorf("messages[%d] must be an object", messageIndex)
		}
		role, valid := message["role"].(string)
		if !valid || strings.TrimSpace(role) == "" {
			return nil, fmt.Errorf("messages[%d].role must not be empty", messageIndex)
		}
		if err := validateNativeContentImages(message["content"]); err != nil {
			return nil, err
		}
		start := len(document.request.Messages)
		document.collectInputContent(message["content"], nativeJSONPath{"messages", messageIndex, "content"}, role, "")
		for i := start; i < len(document.request.Messages); i++ {
			document.request.Messages[i].SecurityMessageRole = role
		}
	}
	document.collectTools(root["tools"])
	return document, nil
}

func validateNativeContentImages(value any) error {
	switch content := value.(type) {
	case []any:
		for _, rawBlock := range content {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			switch nativeString(block["type"]) {
			case "image":
				if err := validateNativeImageBlock(block); err != nil {
					return err
				}
			case "tool_result":
				if err := validateNativeContentImages(block["content"]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateNativeImageBlock(block map[string]any) error {
	source, ok := block["source"].(map[string]any)
	if !ok || nativeString(source["type"]) != "base64" {
		return fmt.Errorf("image source type must be base64")
	}
	switch nativeString(source["media_type"]) {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
	default:
		return fmt.Errorf("unsupported image media_type")
	}
	data := nativeString(source["data"])
	if data == "" {
		return fmt.Errorf("image data must not be empty")
	}
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	if _, err := io.Copy(io.Discard, decoder); err != nil {
		return fmt.Errorf("invalid image base64 data")
	}
	return nil
}

func nativeJSONInt(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 32)
	return int(parsed), err == nil
}

func nativeJSONFloat(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(number.String(), 64)
	return parsed, err == nil
}

func (d *nativeMessagesDocument) addInputText(role, toolCallID, text string, path nativeJSONPath, maskable bool, toolCalls []ToolCall) {
	message := Message{
		Role: role, Content: jsonQuote(text), ToolCallID: toolCallID,
		ToolCalls: toolCalls,
	}
	setNativeInspectionOrigin(&message, path)
	index := len(d.request.Messages)
	d.request.Messages = append(d.request.Messages, message)
	d.bindings = append(d.bindings, nativeInputBinding{
		messageIndex: index,
		path:         append(nativeJSONPath(nil), path...),
		original:     text,
		maskable:     maskable,
	})
}

func (d *nativeMessagesDocument) addInputImage(role, toolCallID string, block map[string]any, path nativeJSONPath) {
	content, err := json.Marshal([]any{block})
	if err != nil {
		return
	}
	message := Message{
		Role: role, ToolCallID: toolCallID, Content: content,
	}
	setNativeInspectionOrigin(&message, path)
	d.request.Messages = append(d.request.Messages, message)
}

func (d *nativeMessagesDocument) addInputAttachment(role, toolCallID string, block map[string]any, path nativeJSONPath) {
	content, err := json.Marshal([]any{block})
	if err != nil {
		return
	}
	message := Message{
		Role: role, ToolCallID: toolCallID, Content: content,
	}
	setNativeInspectionOrigin(&message, path)
	d.request.Messages = append(d.request.Messages, message)
}

func (d *nativeMessagesDocument) collectInputContent(value any, path nativeJSONPath, role, toolCallID string) {
	switch content := value.(type) {
	case string:
		d.addInputText(role, toolCallID, content, path, true, nil)
	case []any:
		for index, rawBlock := range content {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			blockPath := appendPath(path, index)
			typeName, _ := block["type"].(string)
			switch typeName {
			case "text":
				if text, ok := block["text"].(string); ok {
					d.addInputText(role, toolCallID, text, appendPath(blockPath, "text"), true, nil)
				}
			case "thinking":
				if thinking, ok := block["thinking"].(string); ok {
					d.addInputText(role, toolCallID, thinking, appendPath(blockPath, "thinking"), false, nil)
				}
			case "image":
				d.addInputImage(role, toolCallID, block, blockPath)
			case "input_image":
				d.addInputImage(role, toolCallID, block, blockPath)
			case "document", "file", "input_file", "input_document", "attachment":
				d.addInputAttachment(role, toolCallID, block, blockPath)
			case "tool_result":
				resultID, _ := block["tool_use_id"].(string)
				start := len(d.request.Messages)
				d.collectInputContent(block["content"], appendPath(blockPath, "content"), "tool", resultID)
				if isError, _ := block["is_error"].(bool); isError {
					for i := start; i < len(d.request.Messages); i++ {
						d.request.Messages[i].ToolResultError = true
					}
				}
			case "tool_use", "server_tool_use":
				id, _ := block["id"].(string)
				name, _ := block["name"].(string)
				input := block["input"]
				arguments, marshalErr := json.Marshal(input)
				if marshalErr != nil {
					continue
				}
				call := ToolCall{
					ID: id, Type: "function",
					Function: ToolCallFunc{Name: name, Arguments: string(arguments)},
				}
				d.addInputText(role, toolCallID, string(arguments), appendPath(blockPath, "input"), false, []ToolCall{call})
				if name != "" {
					d.addInputText(role, toolCallID, name, appendPath(blockPath, "name"), false, nil)
				}
			default:
				if text, ok := block["text"].(string); ok {
					d.addInputText(role, toolCallID, text, appendPath(blockPath, "text"), true, nil)
				}
			}
		}
	}
}

func (d *nativeMessagesDocument) collectTools(value any) {
	tools, ok := value.([]any)
	if !ok {
		return
	}
	for index, rawTool := range tools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		description, _ := tool["description"].(string)
		var schema json.RawMessage
		if inputSchema, exists := tool["input_schema"]; exists {
			if encoded, err := json.Marshal(inputSchema); err == nil {
				schema = encoded
			}
		}
		d.request.Tools = append(d.request.Tools, ToolDef{
			Type: "function",
			Function: ToolFunc{
				Name: name, Description: description, Parameters: schema,
			},
		})
		toolPath := nativeJSONPath{"tools", index}
		if name != "" {
			d.addInputText("system", "", name, appendPath(toolPath, "name"), false, nil)
		}
		if description != "" {
			d.addInputText("system", "", description, appendPath(toolPath, "description"), true, nil)
		}
		if len(schema) > 0 {
			d.addInputText("system", "", string(schema), appendPath(toolPath, "input_schema"), false, nil)
		}
	}
}

func appendPath(path nativeJSONPath, component any) nativeJSONPath {
	result := make(nativeJSONPath, len(path), len(path)+1)
	copy(result, path)
	return append(result, component)
}

func applyNativeMessagesInputSecurity(document *nativeMessagesDocument) ([]byte, error) {
	changed := false
	for _, binding := range document.bindings {
		if binding.messageIndex < 0 || binding.messageIndex >= len(document.request.Messages) {
			return nil, fmt.Errorf("native input security binding is out of range")
		}
		secured := messageText(document.request.Messages[binding.messageIndex].Content)
		if secured == binding.original {
			continue
		}
		if !binding.maskable || secured == "" {
			return nil, fmt.Errorf("structured native input required unsafe redaction")
		}
		if err := setNativeJSONString(document.root, binding.path, secured); err != nil {
			return nil, err
		}
		changed = true
	}
	if !changed {
		return document.raw, nil
	}
	return json.Marshal(document.root)
}

func setNativeJSONString(root any, path nativeJSONPath, value string) error {
	if len(path) == 0 {
		return fmt.Errorf("native JSON path is empty")
	}
	current := root
	for index, component := range path {
		last := index == len(path)-1
		switch key := component.(type) {
		case string:
			object, ok := current.(map[string]any)
			if !ok {
				return fmt.Errorf("native JSON path does not reference an object")
			}
			if last {
				if _, ok := object[key].(string); !ok {
					return fmt.Errorf("native JSON path does not reference a string")
				}
				object[key] = value
				return nil
			}
			current = object[key]
		case int:
			array, ok := current.([]any)
			if !ok || key < 0 || key >= len(array) {
				return fmt.Errorf("native JSON path does not reference an array item")
			}
			if last {
				if _, ok := array[key].(string); !ok {
					return fmt.Errorf("native JSON path does not reference a string")
				}
				array[key] = value
				return nil
			}
			current = array[key]
		default:
			return fmt.Errorf("native JSON path component is invalid")
		}
	}
	return fmt.Errorf("native JSON path could not be updated")
}

type nativeOutputBinding struct {
	choiceIndex int
	path        nativeJSONPath
	original    string
	maskable    bool
	sseRefs     []nativeSSETextRef
}

type nativeMessagesUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

type nativeOutputProjection struct {
	raw      []byte
	root     map[string]any
	view     ChatCompletionResponse
	bindings []nativeOutputBinding
	toolRefs map[int]int
	usage    nativeMessagesUsage
	// usageReported 记录上游响应里是否真的出现过 usage 对象。全 0 的 usage 与「上游没给 usage」在 usage 字段上
	// 无法区分；断开收尾的 usage 载体（见 inspectNativeMessagesOutput）只在上游真的报了 usage 时才返回，
	// 否则会把「没给」伪造成「上游报了 0 token」，让结算按 0 走。
	usageReported bool
	records       []nativeSSERecord
}

// nativeUsageReported 判断 usage 值是否是一个真实的 usage 对象。
func nativeUsageReported(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

type nativeSSERecord struct {
	start int
	end   int
	value map[string]any
	dirty bool
}

type nativeSSETextRef struct {
	recordIndex int
	path        nativeJSONPath
}

type nativeSSEBlock struct {
	index       int
	kind        string
	text        string
	refs        []nativeSSETextRef
	id          string
	name        string
	input       any
	partialJSON strings.Builder
}

func inspectNativeMessagesOutput(
	ctx context.Context,
	chatHandler *ChatCompletionsHandler,
	envelope *modelrouter.RequestEnvelope,
	requestMessages []Message,
	raw []byte,
	stream bool,
) ([]byte, []byte, []byte, *AuditResult, error) {
	projection, err := buildNativeMessagesOutputProjection(raw, stream)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid native Messages response: %w", err)
	}
	view, err := json.Marshal(projection.view)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	securedView, auditResult, err := chatHandler.applyOutputSecurity(
		withProviderExecutedToolCalls(ctx, providerExecutedToolCallsOf(projection.view)), envelope, requestMessages, view)
	if err != nil {
		// 扫描期间客户端断开：上游响应已完整拿到，调用方要用它的真实 usage 结算。
		// 只返回 usage 载体（{"usage":{...}}），不返回任何正文：这个载体只会交给 FinalizeRequestLog 解析 usage，
		// 不会写给客户端、不进内容日志、不落库。其余错误保持原样（不带载体）。
		if clientGoneDuring(ctx, err) {
			// 上游没报 usage 时返回 nil 载体：收尾回落到按预占估算，而不是被当成「上游报了 0 token」。
			var usageOnly []byte
			if projection.usageReported {
				if encoded, marshalErr := json.Marshal(map[string]any{"usage": projection.usage}); marshalErr == nil {
					usageOnly = encoded
				}
			}
			return nil, nil, usageOnly, auditResult, err
		}
		return nil, nil, nil, auditResult, err
	}
	if outputActionOf(auditResult) == "block" {
		return nil, nil, nil, auditResult, fmt.Errorf("native Messages tool output was blocked")
	}

	var secured ChatCompletionResponse
	if err := json.Unmarshal(securedView, &secured); err != nil {
		return nil, nil, nil, auditResult, err
	}
	output, changed, err := projection.applySecuredView(&secured)
	if err != nil {
		return nil, nil, nil, auditResult, err
	}
	if outputActionOf(auditResult) == "mask" && !changed {
		// The configured action is "mask", not "block": the native output is
		// forwarded unmasked and the gap is alerted.
		auditResult = markMaskUnavailable(auditResult)
		if chatHandler.auditWriter != nil {
			chatHandler.auditWriter.WriteSecurityEvent(withMaskUnavailable(withSecurityEventStage(ctx, "output")), envelope, nil,
				"security_audit", "native Messages output could not be safely redacted; forwarded unmasked")
		}
	}
	auditBody := output
	if stream {
		auditBody, err = json.Marshal(map[string]any{"usage": projection.usage})
		if err != nil {
			return nil, nil, nil, auditResult, err
		}
	}
	return output, securedView, auditBody, auditResult, nil
}

func buildNativeMessagesOutputProjection(raw []byte, stream bool) (*nativeOutputProjection, error) {
	if stream {
		return buildNativeMessagesSSEProjection(raw)
	}
	return buildNativeMessagesJSONProjection(raw)
}

func buildNativeMessagesJSONProjection(raw []byte) (*nativeOutputProjection, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil || root == nil {
		return nil, fmt.Errorf("response is not a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("response contains trailing JSON data")
	}
	if responseType, _ := root["type"].(string); responseType != "message" {
		return nil, fmt.Errorf("response type is %q", responseType)
	}
	content, ok := root["content"].([]any)
	if !ok {
		return nil, fmt.Errorf("response content is not an array")
	}
	projection := &nativeOutputProjection{
		raw: raw, root: root, toolRefs: make(map[int]int),
		view: ChatCompletionResponse{
			Object: "chat.completion",
			Model:  nativeString(root["model"]),
		},
	}
	projection.view.ID = nativeString(root["id"])
	projection.usage = nativeUsageFromValue(root["usage"])
	projection.usageReported = nativeUsageReported(root["usage"])
	projection.view.Usage = Usage{
		PromptTokens: projection.usage.InputTokens, CompletionTokens: projection.usage.OutputTokens,
		TotalTokens: projection.usage.InputTokens + projection.usage.OutputTokens,
	}

	toolUseIDs := make(map[string]struct{})
	for blockIndex, rawBlock := range content {
		block, ok := rawBlock.(map[string]any)
		if !ok {
			continue
		}
		choice := Choice{
			Index:        len(projection.view.Choices),
			Message:      ChoiceMessage{Role: "assistant"},
			FinishReason: "stop",
		}
		typeName, _ := block["type"].(string)
		var binding *nativeOutputBinding
		switch typeName {
		case "text":
			if text, ok := block["text"].(string); ok {
				choice.Message.Content = text
				binding = &nativeOutputBinding{
					choiceIndex: choice.Index,
					path:        nativeJSONPath{"content", blockIndex, "text"},
					original:    text,
					maskable:    true,
				}
			}
		case "thinking":
			if thinking, ok := block["thinking"].(string); ok {
				choice.Message.Content = thinking
				binding = &nativeOutputBinding{
					choiceIndex: choice.Index,
					path:        nativeJSONPath{"content", blockIndex, "thinking"},
					original:    thinking,
				}
			}
		case "tool_use", "server_tool_use":
			id := nativeString(block["id"])
			if id != "" {
				if _, exists := toolUseIDs[id]; exists {
					return nil, fmt.Errorf("duplicate native Messages tool_use id")
				}
				toolUseIDs[id] = struct{}{}
			}
			name := nativeString(block["name"])
			arguments, err := json.Marshal(block["input"])
			if err != nil {
				return nil, err
			}
			choice.Message.ToolCalls = []ToolCall{{
				ID: id, Type: "function", OutputItemID: fmt.Sprintf("content-%d", blockIndex),
				ProtocolIdentityRejected: id == "" || name == "",
				Function:                 ToolCallFunc{Name: name, Arguments: string(arguments)},
				ProviderExecuted:         typeName == "server_tool_use",
			}}
			projection.toolRefs[choice.Index] = 1
		default:
			continue
		}
		projection.view.Choices = append(projection.view.Choices, choice)
		if binding != nil {
			projection.bindings = append(projection.bindings, *binding)
		}
	}
	if len(projection.view.Choices) == 0 {
		projection.view.Choices = []Choice{{
			Index: 0, Message: ChoiceMessage{Role: "assistant"}, FinishReason: "stop",
		}}
	}
	return projection, nil
}

func (p *nativeOutputProjection) applySecuredView(secured *ChatCompletionResponse) ([]byte, bool, error) {
	for choiceIndex, expectedTools := range p.toolRefs {
		if choiceIndex >= len(secured.Choices) || len(secured.Choices[choiceIndex].Message.ToolCalls) != expectedTools {
			return nil, false, fmt.Errorf("native Messages tool output was withheld")
		}
	}
	changed := false
	for _, binding := range p.bindings {
		if binding.choiceIndex < 0 || binding.choiceIndex >= len(secured.Choices) {
			return nil, false, fmt.Errorf("native output security binding is out of range")
		}
		masked := secured.Choices[binding.choiceIndex].Message.Content
		if masked == binding.original {
			continue
		}
		if !binding.maskable || masked == "" {
			return nil, false, fmt.Errorf("native Messages output was removed by security policy")
		}
		if len(binding.sseRefs) == 0 {
			if err := setNativeJSONString(p.root, binding.path, masked); err != nil {
				return nil, false, err
			}
		} else {
			for index, ref := range binding.sseRefs {
				value := ""
				if index == 0 {
					value = masked
				}
				if ref.recordIndex < 0 || ref.recordIndex >= len(p.records) {
					return nil, false, fmt.Errorf("native SSE security binding is out of range")
				}
				if err := setNativeJSONString(p.records[ref.recordIndex].value, ref.path, value); err != nil {
					return nil, false, err
				}
				p.records[ref.recordIndex].dirty = true
			}
		}
		changed = true
	}
	if !changed {
		return p.raw, false, nil
	}
	if len(p.records) == 0 {
		encoded, err := json.Marshal(p.root)
		return encoded, true, err
	}
	patched := append([]byte(nil), p.raw...)
	for index := len(p.records) - 1; index >= 0; index-- {
		record := p.records[index]
		if !record.dirty {
			continue
		}
		encoded, err := json.Marshal(record.value)
		if err != nil {
			return nil, false, err
		}
		patched = append(patched[:record.start], append(encoded, patched[record.end:]...)...)
	}
	return patched, true, nil
}

func nativeString(value any) string {
	text, _ := value.(string)
	return text
}

func nativeUsageFromValue(value any) nativeMessagesUsage {
	usage, _ := value.(map[string]any)
	return nativeMessagesUsage{
		InputTokens:              nativeNonNegativeInt(usage["input_tokens"]),
		OutputTokens:             nativeNonNegativeInt(usage["output_tokens"]),
		CacheCreationInputTokens: nativeNonNegativeInt(usage["cache_creation_input_tokens"]),
		CacheReadInputTokens:     nativeNonNegativeInt(usage["cache_read_input_tokens"]),
	}
}

func nativeNonNegativeInt(value any) int {
	parsed, ok := nativeJSONInt(value)
	if !ok || parsed < 0 {
		return 0
	}
	return parsed
}

func buildNativeMessagesSSEProjection(raw []byte) (*nativeOutputProjection, error) {
	records, err := parseNativeMessagesSSERecords(raw)
	if err != nil {
		return nil, err
	}
	projection := &nativeOutputProjection{
		raw: raw, records: records, toolRefs: make(map[int]int),
		view: ChatCompletionResponse{Object: "chat.completion"},
	}
	blocksByIndex := make(map[int]*nativeSSEBlock)
	var blocks []*nativeSSEBlock
	blockStopped := make(map[int]bool)
	toolUseIDs := make(map[string]struct{})
	messageStarted := false
	messageDeltaSeen := false
	messageStopped := false
	getBlock := func(index int) *nativeSSEBlock {
		if block := blocksByIndex[index]; block != nil {
			return block
		}
		block := &nativeSSEBlock{index: index}
		blocksByIndex[index] = block
		blocks = append(blocks, block)
		return block
	}

	for recordIndex := range projection.records {
		record := projection.records[recordIndex].value
		eventType := nativeString(record["type"])
		if messageStopped {
			return nil, fmt.Errorf("native Messages SSE contains an event after message_stop")
		}
		switch eventType {
		case "message_start":
			if messageStarted {
				return nil, fmt.Errorf("native Messages SSE contains duplicate message_start")
			}
			messageStarted = true
			message, _ := record["message"].(map[string]any)
			projection.view.ID = nativeString(message["id"])
			projection.view.Model = nativeString(message["model"])
			projection.usage = mergeNativeUsage(projection.usage, nativeUsageFromValue(message["usage"]))
			projection.usageReported = projection.usageReported || nativeUsageReported(message["usage"])
		case "content_block_start":
			if !messageStarted {
				return nil, fmt.Errorf("content_block_start occurred before message_start")
			}
			if messageDeltaSeen {
				return nil, fmt.Errorf("content_block_start occurred after message_delta")
			}
			index, ok := nativeJSONInt(record["index"])
			if !ok || index < 0 {
				return nil, fmt.Errorf("content_block_start has an invalid index")
			}
			if _, exists := blocksByIndex[index]; exists {
				return nil, fmt.Errorf("duplicate content_block_start index")
			}
			contentBlock, _ := record["content_block"].(map[string]any)
			block := getBlock(index)
			block.kind = nativeString(contentBlock["type"])
			block.id = nativeString(contentBlock["id"])
			if (block.kind == "tool_use" || block.kind == "server_tool_use") && block.id != "" {
				if _, exists := toolUseIDs[block.id]; exists {
					return nil, fmt.Errorf("duplicate native Messages tool_use id")
				}
				toolUseIDs[block.id] = struct{}{}
			}
			block.name = nativeString(contentBlock["name"])
			block.input = contentBlock["input"]
			switch block.kind {
			case "text":
				if text, ok := contentBlock["text"].(string); ok && text != "" {
					block.text += text
					block.refs = append(block.refs, nativeSSETextRef{recordIndex: recordIndex, path: nativeJSONPath{"content_block", "text"}})
				}
			case "thinking":
				if thinking, ok := contentBlock["thinking"].(string); ok && thinking != "" {
					block.text += thinking
					block.refs = append(block.refs, nativeSSETextRef{recordIndex: recordIndex, path: nativeJSONPath{"content_block", "thinking"}})
				}
			}
		case "content_block_delta":
			if !messageStarted {
				return nil, fmt.Errorf("content_block_delta occurred before message_start")
			}
			if messageDeltaSeen {
				return nil, fmt.Errorf("content_block_delta occurred after message_delta")
			}
			index, ok := nativeJSONInt(record["index"])
			if !ok || index < 0 {
				return nil, fmt.Errorf("content_block_delta has an invalid index")
			}
			block := blocksByIndex[index]
			if block == nil || blockStopped[index] {
				return nil, fmt.Errorf("content_block_delta occurred outside an active content block")
			}
			delta, _ := record["delta"].(map[string]any)
			deltaType := nativeString(delta["type"])
			switch deltaType {
			case "text_delta":
				if block.kind != "text" {
					return nil, fmt.Errorf("text_delta does not match content block type")
				}
				if text, ok := delta["text"].(string); ok {
					block.text += text
					block.refs = append(block.refs, nativeSSETextRef{recordIndex: recordIndex, path: nativeJSONPath{"delta", "text"}})
				}
			case "thinking_delta":
				if block.kind != "thinking" {
					return nil, fmt.Errorf("thinking_delta does not match content block type")
				}
				if thinking, ok := delta["thinking"].(string); ok {
					block.text += thinking
					block.refs = append(block.refs, nativeSSETextRef{recordIndex: recordIndex, path: nativeJSONPath{"delta", "thinking"}})
				}
			case "input_json_delta":
				if block.kind != "tool_use" && block.kind != "server_tool_use" {
					return nil, fmt.Errorf("input_json_delta does not match content block type")
				}
				if partial, ok := delta["partial_json"].(string); ok {
					block.partialJSON.WriteString(partial)
				}
			}
		case "content_block_stop":
			if !messageStarted {
				return nil, fmt.Errorf("content_block_stop occurred before message_start")
			}
			if messageDeltaSeen {
				return nil, fmt.Errorf("content_block_stop occurred after message_delta")
			}
			index, ok := nativeJSONInt(record["index"])
			if !ok || index < 0 {
				return nil, fmt.Errorf("content_block_stop has an invalid index")
			}
			if blocksByIndex[index] == nil || blockStopped[index] {
				return nil, fmt.Errorf("content_block_stop occurred outside an active content block")
			}
			blockStopped[index] = true
		case "message_delta":
			if !messageStarted {
				return nil, fmt.Errorf("message_delta occurred before message_start")
			}
			if messageDeltaSeen {
				return nil, fmt.Errorf("native Messages SSE contains duplicate message_delta")
			}
			for index := range blocksByIndex {
				if !blockStopped[index] {
					return nil, fmt.Errorf("message_delta occurred before content_block_stop")
				}
			}
			messageDeltaSeen = true
			projection.usage = mergeNativeUsage(projection.usage, nativeUsageFromValue(record["usage"]))
			projection.usageReported = projection.usageReported || nativeUsageReported(record["usage"])
		case "message_stop":
			if !messageStarted {
				return nil, fmt.Errorf("message_stop occurred before message_start")
			}
			if !messageDeltaSeen {
				return nil, fmt.Errorf("message_stop occurred before message_delta")
			}
			for index := range blocksByIndex {
				if !blockStopped[index] {
					return nil, fmt.Errorf("message_stop occurred before content_block_stop")
				}
			}
			messageStopped = true
		case "error":
			return nil, fmt.Errorf("upstream returned a Messages error event")
		}
	}
	if !messageStarted {
		return nil, fmt.Errorf("native Messages SSE has no message_start event")
	}
	if !messageStopped {
		return nil, fmt.Errorf("native Messages SSE has no message_stop event")
	}

	projection.view.Usage = Usage{
		PromptTokens: projection.usage.InputTokens, CompletionTokens: projection.usage.OutputTokens,
		TotalTokens: projection.usage.InputTokens + projection.usage.OutputTokens,
	}
	for _, block := range blocks {
		choice := Choice{
			Index:        len(projection.view.Choices),
			Message:      ChoiceMessage{Role: "assistant"},
			FinishReason: "stop",
		}
		switch block.kind {
		case "text", "thinking":
			choice.Message.Content = block.text
			projection.bindings = append(projection.bindings, nativeOutputBinding{
				choiceIndex: choice.Index, original: block.text,
				maskable: block.kind == "text",
				sseRefs:  append([]nativeSSETextRef(nil), block.refs...),
			})
		case "tool_use", "server_tool_use":
			arguments := block.partialJSON.String()
			if arguments == "" {
				encoded, marshalErr := json.Marshal(block.input)
				if marshalErr != nil {
					return nil, marshalErr
				}
				arguments = string(encoded)
			}
			choice.Message.ToolCalls = []ToolCall{{
				ID: block.id, Type: "function", OutputItemID: fmt.Sprintf("content-%d", block.index),
				ProtocolIdentityRejected: block.id == "" || block.name == "",
				Function:                 ToolCallFunc{Name: block.name, Arguments: arguments},
				ProviderExecuted:         block.kind == "server_tool_use",
			}}
			projection.toolRefs[choice.Index] = 1
		default:
			continue
		}
		projection.view.Choices = append(projection.view.Choices, choice)
	}
	if len(projection.view.Choices) == 0 {
		projection.view.Choices = []Choice{{
			Index: 0, Message: ChoiceMessage{Role: "assistant"}, FinishReason: "stop",
		}}
	}
	return projection, nil
}

func parseNativeMessagesSSERecords(raw []byte) ([]nativeSSERecord, error) {
	var records []nativeSSERecord
	for offset := 0; offset < len(raw); {
		lineStart := offset
		relativeEnd := bytes.IndexByte(raw[offset:], '\n')
		lineEnd := len(raw)
		if relativeEnd >= 0 {
			lineEnd = offset + relativeEnd
			offset = lineEnd + 1
		} else {
			offset = len(raw)
		}
		contentEnd := lineEnd
		if contentEnd > lineStart && raw[contentEnd-1] == '\r' {
			contentEnd--
		}
		line := raw[lineStart:contentEnd]
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payloadStart := lineStart + len("data:")
		for payloadStart < contentEnd && (raw[payloadStart] == ' ' || raw[payloadStart] == '\t') {
			payloadStart++
		}
		payload := raw[payloadStart:contentEnd]
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || value == nil {
			return nil, fmt.Errorf("invalid Messages SSE data event")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("invalid trailing Messages SSE data")
		}
		records = append(records, nativeSSERecord{
			start: payloadStart, end: contentEnd, value: value,
		})
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("native Messages SSE has no data events")
	}
	return records, nil
}

func mergeNativeUsage(current, next nativeMessagesUsage) nativeMessagesUsage {
	if next.InputTokens != 0 {
		current.InputTokens = next.InputTokens
	}
	if next.OutputTokens != 0 {
		current.OutputTokens = next.OutputTokens
	}
	if next.CacheCreationInputTokens != 0 {
		current.CacheCreationInputTokens = next.CacheCreationInputTokens
	}
	if next.CacheReadInputTokens != 0 {
		current.CacheReadInputTokens = next.CacheReadInputTokens
	}
	return current
}
