package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

type chatProviderErrorFinalizerInput struct {
	envelope  *modelrouter.RequestEnvelope
	requestID string
	startedAt time.Time
	err       error
}

type chatJSONSuccessFinalizerInput struct {
	envelope     *modelrouter.RequestEnvelope
	respBody     []byte
	startedAt    time.Time
	auditResult  *AuditResult
	fallbackUsed bool
	cacheLookup  *responseCacheLookup
}

func (h *ChatCompletionsHandler) finalizeChatProviderError(ctx context.Context, w http.ResponseWriter, input chatProviderErrorFinalizerInput) bool {
	if input.err == nil {
		return false
	}
	if errors.Is(input.err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		h.auditWriter.FinalizeRequestLog(ctx, input.envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(input.startedAt)/time.Millisecond), nil)
		writeErrorResponseWithStatus(w, "request_canceled", "request was canceled", input.requestID, http.StatusRequestTimeout)
		return true
	}
	if errors.Is(input.err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		h.auditWriter.FinalizeRequestLog(ctx, input.envelope, nil, "provider_timeout", http.StatusGatewayTimeout, int(time.Since(input.startedAt)/time.Millisecond), nil)
		writeErrorResponseWithStatus(w, "provider_timeout", "upstream provider timed out", input.requestID, http.StatusGatewayTimeout)
		return true
	}

	if upstreamErr := provider.GetUpstreamHTTPError(input.err); upstreamErr != nil {
		// 上游错误正文由 writeUpstreamErrorResponse 统一落日志，这里只负责审计留存。
		h.auditWriter.FinalizeRequestLog(ctx, input.envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(input.startedAt)/time.Millisecond), &AuditResult{ResponseMetadata: map[string]interface{}{"error_message": retainedProviderErrorMessage(upstreamErr.Message)}})
		if input.envelope != nil && input.envelope.UpstreamProtocol != "" {
			w.Header().Set("X-JJDGuard-Upstream-Protocol", input.envelope.UpstreamProtocol)
		}
		writeUpstreamErrorResponse(w, upstreamErr, input.requestID, "upstream_response")
		return true
	}
	if errors.Is(input.err, errUserModelForbidden) {
		if input.envelope != nil {
			input.envelope.RejectReason = modelDenialRejectReason(ctx, input.envelope.Model)
		}
		h.auditWriter.FinalizeRequestLog(ctx, input.envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(input.startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "forbidden_model", modelDeniedMessage(ctx, envelopeModelName(input.envelope)), input.requestID)
		return true
	}
	if errors.Is(input.err, errModelRouteUnavailable) {
		h.auditWriter.FinalizeRequestLog(ctx, input.envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(input.startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(input.envelope), input.requestID)
		return true
	}

	h.auditWriter.FinalizeRequestLog(ctx, input.envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(input.startedAt)/time.Millisecond), nil)
	writeErrorResponse(w, "provider_unavailable", "upstream provider is unavailable", input.requestID)
	return true
}

func boundedUpstreamErrorMessage(message string) string {
	message = strings.TrimSpace(message)
	message = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(message)
	const maxRunes = 512
	runes := []rune(message)
	if len(runes) <= maxRunes {
		return message
	}
	return string(runes[:maxRunes]) + "..."
}

func (h *ChatCompletionsHandler) finalizeChatJSONSuccess(ctx context.Context, w http.ResponseWriter, input chatJSONSuccessFinalizerInput) {
	h.writeResponseContentLogs(ctx, input.envelope, input.respBody)
	h.auditWriter.FinalizeRequestLog(ctx, input.envelope, input.respBody, "success", http.StatusOK, int(time.Since(input.startedAt)/time.Millisecond), input.auditResult)
	h.recordPromptCacheMetrics(input.respBody)
	h.recordProxyUsageIfNeeded(ctx, input.envelope, input.respBody)
	h.storeResponseCache(input.cacheLookup, input.envelope, input.respBody, input.auditResult)

	setRoutingHeaders(w, input.envelope, input.fallbackUsed)
	w.Header().Set("Content-Type", "application/json")
	writeGatewayJSONBody(w, deliverResponseBody(ctx, h.toolRiskClient, input.envelope, input.respBody))
}

// Keep the provider's diagnostic text, never its raw body or credentials.
func retainedProviderErrorMessage(message string) string {
	return boundedUpstreamErrorMessage(redactMCPResultString(message))
}
