package handler

import (
	"context"
	"encoding/json"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// SetProxyAuth injects the proxy key verifier and usage recorder (阶段二 2.5).
// Both are nil-safe: leaving them nil disables proxy key auth / usage metering,
// so existing tests that never call SetProxyAuth are unaffected.
func (h *ChatCompletionsHandler) SetProxyAuth(verifier ProxyKeyVerifier, recorder ProxyUsageRecorder) {
	h.proxyKeyVerifier = verifier
	h.proxyUsageRecorder = recorder
}

// recordProxyUsageIfNeeded records proxy usage for no-token proxy requests when a recorder is configured.
func (h *ChatCompletionsHandler) recordProxyUsageIfNeeded(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte) {
	if h == nil || h.proxyUsageRecorder == nil || envelope == nil {
		return
	}
	if !isProxyRequest(ctx) {
		return
	}
	var parsed struct {
		Usage Usage `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	_ = h.proxyUsageRecorder.RecordProxyUsage(ctx, envelope.ModelID, parsed.Usage.PromptTokens, parsed.Usage.CompletionTokens)
}
