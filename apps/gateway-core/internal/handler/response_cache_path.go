package handler

// 响应缓存接入 chat 请求路径：查找、命中回复、写入。

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// inputDetectionVersions 记录本请求输入检测实际用到的版本；拿不到版本时不缓存。
type inputDetectionVersionsKey struct{}

type inputDetectionVersions struct {
	rulePack, engineBuild, semantic string
}

func withInputDetectionVersionSlot(ctx context.Context) context.Context {
	if _, ok := ctx.Value(inputDetectionVersionsKey{}).(*inputDetectionVersions); ok {
		return ctx
	}
	return context.WithValue(ctx, inputDetectionVersionsKey{}, &inputDetectionVersions{})
}

func recordInputDetectionVersions(ctx context.Context, rulePack, engineBuild, semantic string) {
	if rulePack == "" || engineBuild == "" {
		return
	}
	if slot, ok := ctx.Value(inputDetectionVersionsKey{}).(*inputDetectionVersions); ok && slot.rulePack == "" {
		slot.rulePack, slot.engineBuild, slot.semantic = rulePack, engineBuild, semantic
	}
}

func inputDetectionVersionsFrom(ctx context.Context) inputDetectionVersions {
	if slot, ok := ctx.Value(inputDetectionVersionsKey{}).(*inputDetectionVersions); ok {
		return *slot
	}
	return inputDetectionVersions{}
}

// responseCacheVersionsFor 汇总缓存键里的检测版本：本请求真实引擎响应优先，全部命中检测指纹缓存时
// 用指纹缓存记录的最近版本；网关语义配置修订号一并纳入。
func (h *ChatCompletionsHandler) responseCacheVersionsFor(ctx context.Context) responseCacheVersions {
	v := inputDetectionVersionsFrom(ctx)
	out := responseCacheVersions{rulePack: v.rulePack, engineBuild: v.engineBuild, semantic: v.semantic}
	if out.rulePack == "" && h.fingerprints != nil {
		out.rulePack, out.engineBuild, out.semantic = h.fingerprints.CurrentVersions()
	}
	if config, err := h.toolRiskClient.semanticRuntimeConfig(ctx); err == nil {
		out.gatewayRevision = config.Revision
	}
	return out
}

// lookupResponseCache 在输入检测之后、计费预占之前调用。返回 nil 表示未命中或不参与缓存；
// 返回的 lookup 未命中时仍带 key，供成功收尾时写入。
func (h *ChatCompletionsHandler) lookupResponseCache(ctx context.Context, r *http.Request, envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest, body, securedBody []byte) *responseCacheLookup {
	if h == nil || h.responseCache == nil || h.toolRiskClient == nil {
		return nil
	}
	settings := h.toolRiskClient.ResponseCacheSettings()
	cacheControl := ""
	if r != nil {
		cacheControl = r.Header.Get("Cache-Control")
	}
	if !responseCacheRequestEligible(ctx, envelope, req, cacheControl, settings) || rawBodyRequestsMultipleOrLogprobs(body) {
		return nil
	}
	key, shared, err := responseCacheKey(settings, envelope, h.responseCacheVersionsFor(ctx), securedBody)
	if err != nil {
		return nil
	}
	lookup := &responseCacheLookup{key: key, shared: shared, settings: settings}
	raw, hit := h.responseCache.Get(ctx, key)
	if !hit {
		return lookup
	}
	var entry responseCacheEntry
	if json.Unmarshal(raw, &entry) != nil || len(entry.Choices) == 0 {
		return lookup
	}
	if shared && !h.cachedAnswerPassesOutputCheck(ctx, envelope, req, &entry) {
		return lookup
	}
	lookup.entry = &entry
	return lookup
}

// cachedAnswerPassesOutputCheck 共享缓存命中时按本次请求身份重跑输出检测；不是放行就按未命中处理。
func (h *ChatCompletionsHandler) cachedAnswerPassesOutputCheck(ctx context.Context, envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest, entry *responseCacheEntry) bool {
	body := buildCacheHitResponse(envelope, entry)
	_, audit, err := h.secureChatOutput(ctx, envelope, req.Messages, body)
	if err != nil {
		return false
	}
	action := outputActionOf(audit)
	return action == "" || action == "allow"
}

// storeResponseCache 在成功收尾（FinalizeRequestLog 之后、交付之前）调用，后台写入，不占用户时间。
func (h *ChatCompletionsHandler) storeResponseCache(lookup *responseCacheLookup, envelope *modelrouter.RequestEnvelope, respBody []byte, audit *AuditResult) {
	if h == nil || h.responseCache == nil || lookup == nil || lookup.entry != nil || lookup.key == "" {
		return
	}
	entry, ok := responseCacheStorable(lookup.settings, envelope, respBody, audit)
	if !ok {
		return
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	cache, key, ttl := h.responseCache, lookup.key, lookup.settings.TTL
	go cache.Set(context.Background(), key, raw, ttl)
}

// writeCacheHitChat 用缓存回答回复本次请求：不调上游、不计费，审计照常记录。
func (h *ChatCompletionsHandler) writeCacheHitChat(ctx context.Context, w http.ResponseWriter, result *ProcessedRequestResult, stream bool) {
	envelope := result.Envelope
	entry := result.CacheHit.entry
	body := buildCacheHitResponse(envelope, entry)

	envelope.CacheHit = true
	envelope.BillingUsageSource = "synthetic_no_upstream"
	auditResult := &AuditResult{
		OutputFindings:   []map[string]interface{}{},
		OutputAction:     "allow",
		ResponseMetadata: map[string]interface{}{"cache": cacheHitMetadata(entry, result.CacheHit.shared)},
	}
	h.writeResponseContentLogs(ctx, envelope, body)
	// 用量写 0：命中没有调用上游，不能计入预算计数、启动回填和用量报表；省下的量记在 metadata。
	h.auditWriter.FinalizeRequestLog(ctx, envelope, zeroUsageResponse(body), "success", http.StatusOK, int(time.Since(result.StartedAt)/time.Millisecond), auditResult)

	setRoutingHeaders(w, envelope, false)
	w.Header().Set("X-JJDGuard-Cache", "hit")
	delivered := deliverResponseBody(ctx, h.toolRiskClient, envelope, body)
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		writeGatewayJSONBody(w, delivered)
		return
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(delivered, &resp); err != nil {
		writeSSEError(w, envelope.RequestID, "internal_error", "failed to build cached response")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	writeBufferedChatSSE(w, &resp, nil)
}

// zeroUsageResponse 把回复体里的 usage 换成 0，供审计收尾使用（客户端看到的仍是原始用量）。
func zeroUsageResponse(body []byte) []byte {
	var resp map[string]any
	if json.Unmarshal(body, &resp) != nil {
		return body
	}
	resp["usage"] = map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
	out, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return out
}

// writeBufferedChatSSE 把一个完整的 chat completion 按 OpenAI 流式格式发出：每个 choice 一帧，
// 随后 usage 帧与 [DONE]。extra 会并入 usage 帧（先攒后发路径用它带最终安全动作）。
func writeBufferedChatSSE(w http.ResponseWriter, resp *ChatCompletionResponse, extra map[string]any) {
	for _, choice := range resp.Choices {
		finishReason := choice.FinishReason
		if finishReason == "" {
			finishReason = "stop"
		}
		deltaChunk := SSEChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []SSEChoice{{Index: choice.Index, Delta: buildSSEDelta(choice.Message), FinishReason: finishReason}},
		}
		deltaData, _ := json.Marshal(deltaChunk)
		writeSSEData(w, string(deltaData))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	usageFrame := map[string]any{"id": resp.ID, "object": "chat.completion.chunk", "created": resp.Created, "model": resp.Model, "choices": []any{}, "usage": resp.Usage}
	for k, v := range extra {
		usageFrame[k] = v
	}
	usageChunk, _ := json.Marshal(usageFrame)
	writeSSEData(w, string(usageChunk))
	writeSSEData(w, "[DONE]")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
