package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

type FallbackProviderPlan struct {
	ProviderID      string
	ProviderType    string
	ModelID         string
	UpstreamModelID string
	Caller          ProviderCaller
	ResponsesNative bool
	Route           modelrouter.ModelRecord
	Next            *FallbackProviderPlan
}

type FallbackAttemptResult struct {
	Caller               ProviderCaller
	RespBody             []byte
	Err                  error
	Attempted            bool
	TriggerKind          string
	PrimaryProviderID    string
	PrimaryProviderType  string
	FallbackProviderID   string
	FallbackProviderType string
}

func buildFallbackProviderPlan(ctx context.Context, resolver ModelResolver, factory ProviderAdapterFactory, modelRecord *modelrouter.ModelRecord) *FallbackProviderPlan {
	if modelRecord == nil || modelRecord.FallbackProviderID == "" || modelRecord.FallbackProviderID == modelRecord.ProviderID {
		return nil
	}

	apiKey, err := resolver.GetProviderCredential(ctx, modelRecord.FallbackProviderID)
	if err != nil || apiKey == "" {
		return nil
	}

	fallbackRecord := &modelrouter.ModelRecord{
		ID:               modelRecord.FallbackModelID,
		ModelName:        modelRecord.ModelName,
		UpstreamModelID:  modelRecord.FallbackUpstreamModelID,
		ProviderID:       modelRecord.FallbackProviderID,
		ProviderType:     modelRecord.FallbackProviderType,
		ProviderBaseURL:  modelRecord.FallbackProviderBaseURL,
		ProviderAuthMode: modelRecord.FallbackProviderAuthMode,
		UpstreamProxyURL: modelRecord.UpstreamProxyURL,
	}

	return &FallbackProviderPlan{
		ProviderID:      modelRecord.FallbackProviderID,
		ProviderType:    modelRecord.FallbackProviderType,
		ModelID:         modelRecord.FallbackModelID,
		UpstreamModelID: modelRecord.FallbackUpstreamModelID,
		Caller:          factory.CreateAdapter(fallbackRecord, apiKey),
		ResponsesNative: modelRecord.FallbackResponsesNative,
		Route: modelrouter.ModelRecord{
			ID:                   modelRecord.FallbackModelID,
			ModelName:            modelRecord.ModelName,
			UpstreamModelID:      modelRecord.FallbackUpstreamModelID,
			ProviderID:           modelRecord.FallbackProviderID,
			ProviderType:         modelRecord.FallbackProviderType,
			ProviderBaseURL:      modelRecord.FallbackProviderBaseURL,
			ProviderAuthMode:     modelRecord.FallbackProviderAuthMode,
			UpstreamProxyURL:     modelRecord.UpstreamProxyURL,
			ProtocolCapabilities: modelRecord.FallbackProtocolCapabilities,
			ResponsesNative:      modelRecord.FallbackResponsesNative,
		},
	}
}

func shouldRetryWithFallback(ctx context.Context, err error) bool {
	return shouldRetryModelRoute(ctx, err)
}

// callUpstream 按 streaming 开关在 Call / CallStreaming 之间分流。streaming=true 时走流式累积,
// 网关内部边收 SSE 边累积成与 Call 等价的完整 JSON, 治长生成撞上游非流式 ~300s 上限(Stage 2)。
// streaming=false 时行为与改造前完全一致(调 Call)。
func callUpstream(ctx context.Context, caller ProviderCaller, envelope *modelrouter.RequestEnvelope, providerReq []byte, streaming bool) ([]byte, error) {
	started := time.Now()
	recordPreUpstreamTiming(envelope, started)
	defer func() { recordGenerationTiming(envelope, started, time.Now()) }()
	if streaming {
		return caller.CallStreaming(ctx, envelope, providerReq)
	}
	return caller.Call(ctx, envelope, providerReq)
}

func attemptFallbackCall(ctx context.Context, envelope *modelrouter.RequestEnvelope, securedBody []byte, primaryErr error, fallback *FallbackProviderPlan, streaming bool) FallbackAttemptResult {
	if fallback == nil || !shouldRetryWithFallback(ctx, primaryErr) {
		return FallbackAttemptResult{Err: primaryErr}
	}
	upstreamProtocol := envelope.EndpointType
	if fallback.Route.ProviderID != "" {
		var decision relay.CapabilityDecision
		upstreamProtocol, decision = selectModelRouteProtocol(
			fallback.Route,
			modelRouteRequestFeatures(envelope, securedBody, streaming),
		)
		if !decision.Eligible {
			if fallback.Next != nil {
				return attemptFallbackCall(ctx, envelope, securedBody, primaryErr, fallback.Next, streaming)
			}
			return FallbackAttemptResult{Err: primaryErr}
		}
	}
	if fallback.Caller == nil {
		if fallback.Next != nil {
			return attemptFallbackCall(ctx, envelope, securedBody, primaryErr, fallback.Next, streaming)
		}
		return FallbackAttemptResult{Err: primaryErr}
	}

	triggerKind := "network"
	if upstreamErr := provider.GetUpstreamHTTPError(primaryErr); upstreamErr != nil && upstreamErr.StatusCode >= http.StatusInternalServerError {
		triggerKind = "upstream_5xx"
	}

	result := FallbackAttemptResult{
		Attempted:            true,
		TriggerKind:          triggerKind,
		PrimaryProviderID:    envelope.ProviderID,
		PrimaryProviderType:  envelope.Provider,
		FallbackProviderID:   fallback.ProviderID,
		FallbackProviderType: fallback.ProviderType,
	}

	envelope.ProviderID = fallback.ProviderID
	envelope.Provider = fallback.ProviderType
	envelope.ProtocolCapabilities = fallback.Route.ProtocolCapabilities
	envelope.UpstreamProtocol = upstreamProtocol
	if fallback.ModelID != "" {
		envelope.ModelID = fallback.ModelID
	}
	envelope.UpstreamModelID = fallback.UpstreamModelID

	fallbackCaller := adaptProviderIngress(fallback.Caller, envelope)
	fallbackReq, err := fallbackCaller.TransformRequest(envelope, securedBody)
	if err != nil {
		result.Err = primaryErr
		return result
	}

	respBody, err := callUpstream(ctx, fallbackCaller, envelope, fallbackReq, streaming)
	result.Caller = fallbackCaller
	result.RespBody = respBody
	result.Err = err

	// 多跳兜底：当前跳仍失败且链表还有下一跳时，沿 FallbackChain 顺序继续切换。
	if err != nil && fallback.Next != nil && shouldRetryWithFallback(ctx, err) {
		return attemptFallbackCall(ctx, envelope, securedBody, err, fallback.Next, streaming)
	}

	return result
}

func recordFallbackEvent(ctx context.Context, auditWriter AuditWriter, envelope *modelrouter.RequestEnvelope, result FallbackAttemptResult) {
	if auditWriter == nil || envelope == nil || !result.Attempted {
		return
	}

	summary := fmt.Sprintf(
		"fallback triggered: primary=%s(%s) fallback=%s(%s) endpoint=%s trigger=%s",
		result.PrimaryProviderID,
		result.PrimaryProviderType,
		result.FallbackProviderID,
		result.FallbackProviderType,
		envelope.EndpointType,
		result.TriggerKind,
	)
	auditWriter.WriteSecurityEvent(ctx, envelope, nil, "provider_fallback", summary)
}

func setRoutingHeaders(w http.ResponseWriter, envelope *modelrouter.RequestEnvelope, fallbackUsed bool) {
	if envelope == nil {
		return
	}
	if envelope.ProviderID != "" {
		w.Header().Set("X-JJDGuard-Provider-ID", envelope.ProviderID)
	}
	if envelope.RequestID != "" {
		w.Header().Set("X-Request-ID", envelope.RequestID)
	}
	if envelope.UpstreamProtocol != "" {
		w.Header().Set("X-JJDGuard-Upstream-Protocol", envelope.UpstreamProtocol)
	}
	if fallbackUsed {
		w.Header().Set("X-JJDGuard-Fallback-Used", "true")
	}
}

// buildFallbackChainPlan 从 ProviderDecision.FallbackChain 构造多跳兜底链表。
// 链首（chain[0]）为主 provider 自身，按顺序串接 [1:] 各跳；少于 2 个元素返回 nil。
func buildFallbackChainPlan(ctx context.Context, resolver ModelResolver, factory ProviderAdapterFactory, tenantID string, modelRecord *modelrouter.ModelRecord, provDec *modelrouter.ProviderDecision) *FallbackProviderPlan {
	if modelRecord == nil || provDec == nil || len(provDec.FallbackChain) < 2 {
		return nil
	}

	var head, tail *FallbackProviderPlan
	for _, providerID := range provDec.FallbackChain[1:] {
		if providerID == "" || providerID == provDec.ProviderID {
			continue
		}
		apiKey, err := resolver.GetProviderCredential(ctx, providerID)
		if err != nil || apiKey == "" {
			continue
		}
		providerRecord, err := resolver.GetProvider(ctx, tenantID, providerID)
		if err != nil || providerRecord == nil {
			continue
		}
		hopRecord := *modelRecord
		hopRecord.ProviderID = providerRecord.ID
		hopRecord.ProviderType = providerRecord.ProviderType
		hopRecord.ProviderBaseURL = providerRecord.BaseURL
		hopRecord.ProviderAuthMode = providerRecord.AuthMode
		hopRecord.UpstreamProxyURL = providerRecord.UpstreamProxyURL
		hopModelID := ""
		hopUpstreamModelID := modelRecord.UpstreamModelID
		hopResponsesNative := false
		if providerID == modelRecord.FallbackProviderID {
			hopModelID = modelRecord.FallbackModelID
			hopUpstreamModelID = modelRecord.FallbackUpstreamModelID
			hopResponsesNative = modelRecord.FallbackResponsesNative
			hopRecord.ID = hopModelID
			hopRecord.UpstreamModelID = hopUpstreamModelID
		}
		hop := &FallbackProviderPlan{
			ProviderID:      providerID,
			ProviderType:    providerRecord.ProviderType,
			ModelID:         hopModelID,
			UpstreamModelID: hopUpstreamModelID,
			Caller:          factory.CreateAdapter(&hopRecord, apiKey),
			ResponsesNative: hopResponsesNative,
			Route:           hopRecord,
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

// fallbackChainLength 返回兜底链表的跳数（沿 Next 计数）。
func fallbackChainLength(plan *FallbackProviderPlan) int {
	n := 0
	for p := plan; p != nil; p = p.Next {
		n++
	}
	return n
}
