package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/google/uuid"
)

const maximumModelRouteAttempts = 3
const maximumSameRouteRetries = 1

var (
	errUserModelForbidden         = errors.New("forbidden_model")
	errModelRouteUnavailable      = errors.New("model_route_unavailable")
	errModelRouteSecurityRejected = errors.New("model route security rejected")
	errResponsesNativeUnavailable = errors.New("responses_native_unavailable")
)

func modelRouteSupportsEndpoint(route modelrouter.ModelRecord, endpoint string) bool {
	_, decision := selectModelRouteProtocol(route, relay.RequestFeatures{IngressProtocol: endpoint, ResponsesCompatibility: endpoint == "responses"})
	return decision.Eligible
}

func modelRouteRequestFeatures(envelope *modelrouter.RequestEnvelope, body []byte, stream bool) relay.RequestFeatures {
	features := relay.DetectRequestFeatures(envelope.EndpointType, body, stream)
	features.ResponsesCompatibility = envelope.ResponsesCompatibility
	return features
}

func selectModelRouteProtocol(route modelrouter.ModelRecord, request relay.RequestFeatures) (string, relay.CapabilityDecision) {
	endpoint := strings.ToLower(strings.TrimSpace(request.IngressProtocol))
	capabilities := route.ProtocolCapabilities
	upstreamProtocol := endpoint
	conversion := false
	if !capabilities.Explicit {
		return upstreamProtocol, relay.CapabilityDecision{Eligible: endpoint != ""}
	}

	if endpoint == "chat" {
		providerType := strings.ToLower(strings.TrimSpace(route.ProviderType))
		messagesBridge := (providerType == "anthropic" &&
			(capabilities.AnthropicMessages || capabilities.ChatCompletions)) ||
			shouldBridgeClaudeChatToNativeMessages(&route)
		geminiBridge := providerType == "gemini" || providerType == "vertex"
		bedrockBridge := providerType == "bedrock"
		bridgeAvailable := capabilities.ResponsesNative &&
			provider.SupportsChatResponsesBridge(route.ProviderType)
		autoBridge := bridgeAvailable && capabilities.ChatCompletions &&
			(capabilities.Verified || capabilities.ChatResponsesBridge) && relay.PrefersResponsesBridge(request)
		explicitBridge := bridgeAvailable && capabilities.ChatResponsesBridge
		switch {
		case messagesBridge:
			upstreamProtocol = "messages"
			conversion = true
		case geminiBridge:
			upstreamProtocol = "gemini"
			conversion = true
		case bedrockBridge:
			upstreamProtocol = "bedrock_converse"
			conversion = true
		case autoBridge || (!capabilities.ChatCompletions && explicitBridge):
			upstreamProtocol = "responses"
			conversion = true
		case route.SupportsConfiguredEndpoint("chat"):
			upstreamProtocol = "chat"
		case explicitBridge:
			upstreamProtocol = "responses"
			conversion = true
		case capabilities.BlocksEndpoint("chat"):
			return "", relay.CapabilityDecision{Reasons: []string{"ingress_protocol"}}
		default:
			// 探测未验证不拦截：按入口协议原样转发，上游不支持时由上游返回真实错误。
			upstreamProtocol = "chat"
		}
	} else if endpoint == "responses" && !route.SupportsConfiguredEndpoint("responses") && request.ResponsesCompatibility {
		chatRequest := request
		chatRequest.IngressProtocol = "chat"
		upstreamProtocol, decision := selectModelRouteProtocol(route, chatRequest)
		if !decision.Eligible {
			return "", decision
		}
		// The Responses handler has explicitly normalized the stateless request
		// to Chat. Native state, hosted tools and unknown fields remain gated.
		return upstreamProtocol, decision
	} else if endpoint == "messages" {
		providerType := strings.ToLower(strings.TrimSpace(route.ProviderType))
		openAIBridge := (providerType == "openai" || providerType == "azure" ||
			capabilities.ChatResponsesBridge || capabilities.ResponsesNative) &&
			provider.SupportsChatResponsesBridge(providerType)
		switch {
		case route.SupportsConfiguredEndpoint("messages"):
			upstreamProtocol = "messages"
		case openAIBridge && capabilities.ResponsesNative:
			upstreamProtocol = "responses"
			conversion = true
		case (providerType == "gemini" || providerType == "vertex") && (capabilities.Gemini || capabilities.ChatCompletions):
			upstreamProtocol = "gemini"
			conversion = true
		case providerType == "bedrock" && capabilities.ChatCompletions:
			upstreamProtocol = "bedrock_converse"
			conversion = true
		case (openAIBridge || provider.SupportsChatResponsesBridge(providerType)) && capabilities.ChatCompletions:
			upstreamProtocol = "chat"
			conversion = true
		case capabilities.BlocksEndpoint("messages"):
			return "", relay.CapabilityDecision{Reasons: []string{"ingress_protocol"}}
		default:
			upstreamProtocol = "messages"
		}
	} else if !route.SupportsConfiguredEndpoint(endpoint) && capabilities.BlocksEndpoint(endpoint) {
		return "", relay.CapabilityDecision{Reasons: []string{"ingress_protocol"}}
	}

	routeCapabilities := relay.RouteCapabilities{
		ProviderID:        route.ProviderID,
		ModelID:           route.ID,
		Source:            capabilities.Source,
		Version:           capabilities.Version,
		Verified:          capabilities.Verified || capabilities.ChatResponsesBridge,
		UpstreamProtocols: []string{upstreamProtocol},
		Stream:            capabilities.SupportsFeatureOrUnknown("stream"),
		Tools:             capabilities.SupportsFeatureOrUnknown("tools"),
		ToolResults:       capabilities.SupportsFeatureOrUnknown("tool_results"),
		ParallelTools:     capabilities.SupportsFeatureOrUnknown("parallel_tools"),
		Vision:            capabilities.SupportsFeatureOrUnknown("vision"),
		Audio:             true,
		Video:             true,
		Files:             true,
		Reasoning:         capabilities.SupportsFeatureOrUnknown("reasoning"),
		ResponseFormat:    capabilities.SupportsFeatureOrUnknown("response_format"),
		JSONSchema:        capabilities.SupportsFeatureOrUnknown("json_schema"),
		CacheTokens:       capabilities.SupportsFeatureOrUnknown("cache_tokens"),
		Stateful:          true,
		LongContext:       true,
		Idempotent:        capabilities.Idempotent,
		Retryable:         capabilities.Retryable,
	}
	if upstreamProtocol == "gemini" || upstreamProtocol == "bedrock_converse" {
		routeCapabilities.Audio = false
		routeCapabilities.Video = false
		routeCapabilities.Files = false
		routeCapabilities.Reasoning = false
		routeCapabilities.CacheTokens = false
		routeCapabilities.Stateful = false
	}
	if upstreamProtocol == "bedrock_converse" {
		routeCapabilities.Vision = false
		routeCapabilities.ResponseFormat = false
		routeCapabilities.JSONSchema = false
	}
	if conversion && upstreamProtocol == "messages" {
		// The Chat -> Anthropic Messages adapter preserves text, images and the
		// complete tool loop, and translates OpenAI-compatible reasoning controls
		// to adaptive thinking plus output_config.effort. Features with no Messages
		// equivalent fail closed so a compatible fallback can be selected instead
		// of silently dropping.
		routeCapabilities.Audio = false
		routeCapabilities.Video = false
		routeCapabilities.Files = false
		routeCapabilities.Reasoning = true
		// Current Anthropic Messages supports output_config.format JSON Schema.
		routeCapabilities.ResponseFormat = capabilities.SupportsFeatureOrUnknown("response_format")
		routeCapabilities.JSONSchema = capabilities.SupportsFeatureOrUnknown("json_schema")
		// Chat 的块级 cache_control / 顶层 cache_control 都被转换层映射成 Messages 的块级断点，
		// 缓存读写计数也映射回 usage；prompt_cache_key 只是路由提示，丢弃不改变语义。
		routeCapabilities.CacheTokens = capabilities.SupportsFeatureOrUnknown("cache_tokens")
		routeCapabilities.Stateful = false
	}
	if conversion && endpoint == "messages" {
		// Cache breakpoints and state/container identity are provider-specific.
		// All message/content/tool/media fields are converted explicitly; signed
		// thinking history fails before dispatch rather than being dropped.
		routeCapabilities.Audio = false
		routeCapabilities.Video = false
		// Messages 的 cache_control 只是缓存断点提示，桥接到 OpenAI 的 Responses/Chat 时
		// 由桥接器无损丢弃（不影响语义，只影响成本和延迟），所以不能因此拒绝路由；
		// Claude Code 每个请求都带它。其余上游（Gemini/Bedrock 等）没有等价语义，保持拒绝。
		routeCapabilities.CacheTokens = upstreamProtocol == "responses" || upstreamProtocol == "chat"
		routeCapabilities.Stateful = false
	}
	if conversion {
		routeCapabilities.Conversions = []relay.ProtocolConversion{{From: endpoint, To: upstreamProtocol, Lossless: true}}
	} else {
		routeCapabilities.IngressProtocols = []string{endpoint}
	}
	request.UpstreamProtocol = upstreamProtocol
	decision := relay.MatchRoute(request, routeCapabilities)
	return upstreamProtocol, decision
}

type providerCredentialResolver interface {
	GetProviderCredential(ctx context.Context, providerID string) (string, error)
}

type modelRouteExecutionInput struct {
	Engine             modelrouter.Engine
	CredentialResolver providerCredentialResolver
	Factory            ProviderAdapterFactory
	Envelope           *modelrouter.RequestEnvelope
	SecuredBody        []byte
	// Streaming requests an upstream streaming transport. It does not imply
	// that bytes are streamed live to the downstream client.
	Streaming     bool
	CommitTracker *relay.CommitTracker
	StreamSink    func(context.Context, ProviderCaller, *modelrouter.RequestEnvelope, []byte) (attempted bool, err error)
	PreparedPlan  *modelrouter.RoutePlan
}

type modelRouteExecutionResult struct {
	Caller       ProviderCaller
	ResponseBody []byte
	Envelope     *modelrouter.RequestEnvelope
	Attempts     int
	UsedFallback bool
	LiveStream   bool
}

func selectModelRoutingMode(ctx context.Context, engine modelrouter.Engine, tenantID, modelRef string) (bool, error) {
	if engine == nil {
		return false, nil
	}
	return engine.HasV2Policy(ctx, tenantID, modelRef)
}

func executeModelRoutePlan(ctx context.Context, input modelRouteExecutionInput) (*modelRouteExecutionResult, error) {
	if input.Engine == nil || input.CredentialResolver == nil || input.Factory == nil || input.Envelope == nil {
		return nil, fmt.Errorf("%w: routing dependencies unavailable", errModelRouteUnavailable)
	}
	requestedModel := input.Envelope.Model
	var plan modelrouter.RoutePlan
	applied := true
	var err error
	if input.PreparedPlan != nil {
		plan = *input.PreparedPlan
	} else {
		plan, applied, err = input.Engine.Plan(ctx, *input.Envelope)
	}
	if plan.Decision != nil {
		input.Envelope.RoutingDecision = plan.Decision
	}
	if err != nil {
		input.Envelope.RejectReason = plannedRouteRejectReason(plan, err, applied)
		return nil, fmt.Errorf("%w: no usable route for requested model", errModelRouteUnavailable)
	}
	if !applied {
		input.Envelope.RejectReason = plannedRouteRejectReason(plan, err, applied)
		return nil, fmt.Errorf("%w: selected policy is no longer available", errModelRouteUnavailable)
	}
	routes := append([]modelrouter.ModelRecord{plan.Primary}, plan.Fallbacks...)
	if len(routes) == 0 || routes[0].ProviderID == "" {
		input.Envelope.RejectReason = "route_plan_empty"
		return nil, fmt.Errorf("%w: no usable route for requested model", errModelRouteUnavailable)
	}
	logicalModel := routes[0].ModelName
	if logicalModel == "" {
		logicalModel = requestedModel
	}
	if !auth.UserFinalModelAllowed(ctx, logicalModel) {
		return nil, errUserModelForbidden
	}
	requestFeatures := modelRouteRequestFeatures(input.Envelope, input.SecuredBody, input.Streaming)
	if plan.Decision != nil {
		plan.Decision.IngressProtocol = input.Envelope.EndpointType
		plan.Decision.RequestFeatures = relay.FeatureNames(requestFeatures)
	}

	var lastErr error
	var contractShortfall []string
	attempts := 0
	for routeIndex, route := range routes {
		if attempts >= maximumModelRouteAttempts {
			break
		}
		if !auth.UserFinalModelAllowed(ctx, route.ModelName) {
			return nil, errUserModelForbidden
		}
		if route.ModelName != logicalModel {
			return nil, fmt.Errorf("%w: route changed logical model", errModelRouteUnavailable)
		}
		routeIdentity := modelRouteAuditIdentity(plan, route, routeIndex)
		upstreamProtocol, capabilityDecision := selectModelRouteProtocol(route, requestFeatures)
		if !capabilityDecision.Eligible {
			reason := "endpoint_not_supported"
			if input.Envelope.EndpointType == "responses" {
				reason = "responses_native_unavailable"
			}
			if len(capabilityDecision.Reasons) > 0 &&
				!(len(capabilityDecision.Reasons) == 1 && capabilityDecision.Reasons[0] == "ingress_protocol") {
				reason = "semantic_capability:" + strings.Join(capabilityDecision.Reasons, ",")
				contractShortfall = append(contractShortfall, capabilityDecision.Reasons...)
			}
			markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, reason, reason)
			continue
		}
		apiKey, credentialErr := input.CredentialResolver.GetProviderCredential(ctx, route.ProviderID)
		if credentialErr != nil || apiKey == "" {
			markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "missing_credential", "planned_route_ineligible")
			continue
		}
		caller := input.Factory.CreateAdapter(&route, apiKey)
		if caller == nil {
			markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "unsupported_provider_type", "planned_route_ineligible")
			lastErr = fmt.Errorf("%w: %s", provider.ErrProviderTypeUnsupported, route.ProviderType)
			continue
		}
		bridgeEnvelope := *input.Envelope
		bridgeEnvelope.UpstreamProtocol = upstreamProtocol
		caller = adaptProviderIngress(caller, &bridgeEnvelope)
		if capability, ok := caller.(provider.EndpointCapability); ok && !capability.SupportsEndpoint(input.Envelope.EndpointType) {
			markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "endpoint_not_supported", "endpoint_not_supported")
			continue
		}
		attemptEnvelope := *input.Envelope
		attemptEnvelope.UpstreamTTFTMs = nil
		attemptEnvelope.Model = requestedModel
		attemptEnvelope.ModelID = route.ID
		attemptEnvelope.ProviderID = route.ProviderID
		attemptEnvelope.Provider = route.ProviderType
		attemptEnvelope.UpstreamModelID = route.UpstreamModelID
		attemptEnvelope.ProtocolCapabilities = route.ProtocolCapabilities
		attemptEnvelope.UpstreamProtocol = upstreamProtocol
		attemptEnvelope.RoutingDecision = plan.Decision
		if plan.Decision != nil {
			plan.Decision.UpstreamProtocol = upstreamProtocol
		}

		providerReq, transformErr := caller.TransformRequest(&attemptEnvelope, append([]byte(nil), input.SecuredBody...))
		if transformErr != nil {
			if provider.IsEndpointNotSupported(transformErr) {
				markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "endpoint_not_supported", "endpoint_not_supported")
				continue
			}
			markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "request_transform_failed", "planned_route_ineligible")
			lastErr = transformErr
			break
		}
		key := modelrouter.RouteKey{TenantID: attemptEnvelope.TenantID, ModelName: logicalModel, ProviderID: route.ProviderID}
		for sameRouteRetry := 0; ; sameRouteRetry++ {
			if attempts >= maximumModelRouteAttempts {
				break
			}
			if !input.Engine.AllowAttempt(key) {
				markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "health_gate_refused", "planned_route_ineligible")
				break
			}
			attempts++
			attemptEnvelope.UpstreamTTFTMs = nil
			started := time.Now()
			ledgerEntry := modelrouter.RouteAttemptLedgerEntry{
				AttemptID: "attempt_" + uuid.NewString(), LogicalRequestID: attemptEnvelope.RequestID,
				ClientRetryID: attemptEnvelope.ClientRetryID, TenantID: attemptEnvelope.TenantID,
				ProviderID: route.ProviderID, ModelID: route.ID, EndpointType: attemptEnvelope.EndpointType,
				StartedAt: started, DispatchState: "dispatch_started", DownstreamCommitState: commitStateString(input.CommitTracker),
			}
			ledger, _ := input.Engine.(modelrouter.AttemptLedgerRecorder)
			if ledger != nil {
				_ = ledger.StartRouteAttempt(ctx, ledgerEntry)
			}
			var respBody []byte
			var callErr error
			liveAttempted := false
			if input.Streaming && input.StreamSink != nil {
				liveAttempted, callErr = input.StreamSink(ctx, caller, &attemptEnvelope, providerReq)
			}
			if !liveAttempted {
				respBody, callErr = callAndRecordModelRouteAttempt(ctx, input.Engine, key, caller, &attemptEnvelope, providerReq, input.Streaming)
			} else if !provider.IsEndpointNotSupported(callErr) {
				input.Engine.RecordAttempt(key, routeAttemptResult(ctx, callErr, time.Since(started), attemptEnvelope.UpstreamTTFTMs))
			}
			if provider.IsEndpointNotSupported(callErr) {
				if ledger != nil {
					finishRouteAttemptLedger(ctx, ledger, ledgerEntry, callErr, input.CommitTracker)
				}
				attempts--
				if releaser, ok := input.Engine.(modelrouter.AttemptClaimReleaser); ok {
					releaser.ReleaseAttempt(key)
				}
				markModelRouteIneligible(plan.Decision, routeIdentity, routeIndex, "endpoint_not_supported", "endpoint_not_supported")
				break
			}
			appendModelRouteAuditAttempt(plan.Decision, routeIdentity, routeIndex, callErr, time.Since(started))
			if ledger != nil {
				finishRouteAttemptLedger(ctx, ledger, ledgerEntry, callErr, input.CommitTracker)
			}
			if plan.Decision != nil {
				plan.Decision.FallbackRetries = routeIndex
			}
			if callErr == nil {
				completeModelRouteAudit(plan.Decision, routeIdentity, routeIndex)
				*input.Envelope = attemptEnvelope
				if routeIndex > 0 {
					if recorder, ok := input.Engine.(modelrouter.FallbackAlertRecorder); ok {
						recorder.RecordFallback(ctx, key)
					}
				}
				return &modelRouteExecutionResult{Caller: caller, ResponseBody: respBody, Envelope: input.Envelope, Attempts: attempts, UsedFallback: routeIndex > 0, LiveStream: liveAttempted}, nil
			}
			*input.Envelope = attemptEnvelope
			lastErr = callErr
			if input.CommitTracker != nil && !input.CommitTracker.CanRetry() {
				return nil, callErr
			}
			if !shouldRetryModelRoute(ctx, callErr) {
				return nil, callErr
			}
			if !shouldRetrySameModelRoute(len(routes), sameRouteRetry, callErr) {
				break
			}
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if input.Envelope.EndpointType == "responses" && attempts == 0 {
		return nil, fmt.Errorf("%w: no route explicitly supports native Responses", errResponsesNativeUnavailable)
	}
	input.Envelope.RejectReason = admittedRouteRejectReason(plan, contractShortfall)
	return nil, fmt.Errorf("%w: no route admitted execution", errModelRouteUnavailable)
}

func commitStateString(tracker *relay.CommitTracker) string {
	if tracker == nil {
		return string(relay.CommitNotStarted)
	}
	return string(tracker.State())
}

func finishRouteAttemptLedger(ctx context.Context, ledger modelrouter.AttemptLedgerRecorder, entry modelrouter.RouteAttemptLedgerEntry, err error, tracker *relay.CommitTracker) {
	entry.FinishedAt = time.Now()
	entry.DispatchState = "dispatched"
	entry.DownstreamCommitState = commitStateString(tracker)
	entry.DeliveryOutcome = "pending"
	entry.UpstreamOutcome = "success"
	if tracker != nil {
		switch tracker.State() {
		case relay.CommitCompleted:
			entry.DeliveryOutcome = "completed"
		case relay.CommitAborted:
			entry.DeliveryOutcome = "aborted"
		}
	}
	if err != nil {
		if entry.DeliveryOutcome == "pending" {
			entry.DeliveryOutcome = "not_started"
		}
		entry.UpstreamOutcome = "unknown"
		entry.ResultUnknown = true
		var upstreamErr *provider.UpstreamHTTPError
		switch {
		case errors.As(err, &upstreamErr):
			entry.UpstreamOutcome = "http_error"
			entry.ResultUnknown = false
		case errors.Is(err, context.Canceled):
			entry.UpstreamOutcome = "canceled"
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, provider.ErrUpstreamStreamIdleTimeout):
			entry.UpstreamOutcome = "timeout"
		case provider.IsEndpointNotSupported(err), errors.Is(err, provider.ErrInvalidAnthropicMessagesResponse):
			entry.UpstreamOutcome = "protocol_error"
			entry.ResultUnknown = false
		default:
			var networkErr net.Error
			if errors.As(err, &networkErr) || isTransientConnectionError(err) {
				entry.UpstreamOutcome = "network_error"
			}
		}
	}
	_ = ledger.FinishRouteAttempt(ctx, entry)
}

func routePlanSupportsNativeResponses(plan modelrouter.RoutePlan) bool {
	if plan.Primary.ProviderID != "" && plan.Primary.ResponsesNative {
		return true
	}
	for _, route := range plan.Fallbacks {
		if route.ProviderID != "" && route.ResponsesNative {
			return true
		}
	}
	return false
}

func safeAttemptRoute(route modelrouter.ModelRecord, index int) modelrouter.RouteIdentity {
	name := strings.TrimSpace(route.ProviderName)
	if name == "" {
		name = "上游线路"
	}
	return modelrouter.RouteIdentity{ProviderName: name, RouteRef: fmt.Sprintf("线路 %d", index+1)}
}

func modelRouteAuditIdentity(plan modelrouter.RoutePlan, route modelrouter.ModelRecord, index int) modelrouter.RouteIdentity {
	if identity, ok := plan.RouteIdentities[route.ProviderID]; ok && identity.RouteRef != "" {
		return identity
	}
	return safeAttemptRoute(route, index)
}

func markModelRouteIneligible(decision *modelrouter.RoutingDecision, identity modelrouter.RouteIdentity, index int, candidateReason, fallbackReason string) {
	if decision == nil || decision.ModelRouteV2 == nil {
		return
	}
	for i := range decision.ModelRouteV2.Candidates {
		candidate := &decision.ModelRouteV2.Candidates[i]
		if identity.RouteRef != "" && candidate.RouteRef == identity.RouteRef {
			candidate.ExclusionReason = candidateReason
			break
		}
	}
	if index == 0 && decision.ModelRouteV2.FallbackReason == "" {
		decision.ModelRouteV2.FallbackReason = fallbackReason
	}
}

func appendModelRouteAuditAttempt(decision *modelrouter.RoutingDecision, identity modelrouter.RouteIdentity, index int, err error, latency time.Duration) {
	if decision == nil || decision.ModelRouteV2 == nil {
		return
	}
	attempt := modelrouter.RouteAttemptDecision{Route: identity, Result: "success", LatencyMS: latency.Milliseconds()}
	if err != nil {
		attempt.Result = "failed"
		attempt.FailureCategory = modelRouteFailureCategory(err)
	}
	var upstreamErr *provider.UpstreamHTTPError
	if errors.As(err, &upstreamErr) {
		attempt.StatusCodeCategory = fmt.Sprintf("%dxx", upstreamErr.StatusCode/100)
	}
	decision.ModelRouteV2.Attempts = append(decision.ModelRouteV2.Attempts, attempt)
	decision.ModelRouteV2.ActualRoute = attempt.Route
	if index > 0 {
		decision.ModelRouteV2.FallbackUsed = true
		if decision.ModelRouteV2.FallbackReason == "" {
			if len(decision.ModelRouteV2.Attempts) > 1 {
				decision.ModelRouteV2.FallbackReason = "primary_route_failed"
			} else {
				decision.ModelRouteV2.FallbackReason = "planned_route_ineligible"
			}
		}
	}
}

func completeModelRouteAudit(decision *modelrouter.RoutingDecision, identity modelrouter.RouteIdentity, index int) {
	if decision == nil || decision.ModelRouteV2 == nil {
		return
	}
	decision.ModelRouteV2.ActualRoute = identity
	decision.ModelRouteV2.FallbackUsed = index > 0
	if index > 0 && decision.ModelRouteV2.FallbackReason == "" {
		decision.ModelRouteV2.FallbackReason = "primary_route_failed"
	}
}

func modelRouteFailureCategory(err error) string {
	if err == nil {
		return ""
	}
	var upstreamErr *provider.UpstreamHTTPError
	if errors.As(err, &upstreamErr) {
		if upstreamErr.StatusCode == http.StatusTooManyRequests {
			return "rate_limited"
		}
		if upstreamErr.StatusCode >= 500 {
			return "upstream_5xx"
		}
		return "upstream_rejected"
	}
	if errors.Is(err, provider.ErrInvalidAnthropicMessagesResponse) {
		return "upstream_protocol_error"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return "network_error"
	}
	return "adapter_error"
}

func callAndRecordModelRouteAttempt(ctx context.Context, engine modelrouter.Engine, key modelrouter.RouteKey, caller ProviderCaller, envelope *modelrouter.RequestEnvelope, providerReq []byte, streaming bool) (respBody []byte, err error) {
	started := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			engine.RecordAttempt(key, modelrouter.AttemptResult{Retryable: true, Latency: time.Since(started)})
			panic(recovered)
		}
	}()
	respBody, err = callUpstream(ctx, caller, envelope, providerReq, streaming)
	if provider.IsEndpointNotSupported(err) {
		return respBody, err
	}
	engine.RecordAttempt(key, routeAttemptResult(ctx, err, time.Since(started), envelope.UpstreamTTFTMs))
	return respBody, err
}

func isHealthNeutralModelRouteResult(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, errModelRouteSecurityRejected) {
		return true
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	var upstreamErr *provider.UpstreamHTTPError
	return errors.As(err, &upstreamErr) &&
		(upstreamErr.StatusCode == http.StatusRequestEntityTooLarge || upstreamErr.StatusCode == http.StatusTooManyRequests)
}

func routeAttemptResult(ctx context.Context, err error, latency time.Duration, ttftMS *int64) modelrouter.AttemptResult {
	result := modelrouter.AttemptResult{
		Success:       err == nil,
		Retryable:     shouldRetryModelRoute(ctx, err),
		HealthNeutral: isHealthNeutralModelRouteResult(ctx, err),
		Latency:       latency,
	}
	var upstreamErr *provider.UpstreamHTTPError
	if errors.As(err, &upstreamErr) {
		result.StatusCode = upstreamErr.StatusCode
	}
	if ttftMS != nil && *ttftMS >= 0 {
		result.TTFT = time.Duration(*ttftMS) * time.Millisecond
	}
	return result
}

func shouldRetryModelRoute(ctx context.Context, err error) bool {
	if err == nil || errors.Is(err, errModelRouteSecurityRejected) || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, provider.ErrUpstreamStreamIdleTimeout) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if provider.IsEndpointNotSupported(err) {
		return false
	}
	if errors.Is(err, provider.ErrInvalidAnthropicMessagesResponse) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var upstreamErr *provider.UpstreamHTTPError
	if errors.As(err, &upstreamErr) {
		return shouldFallbackForUpstreamStatus(upstreamErr.StatusCode)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var certificateInvalid x509.CertificateInvalidError
	if errors.As(err, &certificateInvalid) {
		return true
	}
	var recordHeaderError tls.RecordHeaderError
	if errors.As(err, &recordHeaderError) {
		return true
	}
	var addressError *net.AddrError
	if errors.As(err, &addressError) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var operationErr *net.OpError
	if errors.As(err, &operationErr) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		message := strings.ToLower(urlErr.Err.Error())
		if strings.Contains(message, "unsupported protocol scheme") ||
			strings.Contains(message, "missing protocol scheme") ||
			strings.Contains(message, "invalid url") {
			return false
		}
		return isTransientConnectionError(urlErr.Err)
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return true
	}
	return isTransientConnectionError(err)
}

func shouldRetrySameModelRoute(routeCount, retryCount int, err error) bool {
	if routeCount != 1 || retryCount >= maximumSameRouteRetries {
		return false
	}
	var upstreamErr *provider.UpstreamHTTPError
	if !errors.As(err, &upstreamErr) {
		return false
	}
	return upstreamErr.StatusCode >= http.StatusInternalServerError && upstreamErr.StatusCode < 600
}

func shouldFallbackForUpstreamStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests:
		return true
	default:
		return status >= http.StatusInternalServerError
	}
}

func isTransientConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	if message == "connection refused" || strings.HasSuffix(message, ": connection refused") {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func modelRouteErrorCode(err error) string {
	if errors.Is(err, errUserModelForbidden) {
		return "forbidden_model"
	}
	if errors.Is(err, errModelRouteUnavailable) {
		return "model_route_unavailable"
	}
	return ""
}
