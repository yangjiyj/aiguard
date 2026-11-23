package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// EmbeddingsRequest represents OpenAI embeddings API request
type EmbeddingsRequest struct {
	Model          string      `json:"model"`
	Input          interface{} `json:"input"` // string or array of strings
	EncodingFormat string      `json:"encoding_format,omitempty"`
	Dimensions     int         `json:"dimensions,omitempty"`
}

// EmbeddingsResponse represents OpenAI embeddings API response
type EmbeddingsResponse struct {
	Object string          `json:"object"`
	Data   []EmbeddingData `json:"data"`
	Model  string          `json:"model"`
	Usage  EmbeddingsUsage `json:"usage"`
}

type EmbeddingData struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

type EmbeddingsUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// EmbeddingsHandler handles /v1/embeddings with injectable dependencies
type EmbeddingsHandler struct {
	cfg                    *config.Config
	modelResolver          ModelResolver
	rateLimiter            RateLimitChecker
	securityClient         SecurityChecker
	auditWriter            AuditWriter
	providerAdapterFactory ProviderAdapterFactory
	toolRiskClient         *ToolRiskClient
	modelRouteEngine       modelrouter.Engine
	billingPreflight       BillingPreflight
	governor               GovernorDecider
	quotaAdmission         QuotaAdmission
	db                     *pgxpool.Pool
}

// NewEmbeddingsHandler creates a handler with injectable dependencies
func NewEmbeddingsHandler(
	cfg *config.Config,
	modelResolver ModelResolver,
	rateLimiter RateLimitChecker,
	securityClient SecurityChecker,
	auditWriter AuditWriter,
	providerAdapterFactory ProviderAdapterFactory,
) *EmbeddingsHandler {
	if providerAdapterFactory == nil {
		providerAdapterFactory = &RealProviderAdapterFactory{}
	}
	return &EmbeddingsHandler{
		cfg:                    cfg,
		modelResolver:          modelResolver,
		rateLimiter:            rateLimiter,
		securityClient:         securityClient,
		auditWriter:            auditWriter,
		providerAdapterFactory: providerAdapterFactory,
	}
}

func (h *EmbeddingsHandler) SetRuntimeConfigClient(client *ToolRiskClient) {
	h.toolRiskClient = client
}

func (h *EmbeddingsHandler) SetModelRoutingEngine(engine modelrouter.Engine) {
	h.modelRouteEngine = engine
}

func (h *EmbeddingsHandler) SetBillingPreflight(client BillingPreflight) { h.billingPreflight = client }

func (h *EmbeddingsHandler) SetGovernor(gov GovernorDecider) { h.governor = gov }

func (h *EmbeddingsHandler) SetQuotaAdmission(admission QuotaAdmission) {
	h.quotaAdmission = admission
}

func (h *EmbeddingsHandler) SetDB(db *pgxpool.Pool) { h.db = db }

func (h *EmbeddingsHandler) securityAuditOnly(ctx context.Context) bool {
	fallback := false
	if h != nil && h.cfg != nil {
		fallback = h.cfg.SecurityAuditOnly
	}
	if h != nil && h.toolRiskClient != nil {
		return h.toolRiskClient.SecurityAuditOnly(ctx, fallback)
	}
	return fallback
}

// guardrailFailureMode 解析当前生效的护栏失败模式（动态 > env > 默认 open）。
func (h *EmbeddingsHandler) guardrailFailureMode(ctx context.Context) string {
	if h == nil {
		return "close"
	}
	return resolvedGuardrailFailureMode(ctx, h.cfg, h.toolRiskClient)
}

// Handler returns the HTTP handler function
func (h *EmbeddingsHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		authInfo := auth.GetAuthInfo(r)
		startedAt := time.Now()
		ctx := withBlockLedger(r.Context())

		bodyLimit := apiRequestBodyLimitBytes(h.cfg)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
		if err != nil {
			envelope := buildPartialEnvelope(requestID, authInfo, "", "embeddings")
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				logRequestBodyTooLarge(r, requestID, bodyLimit)
				recordEarlyRequestFailure(ctx, h.auditWriter, envelope, w, "request_too_large", "request body too large", requestID, startedAt, http.StatusRequestEntityTooLarge)
				return
			}
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", "failed to read request body", requestID, startedAt)
			return
		}

		var req EmbeddingsRequest
		if err := json.Unmarshal(body, &req); err != nil {
			envelope := buildPartialEnvelope(requestID, authInfo, req.Model, "embeddings")
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", "invalid JSON format", requestID, startedAt)
			return
		}

		result, err := h.processRequest(ctx, w, r, requestID, authInfo, startedAt, &req, body)
		if err != nil {
			return
		}
		if result.Envelope.QuotaHeartbeatStop != nil {
			defer result.Envelope.QuotaHeartbeatStop()
		}

		if result.ConcurrencyAcquired {
			defer h.rateLimiter.ReleaseConcurrency(ctx, result.Envelope.ProjectID)
		}

		responseCaller := result.ProviderCaller
		fallbackUsed := false
		var respBody []byte
		if result.UseV2ModelRouting {
			routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{Engine: h.modelRouteEngine, CredentialResolver: h.modelResolver, Factory: h.providerAdapterFactory, Envelope: result.Envelope, SecuredBody: result.SecuredBody})
			err = routeErr
			if routeResult != nil {
				responseCaller = routeResult.Caller
				respBody = routeResult.ResponseBody
				fallbackUsed = routeResult.UsedFallback
			}
		} else {
			respBody, err = result.ProviderCaller.Call(ctx, result.Envelope, result.ProviderReq)
			if err != nil {
				fallbackResult := attemptFallbackCall(ctx, result.Envelope, result.SecuredBody, err, result.FallbackProvider, false)
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
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponseWithStatus(w, "request_canceled", "request was canceled", requestID, http.StatusRequestTimeout)
				return
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_timeout", http.StatusGatewayTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponseWithStatus(w, "provider_timeout", "upstream provider timed out", requestID, http.StatusGatewayTimeout)
				return
			}
			if errors.Is(err, errUserModelForbidden) {
				result.Envelope.RejectReason = modelDenialRejectReason(ctx, result.Envelope.Model)
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "forbidden_model", modelDeniedMessage(ctx, result.Envelope.Model), requestID)
				return
			}
			if errors.Is(err, errModelRouteUnavailable) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(result.Envelope), requestID)
				return
			}
			// Check if this is an endpoint not supported error
			if provider.IsEndpointNotSupported(err) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "provider_unsupported", err.Error(), requestID)
				return
			}

			// Check if this is an upstream HTTP error (4xx/5xx from provider)
			if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(startedAt)/time.Millisecond), &AuditResult{ResponseMetadata: map[string]interface{}{"error_message": retainedProviderErrorMessage(upstreamErr.Message)}})
				writeUpstreamErrorResponse(w, upstreamErr, requestID, "upstream_response")
				return
			}

			// Other errors (network, timeout, etc.)
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "upstream provider is unavailable", requestID)
			return
		}

		openaiResp, err := responseCaller.TransformResponse(respBody)
		if err != nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "failed to parse provider response", requestID)
			return
		}

		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, openaiResp, "success", http.StatusOK, int(time.Since(startedAt)/time.Millisecond), nil)

		setRoutingHeaders(w, result.Envelope, fallbackUsed)
		w.Header().Set("Content-Type", "application/json")
		writeGatewayJSONBody(w, openaiResp)
	}
}

// EmbeddingsProcessedResult holds the result of embeddings request processing
type EmbeddingsProcessedResult struct {
	Envelope            *modelrouter.RequestEnvelope
	ProviderCaller      ProviderCaller
	ProviderReq         []byte
	SecuredBody         []byte
	FallbackProvider    *FallbackProviderPlan
	StartedAt           time.Time
	ConcurrencyAcquired bool
	UseV2ModelRouting   bool
}

func (h *EmbeddingsHandler) processRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	authInfo *auth.AuthInfo,
	startedAt time.Time,
	req *EmbeddingsRequest,
	body []byte,
) (*EmbeddingsProcessedResult, error) {
	// Create partial envelope immediately after auth success for session recording
	// This ensures session is recorded even if model resolution fails later
	partialEnvelope := &modelrouter.RequestEnvelope{
		RequestID:        requestID,
		TenantID:         authInfo.TenantID,
		ProjectID:        authInfo.ProjectID,
		UserID:           authInfo.UserID,
		ClientID:         authInfo.KeyID,
		EnvironmentScope: authInfo.EnvironmentScope,
		AgentType:        authInfo.AgentType,
		AgentInstanceID:  authInfo.AgentInstanceID,
		SessionID:        authInfo.SessionID,
		WorkspaceID:      authInfo.WorkspaceID,
		TraceID:          authInfo.TraceID,
		LSEEvalRunID:     authInfo.LSEEvalRunID,
		LSETaskID:        authInfo.LSETaskID,
		LSESampleID:      authInfo.LSESampleID,
		LSETargetID:      authInfo.LSETargetID,
		Model:            req.Model,
		ClientModel:      req.Model,
		EndpointType:     "embeddings",
		SourceIP:         authInfo.ClientIP,
	}

	// Upsert session immediately after auth success - do this BEFORE any model/provider checks
	// Contract: authenticated request with session header should always create/update session record
	if partialEnvelope.SessionID != "" {
		h.auditWriter.UpsertAgentSession(ctx, partialEnvelope)
	}

	// Validate input
	if err := h.validateInput(req); err != nil {
		// Audit contract: request log for input validation rejection
		h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
		h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "invalid_request", err.Error(), requestID)
		return nil, fmt.Errorf("invalid_request")
	}

	modelRecord, err := h.modelResolver.ResolveModelWithDB(ctx, authInfo.TenantID, req.Model)
	if miss, ok := asModelNotFound(err); ok {
		rejectModelNotFound(ctx, w, h.auditWriter, partialEnvelope, miss, req.Model, requestID, startedAt)
		return nil, errModelNotFoundRejected
	}
	if err == nil {
		if full := applyModelAlias(partialEnvelope, modelRecord); full != "" {
			req.Model = full
		}
	}
	if err != nil {
		// Audit contract: request log for model not configured rejection
		h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
		h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "model_not_configured", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "model_not_configured", "model "+req.Model+" is not configured", requestID)
		return nil, fmt.Errorf("model_not_configured")
	}

	modelPolicy, err := h.modelResolver.GetModelPolicy(ctx, authInfo.ProjectID)
	if !auth.UserModelAllowed(ctx, req.Model) || (!auth.UserModelAccessEnforced(ctx) && err == nil && !modelPolicy.IsModelAllowed(req.Model)) {
		// Audit contract: request log for policy rejection
		partialEnvelope.RejectReason = modelDenialRejectReason(ctx, req.Model)
		h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
		h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, auth.ModelDenialCode(ctx, req.Model), http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, auth.ModelDenialCode(ctx, req.Model), modelDeniedMessage(ctx, req.Model), requestID)
		return nil, fmt.Errorf("%s", auth.ModelDenialCode(ctx, req.Model))
	}

	concurrencyAcquired := false
	releaseConcurrencyOnError := func() {
		if concurrencyAcquired {
			h.rateLimiter.ReleaseConcurrency(ctx, authInfo.ProjectID)
		}
	}

	quotaPolicy, err := h.modelResolver.GetQuotaPolicy(ctx, authInfo.ProjectID)
	if h.quotaAdmission == nil && err == nil && quotaPolicyEnforced(quotaPolicy) {
		if quotaPolicy.RPMLimit > 0 {
			allowed, checkErr := h.rateLimiter.CheckRPM(ctx, authInfo.ProjectID, quotaPolicy.RPMLimit)
			if checkErr == nil && !allowed {
				// Audit contract: request log for rate limit rejection
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "rate_limited", http.StatusTooManyRequests, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "rate_limited", "RPM limit exceeded", requestID)
				return nil, fmt.Errorf("rate_limited")
			}
		}

		if quotaPolicy.ConcurrencyLimit > 0 {
			allowed, _, checkErr := h.rateLimiter.CheckConcurrency(ctx, authInfo.ProjectID, quotaPolicy.ConcurrencyLimit)
			if checkErr == nil && !allowed {
				// Audit contract: request log for concurrency limit rejection
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "concurrency_limit", http.StatusTooManyRequests, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "concurrency_limit", "concurrency limit exceeded", requestID)
				return nil, fmt.Errorf("concurrency_limit")
			}
			if checkErr == nil && allowed {
				concurrencyAcquired = true
			}
		}

		if quotaPolicy.DailyTokenLimit > 0 {
			allowed, _, checkErr := h.rateLimiter.CheckDailyTokenLimit(ctx, authInfo.ProjectID, quotaPolicy.DailyTokenLimit)
			if checkErr == nil && !allowed {
				releaseConcurrencyOnError()
				// Audit contract: request log for quota rejection
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "quota_exceeded", http.StatusTooManyRequests, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "quota_exceeded", "daily token limit exceeded", requestID)
				return nil, fmt.Errorf("quota_exceeded")
			}
		}

		if quotaPolicy.MonthlyTokenLimit > 0 {
			allowed, _, checkErr := h.rateLimiter.CheckMonthlyTokenLimit(ctx, authInfo.ProjectID, quotaPolicy.MonthlyTokenLimit)
			if checkErr == nil && !allowed {
				releaseConcurrencyOnError()
				// Audit contract: request log for quota rejection
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "quota_exceeded", http.StatusTooManyRequests, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "quota_exceeded", "monthly token limit exceeded", requestID)
				return nil, fmt.Errorf("quota_exceeded")
			}
		}
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID:            requestID,
		TenantID:             authInfo.TenantID,
		ProjectID:            authInfo.ProjectID,
		UserID:               authInfo.UserID,
		ClientID:             authInfo.KeyID,
		EnvironmentScope:     authInfo.EnvironmentScope,
		AgentType:            authInfo.AgentType,
		AgentInstanceID:      authInfo.AgentInstanceID,
		SessionID:            authInfo.SessionID,
		WorkspaceID:          authInfo.WorkspaceID,
		TraceID:              authInfo.TraceID,
		LSEEvalRunID:         authInfo.LSEEvalRunID,
		LSETaskID:            authInfo.LSETaskID,
		LSESampleID:          authInfo.LSESampleID,
		LSETargetID:          authInfo.LSETargetID,
		Model:                req.Model,
		ClientModel:          partialEnvelope.ClientModel,
		ModelResolution:      partialEnvelope.ModelResolution,
		ModelID:              modelRecord.ID,
		UpstreamModelID:      modelRecord.UpstreamModelID,
		EndpointType:         "embeddings",
		SourceIP:             authInfo.ClientIP,
		Provider:             modelRecord.ProviderType,
		ProviderID:           modelRecord.ProviderID,
		ProtocolCapabilities: modelRecord.ProtocolCapabilities,
	}
	envelope.TeamID, _ = h.modelResolver.GetProjectTeamID(ctx, authInfo.ProjectID)
	envelope.Principal = principalForGatewayEndpoint(authInfo.Principal, "embeddings", "gateway_api", envelope.TeamID)
	envelope.ClientRetryID = clientRetryID(r.Header)
	useV2ModelRouting := false
	if os.Getenv("UAG_ROUTING_DISABLED") != "true" {
		useV2ModelRouting, err = selectModelRoutingMode(ctx, h.modelRouteEngine, envelope.TenantID, envelope.Model)
		if err != nil {
			releaseConcurrencyOnError()
			h.auditWriter.EnsureRequestLog(ctx, envelope)
			envelope.RejectReason = "route_policy_lookup_failed"
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(envelope), requestID)
			return nil, errModelRouteUnavailable
		}
	}
	if !useV2ModelRouting && modelRecord.ProtocolCapabilities.Explicit && !modelRecord.SupportsConfiguredEndpoint("embeddings") {
		releaseConcurrencyOnError()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "provider_unsupported", "configured upstream route does not support embeddings", requestID)
		return nil, provider.ErrEndpointNotSupported
	}

	var providerAdapter ProviderCaller
	var fallbackProvider *FallbackProviderPlan
	if !useV2ModelRouting {
		var apiKey string
		if modelRecord.ProviderID != "" {
			apiKey, _ = h.modelResolver.GetProviderCredential(ctx, modelRecord.ProviderID)
		}
		if apiKey == "" {
			releaseConcurrencyOnError()
			h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
			h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "provider_not_configured", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_not_configured", "provider credentials not configured", requestID)
			return nil, fmt.Errorf("provider_not_configured")
		}
		providerAdapter = h.providerAdapterFactory.CreateAdapter(modelRecord, apiKey)
		fallbackProvider = buildFallbackProviderPlan(ctx, h.modelResolver, h.providerAdapterFactory, modelRecord)
	}

	h.auditWriter.EnsureRequestLog(ctx, envelope)
	if applyGovernorDecision(ctx, w, envelope, requestID, h.governor, h.quotaAdmission != nil, false, h.db) {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "governor_blocked", http.StatusTooManyRequests, int(time.Since(startedAt)/time.Millisecond), nil)
		return nil, fmt.Errorf("governor_blocked")
	}

	// Legacy model rules and governor downgrades may change the logical
	// model after request preflight. Recheck before routing or upstream work.
	if !auth.UserFinalModelAllowed(ctx, envelope.Model) {
		releaseConcurrencyOnError()
		envelope.RejectReason = modelDenialRejectReason(ctx, envelope.Model)
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "forbidden_model", modelDeniedMessage(ctx, envelope.Model), requestID)
		return nil, fmt.Errorf("forbidden_model")
	}

	// Note: UpsertAgentSession was already called early in the process (before model resolution)
	// to ensure session is recorded even if model/provider checks fail.
	// The early call used a partial envelope; now we have the full envelope with model info,
	// but session upsert uses ON CONFLICT so no need to call again.

	if err := h.applyInputSecurity(ctx, envelope, req); err != nil {
		releaseConcurrencyOnError()
		// 客户端在输入扫描期间已断开：没有响应可写，按 client_canceled 收尾，不记成 security_blocked。
		if clientGoneDuring(ctx, err) {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponseWithStatus(w, "request_canceled", "request was canceled", requestID, http.StatusRequestTimeout)
			return nil, err
		}
		if rejectGuardrailDetectionUnavailable(ctx, w, h.auditWriter, envelope, requestID, startedAt, nil, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient), err) {
			return nil, errGuardrailDetectionUnavailable
		}
		// These data endpoints retain their 403 error shape; an assistant
		// message would not be a valid image/embedding response.
		notice := (&ChatCompletionsHandler{cfg: h.cfg, toolRiskClient: h.toolRiskClient, auditWriter: h.auditWriter}).blockNoticeForResponse(ctx, envelope, "input", err.Error())
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "security_blocked", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
		setBlockNoticeHeaders(w, notice)
		// 已知边界：embeddings 本期只在 block 时设 X-Security-Action，
		// mask/audit 不带出（其 applyInputSecurity 签名未改，与 chat/messages/responses 不同）。
		setSecurityActionHeader(w, "block", securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		writeErrorResponse(w, "security_blocked", notice.Text, requestID)
		return nil, fmt.Errorf("security_blocked")
	}

	securedBody, err := json.Marshal(req)
	if err != nil {
		releaseConcurrencyOnError()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "invalid_request", "failed to serialize", requestID)
		return nil, fmt.Errorf("invalid_request")
	}

	var providerReq []byte
	if !useV2ModelRouting {
		providerReq, err = providerAdapter.TransformRequest(envelope, securedBody)
		if err != nil {
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "invalid_request", "failed to transform request for provider", requestID)
			return nil, fmt.Errorf("invalid_request")
		}
	}

	if h.billingPreflight != nil {
		if billingErr := h.billingPreflight.ReserveUsage(ctx, envelope, BillingUsage{PromptTokens: estimateEmbeddingInputTokens(req.Input)}); billingErr != nil {
			releaseConcurrencyOnError()
			statusCode, code, message := billingAdmissionResponse(billingErr)
			markBudgetOutcome(envelope, billingAdmissionOutcome(billingErr))
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, code, statusCode, int(time.Since(startedAt)/time.Millisecond), nil)
			setBillingAdmissionRetryAfter(w, billingErr)
			writeErrorResponseWithStatus(w, code, message, requestID, statusCode)
			return nil, billingErr
		}
	}
	if h.quotaAdmission != nil {
		if admissionErr := attachQuotaAdmission(ctx, h.quotaAdmission, envelope, estimateEmbeddingInputTokens(req.Input), func(recordCtx context.Context, decision governor.Decision) {
			recordGovernorEvent(recordCtx, h.db, decision, envelope, quotaAdmissionEventType(decision))
		}); admissionErr != nil {
			releaseConcurrencyOnError()
			statusCode, auditStatus := quotaAdmissionHTTPStatus(admissionErr)
			markBudgetOutcome(envelope, quotaAdmissionBillingOutcome(admissionErr))
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, auditStatus, statusCode, int(time.Since(startedAt)/time.Millisecond), nil)
			writeQuotaAdmissionError(w, admissionErr, requestID)
			return nil, admissionErr
		}
	}

	return &EmbeddingsProcessedResult{
		Envelope:            envelope,
		ProviderCaller:      providerAdapter,
		ProviderReq:         providerReq,
		SecuredBody:         securedBody,
		FallbackProvider:    fallbackProvider,
		StartedAt:           startedAt,
		ConcurrencyAcquired: concurrencyAcquired,
		UseV2ModelRouting:   useV2ModelRouting,
	}, nil
}

// estimateEmbeddingInputTokens shares the chat prompt estimator (7.6) so
// Chinese input is no longer reserved at three tokens per character.
func estimateEmbeddingInputTokens(input interface{}) int64 {
	tokens := int64(1)
	switch value := input.(type) {
	case string:
		tokens += estimateTextTokens(value) + 8
	case []interface{}:
		for _, item := range value {
			if text, ok := item.(string); ok {
				tokens += estimateTextTokens(text) + 8
			}
		}
	}
	return tokens
}

func (h *EmbeddingsHandler) validateInput(req *EmbeddingsRequest) error {
	if req.Model == "" {
		return fmt.Errorf("model is required")
	}

	if req.Input == nil {
		return fmt.Errorf("input is required")
	}

	switch v := req.Input.(type) {
	case string:
		if v == "" {
			return fmt.Errorf("input must not be empty")
		}
	case []interface{}:
		if len(v) == 0 {
			return fmt.Errorf("input array must not be empty")
		}
		for i, item := range v {
			if s, ok := item.(string); ok {
				if s == "" {
					return fmt.Errorf("input[%d] must not be empty", i)
				}
			} else {
				return fmt.Errorf("input[%d] must be a string", i)
			}
		}
	default:
		return fmt.Errorf("input must be a string or array of strings")
	}

	return nil
}

func (h *EmbeddingsHandler) applyInputSecurity(ctx context.Context, envelope *modelrouter.RequestEnvelope, req *EmbeddingsRequest) error {
	inputs := h.extractInputs(req)

	for i, input := range inputs {
		if input == "" {
			continue
		}

		action, maskedContent, findings, err := h.securityClient.CheckInput(ctx, envelope, input, i, "input", "user")
		if err != nil {
			// 客户端在输入扫描期间断开（Esc / 中断）：不是检测失败，不写 security_check_failed，
			// 不走 fail-closed；返回包装 context.Canceled 的错误，调用方记 client_canceled。
			if clientGoneDuring(ctx, err) {
				return fmt.Errorf("%w: input[%d]", errClientGoneDuringSecurity, i)
			}
			mode := h.guardrailFailureMode(ctx)
			h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "security_check_failed", fmt.Sprintf("input[%d]: %s (failure_mode=%s)", i, err.Error(), mode))
			// A failed inspection is a coverage gap unless the explicit
			// fail-closed option applies (protect mode only).
			if securityexit.DecideWithPolicy(securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx)), "block", securityexit.FailureCause(err), guardrailPolicy(ctx, h.toolRiskClient)).Enforce {
				return fmt.Errorf("%w: input[%d]", errGuardrailDetectionUnavailable, i)
			}
			continue
		}

		exitMode := securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx))
		if exitMode == securityexit.Record && (len(findings) > 0 || securityexit.Blocks(action) || action == "mask") {
			h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_audit_only",
				fmt.Sprintf("input[%d] matched security action '%s'", i, action))
			continue
		}

		if securityexit.Decide(exitMode, action, securityexit.RuleHit).Enforce {
			h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_blocked", fmt.Sprintf("blocked input[%d]", i))
			return fmt.Errorf("request blocked due to security findings in input[%d]", i)
		}

		if action == "mask" && maskedContent != "" {
			h.maskInput(req, i, maskedContent)
			h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_masked", fmt.Sprintf("masked input[%d]", i))
		}

		if len(findings) > 0 {
			h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_audit", fmt.Sprintf("input findings in input[%d]", i))
		}
	}

	return nil
}

func (h *EmbeddingsHandler) extractInputs(req *EmbeddingsRequest) []string {
	switch v := req.Input.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			if s, ok := item.(string); ok {
				result[i] = s
			}
		}
		return result
	default:
		return nil
	}
}

func (h *EmbeddingsHandler) maskInput(req *EmbeddingsRequest, index int, maskedContent string) {
	switch v := req.Input.(type) {
	case string:
		if index == 0 {
			req.Input = maskedContent
		}
	case []interface{}:
		if index < len(v) {
			v[index] = maskedContent
		}
	}
}
