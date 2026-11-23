package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type ImagesRequest struct {
	Model   string
	Prompt  string
	N       int
	Stream  bool
	Size    string
	Quality string
}

type imagesParsedRequest struct {
	request ImagesRequest
	raw     map[string]json.RawMessage
}

type ImagesHandler struct {
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

func NewImagesHandler(
	cfg *config.Config,
	modelResolver ModelResolver,
	rateLimiter RateLimitChecker,
	securityClient SecurityChecker,
	auditWriter AuditWriter,
	providerAdapterFactory ProviderAdapterFactory,
	toolRiskClient *ToolRiskClient,
) *ImagesHandler {
	if providerAdapterFactory == nil {
		providerAdapterFactory = &RealProviderAdapterFactory{}
	}
	return &ImagesHandler{
		cfg:                    cfg,
		modelResolver:          modelResolver,
		rateLimiter:            rateLimiter,
		securityClient:         securityClient,
		auditWriter:            auditWriter,
		providerAdapterFactory: providerAdapterFactory,
		toolRiskClient:         toolRiskClient,
	}
}

func (h *ImagesHandler) SetRuntimeConfigClient(client *ToolRiskClient) {
	h.toolRiskClient = client
}

func (h *ImagesHandler) SetModelRoutingEngine(engine modelrouter.Engine) {
	h.modelRouteEngine = engine
}

func (h *ImagesHandler) SetBillingPreflight(client BillingPreflight) {
	h.billingPreflight = client
}

func (h *ImagesHandler) SetGovernor(gov GovernorDecider) { h.governor = gov }

func (h *ImagesHandler) SetQuotaAdmission(admission QuotaAdmission) {
	h.quotaAdmission = admission
}

func (h *ImagesHandler) SetDB(db *pgxpool.Pool) { h.db = db }

func (h *ImagesHandler) securityAuditOnly(ctx context.Context) bool {
	fallback := false
	if h != nil && h.cfg != nil {
		fallback = h.cfg.SecurityAuditOnly
	}
	if h != nil && h.toolRiskClient != nil {
		return h.toolRiskClient.SecurityAuditOnly(ctx, fallback)
	}
	return fallback
}

func (h *ImagesHandler) guardrailFailureMode(ctx context.Context) string {
	if h == nil {
		return "close"
	}
	return resolvedGuardrailFailureMode(ctx, h.cfg, h.toolRiskClient)
}

func (h *ImagesHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		authInfo := auth.GetAuthInfo(r)
		startedAt := time.Now()
		ctx := withBlockLedger(r.Context())

		bodyLimit := apiRequestBodyLimitBytes(h.cfg)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
		if err != nil {
			envelope := buildPartialEnvelope(requestID, authInfo, "", "images")
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				logRequestBodyTooLarge(r, requestID, bodyLimit)
				recordEarlyRequestFailure(ctx, h.auditWriter, envelope, w, "request_too_large", "request body too large", requestID, startedAt, http.StatusRequestEntityTooLarge)
				return
			}
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", "failed to read request body", requestID, startedAt)
			return
		}

		parsed, err := parseImagesRequest(body)
		if err != nil {
			model := ""
			if parsed != nil {
				model = parsed.request.Model
			}
			envelope := buildPartialEnvelope(requestID, authInfo, model, "images")
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", err.Error(), requestID, startedAt)
			return
		}

		result, err := h.processRequest(ctx, w, r, requestID, authInfo, startedAt, parsed, body)
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
			routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{
				Engine:             h.modelRouteEngine,
				CredentialResolver: h.modelResolver,
				Factory:            h.providerAdapterFactory,
				Envelope:           result.Envelope,
				SecuredBody:        result.SecuredBody,
			})
			err = routeErr
			if routeResult != nil {
				responseCaller = routeResult.Caller
				respBody = routeResult.ResponseBody
				fallbackUsed = routeResult.UsedFallback
			}
		} else {
			respBody, err = callUpstream(ctx, result.ProviderCaller, result.Envelope, result.ProviderReq, false)
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
			if provider.IsEndpointNotSupported(err) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "provider_unsupported", err.Error(), requestID)
				return
			}
			if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(startedAt)/time.Millisecond), &AuditResult{ResponseMetadata: map[string]interface{}{"error_message": retainedProviderErrorMessage(upstreamErr.Message)}})
				writeUpstreamErrorResponse(w, upstreamErr, requestID, "upstream_response")
				return
			}
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "upstream provider is unavailable", requestID)
			return
		}

		if responseCaller == nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "provider adapter unavailable", requestID)
			return
		}
		openaiResp, err := responseCaller.TransformResponse(respBody)
		if err == nil {
			if transformer, ok := responseCaller.(provider.ImageResponseTransformer); ok {
				openaiResp, err = transformer.TransformImageResponse(openaiResp)
			}
		}
		if err != nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "failed to parse provider response", requestID)
			return
		}

		auditResult := &AuditResult{ResponseMetadata: imageResponseMetadata(result.Envelope.Model, openaiResp)}
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, imageUsageEvidence(openaiResp), "success", http.StatusOK, int(time.Since(startedAt)/time.Millisecond), auditResult)

		setRoutingHeaders(w, result.Envelope, fallbackUsed)
		w.Header().Set("Content-Type", "application/json")
		writeGatewayJSONBody(w, restoreRedactionBody(ctx, result.Envelope, openaiResp))
	}
}

type ImagesProcessedResult struct {
	Envelope            *modelrouter.RequestEnvelope
	ProviderCaller      ProviderCaller
	ProviderReq         []byte
	SecuredBody         []byte
	FallbackProvider    *FallbackProviderPlan
	ConcurrencyAcquired bool
	UseV2ModelRouting   bool
}

func (h *ImagesHandler) processRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	authInfo *auth.AuthInfo,
	startedAt time.Time,
	parsed *imagesParsedRequest,
	rawBody []byte,
) (*ImagesProcessedResult, error) {
	req := &parsed.request
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
		EndpointType:     "images",
		SourceIP:         authInfo.ClientIP,
	}
	if partialEnvelope.SessionID != "" {
		h.auditWriter.UpsertAgentSession(ctx, partialEnvelope)
	}

	if err := validateImagesRequest(req); err != nil {
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
			// 原始请求体里的 model 同步成全名，上游收到的与直接写全名一致。
			if encoded, encErr := json.Marshal(full); encErr == nil {
				parsed.raw["model"] = encoded
			}
			if rewritten, rewriteErr := rewriteRequestBodyModel(rawBody, full); rewriteErr == nil {
				rawBody = rewritten
			}
		}
	}
	if err != nil {
		h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
		h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "model_not_configured", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "model_not_configured", "model "+req.Model+" is not configured", requestID)
		return nil, fmt.Errorf("model_not_configured")
	}

	modelPolicy, err := h.modelResolver.GetModelPolicy(ctx, authInfo.ProjectID)
	if !auth.UserModelAllowed(ctx, req.Model) || (!auth.UserModelAccessEnforced(ctx) && err == nil && !modelPolicy.IsModelAllowed(req.Model)) {
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
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "rate_limited", http.StatusTooManyRequests, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "rate_limited", "RPM limit exceeded", requestID)
				return nil, fmt.Errorf("rate_limited")
			}
		}
		if quotaPolicy.ConcurrencyLimit > 0 {
			allowed, _, checkErr := h.rateLimiter.CheckConcurrency(ctx, authInfo.ProjectID, quotaPolicy.ConcurrencyLimit)
			if checkErr == nil && !allowed {
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
		EnvironmentScope:     authInfo.EnvironmentScope,
		ModelID:              modelRecord.ID,
		UpstreamModelID:      modelRecord.UpstreamModelID,
		EndpointType:         "images",
		SourceIP:             authInfo.ClientIP,
		Provider:             modelRecord.ProviderType,
		ProviderID:           modelRecord.ProviderID,
		ProtocolCapabilities: modelRecord.ProtocolCapabilities,
	}
	envelope.TeamID, _ = h.modelResolver.GetProjectTeamID(ctx, authInfo.ProjectID)
	envelope.Principal = principalForGatewayEndpoint(authInfo.Principal, "images", "gateway_api", envelope.TeamID)
	envelope.ClientRetryID = clientRetryID(r.Header)
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

	useV2ModelRouting := false
	if os.Getenv("UAG_ROUTING_DISABLED") != "true" {
		useV2ModelRouting, err = selectModelRoutingMode(ctx, h.modelRouteEngine, envelope.TenantID, envelope.Model)
		if err != nil {
			releaseConcurrencyOnError()
			envelope.RejectReason = "route_policy_lookup_failed"
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(envelope), requestID)
			return nil, errModelRouteUnavailable
		}
	}
	if !useV2ModelRouting && modelRecord.ProtocolCapabilities.Explicit && !modelRecord.SupportsConfiguredEndpoint("images") {
		releaseConcurrencyOnError()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "provider_unsupported", "configured upstream route does not support images", requestID)
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
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_not_configured", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_not_configured", "provider credentials not configured", requestID)
			return nil, fmt.Errorf("provider_not_configured")
		}
		providerAdapter = h.providerAdapterFactory.CreateAdapter(modelRecord, apiKey)
		if providerAdapter == nil {
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "provider adapter unavailable", requestID)
			return nil, fmt.Errorf("provider_unavailable")
		}
		if capability, ok := providerAdapter.(provider.EndpointCapability); ok && !capability.SupportsEndpoint("images") {
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unsupported", "provider does not support image generation", requestID)
			return nil, fmt.Errorf("provider_unsupported")
		}
		fallbackProvider = buildFallbackProviderPlan(ctx, h.modelResolver, h.providerAdapterFactory, modelRecord)
	}

	securedBody, err := h.applyInputSecurity(ctx, envelope, req, parsed.raw, rawBody)
	if err != nil {
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
		setSecurityActionHeader(w, "block", securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		writeErrorResponse(w, "security_blocked", notice.Text, requestID)
		return nil, fmt.Errorf("security_blocked")
	}

	var providerReq []byte
	if !useV2ModelRouting {
		providerReq, err = providerAdapter.TransformRequest(envelope, securedBody)
		if err != nil {
			releaseConcurrencyOnError()
			status := "invalid_request"
			message := "failed to transform request for provider"
			if provider.IsEndpointNotSupported(err) {
				status = "provider_unsupported"
				message = err.Error()
			}
			httpStatus := http.StatusBadRequest
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, status, httpStatus, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, status, message, requestID)
			return nil, errors.New(status)
		}
	}

	if h.billingPreflight != nil {
		estimatedPromptTokens := estimateTextTokens(req.Prompt)
		if estimatedPromptTokens < 1 {
			estimatedPromptTokens = 1
		}
		imageCount := int64(req.N)
		if imageCount <= 0 {
			imageCount = 1
		}
		if billingErr := h.billingPreflight.ReserveUsage(ctx, envelope, BillingUsage{PromptTokens: estimatedPromptTokens, ImageCount: imageCount, ImageRequest: true, ImageSize: req.Size, ImageQuality: req.Quality}); billingErr != nil {
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
		if admissionErr := attachQuotaAdmission(ctx, h.quotaAdmission, envelope, estimatedImageAdmissionTokens(req.Prompt), func(recordCtx context.Context, decision governor.Decision) {
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

	return &ImagesProcessedResult{
		Envelope:            envelope,
		ProviderCaller:      providerAdapter,
		ProviderReq:         providerReq,
		SecuredBody:         securedBody,
		FallbackProvider:    fallbackProvider,
		ConcurrencyAcquired: concurrencyAcquired,
		UseV2ModelRouting:   useV2ModelRouting,
	}, nil
}

func parseImagesRequest(body []byte) (*imagesParsedRequest, error) {
	parsed := &imagesParsedRequest{raw: map[string]json.RawMessage{}}
	if err := json.Unmarshal(body, &parsed.raw); err != nil || parsed.raw == nil {
		return nil, fmt.Errorf("invalid JSON format")
	}

	var req ImagesRequest
	modelRaw, ok := parsed.raw["model"]
	if !ok {
		return parsed, fmt.Errorf("model is required")
	}
	if err := json.Unmarshal(modelRaw, &req.Model); err != nil {
		return parsed, fmt.Errorf("model must be a string")
	}
	promptRaw, ok := parsed.raw["prompt"]
	if !ok {
		return parsed, fmt.Errorf("prompt is required")
	}
	if err := json.Unmarshal(promptRaw, &req.Prompt); err != nil {
		return parsed, fmt.Errorf("prompt must be a string")
	}
	if streamRaw, ok := parsed.raw["stream"]; ok {
		if err := json.Unmarshal(streamRaw, &req.Stream); err != nil {
			return parsed, fmt.Errorf("stream must be a boolean")
		}
	}
	if req.Stream {
		return parsed, fmt.Errorf("streaming is not supported for image generation")
	}
	if nRaw, ok := parsed.raw["n"]; ok {
		if err := json.Unmarshal(nRaw, &req.N); err != nil || req.N < 1 || req.N > 10 {
			return parsed, fmt.Errorf("n must be an integer between 1 and 10")
		}
	}
	for key, target := range map[string]*string{"size": &req.Size, "quality": &req.Quality} {
		if value, ok := parsed.raw[key]; ok {
			if json.Unmarshal(value, target) != nil || !billingmedia.ValidDimension(*target, false) {
				return parsed, fmt.Errorf("%s must be a valid string", key)
			}
			*target = billingmedia.Dimension(*target)
		}
	}
	parsed.request = req
	return parsed, nil
}

func validateImagesRequest(req *ImagesRequest) error {
	if strings.TrimSpace(req.Model) == "" {
		return fmt.Errorf("model is required")
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return fmt.Errorf("prompt must not be empty")
	}
	if req.Stream {
		return fmt.Errorf("streaming is not supported for image generation")
	}
	return nil
}

func (h *ImagesHandler) applyInputSecurity(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	req *ImagesRequest,
	raw map[string]json.RawMessage,
	rawBody []byte,
) ([]byte, error) {
	var action, maskedContent string
	var findings []SecurityFinding
	var outcome *InputCheckOutcome
	var err error
	if detailed, ok := h.securityClient.(detailedInputChecker); ok {
		outcome, err = detailed.CheckInputDetailed(ctx, envelope, req.Prompt, 0, "user", "user")
		if err == nil && outcome != nil {
			action, maskedContent, findings = outcome.Action, outcome.MaskedContent, outcome.Findings
		}
	} else {
		action, maskedContent, findings, err = h.securityClient.CheckInput(ctx, envelope, req.Prompt, 0, "user", "user")
	}

	if err != nil {
		// 客户端在输入扫描期间断开（Esc / 中断）：不是检测失败，不写 security_check_failed，
		// 不走 fail-closed；返回包装 context.Canceled 的错误，调用方记 client_canceled。
		if clientGoneDuring(ctx, err) {
			return nil, fmt.Errorf("%w: image prompt", errClientGoneDuringSecurity)
		}
		mode := h.guardrailFailureMode(ctx)
		h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "security_check_failed", fmt.Sprintf("image prompt check failed (failure_mode=%s)", mode))
		// A failed inspection is a coverage gap unless the explicit fail-closed
		// option applies (protect mode only).
		if securityexit.DecideWithPolicy(securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx)), "block", securityexit.FailureCause(err), guardrailPolicy(ctx, h.toolRiskClient)).Enforce {
			return nil, fmt.Errorf("%w: image prompt", errGuardrailDetectionUnavailable)
		}
		return rawBody, nil
	}

	exitMode := securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx))
	if exitMode == securityexit.Record && (len(findings) > 0 || securityexit.Blocks(action) || action == "mask") {
		h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_audit_only", fmt.Sprintf("image prompt matched security action %q", action))
		return rawBody, nil
	}
	if securityexit.Decide(exitMode, action, securityexit.RuleHit).Enforce {
		h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_blocked", "blocked image prompt")
		return nil, fmt.Errorf("request blocked due to security findings in image prompt")
	}
	if action == "mask" && maskedContent != "" {
		req.Prompt = maskedContent
		if outcome != nil {
			addRequestRedaction(ctx, envelope, maskedContent, outcome.RedactionMapping)
		}
		raw["prompt"], _ = json.Marshal(maskedContent)
		secured, marshalErr := json.Marshal(raw)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to serialize masked image prompt: %w", marshalErr)
		}
		h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_masked", "masked image prompt")
		return secured, nil
	}
	if len(findings) > 0 {
		h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, "security_audit", "image prompt findings")
	}
	return rawBody, nil
}

func imageResponseMetadata(model string, response []byte) map[string]interface{} {
	sum := sha256.Sum256(response)
	metadata := map[string]interface{}{
		"model":           model,
		"response_bytes":  len(response),
		"response_sha256": fmt.Sprintf("%x", sum[:]),
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response, &raw); err == nil {
		var data []json.RawMessage
		if dataRaw, ok := raw["data"]; ok && json.Unmarshal(dataRaw, &data) == nil {
			metadata["image_count"] = len(data)
		}
	}
	return metadata
}

// Forward only usage evidence into audit and settlement; never retain image data.
func imageUsageEvidence(response []byte) []byte {
	var payload struct {
		Usage   json.RawMessage `json:"usage"`
		Size    string          `json:"size"`
		Quality string          `json:"quality"`
		Data    []struct {
			Size    string `json:"size"`
			Quality string `json:"quality"`
		} `json:"data"`
	}
	if json.Unmarshal(response, &payload) != nil {
		return nil
	}
	validUsage := len(payload.Usage) > 0 && len(payload.Usage) <= 64<<10 && string(payload.Usage) != "null"
	if payload.Data == nil && !validUsage {
		return nil
	}
	evidence := map[string]any{}
	if payload.Data != nil {
		evidence["image_count"] = len(payload.Data)
	}
	if payload.Size != "" {
		evidence["image_size"] = billingmedia.Dimension(payload.Size)
	}
	if payload.Quality != "" {
		evidence["image_quality"] = billingmedia.Dimension(payload.Quality)
	}
	variants := []billingmedia.ImageVariantUsage{}
	for _, item := range payload.Data {
		if item.Size != "" || item.Quality != "" {
			variants = append(variants, billingmedia.ImageVariantUsage{Size: billingmedia.Dimension(item.Size), Quality: billingmedia.Dimension(item.Quality), Count: 1})
		}
	}
	if len(variants) > 0 {
		// Unspecified outputs inherit the top-level or requested dimensions.
		if len(variants) < len(payload.Data) {
			variants = append(variants, billingmedia.ImageVariantUsage{Count: int64(len(payload.Data) - len(variants))})
		}
		evidence["image_variants"] = variants
	}
	if validUsage {
		evidence["usage"] = payload.Usage
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return nil
	}
	return encoded
}
