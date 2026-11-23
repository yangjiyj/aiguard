package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/aiadapters"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/yangjiyj/aiguard/packages/shared-go/ratelog"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type ChatCompletionRequest struct {
	Model                      string          `json:"model"`
	Messages                   []Message       `json:"messages"`
	Tools                      []ToolDef       `json:"tools,omitempty"`
	ToolChoice                 interface{}     `json:"tool_choice,omitempty"`
	Stream                     bool            `json:"stream,omitempty"`
	MaxTokens                  int             `json:"max_tokens,omitempty"`
	MaxCompletionTokens        int             `json:"max_completion_tokens,omitempty"`
	Temperature                float64         `json:"temperature,omitempty"`
	TopP                       *float64        `json:"top_p,omitempty"`
	ReasoningEffort            string          `json:"reasoning_effort,omitempty"`
	ResponseFormat             json.RawMessage `json:"response_format,omitempty"`
	ParallelToolCalls          *bool           `json:"parallel_tool_calls,omitempty"`
	Store                      *bool           `json:"store,omitempty"`
	Metadata                   json.RawMessage `json:"metadata,omitempty"`
	PromptCacheKey             string          `json:"prompt_cache_key,omitempty"`
	DeferProviderTransform     bool            `json:"-"`
	PreserveOriginalBody       bool            `json:"-"`
	EndpointType               string          `json:"-"`
	EvidenceCorrelationKey     string          `json:"-"`
	EvidenceCorrelationSource  string          `json:"-"`
	ToolCorrelationCandidate   bool            `json:"-"`
	ToolCorrelationContextHash string          `json:"-"`
}

type ToolDef struct {
	Type     string   `json:"type"`
	Function ToolFunc `json:"function"`
	// CacheControl 是 Anthropic 风格的工具级缓存标记；typed 重组请求体时必须保留，否则转换到
	// Messages 时客户端的缓存断点被静默丢掉。
	CacheControl json.RawMessage `json:"cache_control,omitempty"`
}

type ToolFunc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

type Message struct {
	// Internal provenance survives protocol conversion and cannot be supplied in JSON.
	SecuritySource       string `json:"-"`
	SecurityMessageIndex *int   `json:"-"`
	SecurityMessageRole  string `json:"-"`
	SecuritySourcePath   string `json:"-"`
	Role                 string `json:"role"`
	// Content 兼容两种形态: JSON 字符串("...") 或多模态数组([{type:"text",...},{type:"image_url",...}])。
	// 用 json.RawMessage 逐字节透传, 避免多模态请求在解析期 400; 取文本一律走 messageText。
	Content    json.RawMessage `json:"content,omitempty"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	// ToolResultError 是 Anthropic tool_result 的 is_error：客户端明确标了这次工具执行失败
	// （Claude Code 的“Exit code 1”正文里没有文本失败标记）。只供工具连续失败统计用，不发往上游。
	ToolResultError bool `json:"-"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int           `json:"index"`
	Message      ChoiceMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

// ChoiceMessage supports both simple content and tool_calls in response
type ChoiceMessage struct {
	Role    string `json:"role"`
	Content string `json:"content,omitempty"`
	// ReasoningContent 是思维链(DeepSeek 口径); 流式累积时按片拼接, 否则高推理输出会静默丢失。
	ReasoningContent string     `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
}

type ToolCall struct {
	ID                       string       `json:"id"`
	Type                     string       `json:"type"`
	Function                 ToolCallFunc `json:"function"`
	OutputItemID             string       `json:"_jjdguard_output_item_id,omitempty"`
	ProtocolIdentityRejected bool         `json:"_jjdguard_protocol_identity_rejected,omitempty"`
	// ProviderExecuted：由模型服务方执行的工具（Responses mcp_call 等、Messages server_tool_use、mcp_tool_use），
	// 参数会离开本机，送检时 tool_may_egress 一律 true。只在网关内部用：不进对外 JSON（上游回包里的同名键
	// 照 2.9.20 当未知键丢掉），送检视图经 JSON 往返时由 withProviderExecutedToolCalls 按位置带过去。
	ProviderExecuted bool `json:"-"`
}

type ToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Usage struct {
	PromptTokens             int                      `json:"prompt_tokens"`
	CompletionTokens         int                      `json:"completion_tokens"`
	TotalTokens              int                      `json:"total_tokens"`
	CompletionTokensDetails  *CompletionTokensDetails `json:"completion_tokens_details,omitempty"`
	PromptTokensDetails      *PromptTokensDetails     `json:"prompt_tokens_details,omitempty"`
	CacheReadInputTokens     int                      `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens int                      `json:"cache_creation_input_tokens,omitempty"`
	PromptCacheHitTokens     int                      `json:"prompt_cache_hit_tokens,omitempty"`
	PromptCacheMissTokens    int                      `json:"prompt_cache_miss_tokens,omitempty"`
}

// CompletionTokensDetails 携带高推理(reasoning)token 细分, 用于正确还原高推理计费。
type CompletionTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

type PromptTokensDetails struct {
	CachedTokens             int `json:"cached_tokens,omitempty"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
}

// ChatCompletionsHandler handles chat completions with injectable dependencies
type ChatCompletionsHandler struct {
	cfg                    *config.Config
	modelResolver          ModelResolver
	rateLimiter            RateLimitChecker
	securityClient         SecurityChecker
	auditWriter            AuditWriter
	providerAdapterFactory ProviderAdapterFactory
	toolRiskClient         *ToolRiskClient
	proxyRateLimiter       ProxyRateLimiter
	governor               GovernorDecider // nil = disabled (ENV kill switch)
	quotaAdmission         QuotaAdmission
	db                     *pgxpool.Pool                 // for governor alert_inbox writes; may be nil
	modelSelector          *modelrouter.ModelSelector    // nil = routing disabled
	providerSelector       *modelrouter.ProviderSelector // nil = routing disabled
	policyCache            *modelrouter.PolicyCache      // nil = routing disabled
	modelRouteEngine       modelrouter.Engine            // nil = v2 model routing disabled
	legacyModelResolver    func(context.Context, *modelrouter.RequestEnvelope) *modelrouter.ModelDecision
	legacyProviderResolver func(context.Context, *modelrouter.RequestEnvelope, string) *modelrouter.ProviderDecision
	agentGuardBehavior     *agentguard.BehaviorWindow
	agentGuardToolTypes    *agentGuardToolTypeCache // W5 5.9
	agentGuardToolFailures *agentguard.ToolFailureWindow
	proxyKeyVerifier       ProxyKeyVerifier
	proxyUsageRecorder     ProxyUsageRecorder
	billingPreflight       BillingPreflight
	fingerprints           *scanfp.Store // P1-B 已检指纹缓存（模块 2a）；nil=禁用（默认零回归）
	responseCache          ResponseCache // 响应缓存（独立 redis-cache）；nil=禁用
	artifactStore          retentionstore.Store
	relayMetrics           *relay.Metrics
	capacityDedupeMu       sync.Mutex
	capacityIncomplete     *capacityIncompleteDedupe
}

func (h *ChatCompletionsHandler) SetRelayMetrics(metrics *relay.Metrics) {
	h.relayMetrics = metrics
}

// SetBillingPreflight injects the optional billing admission and settlement client.
func (h *ChatCompletionsHandler) SetBillingPreflight(client BillingPreflight) {
	h.billingPreflight = client
}

func (h *ChatCompletionsHandler) SetQuotaAdmission(admission QuotaAdmission) {
	h.quotaAdmission = admission
}

// NewChatCompletionsHandler creates a handler with injectable dependencies
func NewChatCompletionsHandler(
	cfg *config.Config,
	modelResolver ModelResolver,
	rateLimiter RateLimitChecker,
	securityClient SecurityChecker,
	auditWriter AuditWriter,
	providerAdapterFactory ProviderAdapterFactory,
	toolRiskClient *ToolRiskClient,
	proxyRateLimiter ProxyRateLimiter,
) *ChatCompletionsHandler {
	if providerAdapterFactory == nil {
		factory := &RealProviderAdapterFactory{}
		if cfg != nil {
			factory.StreamIdleTimeout = cfg.UpstreamStreamIdleTimeout
		}
		providerAdapterFactory = factory
	}
	return &ChatCompletionsHandler{
		cfg:                    cfg,
		modelResolver:          modelResolver,
		rateLimiter:            rateLimiter,
		securityClient:         securityClient,
		auditWriter:            auditWriter,
		providerAdapterFactory: providerAdapterFactory,
		toolRiskClient:         toolRiskClient,
		proxyRateLimiter:       proxyRateLimiter,
		agentGuardBehavior:     agentguard.NewBehaviorWindow(registrySeconds(protection.KeyBurst), defaultAgentGuardBehaviorThresholds),
		agentGuardToolTypes:    newAgentGuardToolTypeCache(),
		agentGuardToolFailures: agentguard.NewToolFailureWindow(registrySeconds(protection.KeyToolFailureLoop), protection.DefaultIntParam(protection.KeyToolFailureLoop, protection.ParamThreshold)),
	}
}

// upstreamStreamingEnabled 报告是否对上游走流式累积调用(Stage 2)。
// 默认 false(cfg 为 nil 或未配置时), 行为与改造前一致。
func (h *ChatCompletionsHandler) upstreamStreamingEnabled() bool {
	return h != nil && h.cfg != nil && h.cfg.UpstreamStreaming
}

func (h *ChatCompletionsHandler) securityAuditOnly(ctx context.Context) bool {
	fallback := false
	if h != nil && h.cfg != nil {
		fallback = h.cfg.SecurityAuditOnly
	}
	if h != nil && h.toolRiskClient != nil {
		return h.toolRiskClient.SecurityAuditOnly(ctx, fallback)
	}
	return fallback
}

// exitMode is the execution mode every input-side exit passes to
// securityexit.Decide.
func (h *ChatCompletionsHandler) exitMode(ctx context.Context) securityexit.Mode {
	return securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx))
}

// outputExitMode is the execution mode for output-side exits; the
// stream_audit output posture records like record mode.
func (h *ChatCompletionsHandler) outputExitMode(ctx context.Context) securityexit.Mode {
	return securityexit.ModeFromAuditOnly(h.outputSecurityAuditOnly(ctx))
}

// fileContentDLPEnabled 解析当前生效的文件内容 DLP 全局动态开关（动态缓存值优先，
// 控制平面不可用时回落启动环境后备 SECURITY_FILE_CONTENT_DLP_ENABLED，默认关闭）。
func (h *ChatCompletionsHandler) fileContentDLPEnabled(ctx context.Context) bool {
	fallback := fileContentDLPEnvFallback()
	if h != nil && h.toolRiskClient != nil {
		return h.toolRiskClient.FileContentDLPEnabled(ctx, fallback)
	}
	return fallback
}

// normalizeGuardrailFailureMode 归一化护栏失败模式：close/closed -> "close"，其余 -> "open"。
func normalizeGuardrailFailureMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "close", "closed", "fail-close", "fail_close":
		return "close"
	default:
		return "open"
	}
}

// isSecurityScanTimeout 判断安全检测失败是否为「超时」而非「引擎不可达」。
//
// 超时意味着引擎收到了请求并在执行检测，只是未在预算内返回；不可达（连接
// 被拒、鉴权失败、5xx）意味着内容从未被检测。两者的安全含义不同：前者可按
// 配置的护栏失败模式决策，后者对带附件的请求必须固定 fail-closed。
func isSecurityScanTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// resolvedGuardrailFailureMode reports the detection-failure posture for logs.
// It is "open" (a failed, timed-out, or incomplete inspection is recorded and
// the request is forwarded) unless the explicit, signed console option
// guardrail_fail_closed_enabled is on AND the execution mode is protect; then
// it is "close". GUARDRAIL_FAILURE_MODE and the legacy guardrail_failure_mode
// setting stay ignored. The exits themselves decide through
// securityexit.DecideWithPolicy with guardrailPolicy, never on this string.
func resolvedGuardrailFailureMode(ctx context.Context, cfg *config.Config, client *ToolRiskClient) string {
	auditOnly := cfg != nil && cfg.SecurityAuditOnly
	if client != nil {
		auditOnly = client.SecurityAuditOnly(ctx, auditOnly)
	}
	if securityexit.DecideWithPolicy(securityexit.ModeFromAuditOnly(auditOnly), "block", securityexit.DetectionFailure, guardrailPolicy(ctx, client)).Enforce {
		return "close"
	}
	return "open"
}

// guardrailFailureMode 解析当前生效的护栏失败模式（见 resolvedGuardrailFailureMode）。
func (h *ChatCompletionsHandler) guardrailFailureMode(ctx context.Context) string {
	if h == nil {
		return "open"
	}
	return resolvedGuardrailFailureMode(ctx, h.cfg, h.toolRiskClient)
}

// Handler returns the HTTP handler function
func (h *ChatCompletionsHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		authInfo := auth.GetAuthInfo(r)
		startedAt := time.Now()
		ctx := withInputDetectionVersionSlot(withBlockLedger(r.Context()))

		bodyLimit := apiRequestBodyLimitBytes(h.cfg)
		parsed, err := readChatCompletionRequest(r, bodyLimit)
		if err != nil {
			message := "invalid JSON format"
			errorCode := "invalid_request"
			statusCode := http.StatusBadRequest
			var parseErr *chatRequestParseError
			if errors.As(err, &parseErr) {
				switch parseErr.failure {
				case chatRequestReadFailed:
					message = "failed to read request body"
				case chatRequestBodyTooLarge:
					message = "request body too large"
					errorCode = "request_too_large"
					statusCode = http.StatusRequestEntityTooLarge
					logRequestBodyTooLarge(r, requestID, bodyLimit)
				}
			}
			envelope := buildPartialEnvelope(requestID, authInfo, "", "chat")
			recordEarlyRequestFailure(ctx, h.auditWriter, envelope, w, errorCode, message, requestID, startedAt, statusCode)
			return
		}

		req := parsed.request
		body := parsed.raw

		result, err := h.processSharedRequestPath(ctx, w, r, requestID, authInfo, startedAt, &req, body)
		if err != nil {
			return
		}
		if result.Envelope.QuotaHeartbeatStop != nil {
			defer result.Envelope.QuotaHeartbeatStop()
		}

		if result.ConcurrencyAcquired {
			defer h.rateLimiter.ReleaseConcurrency(ctx, result.Envelope.ProjectID)
		}

		if result.SecurityReply != nil {
			h.writeSecurityReplyChat(ctx, w, result, req.Stream)
			return
		}

		if result.CacheHit != nil && result.CacheHit.entry != nil {
			h.writeCacheHitChat(ctx, w, result, req.Stream)
			return
		}

		if req.Stream {
			h.handleStreamingRequest(ctx, w, result, &req)
			return
		}

		streamingUpstream := h.upstreamStreamingEnabled()
		responseCaller := result.ProviderCaller
		fallbackUsed := false
		var respBody []byte
		if result.UseV2ModelRouting {
			routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{Engine: h.modelRouteEngine, CredentialResolver: h.modelResolver, Factory: h.providerAdapterFactory, Envelope: result.Envelope, SecuredBody: result.SecuredBody, Streaming: streamingUpstream})
			err = routeErr
			if routeResult != nil {
				responseCaller = routeResult.Caller
				respBody = routeResult.ResponseBody
				fallbackUsed = routeResult.UsedFallback
			}
		} else {
			respBody, err = callUpstream(ctx, result.ProviderCaller, result.Envelope, result.ProviderReq, streamingUpstream)
			if err != nil {
				fallbackResult := attemptFallbackCall(ctx, result.Envelope, result.SecuredBody, err, result.FallbackProvider, streamingUpstream)
				if fallbackResult.Attempted {
					recordFallbackEvent(ctx, h.auditWriter, result.Envelope, fallbackResult)
					if fallbackResult.Caller != nil {
						responseCaller = fallbackResult.Caller
					}
					respBody, err = fallbackResult.RespBody, fallbackResult.Err
					fallbackUsed = fallbackResult.Err == nil
				}
			}
		}
		if err != nil {
			h.finalizeChatProviderError(ctx, w, chatProviderErrorFinalizerInput{
				envelope:  result.Envelope,
				requestID: requestID,
				startedAt: startedAt,
				err:       err,
			})
			return
		}

		openaiResp, err := transformProviderResponse(responseCaller, result.Envelope, respBody)
		if err != nil {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_unavailable", "failed to parse provider response", requestID)
			return
		}

		upstreamResp := openaiResp // 扫描失败时 secureChatOutput 返回 nil，先留住上游响应供断开收尾解析 usage
		openaiResp, auditResult, err := h.secureChatOutput(ctx, result.Envelope, req.Messages, openaiResp)
		if err != nil {
			// 客户端在输出扫描期间已断开（Esc / 中断）：没有响应可放行也没有响应可拦截。
			// 上游响应已完整拿到，收尾带上它，让结算按真实 usage 走（与改前 success 路径口径一致）。
			// 正文只用于解析 usage 与审计元数据，不写给客户端，不写内容日志，不落库。
			if clientGoneDuring(ctx, err) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, upstreamResp, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponseWithStatus(w, "request_canceled", "request was canceled", requestID, http.StatusRequestTimeout)
				return
			}
			if rejectGuardrailDetectionUnavailable(ctx, w, h.auditWriter, result.Envelope, requestID, startedAt, auditResult, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient), err) {
				return
			}
			notice := h.blockNoticeForResponse(ctx, result.Envelope, "output", err.Error())
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "security_blocked", blockHTTPStatus(notice), int(time.Since(startedAt)/time.Millisecond), auditResult)
			h.writeChatBlockResponse(ctx, w, result.Envelope, requestID, false, notice)
			return
		}

		setSecurityActionHeader(w, strongerSecurityAction(result.InputSecurityAction, outputActionOf(auditResult)), securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		h.finalizeChatJSONSuccess(ctx, w, chatJSONSuccessFinalizerInput{
			cacheLookup:  result.CacheHit,
			envelope:     result.Envelope,
			respBody:     openaiResp,
			startedAt:    startedAt,
			auditResult:  auditResult,
			fallbackUsed: fallbackUsed,
		})
	}
}

// ProcessedRequestResult holds the result of shared request processing
type ProcessedRequestResult struct {
	Envelope            *modelrouter.RequestEnvelope
	ModelRecord         *modelrouter.ModelRecord
	ProviderCaller      ProviderCaller
	ProviderReq         []byte
	SecuredBody         []byte
	FallbackProvider    *FallbackProviderPlan
	SecurityReply       *SecurityReplyResult
	StartedAt           time.Time
	ConcurrencyAcquired bool
	// InputSecurityAction 是输入侧实际执行的最强动作（mask/audit，空=未命中），
	// 成功路径与输出侧动作合成 X-Security-Action 头；纯陈述性、不参与任何决策。
	InputSecurityAction string
	// UseV2ModelRouting defers adapter creation and upstream execution until
	// after input security has approved the final logical model.
	UseV2ModelRouting bool
	// ResponsesNative comes only from the model route capability flag.
	ResponsesNative bool
	// PreparedModelRoutePlan freezes the V2 route snapshot selected after input
	// security so native capability checks and execution use the same plan.
	PreparedModelRoutePlan *modelrouter.RoutePlan
	// CacheHit 非 nil 时：entry 有值表示命中，直接回缓存答案；entry 为空表示未命中，成功收尾时写入。
	CacheHit *responseCacheLookup
}

type SecurityReplyResult struct {
	Content      string
	Findings     []SecurityFinding
	MessageIndex int
	// Notice is set when the reply delivers a block notice ("message" mode):
	// the request is logged as security_blocked, not security_replied.
	Notice *securityBlockNotice
}

// securityReplyHeaderAction is the X-Security-Action value for a reply.
func securityReplyHeaderAction(reply *SecurityReplyResult) string {
	if reply != nil && reply.Notice != nil {
		return "block"
	}
	return "reply"
}

// setSecurityReplyHeaders marks a reply response, including the block number
// when the reply is a block notice.
func setSecurityReplyHeaders(w http.ResponseWriter, reply *SecurityReplyResult, enabled bool) {
	setSecurityActionHeader(w, securityReplyHeaderAction(reply), enabled)
	if reply != nil && reply.Notice != nil {
		setBlockNoticeHeaders(w, *reply.Notice)
	}
}

type securityReplyError struct {
	content      string
	findings     []SecurityFinding
	messageIndex int
}

func (e *securityReplyError) Error() string {
	return fmt.Sprintf("security reply for input message %d", e.messageIndex)
}

// processSharedRequestPath handles shared logic
func (h *ChatCompletionsHandler) processSharedRequestPath(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	authInfo *auth.AuthInfo,
	startedAt time.Time,
	req *ChatCompletionRequest,
	body []byte,
) (*ProcessedRequestResult, error) {
	refineChatAgentAttribution(authInfo, req.Messages)
	// Create partial envelope immediately after auth success for session recording
	// This ensures session is recorded even if model resolution fails later
	partialEnvelope := &modelrouter.RequestEnvelope{
		BillingIngress:   billingIngressFromContext(ctx),
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
		EndpointType:     requestEndpointType(req),
		SourceIP:         authInfo.ClientIP,
	}

	// Upsert session immediately after auth success - do this BEFORE any model/provider checks
	// Contract: authenticated request with session header should always create/update session record
	if partialEnvelope.SessionID != "" {
		h.auditWriter.UpsertAgentSession(ctx, partialEnvelope)
	}

	var modelRecord *modelrouter.ModelRecord
	var err error
	resolveTenant := authInfo.TenantID
	if isProxyRequest(ctx) {
		resolveTenant = h.cfg.ProxyDefaultTenantID
	}
	modelRecord, err = h.modelResolver.ResolveModelWithDB(ctx, resolveTenant, req.Model)
	miss, isModelMiss := asModelNotFound(err)
	if err != nil && !isModelMiss && !auth.UserModelAllowed(ctx, req.Model) {
		// 解析本身出了基础设施故障：名单外的模型仍先按 403 拒绝（与原有顺序一致）。
		return nil, rejectModelDenied(ctx, w, h.auditWriter, partialEnvelope, req.Model, requestID, startedAt)
	}
	if err == nil {
		// 未加前缀的简写名补全成唯一的全名后，授权/计费/路由/上游转发都按全名处理。
		if full := applyModelAlias(partialEnvelope, modelRecord); full != "" {
			req.Model = full
		}
		if !auth.UserModelAllowed(ctx, req.Model) {
			return nil, rejectModelDenied(ctx, w, h.auditWriter, partialEnvelope, req.Model, requestID, startedAt)
		}
	}
	if err != nil {
		h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
		if isProxyRequest(ctx) {
			h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "unauthorized", http.StatusUnauthorized, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "unauthorized", "authentication required", requestID)
			return nil, fmt.Errorf("proxy_model_not_authorized")
		}
		if isModelMiss {
			rejectModelNotFound(ctx, w, h.auditWriter, partialEnvelope, miss, req.Model, requestID, startedAt)
			return nil, errModelNotFoundRejected
		}
		if auth.UserModelAccessEnforced(ctx) {
			partialEnvelope.RejectReason = "model_resolution_failed"
			h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(partialEnvelope), requestID)
			return nil, errModelRouteUnavailable
		}
		h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "model_not_configured", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "model_not_configured", "model "+req.Model+" is not configured", requestID)
		return nil, fmt.Errorf("model_not_configured")
	}

	preflightResult, err := h.runChatPolicyPreflight(chatPolicyPreflightInput{
		ctx:             ctx,
		w:               w,
		r:               r,
		requestID:       requestID,
		authInfo:        authInfo,
		startedAt:       startedAt,
		request:         req,
		modelRecord:     modelRecord,
		partialEnvelope: partialEnvelope,
	})
	if err != nil {
		return nil, err
	}
	concurrencyAcquired := preflightResult.concurrencyAcquired
	releaseConcurrencyOnError := func() {
		if concurrencyAcquired {
			h.rateLimiter.ReleaseConcurrency(ctx, authInfo.ProjectID)
		}
	}

	teamID, _ := h.modelResolver.GetProjectTeamID(ctx, authInfo.ProjectID)

	// R13: build request envelope with routing hints and prompt context.
	envelope := buildChatRuntimeEnvelope(chatRuntimeContextInput{
		requestID:   requestID,
		authInfo:    authInfo,
		request:     req,
		modelRecord: modelRecord,
		teamID:      teamID,
		routeHint:   r.Header.Get("X-UAG-Route"),
	})
	envelope.RequestStartedAt = startedAt
	envelope.BillingIngress = partialEnvelope.BillingIngress
	envelope.ClientModel = partialEnvelope.ClientModel
	envelope.ModelResolution = partialEnvelope.ModelResolution
	envelope.ResponsesCompatibility = req.EndpointType == "responses" && req.DeferProviderTransform
	envelope.ClientRetryID = clientRetryID(r.Header)
	// P1-D：A 路会话归组键（跨日稳定），写 security_events 时物化 conversation_key。
	envelope.ConversationKey = computeConversationKey(envelope, req)
	envelope.InspectionSessionKey = inspectionSessionKey(r.Header, envelope)
	h.auditWriter.EnsureRequestLog(ctx, envelope)

	routingEnabled := os.Getenv("UAG_ROUTING_DISABLED") != "true"
	originalModelRef := envelope.Model
	originalHasV2 := false
	if routingEnabled {
		var modeErr error
		originalHasV2, modeErr = selectModelRoutingMode(ctx, h.modelRouteEngine, envelope.TenantID, envelope.Model)
		if modeErr != nil {
			releaseConcurrencyOnError()
			envelope.RejectReason = "route_policy_lookup_failed"
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(envelope), requestID)
			return nil, errModelRouteUnavailable
		}
	}

	// Preserve the baseline path exactly when routing is disabled or the
	// original model has no v2 policy: adapter -> legacy model-layer -> governor.
	var providerAdapter ProviderCaller
	var fallbackProvider *FallbackProviderPlan
	var modelDec *modelrouter.ModelDecision
	if !routingEnabled || !originalHasV2 {
		var apiKey string
		if modelRecord.ProviderID != "" {
			apiKey, _ = h.modelResolver.GetProviderCredential(ctx, modelRecord.ProviderID)
		}
		if apiKey == "" {
			releaseConcurrencyOnError()
			if auth.UserModelAccessEnforced(ctx) {
				envelope.RejectReason = "no_provider_credential"
				h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(envelope), requestID)
				return nil, errModelRouteUnavailable
			}
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_not_configured", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "provider_not_configured", "provider credentials not configured", requestID)
			return nil, fmt.Errorf("provider_not_configured")
		}
		providerAdapter = h.providerAdapterFactory.CreateAdapter(modelRecord, apiKey)
		fallbackProvider = buildFallbackProviderPlan(ctx, h.modelResolver, h.providerAdapterFactory, modelRecord)
		if h.legacyModelResolver != nil {
			modelDec = h.legacyModelResolver(ctx, envelope)
		} else {
			modelDec = h.resolveModelLayer(ctx, envelope)
		}
	}

	// Governor hot-path decision: enforce cost/quota/rate policy before calling provider.
	// Governor is nil when UAG_GOVERNOR_DISABLED=true (kill switch).
	if h.applyGovernorDecision(ctx, w, envelope, requestID) {
		releaseConcurrencyOnError()
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
	var governorOverride map[string]any
	if envelope.ModelID != modelRecord.ID {
		governorOverride = map[string]any{"original_model_id": modelRecord.ID}
	}

	// Re-evaluate only when the final logical model changed. Reusing the first
	// snapshot for an unchanged model avoids mixed legacy/v2 TOCTOU semantics.
	// A v2 -> non-v2 transition is closed rather than running legacy model-layer
	// late with a different governor input/order.
	useV2ModelRouting := false
	if routingEnabled {
		useV2ModelRouting = originalHasV2
		if envelope.Model != originalModelRef {
			var modeErr error
			useV2ModelRouting, modeErr = selectModelRoutingMode(ctx, h.modelRouteEngine, envelope.TenantID, envelope.Model)
			if modeErr != nil {
				releaseConcurrencyOnError()
				envelope.RejectReason = "route_policy_lookup_failed"
				h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
				writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(envelope), requestID)
				return nil, errModelRouteUnavailable
			}
		}
		if originalHasV2 && !useV2ModelRouting {
			releaseConcurrencyOnError()
			envelope.RejectReason = "route_policy_changed"
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "model_route_unavailable", routeUnavailableMessage(envelope), requestID)
			return nil, errModelRouteUnavailable
		}
	}

	// R13 ③/④: provider layer and RoutingDecision audit shape.
	if !useV2ModelRouting {
		var provDec *modelrouter.ProviderDecision
		if h.legacyProviderResolver != nil {
			provDec = h.legacyProviderResolver(ctx, envelope, modelRecord.ProviderID)
		} else {
			provDec = h.resolveProviderLayer(ctx, envelope, modelRecord.ProviderID)
		}
		routingResult := h.applyChatRoutingDecision(chatRoutingDecisionInput{
			ctx:              ctx,
			envelope:         envelope,
			modelRecord:      modelRecord,
			providerCaller:   providerAdapter,
			fallbackProvider: fallbackProvider,
			modelDecision:    modelDec,
			governorOverride: governorOverride,
			providerDecision: provDec,
		})
		providerAdapter = routingResult.providerCaller
		fallbackProvider = routingResult.fallbackProvider
	}
	if !useV2ModelRouting && providerAdapter == nil {
		releaseConcurrencyOnError()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "provider_unsupported", "configured provider type has no explicit adapter", requestID)
		return nil, provider.ErrProviderTypeUnsupported
	}
	if !useV2ModelRouting && envelope.EndpointType == "chat" && modelRecord.ProtocolCapabilities.Explicit && !modelRouteSupportsEndpoint(*modelRecord, "chat") {
		releaseConcurrencyOnError()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unsupported", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeErrorResponse(w, "provider_unsupported", "configured upstream route does not support Chat Completions", requestID)
		return nil, provider.ErrEndpointNotSupported
	}

	// Note: UpsertAgentSession was already called early in the process (before model resolution)
	// to ensure session is recorded even if model/provider checks fail.
	// The early call used a partial envelope; now we have the full envelope with model info,
	// but session upsert uses ON CONFLICT so no need to call again.

	inputSecurityStarted := time.Now()
	inputSecurity := h.applyChatInputSecurity(ctx, envelope, req)
	recordSecurityTiming(envelope, h.relayMetrics, "input_security_ms", time.Since(inputSecurityStarted))
	if inputSecurity.err != nil {
		if inputSecurity.auditStatus == "client_canceled" {
			// 客户端在输入扫描期间已断开（Esc / 中断）：没有响应可放行也没有响应可拦截，
			// 不写拦截通知、不记 security_blocked；request_logs 记 client_canceled/408。
			// 这一支决定的是响应形态：回 408 request_canceled，不回拦截通知、不带 X-Security-Action 头，
			// 也不进 message 模式的 SecurityReply。若删掉它，后面的通用拦截分支虽然收尾状态相同，
			// 响应会变成拦截通知（error 模式还会落到 500）；TestChatInputScanClientGoneResponseIsCancellationNotBlockNotice 钉住这一点。
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, inputSecurity.auditStatus, inputSecurity.httpStatus, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponseWithStatus(w, inputSecurity.errorCode, inputSecurity.message, requestID, inputSecurity.httpStatus)
			return nil, errors.New(inputSecurity.errorCode)
		}
		if inputSecurity.errorCode == guardrailDetectionUnavailableCode {
			// Fail-closed rejection: an availability answer, not a block notice.
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, inputSecurity.auditStatus, inputSecurity.httpStatus, int(time.Since(startedAt)/time.Millisecond), nil)
			writeGuardrailDetectionUnavailable(w, requestID, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
			return nil, errors.New(inputSecurity.errorCode)
		}
		notice := h.securityBlockNotice(ctx, envelope, "")
		if notice.Mode == blockResponseModeMessage {
			// The block reaches the agent as an ordinary assistant reply through
			// each protocol's reply writer; the request is still logged as blocked.
			return &ProcessedRequestResult{
				Envelope:            envelope,
				SecurityReply:       &SecurityReplyResult{Content: notice.Text, Notice: &notice},
				StartedAt:           startedAt,
				ConcurrencyAcquired: concurrencyAcquired,
				ResponsesNative:     legacyRouteSupportsNativeResponses(modelRecord, envelope),
			}, nil
		}
		releaseConcurrencyOnError()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, inputSecurity.auditStatus, inputSecurity.httpStatus, int(time.Since(startedAt)/time.Millisecond), nil)
		setSecurityActionHeader(w, "block", securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		setBlockNoticeHeaders(w, notice)
		writeErrorResponse(w, inputSecurity.errorCode, notice.Text, requestID)
		return nil, errors.New(inputSecurity.errorCode)
	}
	if inputSecurity.reply != nil {
		return &ProcessedRequestResult{
			Envelope:            envelope,
			SecurityReply:       inputSecurity.reply,
			StartedAt:           startedAt,
			ConcurrencyAcquired: concurrencyAcquired,
			ResponsesNative:     legacyRouteSupportsNativeResponses(modelRecord, envelope),
		}, nil
	}

	h.writeRequestContentLogs(ctx, envelope, req.Messages)

	var securedBody []byte
	if req.PreserveOriginalBody {
		securedBody = body
	} else if req.EndpointType == "" || strings.EqualFold(req.EndpointType, "chat") {
		securedBody, err = marshalChatProviderBody(body, req)
	} else {
		securedBody, err = json.Marshal(req)
		if err != nil {
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "invalid_request", "failed to serialize", requestID)
			return nil, fmt.Errorf("invalid_request")
		}
	}
	if envelope.EndpointType == "responses" {
		// float64+omitempty must not erase an explicitly requested temperature:0.
		var original, normalized map[string]json.RawMessage
		if json.Unmarshal(body, &original) == nil && original["temperature"] != nil && json.Unmarshal(securedBody, &normalized) == nil {
			normalized["temperature"], _ = json.Marshal(req.Temperature)
			securedBody, err = json.Marshal(normalized)
			if err != nil {
				return nil, err
			}
		}
	}
	cacheLookup := h.lookupResponseCache(ctx, r, envelope, req, body, securedBody)
	if cacheLookup != nil && cacheLookup.entry != nil {
		return &ProcessedRequestResult{
			Envelope:            envelope,
			ModelRecord:         modelRecord,
			StartedAt:           startedAt,
			ConcurrencyAcquired: concurrencyAcquired,
			CacheHit:            cacheLookup,
		}, nil
	}
	if !useV2ModelRouting {
		legacyRoute := *modelRecord
		legacyRoute.ProviderID = envelope.ProviderID
		legacyRoute.ProviderType = envelope.Provider
		requestFeatures := modelRouteRequestFeatures(envelope, securedBody, req.Stream)
		upstreamProtocol, capabilityDecision := selectModelRouteProtocol(
			legacyRoute,
			requestFeatures,
		)
		if !capabilityDecision.Eligible {
			releaseConcurrencyOnError()
			envelope.RejectReason = featureContractRejectReason(capabilityDecision.Reasons)
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusUnprocessableEntity, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponseWithStatus(w, "model_route_unavailable", featureContractMessage(capabilityDecision.Reasons), requestID, http.StatusUnprocessableEntity)
			return nil, errModelRouteUnavailable
		}
		envelope.UpstreamProtocol = upstreamProtocol
		providerAdapter = adaptProviderIngress(providerAdapter, envelope)
		if envelope.RoutingDecision != nil {
			envelope.RoutingDecision.IngressProtocol = envelope.EndpointType
			envelope.RoutingDecision.UpstreamProtocol = upstreamProtocol
			envelope.RoutingDecision.RequestFeatures = relay.FeatureNames(requestFeatures)
		}
	}

	// For non-streaming: Transform request here. For streaming: defer to handleStreamingRequest
	// which needs to transform the non-stream version for server-side buffering strategy
	var providerReq []byte
	if !req.Stream && !useV2ModelRouting && !req.DeferProviderTransform {
		// Transform request for provider-specific format (e.g., Anthropic needs different structure)
		providerReq, err = providerAdapter.TransformRequest(envelope, securedBody)
		if err != nil {
			releaseConcurrencyOnError()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
			writeErrorResponse(w, "invalid_request", "failed to transform request for provider", requestID)
			return nil, fmt.Errorf("invalid_request")
		}
	}

	if h.billingPreflight != nil {
		if billingErr := h.billingPreflight.Reserve(ctx, envelope, req); billingErr != nil {
			releaseConcurrencyOnError()
			statusCode, code, message := billingAdmissionResponse(billingErr)
			markBudgetOutcome(envelope, billingAdmissionOutcome(billingErr))
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, code, statusCode, int(time.Since(startedAt)/time.Millisecond), nil)
			setBillingAdmissionRetryAfter(w, billingErr)
			writeErrorResponseWithStatus(w, code, message, requestID, statusCode)
			return nil, billingErr
		}
		// 预算断流开启时把输出上限收紧到上游请求参数上；未下发上限时请求体不变。
		// 原生 Messages（PreserveOriginalBody）和原生 Responses 在各自入口收紧原始请求体。
		if limit, capped := billingOutputTokenCap(h.billingPreflight, envelope.RequestID); capped && !req.PreserveOriginalBody {
			cappedBody, changed, capErr := capChatRequestOutputTokens(req, securedBody, envelope.Provider, limit)
			if capErr == nil && changed {
				securedBody = cappedBody
				if len(providerReq) > 0 {
					if providerReq, err = providerAdapter.TransformRequest(envelope, securedBody); err != nil {
						releaseConcurrencyOnError()
						h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
						writeErrorResponse(w, "invalid_request", "failed to transform request for provider", requestID)
						return nil, fmt.Errorf("invalid_request")
					}
				}
			}
		}
	}
	if h.quotaAdmission != nil && !isProxyRequest(ctx) {
		if admissionErr := attachQuotaAdmission(ctx, h.quotaAdmission, envelope, estimatedChatAdmissionTokensScaled(req, chatAdmissionPromptPermille(envelope, modelRecord)), func(recordCtx context.Context, decision governor.Decision) {
			h.recordGovernorEvent(recordCtx, decision, envelope, quotaAdmissionEventType(decision))
		}); admissionErr != nil {
			releaseConcurrencyOnError()
			statusCode, auditStatus := quotaAdmissionHTTPStatus(admissionErr)
			markBudgetOutcome(envelope, quotaAdmissionBillingOutcome(admissionErr))
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, auditStatus, statusCode, int(time.Since(startedAt)/time.Millisecond), nil)
			writeQuotaAdmissionError(w, admissionErr, requestID)
			return nil, admissionErr
		}
	}

	return &ProcessedRequestResult{
		Envelope:            envelope,
		ModelRecord:         modelRecord,
		ProviderCaller:      providerAdapter,
		ProviderReq:         providerReq,
		SecuredBody:         securedBody,
		FallbackProvider:    fallbackProvider,
		StartedAt:           startedAt,
		ConcurrencyAcquired: concurrencyAcquired,
		InputSecurityAction: inputSecurity.observedAction,
		UseV2ModelRouting:   useV2ModelRouting,
		ResponsesNative:     legacyRouteSupportsNativeResponses(modelRecord, envelope),
		CacheHit:            cacheLookup,
	}, nil
}

func clientRetryID(header http.Header) string {
	raw := strings.TrimSpace(header.Get("Idempotency-Key"))
	if raw == "" {
		raw = strings.TrimSpace(header.Get("X-Client-Retry-ID"))
	}
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("jjdguard:client-retry:v1\x00" + raw))
	return fmt.Sprintf("retry_%x", sum[:16])
}

func legacyRouteSupportsNativeResponses(modelRecord *modelrouter.ModelRecord, envelope *modelrouter.RequestEnvelope) bool {
	if modelRecord == nil || envelope == nil || !modelRecord.ResponsesNative {
		return false
	}
	return envelope.Model == modelRecord.ModelName && envelope.ProviderID == modelRecord.ProviderID
}

// handleStreamingRequest handles streaming with server-side buffering
func (h *ChatCompletionsHandler) handleStreamingRequest(ctx context.Context, w http.ResponseWriter, result *ProcessedRequestResult, req *ChatCompletionRequest) {
	requestID := result.Envelope.RequestID
	envelope := result.Envelope
	startedAt := result.StartedAt

	// Stage 2: 给上游的调用从"非流式阻塞"换成"流式 SSE + 内部累积"以避开上游 ~300s 非流式上限,
	// 由 GATEWAY_UPSTREAM_STREAMING 控制(默认 false=老行为)。无论开关如何, 这里仍是 buffer-then-emit:
	// 累积/扫描期间不向 w 写任何字节, emit 在 secureChatOutput 之后(安全语义不变)。
	streamingUpstream := h.upstreamStreamingEnabled()

	// 构造发给上游的请求体。stream 字段在 CallStreaming 内部会被强制改写(forceStream),
	// 故这里 marshal 什么都行; 走老路径(Call)时则保持非流式(Stream=false)。
	upstreamReq := *req
	upstreamReq.Stream = false
	upstreamReqBody, err := marshalChatProviderBody(result.SecuredBody, &upstreamReq)
	if err != nil {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
		writeSSEError(w, requestID, "invalid_request", "failed to serialize")
		return
	}

	// 先攒后发期间的连接保活（GATEWAY_STREAM_KEEPALIVE_INTERVAL，默认 15s，0 关闭）。
	// keepaliveCommitted=true 表示 200 + SSE 头已发出，之后的错误/拦截只能走 SSE 帧。
	keepaliveRequestID := requestID
	keepaliveAction := result.InputSecurityAction
	keepaliveActionHeader := securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient)
	var keepalive *streamKeepalive
	keepaliveCommitted := false
	startKeepalive := func() {
		if keepalive != nil {
			return
		}
		keepalive = startStreamKeepalive(w, h.streamKeepaliveInterval(), keepaliveCommitted, func() {
			if keepaliveRequestID != "" {
				w.Header().Set("X-Request-ID", keepaliveRequestID)
			}
			setSecurityActionHeader(w, keepaliveAction, keepaliveActionHeader)
		})
	}
	stopKeepalive := func() bool {
		if keepalive != nil {
			if keepalive.Finish() {
				keepaliveCommitted = true
			}
			keepalive = nil
		}
		return keepaliveCommitted
	}
	defer stopKeepalive()
	// 实时流尝试前停掉保活；头已由保活发出时不再尝试实时流，本次改走先攒后发。
	tryLive := func(streamCtx context.Context, caller ProviderCaller, streamEnvelope *modelrouter.RequestEnvelope, providerReq []byte, tracker *relay.CommitTracker) (bool, error) {
		if stopKeepalive() {
			startKeepalive()
			return false, nil
		}
		attempted, liveErr := h.tryLiveChatStream(streamCtx, w, streamEnvelope, caller, providerReq, startedAt, result.InputSecurityAction, tracker, req.Messages)
		if !attempted {
			startKeepalive()
		}
		return attempted, liveErr
	}
	if !streamingUpstream {
		startKeepalive()
	}

	responseCaller := result.ProviderCaller
	fallbackUsed := false
	var respBody []byte
	if result.UseV2ModelRouting {
		commitTracker := &relay.CommitTracker{}
		routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{
			Engine: h.modelRouteEngine, CredentialResolver: h.modelResolver, Factory: h.providerAdapterFactory,
			Envelope: envelope, SecuredBody: upstreamReqBody, Streaming: streamingUpstream,
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
			respBody = routeResult.ResponseBody
			fallbackUsed = routeResult.UsedFallback
		}
		if err != nil && (!commitTracker.CanRetry() || isLiveStreamTerminalError(err)) {
			return
		}
	} else {
		// Transform request for provider-specific format (important for Anthropic, etc.)
		providerReq, transformErr := result.ProviderCaller.TransformRequest(envelope, upstreamReqBody)
		if transformErr != nil {
			stopKeepalive()
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
			writeSSEError(w, requestID, "invalid_request", "failed to transform request")
			return
		}
		commitTracker := &relay.CommitTracker{}
		liveAttempted, liveErr := tryLive(ctx, result.ProviderCaller, envelope, providerReq, commitTracker)
		if liveAttempted {
			if liveErr == nil {
				return
			}
			if !commitTracker.CanRetry() || isLiveStreamTerminalError(liveErr) {
				return
			}
			err = liveErr
		} else {
			respBody, err = callUpstream(ctx, result.ProviderCaller, envelope, providerReq, streamingUpstream)
		}
		if err != nil {
			startKeepalive()
			fallbackResult := attemptFallbackCall(ctx, envelope, upstreamReqBody, err, result.FallbackProvider, streamingUpstream)
			if fallbackResult.Attempted {
				recordFallbackEvent(ctx, h.auditWriter, envelope, fallbackResult)
				if fallbackResult.Caller != nil {
					responseCaller = fallbackResult.Caller
				}
				respBody, err = fallbackResult.RespBody, fallbackResult.Err
				fallbackUsed = fallbackResult.Err == nil
			}
		}
	}
	if err != nil {
		headersCommitted := stopKeepalive()
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
			writeSSEError(w, requestID, "request_canceled", "request was canceled")
			return
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_timeout", http.StatusGatewayTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
			writeSSEError(w, requestID, "provider_timeout", "upstream provider timed out")
			return
		}
		if errors.Is(err, errUserModelForbidden) {
			envelope.RejectReason = modelDenialRejectReason(ctx, envelope.Model)
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
			writeSSEError(w, requestID, "forbidden_model", modelDeniedMessage(ctx, envelope.Model))
			return
		}
		if errors.Is(err, errModelRouteUnavailable) {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeSSEError(w, requestID, "model_route_unavailable", routeUnavailableMessage(envelope))
			return
		}
		// Check if this is an upstream HTTP error (4xx/5xx from provider)
		// Since this is "buffer-then-emit" streaming, we haven't started SSE output yet
		// Return standard JSON error response for consistency with non-stream path
		if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(startedAt)/time.Millisecond), nil)
			if headersCommitted {
				writeCommittedStreamError(w, committedUpstreamErrorDetail(upstreamErr, requestID, "upstream_response"))
				return
			}
			writeUpstreamErrorResponse(w, upstreamErr, requestID, "upstream_response")
			return
		}

		// Other errors (network, timeout, etc.)
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
		writeSSEError(w, requestID, "provider_unavailable", "upstream provider is unavailable")
		return
	}

	openaiResp, err := transformProviderResponse(responseCaller, envelope, respBody)
	if err != nil {
		stopKeepalive()
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
		writeSSEError(w, requestID, "provider_unavailable", "failed to parse response")
		return
	}

	// 输出扫描（安全引擎 + 语义裁判）可能比生成还久，保活一直跑到扫描结束；扫描链路不写 w。
	securedResp, auditResult, err := h.secureChatOutput(ctx, envelope, req.Messages, openaiResp)
	headersCommitted := stopKeepalive()
	if err != nil {
		// 客户端在输出扫描期间已断开（Esc / 中断）：不写拦截帧，不记 security_blocked，
		// request_logs 记 client_canceled/408。上游响应已完整拿到，收尾带上它，让结算按真实 usage 走
		// （正文只用于解析 usage，不写给客户端，不写内容日志，不落库）。
		// 下面的 writeSSEError 只是为了与同函数里既有的 client_canceled 分支（上游调用失败那一支）
		// 写法保持一致；客户端已经断开，这次写入很可能失败，失败可忽略，不影响收尾状态。
		if clientGoneDuring(ctx, err) {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, openaiResp, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
			writeSSEError(w, requestID, "request_canceled", "request was canceled")
			return
		}
		// buffer-then-emit: nothing was written yet, so a fail-closed
		// rejection is still a plain 503.
		if headersCommitted && isGuardrailDetectionUnavailable(err) {
			h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "security_blocked", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), auditResult)
			writeCommittedStreamError(w, ErrorDetail{Code: guardrailDetectionUnavailableCode, Message: guardrailDetectionUnavailableMessage, RequestID: requestID})
			return
		}
		if rejectGuardrailDetectionUnavailable(ctx, w, h.auditWriter, envelope, requestID, startedAt, auditResult, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient), err) {
			return
		}
		if !blockRecorded(ctx) {
			h.auditWriter.WriteSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, nil, "stream_blocked", "streaming response blocked: "+err.Error())
		}
		notice := h.securityBlockNotice(ctx, envelope, "")
		h.auditWriter.FinalizeRequestLog(ctx, envelope, nil, "security_blocked", blockHTTPStatus(notice), int(time.Since(startedAt)/time.Millisecond), auditResult)
		if headersCommitted && notice.Mode == blockResponseModeMessage {
			writeCommittedChatMessageBlock(w, envelope.Model, requestID, notice, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
			return
		}
		if headersCommitted {
			// 保活已发头：error 模式改用实时流提交后的同一错误帧，block_id 只能随帧带出。
			for _, payload := range liveChatBlockPayloads(requestID, envelope.Model, notice) {
				writeSSEData(w, string(payload))
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
		// buffer-then-emit：此时尚未写任何字节，header 仍可设
		h.writeChatBlockResponse(ctx, w, envelope, requestID, true, notice)
		return
	}

	h.writeResponseContentLogs(ctx, envelope, securedResp)
	h.auditWriter.FinalizeRequestLog(ctx, envelope, securedResp, "success", http.StatusOK, int(time.Since(startedAt)/time.Millisecond), auditResult)
	h.recordPromptCacheMetrics(securedResp)
	h.recordProxyUsageIfNeeded(ctx, envelope, securedResp)
	h.storeResponseCache(result.CacheHit, envelope, securedResp, auditResult)

	securedResp = deliverResponseBody(ctx, h.toolRiskClient, envelope, securedResp)
	var resp ChatCompletionResponse
	if err := json.Unmarshal(securedResp, &resp); err != nil {
		writeSSEError(w, requestID, "internal_error", "failed to parse response")
		return
	}

	setRoutingHeaders(w, envelope, fallbackUsed)
	setSecurityActionHeader(w, strongerSecurityAction(result.InputSecurityAction, outputActionOf(auditResult)), securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeSSEError(w, requestID, "internal_error", "streaming not supported")
		return
	}

	_ = flusher
	var extra map[string]any
	if headersCommitted {
		// 保活已提前发头，X-Security-Action 只能反映输入阶段；把最终动作随末帧带出（OpenAI 兼容客户端忽略未知字段）。
		if action := strongerSecurityAction(result.InputSecurityAction, outputActionOf(auditResult)); action != "" && securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient) {
			extra = map[string]any{streamSecurityActionField: action}
		}
	}
	writeBufferedChatSSE(w, &resp, extra)
}

func (h *ChatCompletionsHandler) writeRequestContentLogs(ctx context.Context, envelope *modelrouter.RequestEnvelope, messages []Message) {
	anchoredWriter, supportsAnchors := h.auditWriter.(AnchoredContentLogWriter)
	batchWriter, supportsBatch := h.auditWriter.(BatchContentLogWriter)
	batch := make([]ContentLogEntry, 0, len(messages))
	for messageIndex, message := range messages {
		t := messageText(message.Content)
		if t == "" {
			continue
		}
		if isWorkBuddyAgent(envelope.AgentType) &&
			strings.EqualFold(strings.TrimSpace(message.Role), "user") {
			normalized, status, matched := aimsg.NormalizeAgentEnvelope(t)
			if matched {
				if status != aimsg.ParseComplete || strings.TrimSpace(normalized) == "" {
					continue
				}
				t = normalized
			}
		}
		if supportsBatch {
			batch = append(batch, ContentLogEntry{Role: message.Role, Content: t, MessageIndex: messageIndex})
		} else if supportsAnchors {
			anchoredWriter.WriteContentLogAnchored(ctx, envelope, message.Role, t, 0, messageIndex)
		} else {
			h.auditWriter.WriteContentLog(ctx, envelope, message.Role, t, 0)
		}
	}
	if supportsBatch && len(batch) > 0 {
		batchWriter.WriteContentLogsBatch(ctx, envelope, batch)
	}
	if writer, ok := h.auditWriter.(retentionTurnContextWriter); ok && envelope != nil {
		raw, _ := json.Marshal(map[string]interface{}{"messages": messages})
		if parsed, ok := aimsg.ParseOpenAIChatRequest(raw); ok {
			identity := strings.Join([]string{envelope.UserID, envelope.ClientID, envelope.SessionID, envelope.AgentType}, "\x00")
			if request := retentionturn.BuildRequest(parsed.Messages, raw, identity); request != nil {
				writer.WriteRetentionTurnContext(ctx, envelope, retentionturn.Patch(request, nil))
			}
		}
	}
	h.retainInputArtifacts(ctx, envelope, messages)
}

// SetRetentionArtifactStore enables durable image/file evidence for direct model APIs.
// The store is injected at startup and may be nil when artifact retention is disabled.
func (h *ChatCompletionsHandler) SetRetentionArtifactStore(store retentionstore.Store) {
	if h != nil {
		h.artifactStore = store
	}
}

func chatInputArtifactCandidates(messages []Message) []retentionartifact.Candidate {
	candidates := make([]retentionartifact.Candidate, 0)
	for _, message := range messages {
		if !strings.EqualFold(strings.TrimSpace(message.Role), "user") {
			continue
		}
		body, err := json.Marshal(struct {
			Messages []Message `json:"messages"`
		}{Messages: []Message{message}})
		if err != nil {
			continue
		}
		parsed, ok := aimsg.ParseOpenAIChatRequest(body)
		if !ok {
			continue
		}
		for _, candidate := range parsed.Artifacts {
			candidate.Ordinal = len(candidates)
			candidates = append(candidates, candidate)
		}
	}
	return retentionartifact.Deduplicate(candidates)
}

func (h *ChatCompletionsHandler) retainInputArtifacts(ctx context.Context, envelope *modelrouter.RequestEnvelope, messages []Message) {
	h.retainArtifacts(ctx, envelope, chatInputArtifactCandidates(messages))
}

func (h *ChatCompletionsHandler) retainArtifacts(ctx context.Context, envelope *modelrouter.RequestEnvelope, candidates []retentionartifact.Candidate) {
	if h == nil || h.db == nil || h.artifactStore == nil || envelope == nil || envelope.TenantID == "" || envelope.RequestID == "" || len(candidates) == 0 {
		return
	}
	recorder := &reverseProxyDBAuditRecorder{db: h.db, artifactStore: h.artifactStore}
	retentionUntil := time.Now().UTC().AddDate(0, 0, recorder.retentionDays(ctx))
	recorder.retainReverseProxyArtifacts(ctx, reverseProxyAuditRecord{
		TenantID:  envelope.TenantID,
		RequestID: envelope.RequestID,
		Provider:  "gateway_chat_completions",
		Product:   "gateway_chat_completions",
	}, candidates, retentionUntil)
}

func (h *ChatCompletionsHandler) writeResponseContentLogs(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte) {
	// 客户端断开不能让内容日志、保留上下文和制品留存丢失（收尾已写成功却没有内容日志）。
	logCtx, cancelLogs := detachAuditContext(ctx)
	defer cancelLogs()
	bindChatToolEvidenceFromResponse(envelope, respBody)
	var resp ChatCompletionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return
	}

	for i, choice := range resp.Choices {
		content := choice.Message.Content
		if content == "" {
			continue
		}

		tokens := 0
		if i == 0 {
			tokens = resp.Usage.CompletionTokens
		}

		h.auditWriter.WriteContentLog(logCtx, envelope, choice.Message.Role, content, tokens)
	}
	projection, projected := aimsg.ParseOpenAIChatResponse(respBody)
	// Tool-only responses have no visible content projection, but their call IDs
	// still connect the next physical request to this human submission.
	if writer, ok := h.auditWriter.(retentionTurnContextWriter); ok && envelope != nil {
		writer.WriteRetentionTurnContext(logCtx, envelope, retentionturn.Patch(nil, retentionturn.BuildResponse(respBody, projection.ModelOutput)))
	}
	if projected {
		h.retainResponseArtifacts(ctx, envelope, projection.Artifacts)
	}
}

// retainResponseArtifacts 留存响应制品，脱离请求取消。制品存储没有自带超时，
// 这里给一个比普通审计写入宽松的有界限时（auditArtifactTimeout）。
func (h *ChatCompletionsHandler) retainResponseArtifacts(ctx context.Context, envelope *modelrouter.RequestEnvelope, candidates []retentionartifact.Candidate) {
	artifactCtx, cancel := detachAuditContextFor(ctx, auditArtifactTimeout)
	defer cancel()
	h.retainArtifacts(artifactCtx, envelope, candidates)
}

func (h *ChatCompletionsHandler) buildSecurityReplyBody(envelope *modelrouter.RequestEnvelope, content string) []byte {
	resp := ChatCompletionResponse{
		ID:      "chatcmpl-" + envelope.RequestID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   envelope.Model,
		Choices: []Choice{
			{
				Index: 0,
				Message: ChoiceMessage{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: "stop",
			},
		},
		Usage: Usage{},
	}
	body, _ := json.Marshal(resp)
	return body
}

func (h *ChatCompletionsHandler) finalizeSecurityReply(ctx context.Context, result *ProcessedRequestResult) []byte {
	body := h.buildSecurityReplyBody(result.Envelope, result.SecurityReply.Content)
	auditResult := &AuditResult{
		InputFindings:  securityFindingsToAuditMaps(result.SecurityReply.Findings),
		InputAction:    "reply",
		OutputFindings: []map[string]interface{}{},
		OutputAction:   "allow",
	}
	status := "security_replied"
	if result.SecurityReply.Notice != nil {
		status = "security_blocked"
		auditResult.InputAction = "block"
		auditResult.ResponseMetadata = map[string]interface{}{
			"block_id":            result.SecurityReply.Notice.Attribution.BlockID,
			"block_response_mode": blockResponseModeMessage,
		}
	}
	// 内容留存只写不含命中原文片段的副本；返回给使用者的 body 仍是完整提示。
	// 有阻断提示就只写副本，副本为空串也不退回完整提示；没有提示的安全代答才写 Content。
	retained := result.SecurityReply.Content
	if result.SecurityReply.Notice != nil {
		retained = result.SecurityReply.Notice.RetainedText
	}
	h.auditWriter.WriteContentLog(ctx, result.Envelope, "assistant", retained, 0)
	h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, body, status, http.StatusOK, int(time.Since(result.StartedAt)/time.Millisecond), auditResult)
	return body
}

func (h *ChatCompletionsHandler) writeSecurityReplyChat(ctx context.Context, w http.ResponseWriter, result *ProcessedRequestResult, stream bool) {
	body := h.finalizeSecurityReply(ctx, result)
	setRoutingHeaders(w, result.Envelope, false)
	setSecurityReplyHeaders(w, result.SecurityReply, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))

	if !stream {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		writeGatewayJSONBody(w, body)
		return
	}

	var resp ChatCompletionResponse
	_ = json.Unmarshal(body, &resp)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	for _, choice := range resp.Choices {
		chunk := SSEChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []SSEChoice{
				{
					Index: choice.Index,
					Delta: SSEDelta{
						Role:    "assistant",
						Content: choice.Message.Content,
					},
					FinishReason: "stop",
				},
			},
		}
		chunkData, _ := json.Marshal(chunk)
		writeSSEData(w, string(chunkData))
	}
	writeSSEData(w, "[DONE]")

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func securityFindingsToAuditMaps(findings []SecurityFinding) []map[string]interface{} {
	return securityFindingsToSummary(findings)
}

// messageRoleToSource 把 OpenAI 消息 role 映射为引擎内容来源档位（content_source）。
// 契约第 4/5 条：system|developer→system_prompt / user→user / assistant→assistant_history /
// tool|function→tool_result；未知 role 返回空（引擎按全量检测处理）。
// developer 归 system_prompt 与 Plan C（aimsg.ParseOpenAIChatRequest 的 system/developer 分支）、
// Plan D（computeConversationKey 的 system/developer 分支）跨计划口径一致。
func messageRoleToSource(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "system", "developer":
		return "system_prompt"
	case "user":
		return "user"
	case "assistant":
		return "assistant_history"
	case "tool", "function":
		return "tool_result"
	default:
		return ""
	}
}

// applyInputSecurity 第一返回值是输入侧实际执行的最强非终止动作（mask/audit，供 X-Security-Action 陈述），
// block/reply 走 error 返回（错误路径的第一返回值无意义）。只观察、绝不改变任何动作决策。
func (h *ChatCompletionsHandler) applyInputSecurity(ctx context.Context, envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest) (string, error) {
	policy := h.inspectionPolicy(ctx)
	messages := inspectionMessagesWithTools(req, policy)
	defer func() { copy(req.Messages, messages[:len(req.Messages)]) }()
	plan := gatewayInputInspectionPlan(messages, policy)
	plan.agentRequestKind = agentRequestKindForMessages(envelope.AgentType, messages)
	ctx = context.WithValue(ctx, inputInspectionPlanKey{}, plan)
	requestBudget := 30 * time.Second
	if h.cfg != nil && h.cfg.InputSecurityRequestTimeout > 0 {
		requestBudget = h.cfg.InputSecurityRequestTimeout
	}
	inputSecurityCtx, cancelInputSecurity := context.WithTimeout(ctx, requestBudget)
	defer cancelInputSecurity()

	// 输入侧语义异步旁路：开启时同步检查跳语义（快层照跑、立即转发=零语义延迟），
	// 语义检测移到 fire-and-forget goroutine（命中只写 audit，observe-only、不漏每条）。
	// syncCtx 携带 skip-semantic 标记给同步 CheckInput；asyncOn 默认关=零回归。
	asyncOn := h.inputSemanticAsyncEnabled(ctx)
	syncCtx := inputSecurityCtx
	if asyncOn {
		syncCtx = withSkipSemantic(ctx)
		// 异步旁路：把本次请求被检查的各非空消息内容拼成一段，整段只派一个 goroutine 跑语义，
		// 一次覆盖全部输入（不漏），fan-out 从 per-message 降到 per-request（避免每条各起 goroutine）。
		// 与同步循环的派发门槛对齐：同步循环跳 Content=="" 的消息，拼接同样只纳入非空消息，
		// 拼接结果非空才派（消除纯空白消息的覆盖差）。
		// 旁路只能看到检测计划选中的消息：内置上下文/历史不在策略范围内时绝不进入语义裁判。
		h.dispatchAsyncInputSemantic(ctx, envelope, selectedInspectionText(messages, plan))
	}

	// triageFindings 聚合本次同步循环命中的规则 findings（仅在异步旁路 + FP 压制双开时收集），
	// 循环结束后一次性派发 /check-triage 标注（observe-only，绝不改主链/不阻塞）。
	var triageFindings []SecurityFinding
	inputCheckFailureRecorded := false

	// observed 只做陈述性记录，任何分支的动作/降级判断都不读它
	observed := ""

	// P1-B 指纹缓存（模块 2a，契约 9）：securityClient 具备 detailed/replay 能力且已注入
	// store 时启用。h.fingerprints==nil（开关关/未接线）→ fpActive=false，循环走与现状
	// 完全相同的路径（默认零回归）。
	detailed, canDetail := h.securityClient.(detailedInputChecker)
	replayer, canReplay := h.securityClient.(contextReplayer)
	fpActive := h.fingerprints != nil && canDetail && canReplay
	semanticTasks := semanticTasksForMessages(messages)
	batchResults := make(map[int]InputCheckBatchResult)
	// C2: only the gateway knows which history/tool segments were served from
	// the scanfp cache. Count checks and reuse hits here and pass them to the
	// engine as advisory /metrics headers; no detection decision reads them.
	fpChecks, fpHits := 0, 0
	if batcher, ok := h.securityClient.(detailedInputBatchChecker); ok {
		items := make([]InputCheckBatchItem, 0, len(req.Messages))
		indices := make([]int, 0, len(req.Messages))
		for i := range messages {
			message := &messages[i]
			target, selected := plan.targets[i]
			if !selected {
				continue
			}
			content := messageText(message.Content)
			attachments := extractAttachments(message.Content)
			if content == "" && len(attachments) == 0 {
				continue
			}
			itemCtx := withSemanticTaskContext(inputSecurityCtx, semanticTasks[i])
			if asyncOn {
				itemCtx = withSkipSemantic(itemCtx)
			}
			if len(attachments) > 0 {
				itemCtx = withAttachments(itemCtx, attachments)
			}
			source := target.source
			itemCtx = context.WithValue(itemCtx, inputInspectionTargetKey{}, target)
			actorType := classifyMessageActor(envelope.AgentType, message.Role, content)
			if actorType != "" {
				itemCtx = withMessageActor(itemCtx, actorType)
			}
			if fpActive && actorType == "" {
				fpChecks++
				sha := scanfp.SHA256Hex(content)
				scope := inspectionFingerprintScope(itemCtx, envelope, source, actorType)
				if _, hit := h.fingerprints.LookupScoped(inputSecurityCtx, envelope.TenantID, sha, scope); hit {
					fpHits++
					continue
				}
			}
			items = append(items, InputCheckBatchItem{
				Context: itemCtx, Content: content, MessageIndex: target.messageIndex,
				MessageRole: target.role, ContentSource: source,
			})
			indices = append(indices, i)
		}
		if len(items) > 1 {
			batchCtx := inputSecurityCtx
			if fpChecks > 0 {
				batchCtx = security.WithFingerprintStats(inputSecurityCtx,
					security.FingerprintStats{Checks: fpChecks, Hits: fpHits})
			}
			results, err := batcher.CheckInputBatchDetailed(batchCtx, envelope, items)
			if err != nil {
				for _, index := range indices {
					batchResults[index] = InputCheckBatchResult{Err: err}
				}
			} else if len(results) != len(items) {
				err = fmt.Errorf("security batch result count mismatch: got %d want %d", len(results), len(items))
				for _, index := range indices {
					batchResults[index] = InputCheckBatchResult{Err: err}
				}
			} else {
				for resultIndex, index := range indices {
					batchResults[index] = results[resultIndex]
				}
			}
		}
	}

	// 任务 7.3：Codex 附件清单（# Files … by the user:）按受限文件模式拦截。
	// 只对最新用户消息检查；命中按配置动作处理，block 走与 1502 同款 error 路径。
	if blocked, err := h.checkCodexMentionedFilesRestricted(ctx, envelope, messages); blocked || err != nil {
		return "", err
	}

	for i := range messages {
		message := &messages[i]
		target, selected := plan.targets[i]
		if !selected {
			continue
		}
		// 本条消息写出的脱敏/阻断事件带上网关位置，原文留证据此找到命中的那段（含序号为 -1 的内置上下文）。
		ctx := withRawEvidencePosition(ctx, i)
		t := messageText(message.Content)
		// 每条 message 重建 syncCtx（避免上一条附件残留）；asyncOn 时加 skip-semantic。
		syncCtx = withSemanticTaskContext(inputSecurityCtx, semanticTasks[i])
		if asyncOn {
			syncCtx = withSkipSemantic(syncCtx)
		}
		// 文件类型策略必须始终检查真实附件字节。正文 DLP 是否提取和扫描正文，
		// 由安全引擎加载的租户 file_policy.content_dlp_enabled 决定，不能在网关跳过附件。
		atts := extractAttachments(message.Content)
		if len(atts) > 0 {
			syncCtx = withAttachments(syncCtx, atts)
		}
		// 即使消息无文本，只要有附件也必须送检（纯附件消息不跳过）。
		if t == "" && len(atts) == 0 {
			continue
		}
		// P1-A：role→source 映射（content_source），检测与指纹重放共用同一档位值。
		source := target.source
		syncCtx = context.WithValue(syncCtx, inputInspectionTargetKey{}, target)
		actorType := classifyMessageActor(envelope.AgentType, message.Role, t)
		if actorType != "" {
			syncCtx = withMessageActor(syncCtx, actorType)
		}
		// actor_type 只是候选提示，不能进入跨上下文指纹缓存形成信任旁路。
		fpMessageActive := fpActive && actorType == ""
		fpContextScope := inspectionFingerprintScope(syncCtx, envelope, source, actorType)

		var (
			action        string
			maskedContent string
			findings      []SecurityFinding
			outcome       *InputCheckOutcome
			err           error
		)
		evCtx := ctx      // 事件写入 ctx：指纹重放命中时换成带标注的 ctx
		resolved := false // true = 本条结果已由缓存重放给出，不再调引擎
		sha := ""

		if fpMessageActive {
			sha = scanfp.SHA256Hex(t)
			entry, hit := h.fingerprints.LookupScoped(inputSecurityCtx, envelope.TenantID, sha, fpContextScope)
			if h.relayMetrics != nil {
				if hit {
					h.relayMetrics.Inc("scan_cache_hit")
				} else {
					h.relayMetrics.Inc("scan_cache_miss")
				}
			}
			if hit {
				if !entry.HasFindings() {
					// 契约 9：首见无 findings 的重复内容静默跳过
					//（现状无 findings 也不写事件，语义一致；证据不减量红线不涉及无发现流量）
					continue
				}
				// A cached finding is replayed like any other segment. An untrusted history
				// segment's scope already carries the task it was first judged under
				// (inspectionFingerprintScope), so a hit here is always the same task: it folds
				// into an occurrence of the first event instead of being re-judged and
				// re-audited on every agent turn. A different task misses and is judged once.
				replayAction, replayFindings, replayErr := replayer.ApplyContext(
					syncCtx, envelope, entry.RawFindings, source)
				if replayErr == nil && replayAction != "mask" {
					replayFindings = reanchorReplayedInputFindings(replayFindings, target.messageIndex, target.role)
					action, findings, resolved = replayAction, replayFindings, true
					replaySemanticStatus, _ := semanticStatusFromFindings(replayFindings)
					replayContextKey := fingerprintDetectionContextKey(
						envelope, replayAction, replayFindings, source, actorType, replaySemanticStatus)
					if entry.FirstSecurityEventID != "" &&
						entry.ContextKey != "" &&
						replayContextKey == entry.ContextKey {
						evCtx = withFingerprintOccurrence(
							ctx, entry.FirstSecurityEventID, entry.ContextKey)
					} else {
						// 上下文或处置变化：保守保留一条新的完整事件，绝不错误折叠。
						evCtx = withFingerprintReuse(ctx, entry.FirstRequestID)
					}
				}
				// replayErr != nil 或重放判 mask（无法产出 masked_content）→ 契约 9 回退全量检测
			}
		}

		if !resolved {
			if batched, ok := batchResults[i]; ok {
				outcome, err = batched.Outcome, batched.Err
				if err == nil && outcome == nil {
					err = errors.New("security batch returned no outcome")
				}
				if err == nil {
					action, maskedContent, findings = outcome.Action, outcome.MaskedContent, outcome.Findings
					evCtx = withSemanticStatus(evCtx, outcome.SemanticStatus, outcome.SemanticReason)
				}
			} else if canDetail {
				outcome, err = detailed.CheckInputDetailed(syncCtx, envelope, t, target.messageIndex, target.role, source)
				if err == nil && outcome != nil {
					action, maskedContent, findings = outcome.Action, outcome.MaskedContent, outcome.Findings
					evCtx = withSemanticStatus(evCtx, outcome.SemanticStatus, outcome.SemanticReason)
				}
			} else {
				// Pass message index and role for better observability
				// 多模态消息只把 text 块喂给安全引擎(图内文字仍被检测); 图片字节不入检查。
				action, maskedContent, findings, err = h.securityClient.CheckInput(syncCtx, envelope, t, target.messageIndex, target.role, source)
			}
			if err == nil && outcome != nil {
				recordInputDetectionVersions(ctx, outcome.RulePackVersion, outcome.EngineBuild, outcome.SemanticConfigRevision)
			}
			if err == nil && outcome != nil && fpMessageActive && outcome.SemanticStatus != "incomplete" && outcome.SemanticReason != "deferred" && outcome.RulePackVersion != "" && outcome.EngineBuild != "" {
				contextKey := fingerprintDetectionContextKey(
					envelope, action, findings, source, actorType, outcome.SemanticStatus)
				firstSecurityEventID := ""
				// 「仅记录」类观察与真实命中一样预分配首条事件 ID，后续重放折叠为 occurrence。
				if contextKey != "" && (shouldPersistSecurityEvent(action, findings) || hasRetainedObservations(findings)) {
					// 同一会话里同一条最新 user 消息、同一命中：并到本会话首条事件（见 latestUserSessionFoldScope）。
					if foldScope := latestUserSessionFoldScope(syncCtx, envelope, source, actorType); foldScope != "" {
						if first, hit := h.fingerprints.LookupScoped(inputSecurityCtx, envelope.TenantID, sha, foldScope); hit &&
							first.FirstSecurityEventID != "" && first.ContextKey == contextKey {
							firstSecurityEventID = first.FirstSecurityEventID
							evCtx = withFingerprintOccurrence(evCtx, firstSecurityEventID, contextKey)
						} else {
							firstSecurityEventID = newAuditID("evt_")
							evCtx = withSecurityEventID(evCtx, firstSecurityEventID)
							h.fingerprints.StoreResult(inputSecurityCtx, scanfp.Entry{
								TenantID:               envelope.TenantID,
								ContentSHA256:          sha,
								RulePackVersion:        outcome.RulePackVersion,
								EngineBuild:            outcome.EngineBuild,
								SemanticConfigRevision: outcome.SemanticConfigRevision,
								ContextScope:           foldScope,
								ContextKey:             contextKey,
								RawFindings:            outcome.RawFindings,
								FirstRequestID:         envelope.RequestID,
								FirstSecurityEventID:   firstSecurityEventID,
							})
						}
					} else {
						firstSecurityEventID = newAuditID("evt_")
						evCtx = withSecurityEventID(evCtx, firstSecurityEventID)
					}
				}
				h.fingerprints.StoreResult(inputSecurityCtx, scanfp.Entry{
					TenantID:               envelope.TenantID,
					ContentSHA256:          sha,
					RulePackVersion:        outcome.RulePackVersion,
					EngineBuild:            outcome.EngineBuild,
					SemanticConfigRevision: outcome.SemanticConfigRevision,
					ContextScope:           fpContextScope,
					ContextKey:             contextKey,
					RawFindings:            outcome.RawFindings,
					FirstRequestID:         envelope.RequestID,
					FirstSecurityEventID:   firstSecurityEventID,
				})
			}
		}

		if source == "tool_def" && action == "mask" {
			// A text result cannot safely rewrite a protocol tool schema. The
			// configured action is "mask", not "block": forward and alert.
			action = "audit"
			evCtx = withMaskUnavailable(evCtx)
		}
		if resolved {
			status, reason := semanticStatusFromFindings(findings)
			evCtx = withSemanticStatus(evCtx, status, reason)
		}

		if err != nil {
			// 客户端在输入扫描期间断开（Esc / 中断）：不是检测失败。不写 security_check_failed，
			// 不走 fail-closed（503），交给调用方既有的 client_canceled 分支收尾。
			// ctx 是原始请求 ctx；inputSecurityCtx / syncCtx 是带超时的派生 ctx，不能拿来判定。
			if clientGoneDuring(ctx, err) {
				return "", fmt.Errorf("%w: input message %d", errClientGoneDuringSecurity, i)
			}
			mode := h.guardrailFailureMode(ctx)
			failure := securityexit.DecideWithPolicy(h.exitMode(ctx), "block", securityexit.FailureCause(err), guardrailPolicy(ctx, h.toolRiskClient))
			// 检测异常（引擎不可达或超时，含带附件的请求）只记录不阻断：
			// 页面上没有任何策略把"检测失败"配置成阻断。
			if !inputCheckFailureRecorded {
				reason := "security_engine_unavailable"
				if isSecurityScanTimeout(err) {
					reason = "security_pipeline_timeout"
				}
				failureCtx := withSecurityEventStage(withSemanticStatus(ctx, "incomplete", reason), "input")
				effectiveAction := failure.Action
				failureCtx = context.WithValue(failureCtx, semanticEffectiveActionKey{}, effectiveAction)
				h.auditWriter.WriteSecurityEvent(failureCtx, envelope, nil, "security_check_failed", fmt.Sprintf("input security pipeline unavailable; first_failed_message=%d (failure_mode=%s, attachments=%d, timeout=%t)", i, mode, len(atts), isSecurityScanTimeout(err)))
				inputCheckFailureRecorded = true
			}
			// Explicit fail-closed option (protect mode only): reject with 503.
			if failure.Enforce {
				return "", fmt.Errorf("%w: input message %d", errGuardrailDetectionUnavailable, i)
			}
			// A failed inspection is a coverage gap in every mode (securityexit
			// DetectionFailure): recorded above, never an interruption.
			continue
		}
		if state, ok := semanticStatusFromContext(evCtx); ok && state.Status == "incomplete" {
			observed = strongerSecurityAction(observed, "audit")
			if h.auditWriter != nil {
				h.recordSemanticIncomplete(evCtx, envelope, "input", state.Reason, action, findings)
			}
			// An incomplete semantic stage must not erase a deterministic verdict;
			// the incompleteness itself is a coverage gap and never interrupts.
		}
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if h.toolRiskClient != nil && (role == "tool" || role == "function") && strings.TrimSpace(message.ToolCallID) != "" {
			if linkErr := h.toolRiskClient.LinkSkillResult(ctx, envelope, message.ToolCallID, skillResultFindingSummary(findings)); linkErr != nil && !errors.Is(linkErr, ErrSkillInvocationNotFound) {
				h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "skill_result_link_failed", "Skill result finding correlation failed")
			}
		}

		// Execution mode follows the console: record mode is the top priority, so an
		// explicit file-type deny is recorded below; protect mode enforces it.
		exitMode := h.exitMode(ctx)
		if len(atts) > 0 && explicitFileTypePolicyBlocks(findings) && securityexit.Decide(exitMode, "block", securityexit.ExplicitFileType).Enforce {
			h.writeSecurityEvent(evCtx, envelope, findings, "security_blocked", fmt.Sprintf("blocked file type in input message %d", i))
			return "", fmt.Errorf("file attachment blocked by explicit file type policy in message %d", i)
		}

		// Every detector action, including an explicit file-type deny and an
		// integration credential's DLP block posture, follows the global
		// audit-only posture (2.9.22 D6).
		if exitMode == securityexit.Record && (hasSecurityFindings(findings) || fileContentActionBlocksExternalSend(action)) {
			observed = strongerSecurityAction(observed, "audit")
			h.writeSecurityEvent(evCtx, envelope, findings, "security_audit_only",
				fmt.Sprintf("input message %d matched security action '%s'", i, action))
			// audit_only 只降级动作，不该断掉误报治理旁路：命中 findings 照常纳入 triage 候选
			// （与循环末尾 security_audit 路径同口径，过滤在 applyTriageSuppression 内做）。
			// 否则生产 SECURITY_AUDIT_ONLY=true 时 dispatchAsyncTriage 永不触发。
			// observe-only：只多一次异步标注，绝不改动作/不阻塞主链。
			triageFindings = append(triageFindings, findings...)
			continue
		}

		// Protect mode: the single blocking set (block/reply/deny/quarantine)
		// interrupts; reply answers on the gateway's behalf, the rest block.
		if securityexit.Decide(exitMode, action, securityexit.RuleHit).Enforce {
			if strings.EqualFold(strings.TrimSpace(action), "reply") {
				reply := maskedContent
				if reply == "" {
					reply = "请求已被安全策略拦截。"
				}
				h.writeSecurityEvent(evCtx, envelope, findings, "security_replied", fmt.Sprintf("replied to input message %d by security policy", i))
				return "", &securityReplyError{
					content:      reply,
					findings:     findings,
					messageIndex: i,
				}
			}
			if len(atts) > 0 {
				h.writeSecurityEvent(evCtx, envelope, findings, "security_blocked", fmt.Sprintf("blocked file attachment in input message %d", i))
				return "", fmt.Errorf("file attachment blocked by security policy in message %d", i)
			}
			h.writeSecurityEvent(evCtx, envelope, findings, "security_blocked", fmt.Sprintf("blocked input message %d", i))
			return "", fmt.Errorf("request blocked due to security findings in message %d", i)
		}

		masksText := action == "mask" && maskedContent != ""
		if len(atts) > 0 && fileContentActionBlocksExternalSend(action) && !masksText {
			// Only mask/redact reach here: blocking actions were decided above.
			// A binary attachment cannot be masked. The configured action is
			// "mask", not "block": forward the original file and alert.
			observed = strongerSecurityAction(observed, "audit")
			h.writeSecurityEvent(withMaskUnavailable(evCtx), envelope, findings, "security_audit", fmt.Sprintf("file attachment in input message %d could not be masked; forwarded unmasked", i))
			triageFindings = append(triageFindings, findings...)
			continue
		}

		if masksText {
			observed = strongerSecurityAction(observed, "mask")
			// 只改写 text 块，图片/文件块原样保留：附件无法脱敏不能拖累消息文本
			// 一起按原文放行（2.9.11 实测 N03/N10/N12/N13）。
			message.Content = maskMessageTextContent(message.Content, t, maskedContent)
			if outcome != nil {
				addRequestRedaction(ctx, envelope, maskedContent, outcome.RedactionMapping)
			}
			h.writeSecurityEvent(evCtx, envelope, findings, "security_masked", fmt.Sprintf("masked input message %d", i))
			if len(atts) > 0 && attachmentMaskUnavailable(findings) {
				h.writeSecurityEvent(withMaskUnavailable(evCtx), envelope, findings, "security_audit", fmt.Sprintf("file attachment in input message %d could not be masked; forwarded unmasked", i))
			}
		}

		if hasSecurityFindings(findings) {
			observed = strongerSecurityAction(observed, "audit")
			h.writeSecurityEvent(evCtx, envelope, findings, "security_audit", fmt.Sprintf("input findings in message %d", i))
			triageFindings = append(triageFindings, findings...)
		} else if hasRetainedObservations(findings) {
			// 只有「仅记录」类观察：留一条观察事件作证据，不拦截、不计为安全发现、不进误报复核。
			h.writeSecurityEvent(withRetainedObservationEvent(evCtx), envelope, findings, "security_audit",
				fmt.Sprintf("input observation in message %d (evidence only, not a security finding)", i))
		}
	}

	// 误报压制与已停用的语义异步旁路解耦：FP 开关开启时，把同步命中的
	// 规则 findings 整批交 /check-triage 标注后回写 security_event。
	if h.fpSuppressionEnabled() && len(triageFindings) > 0 {
		h.dispatchAsyncTriage(ctx, envelope, selectedInspectionText(messages, plan), triageFindings)
	}

	return observed, nil
}

// checkToolRisk records definitions and learns their classification. A definition
// is not a proposed invocation; configured denial is applied on the call path.
func (h *ChatCompletionsHandler) checkToolRisk(ctx context.Context, envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest) error {
	for _, tool := range req.Tools {
		if tool.Function.Name == "" {
			continue
		}

		definitionHash := toolDefinitionHash(tool)
		h.rememberAgentGuardToolDefinition(envelope, tool) // W5 5.9
		if inferToolTypeFromName(tool.Function.Name) == agentguard.ToolTypeSkill {
			if observeErr := h.toolRiskClient.ObserveSkillDefinition(ctx, envelope, tool); observeErr != nil {
				h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "skill_definition_observe_failed", "Skill definition observation could not be persisted")
			}
		}
		result, err := h.toolRiskClient.CheckToolRisk(ctx, envelope.TenantID, tool.Function.Name)
		if err != nil {
			// Fail-open on error: log but don't block
			h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "tool_risk_check_failed",
				fmt.Sprintf("tool '%s' risk check failed: %s", tool.Function.Name, err.Error()))
			continue
		}

		toolType := inferToolTypeFromName(tool.Function.Name)
		h.rememberAgentGuardToolConfig(envelope, tool.Function.Name, result.Config) // W5 5.9
		toolType = h.resolveAgentGuardToolType(envelope, tool.Function.Name)

		if h.toolRiskClient != nil {
			policyID, policyName, matchedAction, matchReason := toolPolicySnapshot(tool.Function.Name, result)
			_ = h.toolRiskClient.LogToolCall(ctx, envelope, ToolAuditLogPayload{
				ToolName:              tool.Function.Name,
				ToolType:              toolType,
				RiskLevel:             result.RiskLevel,
				Result:                "tool definition observed; invocation policy not evaluated",
				Status:                "observed",
				MatchedPolicyID:       policyID,
				MatchedPolicyName:     policyName,
				MatchedAction:         matchedAction,
				MatchReason:           "definition_only:" + matchReason,
				EventKind:             "definition_exposed",
				ExecutionObserved:     false,
				DefinitionHash:        definitionHash,
				AttributionMode:       "explicit",
				AttributionConfidence: 1,
			})
		}
	}

	return nil
}

func toolDefinitionHash(tool ToolDef) string {
	var parameters interface{}
	if len(tool.Function.Parameters) > 0 {
		if err := json.Unmarshal(tool.Function.Parameters, &parameters); err != nil {
			parameters = string(tool.Function.Parameters)
		}
	}
	canonical, _ := json.Marshal(struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		Parameters  interface{} `json:"parameters"`
	}{
		Name: tool.Function.Name, Description: tool.Function.Description, Parameters: parameters,
	})
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum)
}

// toolResultDropLog 给"客户端带回的工具结果上报被丢弃"限频记日志：首条必打，之后每 100 条一条。
var toolResultDropLog = ratelog.New(100)

func (h *ChatCompletionsHandler) logToolResultObservations(ctx context.Context, envelope *modelrouter.RequestEnvelope, messages []Message) {
	if h.toolRiskClient == nil || envelope == nil {
		return
	}
	for _, message := range messages {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if (role != "tool" && role != "function") || strings.TrimSpace(message.ToolCallID) == "" {
			continue
		}
		// 客户端每轮都重发整段历史里的工具结果；同一个 tool_call_id 只需上报一次。
		if !h.toolRiskClient.reportedToolResults.markIfNew(envelope.TenantID, message.ToolCallID) {
			continue
		}
		if err := h.toolRiskClient.LogToolCall(ctx, envelope, ToolAuditLogPayload{
			ToolName: "tool_result", ToolType: "tool_result", RiskLevel: "low",
			Result: "authenticated client supplied a tool result", Status: "observed",
			EventKind: "result_observed", ExecutionObserved: false, ResultObserved: true,
			ToolCallID: message.ToolCallID, AttributionMode: "explicit", AttributionConfidence: 1,
		}); err != nil && !errors.Is(err, errToolLogIDUnavailable) {
			switch {
			case errors.Is(err, errToolLogRejected):
				// 控制面确定性拒绝（事实违反约束）：重试不会成功，保留"已上报"标记 = 丢弃，不再重投。
				toolResultDropLog.Printf(envelope.TenantID+"|rejected",
					"component=tool_audit stage=tool_result_report event=tool_result_dropped reason=rejected_by_control_plane tenant=%s action=drop_no_retry", envelope.TenantID)
			case h.toolRiskClient.reportedToolResults.retryOrGiveUp(envelope.TenantID, message.ToolCallID, toolResultMaxReportAttempts):
				// 重试预算用尽：放弃，避免客户端每轮重放历史把永久失败放大成持续写入。
				toolResultDropLog.Printf(envelope.TenantID+"|gave_up",
					"component=tool_audit stage=tool_result_report event=tool_result_dropped reason=retry_budget_exhausted tenant=%s attempts=%d last_error=%v", envelope.TenantID, toolResultMaxReportAttempts, err)
			}
			// 其余情况 retryOrGiveUp 已撤销标记：下一轮请求重试，避免瞬时故障漏记。
		}
		if err := h.toolRiskClient.LinkSkillResult(ctx, envelope, message.ToolCallID, nil); err != nil && !errors.Is(err, ErrSkillInvocationNotFound) {
			h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "skill_result_link_failed", "Skill result correlation failed")
		}
	}
}

// recordToolResultFailures 只统计本轮的工具结果（末尾最后一段连续 assistant 块之后的 tool 消息）：
// 失败的计入失败循环滑窗（窗口和次数取防护项 agent.tool_failure_loop 的租户配置），计数达到或超过
// 阈值且本窗口内还没报告过时写一条 tool_failure_loop 运行观察事件（不计入安全命中）。
// 历史重放、客户端截断历史、网关重启都不会让旧失败被重复计数。
// 处置不在这里：下一次出向调用时 applyAgentGuardToolDecisionResult 把窗口内的失败次数交给
// AnalyzeToolCall（ToolFailureLoopCount），按该防护项配置的动作（默认告警放行）与例外判定。
func (h *ChatCompletionsHandler) recordToolResultFailures(ctx context.Context, envelope *modelrouter.RequestEnvelope, messages []Message) {
	if h.agentGuardToolFailures == nil || envelope == nil || len(messages) == 0 {
		return
	}
	failedTools := toolFailuresThisTurn(messages)
	if len(failedTools) == 0 {
		return
	}
	actorKey := agentGuardActorKey(envelope)
	if strings.TrimSpace(actorKey) == "" {
		return
	}
	var policy *agentguard.EffectivePolicy
	if h.toolRiskClient != nil {
		// 拉不到策略时按注册表默认的窗口和次数计数。
		policy, _ = h.toolRiskClient.GetAgentGuardPolicy(ctx, envelope)
	}
	window, threshold := toolFailureLoopParams(policy)
	for _, failed := range failedTools {
		toolName := failed.name
		// Target = 调用编号@本轮之前历史的指纹：客户端原样重发同一请求（429/5xx 自动重试）时键相同，
		// 由滑窗去重；下一轮历史变长、指纹不同，所以 Gemini 适配器跨轮合成的相同编号（call_0_0）
		// 不会被误当成重放而漏掉真正的重试。
		count, reached := h.agentGuardToolFailures.RecordFailureWithin(agentguard.ToolFailureEvent{
			ActorKey: actorKey, ToolName: toolName, Target: failed.target,
		}, window, threshold)
		if reached && h.auditWriter != nil {
			h.auditWriter.WriteSecurityEvent(withSecurityEventStage(withRetainedObservationEvent(ctx), "tool"), envelope,
				[]SecurityFinding{toolFailureLoopFinding(toolName, count)},
				agentguard.ToolFailureLoopReason,
				fmt.Sprintf("tool %q failed %d times within the failure-loop window", toolName, count))
		}
	}
}

// registrySeconds 是防护项 window_seconds 参数的注册表默认值（窗口类的缺省都从注册表取，不另写一份）。
func registrySeconds(key string) time.Duration {
	return time.Duration(protection.DefaultIntParam(key, protection.ParamWindowSeconds)) * time.Second
}

// toolFailureLoopParams 取租户为防护项 agent.tool_failure_loop 保存的窗口和次数；租户没有
// 保存该项时返回 0，由失败窗口用构造时的默认值（注册表默认）。
func toolFailureLoopParams(policy *agentguard.EffectivePolicy) (time.Duration, int) {
	const key = protection.KeyToolFailureLoop
	if policy == nil {
		return 0, 0
	}
	if _, saved := policy.Protections[key]; !saved {
		return 0, 0
	}
	return time.Duration(policy.Protections.IntParam(key, protection.ParamWindowSeconds)) * time.Second, policy.Protections.IntParam(key, protection.ParamThreshold)
}

func toolPolicySnapshot(toolName string, result *ToolCheckResult) (string, string, string, string) {
	if result == nil || result.Config == nil {
		return "", "默认工具审计策略", "audit", fmt.Sprintf("未配置专用策略，按默认策略记录：%s", toolName)
	}
	return result.Config.ID, fmt.Sprintf("%s 工具策略", result.Config.ToolName), result.Config.Action, fmt.Sprintf("工具名称精确匹配：%s", result.Config.ToolName)
}

const agentGuardPolicyVersion = "agentguard-v1"

func (h *ChatCompletionsHandler) applyOutputSecurityCore(ctx context.Context, envelope *modelrouter.RequestEnvelope, requestMessages []Message, respBody []byte) ([]byte, *AuditResult, error) {
	// 非流式及完整缓冲输出检查包含文本、工具和同步裁判的全部耗时。
	checkStarted := time.Now()
	defer func() { recordSecurityTiming(envelope, h.relayMetrics, "output_security_ms", time.Since(checkStarted)) }()
	contextFragments := buildAgentGuardContextFragments(requestMessages)
	auditResult := &AuditResult{
		OutputFindings: []map[string]interface{}{},
		OutputAction:   "allow",
	}

	// strict_buffered is the deployment's explicit "deliver only fully inspected
	// output" option (GATEWAY_OUTPUT_SECURITY_MODE). It is honoured in protect
	// mode only; record mode forwards and records the gap.
	if effectiveOutputSecurityMode(h.toolRiskClient, h.cfg) == relay.OutputSecurityStrictBuffered && h.outputExitMode(ctx) == securityexit.Protect {
		limit := effectiveOutputStrictMaxBytes(h.toolRiskClient, h.cfg)
		if limit <= 0 {
			limit = maxLiveOutputAuditBytes
		}
		if len(respBody) > limit {
			auditResult.OutputAction = "block"
			auditResult.ResponseMetadata = map[string]interface{}{"output_scan_incomplete": true, "output_scan_incomplete_reason": "strict_output_budget", "output_budget_bytes": limit}
			if h.auditWriter != nil {
				h.writeSecurityEvent(withSecurityEventStage(ctx, "output"), envelope, nil, "output_scan_incomplete", "strict output exceeded complete-response byte budget")
			}
			return nil, auditResult, fmt.Errorf("output_scan_incomplete: strict response exceeds %d-byte budget", limit)
		}
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, nil, err
	}
	structuredDecisions := make(map[string]agentguard.Decision)
	for i := range resp.Choices {
		choice := &resp.Choices[i]

		// 1. 检查文本与 reasoning 内容，避免思维链字段绕过输出护栏。
		content := choice.Message.Content
		if choice.Message.ReasoningContent != "" {
			if content != "" {
				content += "\n"
			}
			content += choice.Message.ReasoningContent
		}
		if h.securityClient != nil && content != "" {
			outputEventCtx := withSecurityEventStage(ctx, "output")
			action, maskedContent, findings, err := h.checkOutputWithStatus(withOutputProjection(ctx), envelope, content, i, auditResult)
			if err != nil {
				// 客户端在输出扫描期间断开（Esc / 中断）：没有响应可放行也没有响应可拦截，
				// 不是检测失败。不标 output_scan_incomplete、不写 check_failed 事件、不走 fail-closed，
				// 交给调用方既有的 client_canceled 分支收尾。ctx 是原始请求 ctx。
				if clientGoneDuring(ctx, err) {
					return nil, auditResult, fmt.Errorf("%w: output choice %d", errClientGoneDuringSecurity, i)
				}
				if auditResult.ResponseMetadata == nil {
					auditResult.ResponseMetadata = map[string]interface{}{}
				}
				auditResult.ResponseMetadata["output_scan_incomplete"] = true
				auditResult.ResponseMetadata["output_scan_incomplete_reason"] = "output_security_check_failed"
				mode := h.guardrailFailureMode(ctx)
				if h.auditWriter != nil {
					h.auditWriter.WriteSecurityEvent(outputEventCtx, envelope, nil, "security_output_check_failed", fmt.Sprintf("output choice %d: %s (failure_mode=%s)", i, err.Error(), mode))
				}
				// A failed inspection is a coverage gap unless the explicit
				// fail-closed option applies (protect mode only).
				failure := securityexit.DecideWithPolicy(h.exitMode(ctx), "block", securityexit.FailureCause(err), guardrailPolicy(ctx, h.toolRiskClient))
				auditResult.OutputAction = failure.Action
				if failure.Enforce {
					return nil, auditResult, fmt.Errorf("%w: output choice %d", errGuardrailDetectionUnavailable, i)
				}
				// A text checker failure must not skip this choice's tool DLP/AgentGuard.
				action, maskedContent, findings = "", "", nil
			}
			for _, item := range securityFindingsToAuditMaps(findings) {
				item["choice_index"] = i
				auditResult.OutputFindings = append(auditResult.OutputFindings, item)
			}

			outputMode := h.outputExitMode(ctx)
			if outputMode == securityexit.Record && (hasSecurityFindings(findings) || securityexit.Blocks(action) || action == "mask") {
				auditResult.OutputAction = "audit"
				h.auditWriter.WriteSecurityEvent(outputEventCtx, envelope, findings, "security_audit_only",
					fmt.Sprintf("output choice %d matched security action '%s'", i, action))
				// Keep processing tool calls in audit mode as well.
				action = ""
			}

			if securityexit.Decide(outputMode, action, securityexit.RuleHit).Enforce {
				auditResult.OutputAction = "block"
				h.auditWriter.WriteSecurityEvent(outputEventCtx, envelope, findings, "security_blocked", fmt.Sprintf("blocked output choice %d", i))
				return nil, auditResult, outputTextBlockedError{choice: i}
			}

			if action == "mask" && maskedContent != "" {
				auditResult.OutputAction = "mask"
				masked := true
				switch {
				case choice.Message.Content != "" && choice.Message.ReasoningContent == "":
					choice.Message.Content = maskedContent
				case choice.Message.Content == "" && choice.Message.ReasoningContent != "":
					choice.Message.ReasoningContent = maskedContent
				case outputMode == securityexit.Record:
					// Audit mode keeps the raw response and records the
					// provider's raw decision without claiming masking.
					auditResult.OutputAction = "audit"
				default:
					// One masked string cannot be split back over content and
					// reasoning. The configured action is "mask", not "block":
					// forward the original and raise an alert.
					masked = false
					auditResult.OutputAction = "audit"
					h.auditWriter.WriteSecurityEvent(withMaskUnavailable(outputEventCtx), envelope, findings, "security_audit", fmt.Sprintf("output choice %d could not be safely redacted; forwarded unmasked", i))
				}
				if masked {
					h.auditWriter.WriteSecurityEvent(outputEventCtx, envelope, findings, "security_masked", fmt.Sprintf("masked output choice %d", i))
				}
			}

			if hasSecurityFindings(findings) {
				h.auditWriter.WriteSecurityEvent(outputEventCtx, envelope, findings, "security_audit", fmt.Sprintf("output findings in choice %d", i))
			}
		}

		// 2. 检查结构化 tool_calls（动态检测）
		if len(choice.Message.ToolCalls) > 0 {
			conflictingIDs := conflictingChatToolCallIDs(choice.Message.ToolCalls)
			allowed := make([]ToolCall, 0, len(choice.Message.ToolCalls))
			var blocked []agentguard.Decision
			for toolCallIndex, tc := range choice.Message.ToolCalls {
				if providerExecutedToolCallAt(ctx, i, toolCallIndex) {
					tc.ProviderExecuted = true
				}
				var toolErr error
				tc, toolErr = h.secureOutputToolArguments(ctx, envelope, tc, i, auditResult)
				if toolErr != nil {
					return nil, auditResult, toolErr
				}
				decisionCall := tc
				if _, conflicted := conflictingIDs[chatToolCallConflictKey(decisionCall)]; conflicted {
					decisionCall.OutputItemID = fmt.Sprintf("choice-%d-conflict-%d", i, toolCallIndex)
					decisionCall.ProtocolIdentityRejected = true
				} else if decisionCall.OutputItemID == "" {
					if decisionCall.ID == "" {
						decisionCall.OutputItemID = fmt.Sprintf("choice-%d-tool-%d", i, toolCallIndex)
					} else {
						decisionCall.OutputItemID = fmt.Sprintf("choice-%d", i)
					}
				}
				key := structuredToolCallOperationID(envelope, decisionCall)
				decision, decided := structuredDecisions[key]
				if !decided {
					var err error
					decision, err = h.applyAgentGuardToolDecisionResult(ctx, envelope, decisionCall, contextFragments, auditResult, i)
					if err != nil {
						return nil, auditResult, err
					}
					structuredDecisions[key] = decision
				}
				if isDestructiveGateDecision(decision) &&
					(decision.EffectiveDecision == agentguard.DecisionBlock || decision.EffectiveDecision == agentguard.DecisionConfirm) &&
					securityexit.Decide(h.outputExitMode(ctx), "block", securityexit.ToolPolicy).Enforce {
					blocked = append(blocked, decision)
					continue
				}
				allowed = append(allowed, tc)
			}
			choice.Message.ToolCalls = allowed
			if len(blocked) > 0 {
				auditResult.OutputAction = "block"
				if len(allowed) == 0 {
					choice.FinishReason = "stop"
					choice.Message.Content = h.destructiveBlockNoticeText(ctx, envelope, blocked[0])
				}
			}
		}
	}

	result, err := json.Marshal(resp)
	if err != nil {
		return nil, nil, err
	}
	return result, auditResult, nil
}

func structuredToolCallOperationID(envelope *modelrouter.RequestEnvelope, call ToolCall) string {
	identity := destructiveOperationIdentity{
		OutputItemID: call.OutputItemID, ToolCallID: call.ID, ToolName: call.Function.Name,
		CanonicalArgs:    canonicalOperationArgumentsJSON(call.Function.Arguments),
		IdentityRejected: call.ProtocolIdentityRejected,
	}
	if envelope != nil {
		identity.TenantID = envelope.TenantID
		identity.Protocol = envelope.EndpointType
		identity.SessionID = envelope.SessionID
		identity.RequestID = envelope.RequestID
	}
	return operationID(identity)
}

func conflictingChatToolCallIDs(calls []ToolCall) map[string]struct{} {
	fingerprints := make(map[string][sha256.Size]byte, len(calls))
	conflicts := make(map[string]struct{})
	for _, call := range calls {
		key := chatToolCallConflictKey(call)
		if key == "" {
			continue
		}
		encoded, _ := json.Marshal(struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}{Type: call.Type, Name: call.Function.Name, Arguments: call.Function.Arguments})
		fingerprint := sha256.Sum256(encoded)
		if previous, exists := fingerprints[key]; exists && previous != fingerprint {
			conflicts[key] = struct{}{}
			continue
		}
		fingerprints[key] = fingerprint
	}
	return conflicts
}

func chatToolCallConflictKey(call ToolCall) string {
	if call.ID == "" {
		return ""
	}
	return call.OutputItemID + "\x1f" + call.ID
}

// ToolCallRiskFinding 表示 tool call 参数的风险发现
type ToolCallRiskFinding struct {
	Severity string
	Category string
	Message  string
}

func (h *ChatCompletionsHandler) analyzeAgentGuardToolCall(ctx context.Context, envelope *modelrouter.RequestEnvelope, tc ToolCall, fragments []agentguard.ContextFragment) (agentguard.Decision, map[string]interface{}, error) {
	args, argumentsParseRejected := parseToolCallArguments(tc.Function.Arguments)
	toolType := h.resolveAgentGuardToolType(envelope, tc.Function.Name) // W5 5.9
	var policy *agentguard.EffectivePolicy
	var policyLoadErr error
	if h.toolRiskClient != nil {
		if fetched, err := h.toolRiskClient.GetAgentGuardPolicy(ctx, envelope); err != nil {
			policyLoadErr = err
		} else {
			policy = fetched
		}
	}

	identity := agentguard.SkillIdentity{}
	resolution := skillAdmissionResolution{Status: string(agentguard.SkillAdmissionUnverified)}
	admissionStatus := agentguard.SkillAdmissionUnverified
	var admissionErr error
	if toolType == agentguard.ToolTypeSkill {
		identity = agentguard.ExtractSkillIdentity(args)
		resolution, admissionStatus, admissionErr = resolveSkillAdmissionForAnalysis(ctx, h.toolRiskClient, h.auditWriter, envelope, identity, h.outputExitMode(ctx))
	}
	tenantID := ""
	if envelope != nil {
		tenantID = envelope.TenantID
	}
	allowedDomains, domainEvidence := toolAllowedDomains(ctx, h.db, tenantID, args)
	failureLoopCount := 0
	if h.agentGuardToolFailures != nil {
		window, threshold := toolFailureLoopParams(policy)
		if threshold <= 0 {
			threshold = h.agentGuardToolFailures.Threshold()
		}
		if count := h.agentGuardToolFailures.CountWithin(agentGuardActorKey(envelope), tc.Function.Name, time.Now(), window); count >= threshold {
			failureLoopCount = count
		}
	}
	baseDecision := agentguard.AnalyzeToolCall(ctx, agentguard.ToolCallAnalysisInput{
		ToolName:         tc.Function.Name,
		ToolType:         toolType,
		Arguments:        args,
		ContextFragments: fragments,
		Mode:             h.agentGuardMode(ctx),
		PolicyVersion:    agentGuardPolicyVersion,
		TraceID:          agentGuardTraceID(envelope, tc),
		CommandAllowlist: defaultAgentGuardCommandAllowlist(),
		AllowedDomains:   allowedDomains,
		Policy:           policy,
		Behavior:         h.agentGuardBehavior,
		ActorKey:         agentGuardActorKey(envelope),
		SemanticJudge:    h.agentSemanticJudge(ctx, envelope),
		SkillAdmission:   admissionStatus,
		// 工具连续失败（防护项 agent.tool_failure_loop）：窗口和次数取租户配置，动作按该项。
		ToolFailureLoopCount: failureLoopCount,
	})
	baseDecision.Evidence = append(baseDecision.Evidence, domainEvidence...)
	requestID := ""
	if envelope != nil {
		requestID = envelope.RequestID
	}
	input := structuredToolCallInput{
		RequestID: requestID, OutputItemID: tc.OutputItemID, ToolCallID: tc.ID,
		ToolName: tc.Function.Name, ToolType: toolType, Arguments: args,
		Policy: policy, Mode: h.agentGuardMode(ctx), ConfirmSupported: false,
		RawArguments:             tc.Function.Arguments,
		ArgumentsParseRejected:   argumentsParseRejected,
		ProtocolIdentityRejected: tc.ProtocolIdentityRejected,
		BaseDecision:             baseDecision,
	}
	if envelope != nil {
		input.TenantID = envelope.TenantID
		input.Protocol = envelope.EndpointType
		input.SessionID = envelope.SessionID
		input.AgentType = envelope.AgentType
	}
	evaluation := evaluateStructuredToolCall(input)
	decision := evaluation.Decision
	if h.toolRiskClient != nil && envelope != nil {
		result, _ := h.toolRiskClient.CheckToolRisk(ctx, envelope.TenantID, tc.Function.Name)
		decision = applyConfiguredToolCallPolicy(decision, result, h.agentGuardMode(ctx))
	}
	if decision.TraceID == "" {
		decision.TraceID = agentGuardTraceID(envelope, tc)
	}
	if toolType == agentguard.ToolTypeSkill {
		decision.SkillAssetID = resolution.AssetID
		decision.SkillVersionID = resolution.VersionID
		decision.SkillName = identity.CanonicalName
		if decision.SkillName == "" {
			decision.SkillName = agentguard.CanonicalSkillName(tc.Function.Name)
		}
		decision.SkillVersion = identity.Version
		decision.SkillBundleHash = identity.BundleHash
		decision.SkillSource = identity.Source
		decision.SkillAdmission = resolution.Status
	}
	if policyLoadErr != nil {
		// 客户端在策略加载期间断开（请求 ctx 已取消，GetAgentGuardPolicy 用它发 HTTP 而失败）：
		// 不是策略不可用，是客户端走了。不包成 errAgentGuardPolicyUnavailable，原样带上哨兵，
		// 由 applyAgentGuardToolDecisionResult 在写 agentguard_policy_load_failed 事件之前返回。
		if clientGoneDuring(ctx, policyLoadErr) {
			policyLoadErr = fmt.Errorf("%w: AgentGuard policy load for tool %q", errClientGoneDuringSecurity, tc.Function.Name)
		} else {
			policyLoadErr = fmt.Errorf("%w: %w", errAgentGuardPolicyUnavailable, policyLoadErr)
		}
	}
	return decision, sanitizeToolCallParameters(args), errors.Join(policyLoadErr, admissionErr)
}

// agentSemanticJudge 仅当语义裁判开启且 securityClient 在位时返回裁判后端，否则返回 nil
// （AnalyzeToolCall 据此 fail-open，行为与改造前一致）。开关走公开的 SemanticAgentEnabled：
// 缓存命中即用，否则去 control-plane 拉取 semantic_agent_enabled 并填缓存（DB 优先），
// 拉取失败时回退 env SECURITY_SEMANTIC_AGENT_ENABLED。默认关。范式同 securityAuditOnly。
func (h *ChatCompletionsHandler) agentSemanticJudge(ctx context.Context, envelope *modelrouter.RequestEnvelope) agentguard.SemanticJudge {
	if h.securityClient == nil {
		return nil
	}
	enabled := os.Getenv("SECURITY_SEMANTIC_ENABLED") == "true" &&
		os.Getenv("SECURITY_SEMANTIC_AGENT_ENABLED") == "true"
	if h.toolRiskClient != nil {
		enabled = h.toolRiskClient.SemanticAgentEnabled(ctx, enabled)
	}
	if !enabled {
		return nil
	}
	return agentSemanticJudge{checker: h.securityClient, envelope: envelope}
}

// skipSemanticCtxKey 是 ctx-value 键：置位时让同步 CheckInput 携带 skip_semantic=true。
// 用 ctx-value 而非改 SecurityChecker.CheckInput 签名——不动接口、对其它调用方零影响。
type skipSemanticCtxKey struct{}

// withSkipSemantic 在 ctx 上挂 skip-semantic 标记（异步旁路开启时同步检查跳语义用）。
func withSkipSemantic(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipSemanticCtxKey{}, true)
}

// skipSemanticFromContext 读取 ctx 上的 skip-semantic 标记（RealSecurityChecker.CheckInput 据此设请求位）。
func skipSemanticFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(skipSemanticCtxKey{}).(bool)
	return v
}

// asyncSemanticMaxInflight 异步语义旁路的进程级并发上界（fire-and-forget goroutine 数）。
// 取常量 32：observe-only 旁路，宁可在突发下丢弃少量留证，也不放任 goroutine 无限增长拖垮进程。
const asyncSemanticMaxInflight = 32

// asyncSemaphore 进程级限流：派发前抢一个槽，满了直接丢弃（observe-only 下丢弃可接受）。
var asyncSemaphore = make(chan struct{}, asyncSemanticMaxInflight)

// joinInputMessages 把本次请求各非空消息内容用换行拼成一段。
// 与同步循环一致：只纳入 Content!="" 的消息（纯空消息不参与拼接）。
// 它不看检测范围，只能用于已按策略选好的消息切片；旁路派发请用 selectedInspectionText。
func joinInputMessages(messages []Message) string {
	parts := make([]string, 0, len(messages))
	for i := range messages {
		t := messageText(messages[i].Content)
		if t == "" {
			continue
		}
		parts = append(parts, t)
	}
	return strings.Join(parts, "\n")
}

// selectedInspectionText 只拼接检测计划选中的消息（按协议顺序）。任何旁路（异步语义、
// 误报 triage）都必须经它取正文：inspect_builtin_context=false 时系统提示词/开发者指令/
// 工具定义不会进入，inspect_history=false 时历史轮次不会进入；unknown 来源仍在范围内。
func selectedInspectionText(messages []Message, plan inputInspectionPlan) string {
	selected := make([]Message, 0, len(plan.targets))
	for i := range messages {
		if _, ok := plan.targets[i]; ok {
			selected = append(selected, messages[i])
		}
	}
	return joinInputMessages(selected)
}

// inputSemanticAsync is intentionally pinned off. The legacy environment
// switch silently moved semantic checks out of the enforcement path and could
// drop work under pressure, contradicting the customer-facing "complete input
// inspection" contract. Keep the method during the compatibility window so old
// callers compile, but stale deployment configuration cannot re-enable it.
func (h *ChatCompletionsHandler) inputSemanticAsync() bool {
	return false
}

// inputSemanticAsyncEnabled 要求异步旁路开关与语义总开关、输入开关同时生效。
// 这防止 semantic_only 强制路径在 UI 已关闭总开关或输入检测时仍绕过门控执行。
func (h *ChatCompletionsHandler) inputSemanticAsyncEnabled(ctx context.Context) bool {
	if !h.inputSemanticAsync() {
		return false
	}
	enabled := os.Getenv("SECURITY_SEMANTIC_ENABLED") == "true" &&
		os.Getenv("SECURITY_SEMANTIC_INPUT_ENABLED") == "true"
	if h.toolRiskClient != nil {
		enabled = h.toolRiskClient.SemanticInputEnabled(ctx, enabled)
	}
	return enabled
}

// fpSuppressionEnabled 误报压制门控（默认关=零回归；gateway 与 security-engine 共读同名 env）。
// 开启后，异步旁路在写完 security_event 后追加一次 /check-triage 标注（observe-only，不改主链）。
func (h *ChatCompletionsHandler) fpSuppressionEnabled() bool {
	return os.Getenv("SECURITY_FP_SUPPRESSION_ENABLED") == "true"
}

// applyTriageSuppression 误报压制：把同步 CheckInput 命中的规则 findings 交 /check-triage 做
// 类型感知 triage，再把带 triage 的结果回写该 request 输入侧 security_event 的 matched_summary。
// 默认关（fpSuppressionEnabled=false）即 no-op；triage 失败只 log（fail-open，不藏 finding）。
// observe-only：绝不阻塞主链、绝不改 response。
//
// FIX-2（nit）：仅对「可 triage 的规则 finding」（意图类规则）调 /check-triage。
// 语义路径(dispatchAsyncInputSemantic)会把纯 semantic_attack findings 传进来——语义 finding 非
// 意图类规则命中、不该被 triage；语义命中不参与 triage。全被滤掉则直接跳过
// /check-triage 往返（省一次无意义的裁判调用与回写）。
func (h *ChatCompletionsHandler) applyTriageSuppression(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, ruleFindings []SecurityFinding) {
	if !h.fpSuppressionEnabled() || h.securityClient == nil || h.auditWriter == nil || len(ruleFindings) == 0 {
		return
	}
	triageable := triageableRuleFindings(ruleFindings)
	if len(triageable) == 0 {
		return // 无可 triage 的规则 finding（纯语义）——跳过 /check-triage 往返
	}
	triaged, err := h.securityClient.CheckTriage(ctx, envelope, content, triageable)
	if err != nil {
		log.Printf("[triage.async] check-triage failed req=%s: %v", envelope.RequestID, err)
		return
	}
	h.auditWriter.AnnotateTriage(ctx, envelope, triaged)
}

// triageableRuleFindings 过滤出可做误报 triage 的规则 findings：
// 剔除 type=semantic_attack（语义命中非意图类规则，不参与 triage）
func triageableRuleFindings(findings []SecurityFinding) []SecurityFinding {
	out := findings[:0:0] // 不复用底层数组，避免改写入参
	for _, f := range findings {
		if f.Type == "semantic_attack" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// dispatchAsyncInputSemantic 异步旁路：另起 goroutine 跑仅语义检查，命中写审计事件
// （observe-only，绝不阻塞主链/改 response）。仿 interfaces.go 的 fire-and-forget 范式：
// WithoutCancel(脱离请求生命周期) + 内层 WithTimeout + envelope 值拷贝(指针不进 goroutine) +
// recover 兜 panic + 错误只 log(fail-open)。每请求只派一次（content 已是整段拼接）。
// 进程级 semaphore 限流：抢不到槽位直接丢弃 + log（observe-only 下可接受，防 goroutine 无限增长）。
func (h *ChatCompletionsHandler) dispatchAsyncInputSemantic(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string) {
	if h == nil || h.securityClient == nil || envelope == nil || strings.TrimSpace(content) == "" {
		return
	}
	reqID := envelope.RequestID
	env := *envelope // 浅拷贝快照，指针不进 goroutine（避免主链复用/改写同一 envelope 引发 race）
	// 显式归零浅拷贝里与主链共享的引用字段：异步路只读标量（RequestID/Project/Model/Tenant 等），
	// 不读 ContentSegments/RoutingDecision；归零让 “不共享别名” 的意图显式化，杜绝将来误读触发 race。
	env.ContentSegments = nil
	env.RoutingDecision = nil

	// 进程级限流：抢槽位失败说明在途异步语义已达上界，直接丢弃（observe-only 下可接受）。
	select {
	case asyncSemaphore <- struct{}{}:
	default:
		log.Printf("[semantic.async] dropped (semaphore full) req=%s", reqID)
		return
	}

	go func(parent context.Context, env modelrouter.RequestEnvelope, content string) {
		defer func() { <-asyncSemaphore }() // 释放槽位
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[semantic.async] panic req=%s: %v", reqID, r)
			}
		}()
		c, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		findings, err := h.securityClient.CheckSemanticOnly(c, &env, content)
		if err != nil {
			log.Printf("[semantic.async] check failed req=%s: %v", reqID, err) // fail-open，只 log
			return
		}
		if hasSecurityFindings(findings) {
			// 审计写独立短 deadline，与语义检查超时解耦：慢裁判耗尽 10s 后审计写不应被一起拖死丢证。
			wctx, wcancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
			defer wcancel()
			// actionTaken 与同步审计路径对齐用 "security_audit"（异步用孤值 "audit" 会让看板/口径串不一致）。
			h.auditWriter.WriteSecurityEvent(wctx, &env, findings, "security_audit", "异步输入语义命中")
			// 误报压制（默认关）：event 已留底。findings 此处全为 semantic_attack（语义命中），
			// applyTriageSuppression 内会把语义 过滤掉——纯语义则直接跳过 /check-triage 往返。
			// 保留此调用是为兼顾将来语义路径返回混合 findings 的情形；纯语义场景下它是 no-op。
			h.applyTriageSuppression(wctx, &env, content, findings)
		}
	}(context.WithoutCancel(ctx), env, content)
}

// dispatchAsyncTriage 异步误报压制旁路：另起 goroutine 把规则 findings 交 /check-triage 标注后
// 回写 security_event（observe-only，绝不阻塞主链）。复用语义旁路同款 semaphore 限流。
func (h *ChatCompletionsHandler) dispatchAsyncTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, findings []SecurityFinding) {
	if h == nil || h.securityClient == nil || envelope == nil || len(findings) == 0 {
		return
	}
	reqID := envelope.RequestID
	env := *envelope
	env.ContentSegments = nil
	env.RoutingDecision = nil
	fs := make([]SecurityFinding, len(findings))
	copy(fs, findings)
	select {
	case asyncSemaphore <- struct{}{}:
	default:
		log.Printf("[triage.async] dropped (semaphore full) req=%s", reqID)
		return
	}
	go func(parent context.Context, env modelrouter.RequestEnvelope, content string, fs []SecurityFinding) {
		defer func() { <-asyncSemaphore }()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[triage.async] panic req=%s: %v", reqID, r)
			}
		}()
		c, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		h.applyTriageSuppression(c, &env, content, fs)
	}(context.WithoutCancel(ctx), env, content, fs)
}

const agentGuardPolicyLoadFailureReason = "agentguard_policy_load_failed"

var errAgentGuardPolicyUnavailable = errors.New(agentGuardPolicyLoadFailureReason)

func (h *ChatCompletionsHandler) applyAgentGuardToolDecisionResult(ctx context.Context, envelope *modelrouter.RequestEnvelope, tc ToolCall, fragments []agentguard.ContextFragment, auditResult *AuditResult, choiceIndex int) (agentguard.Decision, error) {
	decision, parameters, policyLoadErr := h.analyzeAgentGuardToolCall(ctx, envelope, tc, fragments)
	// 客户端在策略加载期间已断开：先于一切副作用（覆盖缺口元数据、policy_load_failed 事件、
	// 工具审计上报、fail-closed）返回哨兵，调用方记 client_canceled。
	if clientGoneDuring(ctx, policyLoadErr) {
		return decision, fmt.Errorf("%w: output choice %d", errClientGoneDuringSecurity, choiceIndex)
	}
	policyUnavailable := errors.Is(policyLoadErr, errAgentGuardPolicyUnavailable)
	if policyUnavailable {
		failureMode := h.guardrailFailureMode(ctx)
		failure := securityexit.DecideWithPolicy(h.outputExitMode(ctx), "block", securityexit.DetectionFailure, guardrailPolicy(ctx, h.toolRiskClient))
		if auditResult.ResponseMetadata == nil {
			auditResult.ResponseMetadata = map[string]interface{}{}
		}
		auditResult.ResponseMetadata["tool_policy_coverage_gap"] = failure.Gap
		findings := []SecurityFinding{{
			Type: "coverage_gap", Severity: "medium", Category: "agent_permission_governance",
			RuleID: agentGuardPolicyLoadFailureReason, RuleName: tc.Function.Name,
			Action: "audit", MatchedLocation: "tool", EvidenceReason: agentGuardPolicyLoadFailureReason,
		}}
		auditResult.OutputFindings = append(auditResult.OutputFindings, securityFindingsToAuditMaps(findings)...)
		if h.auditWriter != nil {
			h.auditWriter.WriteSecurityEvent(withSecurityEventStage(ctx, "tool"), envelope, findings, agentGuardPolicyLoadFailureReason,
				fmt.Sprintf("AgentGuard policy unavailable for tool '%s' (failure_mode=%s coverage_gap=%t enforced=%t)", tc.Function.Name, failureMode, failure.Gap, failure.Enforce))
		}
	}
	if decision.RawDecision != agentguard.DecisionAllow || decision.Provenance == agentguard.ProvenanceTainted {
		auditResult.OutputFindings = append(auditResult.OutputFindings, agentGuardAuditFinding(tc, decision, choiceIndex))
	}
	destructiveEvent := h.auditWriter != nil && shouldWriteAgentGuardAuditSecurityEvent(decision)
	if destructiveEvent {
		h.auditWriter.WriteSecurityEvent(ctx, envelope, []SecurityFinding{agentGuardSecurityFinding(tc, decision, choiceIndex)}, agentGuardDestructiveEventAction(decision), fmt.Sprintf("tool %q produced destructive intent in audit mode", tc.Function.Name))
	}
	if h.auditWriter != nil && shouldWriteAgentGuardAlertEvent(decision, destructiveEvent, h.outputSecurityAuditOnly(ctx)) {
		h.auditWriter.WriteSecurityEvent(withSecurityEventStage(ctx, "tool"), envelope, []SecurityFinding{{
			Type: "tool_policy_alert", Severity: normalizeAgentGuardRiskLevel(decision.RiskLevel),
			Category: "agent_behavior_policy", RuleID: decision.MatchedRuleID,
			RuleName: tc.Function.Name, RuleType: "agentguard", Action: "audit",
			Confidence: decision.Confidence, MatchedLocation: "tool",
			EvidenceReason: decision.Reason,
		}}, "alert", fmt.Sprintf("tool %q matched a configured alert-and-allow behavior rule", tc.Function.Name))
	}
	// 受限文件的动作已在判定时按防护项统一给出（含例外与执行模式），由它拦下的调用另记一条
	// 受限文件阻断事件。
	h.writeRestrictedFileBlockEvent(ctx, envelope, tc, decision)
	// W5 5.2: a retry of a human-approved call is released exactly once.
	decision = h.redeemApprovedAgentGuardConfirmation(ctx, envelope, tc, decision)
	decision = h.gateAgentGuardHighRiskExit(ctx, decision) // W5 5.6
	if restrictedFileAlertOnly(decision) && h.auditWriter != nil && decision.EffectiveDecision != agentguard.DecisionBlock && decision.EffectiveDecision != agentguard.DecisionConfirm {
		h.auditWriter.WriteSecurityEvent(ctx, envelope, []SecurityFinding{{Type: "security_audit", Severity: "high", Category: "restricted_file_access", RuleName: tc.Function.Name, MatchedLocation: "tool"}}, "security_audit", fmt.Sprintf("tool %q matched restricted file pattern (alert and allow)", tc.Function.Name))
	}

	if decision.EffectiveDecision == agentguard.DecisionBlock || decision.EffectiveDecision == agentguard.DecisionConfirm {
		operation := agentGuardBlockOperation(tc, decision)
		category := decision.RiskCategory
		if category == "" {
			category = "tool_risk"
		}
		toolActionTaken := "block"
		if decision.EffectiveDecision == agentguard.DecisionConfirm {
			toolActionTaken = "confirm"
		}
		h.auditWriter.WriteSecurityEvent(withBlockOperation(withSecurityEventStage(ctx, "tool"), operation), envelope, []SecurityFinding{{
			Type: "tool_attempt_blocked", Severity: normalizeAgentGuardRiskLevel(decision.RiskLevel), Category: category, Confidence: decision.Confidence,
			RuleID: operation.RuleID, RuleName: operation.RuleName, Action: "block", MatchedLocation: "tool",
			RedactedEvidence: operation.Detail, EvidenceReason: agentGuardDecisionReason(decision),
		}}, toolActionTaken, fmt.Sprintf("tool %q was blocked by the gateway before execution", tc.Function.Name))
	}

	if h.toolRiskClient != nil {
		invocationID := ""
		if inferToolTypeFromName(tc.Function.Name) == agentguard.ToolTypeSkill {
			var recordErr error
			invocationID, recordErr = h.recordSkillInvocation(ctx, envelope, tc, decision, parameters)
			if recordErr != nil {
				h.auditWriter.WriteSecurityEvent(ctx, envelope, nil, "skill_invocation_record_failed", "Skill proposed invocation could not be persisted")
			}
		}
		for _, payload := range buildAgentGuardToolAuditPayloads(tc, decision, parameters) {
			if strings.TrimSpace(payload.ToolName) == "" &&
				!h.toolRiskClient.shouldReportNamelessTool(envelope, choiceIndex, tc.OutputItemID+"|"+tc.ID) {
				continue
			}
			payload.SkillInvocationID = invocationID
			payload.ToolType = h.resolveAgentGuardToolType(envelope, tc.Function.Name)
			_ = h.toolRiskClient.LogToolCall(ctx, envelope, payload)
		}
	}

	if policyUnavailable && decision.EffectiveDecision != agentguard.DecisionBlock && decision.EffectiveDecision != agentguard.DecisionConfirm {
		failure := securityexit.DecideWithPolicy(h.outputExitMode(ctx), "block", securityexit.DetectionFailure, guardrailPolicy(ctx, h.toolRiskClient))
		if failure.Enforce {
			auditResult.OutputAction = failure.Action
			return decision, fmt.Errorf("%w: AgentGuard policy unavailable for tool %q", errGuardrailDetectionUnavailable, tc.Function.Name)
		}
	}

	if decision.EffectiveDecision == agentguard.DecisionAudit && (decision.RawDecision != agentguard.DecisionAllow || decision.EffectiveReason == agentGuardToolRecordedReason) {
		auditResult.OutputAction = "audit"
	}
	if decision.EffectiveDecision == agentguard.DecisionConfirm {
		if h.toolRiskClient != nil {
			_ = h.toolRiskClient.CreateAgentGuardConfirmation(ctx, envelope, decision, tc.Function.Name, tc.ID, tc.Function.Arguments, choiceIndex, "")
		}
		auditResult.OutputAction = "block"
		if isDestructiveGateDecision(decision) {
			return decision, nil
		}
		return decision, fmt.Errorf("tool call '%s' requires AgentGuard confirmation: %s", tc.Function.Name, agentGuardDecisionReason(decision))
	}
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		auditResult.OutputAction = "block"
		if isDestructiveGateDecision(decision) {
			return decision, nil
		}
		return decision, fmt.Errorf("tool call '%s' blocked: %s", tc.Function.Name, agentGuardDecisionReason(decision))
	}
	return decision, nil
}

func (h *ChatCompletionsHandler) applyAgentGuardToolDecision(ctx context.Context, envelope *modelrouter.RequestEnvelope, tc ToolCall, fragments []agentguard.ContextFragment, auditResult *AuditResult, choiceIndex int) error {
	_, err := h.applyAgentGuardToolDecisionResult(ctx, envelope, tc, fragments, auditResult, choiceIndex)
	return err
}

func (h *ChatCompletionsHandler) agentGuardMode(ctx context.Context) agentguard.Mode {
	if h.outputSecurityAuditOnly(ctx) {
		return agentguard.ModeAudit
	}
	return agentguard.ModeStrict
}

func agentGuardActorKey(envelope *modelrouter.RequestEnvelope) string {
	if envelope == nil {
		return "unknown"
	}
	parts := []string{envelope.TenantID, envelope.ProjectID, envelope.UserID, envelope.KeyPrefix, envelope.SessionID}
	for i, part := range parts {
		if strings.TrimSpace(part) == "" {
			parts[i] = "-"
		}
	}
	return strings.Join(parts, "/")
}

func agentGuardTraceID(envelope *modelrouter.RequestEnvelope, tc ToolCall) string {
	if envelope == nil {
		return tc.ID
	}
	if tc.ID == "" {
		return envelope.RequestID
	}
	return envelope.RequestID + ":" + tc.ID
}

func parseToolCallArguments(raw string) (map[string]interface{}, bool) {
	if strings.TrimSpace(raw) == "" {
		return map[string]interface{}{}, false
	}
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &args); err == nil && args != nil {
		return args, false
	}
	// Models regularly write Windows paths into tool-argument JSON with single
	// backslashes (a raw `\U` inside "C:\Users"). The agent client tolerates it,
	// so the gateway must read the same command instead of treating the whole
	// call as unparseable.
	if repaired, ok := repairInvalidJSONStringEscapes(raw); ok {
		args = nil
		if err := json.Unmarshal([]byte(repaired), &args); err == nil && args != nil {
			return args, false
		}
	}
	return map[string]interface{}{}, true
}

// repairInvalidJSONStringEscapes doubles every backslash inside a JSON string
// that does not start a valid escape sequence. Valid escapes and everything
// outside strings are left untouched; ok is false when nothing changed.
func repairInvalidJSONStringEscapes(raw string) (string, bool) {
	var out strings.Builder
	out.Grow(len(raw) + 8)
	inString := false
	changed := false
	for index := 0; index < len(raw); index++ {
		ch := raw[index]
		if !inString {
			if ch == '"' {
				inString = true
			}
			out.WriteByte(ch)
			continue
		}
		switch ch {
		case '"':
			inString = false
			out.WriteByte(ch)
		case '\\':
			if index+1 < len(raw) && validJSONEscapeAt(raw, index+1) {
				out.WriteByte(ch)
				out.WriteByte(raw[index+1])
				index++
				continue
			}
			out.WriteString(`\\`)
			changed = true
		default:
			out.WriteByte(ch)
		}
	}
	return out.String(), changed
}

func validJSONEscapeAt(raw string, index int) bool {
	switch raw[index] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return true
	case 'u':
		if index+4 >= len(raw) {
			return false
		}
		for _, digit := range raw[index+1 : index+5] {
			if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func buildAgentGuardContextFragments(messages []Message) []agentguard.ContextFragment {
	fragments := make([]agentguard.ContextFragment, 0, len(messages))
	for i, message := range messages {
		t := messageText(message.Content)
		if t == "" {
			continue
		}
		fragments = append(fragments, agentguard.ContextFragment{
			ID:    fmt.Sprintf("message-%d", i),
			Trust: trustForMessage(message),
			Text:  t,
		})
	}
	return fragments
}

func trustForMessage(message Message) agentguard.Provenance {
	switch strings.ToLower(message.Role) {
	case "system", "developer", "user":
		return agentguard.ProvenanceTrusted
	case "tool", "function":
		return agentguard.ProvenanceUntrusted
	default:
		return agentguard.ProvenanceMixed
	}
}

func defaultAgentGuardCommandAllowlist() []agentguard.CommandAllowRule {
	return []agentguard.CommandAllowRule{
		{Executable: "go", ArgsPrefix: []string{"test"}},
		{Executable: "npm", ArgsPrefix: []string{"test"}},
		{Executable: "pnpm", ArgsPrefix: []string{"test"}},
		{Executable: "yarn", ArgsPrefix: []string{"test"}},
		{Executable: "python", ArgsPrefix: []string{"-m", "pytest"}},
		{Executable: "python3", ArgsPrefix: []string{"-m", "pytest"}},
	}
}

func shouldWriteAgentGuardAuditSecurityEvent(decision agentguard.Decision) bool {
	if decision.EffectiveDecision != agentguard.DecisionAudit || decision.ObservationOnly {
		return false
	}
	if decision.RawDecision == "" || decision.RawDecision == agentguard.DecisionAllow {
		return false
	}
	risk := normalizeAgentGuardRiskLevel(decision.RiskLevel)
	if risk != "high" && risk != "critical" {
		return false
	}
	return isDestructiveGateDecision(decision) || decision.RiskCategory == agentguard.DestructiveRiskCategory
}

// agentGuardDestructiveEventAction 是破坏性事件的 action_taken：防护项告警放行且要求通知时，
// 仅记录的破坏性结论记为 alert，告警放行只发这一条事件。
func agentGuardDestructiveEventAction(decision agentguard.Decision) string {
	action := agentGuardDestructiveActionTaken(decision)
	if action == "audit" && decision.ProtectionAlert() && decision.NotificationRequired {
		return "alert"
	}
	return action
}

// agentGuardDestructiveActionTaken 把 AgentGuard 破坏性策略的最终动作映射为
// security_events.action_taken 的真实处置值：record→audit、alert_allow→alert、
// confirm→confirm、block→block。决策不可得（FinalAction 为空）回落 "audit"。
func agentGuardDestructiveActionTaken(decision agentguard.Decision) string {
	switch decision.FinalAction {
	case agentguard.DestructiveActionAlertAllow:
		return "alert"
	case agentguard.DestructiveActionConfirm:
		return "confirm"
	case agentguard.DestructiveActionBlock:
		return "block"
	default:
		return "audit"
	}
}

func agentGuardSecurityFinding(tc ToolCall, decision agentguard.Decision, choiceIndex int) SecurityFinding {
	severity := normalizeAgentGuardRiskLevel(decision.RiskLevel)
	category := decision.RiskCategory
	if category == "" && (isDestructiveGateDecision(decision) || decision.FinalAction != "") {
		category = agentguard.DestructiveRiskCategory
	}
	if category == "" {
		category = "agent_permission_governance"
	}
	return SecurityFinding{
		Type:               "tool_destructive_intent",
		Severity:           severity,
		Category:           category,
		RuleName:           tc.Function.Name,
		RuleType:           "agentguard",
		Action:             string(decision.EffectiveDecision),
		Confidence:         decision.Confidence,
		MatchedLocation:    "tool",
		RedactedEvidence:   agentGuardFindingEvidence(decision),
		EvidenceKind:       "agent_tool_call",
		ContentSource:      "assistant_tool_call",
		EvidenceReason:     agentGuardDecisionReason(decision),
		MatchedTextPreview: decision.RiskSubcategory,
	}
}

func buildAgentGuardToolAuditPayload(tc ToolCall, decision agentguard.Decision, parameters map[string]interface{}) ToolAuditLogPayload {
	status := "success"
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		status = "blocked"
	} else if decision.RawDecision == agentguard.DecisionBlock || decision.RawDecision == agentguard.DecisionConfirm {
		status = "audited"
	}

	return ToolAuditLogPayload{
		ToolName:              tc.Function.Name,
		ToolType:              inferToolTypeFromName(tc.Function.Name),
		RiskLevel:             normalizeAgentGuardRiskLevel(decision.RiskLevel),
		Parameters:            parameters,
		Result:                agentGuardDecisionReason(decision),
		Status:                status,
		MatchedPolicyName:     "AgentGuard 工具权限决策",
		MatchedPolicyID:       decision.MatchedPolicyID,
		MatchedAction:         string(decision.EffectiveDecision),
		MatchReason:           agentGuardDecisionReason(decision),
		RawDecision:           string(decision.RawDecision),
		EffectiveDecision:     string(decision.EffectiveDecision),
		Mode:                  string(decision.Mode),
		OperationID:           decision.OperationID,
		EffectiveReason:       decision.EffectiveReason,
		PolicyVersion:         decision.PolicyVersion,
		TraceID:               decision.TraceID,
		Confidence:            decision.Confidence,
		EvidenceJSON:          decision.Evidence,
		NormalizedTarget:      decision.NormalizedTarget,
		Provenance:            string(decision.Provenance),
		TaintedArguments:      decision.TaintedArguments,
		EventKind:             "invocation_proposed",
		ExecutionObserved:     false,
		ToolCallID:            tc.ID,
		AssetID:               decision.SkillAssetID,
		AttributionMode:       "explicit",
		AttributionConfidence: 1,
	}
}

func buildAgentGuardToolAuditPayloads(tc ToolCall, decision agentguard.Decision, parameters map[string]interface{}) []ToolAuditLogPayload {
	base := buildAgentGuardToolAuditPayload(tc, decision, parameters)
	if !isDestructiveGateDecision(decision) {
		return []ToolAuditLogPayload{base}
	}
	base.Parameters = sanitizeToolCallParameters(parameters)
	base.Result = ""
	base.EventType = "tool_destructive_intent"
	base.RiskCategory = decision.RiskCategory
	base.RiskSubcategory = decision.RiskSubcategory
	base.ReasonSummary = decision.ReasonSummary
	base.TargetSummary = decision.NormalizedTarget
	base.ModeDefaultAction = string(decision.ModeDefaultAction)
	base.CustomAction = string(decision.CustomAction)
	base.FinalAction = string(decision.FinalAction)
	base.NotificationRequired = decision.NotificationRequired
	base.NotifyChannelIDs = append([]string(nil), decision.NotifyChannelIDs...)
	base.NotificationStatus = "skipped"
	base.DiscardablePathMatched = decision.DiscardablePathMatched
	base.DiscardablePathReason = decision.DiscardablePathReason
	base.ExecutionForwarded = false
	base.ExecutionObserved = false
	base.ResultObserved = false
	switch decision.FinalAction {
	case agentguard.DestructiveActionAlertAllow:
		base.Status = "alerted"
	case agentguard.DestructiveActionConfirm:
		base.Status = "waiting_confirmation"
	default:
		base.Status = "recorded"
	}
	if decision.NotificationRequired && !decision.DiscardablePathMatched {
		base.NotificationStatus = "pending"
	}
	payloads := []ToolAuditLogPayload{base}
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		blocked := base
		blocked.Parameters = sanitizeToolCallParameters(base.Parameters)
		blocked.EventType = "tool_attempt_blocked"
		blocked.Status = "blocked"
		payloads = append(payloads, blocked)
	}
	return payloads
}

func (h *ChatCompletionsHandler) recordSkillInvocation(ctx context.Context, envelope *modelrouter.RequestEnvelope, tc ToolCall, decision agentguard.Decision, parameters map[string]interface{}) (string, error) {
	canonical, _ := json.Marshal(parameters)
	status := "proposed"
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		status = "blocked"
	} else if decision.EffectiveDecision == agentguard.DecisionConfirm {
		status = "confirmed"
	}
	return h.toolRiskClient.RecordSkillInvocation(ctx, envelope, tc.ID, skillInvocationRecord{
		AssetID:               decision.SkillAssetID,
		AssetVersionID:        decision.SkillVersionID,
		CanonicalName:         decision.SkillName,
		DeclaredVersion:       decision.SkillVersion,
		SourceURI:             decision.SkillSource,
		Status:                status,
		RawDecision:           string(decision.RawDecision),
		EffectiveDecision:     string(decision.EffectiveDecision),
		ParametersDigest:      digestSkillBytes(canonical),
		RedactedPreview:       parameters,
		AttributionMode:       "explicit",
		AttributionConfidence: 1,
	})
}

func skillResultFindingSummary(findings []SecurityFinding) []map[string]any {
	if len(findings) == 0 {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		out = append(out, map[string]any{
			"type":     finding.Type,
			"severity": finding.Severity,
			"category": finding.Category,
			"code":     finding.RuleID,
		})
	}
	return out
}

func agentGuardAuditFinding(tc ToolCall, decision agentguard.Decision, choiceIndex int) map[string]interface{} {
	return map[string]interface{}{
		"type":               "agentguard_tool_decision",
		"severity":           normalizeAgentGuardRiskLevel(decision.RiskLevel),
		"category":           "agent_permission_governance",
		"tool_name":          tc.Function.Name,
		"choice_index":       choiceIndex,
		"raw_decision":       decision.RawDecision,
		"effective_decision": decision.EffectiveDecision,
		"provenance":         decision.Provenance,
	}
}

// shouldWriteAgentGuardAlertEvent 判断要不要写通用的工具告警事件：结论要求通知、
// 生效为审计、不是只记录姿态。破坏性结论有自己的事件，只有命中告警放行的防护项而
// 又没写破坏性事件时才补一条；受限文件的告警放行有专门事件，不重复写。
func shouldWriteAgentGuardAlertEvent(decision agentguard.Decision, destructiveEventWritten, recordOnly bool) bool {
	if !decision.NotificationRequired || decision.EffectiveDecision != agentguard.DecisionAudit || recordOnly || decision.ObservationOnly {
		return false
	}
	if restrictedFileAlertOnly(decision) {
		return false
	}
	if isDestructiveGateDecision(decision) {
		return decision.ProtectionAlert() && !destructiveEventWritten
	}
	return true
}

// restrictedFileAlertOnly 标出“受限文件”防护项结论为告警放行的调用：它有专门的
// restricted_file_access 审计事件，不再另写一条通用的告警事件。
func restrictedFileAlertOnly(decision agentguard.Decision) bool {
	return decision.RestrictedFileMatched && decision.ProtectionItem == protection.KeyRestrictedFile && decision.ProtectionAlert()
}

// restrictedFileBlocked 标出由“受限文件”防护项拦下的调用：动作只由防护项统一处理
// （resolveProtectionHits 定动作、套例外，ApplyEffectivePolicy 按执行模式执行）。
func restrictedFileBlocked(decision agentguard.Decision) bool {
	return decision.EffectiveDecision == agentguard.DecisionBlock && decision.RestrictedFileMatched &&
		decision.ProtectionItem == protection.KeyRestrictedFile && agentGuardBlockCause(decision) == "protection_item"
}

// writeRestrictedFileBlockEvent 为受限文件拦下的调用写 security_blocked 事件（受限文件页的统计口径）。
func (h *ChatCompletionsHandler) writeRestrictedFileBlockEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, tc ToolCall, decision agentguard.Decision) {
	if !restrictedFileBlocked(decision) || h.auditWriter == nil {
		return
	}
	operation := agentGuardBlockOperation(tc, decision)
	h.auditWriter.WriteSecurityEvent(withBlockOperation(withSecurityEventStage(ctx, "tool"), operation), envelope, []SecurityFinding{{
		Type: "security_blocked", Severity: "high", Category: "restricted_file_access",
		RuleID: decision.RestrictedFilePattern, RuleName: "受限文件", Action: "block", MatchedLocation: "tool",
		RedactedEvidence: decision.NormalizedTarget,
	}}, "security_blocked", fmt.Sprintf("tool %q blocked by restricted file pattern", tc.Function.Name))
}

func agentGuardDecisionReason(decision agentguard.Decision) string {
	if decision.EffectiveReason != "" {
		return decision.EffectiveReason
	}
	if decision.Reason != "" {
		return decision.Reason
	}
	return "agentguard_decision"
}

func normalizeAgentGuardRiskLevel(riskLevel string) string {
	switch riskLevel {
	case "low", "medium", "high", "critical":
		return riskLevel
	default:
		return "medium"
	}
}

func sanitizeToolCallParameters(args map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(args))
	for key, value := range args {
		if isSensitiveToolParameterKey(key) {
			result[key] = "<redacted:sensitive-key>"
			continue
		}
		result[key] = sanitizeToolCallParameterValue(value)
	}
	return result
}

func isSensitiveToolParameterKey(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, key)
	if normalized == "" {
		return false
	}
	exact := map[string]struct{}{
		"password": {}, "passwd": {}, "pwd": {}, "token": {},
		"authorization": {}, "proxyauthorization": {}, "cookie": {}, "setcookie": {},
		"apikey": {}, "secret": {}, "credential": {}, "credentials": {},
		"privatekey": {},
	}
	if _, ok := exact[normalized]; ok {
		return true
	}
	for _, suffix := range []string{
		"password", "passwd", "privatekey", "secretkey", "clientsecret",
		"accesstoken", "refreshtoken", "idtoken", "authtoken", "bearertoken",
		"apikey", "credential", "cookie",
	} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func sanitizeToolCallParameterValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case string:
		if len(agentguard.DetectHighConfidenceSecrets(typed)) > 0 {
			return "<redacted:secret>"
		}
		return typed
	case []interface{}:
		items := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			items = append(items, sanitizeToolCallParameterValue(item))
		}
		return items
	case map[string]interface{}:
		return sanitizeToolCallParameters(typed)
	default:
		return typed
	}
}

func highestToolRiskSeverity(findings []ToolCallRiskFinding) string {
	severityRank := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	highest := "low"
	for _, finding := range findings {
		if severityRank[finding.Severity] > severityRank[highest] {
			highest = finding.Severity
		}
	}
	return highest
}

// analyzeToolCallRisk 分析 tool_call 的具体参数，检测风险
func (h *ChatCompletionsHandler) analyzeToolCallRisk(tc ToolCall) []ToolCallRiskFinding {
	findings := []ToolCallRiskFinding{}

	// 解析 arguments JSON
	var args map[string]interface{}
	if tc.Function.Arguments != "" {
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			// 解析失败，不检查
			return findings
		}
	}

	toolName := tc.Function.Name
	toolType := inferToolTypeFromName(toolName)

	switch toolType {
	case "system":
		// Shell/Bash 命令检测
		cmd := getStringArg(args, "command", "cmd", "script", "input")
		if cmd != "" {
			findings = append(findings, analyzeShellRisk(cmd, toolName)...)
		}

	case "database":
		// SQL 语句检测
		sql := getStringArg(args, "query", "sql", "statement", "command")
		if sql != "" {
			findings = append(findings, analyzeSQLRisk(sql, toolName)...)
		}

	case "network":
		// URL/请求检测
		url := getStringArg(args, "url", "uri", "endpoint", "host", "target")
		body := getStringArg(args, "body", "data", "payload", "content")
		if url != "" {
			findings = append(findings, analyzeURLRisk(url, toolName)...)
		}
		if body != "" && len(body) > 100 {
			// POST body 过长可能是在外传数据
			findings = append(findings, ToolCallRiskFinding{
				Severity: "medium",
				Category: "data_exfiltration",
				Message:  fmt.Sprintf("POST body length %d bytes, possible data exfiltration", len(body)),
			})
		}

	case "file":
		// 文件路径检测
		path := getStringArg(args, "path", "file_path", "filepath", "file", "target", "destination")
		mode := getStringArg(args, "mode", "action", "operation")
		if path != "" {
			findings = append(findings, analyzeFilePathRisk(path, mode, toolName)...)
		}
	}

	return findings
}

// inferToolTypeFromName uses the shared lifecycle classifier.
func inferToolTypeFromName(name string) string {
	return agentguard.ClassifyToolType(name)
}

// getStringArg 从 args map 中获取字符串参数（支持多个可能的 key）
func getStringArg(args map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// ===== 各类工具的风险分析函数 =====

// analyzeShellRisk 分析 Shell 命令的风险
func analyzeShellRisk(cmd, toolName string) []ToolCallRiskFinding {
	findings := []ToolCallRiskFinding{}
	cmdLower := strings.ToLower(cmd)

	// 严重风险：删除、格式化、权限提升
	criticalPatterns := []struct {
		pattern string
		message string
	}{
		{"rm -rf", "destructive file deletion command"},
		{"rm --no-preserve-root", "destructive file deletion command"},
		{"mkfs", "filesystem format command"},
		{"dd if=", "disk overwrite command"},
		{"chmod 777", "insecure permission change"},
		{"chown root", "ownership change to root"},
		{"useradd", "user creation command"},
		{"userdel", "user deletion command"},
		{"iptables -f", "firewall flush command"},
		{"systemctl stop", "service stop command"},
		{"killall", "process mass termination"},
		{"pkill -9", "forceful process termination"},
	}

	for _, p := range criticalPatterns {
		if strings.Contains(cmdLower, p.pattern) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "critical",
				Category: "destructive_command",
				Message:  fmt.Sprintf("shell command contains '%s': %s", p.pattern, p.message),
			})
		}
	}

	// 高风险：网络、下载、外传
	highPatterns := []struct {
		pattern string
		message string
	}{
		{"curl", "network request command"},
		{"wget", "file download command"},
		{"nc", "netcat network tool"},
		{"ncat", "netcat network tool"},
		{"scp", "file transfer command"},
		{"rsync", "file sync command"},
		{"ftp", "file transfer protocol"},
		{"ssh", "remote shell connection"},
		{"telnet", "remote connection"},
		{"python -c", "inline python execution"},
		{"perl -e", "inline perl execution"},
		{"eval", "code evaluation"},
		{"exec", "command execution"},
		{"base64", "encoding/decoding (possible obfuscation)"},
		{"xxd", "hex encoding (possible obfuscation)"},
	}

	for _, p := range highPatterns {
		if strings.Contains(cmdLower, p.pattern) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "high",
				Category: "network_command",
				Message:  fmt.Sprintf("shell command contains '%s': %s", p.pattern, p.message),
			})
		}
	}

	// 中风险：环境变量、敏感文件访问
	if strings.Contains(cmdLower, "env") || strings.Contains(cmdLower, "export") {
		findings = append(findings, ToolCallRiskFinding{
			Severity: "medium",
			Category: "env_access",
			Message:  "shell command accessing environment variables",
		})
	}

	// 检查是否访问敏感文件
	sensitiveFiles := []string{"/etc/passwd", "/etc/shadow", "/etc/hosts", ".env", ".ssh", "id_rsa", "id_ed25519", ".gitconfig", ".aws", "credentials"}
	for _, sf := range sensitiveFiles {
		if strings.Contains(cmdLower, strings.ToLower(sf)) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "critical",
				Category: "sensitive_file_access",
				Message:  fmt.Sprintf("shell command accessing sensitive file/path: %s", sf),
			})
		}
	}

	return findings
}

// analyzeSQLRisk 分析 SQL 语句的风险
func analyzeSQLRisk(sql, toolName string) []ToolCallRiskFinding {
	findings := []ToolCallRiskFinding{}
	sqlUpper := strings.ToUpper(sql)

	// 严重风险：破坏性操作
	criticalPatterns := []struct {
		pattern string
		message string
	}{
		{"DROP TABLE", "table deletion"},
		{"DROP DATABASE", "database deletion"},
		{"TRUNCATE TABLE", "table truncation"},
		{"DELETE FROM", "data deletion"},
		{"ALTER TABLE DROP", "column deletion"},
		{"ALTER TABLE", "schema modification"},
		{"CREATE USER", "user creation"},
		{"DROP USER", "user deletion"},
		{"GRANT ALL", "permission grant"},
		{"REVOKE ALL", "permission revoke"},
		{"LOAD DATA INFILE", "file load into database"},
		{"SELECT INTO OUTFILE", "data export to file"},
	}

	for _, p := range criticalPatterns {
		if strings.Contains(sqlUpper, p.pattern) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "critical",
				Category: "destructive_sql",
				Message:  fmt.Sprintf("SQL contains '%s': %s", p.pattern, p.message),
			})
		}
	}

	// 高风险：敏感表访问
	sensitiveTables := []string{"users", "accounts", "passwords", "credentials", "tokens", "sessions", "audit_logs", "security_events", "secrets", "api_keys"}
	for _, t := range sensitiveTables {
		if strings.Contains(sqlUpper, t) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "high",
				Category: "sensitive_table_access",
				Message:  fmt.Sprintf("SQL accesses sensitive table: %s", t),
			})
		}
	}

	// 中风险：大量数据查询
	if strings.Contains(sqlUpper, "SELECT *") {
		findings = append(findings, ToolCallRiskFinding{
			Severity: "medium",
			Category: "bulk_select",
			Message:  "SQL selects all columns (SELECT *)",
		})
	}

	// 检查 LIMIT，没有 LIMIT 的大查询风险更高
	if strings.Contains(sqlUpper, "SELECT") && !strings.Contains(sqlUpper, "LIMIT") {
		findings = append(findings, ToolCallRiskFinding{
			Severity: "medium",
			Category: "unlimited_query",
			Message:  "SELECT without LIMIT clause, may return large dataset",
		})
	}

	return findings
}

// analyzeURLRisk 分析 URL 的风险
func analyzeURLRisk(url, toolName string) []ToolCallRiskFinding {
	findings := []ToolCallRiskFinding{}
	urlLower := strings.ToLower(url)

	// 严重风险：内网地址（SSRF）
	internalPatterns := []struct {
		pattern string
		message string
	}{
		{"localhost", "localhost address"},
		{"127.0.0.1", "localhost IP"},
		{"0.0.0.0", "all interfaces IP"},
		{"10.", "private network (10.x.x.x)"},
		{"172.16.", "private network (172.16.x.x)"},
		{"172.17.", "private network (172.17.x.x)"},
		{"172.18.", "private network (172.18.x.x)"},
		{"172.19.", "private network (172.19.x.x)"},
		{"172.20.", "private network (172.20.x.x)"},
		{"172.21.", "private network (172.21.x.x)"},
		{"172.22.", "private network (172.22.x.x)"},
		{"172.23.", "private network (172.23.x.x)"},
		{"172.24.", "private network (172.24.x.x)"},
		{"172.25.", "private network (172.25.x.x)"},
		{"172.26.", "private network (172.26.x.x)"},
		{"172.27.", "private network (172.27.x.x)"},
		{"172.28.", "private network (172.28.x.x)"},
		{"172.29.", "private network (172.29.x.x)"},
		{"172.30.", "private network (172.30.x.x)"},
		{"172.31.", "private network (172.31.x.x)"},
		{"192.168.", "private network (192.168.x.x)"},
		{"169.254.", "link-local address"},
		{"::1", "localhost IPv6"},
		{"fc00:", "private IPv6"},
		{"fd00:", "private IPv6"},
		{"fe80:", "link-local IPv6"},
		{"file://", "local file protocol"},
		{"gopher://", "gopher protocol (SSRF vector)"},
		{"dict://", "dict protocol (SSRF vector)"},
		{"ldap://", "LDAP protocol (SSRF vector)"},
		{"internal.", "internal hostname"},
		{"intranet.", "intranet hostname"},
		{"corp.", "corporate hostname"},
		{"private.", "private hostname"},
		{"staging.", "staging environment"},
		{"admin.", "admin interface"},
		{"kube.", "kubernetes internal"},
		{"kubernetes.", "kubernetes internal"},
		{"docker.", "docker internal"},
		{"database.", "database internal"},
		{"db.", "database internal"},
		{"redis.", "redis internal"},
		{"postgres.", "postgres internal"},
		{"mysql.", "mysql internal"},
		{"mongo.", "mongodb internal"},
		{"elastic.", "elasticsearch internal"},
		{"es.", "elasticsearch internal"},
		{"vault.", "vault internal"},
		{"consul.", "consul internal"},
		{"grafana.", "grafana internal"},
		{"prometheus.", "prometheus internal"},
	}

	for _, p := range internalPatterns {
		if strings.Contains(urlLower, p.pattern) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "critical",
				Category: "ssrf",
				Message:  fmt.Sprintf("URL targets internal address '%s': %s", p.pattern, p.message),
			})
		}
	}

	// 高风险：敏感外部服务
	sensitiveDomains := []struct {
		pattern string
		message string
	}{
		{"api.slack.com", "Slack API (potential data leak)"},
		{"hooks.slack.com", "Slack webhook (potential data leak)"},
		{"discord.com/api", "Discord API (potential data leak)"},
		{"webhooks.discord", "Discord webhook"},
		{aiadapters.GitHubAPIHost, "GitHub API (potential code leak)"},
		{"api.openai.com", "OpenAI API"},
		{"api.anthropic.com", "Anthropic API"},
		{"api.telegram.org", "Telegram API"},
		{"mailgun.org", "email service"},
		{"sendgrid.com", "email service"},
		{"twilio.com", "SMS/communication service"},
	}

	for _, p := range sensitiveDomains {
		if strings.Contains(urlLower, p.pattern) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "high",
				Category: "sensitive_service",
				Message:  fmt.Sprintf("URL targets sensitive service '%s': %s", p.pattern, p.message),
			})
		}
	}

	// 中风险：可疑的 URL 编码或长 URL
	if strings.Contains(url, "%") && len(url) > 100 {
		findings = append(findings, ToolCallRiskFinding{
			Severity: "medium",
			Category: "encoded_url",
			Message:  "URL contains encoding and is unusually long, possible data exfiltration",
		})
	}

	return findings
}

// analyzeFilePathRisk 分析文件路径的风险
func analyzeFilePathRisk(path, mode, toolName string) []ToolCallRiskFinding {
	findings := []ToolCallRiskFinding{}
	pathLower := strings.ToLower(path)
	modeLower := strings.ToLower(mode)

	// 判断是否是写操作
	isWrite := strings.Contains(modeLower, "write") || strings.Contains(modeLower, "edit") ||
		strings.Contains(modeLower, "create") || strings.Contains(modeLower, "update") ||
		strings.Contains(modeLower, "append") || strings.Contains(modeLower, "modify") ||
		toolName == "write" || toolName == "edit" || strings.Contains(toolName, "write") ||
		strings.Contains(toolName, "edit")

	// 判断是否是删除操作
	isDelete := strings.Contains(modeLower, "delete") || strings.Contains(modeLower, "remove") ||
		strings.Contains(toolName, "delete") || strings.Contains(toolName, "remove")

	// 严重风险：敏感文件
	criticalFiles := []struct {
		pattern string
		message string
	}{
		{"/etc/passwd", "system password file"},
		{"/etc/shadow", "system shadow file"},
		{"/etc/sudoers", "sudo configuration"},
		{"/etc/ssh/", "SSH configuration directory"},
		{".ssh/id_rsa", "SSH private key"},
		{".ssh/id_ed25519", "SSH private key"},
		{".ssh/authorized_keys", "SSH authorized keys"},
		{".pem", "PEM certificate/key file"},
		{".key", "key file"},
		{".env", "environment file"},
		{".env.local", "environment file"},
		{".env.production", "environment file"},
		{"credentials.json", "credentials file"},
		{"secrets.json", "secrets file"},
		{"secrets.yaml", "secrets file"},
		{"secrets.yml", "secrets file"},
		{".aws/credentials", "AWS credentials"},
		{".aws/config", "AWS configuration"},
		{".gcp/credentials", "GCP credentials"},
		{".azure/credentials", "Azure credentials"},
		{"service-account.json", "service account key"},
		{"kubeconfig", "Kubernetes config"},
		{".kube/config", "Kubernetes config"},
		{".docker/config.json", "Docker credentials"},
		{".npmrc", "npm credentials"},
		{".gitconfig", "git configuration"},
		{".netrc", "netrc credentials"},
		{".pgpass", "PostgreSQL password file"},
		{"pgpass.conf", "PostgreSQL password file"},
		{".my.cnf", "MySQL configuration"},
		{".mysql_history", "MySQL history"},
		{".bash_history", "Bash history"},
		{".zsh_history", "Zsh history"},
		{"id_rsa", "SSH private key"},
		{"id_ed25519", "SSH private key"},
		{"id_dsa", "SSH private key"},
		{"id_ecdsa", "SSH private key"},
		{"authorized_keys", "SSH authorized keys"},
	}

	for _, f := range criticalFiles {
		if strings.Contains(pathLower, f.pattern) {
			severity := "critical"
			category := "sensitive_file_read"
			message := fmt.Sprintf("file path contains '%s': %s", f.pattern, f.message)

			if isWrite {
				category = "sensitive_file_write"
				message = fmt.Sprintf("attempting to WRITE sensitive file '%s': %s", f.pattern, f.message)
			}
			if isDelete {
				category = "sensitive_file_delete"
				message = fmt.Sprintf("attempting to DELETE sensitive file '%s': %s", f.pattern, f.message)
			}

			findings = append(findings, ToolCallRiskFinding{
				Severity: severity,
				Category: category,
				Message:  message,
			})
		}
	}

	// 高风险：系统目录
	systemDirs := []struct {
		pattern string
		message string
	}{
		{"/etc/", "system configuration directory"},
		{"/var/log/", "system log directory"},
		{"/var/lib/", "system library directory"},
		{"/usr/bin/", "system binary directory"},
		{"/usr/sbin/", "system admin binary directory"},
		{"/bin/", "system binary directory"},
		{"/sbin/", "system admin binary directory"},
		{"/root/", "root user home directory"},
		{"/home/", "user home directory (accessing other users)"},
		{"/proc/", "process information directory"},
		{"/sys/", "system information directory"},
		{"/dev/", "device directory"},
		{"/boot/", "boot directory"},
		{"/lib/", "system library directory"},
		{"/lib64/", "system library directory"},
	}

	for _, d := range systemDirs {
		if strings.HasPrefix(pathLower, d.pattern) {
			severity := "high"
			category := "system_directory"
			message := fmt.Sprintf("file path in system directory '%s': %s", d.pattern, d.message)

			if isWrite || isDelete {
				severity = "critical"
				category = "system_directory_modify"
				message = fmt.Sprintf("attempting to MODIFY/DELETE in system directory '%s': %s", d.pattern, d.message)
			}

			findings = append(findings, ToolCallRiskFinding{
				Severity: severity,
				Category: category,
				Message:  message,
			})
		}
	}

	// 中风险：项目敏感目录
	projectSensitive := []struct {
		pattern string
		message string
	}{
		{"config/secrets", "project secrets directory"},
		{"config/credentials", "project credentials directory"},
		{"secrets/", "secrets directory"},
		{"credentials/", "credentials directory"},
		{".secrets/", "secrets directory"},
		{".credentials/", "credentials directory"},
		{"private/", "private directory"},
		{"internal/", "internal directory"},
	}

	for _, p := range projectSensitive {
		if strings.Contains(pathLower, p.pattern) {
			findings = append(findings, ToolCallRiskFinding{
				Severity: "high",
				Category: "project_sensitive",
				Message:  fmt.Sprintf("file path in project sensitive directory '%s': %s", p.pattern, p.message),
			})
		}
	}

	// 检查隐藏文件（以 . 开头）
	if strings.Contains(path, "/.") && !strings.Contains(pathLower, ".git/") {
		findings = append(findings, ToolCallRiskFinding{
			Severity: "medium",
			Category: "hidden_file",
			Message:  "file path contains hidden file (dot prefix)",
		})
	}

	return findings
}

// SSEChunk represents an SSE chat completion chunk for proper JSON serialization
type SSEChunk struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []SSEChoice `json:"choices,omitempty"`
	// Usage 用于回放末帧携带累积 usage(stream_options.include_usage 语义)。
	Usage *Usage `json:"usage,omitempty"`
}

type SSEChoice struct {
	Index        int      `json:"index"`
	Delta        SSEDelta `json:"delta,omitempty"`
	FinishReason string   `json:"finish_reason,omitempty"`
}

type SSEDelta struct {
	Role             string             `json:"role,omitempty"`
	Content          string             `json:"content,omitempty"`
	ReasoningContent string             `json:"reasoning_content,omitempty"`
	ToolCalls        []SSEToolCallDelta `json:"tool_calls,omitempty"`
}

type SSEToolCallDelta struct {
	Index    int                 `json:"index"`
	ID       string              `json:"id,omitempty"`
	Type     string              `json:"type,omitempty"`
	Function SSEToolCallFunction `json:"function,omitempty"`
}

type SSEToolCallFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

func buildSSEDelta(message ChoiceMessage) SSEDelta {
	delta := SSEDelta{
		Role:             "assistant",
		Content:          message.Content,
		ReasoningContent: message.ReasoningContent,
	}
	if len(message.ToolCalls) == 0 {
		return delta
	}

	delta.ToolCalls = make([]SSEToolCallDelta, 0, len(message.ToolCalls))
	for i, toolCall := range message.ToolCalls {
		delta.ToolCalls = append(delta.ToolCalls, SSEToolCallDelta{
			Index: i,
			ID:    toolCall.ID,
			Type:  toolCall.Type,
			Function: SSEToolCallFunction{
				Name:      toolCall.Function.Name,
				Arguments: toolCall.Function.Arguments,
			},
		})
	}
	return delta
}

// writeSSEData writes a standard SSE data line (OpenAI-compatible format)
func writeSSEData(w http.ResponseWriter, data string) {
	fmt.Fprintf(w, "data: %s\n\n", data) // nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter -- SSE data is JSON-encoded upstream before framing.
}

func writeGatewayJSONBody(w http.ResponseWriter, body []byte) {
	_, _ = w.Write(body) // #nosec G104,G705 // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- gateway intentionally relays JSON API bodies, never browser-rendered HTML.
}

// writeSSEError writes an error as SSE event using proper JSON serialization
func writeSSEError(w http.ResponseWriter, requestID, code, message string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	errorPayload := map[string]interface{}{
		"error": map[string]string{
			"code":       code,
			"message":    message,
			"request_id": requestID,
		},
	}
	errorData, _ := json.Marshal(errorPayload)
	writeSSEData(w, string(errorData))
}

// === ResponsesHandler ===

// ResponsesRequest represents the minimal supported subset of OpenAI Responses API
type ResponsesRequest struct {
	Model              string                 `json:"model"`
	Input              interface{}            `json:"input"` // string or array of messages
	Instructions       string                 `json:"instructions,omitempty"`
	MaxOutputTokens    int                    `json:"max_output_tokens,omitempty"`
	Temperature        float64                `json:"temperature,omitempty"`
	TopP               *float64               `json:"top_p,omitempty"`
	Metadata           json.RawMessage        `json:"metadata,omitempty"`
	Store              *bool                  `json:"store,omitempty"`
	ParallelToolCalls  *bool                  `json:"parallel_tool_calls,omitempty"`
	Stream             bool                   `json:"stream,omitempty"`
	PromptCacheKey     string                 `json:"prompt_cache_key,omitempty"`
	PreviousResponseID string                 `json:"previous_response_id,omitempty"`
	ClientMetadata     map[string]interface{} `json:"client_metadata,omitempty"`
	Tools              []ResponsesTool        `json:"tools,omitempty"`
	ToolChoice         interface{}            `json:"tool_choice,omitempty"`
}

// ResponsesResponse represents the OpenAI Responses API response format
type ResponsesResponse struct {
	ID        string            `json:"id"`
	Object    string            `json:"object"`
	CreatedAt int64             `json:"created_at"`
	Status    string            `json:"status"`
	Model     string            `json:"model"`
	Output    []ResponsesOutput `json:"output"`
	Usage     *ResponsesUsage   `json:"usage"`
	Error     *ResponsesError   `json:"error,omitempty"`
	// IncompleteDetails 只在 status=incomplete 时出现（例如预算截断：reason=max_output_tokens）。
	IncompleteDetails *ResponsesIncompleteDetails `json:"incomplete_details,omitempty"`
}

type ResponsesIncompleteDetails struct {
	Reason string `json:"reason"`
}

type ResponsesOutput struct {
	ID        string             `json:"id,omitempty"`
	Type      string             `json:"type"`
	Status    string             `json:"status,omitempty"`
	Role      string             `json:"role,omitempty"`
	Text      string             `json:"text,omitempty"`
	Index     int                `json:"index,omitempty"`
	Content   []ResponsesContent `json:"content,omitempty"`
	CallID    string             `json:"call_id,omitempty"`
	Name      string             `json:"name,omitempty"`
	Arguments string             `json:"arguments,omitempty"`
}

type ResponsesContent struct {
	Type        string        `json:"type"`
	Text        string        `json:"text"`
	Annotations []interface{} `json:"annotations"`
}

type ResponsesUsage struct {
	InputTokens              int                          `json:"input_tokens"`
	OutputTokens             int                          `json:"output_tokens"`
	TotalTokens              int                          `json:"total_tokens"`
	InputTokensDetails       *ResponsesInputTokensDetails `json:"input_tokens_details,omitempty"`
	CacheCreationInputTokens int                          `json:"cache_creation_input_tokens,omitempty"`
}

type ResponsesInputTokensDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

// ResponsesHandler handles /v1/responses with injectable dependencies
type ResponsesHandler struct {
	cfg                    *config.Config
	modelResolver          ModelResolver
	rateLimiter            RateLimitChecker
	securityClient         SecurityChecker
	auditWriter            AuditWriter
	providerAdapterFactory ProviderAdapterFactory
	toolRiskClient         *ToolRiskClient
	proxyRateLimiter       ProxyRateLimiter
	governor               GovernorDecider
	quotaAdmission         QuotaAdmission
	db                     *pgxpool.Pool // for governor alert_inbox writes; may be nil
	modelRouteEngine       modelrouter.Engine
	billingPreflight       BillingPreflight
	fingerprints           *scanfp.Store // P1-B 已检指纹缓存（模块 2a）；nil=禁用（默认零回归）
	artifactStore          retentionstore.Store
	relayMetrics           *relay.Metrics
}

// SetGovernor injects a governor into the ResponsesHandler.
func (h *ResponsesHandler) SetGovernor(gov GovernorDecider) {
	h.governor = gov
}

func (h *ResponsesHandler) SetQuotaAdmission(admission QuotaAdmission) {
	h.quotaAdmission = admission
}

// SetDB injects the database pool for governor alert_inbox writes.
func (h *ResponsesHandler) SetDB(db *pgxpool.Pool) {
	h.db = db
}

func (h *ResponsesHandler) SetRetentionArtifactStore(store retentionstore.Store) {
	if h != nil {
		h.artifactStore = store
	}
}

func (h *ResponsesHandler) SetModelRoutingEngine(engine modelrouter.Engine) {
	h.modelRouteEngine = engine
}

func (h *ResponsesHandler) SetBillingPreflight(client BillingPreflight) { h.billingPreflight = client }

func (h *ResponsesHandler) SetRelayMetrics(metrics *relay.Metrics) { h.relayMetrics = metrics }

func (h *ResponsesHandler) newChatHandler() *ChatCompletionsHandler {
	chatHandler := NewChatCompletionsHandler(h.cfg, h.modelResolver, h.rateLimiter, h.securityClient, h.auditWriter, h.providerAdapterFactory, h.toolRiskClient, h.proxyRateLimiter)
	chatHandler.SetGovernor(h.governor)
	chatHandler.SetQuotaAdmission(h.quotaAdmission)
	chatHandler.SetDB(h.db)
	chatHandler.SetFingerprintStore(h.fingerprints)
	chatHandler.SetRouting(nil, nil, nil, h.modelRouteEngine)
	chatHandler.SetRetentionArtifactStore(h.artifactStore)
	chatHandler.SetBillingPreflight(h.billingPreflight)
	chatHandler.SetRelayMetrics(h.relayMetrics)
	return chatHandler
}

func NewResponsesHandler(
	cfg *config.Config,
	modelResolver ModelResolver,
	rateLimiter RateLimitChecker,
	securityClient SecurityChecker,
	auditWriter AuditWriter,
	providerAdapterFactory ProviderAdapterFactory,
	toolRiskClient *ToolRiskClient,
	proxyRateLimiter ProxyRateLimiter,
) *ResponsesHandler {
	if providerAdapterFactory == nil {
		factory := &RealProviderAdapterFactory{}
		if cfg != nil {
			factory.StreamIdleTimeout = cfg.UpstreamStreamIdleTimeout
		}
		providerAdapterFactory = factory
	}
	return &ResponsesHandler{
		cfg:                    cfg,
		modelResolver:          modelResolver,
		rateLimiter:            rateLimiter,
		securityClient:         securityClient,
		auditWriter:            auditWriter,
		providerAdapterFactory: providerAdapterFactory,
		toolRiskClient:         toolRiskClient,
		proxyRateLimiter:       proxyRateLimiter,
	}
}

func (h *ResponsesHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		authInfo := auth.GetAuthInfo(r)
		startedAt := time.Now()
		ctx := withBlockLedger(r.Context())

		bodyLimit := apiRequestBodyLimitBytes(h.cfg)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
		if err != nil {
			envelope := buildPartialEnvelope(requestID, authInfo, "", "responses")
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				logRequestBodyTooLarge(r, requestID, bodyLimit)
				recordEarlyRequestFailure(ctx, h.auditWriter, envelope, w, "request_too_large", "request body too large", requestID, startedAt, http.StatusRequestEntityTooLarge)
				return
			}
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", "failed to read request body", requestID, startedAt)
			return
		}

		var req ResponsesRequest
		if err := json.Unmarshal(body, &req); err != nil {
			envelope := buildPartialEnvelope(requestID, authInfo, req.Model, "responses")
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", "invalid JSON format", requestID, startedAt)
			return
		}

		chatReq, err := h.convertToChatRequest(&req)
		if err != nil {
			envelope := buildPartialEnvelope(requestID, authInfo, req.Model, "responses")
			recordEarlyBadRequest(ctx, h.auditWriter, envelope, w, "invalid_request", err.Error(), requestID, startedAt)
			return
		}

		preflightChatBody, _ := json.Marshal(chatReq)
		chatReq.DeferProviderTransform = true
		chatHandler := h.newChatHandler()

		result, err := chatHandler.processSharedRequestPath(ctx, w, r, requestID, authInfo, startedAt, chatReq, body)
		if err != nil {
			return
		}
		if result.Envelope.QuotaHeartbeatStop != nil {
			defer result.Envelope.QuotaHeartbeatStop()
		}

		if result.ConcurrencyAcquired {
			defer h.rateLimiter.ReleaseConcurrency(ctx, result.Envelope.ProjectID)
		}

		if result.SecurityReply != nil {
			chatBody := chatHandler.finalizeSecurityReply(ctx, result)
			responsesResp := h.transformChatToResponsesResponse(chatBody, requestID)
			setRoutingHeaders(w, result.Envelope, false)
			setSecurityReplyHeaders(w, result.SecurityReply, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
			if req.Stream {
				_ = writeResponsesStream(w, responsesResp)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(responsesResp)
			return
		}

		if result.UseV2ModelRouting {
			plan, applied, planErr := h.modelRouteEngine.Plan(ctx, *result.Envelope)
			if plan.Decision != nil {
				result.Envelope.RoutingDecision = plan.Decision
			}
			if planErr != nil || !applied {
				result.Envelope.RejectReason = plannedRouteRejectReason(plan, planErr, applied)
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesError(w, req.Stream, requestID, "model_route_unavailable", routeUnavailableMessage(result.Envelope))
				return
			}
			result.PreparedModelRoutePlan = &plan
			result.ResponsesNative = routePlanSupportsNativeResponses(plan)
		}

		if result.ResponsesNative {
			// 简写名被补全成全名后 chatReq.Model 已变，而 preflightChatBody 是用客户端原始写法序列化的；
			// 直接比较会永远不相等，走进有损重建分支（图片/文件块被换成纯文本、数字被 float64 转写）。
			// 所以比较时用客户端原始模型名，只比内容；最后再把结果里的 model 改成全名。
			aliased := result.Envelope.ModelResolution == modelResolutionSuffixAlias
			securedForCompare := chatReq
			if aliased {
				copyReq := *chatReq
				copyReq.Model = result.Envelope.ClientModel
				securedForCompare = &copyReq
			}
			securedNativeBody, secureErr := securedNativeResponsesBody(body, preflightChatBody, securedForCompare)
			if secureErr == nil && aliased {
				securedNativeBody, secureErr = rewriteRequestBodyModel(securedNativeBody, result.Envelope.Model)
			}
			if secureErr != nil {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesError(w, req.Stream, requestID, "invalid_request", "failed to apply input security to Responses request")
				return
			}
			// 预算断流开启时收紧 max_output_tokens（只收紧不放大）；未下发上限时请求体逐字节不变。
			if limit, capped := billingOutputTokenCap(chatHandler.billingPreflight, result.Envelope.RequestID); capped {
				if cappedBody, changed, capErr := capResponsesRequestOutputTokens(securedNativeBody, limit); capErr == nil && changed {
					securedNativeBody = cappedBody
				}
			}
			h.handleNativeResponses(ctx, w, requestID, startedAt, req.Stream, securedNativeBody, chatReq, result)
			return
		}
		if result.ModelRecord != nil && result.ModelRecord.ProtocolCapabilities.Explicit && !modelRouteSupportsEndpoint(*result.ModelRecord, "responses") {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "responses_native_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeNativeResponsesError(w, req.Stream, requestID, "responses_native_unavailable", "configured upstream route does not support native Responses")
			return
		}
		if requiresNativeResponses(body) {
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "responses_native_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
			writeNativeResponsesError(w, req.Stream, requestID, "responses_native_unavailable", "requested Responses features require an explicitly native-capable route")
			return
		}

		result.SecuredBody, err = coalesceResponsesToolCalls(result.SecuredBody)
		if err != nil {
			writeErrorResponse(w, "invalid_request", "failed to normalize Responses tool turns", requestID)
			return
		}
		streamingUpstream := chatHandler.upstreamStreamingEnabled()

		// 先攒后发期间的连接保活（GATEWAY_STREAM_KEEPALIVE_INTERVAL，0 关闭；只对流式请求生效）。
		// 兼容转换路径不走上游实时流，保活从调上游之前一直覆盖到输出扫描结束；期间 handler 不写 w，
		// Stop 返回后才独占 w。头已由保活发出（状态码固定 200）后，错误/拦截改走 Responses 的 SSE 失败事件。
		var keepalive *keepaliveSession
		if interval := streamKeepaliveIntervalOf(h.cfg); req.Stream && interval > 0 {
			keepaliveAction := result.InputSecurityAction
			keepaliveActionHeader := securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient)
			keepalive = newKeepaliveSession(w, interval, defaultStreamKeepaliveSpec(), func() {
				w.Header().Set("X-Request-ID", requestID)
				setSecurityActionHeader(w, keepaliveAction, keepaliveActionHeader)
			})
		}
		defer keepalive.Stop()

		responseCaller := result.ProviderCaller
		fallbackUsed := false
		var respBody []byte
		if result.UseV2ModelRouting {
			keepalive.Start()
			routeResult, routeErr := executeModelRoutePlan(ctx, modelRouteExecutionInput{Engine: h.modelRouteEngine, CredentialResolver: h.modelResolver, Factory: h.providerAdapterFactory, Envelope: result.Envelope, SecuredBody: result.SecuredBody, Streaming: streamingUpstream, PreparedPlan: result.PreparedModelRoutePlan})
			err = routeErr
			if routeResult != nil {
				responseCaller = routeResult.Caller
				respBody = routeResult.ResponseBody
				fallbackUsed = routeResult.UsedFallback
			}
		} else {
			if len(result.ProviderReq) == 0 {
				result.ProviderReq, err = result.ProviderCaller.TransformRequest(result.Envelope, result.SecuredBody)
				if err != nil {
					h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "invalid_request", http.StatusBadRequest, int(time.Since(startedAt)/time.Millisecond), nil)
					writeErrorResponse(w, "invalid_request", "failed to transform request for provider", requestID)
					return
				}
			}
			keepalive.Start()
			respBody, err = callUpstream(ctx, result.ProviderCaller, result.Envelope, result.ProviderReq, streamingUpstream)
			if err != nil {
				fallbackResult := attemptFallbackCall(ctx, result.Envelope, result.SecuredBody, err, result.FallbackProvider, streamingUpstream)
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
			// 头是否已由保活发出：已发出时下面原本写 JSON 错误的分支改发 SSE 失败事件（审计口径不变）。
			headersCommitted := keepalive.Stop()
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesErrorWithStatus(w, req.Stream, requestID, "request_canceled", "request was canceled", http.StatusRequestTimeout)
				return
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_timeout", http.StatusGatewayTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesErrorWithStatus(w, req.Stream, requestID, "provider_timeout", "upstream provider timed out", http.StatusGatewayTimeout)
				return
			}
			if errors.Is(err, errUserModelForbidden) {
				result.Envelope.RejectReason = modelDenialRejectReason(ctx, result.Envelope.Model)
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "forbidden_model", http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesError(w, headersCommitted, requestID, "forbidden_model", modelDeniedMessage(ctx, result.Envelope.Model))
				return
			}
			if errors.Is(err, errModelRouteUnavailable) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "model_route_unavailable", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesError(w, headersCommitted, requestID, "model_route_unavailable", routeUnavailableMessage(result.Envelope))
				return
			}
			// Check if this is an upstream HTTP error (4xx/5xx from provider)
			if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_error", upstreamErr.StatusCode, int(time.Since(startedAt)/time.Millisecond), nil)
				if headersCommitted {
					logUpstreamHTTPError(requestID, "upstream_response", upstreamErr)
					_ = writeResponsesStreamFailure(w, "resp_"+strings.ReplaceAll(requestID, "-", ""), "upstream_error", clientUpstreamErrorMessage(upstreamErr, "upstream request failed"))
					return
				}
				writeUpstreamErrorResponse(w, upstreamErr, requestID, "upstream_response")
				return
			}

			// Other errors (network, timeout, etc.)
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			if req.Stream {
				_ = writeResponsesStreamFailure(w, "resp_"+strings.ReplaceAll(requestID, "-", ""), "provider_unavailable", "upstream provider is unavailable")
				return
			}
			writeErrorResponse(w, "provider_unavailable", "upstream provider is unavailable", requestID)
			return
		}

		openaiResp, err := transformProviderResponse(responseCaller, result.Envelope, respBody)
		if err != nil {
			headersCommitted := keepalive.Stop()
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "provider_unavailable", http.StatusBadGateway, int(time.Since(startedAt)/time.Millisecond), nil)
			writeNativeResponsesError(w, headersCommitted, requestID, "provider_unavailable", "failed to parse response")
			return
		}

		upstreamResp := openaiResp // 扫描失败时 applyOutputSecurity 返回 nil，先留住上游响应供断开收尾解析 usage
		openaiResp, auditResult, err := chatHandler.applyOutputSecurity(ctx, result.Envelope, chatReq.Messages, openaiResp)
		// 输出扫描（含语义裁判）结束，保活停止；此后 handler 独占 w。
		headersCommitted := keepalive.Stop()
		if err != nil {
			// 客户端在输出扫描期间已断开（Esc / 中断）：没有响应可放行也没有响应可拦截，
			// 按 client_canceled 收尾，不记 security_blocked，不写拦截帧。收尾带上上游响应，
			// 让结算按真实 usage 走（正文只用于解析 usage，不写给客户端，不写内容日志，不落库）。
			if clientGoneDuring(ctx, err) {
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, upstreamResp, "client_canceled", http.StatusRequestTimeout, int(time.Since(startedAt)/time.Millisecond), nil)
				writeNativeResponsesErrorWithStatus(w, req.Stream, requestID, "request_canceled", "request was canceled", http.StatusRequestTimeout)
				return
			}
			if headersCommitted && isGuardrailDetectionUnavailable(err) {
				// 头已由保活发出：fail-closed 的 503 无法再写，改发 SSE 失败事件；审计仍记 security_blocked/503。
				h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "security_blocked", http.StatusServiceUnavailable, int(time.Since(startedAt)/time.Millisecond), auditResult)
				_ = writeResponsesStreamFailure(w, "resp_"+strings.ReplaceAll(requestID, "-", ""), guardrailDetectionUnavailableCode, guardrailDetectionUnavailableMessage)
				return
			}
			if rejectGuardrailDetectionUnavailable(ctx, w, h.auditWriter, result.Envelope, requestID, startedAt, auditResult, securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient), err) {
				return
			}
			notice := chatHandler.blockNoticeForResponse(ctx, result.Envelope, "output", err.Error())
			h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, nil, "security_blocked", blockHTTPStatus(notice), int(time.Since(startedAt)/time.Millisecond), auditResult)
			h.writeResponsesBlockResponse(w, chatHandler, result.Envelope, requestID, req.Stream, notice)
			return
		}

		chatHandler.writeResponseContentLogs(ctx, result.Envelope, openaiResp)
		h.auditWriter.FinalizeRequestLog(ctx, result.Envelope, openaiResp, "success", http.StatusOK, int(time.Since(startedAt)/time.Millisecond), auditResult)
		chatHandler.recordPromptCacheMetrics(openaiResp)

		responsesResp := h.transformChatToResponsesResponse(deliverResponseBody(ctx, h.toolRiskClient, result.Envelope, openaiResp), requestID)
		// 保活已发头时不再设置路由头和 X-Security-Action（慢请求拿不到输出阶段的安全动作与路由头）。
		if !headersCommitted {
			setRoutingHeaders(w, result.Envelope, fallbackUsed)
			setSecurityActionHeader(w, strongerSecurityAction(result.InputSecurityAction, outputActionOf(auditResult)), securityActionHeaderEnabledForRuntime(ctx, h.cfg, h.toolRiskClient))
		}
		if req.Stream {
			_ = writeResponsesStream(w, responsesResp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responsesResp)
	}
}

func (h *ResponsesHandler) convertToChatRequest(req *ResponsesRequest) (*ChatCompletionRequest, error) {
	messages := []Message{}

	if req.Instructions != "" {
		messages = append(messages, Message{
			Role:           "system",
			Content:        jsonQuote(req.Instructions),
			SecuritySource: "system_prompt", SecurityMessageRole: "system", SecuritySourcePath: "/instructions",
		})
	}

	switch v := req.Input.(type) {
	case string:
		if v == "" {
			return nil, fmt.Errorf("input must not be empty")
		}
		messages = append(messages, Message{
			Role:                 "user",
			Content:              jsonQuote(v),
			SecurityMessageIndex: protocolMessageIndex(0), SecurityMessageRole: "user", SecuritySourcePath: "/input",
		})
	case []interface{}:
		for messageIndex, item := range v {
			if msg, ok := item.(map[string]interface{}); ok {
				itemType, _ := msg["type"].(string)
				if itemType == "function_call_output" || strings.HasSuffix(itemType, "_call_output") {
					callID, _ := msg["call_id"].(string)
					if callID == "" {
						callID, _ = msg["id"].(string)
					}
					output := responsesValueText(msg["output"])
					if callID != "" {
						messages = append(messages, Message{
							Role: "tool", ToolCallID: callID, Content: jsonQuote(output),
							SecuritySource: "tool_result", SecurityMessageIndex: protocolMessageIndex(messageIndex), SecurityMessageRole: "tool", SecuritySourcePath: fmt.Sprintf("/input/%d", messageIndex),
						})
					}
					continue
				}
				if strings.HasSuffix(itemType, "_call") {
					callID, _ := msg["call_id"].(string)
					if callID == "" {
						callID, _ = msg["id"].(string)
					}
					name, _ := msg["name"].(string)
					if name == "" {
						name = itemType
					}
					arguments, _ := msg["arguments"].(string)
					if arguments == "" {
						arguments = responsesValueText(msg["input"])
					}
					if arguments == "" {
						arguments = responsesValueText(msg["action"])
					}
					if callID != "" && name != "" {
						messages = append(messages, Message{
							Role:           "assistant",
							SecuritySource: "assistant_history", SecurityMessageIndex: protocolMessageIndex(messageIndex), SecurityMessageRole: "assistant", SecuritySourcePath: fmt.Sprintf("/input/%d", messageIndex),
							ToolCalls: []ToolCall{{ID: callID, Type: "function",
								Function: ToolCallFunc{Name: name, Arguments: arguments}}},
						})
					}
					continue
				}
				role, _ := msg["role"].(string)
				if role == "" {
					continue
				}
				switch content := msg["content"].(type) {
				case string:
					if content == "" {
						continue
					}
					messages = append(messages, Message{
						Role:                 role,
						Content:              jsonQuote(content),
						SecurityMessageIndex: protocolMessageIndex(messageIndex), SecurityMessageRole: role, SecuritySourcePath: fmt.Sprintf("/input/%d", messageIndex),
					})
				case []interface{}:
					raw, marshalErr := json.Marshal(responsesContentToChat(content))
					if marshalErr != nil || len(content) == 0 {
						continue
					}
					messages = append(messages, Message{Role: role, Content: json.RawMessage(raw), SecurityMessageIndex: protocolMessageIndex(messageIndex), SecurityMessageRole: role, SecuritySourcePath: fmt.Sprintf("/input/%d", messageIndex)})
				}
			} else if text, ok := item.(string); ok {
				if text != "" {
					messages = append(messages, Message{
						Role:                 "user",
						Content:              jsonQuote(text),
						SecurityMessageIndex: protocolMessageIndex(messageIndex), SecurityMessageRole: "user", SecuritySourcePath: fmt.Sprintf("/input/%d", messageIndex),
					})
				}
			}
		}
	default:
		return nil, fmt.Errorf("input must be a string or array of messages")
	}

	if len(messages) == 0 {
		return nil, fmt.Errorf("no valid messages in input")
	}

	tools := make([]ToolDef, 0, len(req.Tools))
	for _, tool := range req.Tools {
		if tool.Type != "function" || tool.Name == "" {
			continue
		}
		tools = append(tools, ToolDef{
			Type: "function",
			Function: ToolFunc{
				Name: tool.Name, Description: tool.Description, Parameters: tool.Parameters,
				Strict: tool.Strict,
			},
		})
	}
	evidenceKey, evidenceSource := responsesEvidenceCorrelation(req)

	return &ChatCompletionRequest{
		Model:                      req.Model,
		EndpointType:               "responses",
		Messages:                   messages,
		Tools:                      tools,
		ToolChoice:                 responsesToolChoiceToChat(req.ToolChoice),
		MaxTokens:                  req.MaxOutputTokens,
		Temperature:                req.Temperature,
		TopP:                       req.TopP,
		Metadata:                   req.Metadata,
		Store:                      req.Store,
		ParallelToolCalls:          req.ParallelToolCalls,
		Stream:                     false,
		PromptCacheKey:             req.PromptCacheKey,
		EvidenceCorrelationKey:     evidenceKey,
		EvidenceCorrelationSource:  evidenceSource,
		ToolCorrelationCandidate:   len(req.Tools) > 0,
		ToolCorrelationContextHash: responsesToolCorrelationContextHash(req),
	}, nil
}

func responsesValueText(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func (h *ResponsesHandler) transformChatToResponsesResponse(chatRespBody []byte, requestID string) *ResponsesResponse {
	var chatResp ChatCompletionResponse
	_ = json.Unmarshal(chatRespBody, &chatResp)

	output := []ResponsesOutput{}
	status := "completed"
	var incomplete *ResponsesIncompleteDetails
	for i, choice := range chatResp.Choices {
		itemStatus := "completed"
		if choice.FinishReason == "length" || choice.FinishReason == "content_filter" {
			status, itemStatus = "incomplete", "incomplete"
			reason := choice.FinishReason
			if reason == "length" {
				reason = "max_output_tokens"
			}
			incomplete = &ResponsesIncompleteDetails{Reason: reason}
		}
		if choice.Message.Content != "" {
			output = append(output, ResponsesOutput{
				ID:     fmt.Sprintf("msg_%s_%d", strings.ReplaceAll(requestID, "-", ""), i),
				Type:   "message",
				Status: itemStatus,
				Role:   "assistant",
				Content: []ResponsesContent{{
					Type: "output_text", Text: choice.Message.Content, Annotations: []interface{}{},
				}},
			})
		}
		for j, toolCall := range choice.Message.ToolCalls {
			output = append(output, ResponsesOutput{
				ID:        fmt.Sprintf("fc_%s_%d_%d", strings.ReplaceAll(requestID, "-", ""), i, j),
				Type:      "function_call",
				Status:    "completed",
				CallID:    toolCall.ID,
				Name:      toolCall.Function.Name,
				Arguments: toolCall.Function.Arguments,
			})
		}
	}

	responseID := chatResp.ID
	if responseID == "" {
		responseID = "resp_" + strings.ReplaceAll(requestID, "-", "")
	}
	responseUsage := &ResponsesUsage{
		InputTokens:              chatResp.Usage.PromptTokens,
		OutputTokens:             chatResp.Usage.CompletionTokens,
		TotalTokens:              chatResp.Usage.TotalTokens,
		CacheCreationInputTokens: chatResp.Usage.CacheCreationInputTokens,
	}
	if chatResp.Usage.CacheReadInputTokens > 0 {
		responseUsage.InputTokensDetails = &ResponsesInputTokensDetails{CachedTokens: chatResp.Usage.CacheReadInputTokens}
	}
	return &ResponsesResponse{
		ID:                responseID,
		Object:            "response",
		CreatedAt:         chatResp.Created,
		Status:            status,
		IncompleteDetails: incomplete,
		Model:             chatResp.Model,
		Output:            output,
		Usage:             responseUsage,
	}
}

// === Error handling ===

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	RequestID      string `json:"request_id"`
	Action         string `json:"action,omitempty"`
	Stage          string `json:"stage,omitempty"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	Metric         string `json:"metric,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Limit          *int64 `json:"limit,omitempty"`
	Used           *int64 `json:"used,omitempty"`
	Reserved       *int64 `json:"reserved,omitempty"`
	Requested      *int64 `json:"requested,omitempty"`
	RetryAfter     *int64 `json:"retry_after,omitempty"`
}

func writeErrorResponse(w http.ResponseWriter, code, message, requestID string) {
	writeErrorResponseWithStatus(w, code, message, requestID, getStatusCode(code))
}

func writeErrorResponseWithStatus(w http.ResponseWriter, code, message, requestID string, status int) {
	w.Header().Set("Content-Type", "application/json")
	if requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	w.WriteHeader(status)

	resp := ErrorResponse{
		Error: ErrorDetail{
			Code:      code,
			Message:   message,
			RequestID: requestID,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// logUpstreamHTTPError 把上游 4xx/5xx 的错误正文落到服务端日志。客户端只会拿到
// 脱敏后的 "upstream request failed"，不记这一行就没人知道上游到底拒了什么
// （例如 "max_tokens: 1000000 > 128000"），排障只能去翻上游日志。
func logUpstreamHTTPError(requestID, stage string, upstreamErr *provider.UpstreamHTTPError) {
	if upstreamErr == nil {
		return
	}
	message := upstreamErr.Message
	if strings.TrimSpace(message) == "" {
		message = string(upstreamErr.Body)
	}
	log.Printf("[provider.error] request_id=%s stage=%s status=%d message=%q", requestID, stage, upstreamErr.StatusCode, boundedUpstreamErrorMessage(message))
}

func writeUpstreamErrorResponse(w http.ResponseWriter, upstreamErr *provider.UpstreamHTTPError, requestID, stage string) {
	status := http.StatusBadGateway
	if upstreamErr != nil {
		status = upstreamErr.StatusCode
	}
	// 与原生 Messages 同一口径：请求类白名单透传定点遮盖后的原文，账号和服务故障返回中文解释。
	message := clientUpstreamErrorMessage(upstreamErr, "upstream request failed")
	logUpstreamHTTPError(requestID, stage, upstreamErr)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("X-JJDGuard-Error-Stage", stage)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: ErrorDetail{
		Code:           "upstream_error",
		Message:        message,
		RequestID:      requestID,
		Stage:          stage,
		UpstreamStatus: status,
	}})
}

func getStatusCode(code string) int {
	switch code {
	case "unauthorized", "key_revoked", "key_expired":
		return http.StatusUnauthorized
	case "forbidden_model", "key_model_not_allowed", "security_blocked":
		return http.StatusForbidden
	case "tool_blocked":
		// 审计侧（chatInputSecurityResult.httpStatus）一直记 403，此前响应走 default 500 与审计不一致
		return http.StatusForbidden
	case "quota_exceeded", "rate_limited", "concurrency_limit":
		return http.StatusTooManyRequests
	case "stream_not_supported":
		return http.StatusBadRequest
	case "request_too_large":
		return http.StatusRequestEntityTooLarge
	case "invalid_request":
		return http.StatusBadRequest
	case "provider_unsupported":
		return http.StatusBadRequest
	case "not_implemented":
		return http.StatusNotImplemented
	case "model_not_found":
		return http.StatusNotFound
	case "model_not_configured", "provider_not_configured":
		return http.StatusServiceUnavailable
	case "model_route_unavailable", "responses_native_unavailable":
		return http.StatusServiceUnavailable
	case guardrailDetectionUnavailableCode:
		return http.StatusServiceUnavailable
	case "provider_unavailable":
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// === ModelsHandler for /v1/models endpoint ===

// ModelInfo represents a model in the OpenAI-compatible response
type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

// ModelsResponse is the OpenAI-compatible models list response
type ModelsResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

// ModelsHandler provides DB-backed /v1/models endpoint
type ModelsHandler struct {
	db       *pgxpool.Pool
	governor GovernorDecider
}

// NewModelsHandler creates a new models handler with database dependency
func NewModelsHandler(db *pgxpool.Pool) *ModelsHandler {
	return &ModelsHandler{db: db}
}

func (h *ModelsHandler) SetGovernor(decider GovernorDecider) { h.governor = decider }

// Handler returns the HTTP handler function for listing models
func (h *ModelsHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authInfo := auth.GetAuthInfo(r)
		if authInfo == nil || authInfo.TenantID == "" {
			writeErrorResponseWithStatus(w, "unauthorized", "authentication required", uuid.NewString(), http.StatusUnauthorized)
			return
		}
		available, err := modelcatalog.Load(r.Context(), h.db, authInfo.TenantID)
		if err != nil {
			writeErrorResponse(w, "internal_error", "failed to query current models", uuid.NewString())
			return
		}
		router := modelrouter.NewModelRouter(h.db)
		policy, err := router.GetModelPolicy(r.Context(), authInfo.ProjectID)
		if err != nil {
			writeErrorResponse(w, "internal_error", "failed to read model permissions", uuid.NewString())
			return
		}
		teamID, err := router.GetProjectTeamID(r.Context(), authInfo.ProjectID)
		if err != nil {
			writeErrorResponse(w, "internal_error", "failed to read model authorization context", uuid.NewString())
			return
		}
		requested := strings.TrimSpace(chi.URLParam(r, "model"))
		names := map[string]ModelInfo{}
		for _, item := range available {
			if !item.Callable || (!auth.UserModelAccessEnforced(r.Context()) && !policy.IsModelAllowed(item.Name)) || !auth.UserModelVisible(r.Context(), item.Name) {
				continue
			}
			if decider, ok := h.governor.(governorNonRealtimeDecider); ok {
				decision := decider.DecideNonRealtime(r.Context(), governor.ScopeRef{UserModelAccessEnforced: auth.UserModelAccessEnforced(r.Context()), TenantID: authInfo.TenantID, ProjectID: authInfo.ProjectID, TeamID: teamID, UserID: authInfo.UserID, KeyID: authInfo.KeyID, ModelID: item.ID, ModelName: item.Name})
				if decision.Action != governor.ActionNone && !decision.AlertOnly {
					continue
				}
			}
			if requested != "" && item.Name != requested {
				continue
			}
			if current, ok := names[item.Name]; ok && current.OwnedBy <= item.ProviderType {
				continue
			}
			names[item.Name] = ModelInfo{ID: item.Name, Object: "model", OwnedBy: item.ProviderType}
		}
		if requested != "" {
			item, ok := names[requested]
			if !ok {
				writeErrorResponseWithStatus(w, "model_not_found", "model not found", uuid.NewString(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(item)
			return
		}
		models := make([]ModelInfo, 0, len(names))
		for _, item := range names {
			models = append(models, item)
		}
		sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ModelsResponse{Object: "list", Data: models})
	}
}

// ===== Pre-parse/pre-process 400 Bad Request helpers =====
// These helpers unify the session+audit contract for early 400 failures.
// IMPORTANT: These helpers ONLY apply to pre-parse/pre-process failures that return 400 Bad Request.
// Do NOT use for 403 Forbidden, 429 Too Many Requests, 503 Service Unavailable, or any non-400 response.

// buildPartialEnvelope creates a RequestEnvelope for pre-parse/pre-process failure recording.
// model is optional (may be empty string for body-read failures before parsing).
func buildPartialEnvelope(requestID string, authInfo *auth.AuthInfo, model string, endpointType string) *modelrouter.RequestEnvelope {
	return buildChatPartialEnvelope(requestID, authInfo, model, endpointType)
}

// recordEarlyBadRequest handles session upsert + request log + error response for pre-parse/pre-process 400 failures.
// errorCode is the audit status (e.g., "invalid_request", "stream_not_supported").
// message is the human-readable error message.
// This helper ALWAYS writes HTTP 400 Bad Request - do not use for other status codes.
func recordEarlyBadRequest(ctx context.Context, auditWriter AuditWriter, envelope *modelrouter.RequestEnvelope, w http.ResponseWriter, errorCode string, message string, requestID string, startedAt time.Time) {
	recordEarlyRequestFailure(ctx, auditWriter, envelope, w, errorCode, message, requestID, startedAt, http.StatusBadRequest)
}

func recordEarlyRequestFailure(ctx context.Context, auditWriter AuditWriter, envelope *modelrouter.RequestEnvelope, w http.ResponseWriter, errorCode string, message string, requestID string, startedAt time.Time, statusCode int) {
	if envelope.SessionID != "" {
		auditWriter.UpsertAgentSession(ctx, envelope)
	}
	auditWriter.EnsureRequestLog(ctx, envelope)
	auditWriter.FinalizeRequestLog(ctx, envelope, nil, errorCode, statusCode, int(time.Since(startedAt)/time.Millisecond), nil)
	writeErrorResponseWithStatus(w, errorCode, message, requestID, statusCode)
}
