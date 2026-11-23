package handler

// Interfaces for dependency injection - enables testing without real DB/Redis/HTTP calls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertcounter"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor/providers"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// ProviderCaller handles calling upstream providers.
// Note: This interface now includes TransformRequest for provider-specific request transformation.
// Call now receives envelope to determine endpoint type (chat, embeddings, etc.)
type ProviderCaller interface {
	TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error)
	Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error)
	// CallStreaming 向上游发 stream:true、边收 SSE 边累积, 返回与 Call 等价的上游原生格式完整响应体。
	// 下游 TransformResponse 照旧跑(Stage 2: 治长生成撞上游非流式 ~300s 上限)。
	CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error)
	TransformResponse(respBody []byte) ([]byte, error)
}

type contextualProviderResponseTransformer interface {
	TransformResponseForEnvelope(envelope *modelrouter.RequestEnvelope, respBody []byte) ([]byte, error)
}

func transformProviderResponse(caller ProviderCaller, envelope *modelrouter.RequestEnvelope, respBody []byte) ([]byte, error) {
	if transformer, ok := caller.(contextualProviderResponseTransformer); ok {
		return transformer.TransformResponseForEnvelope(envelope, respBody)
	}
	return caller.TransformResponse(respBody)
}

// Adapt only after capability selection, retaining the original ingress identity
// for security, metering and audit. Native passthrough keeps its concrete adapter.
func adaptProviderIngress(caller ProviderCaller, envelope *modelrouter.RequestEnvelope) ProviderCaller {
	adapter, ok := caller.(provider.ProviderAdapter)
	if !ok {
		return caller
	}
	return provider.AdaptIngress(adapter, envelope)
}

// ProviderAdapterFactory creates provider adapters based on model configuration.
// This enables mocking the entire provider call chain in tests.
type ProviderAdapterFactory interface {
	CreateAdapter(modelRecord *modelrouter.ModelRecord, apiKey string) ProviderCaller
}

// SecurityChecker handles input and output security checks
// messageIndex and messageRole provide context for input checks
// choiceIndex provides context for output checks
type SecurityChecker interface {
	CheckInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (action string, maskedContent string, findings []SecurityFinding, err error)
	CheckOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (action string, maskedContent string, findings []SecurityFinding, err error)
	// CheckSemanticOnly 只跑语义检测、仅返回语义 findings（输入侧语义异步旁路用）。
	// 由主链异步派发调用：content 为已拼接的输入文本，findings 与 CheckInput 同款转换。
	CheckSemanticOnly(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string) (findings []SecurityFinding, err error)
	// CheckTriage 把规则 findings 交 security-engine 做类型感知误报压制（异步旁路用）。
	// 返回同款 findings，意图类的填了 .Triage（pii/secret/code 永不被碰）。
	CheckTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, findings []SecurityFinding) ([]SecurityFinding, error)
}

// InputCheckOutcome 是 CheckInputDetailed 的完整结果：CheckInput 四元组之上附带
// 引擎回带的版本与原始 findings（P1-B 指纹缓存写入所需，契约 1）。
type InputCheckOutcome struct {
	RedactionMapping       map[string]string `json:"-"`
	Action                 string
	MaskedContent          string
	Findings               []SecurityFinding
	RawFindings            json.RawMessage
	RulePackVersion        string
	SemanticConfigRevision string
	SemanticStatus         string
	SemanticReason         string
	EngineBuild            string
	FileBindings           []security.FileBindingToken
}

// detailedInputChecker / contextReplayer 是可选能力接口（type-assert 探测，不并入
// SecurityChecker）——既有测试桩零改动，同 skipSemantic ctx-value 的最小涟漪先例。
type detailedInputChecker interface {
	// 签名与 P1-A 改造后的 SecurityChecker.CheckInput 对齐（末参 contentSource，契约 4）。
	CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error)
}

type InputCheckBatchItem struct {
	Context       context.Context
	Content       string
	MessageIndex  int
	MessageRole   string
	ContentSource string
}

type InputCheckBatchResult struct {
	Outcome *InputCheckOutcome
	Err     error
}

type detailedInputBatchChecker interface {
	CheckInputBatchDetailed(context.Context, *modelrouter.RequestEnvelope, []InputCheckBatchItem) ([]InputCheckBatchResult, error)
}

type semanticStageChecker interface {
	// CheckSemanticStage 只运行指定 input/agent 阶段的语义检测。
	CheckSemanticStage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, stage string) ([]SecurityFinding, error)
}

type contextReplayer interface {
	// ApplyContext 把缓存的原始 findings 交引擎 /apply-context/ 做上下文重放（契约 2/9）。
	ApplyContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, rawFindings json.RawMessage, contentSource string) (action string, findings []SecurityFinding, err error)
}

// SecurityFinding represents a security finding for handler layer
type SecurityFinding struct {
	Type                    string
	Severity                string
	Category                string
	MatchedTextPreview      string
	RuleID                  string
	Confidence              float64
	RuleName                string
	RuleType                string
	Action                  string
	PolicyCode              string
	PolicyScene             string
	SourceRuleID            string
	MatchedCapabilities     []string
	CountsAsSecurityFinding *bool
	MatchedLocation         string
	RedactedEvidence        string
	RawEvidence             string
	EvidenceContext         string
	// SecretText 是引擎标出的秘密本体（私钥正文、凭据取值）。2.9.22 起前后文按原样落库，它只用于
	// 按 2.9.21 的打码前后文算证据身份（见 putFindingEvidence），本身不落库、不写日志、不进通知、不进缓存键。
	SecretText string `json:"-"`
	// EvidenceLocation 是引擎给的、相对 EvidenceContext 所在那段内容的原始位置 content[起:止]，只用来截原文和前后文。
	// 流式输出分段检测会把 MatchedLocation 改写成整段输出的偏移（offsetStreamFinding），那时它保留段内位置。
	// 不落库、不进缓存键。
	EvidenceLocation string `json:"-"`
	EvidenceKind     string
	ContentSource    string
	EvidenceReason   string
	MessageIndex     *int
	MessageRole      string
	AttachmentIndex  *int
	// ExceptionID 命中的例外 ID（引擎侧规则例外豁免标注，空串=未豁免），端到端透传到 matched_summary。
	ExceptionID string
	Triage      map[string]any
}

// AuditResult holds security audit results for a request
type AuditResult struct {
	InputFindings    []map[string]interface{} `json:"input_findings"`
	InputAction      string                   `json:"input_action"`
	OutputFindings   []map[string]interface{} `json:"output_findings"`
	OutputAction     string                   `json:"output_action"`
	ResponseMetadata map[string]interface{}   `json:"response_metadata,omitempty"`
}

// RateLimitChecker handles rate limit and concurrency checks
type RateLimitChecker interface {
	CheckRPM(ctx context.Context, projectID string, rpmLimit int) (bool, error)
	CheckConcurrency(ctx context.Context, projectID string, concurrencyLimit int) (bool, int64, error)
	ReleaseConcurrency(ctx context.Context, projectID string) error
	CheckDailyTokenLimit(ctx context.Context, projectID string, dailyLimit int64) (bool, int64, error)
	CheckMonthlyTokenLimit(ctx context.Context, projectID string, monthlyLimit int64) (bool, int64, error)
	IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error
}

// AuditWriter handles request log and security event persistence
type AnchoredContentLogWriter interface {
	WriteContentLogAnchored(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens, messageIndex int)
}

type AuditWriter interface {
	EnsureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope)
	FinalizeRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte, status string, upstreamStatusCode int, latencyMs int, auditResult *AuditResult)
	WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string)
	WriteContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int)
	UpsertAgentSession(ctx context.Context, envelope *modelrouter.RequestEnvelope)
	// AnnotateTriage 异步回写：把带 triage 标注的 findings 序列化进该 request 最近一行
	// security_event 的 matched_summary（同步先写 event 留底，异步标注，observe-only）。
	AnnotateTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding)
}

// ModelResolver handles model and policy resolution
type ModelResolver interface {
	ResolveModelWithDB(ctx context.Context, tenantID, modelName string) (*modelrouter.ModelRecord, error)
	GetModelPolicy(ctx context.Context, projectID string) (*modelrouter.ModelPolicy, error)
	GetQuotaPolicy(ctx context.Context, projectID string) (*modelrouter.QuotaPolicy, error)
	GetProviderCredential(ctx context.Context, providerID string) (string, error)
	GetProvider(ctx context.Context, tenantID, providerID string) (*modelrouter.ProviderRecord, error)
	// GetProjectTeamID returns the team_id for the project (empty string if not set).
	// Used to populate RequestEnvelope.TeamID for team-scope governor checks.
	GetProjectTeamID(ctx context.Context, projectID string) (string, error)
}

// FileUploadRouteResolver resolves the single authenticated tenant route for
// the model-free /v1/files endpoint. It is deliberately separate from
// ModelResolver so existing model callers cannot accidentally infer file
// support from a legacy model record.
type FileUploadRouteResolver interface {
	ResolveFileUploadRoute(ctx context.Context, tenantID string) (*modelrouter.ModelRecord, error)
}

// === Internal interfaces for testability ===

// dbExecutor abstracts the DB Exec operation for RealAuditWriter
type dbExecutor interface {
	Exec(ctx context.Context, query string, args ...interface{}) (execResult, error)
}

type securityOccurrenceRecalculator interface {
	RecalculateSecurityOccurrences(context.Context, string, string) error
}

var _ securityOccurrenceRecalculator = (*realDBExecutor)(nil)

type attemptDeliveryReconciler interface {
	ReconcileAttemptDelivery(tenantID, logicalRequestID, deliveryOutcome string)
}

// execResult abstracts the Exec result with RowsAffected
type execResult interface {
	RowsAffected() int64
}

// tokenIncrementer abstracts the token usage increment operation
type tokenIncrementer interface {
	IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error
}

// === Real implementations for internal interfaces ===

// realDBExecutor wraps pgxpool.Pool for production
type realDBExecutor struct {
	pool *pgxpool.Pool
}

func (e *realDBExecutor) Exec(ctx context.Context, query string, args ...interface{}) (execResult, error) {
	return e.pool.Exec(ctx, query, args...)
}

func (e *realDBExecutor) RecalculateSecurityOccurrences(ctx context.Context, tenantID, representativeEventID string) error {
	_, _, err := alertcounter.RecalculateRepresentative(ctx, e.pool, tenantID, representativeEventID)
	return err
}

func (e *realDBExecutor) ReconcileAttemptDelivery(tenantID, logicalRequestID, deliveryOutcome string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := e.pool.Exec(ctx, `
UPDATE model_route_attempts
SET delivery_outcome=$2, updated_at=NOW()
WHERE tenant_id=$1 AND logical_request_id=$3 AND delivery_outcome='pending'
`, tenantID, deliveryOutcome, logicalRequestID); err != nil {
			log.Printf("attempt delivery reconciliation failed for req=%s: %v", logicalRequestID, err)
		}
	}()
}

// realTokenIncrementer wraps auth.RateLimiter for production
type realTokenIncrementer struct {
	limiter *auth.RateLimiter
}

func (i *realTokenIncrementer) IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error {
	return i.limiter.IncrementTokenUsage(ctx, projectID, inputTokens, outputTokens)
}

func contentLogSessionID(envelope *modelrouter.RequestEnvelope) string {
	if envelope.SessionID != "" {
		return envelope.SessionID
	}
	return envelope.RequestID
}

// resolvedProxyAccessType mirrors migration 077's CASE in Go. Computing it here (and
// binding it as a dedicated parameter) avoids reusing the model_id parameter inside a SQL
// CASE — that reuse made Postgres deduce inconsistent types for the parameter (SQLSTATE
// 42P08), which silently failed the entire request_logs INSERT and dropped lse_* correlation.
func resolvedProxyAccessType(modelID string) string {
	if modelID != "" {
		return "llm"
	}
	return "normal_public"
}

// === Real implementations for production ===

// RealModelResolver wraps modelrouter.ModelRouter for production
type RealModelResolver struct {
	router *modelrouter.ModelRouter
}

func NewRealModelResolver(db *pgxpool.Pool) *RealModelResolver {
	return &RealModelResolver{router: modelrouter.NewModelRouter(db)}
}

func (r *RealModelResolver) ResolveModelWithDB(ctx context.Context, tenantID, modelName string) (*modelrouter.ModelRecord, error) {
	return r.router.ResolveModelWithDB(ctx, tenantID, modelName)
}

func (r *RealModelResolver) ResolveFileUploadRoute(ctx context.Context, tenantID string) (*modelrouter.ModelRecord, error) {
	return r.router.ResolveFileUploadRoute(ctx, tenantID)
}

func (r *RealModelResolver) GetModelPolicy(ctx context.Context, projectID string) (*modelrouter.ModelPolicy, error) {
	return r.router.GetModelPolicy(ctx, projectID)
}

func (r *RealModelResolver) GetQuotaPolicy(ctx context.Context, projectID string) (*modelrouter.QuotaPolicy, error) {
	return r.router.GetQuotaPolicy(ctx, projectID)
}

func (r *RealModelResolver) GetProviderCredential(ctx context.Context, providerID string) (string, error) {
	return r.router.GetProviderCredential(ctx, providerID)
}

func (r *RealModelResolver) GetProvider(ctx context.Context, tenantID, providerID string) (*modelrouter.ProviderRecord, error) {
	return r.router.GetProvider(ctx, tenantID, providerID)
}

func (r *RealModelResolver) GetProjectTeamID(ctx context.Context, projectID string) (string, error) {
	return r.router.GetProjectTeamID(ctx, projectID)
}

// RealRateLimitChecker wraps auth.RateLimiter for production
type RealRateLimitChecker struct {
	limiter *auth.RateLimiter
}

func NewRealRateLimitChecker(redisClient *redis.Client) *RealRateLimitChecker {
	return &RealRateLimitChecker{limiter: auth.NewRateLimiter(redisClient)}
}

func (r *RealRateLimitChecker) CheckRPM(ctx context.Context, projectID string, rpmLimit int) (bool, error) {
	return r.limiter.CheckRPM(ctx, projectID, rpmLimit)
}

func (r *RealRateLimitChecker) CheckConcurrency(ctx context.Context, projectID string, concurrencyLimit int) (bool, int64, error) {
	return r.limiter.CheckConcurrency(ctx, projectID, concurrencyLimit)
}

func (r *RealRateLimitChecker) ReleaseConcurrency(ctx context.Context, projectID string) error {
	return r.limiter.ReleaseConcurrency(ctx, projectID)
}

func (r *RealRateLimitChecker) CheckDailyTokenLimit(ctx context.Context, projectID string, dailyLimit int64) (bool, int64, error) {
	return r.limiter.CheckDailyTokenLimit(ctx, projectID, dailyLimit)
}

func (r *RealRateLimitChecker) CheckMonthlyTokenLimit(ctx context.Context, projectID string, monthlyLimit int64) (bool, int64, error) {
	return r.limiter.CheckMonthlyTokenLimit(ctx, projectID, monthlyLimit)
}

func (r *RealRateLimitChecker) IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error {
	return r.limiter.IncrementTokenUsage(ctx, projectID, inputTokens, outputTokens)
}

// RealSecurityChecker wraps security.Client for production
type RealSecurityChecker struct {
	client *security.Client
	// fileReferencePolicy 读租户文件策略里的两项文件引用处置；nil 时按缺省告警放行。
	fileReferencePolicy FileReferencePolicyReader
}

// FileReferencePolicyReader 按租户读文件引用处置（网关和独立代理共用 filereference 口径）。
type FileReferencePolicyReader interface {
	Policy(ctx context.Context, tenantID string) filereference.Policy
}

// SetFileReferencePolicyReader 注入文件引用处置读取器（装配期由 system_settings 读取）。
func (r *RealSecurityChecker) SetFileReferencePolicyReader(reader FileReferencePolicyReader) {
	if r != nil {
		r.fileReferencePolicy = reader
	}
}

func NewRealSecurityChecker(cfg *config.Config) *RealSecurityChecker {
	return &RealSecurityChecker{client: security.NewClientWithSecret(cfg.SecurityEngineURL, cfg.InternalAPISecret)}
}

func fileIDVerdictProvider(envelope *modelrouter.RequestEnvelope) string {
	if envelope == nil {
		return ""
	}
	return strings.TrimSpace(envelope.Provider)
}

func attachmentHasBytes(att map[string]interface{}) bool {
	data, _ := att["data_base64"].(string)
	return strings.TrimSpace(data) != ""
}

func buildInputCheckRequest(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole, contentSource string) *security.CheckInputRequest {
	requestContext := ctxWithAttachments(ctx, map[string]interface{}{
		"tenant_id":      envelope.TenantID,
		"project_id":     envelope.ProjectID,
		"user_id":        envelope.UserID,
		"provider":       fileIDVerdictProvider(envelope),
		"agent_type":     envelope.AgentType,
		"message_index":  messageIndex,
		"message_role":   messageRole,
		"content_source": contentSource,
	})
	if actorType := messageActorFromContext(ctx); actorType != "" {
		requestContext["actor_type"] = actorType
	}
	addInputInspectionContext(ctx, requestContext)
	addSemanticTaskContext(ctx, requestContext)
	return &security.CheckInputRequest{
		RequestID:     envelope.RequestID,
		Content:       content,
		ContentType:   "text",
		ProjectID:     envelope.ProjectID,
		Model:         envelope.Model,
		AgentType:     envelope.AgentType,
		ClientType:    "api",
		SkipSemantic:  skipSemanticFromContext(ctx),
		ContentSource: contentSource,
		UserID:        envelope.UserID,
		Principal:     securityPrincipal(envelope),
		Context:       requestContext,
	}
}

func inputOutcomeFromResponse(resp *security.CheckInputResponse) *InputCheckOutcome {
	return &InputCheckOutcome{
		Action:                 resp.Action,
		MaskedContent:          resp.MaskedContent,
		RedactionMapping:       resp.RedactionMapping,
		Findings:               convertSecurityFindings(resp.Findings),
		RawFindings:            resp.RawFindings,
		RulePackVersion:        resp.RulePackVersion,
		SemanticConfigRevision: resp.SemanticConfigRevision,
		SemanticStatus:         resp.SemanticStatus,
		SemanticReason:         resp.SemanticReason,
		EngineBuild:            resp.EngineBuild,
		FileBindings:           resp.FileBindings,
	}
}

// fileReferenceHit 是一个只带文件 id 的附件按文件策略定出的处置（过内容例外前后都用它）。
type fileReferenceHit struct {
	outcome         filereference.Outcome
	attachmentIndex int
	messageIndex    int
	messageRole     string
}

// fileReferenceExceptionTimeout 是一次请求核对内容例外的上限（测试可调短）。
var fileReferenceExceptionTimeout = filereference.ExceptionCheckTimeout

// fileReferenceHits validates reference-only attachments against the security-engine
// registry. Byte scans never trust or pre-register a client-supplied file_id; only a
// one-time binding token consumed after an upstream object=file response can create it.
//
// 2.9.22（任务 4.2）：检测结论为阻断时照拦；没有检测记录、检测未完成、查询失败按租户
// 文件策略的 unverified_file_reference_action、file_reference_lookup_failure_action 处置
// （缺省告警放行），与独立代理同一口径（packages/shared-go/filereference）。这里只定处置，
// 内容例外由调用方经 applyFileReferenceExceptions 一次核对。检测结论阻断、查询失败按 block
// 处置的不过例外，遇到即返回 hardBlock，后面的附件不再查。
func (r *RealSecurityChecker) fileReferenceHits(ctx context.Context, envelope *modelrouter.RequestEnvelope, attachments []map[string]interface{}, messageIndex int, messageRole string) (hits []*fileReferenceHit, hardBlock bool) {
	var policy *filereference.Policy
	for attachmentIndex, attachment := range attachments {
		fileID := referenceIDFromMap(attachment)
		if fileID == "" || attachmentHasBytes(attachment) {
			continue
		}
		status := ""
		verdict, err := r.client.LookupFileVerdict(ctx, envelope.TenantID, envelope.UserID, fileIDVerdictProvider(envelope), fileID)
		if err == nil && verdict != nil {
			status = verdict.Status
		}
		if policy == nil {
			resolved := filereference.DefaultPolicy()
			if r.fileReferencePolicy != nil {
				resolved = r.fileReferencePolicy.Policy(ctx, envelope.TenantID)
			}
			policy = &resolved
		}
		outcome := filereference.Decide(status, err, *policy)
		if outcome.Action == filereference.Allow {
			continue
		}
		if err != nil {
			log.Printf("file verdict lookup failed (tenant=%s action=%s): %v", envelope.TenantID, outcome.Action, err)
		}
		hits = append(hits, &fileReferenceHit{outcome: outcome, attachmentIndex: attachmentIndex, messageIndex: messageIndex, messageRole: messageRole})
		if outcome.Blocks() && !outcome.ExceptionEligible() {
			return hits, true
		}
	}
	return hits, false
}

// fileReferenceFindings 把处置换成命中；有不带例外的 block 时 blocked 为真，命中只留第一条阻断。
func fileReferenceFindings(hits []*fileReferenceHit) (findings []SecurityFinding, blocked bool) {
	for _, hit := range hits {
		shape := hit.outcome.Finding()
		messageIndex, attachmentIndex := hit.messageIndex, hit.attachmentIndex
		finding := SecurityFinding{
			Type:             "file",
			Category:         shape.Category,
			Severity:         shape.Severity,
			RuleID:           shape.RuleID,
			RuleName:         shape.RuleName,
			RuleType:         "file_reference",
			Action:           shape.Action,
			ExceptionID:      shape.ExceptionID,
			ContentSource:    "file_attachment",
			MatchedLocation:  "file_reference",
			RedactedEvidence: hit.outcome.Message,
			EvidenceReason:   hit.outcome.Message,
			MessageIndex:     &messageIndex,
			MessageRole:      hit.messageRole,
			AttachmentIndex:  &attachmentIndex,
		}
		if hit.outcome.Blocks() {
			return append(findings, finding), true
		}
		findings = append(findings, finding)
	}
	return findings, false
}

// fileReferenceBatch 收齐 hits 里还要核对内容例外的处置。
func fileReferenceBatch(hits []*fileReferenceHit) *filereference.ExceptionBatch {
	batch := &filereference.ExceptionBatch{}
	for _, hit := range hits {
		batch.Add(&hit.outcome)
	}
	return batch
}

// applyFileReferenceExceptions 把未经扫描的文件引用命中合成一次送引擎 /apply-context/ 过内容例外
// （按 rule_ref 匹配，作用域、有效期与引擎文件类命中一致），单独限时 2 秒。引擎调不通或超时按文件
// 策略原处置执行（核对失败不放松），本次请求里不再重试。
func (r *RealSecurityChecker) applyFileReferenceExceptions(ctx context.Context, envelope *modelrouter.RequestEnvelope, batch *filereference.ExceptionBatch) {
	if batch == nil || batch.Len() == 0 {
		return
	}
	var results []filereference.ExceptionResult
	defer func() { batch.Apply(results) }()
	if r == nil || r.client == nil || envelope == nil {
		return
	}
	raw, err := json.Marshal(batch.Probes())
	if err != nil {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, fileReferenceExceptionTimeout)
	defer cancel()
	resp, err := r.client.ApplyContext(checkCtx, &security.ApplyContextRequest{
		TenantID:    envelope.TenantID,
		RawFindings: raw,
		Context: security.ApplyContextContext{
			AgentType:  envelope.AgentType,
			ProjectID:  envelope.ProjectID,
			UserID:     envelope.UserID,
			AccessType: "api",
		},
		Principal: securityPrincipal(envelope),
	})
	if err != nil {
		log.Printf("file reference exception check failed (tenant=%s): %v", envelope.TenantID, err)
		return
	}
	for _, finding := range resp.Findings {
		results = append(results, filereference.ExceptionResult{RuleID: finding.RuleID, AttachmentIndex: finding.AttachmentIndex, ExceptionID: finding.ExceptionID})
	}
}

// findingsRaiseAlert 粗判这批检测命中是否会让本次事件提升告警：有计作安全发现、又没被例外豁免的
// 命中。为真时，文件引用的告警放行命中压不压都不影响告警，不必再核对例外。
func findingsRaiseAlert(findings []SecurityFinding) bool {
	for _, finding := range findings {
		if countsAsSecurityFinding(finding) && finding.ExceptionID == "" {
			return true
		}
	}
	return false
}

// mergeFileReferenceAlerts 把告警放行的文件引用命中并入检测结果：放行的结果至少留 audit。
func mergeFileReferenceAlerts(outcome *InputCheckOutcome, alerts []SecurityFinding) *InputCheckOutcome {
	if outcome == nil || len(alerts) == 0 {
		return outcome
	}
	outcome.Findings = append(outcome.Findings, alerts...)
	if outcome.Action == "" || outcome.Action == "allow" {
		outcome.Action = "audit"
	}
	return outcome
}

// CheckInputDetailed 完整版输入检查：在 CheckInput 之上附带版本回带与原始 findings
// （P1-B 指纹缓存写入所需）。请求构造与 P1-A（任务 15）落地后的 CheckInput 完全一致——
// 顶层 ContentSource/UserID 与 Context 七键逐字保留，缺一即回退 P1-A 的 source 裁剪/例外 scope。
func (r *RealSecurityChecker) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	attachments := attachmentsFromContext(ctx)
	hits, hardBlock := r.fileReferenceHits(ctx, envelope, attachments, messageIndex, messageRole)
	// 按 block 处置的未经扫描引用要先核对例外才能决定拦不拦（一次请求一次调用）。
	if batch := fileReferenceBatch(hits); !hardBlock && batch.Blocking() {
		r.applyFileReferenceExceptions(ctx, envelope, batch)
	}
	referenceFindings, blocked := fileReferenceFindings(hits)
	if blocked {
		return &InputCheckOutcome{Action: "block", Findings: referenceFindings}, nil
	}
	resp, err := r.client.CheckInput(ctx, buildInputCheckRequest(ctx, envelope, content, messageIndex, messageRole, contentSource))
	if err != nil {
		return nil, err
	}
	outcome := inputOutcomeFromResponse(resp)
	// 告警放行的未经扫描引用：核对例外只为压告警；引擎这次已有会提升告警的命中时不必核对。
	if batch := fileReferenceBatch(hits); batch.Len() > 0 && !findingsRaiseAlert(outcome.Findings) {
		r.applyFileReferenceExceptions(ctx, envelope, batch)
		referenceFindings, _ = fileReferenceFindings(hits)
	}
	return mergeFileReferenceAlerts(outcome, referenceFindings), nil
}

func (r *RealSecurityChecker) CheckInputBatchDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, items []InputCheckBatchItem) ([]InputCheckBatchResult, error) {
	results := make([]InputCheckBatchResult, len(items))
	requests := make([]*security.CheckInputRequest, 0, len(items))
	indices := make([]int, 0, len(items))
	referenceHits := make([][]*fileReferenceHit, len(items))
	hardBlocked := make([]bool, len(items))
	for i, item := range items {
		itemCtx := item.Context
		if itemCtx == nil {
			itemCtx = ctx
		}
		referenceHits[i], hardBlocked[i] = r.fileReferenceHits(itemCtx, envelope, attachmentsFromContext(itemCtx), item.MessageIndex, item.MessageRole)
	}
	// 所有消息里按 block 处置的未经扫描引用合成一次例外核对。
	blockBatch := &filereference.ExceptionBatch{}
	for i := range items {
		if !hardBlocked[i] {
			for _, hit := range referenceHits[i] {
				if hit.outcome.Action == filereference.Block {
					blockBatch.Add(&hit.outcome)
				}
			}
		}
	}
	r.applyFileReferenceExceptions(ctx, envelope, blockBatch)
	for i, item := range items {
		itemCtx := item.Context
		if itemCtx == nil {
			itemCtx = ctx
		}
		referenceFindings, blocked := fileReferenceFindings(referenceHits[i])
		if blocked {
			results[i].Outcome = &InputCheckOutcome{Action: "block", Findings: referenceFindings}
			continue
		}
		req := buildInputCheckRequest(itemCtx, envelope, item.Content, item.MessageIndex, item.MessageRole, item.ContentSource)
		req.RequestID = fmt.Sprintf("%s:%d:%d", envelope.RequestID, item.MessageIndex, i)
		requests = append(requests, req)
		indices = append(indices, i)
	}
	responses, err := r.client.CheckInputBatch(ctx, requests)
	if err != nil {
		for _, resultIndex := range indices {
			results[resultIndex].Err = err
		}
		return results, nil
	}
	for i, resp := range responses {
		resultIndex := indices[i]
		if !strings.EqualFold(resp.InspectionStatus, "completed") {
			reason := strings.TrimSpace(resp.InspectionReason)
			if reason == "" {
				reason = "unknown"
			}
			if strings.Contains(strings.ToLower(reason), "timeout") {
				results[resultIndex].Err = fmt.Errorf("security inspection incomplete (%s): %w", reason, context.DeadlineExceeded)
			} else {
				results[resultIndex].Err = fmt.Errorf("security inspection incomplete: %s", reason)
			}
			results[resultIndex].Err = securityexit.NewInspectionFailure(reason, results[resultIndex].Err)
			continue
		}
		results[resultIndex].Outcome = inputOutcomeFromResponse(resp)
	}
	// 告警放行的未经扫描引用：所有消息合成一次核对，只为压告警；任一消息的引擎命中已会提升告警时不必核对。
	alertBatch := &filereference.ExceptionBatch{}
	raise := false
	for _, resultIndex := range indices {
		if outcome := results[resultIndex].Outcome; outcome != nil {
			raise = raise || findingsRaiseAlert(outcome.Findings)
			for _, hit := range referenceHits[resultIndex] {
				alertBatch.Add(&hit.outcome)
			}
		}
	}
	if !raise {
		r.applyFileReferenceExceptions(ctx, envelope, alertBatch)
	}
	for _, resultIndex := range indices {
		if outcome := results[resultIndex].Outcome; outcome != nil {
			referenceFindings, _ := fileReferenceFindings(referenceHits[resultIndex])
			results[resultIndex].Outcome = mergeFileReferenceAlerts(outcome, referenceFindings)
		}
	}
	return results, nil
}

func (r *RealSecurityChecker) CheckInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (string, string, []SecurityFinding, error) {
	out, err := r.CheckInputDetailed(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return "", "", nil, err
	}
	return out.Action, out.MaskedContent, out.Findings, nil
}

// ApplyContext 实现 contextReplayer（契约 2）。access_type 固定 "api"——A 路事实，
// 与 CheckInput 的 ClientType 同源。
// BindScannedFile consumes the opaque one-time capability issued by the
// security engine. The caller must have already verified the upstream
// response is a real object=file payload.
func (r *RealSecurityChecker) BindScannedFile(ctx context.Context, envelope *modelrouter.RequestEnvelope, token security.FileBindingToken, fileID string) error {
	if r == nil || r.client == nil || envelope == nil {
		return fmt.Errorf("security file binding client is not configured")
	}
	return r.client.BindScannedFile(ctx, envelope.TenantID, envelope.UserID, envelope.Provider, token.Token, fileID)
}

func (r *RealSecurityChecker) ApplyContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, rawFindings json.RawMessage, contentSource string) (string, []SecurityFinding, error) {
	resp, err := r.client.ApplyContext(ctx, &security.ApplyContextRequest{
		TenantID:    envelope.TenantID,
		RawFindings: rawFindings,
		Context: security.ApplyContextContext{
			AgentType:     envelope.AgentType,
			ProjectID:     envelope.ProjectID,
			UserID:        envelope.UserID,
			ContentSource: contentSource,
			AccessType:    "api",
		},
		Principal: securityPrincipal(envelope),
	})
	if err != nil {
		return "", nil, err
	}
	return resp.Action, convertSecurityFindings(resp.Findings), nil
}

// CheckSemanticOnly 只跑语义检测（异步旁路）：复用 CheckInput 同款 envelope→request 映射，
// 仅置 SemanticOnly=true，返回的语义 findings 走同款 convertSecurityFindings 转换（字段不丢）。
func (r *RealSecurityChecker) CheckSemanticOnly(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string) ([]SecurityFinding, error) {
	return r.CheckSemanticStage(ctx, envelope, content, "input")
}

// CheckSemanticStage 为 Agent 工具调用和异步输入分别携带明确阶段。
func (r *RealSecurityChecker) CheckSemanticStage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, stage string) ([]SecurityFinding, error) {
	resp, err := r.client.CheckSemanticStage(ctx, &security.CheckInputRequest{
		RequestID:   envelope.RequestID,
		Content:     content,
		ContentType: "text",
		ProjectID:   envelope.ProjectID,
		Model:       envelope.Model,
		AgentType:   envelope.AgentType,
		ClientType:  "api",
		Context: map[string]interface{}{
			"tenant_id":  envelope.TenantID,
			"project_id": envelope.ProjectID,
		},
		Principal: securityPrincipal(envelope),
	}, stage)
	if err != nil {
		return nil, err
	}
	return convertSecurityFindings(resp.Findings), nil
}

// CheckTriage 调 security-engine /check-triage/，把 handler findings 映射回 security.SecurityFinding
// 发送、再把带 triage 的结果转回 handler 层。
func (r *RealSecurityChecker) CheckTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, findings []SecurityFinding) ([]SecurityFinding, error) {
	req := &security.CheckTriageRequest{
		RequestID: envelope.RequestID,
		Content:   content,
		Findings:  handlerFindingsToSecurity(findings),
	}
	resp, err := r.client.CheckTriage(ctx, req)
	if err != nil {
		return nil, err
	}
	return convertSecurityFindings(resp.Findings), nil
}

// handlerFindingsToSecurity 是 convertSecurityFindings 的逆向（handler→client），triage 携带。
func handlerFindingsToSecurity(src []SecurityFinding) []security.SecurityFinding {
	out := make([]security.SecurityFinding, len(src))
	for i, f := range src {
		out[i] = security.SecurityFinding{
			Type:                    f.Type,
			Category:                f.Category,
			Severity:                f.Severity,
			MatchedTextPreview:      f.MatchedTextPreview,
			RuleID:                  f.RuleID,
			Confidence:              f.Confidence,
			RuleName:                f.RuleName,
			RuleType:                f.RuleType,
			Action:                  f.Action,
			PolicyCode:              f.PolicyCode,
			PolicyScene:             f.PolicyScene,
			SourceRuleID:            f.SourceRuleID,
			MatchedCapabilities:     append([]string(nil), f.MatchedCapabilities...),
			CountsAsSecurityFinding: f.CountsAsSecurityFinding,
			MatchedLocation:         f.MatchedLocation,
			RedactedEvidence:        f.RedactedEvidence,
			RawEvidence:             f.RawEvidence,
			EvidenceContext:         f.EvidenceContext,
			// SecretText 故意不传：秘密本体只从引擎单向传给网关，复核请求里不带回。
			EvidenceKind:    f.EvidenceKind,
			ContentSource:   f.ContentSource,
			EvidenceReason:  f.EvidenceReason,
			MessageIndex:    f.MessageIndex,
			MessageRole:     f.MessageRole,
			AttachmentIndex: f.AttachmentIndex,
			ExceptionID:     f.ExceptionID,
			Triage:          f.Triage,
		}
	}
	return out
}

func (r *RealSecurityChecker) CheckOutputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (*InputCheckOutcome, error) {
	checkContext := map[string]interface{}{
		"tenant_id":    envelope.TenantID,
		"project_id":   envelope.ProjectID,
		"model":        envelope.Model,
		"choice_index": choiceIndex,
		"principal":    securityPrincipal(envelope),
	}
	// output_projection / tool_name / tool_may_egress 只来自网关原生路径的 ctx 标注。
	addOutputProjectionContext(ctx, checkContext)
	resp, err := r.client.CheckOutput(ctx, envelope.RequestID, content, checkContext)
	if err != nil {
		return nil, err
	}
	findings := convertSecurityFindings(resp.Findings)
	return &InputCheckOutcome{Action: resp.Action, MaskedContent: resp.MaskedContent, Findings: findings, SemanticStatus: resp.SemanticStatus, SemanticReason: resp.SemanticReason}, nil
}

func (r *RealSecurityChecker) CheckOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (string, string, []SecurityFinding, error) {
	out, err := r.CheckOutputDetailed(ctx, envelope, content, choiceIndex)
	if err != nil {
		return "", "", nil, err
	}
	return out.Action, out.MaskedContent, out.Findings, nil
}

// securityPrincipal stamps the requested model onto a copy of the request
// principal so model-scoped subject bindings evaluate per model. The raw
// envelope principal (used for request logging) is never mutated.
func securityPrincipal(envelope *modelrouter.RequestEnvelope) *principal.Context {
	if envelope == nil || envelope.Principal == nil {
		return nil
	}
	stamped := principal.WithModel(*envelope.Principal, envelope.Model)
	return &stamped
}

func convertSecurityFindings(src []security.SecurityFinding) []SecurityFinding {
	result := make([]SecurityFinding, len(src))
	for i, f := range src {
		result[i] = SecurityFinding{
			Type:                    f.Type,
			Severity:                f.Severity,
			Category:                f.Category,
			MatchedTextPreview:      f.MatchedTextPreview,
			RuleID:                  f.RuleID,
			Confidence:              f.Confidence,
			RuleName:                f.RuleName,
			RuleType:                f.RuleType,
			Action:                  f.Action,
			PolicyCode:              f.PolicyCode,
			PolicyScene:             f.PolicyScene,
			SourceRuleID:            f.SourceRuleID,
			MatchedCapabilities:     append([]string(nil), f.MatchedCapabilities...),
			CountsAsSecurityFinding: f.CountsAsSecurityFinding,
			MatchedLocation:         f.MatchedLocation,
			RedactedEvidence:        f.RedactedEvidence,
			RawEvidence:             f.RawEvidence,
			EvidenceContext:         f.EvidenceContext,
			SecretText:              f.SecretText,
			EvidenceKind:            f.EvidenceKind,
			ContentSource:           f.ContentSource,
			EvidenceReason:          f.EvidenceReason,
			MessageIndex:            f.MessageIndex,
			MessageRole:             f.MessageRole,
			AttachmentIndex:         f.AttachmentIndex,
			ExceptionID:             f.ExceptionID,
			Triage:                  f.Triage,
		}
	}
	return result
}

// RealAuditWriter handles DB persistence for production
type RealAuditWriter struct {
	db         dbExecutor
	limiter    tokenIncrementer
	aggregator *providers.Aggregator // nil when Redis not available
	// rawEvidence 是脱敏原文留证的后台写入队列（零值可用，见 raw_evidence.go）。
	rawEvidence rawEvidenceQueue
}

// inferAgentTypeFromContent 只看 system / developer 角色，按有边界的产品名匹配
// （"You are X" 加分；system 里非断言的提及当前也会命中，见 agentdetect.InferFromContentRole）；
// 用户、助手、工具正文里出现产品名不算数。
func inferAgentTypeFromContent(role, content string) string {
	return agentdetect.InferFromContentRole(role, content)
}

func (w *RealAuditWriter) BackfillRequestAgentType(ctx context.Context, tenantID, requestID, agentType string) {
	if tenantID == "" || requestID == "" || agentType == "" {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	_, _ = w.db.Exec(ctx, `
		UPDATE request_logs
		SET agent_type = $1,
		    agent_detection_source = 'content',
		    agent_detection_confidence = 0.98
		WHERE tenant_id = $2
		  AND request_id = $3
		  AND (
		    COALESCE(agent_type, '') = ''
		    OR (agent_type IN ('agent-tool-call', 'vscode') AND $1 NOT IN ('agent-tool-call', 'vscode'))
		  )
	`, agentType, tenantID, requestID)
}

func NewRealAuditWriter(db *pgxpool.Pool, redisClient *redis.Client) *RealAuditWriter {
	w := &RealAuditWriter{
		db: &realDBExecutor{pool: db},
	}
	if redisClient != nil {
		w.limiter = &realTokenIncrementer{limiter: auth.NewRateLimiter(redisClient)}
		w.aggregator = providers.NewAggregator(redisClient)
	}
	return w
}

func (w *RealAuditWriter) EnsureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	if err := w.ensureRequestLog(ctx, envelope); err != nil {
		// Surface write failures instead of silently swallowing them — a swallowed
		// request_logs INSERT error (param-reuse 42P08) once dropped all lse_* correlation.
		log.Printf("EnsureRequestLog INSERT failed for req=%s: %v", envelope.RequestID, err)
	}
}

func (w *RealAuditWriter) ensureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope) error {
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	logID := newAuditID("log_")
	actorUserID, principalJSON := requestPrincipalAudit(envelope)
	// user_id/provider_id/model_id 都带外键：尚未完成用户归属或路由选择的
	// 早期失败会携带空串，必须 NULLIF 落 NULL，否则整条留痕撞 23503 丢失。
	query := `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id, session_id, agent_type, endpoint_type, trace_id, lse_eval_run_id, lse_task_id, lse_sample_id, lse_target_id, request_status, proxy_access_type_resolved, source_ip, proxy_mode, agent_runtime, agent_detection_source, agent_detection_confidence, evidence_run_id, evidence_run_source, created_at, environment_scope, actor_user_id, principal_context_json, proxy_user_agent, agent_identity_headers, agent_instance_id)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, NULLIF($7, ''), NULLIF($8, ''), $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NULLIF($19, ''), $31, NULLIF($20, ''), NULLIF($21, ''), NULLIF($22, 0), NULLIF($23, ''), NULLIF($24, ''), NOW(), COALESCE(NULLIF($25, ''), 'legacy-unclassified'), NULLIF($26, ''), $27, $28, COALESCE(NULLIF($29, ''), '{}')::jsonb, NULLIF($30, ''))
		ON CONFLICT (request_id) DO NOTHING
	`
	_, ensureErr := w.db.Exec(ctx, query,
		logID,
		envelope.RequestID,
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.ClientID,
		envelope.ProviderID,
		envelope.ModelID,
		envelope.SessionID,
		envelope.AgentType,
		envelope.EndpointType,
		envelope.TraceID,
		envelope.LSEEvalRunID,
		envelope.LSETaskID,
		envelope.LSESampleID,
		envelope.LSETargetID,
		"received",
		resolvedProxyAccessType(envelope.ModelID),
		envelope.SourceIP,
		envelope.AgentRuntime,
		envelope.AgentDetectionSource,
		envelope.AgentDetectionConfidence,
		envelope.EvidenceRunID,
		envelope.EvidenceRunSource,
		envelope.EnvironmentScope,
		actorUserID,
		principalJSON,
		envelope.UserAgent,
		envelope.AgentIdentityHeaders,
		envelope.AgentInstanceID,
		requestLogProxyMode(envelope),
	)
	return ensureErr
}

// RecordRuntimeFault 同步写一条平台级运行告警（请求日志 + 安全事件 + 收尾）并报告结果，
// 供 RuntimeFaultEventWriter 写成功后再登记限频。
func (w *RealAuditWriter) RecordRuntimeFault(ctx context.Context, envelope *modelrouter.RequestEnvelope, summary string) error {
	if err := w.ensureRequestLog(ctx, envelope); err != nil {
		return fmt.Errorf("request log: %w", err)
	}
	if err := w.writeSecurityEvent(ctx, envelope, nil, "audit", summary); err != nil {
		return fmt.Errorf("security event: %w", err)
	}
	w.FinalizeRequestLog(ctx, envelope, nil, "security_check_failed", 0, 0, nil)
	return nil
}

// PersistBillingRoute saves only final channel/model attribution. Ordinary
// audit finalization still owns response evidence, status and quota settlement.
func (w *RealAuditWriter) PersistBillingRoute(ctx context.Context, envelope *modelrouter.RequestEnvelope) error {
	if w == nil || w.db == nil || envelope == nil || envelope.TenantID == "" || envelope.RequestID == "" {
		return fmt.Errorf("billing route identity is unavailable")
	}
	result, err := w.db.Exec(ctx, `UPDATE request_logs rl
	 SET provider_id=NULLIF($3,''),model_id=NULLIF($4,'')
	 WHERE rl.tenant_id=$1 AND rl.request_id=$2
	 AND ($3='' OR EXISTS(SELECT 1 FROM providers p WHERE p.id=$3 AND p.tenant_id=$1))
	 AND ($4='' OR EXISTS(SELECT 1 FROM models m JOIN providers p ON p.id=m.provider_id WHERE m.id=$4 AND m.provider_id=$3 AND p.tenant_id=$1))`, envelope.TenantID, envelope.RequestID, envelope.ProviderID, envelope.ModelID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("billing route request or model identity did not match")
	}
	return nil
}

func (w *RealAuditWriter) FinalizeRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte, status string, upstreamStatusCode int, latencyMs int, auditResult *AuditResult) {
	// 配额结算自带最长约 12s 的限时，不能与后面的审计写库共用同一个限时，否则 Redis 慢时
	// request_logs 的 INSERT 会拿到已过期的 ctx。所以先只脱离取消（保留 value），
	// 配额结算之后再为审计写库取一个新的有界限时。
	base := context.WithoutCancel(ctx)
	actorUserID, principalJSON := requestPrincipalAudit(envelope)
	promptUsage, completionUsage, usageState := responseUsageTokenState(respBody)
	usagePresent := verifiedUsageState(usageState)
	promptTokens, completionTokens := int(promptUsage), int(completionUsage)
	if envelope.QuotaAdmissionManaged && envelope.QuotaFinalize != nil {
		quotaStatus := accountingStatus(status)
		actualTokens := int64(promptTokens + completionTokens)
		actualCostMicros := envelope.QuotaActualCostMicros
		success := quotaStatus == "success" || quotaStatus == "incomplete"
		if status == "security_replied" {
			actualTokens = 0
			promptTokens, completionTokens = 0, 0
			envelope.QuotaUsageSource = "synthetic_no_upstream"
		}
		if success && !usagePresent {
			actualTokens = envelope.QuotaEstimatedTokens
			promptTokens, completionTokens = int(actualTokens), 0
			if envelope.QuotaUsageSource == "" {
				envelope.QuotaUsageSource = "estimated_reservation"
				if quotaStatus == "incomplete" {
					envelope.QuotaUsageSource = "estimated_incomplete"
				}
				if usageState == "invalid" {
					envelope.QuotaUsageSource = "estimated_reservation_invalid_usage"
					if quotaStatus == "incomplete" {
						envelope.QuotaUsageSource = "estimated_incomplete_invalid_usage"
					}
				}
			}
		} else if usagePresent && envelope.QuotaUsageSource == "" {
			envelope.QuotaUsageSource = usageState
		}
		if success && !envelope.QuotaActualCostAvailable {
			actualCostMicros = envelope.QuotaEstimatedCostMicros
		}
		if !success {
			actualCostMicros = 0
		}
		if quotaErr := envelope.QuotaFinalize(base, actualTokens, actualCostMicros, envelope.QuotaActualCostAvailable, success); quotaErr != nil {
			logQuotaFinalizeError(envelope, quotaErr)
		}
	}
	ctx, cancel := detachAuditContext(base)
	defer cancel()

	// 将计时合并到已有元数据中，保留所有原审计字段。
	auditResult = withRequestTiming(envelope, auditResult)

	// Prepare audit result JSON fields
	var inputAuditResultJSON, outputAuditResultJSON []byte
	if auditResult != nil {
		if auditResult.InputFindings != nil || auditResult.InputAction != "" {
			inputAuditResultJSON, _ = json.Marshal(map[string]interface{}{
				"findings": auditResult.InputFindings,
				"action":   auditResult.InputAction,
			})
		}
		if auditResult.OutputFindings != nil || auditResult.OutputAction != "" || auditResult.ResponseMetadata != nil {
			outputAudit := map[string]interface{}{
				"findings": auditResult.OutputFindings,
				"action":   auditResult.OutputAction,
			}
			if auditResult.ResponseMetadata != nil {
				outputAudit["response_metadata"] = auditResult.ResponseMetadata
			}
			outputAuditResultJSON, _ = json.Marshal(outputAudit)
		}
	}
	if block := requestBlockAttribution(ctx); block != nil {
		var outputAudit map[string]interface{}
		if len(outputAuditResultJSON) > 0 {
			_ = json.Unmarshal(outputAuditResultJSON, &outputAudit)
		}
		if outputAudit == nil {
			outputAudit = make(map[string]interface{})
		}
		outputAudit["block"] = block
		outputAuditResultJSON, _ = json.Marshal(outputAudit)
	}
	// One usage_source for the row, with an explicit precedence: the billing
	// marker wins when present, because it is derived from the raw provider body
	// plus the real admission state, whereas the quota marker is only populated
	// when a quota lease ran. They agree whenever both ran (both describe the
	// same usage), and writing a single key avoids a race where two independent
	// assignments would otherwise overwrite each other in this map.
	//
	// Writing it here — unconditionally of any feature switch — is what makes
	// the row attributable to control-plane reconciliation even when billing is
	// enabled without the quota governor.
	usageSource := envelope.BillingUsageSource
	if usageSource == "" {
		usageSource = envelope.QuotaUsageSource
	}
	if usageSource != "" || envelope.BillingIngress != "" {
		var outputAudit map[string]interface{}
		if len(outputAuditResultJSON) > 0 {
			_ = json.Unmarshal(outputAuditResultJSON, &outputAudit)
		}
		if outputAudit == nil {
			outputAudit = make(map[string]interface{})
		}
		metadata, _ := outputAudit["response_metadata"].(map[string]interface{})
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		if usageSource != "" {
			metadata["usage_source"] = usageSource
		}
		if envelope.BillingIngress != "" {
			metadata["billing_ingress"] = envelope.BillingIngress
		}
		outputAudit["response_metadata"] = metadata
		outputAuditResultJSON, _ = json.Marshal(outputAudit)
	}

	// R14: serialize routing decision for white-box audit log.
	var routingDecisionJSON []byte
	// 失败请求/别名解析时在原决策上叠加客户端原始模型名与拒绝原因（不改动原对象）。
	if decision := auditRoutingDecision(envelope, upstreamStatusCode); decision != nil {
		routingDecisionJSON = marshalRoutingDecisionForAudit(decision, json.Marshal)
	}

	logID := newAuditID("log_")
	upstreamOutcome, deliveryOutcome, billingOutcome, cancelOutcome := requestOutcomeDimensions(status, upstreamStatusCode)
	if envelope.BillingOutcome != "" {
		billingOutcome = envelope.BillingOutcome
	}
	// user_id/provider_id/model_id 同 EnsureRequestLog：早期失败空串必须落 NULL。
	query := `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, provider_id, model_id, endpoint_type, trace_id, lse_eval_run_id, lse_task_id, lse_sample_id, lse_target_id, request_status, upstream_status_code, latency_ms, upstream_ttft_ms, input_tokens, output_tokens, input_audit_result, output_audit_result, routing_decision_json, proxy_access_type_resolved, source_ip, proxy_mode, agent_type, agent_runtime, agent_detection_source, agent_detection_confidence, evidence_run_id, evidence_run_source, created_at, environment_scope, upstream_outcome, delivery_outcome, billing_outcome, cancel_outcome, audit_outcome, outcome_schema_version, actor_user_id, principal_context_json, proxy_user_agent, agent_identity_headers, agent_instance_id)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, NULLIF($24, ''), 'chat_completion', NULLIF($25, ''), NULLIF($26, ''), NULLIF($27, ''), NULLIF($28, 0), NULLIF($29, ''), NULLIF($30, ''), NOW(), COALESCE(NULLIF($31, ''), 'legacy-unclassified'), $32, $33, $34, $35, 'completed', 1, NULLIF($36, ''), $37, $38, COALESCE(NULLIF($39, ''), '{}')::jsonb, NULLIF($40, ''))
		ON CONFLICT (request_id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			project_id = EXCLUDED.project_id,
			user_id = EXCLUDED.user_id,
			provider_id = EXCLUDED.provider_id,
			model_id = EXCLUDED.model_id,
			endpoint_type = EXCLUDED.endpoint_type,
			proxy_access_type_resolved = EXCLUDED.proxy_access_type_resolved,
			trace_id = COALESCE(NULLIF(EXCLUDED.trace_id, ''), request_logs.trace_id),
			lse_eval_run_id = COALESCE(NULLIF(EXCLUDED.lse_eval_run_id, ''), request_logs.lse_eval_run_id),
			lse_task_id = COALESCE(NULLIF(EXCLUDED.lse_task_id, ''), request_logs.lse_task_id),
			lse_sample_id = COALESCE(NULLIF(EXCLUDED.lse_sample_id, ''), request_logs.lse_sample_id),
			lse_target_id = COALESCE(NULLIF(EXCLUDED.lse_target_id, ''), request_logs.lse_target_id),
			request_status = EXCLUDED.request_status,
			upstream_status_code = EXCLUDED.upstream_status_code,
			latency_ms = EXCLUDED.latency_ms,
			upstream_ttft_ms = EXCLUDED.upstream_ttft_ms,
			input_tokens = EXCLUDED.input_tokens,
			output_tokens = EXCLUDED.output_tokens,
			input_audit_result = EXCLUDED.input_audit_result,
			output_audit_result = EXCLUDED.output_audit_result,
			routing_decision_json = EXCLUDED.routing_decision_json,
			source_ip = COALESCE(NULLIF(EXCLUDED.source_ip, ''), request_logs.source_ip),
			agent_type = COALESCE(NULLIF(request_logs.agent_type, ''), EXCLUDED.agent_type),
			agent_runtime = COALESCE(NULLIF(request_logs.agent_runtime, ''), EXCLUDED.agent_runtime),
			agent_detection_source = COALESCE(NULLIF(request_logs.agent_detection_source, ''), EXCLUDED.agent_detection_source),
			agent_detection_confidence = COALESCE(request_logs.agent_detection_confidence, EXCLUDED.agent_detection_confidence),
			evidence_run_id = CASE
				WHEN COALESCE(request_logs.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
				 AND EXCLUDED.evidence_run_source = 'chat_tool_call_id'
				THEN EXCLUDED.evidence_run_id
				ELSE COALESCE(NULLIF(request_logs.evidence_run_id, ''), EXCLUDED.evidence_run_id)
			END,
			evidence_run_source = CASE
				WHEN COALESCE(request_logs.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
				 AND EXCLUDED.evidence_run_source = 'chat_tool_call_id'
				THEN EXCLUDED.evidence_run_source
				ELSE COALESCE(NULLIF(request_logs.evidence_run_source, ''), EXCLUDED.evidence_run_source)
			END,
			environment_scope = COALESCE(NULLIF(EXCLUDED.environment_scope, ''), request_logs.environment_scope)
			, upstream_outcome = EXCLUDED.upstream_outcome
			, delivery_outcome = EXCLUDED.delivery_outcome
			, billing_outcome = EXCLUDED.billing_outcome
			, cancel_outcome = EXCLUDED.cancel_outcome
			, audit_outcome = EXCLUDED.audit_outcome
				, outcome_schema_version = EXCLUDED.outcome_schema_version
				, actor_user_id = EXCLUDED.actor_user_id
				, principal_context_json = EXCLUDED.principal_context_json
 , proxy_user_agent = COALESCE(NULLIF(EXCLUDED.proxy_user_agent, ''), request_logs.proxy_user_agent)
 , agent_identity_headers = request_logs.agent_identity_headers || EXCLUDED.agent_identity_headers
	`

	result, err := w.db.Exec(ctx, query,
		logID,
		envelope.RequestID,
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.ProviderID,
		envelope.ModelID,
		envelope.EndpointType,
		envelope.TraceID,
		envelope.LSEEvalRunID,
		envelope.LSETaskID,
		envelope.LSESampleID,
		envelope.LSETargetID,
		status,
		upstreamStatusCode,
		latencyMs,
		envelope.UpstreamTTFTMs,
		promptTokens,
		completionTokens,
		inputAuditResultJSON,
		outputAuditResultJSON,
		routingDecisionJSON,
		resolvedProxyAccessType(envelope.ModelID),
		envelope.SourceIP,
		envelope.AgentType,
		envelope.AgentRuntime,
		envelope.AgentDetectionSource,
		envelope.AgentDetectionConfidence,
		envelope.EvidenceRunID,
		envelope.EvidenceRunSource,
		envelope.EnvironmentScope,
		upstreamOutcome,
		deliveryOutcome,
		billingOutcome,
		cancelOutcome,
		actorUserID,
		principalJSON,
		envelope.UserAgent,
		envelope.AgentIdentityHeaders,
		envelope.AgentInstanceID,
	)

	// Only increment token usage if request log write succeeded and has rows affected
	if err != nil {
		log.Printf("FinalizeRequestLog INSERT failed for req=%s: %v", envelope.RequestID, err)
		return // Don't increment tokens on DB error
	}
	if result.RowsAffected() == 0 {
		return // Don't increment tokens if no rows written
	}
	if reconciler, ok := w.db.(attemptDeliveryReconciler); ok {
		reconciler.ReconcileAttemptDelivery(envelope.TenantID, envelope.RequestID, deliveryOutcome)
	}

	if envelope.CacheHit {
		if _, cacheErr := w.db.Exec(ctx, `UPDATE request_logs SET cache_hit=TRUE WHERE tenant_id=$1 AND request_id=$2`, envelope.TenantID, envelope.RequestID); cacheErr != nil {
			log.Printf("记录响应缓存命中失败 request_id=%s: %v", envelope.RequestID, cacheErr)
		}
	}
	if models := auth.TakeModelObservations(ctx); len(models) > 0 {
		if _, noteErr := w.db.Exec(ctx, `UPDATE request_logs SET policy_note='key_model_outside_allowlist' WHERE tenant_id=$1 AND request_id=$2`, envelope.TenantID, envelope.RequestID); noteErr != nil {
			log.Printf("记录凭据模型名单命中失败 request_id=%s: %v", envelope.RequestID, noteErr)
		}
		w.WriteSecurityEvent(ctx, envelope, []SecurityFinding{{Type: "security_check", Category: "key_model_outside_allowlist", Severity: "low", Action: "audit", RuleName: "凭据模型名单", MatchedTextPreview: strings.Join(models, ", ")}}, "security_audit", "请求使用了凭据名单外的模型，已按记录档放行")
	}
	// Update token usage counters only after successful audit write
	if !envelope.QuotaAdmissionManaged && w.limiter != nil && (promptTokens > 0 || completionTokens > 0) {
		w.limiter.IncrementTokenUsage(ctx, envelope.ProjectID, int64(promptTokens), int64(completionTokens))
	}

	// Asynchronously fan out usage to per-scope Redis budget hashes (best-effort).
	// This feeds the governor snapshot for the next request; failures are logged and ignored.
	if w.aggregator != nil && (promptTokens > 0 || completionTokens > 0) {
		totalTokens := int64(promptTokens + completionTokens)
		if envelope.QuotaAdmissionManaged {
			totalTokens = 0
		}
		go func(parent context.Context, env *modelrouter.RequestEnvelope, tokens int64) {
			ctx, cancel := context.WithTimeout(parent, 5*time.Second)
			defer cancel()

			// 用 Asia/Shanghai 日界写入，与 control-plane budget_handler 读取口径一致
			cnLoc, _ := time.LoadLocation("Asia/Shanghai")
			if cnLoc == nil {
				cnLoc = time.Local
			}
			cnNow := time.Now().In(cnLoc)
			args := providers.IncrementArgs{
				Scopes:   buildMeteringScopes(env),
				Tokens:   tokens,
				Cost:     0,
				Requests: 1,
				YYYYMM:   cnNow.Format("2006-01"),
				YYYYMMDD: cnNow.Format("2006-01-02"),
			}
			if err := w.aggregator.IncrementAllScopes(ctx, args); err != nil {
				log.Printf("[budget.aggregator] increment failed: %v", err)
			}
		}(context.WithoutCancel(ctx), envelope, totalTokens)
	}
}

func (w *RealAuditWriter) MarkBillingOutcome(ctx context.Context, envelope *modelrouter.RequestEnvelope, outcome string) {
	if w == nil || w.db == nil || envelope == nil || envelope.TenantID == "" || envelope.RequestID == "" || outcome == "" {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	if _, err := w.db.Exec(ctx, `
		UPDATE request_logs
		SET billing_outcome = $1
		WHERE tenant_id = $2 AND request_id = $3
	`, outcome, envelope.TenantID, envelope.RequestID); err != nil {
		log.Printf("MarkBillingOutcome UPDATE failed for req=%s: %v", envelope.RequestID, err)
	}
}

func requestOutcomeDimensions(status string, upstreamStatusCode int) (upstream, delivery, billing, cancel string) {
	upstream, delivery, billing, cancel = "unknown", "not_started", "unknown", "none"
	if upstreamStatusCode >= 200 && upstreamStatusCode < 300 {
		upstream = "success"
	} else if upstreamStatusCode >= 400 {
		upstream = "http_error"
	}
	switch status {
	case "success", "security_replied":
		delivery = "completed"
	case "stream_aborted":
		delivery = "aborted"
	case "canceled", "client_canceled":
		upstream, delivery, cancel = "canceled", "client_canceled", "client_canceled"
	case "provider_unavailable":
		upstream = "unknown"
	}
	return
}

func marshalRoutingDecisionForAudit(decision *modelrouter.RoutingDecision, marshal func(any) ([]byte, error)) []byte {
	if decision == nil {
		return nil
	}
	safe := modelrouter.SanitizeRoutingDecision(decision)
	raw, err := marshal(safe)
	if err == nil {
		return raw
	}
	log.Printf("routing decision serialization failed; writing safe fallback")
	requestedModel := ""
	if safe != nil && safe.ModelRouteV2 != nil {
		requestedModel = safe.ModelRouteV2.RequestedModel
	}
	fallback := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: requestedModel, FallbackReason: "serialization_failed"}}
	raw, err = json.Marshal(fallback)
	if err != nil {
		return []byte(`{"fallback_retries":0,"model_route_v2":{"schema_version":2,"requested_model":"","planned_route":{},"actual_route":{},"fallback_used":false,"fallback_reason":"serialization_failed"}}`)
	}
	return raw
}

// buildMeteringScopes writes each budget dimension under its stable identity.
func buildMeteringScopes(env *modelrouter.RequestEnvelope) []providers.ScopeKey {
	candidates := make([]providers.ScopeKey, 0, len(env.QuotaAccountingScopes)+5)
	for _, scope := range env.QuotaAccountingScopes {
		candidates = append(candidates, providers.ScopeKey{Scope: scope.Scope, ID: scope.ID})
	}
	candidates = append(candidates,
		providers.ScopeKey{Scope: "tenant", ID: env.TenantID},
		providers.ScopeKey{Scope: "team", ID: env.TeamID},
		providers.ScopeKey{Scope: "project", ID: env.ProjectID},
		providers.ScopeKey{Scope: "user", ID: trustedActorUserID(env)},
		providers.ScopeKey{Scope: "key", ID: env.ClientID},
	)
	seen := make(map[string]struct{}, len(candidates))
	scopes := make([]providers.ScopeKey, 0, len(candidates))
	for _, scope := range candidates {
		key := scope.Scope + "\x00" + scope.ID
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes
}

func trustedActorUserID(env *modelrouter.RequestEnvelope) string {
	if env == nil || env.Principal == nil || env.Principal.TrustLevel != "authenticated" {
		return ""
	}
	return env.Principal.ActorUserID
}

func requestPrincipalAudit(envelope *modelrouter.RequestEnvelope) (string, []byte) {
	if envelope == nil || envelope.Principal == nil || envelope.Principal.Validate() != nil {
		return "", nil
	}
	encoded, err := json.Marshal(envelope.Principal)
	if err != nil {
		return "", nil
	}
	return trustedActorUserID(envelope), encoded
}

// principalKeyFromEnvelope 物化 principal_key = COALESCE(user_id, client_id, source_ip)
// （契约第 6 条；COALESCE 语义在 Go 侧实现——各写入点各自物化，告警桥不回查 request_logs）。
func principalKeyFromEnvelope(envelope *modelrouter.RequestEnvelope) string {
	if envelope == nil {
		return ""
	}
	for _, v := range []string{envelope.UserID, envelope.ClientID, envelope.SourceIP} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (w *RealAuditWriter) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	if err := w.writeSecurityEvent(ctx, envelope, findings, actionTaken, summary); err != nil {
		log.Printf("[audit] %v", err)
	}
}

func (w *RealAuditWriter) writeSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) error {
	// A block is always persisted: it is the record the agent's notice points to.
	if !writerPersists(ctx, findings, actionTaken) {
		return nil
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	eventID := securityEventIDFromContext(ctx)
	if eventID == "" {
		eventID = newAuditID("evt_")
	}
	// 请求识别标签只进 matched_summary.request_labels（buildSecurityMatchedSummary），不参与事件分级、分桶与规则归属。
	allFindings := findings
	findings, _ = splitRequestContextLabels(findings)

	severity := getFindingsSeverity(findings)
	// P2-2：依命中维度选取 event_type 顶层分桶（纯文件 -> file_security，其余维持 security_check）。
	eventType := eventTypeForFindings(findings)
	// P0-A：物化检索/聚合用生命周期列。策略编译后 rule_id 是 rules(id)
	// 外键，可安全写入；未绑定的内置 detector id 仍只写 class_key。
	effectiveSeverity := securityEventEffectiveSeverity(findings, nil)
	classKey := securityEventClassKey(findings, eventType)
	ruleID := firstPersistablePolicyRuleID(findings)

	matchedSummary := buildSecurityMatchedSummary(allFindings, actionTaken, summary)
	matchedSummary["agent_instance_id"] = envelope.AgentInstanceID
	annotateSecurityEventStage(ctx, matchedSummary)
	annotateFingerprintReuse(ctx, matchedSummary)
	annotateSemanticStatus(ctx, matchedSummary)
	annotateSecurityEventBlock(ctx, envelope, eventID, findings, actionTaken, summary, matchedSummary)
	// 只有真正「什么也没检出」的语义未完成才改写成检测故障；仅记录类观察事件保留原类型与类别，
	// 否则告警桥会把它当 runtime_fault 进收件箱（语义未完成本身另由 recordSemanticIncomplete 记录）。
	if state, ok := semanticStatusFromContext(ctx); ok && state.Status == "incomplete" && !persistableSecurityFindings(findings) && !isBlockingSecurityAction(actionTaken) {
		eventType = "security_check_failed"
		severity = "low"
		effectiveSeverity = "low"
		classKey = "system"
		matchedSummary["category"] = "system"
		matchedSummary["counts_as_security_finding"] = false
		if effective, ok := ctx.Value(semanticEffectiveActionKey{}).(string); ok {
			actionTaken = effective
			matchedSummary["action_taken"] = effective
		}
	}
	matchedSummaryJSON, _ := json.Marshal(matchedSummary)

	// user_id 同 request_logs：users(id) 外键，无归属 key 的空串必须 NULLIF 落 NULL，
	// 否则安全事件整条丢失（写入错误被忽略，无痕）。
	query := `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id, action_taken, matched_summary, created_at, principal_key, conversation_key, effective_severity, class_key, agent_instance_id)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, NULLIF($8, ''), $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''), NULLIF($16, ''))
		ON CONFLICT (id) DO NOTHING
	`

	_, err := w.db.Exec(ctx, query,
		eventID,
		envelope.RequestID,
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		eventType,
		severity,
		ruleID,
		actionTaken,
		matchedSummaryJSON,
		time.Now(),
		principalKeyFromEnvelope(envelope),
		envelope.ConversationKey,
		effectiveSeverity,
		classKey,
		envelope.AgentInstanceID,
	)
	if err != nil {
		forgetBlockRecord(ctx, eventID)
		return fmt.Errorf("security event persistence failed request_id=%s event_id=%s: %w", envelope.RequestID, eventID, err)
	}
	return nil
}

// RecordSecurityEventOccurrence persists one lightweight, request-idempotent repeat
// occurrence. If the representative event has already joined an alert group, the
// group count is bumped in the same statement; otherwise the row remains pending
// for AlertGroupRepository.ReconcileOccurrences.
func (w *RealAuditWriter) RecordSecurityEventOccurrence(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	representativeEventID, contextKey string,
) error {
	if w == nil || w.db == nil || envelope == nil ||
		strings.TrimSpace(envelope.TenantID) == "" ||
		strings.TrimSpace(envelope.RequestID) == "" ||
		strings.TrimSpace(representativeEventID) == "" ||
		strings.TrimSpace(contextKey) == "" {
		return fmt.Errorf("security occurrence missing required fields")
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	occurredAt := time.Now().UTC()
	_, err := w.db.Exec(ctx, `
		WITH inserted AS (
			INSERT INTO security_event_occurrences (
				tenant_id, representative_event_id, request_id, principal_key,
				conversation_key, context_key, alert_group_id, occurred_at
			) VALUES (
				$1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6,
				(SELECT se.alert_group_id
				   FROM security_events se
				  WHERE se.tenant_id = $1 AND se.id = $2),
				$7
			)
			ON CONFLICT (tenant_id, representative_event_id, request_id) DO NOTHING
			RETURNING alert_group_id, occurred_at
		)
		UPDATE alert_groups ag
		   SET occurrence_count = ag.occurrence_count + 1,
		       last_seen_at = GREATEST(ag.last_seen_at, inserted.occurred_at),
		       updated_at = NOW()
		  FROM inserted
		 WHERE ag.tenant_id = $1
		   AND ag.id = inserted.alert_group_id
	`, envelope.TenantID, representativeEventID, envelope.RequestID,
		principalKeyFromEnvelope(envelope), envelope.ConversationKey, contextKey, occurredAt)
	if err != nil {
		return err
	}

	// Derived counters are idempotent snapshots. This second statement is best-effort:
	// the occurrence row is already durable and the control-plane reconciler will
	// recompute the same counters if this request races group creation.
	if recalc, ok := w.db.(securityOccurrenceRecalculator); ok {
		_ = recalc.RecalculateSecurityOccurrences(ctx, envelope.TenantID, representativeEventID)
	}
	return nil
}

// AnnotateTriage 把 triage 标注就地合并回该 request 输入侧 security_event 的 matched_summary
// （异步标注，observe-only；同步路径已先写 event 留底，绝不丢证）。
//
// FIX-2（important，修两处错位/竞态）：
//  1. 精确定位：按 (tenant_id, request_id, stage='input') 定位该请求的输入侧行，而非"最近一行"。
//     多消息请求会落多行 security_event（含输出侧），取 ORDER BY created_at DESC LIMIT 1 会错位到
//     无关行并整体覆盖其 matched_summary，造成跨消息错标/丢数据。
//  2. 逐 finding 合并：不再把整段 matched_summary 序列化覆盖，而用 jsonb_set 在既有 findings 数组上
//     按身份(rule_id+matched_location)只补 triage 子字段，保留其余 finding 与其它顶层字段不动。
//  3. outbox 异步未落库的竞态：与 async_audit_writer 的 outbox 异步写并存时，event 行可能尚未落库。
//     此处用单条 SQL 就地合并（不读后写，无 TOCTOU）；若目标行尚不存在则 RowsAffected==0，安全降级
//     （不报错、记 debug log；丢标注=不压制=安全方向，符合 fail-open）。
func (w *RealAuditWriter) AnnotateTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding) {
	if envelope == nil || envelope.RequestID == "" || len(findings) == 0 {
		return
	}
	// 构造 身份(rule_id|matched_location) -> triage 映射；仅纳入带 triage 的 finding。
	triageByIdentity := map[string]map[string]any{}
	for _, f := range findings {
		if len(f.Triage) == 0 {
			continue
		}
		triageByIdentity[triageIdentityKey(f.RuleID, f.MatchedLocation)] = f.Triage
	}
	if len(triageByIdentity) == 0 {
		return // 没有可标注的 triage（fail-open：不动既有 event）
	}
	triageMapJSON, err := json.Marshal(triageByIdentity)
	if err != nil {
		return
	}

	// 就地合并：遍历既有 findings 数组，元素身份命中 $1 映射时用 jsonb_set 仅改其 triage 子字段，
	// 否则原样保留；最后整体写回 matched_summary->findings。不读后写，避免 TOCTOU。
	// WHERE 以 stage='input'($4) 精确锁定输入侧行（非"最近一行"），杜绝多消息/输出侧错位。
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	res, err := w.db.Exec(ctx, annotateTriageSQL, triageMapJSON, envelope.TenantID, envelope.RequestID, "input")
	if err != nil {
		log.Printf("AnnotateTriage UPDATE failed for req=%s: %v", envelope.RequestID, err)
		return
	}
	// 行不存在（outbox 异步未落库 / 已被清理）：安全降级——丢标注=不压制，仅 debug log。
	if res != nil && res.RowsAffected() == 0 {
		log.Printf("[triage.async] AnnotateTriage no target row (event not yet persisted) req=%s", envelope.RequestID)
	}
}

// annotateTriageSQL 就地合并 triage：findings 按原序号（WITH ORDINALITY）重组，顺序不变——
// primary_finding.findings_index 引用依赖它。
const annotateTriageSQL = `
		UPDATE security_events
		SET matched_summary = jsonb_set(
			matched_summary,
			'{findings}',
			COALESCE((
				SELECT jsonb_agg(
					CASE
						WHEN $1::jsonb ? (COALESCE(f.value->>'rule_id', '') || '|' || COALESCE(f.value->>'matched_location', ''))
						THEN jsonb_set(f.value, '{triage}', $1::jsonb -> (COALESCE(f.value->>'rule_id', '') || '|' || COALESCE(f.value->>'matched_location', '')))
						ELSE f.value
					END
					ORDER BY f.ordinality
				)
				FROM jsonb_array_elements(matched_summary->'findings') WITH ORDINALITY AS f(value, ordinality)
			), matched_summary->'findings')
		)
		WHERE tenant_id = $2
		  AND request_id = $3
		  AND matched_summary->>'stage' = $4
`

// triageIdentityKey 以 rule_id + matched_location 组合身份键（与 SQL 内匹配表达式对齐）。
// 二者均可为空（如纯语义/无 location），仍构成稳定键；用 '|' 分隔避免歧义拼接。
func triageIdentityKey(ruleID, matchedLocation string) string {
	return ruleID + "|" + matchedLocation
}

func normalizedSecurityEventSeverity(severity string) string {
	switch severity {
	case "low", "medium", "high", "critical":
		return severity
	default:
		return ""
	}
}

func securityEventSeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func securityEventEffectiveSeverity(findings []SecurityFinding, matchedSummary map[string]interface{}) string {
	if matchedSummary != nil {
		if severity, _ := matchedSummary["effective_severity"].(string); normalizedSecurityEventSeverity(severity) != "" {
			return normalizedSecurityEventSeverity(severity)
		}
	}
	return getFindingsSeverity(findings)
}

func securityEventClassKey(findings []SecurityFinding, fallback string) string {
	classKey := dominantFindingCategory(findings, true)
	if classKey == "" {
		classKey = dominantFindingCategory(findings, false)
	}
	if classKey != "" {
		return classKey
	}
	return fallback
}

func dominantFindingCategory(findings []SecurityFinding, requireSecurityFinding bool) string {
	f, ok := dominantSecurityFinding(findings, requireSecurityFinding)
	if !ok {
		return ""
	}
	return strings.TrimSpace(f.Category)
}
func dominantSecurityFinding(findings []SecurityFinding, requireSecurityFinding bool) (SecurityFinding, bool) {
	index, found := dominantSecurityFindingIndex(findings, requireSecurityFinding)
	if !found {
		return SecurityFinding{}, false
	}
	return findings[index], true
}

// rawEvidenceReservedIndexes 是事件原文总量里先占预算的命中：主命中、阻断提示与阻断记录依据的那条
// （网关阻断归因按 blockingSecurityFinding，控制面阻断记录取第一条阻断动作的命中，两条都留）。
func rawEvidenceReservedIndexes(findings []SecurityFinding) []int {
	var reserved []int
	if index, ok := dominantSecurityFindingIndex(findings, true); ok {
		reserved = append(reserved, index)
	}
	if index, ok := blockingSecurityFindingIndex(findings); ok {
		reserved = append(reserved, index)
	}
	for index, finding := range findings {
		if isBlockingFindingAction(finding.Action) {
			reserved = append(reserved, index)
			break
		}
	}
	return reserved
}

// dominantSecurityFindingIndex 返回主命中在 findings 里的下标（选取规则同 dominantSecurityFinding）。
func dominantSecurityFindingIndex(findings []SecurityFinding, requireSecurityFinding bool) (int, bool) {
	var best SecurityFinding
	bestIndex := -1
	found := false
	fact := func(f SecurityFinding) int {
		if v, _ := f.Triage["is_canary"].(bool); v {
			return 2
		}
		if f.Type == "secret" {
			return 1
		}
		if v, _ := f.Triage["verified_fact"].(bool); v {
			return 1
		}
		return 0
	}
	key := func(f SecurityFinding) string {
		return strings.Join([]string{f.Type, f.Category, f.RuleID, f.RuleName}, "|")
	}
	for i, f := range findings {
		if requireSecurityFinding && !countsAsSecurityFinding(f) {
			continue
		}
		rank, bestRank := securityEventSeverityRank(strings.ToLower(strings.TrimSpace(f.Severity))), securityEventSeverityRank(strings.ToLower(strings.TrimSpace(best.Severity)))
		if !found || rank > bestRank || (rank == bestRank && (fact(f) > fact(best) || (fact(f) == fact(best) && (f.Confidence > best.Confidence || (f.Confidence == best.Confidence && key(f) < key(best)))))) {
			best, bestIndex = f, i
			found = true
		}
	}
	return bestIndex, found
}

// firstPersistablePolicyRuleID 只从可证明属于 rules(id) 的 finding 取值：
// 编译策略带 policy_code，自定义 matcher 的 rule_id 也直接来自 rules 表。
func firstPersistablePolicyRuleID(findings []SecurityFinding) string {
	candidates := make([]SecurityFinding, 0, len(findings))
	for _, finding := range findings {
		if strings.TrimSpace(finding.PolicyCode) != "" || finding.Type == "custom" {
			candidates = append(candidates, finding)
		}
	}
	if primary, ok := dominantSecurityFinding(candidates, true); ok {
		return strings.TrimSpace(primary.RuleID)
	}
	return ""
}

// eventTypeForFindings 依据命中维度选取 security_events.event_type 顶层分桶。
// 优先级：内置(agent/pii/secret/code_config) > 语义(semantic_attack) > 自定义(custom) > 文件(file)。
// 内置维持既有 "security_check"（零回归）；纯语义命中单出 "semantic_attack"（供收件箱筛选）；
// 客户自定义敏感数据归 "data_security"；纯文件命中归 "file_security"。
// 各维度命中始终完整保留在 matched_summary.findings[] 中，event_type 仅作粗粒度过滤分桶。
func eventTypeForFindings(findings []SecurityFinding) string {
	hasFile, hasCustom, hasSemantic, hasBuiltin := false, false, false, false
	for _, f := range findings {
		switch f.Type {
		case "":
			continue
		case "file":
			hasFile = true
		case "custom":
			hasCustom = true
		case "semantic_attack":
			hasSemantic = true
		case "tool_destructive_intent", "tool_attempt_blocked", "tool_execution_risk":
			return f.Type
		default:
			hasBuiltin = true
		}
	}
	if hasBuiltin { // 内置(agent/pii/secret/code_config)优先，维持既有看板分桶零回归
		return "security_check"
	}
	if hasSemantic { // 纯语义命中单出，供收件箱筛选
		return "semantic_attack"
	}
	if hasCustom {
		return "data_security"
	}
	if hasFile {
		return "file_security"
	}
	return "security_check"
}

func buildSecurityMatchedSummary(findings []SecurityFinding, actionTaken, summary string) map[string]interface{} {
	findings, requestLabels := splitRequestContextLabels(findings)
	securityFindingCount := 0
	for _, finding := range findings {
		if finding.CountsAsSecurityFinding == nil || *finding.CountsAsSecurityFinding {
			securityFindingCount++
		}
	}
	matchedSummary := map[string]interface{}{
		"action_taken":   actionTaken,
		"summary":        summary,
		"findings_count": securityFindingCount,
	}
	if len(requestLabels) > 0 {
		// 请求识别标签（如「直接 API 调用」）作为事件上下文保留，不作为一条命中。
		matchedSummary["request_labels"] = requestLabels
	}
	if len(findings) > 0 {
		// 原文只在 findings 里存一份，并受事件原文总量限制；主命中引用 findings 里的位置。
		// request_logs 的审计结果（securityFindingsToAuditMaps）不走这里，保持原样。
		items := alertevidence.LimitEventRaw(securityFindingsToSummary(findings), rawEvidenceReservedIndexes(findings)...)
		if index, ok := dominantSecurityFindingIndex(findings, true); ok {
			primary := findings[index]
			matchedSummary["category"] = primary.Category
			matchedSummary["rule_id"] = primary.RuleID
			matchedSummary["rule_name"] = primary.RuleName
			matchedSummary["rule_type"] = primary.Type
			matchedSummary["primary_finding"] = alertevidence.PrimaryReference(items[index], index)
		}
		matchedSummary["findings"] = items
		matchedSummary["source"] = "gateway"
		matchedSummary["stage"] = deriveStage(findings)
	}
	return matchedSummary
}

// deriveStage 从 finding 的 matched_location 推断 input/output（语义 finding 的 matched_location 即 stage）；
// 取不到时保守回退 input。仅作 matched_summary 展示/筛选用，不参与决策。
func deriveStage(findings []SecurityFinding) string {
	for _, f := range findings {
		if f.MatchedLocation == "output" {
			return "output"
		}
		if f.MatchedLocation == "tool" {
			return "tool"
		}
		if f.MatchedLocation == "input" {
			return "input"
		}
	}
	return "input"
}

func securityFindingsToSummary(findings []SecurityFinding) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(findings))
	for _, finding := range findings {
		item := map[string]interface{}{
			"type":     finding.Type,
			"severity": finding.Severity,
			"category": finding.Category,
			"rule_id":  finding.RuleID,
		}
		if finding.RuleName != "" {
			item["rule_name"] = finding.RuleName
		}
		if finding.RuleType != "" {
			item["rule_type"] = finding.RuleType
		}
		if finding.Action != "" {
			item["action"] = finding.Action
		}
		if finding.PolicyCode != "" {
			item["policy_code"] = finding.PolicyCode
		}
		if finding.PolicyScene != "" {
			item["policy_scene"] = finding.PolicyScene
		}
		if finding.SourceRuleID != "" {
			item["source_rule_id"] = finding.SourceRuleID
		}
		if len(finding.MatchedCapabilities) > 0 {
			item["matched_capabilities"] = append([]string(nil), finding.MatchedCapabilities...)
		}
		if finding.CountsAsSecurityFinding != nil {
			item["counts_as_security_finding"] = *finding.CountsAsSecurityFinding
		}
		if finding.MatchedLocation != "" {
			item["matched_location"] = finding.MatchedLocation
		}
		if finding.RedactedEvidence != "" {
			item["redacted_evidence"] = finding.RedactedEvidence
		}
		if finding.RawEvidence != "" {
			item["raw_evidence_sha256"] = securityEvidenceSHA256(finding.RawEvidence)
		}
		if finding.EvidenceContext != "" {
			item["evidence_context_sha256"] = securityEvidenceSHA256(finding.EvidenceContext)
		}
		putFindingEvidence(item, finding)
		if finding.EvidenceKind != "" {
			item["evidence_kind"] = finding.EvidenceKind
		}
		if finding.ContentSource != "" {
			item["content_source"] = finding.ContentSource
		}
		if finding.EvidenceReason != "" {
			item["evidence_reason"] = finding.EvidenceReason
		}
		if finding.MessageIndex != nil {
			item["message_index"] = *finding.MessageIndex
		}
		if finding.MessageRole != "" {
			item["message_role"] = finding.MessageRole
		}
		if finding.AttachmentIndex != nil {
			item["attachment_index"] = *finding.AttachmentIndex
		}
		if finding.MatchedTextPreview != "" {
			item["matched_text_preview"] = finding.MatchedTextPreview
		}
		item["confidence"] = finding.Confidence
		// 例外豁免标注：非空才输出（照 triage 的条件输出风格，空串=未豁免不落字段）。
		if finding.ExceptionID != "" {
			item["exception_id"] = finding.ExceptionID
		}
		if len(finding.Triage) > 0 {
			item["triage"] = finding.Triage
		}
		result = append(result, item)
	}
	return result
}

// putFindingEvidence 写落库的命中证据（口径见 shared-go/alertevidence）：
//   - 字面类命中：raw_evidence 原文片段（位置可用时取内容里的实际片段，超长截断并标 raw_evidence_truncated）、
//     不打码的 evidence_context，
//     以及按 2.9.21 落库内容（打码前后文、预览）算出的证据身份，保证升级前后证据身份、案件归并不变；
//   - 语义类、运行类：raw_evidence 是整段内容，不存原文，evidence_context 维持打码版本，落库形态与 2.9.21 一样。
func putFindingEvidence(item map[string]interface{}, finding SecurityFinding) {
	if finding.RawEvidence == "" && finding.EvidenceContext == "" {
		return
	}
	legacyContext := ""
	if finding.EvidenceContext != "" {
		legacyContext = redactedEvidenceContext(finding)
	}
	if !alertevidence.StoresRaw(finding.Type, finding.Category, finding.EvidenceKind) {
		if legacyContext != "" {
			item[alertevidence.FieldEvidenceContext] = alertevidence.Stored(legacyContext)
		}
		return
	}
	item[alertevidence.IdentityKey] = alertevidence.Identity(legacyContext, finding.MatchedTextPreview)
	// 位置可用时原文与前后文按位置从引擎前后文里取（内容里的实际原文），否则用引擎给的命中文字。
	location := finding.EvidenceLocation
	if location == "" {
		location = finding.MatchedLocation
	}
	hit, window := alertevidence.Extract(finding.RawEvidence, finding.EvidenceContext, location)
	if hit != "" {
		raw, truncated := alertevidence.Truncate(hit)
		item[alertevidence.FieldRawEvidence] = alertevidence.Stored(raw)
		if truncated {
			item[alertevidence.FieldRawEvidenceTruncated] = true
		}
	}
	if window != "" {
		item[alertevidence.FieldEvidenceContext] = window
	}
}

func securityEvidenceSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func redactedFindingEvidence(finding SecurityFinding) string {
	if value := strings.TrimSpace(finding.RedactedEvidence); value != "" {
		return value
	}
	if value := strings.TrimSpace(finding.MatchedTextPreview); value != "" {
		return value
	}
	return "<MASKED>"
}

func (w *RealAuditWriter) WriteContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int) {
	w.writeContentLog(ctx, envelope, role, content, tokens, nil)
}

func (w *RealAuditWriter) WriteContentLogAnchored(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens, messageIndex int) {
	w.writeContentLog(ctx, envelope, role, content, tokens, &messageIndex)
}

func (w *RealAuditWriter) writeContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int, messageIndex *int) {
	if envelope == nil || content == "" {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	w.writeContentLogWithin(ctx, envelope, role, content, tokens, messageIndex)
}

// writeContentLogWithin 是 writeContentLog 的内部写：直接使用调用方已带限时的 ctx，不再重新计时。
// 批量写失败后逐条回退走这里，让回退总耗时受批量入口那一个整体预算约束。
func (w *RealAuditWriter) writeContentLogWithin(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int, messageIndex *int) {
	logID := newAuditID("cl_")
	requestLogID := newAuditID("log_")
	// user_id（$5）同 EnsureRequestLog：request_logs.user_id 是 users(id) 外键，
	// 空串必须 NULLIF；content_logs 无外键但同口径落 NULL（与反代无归属留证一致）。
	query := `
		WITH request_log AS (
			INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id, session_id, agent_type, endpoint_type, trace_id, lse_eval_run_id, lse_task_id, lse_sample_id, lse_target_id, request_status, proxy_access_type_resolved, source_ip, proxy_mode, agent_runtime, agent_detection_source, agent_detection_confidence, evidence_run_id, evidence_run_source, created_at, environment_scope, proxy_user_agent, agent_identity_headers, agent_instance_id)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10, $11, $17, $18, $19, $20, $21, 'received', $22, NULLIF($23, ''), 'chat_completion', NULLIF($24, ''), NULLIF($25, ''), NULLIF($26, 0), NULLIF($27, ''), NULLIF($28, ''), NOW(), COALESCE(NULLIF($29, ''), 'legacy-unclassified'), $31, COALESCE(NULLIF($32, ''), '{}')::jsonb, NULLIF($33, ''))
			-- 父请求行已存在时不能用 DO UPDATE 拿 RETURNING：那是一次真实的整行重写，
			-- 长对话一个请求逐条写上千条消息就把同一行重写上千次（客户现场磁盘被写满）。
			ON CONFLICT (request_id) DO NOTHING
			RETURNING id
		), parent AS (
			SELECT id FROM request_log
			UNION ALL
			SELECT rl.id FROM request_logs rl
			WHERE rl.request_id = $2 AND NOT EXISTS (SELECT 1 FROM request_log)
		)
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, environment_scope, message_index)
		SELECT $12, parent.id, $3, NULLIF($5, ''), $13, $14, $15, $16, COALESCE(NULLIF($29, ''), 'legacy-unclassified'), $30
		FROM parent
	`

	args := []interface{}{
		requestLogID,
		envelope.RequestID,
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.ClientID,
		envelope.ProviderID,
		envelope.ModelID,
		envelope.SessionID,
		envelope.AgentType,
		envelope.EndpointType,
		logID,
		contentLogSessionID(envelope),
		role,
		content,
		tokens,
		envelope.TraceID,
		envelope.LSEEvalRunID,
		envelope.LSETaskID,
		envelope.LSESampleID,
		envelope.LSETargetID,
		resolvedProxyAccessType(envelope.ModelID),
		envelope.SourceIP,
		envelope.AgentRuntime,
		envelope.AgentDetectionSource,
		envelope.AgentDetectionConfidence,
		envelope.EvidenceRunID,
		envelope.EvidenceRunSource,
		envelope.EnvironmentScope,
		messageIndex,
		envelope.UserAgent,
		envelope.AgentIdentityHeaders,
		envelope.AgentInstanceID,
	}
	result, err := w.db.Exec(ctx, query, args...)
	// 父请求行恰好由并发事务在本语句开始之后提交时：DO NOTHING 不返回行，parent 的兜底查询用的是
	// 更早的语句快照也看不到它，于是写入 0 行。换新快照（新语句）重试一次即可看到父行。
	if err == nil && result != nil && result.RowsAffected() == 0 {
		result, err = w.db.Exec(ctx, query, args...)
	}
	if err != nil {
		log.Printf("failed to write content log for request %s: %v", envelope.RequestID, err)
		return
	}
	if result != nil && result.RowsAffected() == 0 {
		log.Printf("content log write affected 0 rows for request %s", envelope.RequestID)
	}
	// 例外：BackfillRequestAgentType 入口会重新计时一次，不复用这里的 ctx；但它只在上面
	// 的内容日志写成功后才触发，所以总耗时仍然有界。
	if agentType := inferAgentTypeFromContent(role, content); agentType != "" {
		w.BackfillRequestAgentType(ctx, envelope.TenantID, envelope.RequestID, agentType)
	}
}

func agentSessionNormalizedSQL(column string) string {
	return "regexp_replace(lower(btrim(COALESCE(" + column + ", ''))), '[[:space:]_]+', '-', 'g')"
}

// agentSessionTypeUpgradeSQL：会话已存值是空 / 通用值 / 可升级运行时值（vscode、agent-tool-call），
// 且新值是具体产品（非空、非通用、非可升级运行时值）时才覆盖；已存具体产品永不被覆盖
// （首个具体值固化）。名单由 $10::text[] 传入，来自 agentdetect.SessionOverwritableIdentities()；
// SQL 侧比较前做同样的归一化（小写、空白/下划线转连字符）。
var agentSessionTypeUpgradeSQL = `CASE
				WHEN ` + agentSessionNormalizedSQL("agent_sessions.agent_type") + ` = ANY($10::text[])
				 AND ` + agentSessionNormalizedSQL("EXCLUDED.agent_type") + ` <> ALL($10::text[])
				THEN EXCLUDED.agent_type
				ELSE agent_sessions.agent_type
			END`

func (w *RealAuditWriter) UpsertAgentSession(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	if envelope.SessionID == "" {
		return
	}

	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	sessionID := newAuditID("sess_")
	now := time.Now()

	query := `
		INSERT INTO agent_sessions (id, tenant_id, project_id, user_id, session_id, agent_type, workspace_id, first_request_at, last_request_at, request_count, risk_score, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 0, 'active')
		ON CONFLICT (session_id) DO UPDATE SET
			last_request_at = EXCLUDED.last_request_at,
			request_count = agent_sessions.request_count + 1,
			risk_score = LEAST(100, agent_sessions.request_count * 2),
			agent_type = ` + agentSessionTypeUpgradeSQL + `,
			updated_at = NOW()
		WHERE agent_sessions.tenant_id = EXCLUDED.tenant_id
	`

	_, _ = w.db.Exec(ctx, query,
		sessionID,
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.SessionID,
		envelope.AgentType,
		envelope.WorkspaceID,
		now,
		now,
		agentdetect.SessionOverwritableIdentities(),
	)
}

// RealProviderAdapterFactory uses real provider adapters
type RealProviderAdapterFactory struct {
	StreamIdleTimeout time.Duration
}

func (f *RealProviderAdapterFactory) CreateAdapter(modelRecord *modelrouter.ModelRecord, apiKey string) ProviderCaller {
	bridgeNativeMessages := shouldBridgeClaudeChatToNativeMessages(modelRecord)
	providerConfig := provider.ProviderConfig{
		BaseURL:                 modelRecord.ProviderBaseURL,
		APIKey:                  apiKey,
		ProxyURL:                modelRecord.UpstreamProxyURL,
		NativeAnthropicMessages: bridgeNativeMessages,
		StreamIdleTimeout:       f.StreamIdleTimeout,
	}
	if bridgeNativeMessages || strings.EqualFold(strings.TrimSpace(modelRecord.ProviderAuthMode), "authorization_raw") {
		providerConfig.AuthMode = modelRecord.ProviderAuthMode
	}
	if bridgeNativeMessages && strings.EqualFold(strings.TrimSpace(modelRecord.ProviderAuthMode), "api_key") {
		// api_key 是 OpenAI 兼容 provider 持久化的默认值：Chat 路由发 Bearer，
		// 控制面的 messages 协议探测同样发 Bearer。桥接原生 Messages 必须沿用，
		// 否则 Anthropic 适配器不认 "api_key"，未连上游即 502（2.9.11 实测）。
		providerConfig.AuthMode = "bearer"
	}
	if bridgeNativeMessages && strings.TrimRight(strings.ToLower(strings.TrimSpace(modelRecord.ProviderBaseURL)), "/") == "https://api.example-gateway.com" {
		// api.example-gateway.com is an OpenAI-compatible customer gateway.  Its
		// historical provider record says api_key, but its actual transport
		// contract is Authorization: Bearer (the same as the existing Chat
		// route).  Native Messages must retain that contract.
		providerConfig.AuthMode = "bearer"
	}
	return provider.GetAdapterWithConfig(modelRecord.ProviderType, providerConfig)
}

// shouldBridgeClaudeChatToNativeMessages keeps a uniform OpenAI Chat contract
// for clients such as WorkBuddy while sending tool turns to an upstream that
// has explicitly verified its native Messages endpoint. The decision is based
// on route capabilities, never a model-name prefix or provider hostname.
func shouldBridgeClaudeChatToNativeMessages(modelRecord *modelrouter.ModelRecord) bool {
	if modelRecord == nil || !modelRecord.ProtocolCapabilities.AnthropicMessages {
		return false
	}
	if modelRecord.ProviderType != "custom" && modelRecord.ProviderType != "openai" {
		return false
	}
	return true
}

// Helper to get findings severity for audit
func getFindingsSeverity(findings []SecurityFinding) string {
	severity := "low"
	for _, f := range findings {
		if !countsAsSecurityFinding(f) {
			continue
		}
		switch f.Severity {
		case "critical":
			return "critical"
		case "high":
			severity = "high"
		case "medium":
			if severity == "low" {
				severity = "medium"
			}
		}
	}
	return severity
}

// ProxyKeyInfo carries the verified 免Token代理 key identity (阶段二 2.5).
type ProxyKeyInfo struct {
	KeyID    string
	ModelIDs []string
}

// ProxyKeyVerifier verifies an X-Proxy-Key for a given model.
type ProxyKeyVerifier interface {
	VerifyProxyKey(ctx context.Context, rawKey, modelID string) (*ProxyKeyInfo, error)
}

// ProxyUsageRecorder records 免Token代理 usage for billing/metering.
type ProxyUsageRecorder interface {
	RecordProxyUsage(ctx context.Context, modelID string, inputTokens, outputTokens int) error
}

// requestLogProxyMode：网关自己的请求记 chat_completion；平台自建的运行故障日志记 runtime_fault，
// 便于和业务请求区分（控制面统计按 endpoint_type 排除，2.9.22）。proxy_mode 是 VARCHAR(16)、无取值约束。
func requestLogProxyMode(envelope *modelrouter.RequestEnvelope) string {
	if envelope != nil && envelope.EndpointType == "runtime_fault" {
		return "runtime_fault"
	}
	return "chat_completion"
}
