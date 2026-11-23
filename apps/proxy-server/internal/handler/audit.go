package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
	"github.com/yangjiyj/aiguard/packages/shared-go/clientip"
	"github.com/yangjiyj/aiguard/packages/shared-go/logretention"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// AuditWriter writes audit logs to the database
type AuditWriter struct {
	// db 只用到 Exec/QueryRow，按接口持有便于测试观察写入；运行时始终是 *pgxpool.Pool。
	db               retentionartifact.RepositoryDB
	retentionStore   retentionstore.Store
	environmentScope string

	retentionMu       sync.Mutex
	retentionDays     int
	retentionLoadedAt time.Time
}

const (
	defaultAccessContentRetentionDays = 90
	retentionSettingsCacheTTL         = 5 * time.Minute
)

// NewAuditWriter creates a new audit writer
func NewAuditWriter(db *pgxpool.Pool) *AuditWriter {
	a := &AuditWriter{environmentScope: retentionartifact.LegacyEnvironmentScope}
	if db != nil {
		// nil *pgxpool.Pool 装进接口会变成非 nil，各处 a.db == nil 的空转判断就失效了。
		a.db = db
	}
	return a
}

// WithEnvironmentScope installs the trusted deployment-level fallback used
// when a proxy record does not carry an explicit environment scope.
func (a *AuditWriter) WithEnvironmentScope(scope string) *AuditWriter {
	if a == nil {
		return nil
	}
	a.environmentScope = retentionartifact.NormalizeEnvironmentScope(scope)
	return a
}

func (a *AuditWriter) environmentScopeForRecord(record ProxyAuditRecord) string {
	if a == nil {
		return retentionartifact.ResolveEnvironmentScope(record.EnvironmentScope, "")
	}
	return retentionartifact.ResolveEnvironmentScope(record.EnvironmentScope, a.environmentScope)
}

func (a *AuditWriter) withEnvironmentScope(record ProxyAuditRecord) ProxyAuditRecord {
	record.EnvironmentScope = a.environmentScopeForRecord(record)
	return record
}

func (a *AuditWriter) WithRetentionStore(store retentionstore.Store) *AuditWriter {
	if a == nil {
		return nil
	}
	a.retentionMu.Lock()
	a.retentionStore = store
	a.retentionMu.Unlock()
	return a
}

// RetentionStore 返回当前留存后端(线程安全;配置热刷新会运行时替换它)。
func (a *AuditWriter) RetentionStore() retentionstore.Store {
	if a == nil {
		return nil
	}
	a.retentionMu.Lock()
	defer a.retentionMu.Unlock()
	return a.retentionStore
}

// normalizeAccessContentRetentionDays 与 control-plane 清理任务同一口径（shared-go/logretention）：
// 低于 30 天抬到 30 天，超过上限按上限，无法解析用 fallback。
func normalizeAccessContentRetentionDays(raw string, fallback int) int {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days <= 0 {
		return fallback
	}
	return logretention.Resolve(raw)
}

func (a *AuditWriter) accessContentRetentionDays(ctx context.Context) int {
	if a == nil || a.db == nil {
		return defaultAccessContentRetentionDays
	}
	a.retentionMu.Lock()
	defer a.retentionMu.Unlock()
	if a.retentionDays > 0 && time.Since(a.retentionLoadedAt) < retentionSettingsCacheTTL {
		return a.retentionDays
	}

	days := defaultAccessContentRetentionDays
	var raw string
	if err := a.db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = 'log_retention_days'`).Scan(&raw); err != nil {
		log.Printf("access content retention setting unavailable, using default %d days: %v", defaultAccessContentRetentionDays, err)
	} else {
		days = normalizeAccessContentRetentionDays(raw, defaultAccessContentRetentionDays)
	}
	a.retentionDays = days
	a.retentionLoadedAt = time.Now()
	return days
}

type ProxyAuditRecord struct {
	EvidenceRunID                                                                        string
	AgentIdentityHeaders                                                                 string
	InputSemanticStatus, InputSemanticReason, OutputSemanticStatus, OutputSemanticReason string
	OutputAlreadySent                                                                    bool
	RequestID                                                                            string
	TenantID                                                                             string
	ProjectID                                                                            string
	TargetHost                                                                           string
	TargetPath                                                                           string
	Method                                                                               string
	SourceIP                                                                             string
	UserAgent                                                                            string
	AgentType                                                                            string
	RequestBytes                                                                         int64
	ResponseBytes                                                                        int64
	TLSInspected                                                                         bool
	Provider                                                                             string
	ProviderCN                                                                           string
	Product                                                                              string
	ProductCN                                                                            string
	EndpointKind                                                                         string
	AccessType                                                                           string
	PathTemplate                                                                         string
	URLHash                                                                              string
	RetentionLevel                                                                       string
	ContentRetained                                                                      bool
	Status                                                                               string
	StatusCode                                                                           int
	EnvironmentScope                                                                     string
	InputAuditResult                                                                     map[string]interface{}
	OutputAuditResult                                                                    map[string]interface{}
	// P1-B 指纹缓存重放标注（契约 9）：非空时写进 matched_summary
	ScanMode           string
	FirstSeenRequestID string
	// Task 3b: upstream account / credential fingerprint for forward-proxy rows.
	// Credential-based attribution only ever stores the truncated digest.
	UpstreamPrincipal string
	UpstreamSession   string
}

const defaultForwardProxyProjectID = "project_default"

func NewProxyAuditRecord(requestID, tenantID, targetHost string, req *http.Request, match LLMProviderMatch, tlsInspected bool) (ProxyAuditRecord, error) {
	if requestID == "" {
		requestID = uuid.New().String()
	}
	record := ProxyAuditRecord{
		RequestID:    requestID,
		TenantID:     tenantID,
		ProjectID:    defaultForwardProxyProjectID,
		TargetHost:   normalizeHost(targetHost),
		TLSInspected: tlsInspected,
		Provider:     match.Provider,
		EndpointKind: match.EndpointKind,
		Status:       "in_progress",
	}
	if req != nil {
		record.TargetPath = req.URL.RequestURI()
		if record.TargetPath == "" {
			record.TargetPath = req.URL.Path
		}
		record.PathTemplate = summarizePathTemplate(req.URL.Path)
		record.URLHash = hashValue(normalizeHost(targetHost) + " " + req.Method + " " + req.URL.RequestURI())
		record.Method = req.Method
		record.SourceIP = clientIPFromRequest(req)
		record.UserAgent = agentdetect.BoundedIdentityValue(req.UserAgent(), 512)
		record.AgentIdentityHeaders = agentdetect.IdentityHeaders(req.Header)
		var err error
		record.AgentType, err = agentdetect.InferFromHeaders(req.Header)
		if err != nil {
			return ProxyAuditRecord{}, err
		}
		record.RequestBytes = req.ContentLength
		if record.RequestBytes < 0 {
			record.RequestBytes = 0
		}
	}

	if match.Known {
		record.ProviderCN = match.ProviderCN
		record.Product = match.Product
		record.ProductCN = match.ProductCN
		record.AccessType = accessTypeForMatch(match)
		record.RetentionLevel = match.RetainLevel
		if record.RetentionLevel == "" {
			record.RetentionLevel = "content"
		}
		record.ContentRetained = record.RetentionLevel == "content"
	} else {
		record.AccessType = "normal_public"
		record.RetentionLevel = "summary"
		record.ContentRetained = false
		if req != nil {
			record.TargetPath = record.PathTemplate
		}
	}
	return record, nil
}

func accessTypeForMatch(match LLMProviderMatch) string {
	if !match.Known {
		return "normal_public"
	}
	riskProfile := strings.ToLower(strings.TrimSpace(match.RiskProfile))
	category := strings.ToLower(strings.TrimSpace(match.Category))
	if riskProfile == "ai_ide_agent" || riskProfile == "coding_ai" || category == "coding" {
		return "ai_ide"
	}
	return "llm"
}

func (r ProxyAuditRecord) WithInputAudit(action string, findings []map[string]interface{}) ProxyAuditRecord {
	r.InputAuditResult = auditResult(action, findings)
	return r
}

func (r ProxyAuditRecord) WithOutputAudit(action string, findings []map[string]interface{}) ProxyAuditRecord {
	r.OutputAuditResult = auditResult(action, findings)
	return r
}

func forwardProxyRequestLogUpsertSQL() string {
	return `
		INSERT INTO request_logs (
			id, request_id, tenant_id, endpoint_type,
			request_status, upstream_status_code, latency_ms,
			input_tokens, output_tokens, total_cost, proxy_mode,
			input_audit_result, output_audit_result,
			proxy_target_host, proxy_target_path, proxy_method,
			proxy_source_ip, proxy_user_agent, proxy_request_bytes,
			proxy_response_bytes, proxy_tls_inspected, proxy_provider,
			proxy_product, proxy_endpoint_kind, proxy_access_type,
			proxy_access_type_resolved, proxy_path_template, proxy_url_hash,
			proxy_retention_level, proxy_content_retained, agent_type, source_ip,
			environment_scope, created_at, agent_identity_headers, evidence_run_id, evidence_run_source,
			principal_context_json
		) VALUES (
			$1, $2, $3, 'proxy',
			$4, $5, 0,
			0, 0, 0, 'forward',
			$6, $7,
			$8, $9, $10,
			$11, $12, $13,
			$14, $15, $16,
			$17, $18, $19,
			$19, $20, $21,
			$22, $23, $24, $25, $26, NOW(), COALESCE(NULLIF($27, ''), '{}')::jsonb, NULLIF($28,''), CASE WHEN $28::text<>'' THEN 'workbuddy_workspace' ELSE NULL END,
			NULLIF($29, '')::jsonb
		)
		ON CONFLICT (request_id) DO UPDATE SET
			request_status = EXCLUDED.request_status,
			upstream_status_code = EXCLUDED.upstream_status_code,
			input_audit_result = COALESCE(NULLIF(EXCLUDED.input_audit_result, '{}'::jsonb), request_logs.input_audit_result),
			output_audit_result = COALESCE(NULLIF(EXCLUDED.output_audit_result, '{}'::jsonb), request_logs.output_audit_result),
			proxy_target_host = EXCLUDED.proxy_target_host,
			proxy_target_path = EXCLUDED.proxy_target_path,
			proxy_method = EXCLUDED.proxy_method,
			proxy_source_ip = EXCLUDED.proxy_source_ip,
			proxy_user_agent = EXCLUDED.proxy_user_agent,
 agent_identity_headers = request_logs.agent_identity_headers || EXCLUDED.agent_identity_headers,
 evidence_run_id = COALESCE(EXCLUDED.evidence_run_id, request_logs.evidence_run_id),
 evidence_run_source = COALESCE(EXCLUDED.evidence_run_source, request_logs.evidence_run_source),
			proxy_request_bytes = EXCLUDED.proxy_request_bytes,
			proxy_response_bytes = EXCLUDED.proxy_response_bytes,
			proxy_tls_inspected = EXCLUDED.proxy_tls_inspected,
			proxy_provider = EXCLUDED.proxy_provider,
			proxy_product = EXCLUDED.proxy_product,
			proxy_endpoint_kind = EXCLUDED.proxy_endpoint_kind,
			proxy_access_type = EXCLUDED.proxy_access_type,
			proxy_access_type_resolved = EXCLUDED.proxy_access_type_resolved,
			proxy_path_template = EXCLUDED.proxy_path_template,
			proxy_url_hash = EXCLUDED.proxy_url_hash,
			proxy_retention_level = EXCLUDED.proxy_retention_level,
			proxy_content_retained = EXCLUDED.proxy_content_retained,
			agent_type = COALESCE(NULLIF(EXCLUDED.agent_type, ''), request_logs.agent_type),
			source_ip = COALESCE(NULLIF(EXCLUDED.source_ip, ''), request_logs.source_ip),
			environment_scope = EXCLUDED.environment_scope,
			principal_context_json = COALESCE(request_logs.principal_context_json, EXCLUDED.principal_context_json)
	`
}

// WriteRequestLog upserts a request log entry. It is safe to call once before
// security events and again after the upstream response is known.
func (a *AuditWriter) WriteRequestLog(ctx context.Context, record ProxyAuditRecord) {
	if a == nil || a.db == nil || record.TenantID == "" || record.RequestID == "" {
		return
	}
	record = a.withEnvironmentScope(record)
	if record.TargetHost == "" {
		record.TargetHost = "unknown"
	}
	if record.Status == "" {
		record.Status = "success"
	}

	inputAuditJSON := mustJSON(record.InputAuditResult)
	outputAuditJSON := mustJSON(record.OutputAuditResult)

	_, err := a.db.Exec(ctx, forwardProxyRequestLogUpsertSQL(),
		record.RequestID,
		record.RequestID,
		record.TenantID,
		record.Status,
		record.StatusCode,
		inputAuditJSON,
		outputAuditJSON,
		record.TargetHost,
		record.TargetPath,
		record.Method,
		record.SourceIP,
		record.UserAgent,
		record.RequestBytes,
		record.ResponseBytes,
		record.TLSInspected,
		record.Provider,
		record.Product,
		record.EndpointKind,
		record.AccessType,
		record.PathTemplate,
		record.URLHash,
		record.RetentionLevel,
		record.ContentRetained,
		record.AgentType,
		record.SourceIP,
		record.EnvironmentScope,
		record.AgentIdentityHeaders,
		record.EvidenceRunID,
		upstreamPrincipalContextJSON(record),
	)
	if err != nil {
		log.Printf("Failed to write request log: %v", err)
	}
}

type accessContentLogPayload struct {
	ID                      string
	RequestID               string
	TenantID                string
	Provider                string
	Product                 string
	RequestContentRedacted  string
	ResponseContentRedacted string
	FileMetadataJSON        string
	ToolCallMetadataJSON    string
	DecoderName             string
	DecoderVersion          string
	ConversationID          string
	SectionID               string
	Model                   string
	ArtifactMetadata        []retainedAttachmentMetadata
}

type retainedAttachmentMetadata struct {
	Source          string `json:"source"`
	Stage           string `json:"stage,omitempty"`
	FieldName       string `json:"field_name,omitempty"`
	FileName        string `json:"file_name,omitempty"`
	ReferenceID     string `json:"reference_id,omitempty"`
	ContentType     string `json:"content_type,omitempty"`
	Size            int64  `json:"size"`
	SHA256          string `json:"sha256,omitempty"`
	TextPreview     string `json:"text_preview,omitempty"`
	DataBase64      string `json:"data_base64,omitempty"`
	DownloadURL     string `json:"download_url,omitempty"`
	ObjectKey       string `json:"object_key,omitempty"`
	StorageBackend  string `json:"storage_backend,omitempty"`
	RetentionUntil  string `json:"retention_until,omitempty"`
	RetentionStatus string `json:"retention_status,omitempty"`
}

var retainedSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

const maxAccessRetentionTextBytes = 64 * 1024

// accessContentLogUpsertSQL 把留证正文与工具调用索引一起落库。tool_call_metadata_json 与
// file_metadata_json 同级：正文里已经有【工具】段（人可读），这份 JSON 是机器可读的结构索引
// （工具名、种类、阶段、脱敏后的参数/结果预览）。空工具轮写 '[]' 而不是 NULL，读侧不用判空。
func accessContentLogUpsertSQL() string {
	return `
		INSERT INTO access_content_logs (
			id, request_id, tenant_id, provider, product,
			request_content_redacted, response_content_redacted,
			file_metadata_json, decoder_name, decoder_version,
			conversation_id, section_id, model,
			retention_until, environment_scope, tool_call_metadata_json, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''), NOW() + ($14::int * INTERVAL '1 day'), $15, $16::jsonb, NOW())
		ON CONFLICT (request_id) DO UPDATE SET
			provider = EXCLUDED.provider,
			product = EXCLUDED.product,
			request_content_redacted = EXCLUDED.request_content_redacted,
			response_content_redacted = EXCLUDED.response_content_redacted,
			file_metadata_json = EXCLUDED.file_metadata_json,
			decoder_name = EXCLUDED.decoder_name,
			decoder_version = EXCLUDED.decoder_version,
			conversation_id = NULLIF(EXCLUDED.conversation_id, ''),
			section_id = NULLIF(EXCLUDED.section_id, ''),
			model = NULLIF(EXCLUDED.model, ''),
			retention_until = EXCLUDED.retention_until,
			environment_scope = EXCLUDED.environment_scope,
			tool_call_metadata_json = EXCLUDED.tool_call_metadata_json
	`
}

func (a *AuditWriter) WriteAccessContentLog(ctx context.Context, record ProxyAuditRecord, requestContent, responseContent ExtractedContent) {
	if a == nil || a.db == nil {
		return
	}
	// Scope the record before building retained-artifact writes so the request,
	// content row, artifact and artifact link all share one customer identity.
	record = a.withEnvironmentScope(record)
	retentionDays := a.accessContentRetentionDays(ctx)
	retentionUntil := time.Now().UTC().AddDate(0, 0, retentionDays)
	payload, ok := buildAccessContentLogPayloadWithRetentionStore(ctx, a.RetentionStore(), retentionUntil, record, requestContent, responseContent)
	if !ok {
		return
	}

	if _, err := a.db.Exec(ctx, accessContentLogUpsertSQL(), payload.ID, payload.RequestID, payload.TenantID, payload.Provider, payload.Product, payload.RequestContentRedacted, payload.ResponseContentRedacted, payload.FileMetadataJSON, payload.DecoderName, payload.DecoderVersion, payload.ConversationID, payload.SectionID, payload.Model, retentionDays, record.EnvironmentScope, payload.ToolCallMetadataJSON); err != nil {
		log.Printf("Failed to write access content log: %v", err)
		return
	}
	if patch := forwardProxyTurnPatch(record, requestContent, responseContent, payload.ResponseContentRedacted); patch != nil {
		if _, err := a.db.Exec(ctx, retentionturn.UpdateSQL, record.TenantID, record.RequestID, record.EnvironmentScope, string(patch)); err != nil {
			log.Printf("Failed to write forward proxy turn correlation: %v", err)
		}
	}

	a.persistRetainedArtifacts(ctx, record, retentionUntil, payload.ArtifactMetadata)
}

func isInternalTopicTitleGeneration(record ProxyAuditRecord, requestContent, responseContent ExtractedContent) bool {
	agentType := strings.ToLower(strings.TrimSpace(record.AgentType))
	if agentType == "codebuddy" {
		path := strings.ToLower(strings.TrimSpace(strings.SplitN(record.TargetPath, "?", 2)[0]))
		if normalizeHost(record.TargetHost) != "copilot.tencent.com" ||
			path != "/v2/chat/completions" ||
			record.RequestBytes <= 0 || record.RequestBytes > 4096 ||
			!strings.EqualFold(strings.TrimSpace(requestContent.Model), "deepseek-v4-pro") ||
			len(requestContent.Attachments) > 0 {
			return false
		}
		requestText := strings.TrimSpace(strings.ReplaceAll(requestContent.Text, "\r\n", "\n"))
		responseText := strings.TrimSpace(responseContent.Text)
		return strings.HasPrefix(requestText, "Q:") &&
			strings.Contains(requestText, "\nA:") &&
			responseText != "" &&
			!strings.Contains(responseText, "\n") &&
			len([]rune(responseText)) <= 80
	}
	if agentType != "workbuddy" {
		return false
	}
	path := strings.ToLower(strings.TrimSpace(strings.SplitN(record.TargetPath, "?", 2)[0]))
	requestText := strings.TrimSpace(requestContent.Text)
	if normalizeHost(record.TargetHost) != "copilot.tencent.com" ||
		path != "/v2/chat/completions" ||
		record.RequestBytes <= 0 || record.RequestBytes > 4096 ||
		!strings.EqualFold(strings.TrimSpace(requestContent.Model), "deepseek-v4-flash") ||
		len(requestContent.Attachments) > 0 ||
		!strings.HasPrefix(requestText, "<session>") || !strings.HasSuffix(requestText, "</session>") {
		return false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(responseContent.Text)), &raw); err != nil || len(raw) != 2 {
		return false
	}
	isNewTopicRaw, hasIsNewTopic := raw["isNewTopic"]
	titleRaw, hasTitle := raw["title"]
	if !hasIsNewTopic || !hasTitle {
		return false
	}
	var isNewTopic bool
	var title string
	if json.Unmarshal(isNewTopicRaw, &isNewTopic) != nil || json.Unmarshal(titleRaw, &title) != nil {
		return false
	}
	return isNewTopic && strings.TrimSpace(title) != ""
}

func buildAccessContentLogPayload(record ProxyAuditRecord, requestContent, responseContent ExtractedContent) (accessContentLogPayload, bool) {
	return buildAccessContentLogPayloadWithRetentionStore(context.Background(), nil, time.Time{}, record, requestContent, responseContent)
}

func buildAccessContentLogPayloadWithRetentionStore(ctx context.Context, store retentionstore.Store, retentionUntil time.Time, record ProxyAuditRecord, requestContent, responseContent ExtractedContent) (accessContentLogPayload, bool) {
	if record.RequestID == "" || record.TenantID == "" || !record.ContentRetained || record.RetentionLevel != "content" {
		return accessContentLogPayload{}, false
	}
	// WorkBuddy 会在真正对话开始前额外调用一次模型生成侧边栏标题，响应形态固定为
	// {"isNewTopic": ..., "title": ...}。这不是用户与模型的一轮对话；若写入内容留证，
	// 它会因首条 user 锚点不同而形成一个孤立 conversation_id，看起来像同一 UI 会话
	// 被拆成两条。原始 request_log 仍保留，只跳过这条内部元数据调用的正文留证。
	if isInternalTopicTitleGeneration(record, requestContent, responseContent) {
		return accessContentLogPayload{}, false
	}
	metadata := redactRetainedAttachments("request", requestContent.Attachments)
	metadata = append(metadata, redactRetainedAttachments("response", responseContent.Attachments)...)
	metadata = externalizeRetainedAttachmentData(ctx, store, record, retentionUntil, metadata)
	metadata = resolveRetainedUploadMetadata(defaultRetainedUploadCatalog, record.TenantID, record.Provider, metadata)
	// 结构化解码器（openai_compatible / anthropic_messages / yuanbao_web 等）产出带 source 的
	// 消息数组时，按 role 渲染留证文本（system/tool 段加【系统】/【工具】前缀），前端 collapseSystem
	// Sections 据此把机器噪音段默认折叠、只显真实对话（如 WorkBuddy 只显"真的吗"，652 行系统提示词
	// 折叠）。无 Messages 时退回原平铺 Text，旧解码器零改动。
	//
	// 工具轮补全（v3）：请求侧除了最近一条用户文本，还要带上该轮之后的【工具】段——编码 agent
	// 读进来的文件/命令输出正是命中规则的地方，此前完全没留证；响应侧同理（纯 tool_use 轮的
	// VisibleText 为空，此前留证是空串）。归一化必须先于拼接：NormalizeRetainedUserText 会把以
	// 【工具】开头的段落当内部角色丢弃。
	requestSource := requestContent.Text
	var requestToolSections []string
	decoderVersion := "v1"
	if len(requestContent.Messages) > 0 {
		requestSource, requestToolSections = retainedRequestText(requestContent.Messages)
		decoderVersion = "v3"
	}
	requestSource = aimsg.NormalizeRetainedUserText(requestSource)
	responseSource := responseContent.Text
	var responseToolSections []string
	if responseContent.VisibleTextKnown {
		responseSource = responseContent.VisibleText
		// 工具行只存在于 Text（VisibleText 只含 text 块），故从 Text 里挑。
		responseToolSections = retainedResponseToolSections(responseContent.Text)
	}
	if len(responseContent.Messages) > 0 {
		responseSource = messagesToRetentionText(responseContent.Messages)
		responseToolSections = nil
		if decoderVersion == "v1" {
			decoderVersion = "v2"
		}
	}
	responseSource = aimsg.NormalizeRetainedAssistantText(responseSource)
	requestText := redactRetainedText(joinRetainedToolSections(requestSource, requestToolSections))
	responseText := redactRetainedText(joinRetainedToolSections(responseSource, responseToolSections))
	if strings.TrimSpace(requestText) == "" && strings.TrimSpace(responseText) == "" && len(metadata) == 0 && requestContent.TurnRequest == nil {
		return accessContentLogPayload{}, false
	}
	toolCalls := make([]retainedToolCall, 0, len(requestContent.ToolCalls)+len(responseContent.ToolCalls))
	toolCalls = append(toolCalls, requestContent.ToolCalls...)
	toolCalls = append(toolCalls, responseContent.ToolCalls...)
	toolCallsJSON, _ := json.Marshal(toolCalls)
	metadataJSON, _ := json.Marshal(metadata)
	return accessContentLogPayload{
		ID:                      "acl_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		RequestID:               record.RequestID,
		TenantID:                record.TenantID,
		Provider:                record.Provider,
		Product:                 record.Product,
		RequestContentRedacted:  requestText,
		ResponseContentRedacted: responseText,
		FileMetadataJSON:        string(metadataJSON),
		ToolCallMetadataJSON:    string(toolCallsJSON),
		DecoderName:             firstNonEmpty(record.Product, record.Provider, "llm_provider_catalog"),
		DecoderVersion:          decoderVersion,
		ConversationID:          firstNonEmpty(responseContent.ConversationID, requestContent.ConversationID),
		SectionID:               firstNonEmpty(responseContent.SectionID, requestContent.SectionID),
		Model:                   firstNonEmpty(responseContent.Model, requestContent.Model),
		ArtifactMetadata:        metadata,
	}, true
}

func redactRetainedAttachments(stage string, items []ExtractedAttachment) []retainedAttachmentMetadata {
	out := make([]retainedAttachmentMetadata, 0, len(items))
	for _, item := range items {
		meta := retainedAttachmentMetadata{
			Source:      sanitizeRetainedStorageText(item.Source),
			Stage:       sanitizeRetainedStorageText(stage),
			FieldName:   sanitizeRetainedStorageText(item.FieldName),
			FileName:    sanitizeRetainedStorageText(item.FileName),
			ReferenceID: sanitizeRetainedStorageText(item.ReferenceID),
			ContentType: sanitizeRetainedStorageText(item.ContentType),
			Size:        item.Size,
			SHA256:      sanitizeRetainedStorageText(item.SHA256),
			TextPreview: redactRetainedText(item.TextPreview),
		}
		if item.DataBase64 != "" {
			meta.DataBase64 = sanitizeRetainedStorageText(item.DataBase64)
		}
		if item.DownloadURL != "" {
			meta.DownloadURL = sanitizeRetainedStorageText(item.DownloadURL)
		}
		out = append(out, meta)
	}
	return out
}

// WriteSecurityEvent writes a security event entry linked to a forward proxy request.
// UpdateTunnelTraffic 在不解密 CONNECT 隧道结束时回写上/下行字节数与持续时长。
// 只更新已存在的行（按 tenant_id + request_id），不插入；失败只打日志。
func (a *AuditWriter) UpdateTunnelTraffic(ctx context.Context, requestID, tenantID string, stats tunnelStats) {
	if a == nil || a.db == nil || requestID == "" || tenantID == "" {
		return
	}
	durationMS := stats.Duration.Milliseconds()
	if durationMS < 1 {
		durationMS = 1
	}
	tag, err := a.db.Exec(ctx, `
		UPDATE request_logs
		SET proxy_request_bytes = $3, proxy_response_bytes = $4, proxy_tunnel_duration_ms = $5
		WHERE tenant_id = $1 AND request_id = $2`,
		tenantID, requestID, stats.UpBytes, stats.DownBytes, durationMS)
	if err != nil {
		log.Printf("Failed to update tunnel traffic for %s: %v", requestID, err)
		return
	}
	if tag.RowsAffected() == 0 {
		log.Printf("Tunnel traffic update matched no request log: %s", requestID)
	}
}

func (a *AuditWriter) WriteSecurityEvent(ctx context.Context, requestID, tenantID, targetHost string, action string, findings []map[string]interface{}, stage string) {
	a.WriteSecurityEventForRecord(ctx, ProxyAuditRecord{
		RequestID:  requestID,
		TenantID:   tenantID,
		ProjectID:  defaultForwardProxyProjectID,
		TargetHost: targetHost,
	}, action, findings, stage)
}

func securityEventProjectID(record ProxyAuditRecord) string {
	if strings.TrimSpace(record.ProjectID) != "" {
		return record.ProjectID
	}
	return defaultForwardProxyProjectID
}

func securityEventInsertSQL() string {
	return `
		INSERT INTO security_events (
			id, request_id, tenant_id, project_id, event_type, severity,
			rule_id, action_taken, matched_summary, evidence_ref, created_at, principal_key,
			effective_severity, class_key
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''))
	`
}

func proxyFindingCountsAsSecurity(finding map[string]interface{}) bool {
	value, exists := finding["counts_as_security_finding"]
	if !exists {
		return true
	}
	counts, ok := value.(bool)
	return !ok || counts
}

func countProxySecurityFindings(findings []map[string]interface{}) int {
	count := 0
	for _, finding := range findings {
		if proxyFindingCountsAsSecurity(finding) {
			count++
		}
	}
	return count
}

func proxySecurityEventAttribution(findings []map[string]interface{}) (string, string) {
	bestRank := -1
	ruleID := ""
	classKey := ""
	for _, finding := range findings {
		if !proxyFindingCountsAsSecurity(finding) {
			continue
		}
		category := proxyFindingString(finding, "category")
		severity := strings.ToLower(proxyFindingString(finding, "severity"))
		rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}[severity]
		if classKey == "" || rank > bestRank {
			classKey = category
			bestRank = rank
		}
		policyCode := proxyFindingString(finding, "policy_code")
		findingType := proxyFindingString(finding, "type")
		candidateRuleID := proxyFindingString(finding, "rule_id")
		if ruleID == "" && candidateRuleID != "" && (policyCode != "" || findingType == "custom") {
			ruleID = candidateRuleID
		}
	}
	return ruleID, classKey
}

func proxyFindingString(finding map[string]interface{}, key string) string {
	value, ok := finding[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// WriteSecurityEventForRecord writes a security event with proxy catalog context.
func (a *AuditWriter) WriteSecurityEventForRecord(ctx context.Context, record ProxyAuditRecord, action string, findings []map[string]interface{}, stage string) string {
	if a == nil || a.db == nil || record.RequestID == "" {
		return ""
	}
	action = normalizeAction(action)
	// The durable job publishes one final threat event after all parts finish.
	// Keep provisional evidence in the encrypted queue rather than duplicating alerts.
	if record.ScanMode == "durable_inspection" && record.InputSemanticReason == "inspection_queued" && stage == "input" {
		return ""
	}
	securityFindingCount := countProxySecurityFindings(findings)
	if securityFindingCount == 0 && (action == "allow" || action == "audit") && !record.semanticIncomplete(stage) {
		return ""
	}

	eventID := uuid.New().String()
	matchedSummary := buildSecurityEventSummaryForRecord(record, stage, findings)
	if record.Status == "blocked" && securityexit.Blocks(action) {
		matchedSummary["block"] = proxyBlockAttribution(record.RequestID, eventID, stage, findings)
	}
	matchedJSON, _ := json.Marshal(matchedSummary)

	severity := severityForActionAndFindings(action, findings)
	ruleID, classKey := proxySecurityEventAttribution(findings)
	effectiveSeverity := proxySecurityEventEffectiveSeverity(findings, severity)
	eventType := fmt.Sprintf("proxy_%s_%s", stage, action)
	if record.semanticIncomplete(stage) && securityFindingCount == 0 {
		eventType = "security_check_failed"
		severity = "low"
	}
	// principal_key（契约第 6 条）：正向代理路径仅有来源 IP 归属——ProxyAuditRecord
	// 无 user_id/client_id 字段，故 principal_key = source_ip 兜底；空来源 IP 由 SQL 的
	// NULLIF 归 NULL，便于 COALESCE(user_id, client_id, source_ip) 归属统计。
	// MITM 员工级归属本轮不做。
	// Task 3b: an upstream account / credential fingerprint is a real subject, so it
	// outranks the NAT source address; the source IP stays the fallback.
	_, err := a.db.Exec(ctx, securityEventInsertSQL(),
		eventID,
		record.RequestID,
		record.TenantID,
		securityEventProjectID(record),
		eventType,
		severity,
		ruleID,
		action,
		matchedJSON,
		fmt.Sprintf("request_logs:%s", record.RequestID),
		time.Now(),
		firstNonEmpty(strings.TrimSpace(record.UpstreamPrincipal), strings.TrimSpace(record.SourceIP)),
		effectiveSeverity,
		classKey,
	)
	if err != nil {
		log.Printf("Failed to write security event request_id=%s event_id=%s: %v", record.RequestID, eventID, err)
		return ""
	}
	return eventID
}

func auditResult(action string, findings []map[string]interface{}) map[string]interface{} {
	action = normalizeAction(action)
	securityFindingCount := countProxySecurityFindings(findings)
	if action == "allow" && len(findings) == 0 {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"action_taken":   action,
		"findings":       redactFindings(findings),
		"findings_count": securityFindingCount,
		"check_time":     time.Now().Format(time.RFC3339),
	}
}

func mustJSON(v map[string]interface{}) []byte {
	if len(v) == 0 {
		return []byte("{}")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func buildSecurityEventSummary(targetHost, stage string, findings []map[string]interface{}) map[string]interface{} {
	return buildSecurityEventSummaryForRecord(ProxyAuditRecord{TargetHost: targetHost}, stage, findings)
}

func buildSecurityEventSummaryForRecord(record ProxyAuditRecord, stage string, findings []map[string]interface{}) map[string]interface{} {
	summary := map[string]interface{}{
		"target_host":    normalizeHost(record.TargetHost),
		"stage":          stage,
		"findings_count": countProxySecurityFindings(findings),
	}
	putSecurityEventFindings(summary, findings)
	status, reason := record.InputSemanticStatus, record.InputSemanticReason
	if stage == "output" {
		status, reason = record.OutputSemanticStatus, record.OutputSemanticReason
	}
	if status != "" {
		summary["semantic_status"] = status
		summary["semantic_reason"] = reason
	}
	if status == "incomplete" && countProxySecurityFindings(findings) == 0 {
		summary["category"] = "system"
		summary["counts_as_security_finding"] = false
	}
	if stage == "output" && record.OutputAlreadySent {
		summary["output_already_sent"] = true
		summary["enforcement_boundary"] = "post_send_audit"
	}
	if record.AccessType != "" {
		summary["access_type"] = record.AccessType
	}
	if record.Provider != "" {
		summary["provider"] = record.Provider
	}
	if record.Product != "" {
		summary["product"] = record.Product
	}
	if record.EndpointKind != "" {
		summary["endpoint_kind"] = record.EndpointKind
	}
	if record.ScanMode != "" {
		summary["scan_mode"] = record.ScanMode
		if record.FirstSeenRequestID != "" {
			summary["first_seen_request_id"] = record.FirstSeenRequestID
		}
	}
	summary["tls_inspected"] = record.TLSInspected
	return summary
}

var findingContentLocation = regexp.MustCompile(`^content\[[0-9]{1,9}:[0-9]{1,9}\]$`)

// redactFindings 生成落库的命中证据。2.9.22 起（用户 11-17 定）与网关同口径：字面类命中的 raw_evidence、
// evidence_context 存原文（见 putLiteralEvidence），语义类、运行类照旧只存哈希；matched、token、
// credential 一类的其它字段仍只存哈希和打码预览。
func redactFindings(findings []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(findings))
	for _, finding := range findings {
		storesRaw := findingStoresRaw(finding)
		item := map[string]interface{}{}
		for key, value := range finding {
			lowerKey := strings.ToLower(key)
			// secret_text 是引擎给网关打码用的秘密本体，预览和哈希也不能落库。
			// 证据身份只认代理自己按旧口径算出的值，引擎回包里带的一律丢掉。
			if lowerKey == "secret_text" || lowerKey == alertevidence.IdentityKey {
				continue
			}
			if storesRaw && (lowerKey == alertevidence.FieldRawEvidence || lowerKey == alertevidence.FieldEvidenceContext) {
				item[key+"_sha256"] = hashValue(fmt.Sprint(value))
				continue
			}
			// Locations contain offsets, not content. Keep the validated anchor
			// so authorized readers can recover evidence by its stored digest.
			if lowerKey == "matched_location" && findingContentLocation.MatchString(fmt.Sprint(value)) {
				item[key] = value
				continue
			}
			if lowerKey == "matched_text_preview" {
				item[key] = redactValue(fmt.Sprint(value))
				item[key+"_sha256"] = hashValue(fmt.Sprint(value))
				continue
			}
			if shouldRedactFindingField(lowerKey) {
				item[key+"_sha256"] = hashValue(fmt.Sprint(value))
				if lowerKey == alertevidence.FieldRawEvidence || lowerKey == alertevidence.FieldEvidenceContext {
					item[key+"_preview"] = "<MASKED>"
				} else {
					item[key+"_preview"] = redactValue(fmt.Sprint(value))
				}
				continue
			}
			item[key] = value
		}
		if storesRaw {
			putLiteralEvidence(item, finding)
		}
		if preview, ok := item["matched_text_preview"].(string); ok && preview != "" {
			if existing, _ := item["redacted_evidence"].(string); strings.TrimSpace(existing) == "" {
				item["redacted_evidence"] = preview
			}
		}
		out = append(out, item)
	}
	return out
}

// putSecurityEventFindings 写安全事件摘要的命中，与网关同口径：findings 同 redactFindings，按事件原文总量限制，
// 主命中与阻断依据的那条（第一条阻断动作的命中，控制面阻断记录取它）先占预算；primary_finding 是主命中
// 去掉原文、用 findings_index 指向 findings 的引用。请求审计结果（auditResult，写 request_logs）不走这里，保持原样。
func putSecurityEventFindings(summary map[string]interface{}, findings []map[string]interface{}) {
	var reserved []int
	primary, hasPrimary := proxyDominantFindingIndex(findings)
	if hasPrimary {
		reserved = append(reserved, primary)
	}
	for index, finding := range findings {
		action := strings.ToLower(strings.TrimSpace(fmt.Sprint(finding["action"])))
		if action == "block" || action == "quarantine" || action == "deny" || action == "blocked" {
			reserved = append(reserved, index)
			break
		}
	}
	items := alertevidence.LimitEventRaw(redactFindings(findings), reserved...)
	summary["findings"] = items
	if hasPrimary {
		summary["primary_finding"] = alertevidence.PrimaryReference(items[primary], primary)
	}
}

// proxyDominantFindingIndex 选主命中，规则与网关 dominantSecurityFinding 一致：只看计入安全命中的命中，
// 严重度高者优先，其次事实类（金丝雀 2，密钥或已验证 1），再次置信度，最后 type|category|rule_id|rule_name 字典序小者。
func proxyDominantFindingIndex(findings []map[string]interface{}) (int, bool) {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	fact := func(finding map[string]interface{}) int {
		triage, _ := finding["triage"].(map[string]interface{})
		if canary, _ := triage["is_canary"].(bool); canary {
			return 2
		}
		if proxyFindingString(finding, "type") == "secret" {
			return 1
		}
		if verified, _ := triage["verified_fact"].(bool); verified {
			return 1
		}
		return 0
	}
	confidence := func(finding map[string]interface{}) float64 {
		value, _ := finding["confidence"].(float64)
		return value
	}
	key := func(finding map[string]interface{}) string {
		return strings.Join([]string{proxyFindingString(finding, "type"), proxyFindingString(finding, "category"),
			proxyFindingString(finding, "rule_id"), proxyFindingString(finding, "rule_name")}, "|")
	}
	best := -1
	for index, finding := range findings {
		if !proxyFindingCountsAsSecurity(finding) {
			continue
		}
		if best < 0 {
			best = index
			continue
		}
		current, top := findings[index], findings[best]
		r, br := rank[strings.ToLower(proxyFindingString(current, "severity"))], rank[strings.ToLower(proxyFindingString(top, "severity"))]
		if r > br || (r == br && (fact(current) > fact(top) || (fact(current) == fact(top) &&
			(confidence(current) > confidence(top) || (confidence(current) == confidence(top) && key(current) < key(top)))))) {
			best = index
		}
	}
	return best, best >= 0
}

func findingStoresRaw(finding map[string]interface{}) bool {
	text := func(key string) string { value, _ := finding[key].(string); return value }
	return alertevidence.StoresRaw(text("type"), text("category"), text("evidence_kind"))
}

// putLiteralEvidence 写字面类命中的原文片段（超长截断并标 raw_evidence_truncated）、命中前后各 120 字的
// 不打码前后文，以及证据身份：2.9.21 落库的是打码预览，证据身份按它算，升级前后同一命中不分案。
func putLiteralEvidence(item, finding map[string]interface{}) {
	raw, _ := finding[alertevidence.FieldRawEvidence].(string)
	context, _ := finding[alertevidence.FieldEvidenceContext].(string)
	if raw == "" && context == "" {
		return
	}
	legacyPreview, _ := item["matched_text_preview"].(string)
	item[alertevidence.IdentityKey] = alertevidence.Identity(legacyPreview)
	// 位置可用时原文与前后文按位置从引擎前后文里取（内容里的实际原文），否则用引擎给的命中文字。
	location, _ := finding["matched_location"].(string)
	hit, window := alertevidence.Extract(raw, context, location)
	if hit != "" {
		stored, truncated := alertevidence.Truncate(hit)
		item[alertevidence.FieldRawEvidence] = alertevidence.Stored(stored)
		if truncated {
			item[alertevidence.FieldRawEvidenceTruncated] = true
		}
	}
	if window != "" {
		item[alertevidence.FieldEvidenceContext] = window
	}
}

func shouldRedactFindingField(key string) bool {
	return key == alertevidence.FieldRawEvidence || key == alertevidence.FieldEvidenceContext ||
		strings.Contains(key, "matched") || strings.Contains(key, "secret") ||
		strings.Contains(key, "token") || strings.Contains(key, "credential") ||
		strings.Contains(key, "preview")
}

func redactValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if utf8.RuneCountInString(value) <= 6 {
		return "***"
	}
	runes := []rune(value)
	return string(runes[:3]) + "***" + string(runes[len(runes)-3:])
}

func sanitizeRetainedStorageText(value string) string {
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\x00", "")
	return strings.ToValidUTF8(value, "")
}

func redactRetainedText(value string) string {
	value = strings.TrimSpace(sanitizeRetainedStorageText(value))
	if value == "" {
		return ""
	}
	for _, pattern := range retainedSecretPatterns {
		value = pattern.ReplaceAllString(value, "<redacted:secret>")
	}
	if len(value) > maxAccessRetentionTextBytes {
		value = sanitizeRetainedStorageText(value[:maxAccessRetentionTextBytes]) + "...[truncated]"
	}
	return sanitizeRetainedStorageText(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hashValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Severity follows evidence, independently of the configured policy action.
func severityForActionAndFindings(_ string, findings []map[string]interface{}) string {
	best := "low"
	ranks := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, finding := range findings {
		if !proxyFindingCountsAsSecurity(finding) && proxyFindingString(finding, "evidence_kind") != "runtime" {
			continue
		}
		severity := strings.ToLower(proxyFindingString(finding, "severity"))
		if ranks[severity] > ranks[best] {
			best = severity
		}
	}
	return best
}

func proxySecurityEventEffectiveSeverity(findings []map[string]interface{}, fallback string) string {
	best := strings.ToLower(strings.TrimSpace(fallback))
	bestRank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}[best]
	for _, finding := range findings {
		if !proxyFindingCountsAsSecurity(finding) {
			continue
		}
		severity := strings.ToLower(proxyFindingString(finding, "severity"))
		rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}[severity]
		if rank > bestRank {
			best, bestRank = severity, rank
		}
	}
	return best
}

func normalizeAction(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" || action == "pass" || action == "ok" {
		return "allow"
	}
	return action
}

func clientIPFromRequest(req *http.Request) string {
	// 只读采集源 IP：默认裸暴露场景下用 RemoteAddr，仅当 TCP peer 命中
	// TRUSTED_PROXY_CIDRS 时才采信 XFF/X-Real-IP，杜绝伪造。
	return clientip.ClientIP(req)
}

func summarizePathTemplate(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		if len(part) >= 16 || strings.Contains(lower, "-") || allDigits(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (r ProxyAuditRecord) semanticIncomplete(stage string) bool {
	if stage == "output" {
		return r.OutputSemanticStatus == "incomplete"
	}
	return r.InputSemanticStatus == "incomplete"
}

func forwardProxyTurnPatch(record ProxyAuditRecord, request, response ExtractedContent, visibleText string) []byte {
	if !record.ContentRetained || record.RetentionLevel != "content" || request.TurnRequest == nil {
		return nil
	}
	turnRequest := *request.TurnRequest
	turnRequest.IdentityKey = retentionturn.Digest(strings.Join([]string{record.SourceIP, record.TargetHost, record.AgentType}, "\x00"))
	output := response.TurnResponse
	if output == nil {
		output = retentionturn.BuildResponse(nil, visibleText)
	}
	return retentionturn.Patch(&turnRequest, output)
}
