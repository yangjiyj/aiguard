package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/aiconvo"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/clientip"
	"github.com/yangjiyj/aiguard/packages/shared-go/headercompat"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"github.com/yangjiyj/aiguard/packages/shared-go/logretention"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultReverseProxyRetentionDays = 90
	maxReverseProxyRetainedBodyBytes = 256 * 1024
	maxReverseProxyRetainedTextBytes = 64 * 1024
	// defaultReverseProxyProjectID 满足 security_events.project_id NOT NULL 外键。
	// 反向代理无业务 project，沿用 forward proxy 既有的 project_default 占位。
	defaultReverseProxyProjectID = "project_default"
)

type reverseProxyAuditRecorder interface {
	WriteReverseProxyAccess(ctx context.Context, record reverseProxyAuditRecord)
	WriteReverseProxyContent(ctx context.Context, record reverseProxyAuditRecord, requestBody []byte, requestContentType string, responseBody []byte, responseContentType string)
	// WriteReverseProxySecurityEvent 把运行时命中的 findings 落 security_events，
	// 由 control-plane SecEventBridge 升级为 alert_groups/alert_inbox 告警（不依赖 LSE 回写）。
	WriteReverseProxySecurityEvent(ctx context.Context, record reverseProxyAuditRecord, stage, actionTaken string, findings []SecurityFinding)
}

type reverseProxyAuditRecord struct {
	InputRetryIDs, OutputRetryIDs                                                        []string
	InputRetryUnavailable, OutputRetryUnavailable                                        bool
	EvidenceRunID                                                                        string
	AgentIdentityHeaders                                                                 string
	OutputAlreadySent                                                                    bool
	OutputGuarded                                                                        bool
	InputRawSecurityAction, OutputRawSecurityAction                                      string
	InputSemanticStatus, InputSemanticReason, OutputSemanticStatus, OutputSemanticReason string
	RequestID                                                                            string
	ProxyMode                                                                            string
	TenantID                                                                             string
	SessionID                                                                            string
	TraceID                                                                              string
	LSEEvalRunID                                                                         string
	LSETaskID                                                                            string
	LSESampleID                                                                          string
	LSETargetID                                                                          string
	TargetHost                                                                           string
	TargetPath                                                                           string
	Method                                                                               string
	SourceIP                                                                             string
	// ClientID 是调用方的稳定脱敏身份（caller_<sha256(key)前12位>），
	// 由请求的 Authorization/X-Api-Key 派生，不含任何明文密钥材料；无凭据时为空。
	ClientID                 string
	UserAgent                string
	RequestBytes             int64
	ResponseBytes            int64
	ResponseCaptureTruncated bool
	TLSInspected             bool
	Provider                 string
	ProviderCN               string
	Product                  string
	ProductCN                string
	EndpointKind             string
	AccessType               string
	PathTemplate             string
	URLHash                  string
	RetentionLevel           string
	ContentRetained          bool
	InputContentSource       string
	OutputContentSource      string
	AgentType                string
	Status                   string
	StatusCode               int
	LatencyMS                int
	InputTokens              int
	OutputTokens             int
}

type reverseProxyDBAuditRecorder struct {
	db               *pgxpool.Pool
	artifactStore    retentionstore.Store
	environmentScope string
}

func newReverseProxyDBAuditRecorder(db *pgxpool.Pool, environmentScope string) reverseProxyAuditRecorder {
	if db == nil {
		return nil
	}
	return &reverseProxyDBAuditRecorder{db: db, environmentScope: normalizeDeploymentEnvironmentScope(environmentScope)}
}

func newReverseProxyRequestID() string {
	return uuid.New().String()
}

func trimReverseProxyHeader(req *http.Request, name string) string {
	if req == nil {
		return ""
	}
	return strings.TrimSpace(req.Header.Get(name))
}

// reverseProxyCallerID 从调用方凭据派生稳定的脱敏身份，用于「是谁发的」归因。
// 只保留 sha256 摘要前缀，绝不存储明文密钥；同一 key 始终映射到同一 caller_id。
func reverseProxyCallerID(req *http.Request) string {
	if req == nil {
		return ""
	}
	cred := strings.TrimSpace(req.Header.Get("Authorization"))
	if cred == "" {
		cred = strings.TrimSpace(req.Header.Get("X-Api-Key"))
	}
	if cred == "" {
		cred = strings.TrimSpace(req.Header.Get("Api-Key"))
	}
	if cred == "" {
		return ""
	}
	// 去掉 Bearer/Basic 等鉴权方案前缀，只对密钥本体取摘要。
	if idx := strings.IndexByte(cred, ' '); idx > 0 {
		cred = strings.TrimSpace(cred[idx+1:])
	}
	if cred == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(cred))
	return "caller_" + hex.EncodeToString(sum[:])[:12]
}

func compactReverseProxyAuditID(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if value == "" || maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	suffix := hex.EncodeToString(sum[:])[:16]
	if maxLen <= len(suffix)+1 {
		return suffix[:maxLen]
	}
	return value[:maxLen-len(suffix)-1] + "_" + suffix
}

func newReverseProxyAuditRecord(requestID, tenantID, targetHost string, targetURL *url.URL, req *http.Request, requestBody, responseBody []byte, status string, statusCode int, responseBytes int64, latency time.Duration) (reverseProxyAuditRecord, error) {
	if requestID == "" {
		requestID = newReverseProxyRequestID()
	}
	if status == "" {
		status = "success"
	}
	path := "/"
	requestURI := "/"
	if targetURL != nil {
		path = targetURL.EscapedPath()
		if path == "" {
			path = "/"
		}
		requestURI = targetURL.RequestURI()
		if requestURI == "" {
			requestURI = path
		}
	}

	match := matchReverseProxyProvider(targetHost, path)
	pathTemplate := summarizeReverseProxyPathTemplate(path)
	accessType, retentionLevel, contentRetained := reverseProxyAccessPolicy(match)
	targetPath := requestURI
	if !contentRetained {
		targetPath = pathTemplate
	}
	method := ""
	sourceIP := ""
	userAgent := ""
	requestBytes := int64(len(requestBody))
	if req != nil {
		method = req.Method
		sourceIP = reverseProxyClientIP(req)
		userAgent = agentdetect.BoundedIdentityValue(req.UserAgent(), 512)
		if requestBytes == 0 && req.ContentLength > 0 {
			requestBytes = req.ContentLength
		}
	}
	inputTokens, outputTokens := parseReverseProxyUsage(responseBody)
	traceID := trimReverseProxyHeader(req, "X-LSE-Trace-Id")
	var sessionID string
	var err error
	if req != nil {
		sessionID, _, err = headercompat.Resolve(req.Header, "X-JJDGuard-Session-Id", "X-NewAPI-Session-Id")
		if err != nil {
			return reverseProxyAuditRecord{}, err
		}
	}
	if sessionID == "" {
		sessionID = traceID
	}
	sessionID = compactReverseProxyAuditID(sessionID, 64)

	agentType, err := inferReverseProxyAgentType(req, match, requestBody, responseBody)
	if err != nil {
		return reverseProxyAuditRecord{}, err
	}

	// Prefer the native Codex thread over a process session or prompt fingerprint.
	// Scope the client-declared ID to the tenant and authenticated proxy caller.
	if agentType == "openai-codex" && req != nil {
		caller := reverseProxyCallerID(req)
		if caller == "" {
			caller = sourceIP
		}
		if native := aiconvo.CodexThreadKey(req.Header, tenantID, caller); native != "" {
			sessionID = native
		}
	}

	taskID := ""
	if agentType == "workbuddy" {
		var structured struct {
			Messages []Message `json:"messages"`
		}
		if json.Unmarshal(requestBody, &structured) == nil {
			key, source := workBuddyEvidenceCorrelation(agentType, structured.Messages)
			taskID = deriveEvidenceRunID(tenantID, source, key)
		}
	}
	identityHeaders := "{}"
	if req != nil {
		identityHeaders = agentdetect.IdentityHeaders(req.Header)
	}
	return reverseProxyAuditRecord{
		AgentIdentityHeaders: identityHeaders,
		EvidenceRunID:        taskID,
		RequestID:            requestID,
		TenantID:             tenantID,
		SessionID:            sessionID,
		TraceID:              traceID,
		LSEEvalRunID:         trimReverseProxyHeader(req, "X-LSE-Eval-Run-Id"),
		LSETaskID:            trimReverseProxyHeader(req, "X-LSE-Task-Id"),
		LSESampleID:          trimReverseProxyHeader(req, "X-LSE-Sample-Id"),
		LSETargetID:          trimReverseProxyHeader(req, "X-LSE-Target-Id"),
		TargetHost:           llmcatalog.NormalizeHost(targetHost),
		TargetPath:           targetPath,
		Method:               method,
		SourceIP:             sourceIP,
		ClientID:             reverseProxyCallerID(req),
		UserAgent:            userAgent,
		RequestBytes:         requestBytes,
		ResponseBytes:        responseBytes,
		TLSInspected:         true,
		Provider:             match.Provider,
		ProviderCN:           match.ProviderCN,
		Product:              match.Product,
		ProductCN:            match.ProductCN,
		EndpointKind:         match.EndpointKind,
		AccessType:           accessType,
		PathTemplate:         pathTemplate,
		URLHash:              hashReverseProxyValue(llmcatalog.NormalizeHost(targetHost) + " " + method + " " + requestURI),
		RetentionLevel:       retentionLevel,
		ContentRetained:      contentRetained,
		AgentType:            agentType,
		Status:               status,
		StatusCode:           statusCode,
		LatencyMS:            int(latency / time.Millisecond),
		InputTokens:          inputTokens,
		OutputTokens:         outputTokens,
	}, nil
}

func reverseProxyAccessUpsertSQL() string {
	return `
		INSERT INTO request_logs (
			id, request_id, tenant_id, session_id, trace_id,
			lse_eval_run_id, lse_task_id, lse_sample_id, lse_target_id,
			agent_type, endpoint_type, request_status, upstream_status_code, latency_ms,
			input_tokens, output_tokens, total_cost, proxy_mode,
			proxy_target_host, proxy_target_path, proxy_method,
			proxy_source_ip, proxy_user_agent, proxy_request_bytes,
			proxy_response_bytes, proxy_tls_inspected, proxy_provider,
			proxy_product, proxy_endpoint_kind, proxy_access_type,
			proxy_access_type_resolved, proxy_path_template, proxy_url_hash,
			proxy_retention_level, proxy_content_retained, client_id, source_ip, environment_scope, created_at, agent_identity_headers, evidence_run_id, evidence_run_source
		) VALUES (
			$1, $2, $3, NULLIF($4, ''), NULLIF($5, ''),
			NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			$10, 'proxy', $11, $12, $13,
			$14, $15, NULL, $37,
			$16, $17, $18,
			$19, $20, $21,
			$22, $23, $24,
			$25, $26, $27,
			$27, $28, $29,
			$30, $31, NULLIF($32, ''), NULLIF($33, ''), $34, NOW(), COALESCE(NULLIF($35, ''), '{}')::jsonb, NULLIF($36,''), CASE WHEN $36::text<>'' THEN 'workbuddy_workspace' ELSE NULL END
		)
		ON CONFLICT (request_id) DO UPDATE SET
			session_id = COALESCE(NULLIF(EXCLUDED.session_id, ''), request_logs.session_id),
			trace_id = COALESCE(NULLIF(EXCLUDED.trace_id, ''), request_logs.trace_id),
			lse_eval_run_id = COALESCE(NULLIF(EXCLUDED.lse_eval_run_id, ''), request_logs.lse_eval_run_id),
			lse_task_id = COALESCE(NULLIF(EXCLUDED.lse_task_id, ''), request_logs.lse_task_id),
			lse_sample_id = COALESCE(NULLIF(EXCLUDED.lse_sample_id, ''), request_logs.lse_sample_id),
			lse_target_id = COALESCE(NULLIF(EXCLUDED.lse_target_id, ''), request_logs.lse_target_id),
			agent_type = COALESCE(NULLIF(EXCLUDED.agent_type, ''), request_logs.agent_type),
			request_status = EXCLUDED.request_status,
			upstream_status_code = EXCLUDED.upstream_status_code,
			latency_ms = EXCLUDED.latency_ms,
			input_tokens = EXCLUDED.input_tokens,
			output_tokens = EXCLUDED.output_tokens,
			proxy_mode = EXCLUDED.proxy_mode,
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
			client_id = COALESCE(NULLIF(EXCLUDED.client_id, ''), request_logs.client_id),
			source_ip = COALESCE(NULLIF(EXCLUDED.source_ip, ''), request_logs.source_ip),
			environment_scope = COALESCE(NULLIF(EXCLUDED.environment_scope, ''), request_logs.environment_scope)
	`
}

func (r *reverseProxyDBAuditRecorder) WriteReverseProxyAccess(ctx context.Context, record reverseProxyAuditRecord) {
	if r == nil || r.db == nil || record.TenantID == "" || record.RequestID == "" {
		return
	}
	if record.TargetHost == "" {
		record.TargetHost = "unknown"
	}
	proxyMode := record.ProxyMode
	if proxyMode == "" {
		proxyMode = "reverse"
	}
	_, err := r.db.Exec(ctx, reverseProxyAccessUpsertSQL(),
		"log_"+strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		record.RequestID,
		record.TenantID,
		record.SessionID,
		record.TraceID,
		record.LSEEvalRunID,
		record.LSETaskID,
		record.LSESampleID,
		record.LSETargetID,
		record.AgentType,
		record.Status,
		record.StatusCode,
		record.LatencyMS,
		record.InputTokens,
		record.OutputTokens,
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
		record.ClientID,
		record.SourceIP,
		r.environmentScope,
		record.AgentIdentityHeaders,
		record.EvidenceRunID,
		proxyMode,
	)
	if err != nil {
		log.Printf("Failed to write reverse proxy access retention log: %v", err)
	}
}

// reverseProxySecurityEventRow 是一条 security_events 行的归一化字段（不含 id/时间）。
type reverseProxySecurityEventRow struct {
	EventType         string
	Severity          string
	ActionTaken       string
	RuleID            string
	EffectiveSeverity string
	ClassKey          string
	MatchedSummary    map[string]interface{}
	EvidenceRef       string
}

// buildReverseProxySecurityEventRow 复用 chat 路径的 event_type/severity/rule_id/matched_summary
// 语义，把反向代理运行时 findings 归一为 security_events 行，确保安全事件页与告警桥零差异处理；
// 额外注入 stage/source/target_host/target_path，以及流量画像 access_type/product/endpoint_kind
// （与 C 路正向代理口径一致，非空才写），供收件箱闸 / 看板按维度过滤与闭环处置。
func buildReverseProxySecurityEventRow(record reverseProxyAuditRecord, stage, actionTaken string, findings []SecurityFinding) reverseProxySecurityEventRow {
	return buildReverseProxySecurityEventRowWithContext(record, stage, actionTaken, "", findings)
}

func buildReverseProxySecurityEventRowWithContext(record reverseProxyAuditRecord, stage, actionTaken, contentSource string, findings []SecurityFinding) reverseProxySecurityEventRow {
	summary := buildSecurityMatchedSummary(findings, actionTaken, reverseProxySecuritySummaryText(stage, findings))
	rawAction := record.InputRawSecurityAction
	if stage == "output" {
		rawAction = record.OutputRawSecurityAction
	}
	if rawAction != "" {
		summary["raw_action"] = rawAction
		summary["would_block"] = securityexit.Blocks(rawAction)
	}
	status, reason := record.InputSemanticStatus, record.InputSemanticReason
	if stage == "output" {
		status, reason = record.OutputSemanticStatus, record.OutputSemanticReason
	}
	if status != "" {
		summary["semantic_status"] = status
		summary["semantic_reason"] = reason
	}
	retryIDs, unavailable := record.InputRetryIDs, record.InputRetryUnavailable
	if stage == "output" {
		retryIDs, unavailable = record.OutputRetryIDs, record.OutputRetryUnavailable
	}
	if status == "incomplete" {
		summary["retry_task_ids"] = retryIDs
		summary["retry_unavailable"] = unavailable
		retryStatus := "retry_not_saved"
		if len(retryIDs) > 0 && !unavailable {
			retryStatus = "retry_pending"
		}
		summary["remediation"] = map[string]interface{}{"version": "durable-retry-v1", "status": retryStatus, "original_gap_resolved": false}
	}
	summary["stage"] = stage
	if stage == "output" && record.OutputAlreadySent {
		summary["output_already_sent"] = true
		summary["enforcement_boundary"] = "post_send_audit"
		if record.OutputGuarded {
			summary["enforcement_boundary"] = "stream_holdback"
		}
	}
	if strings.TrimSpace(contentSource) != "" && hasSecurityFindings(findings) {
		summary["content_source"] = contentSource
		if contentSource == "verified_user_input" || contentSource == "verified_final_output" {
			summary["review_state"] = "review_pending"
			summary["effective_severity"] = "medium"
		}
	}
	summary["source"] = "gateway_reverse_proxy"
	if record.ProxyMode == "forward" {
		summary["source"] = "gateway_forward_proxy"
		summary["tls_inspected"] = record.TLSInspected
	}
	if record.TargetHost != "" {
		summary["target_host"] = record.TargetHost
	}
	if record.TargetPath != "" {
		summary["target_path"] = record.TargetPath
	}
	if record.AccessType != "" {
		summary["access_type"] = record.AccessType
	}
	if record.Product != "" {
		summary["product"] = record.Product
	}
	if record.EndpointKind != "" {
		summary["endpoint_kind"] = record.EndpointKind
	}
	if status == "incomplete" && !hasSecurityFindings(findings) {
		switch actionTaken {
		case "security_audit_only", "security_audit":
			actionTaken = "audit"
		case "security_blocked":
			actionTaken = "block"
		case "security_allowed":
			actionTaken = "allow"
		}

		summary["counts_as_security_finding"] = false
		summary["category"] = "system"
		summary["summary"] = "语义检测未完成"
		return reverseProxySecurityEventRow{
			EventType: "security_check_failed", Severity: "low", ActionTaken: actionTaken,
			EffectiveSeverity: "low", ClassKey: "system",
			MatchedSummary: summary, EvidenceRef: "request_logs:" + record.RequestID,
		}
	}
	if isBlockingSecurityAction(actionTaken) {
		// Same attribution the gateway protocols persist; the block number is
		// the event id assigned when the row is written.
		attribution := deriveBlockAttribution(withSecurityEventStage(context.Background(), stage), "", findings, actionTaken, "")
		attribution.RequestID = record.RequestID
		summary["block"] = attribution
	}
	return reverseProxySecurityEventRow{
		EventType:         eventTypeForFindings(findings),
		Severity:          getFindingsSeverity(findings),
		ActionTaken:       actionTaken,
		RuleID:            firstPersistablePolicyRuleID(findings),
		EffectiveSeverity: securityEventEffectiveSeverity(findings, summary),
		ClassKey:          securityEventClassKey(findings, eventTypeForFindings(findings)),
		MatchedSummary:    summary,
		EvidenceRef:       "request_logs:" + record.RequestID,
	}
}

func reverseProxySecuritySummaryText(stage string, findings []SecurityFinding) string {
	label := stage
	switch stage {
	case "input":
		label = "输入"
	case "output":
		label = "输出"
	}
	return "反向代理" + label + "命中 " + strconv.Itoa(len(findings)) + " 项运行时安全风险"
}

// reverseProxyPrincipalKey 物化 principal_key（契约第 6 条）。反代路径无用户归属：
// client_id（caller_ 脱敏身份）优先，来源 IP 兜底——与设计"MITM 员工级归属不做，
// principal_key 用 source_ip 兜底"一致。
func reverseProxyPrincipalKey(record reverseProxyAuditRecord) string {
	if strings.TrimSpace(record.ClientID) != "" {
		return record.ClientID
	}
	return strings.TrimSpace(record.SourceIP)
}

// WriteReverseProxySecurityEvent 写一条与本次反向代理请求关联的安全事件。
// 调用方保证此前已写 request_logs（access 留证），以满足 request_id 外键。
func (r *reverseProxyDBAuditRecorder) WriteReverseProxySecurityEvent(ctx context.Context, record reverseProxyAuditRecord, stage, actionTaken string, findings []SecurityFinding) {
	incomplete := record.InputSemanticStatus == "incomplete"
	if stage == "output" {
		incomplete = record.OutputSemanticStatus == "incomplete"
	}
	if r == nil || r.db == nil || record.RequestID == "" || record.TenantID == "" || (!hasSecurityFindings(findings) && !incomplete) {
		return
	}
	contentSource := ""
	if stage == "input" {
		contentSource = record.InputContentSource
	} else if stage == "output" {
		contentSource = record.OutputContentSource
	}
	row := buildReverseProxySecurityEventRowWithContext(record, stage, actionTaken, contentSource, findings)
	eventID := newAuditID("evt_")
	if _, blocking := row.MatchedSummary["block"]; blocking {
		annotateSecurityEventBlock(withSecurityEventStage(ctx, stage), &modelrouter.RequestEnvelope{RequestID: record.RequestID, TenantID: record.TenantID}, eventID, findings, row.ActionTaken, "", row.MatchedSummary)
	}
	matchedJSON, _ := json.Marshal(row.MatchedSummary)
	query := `
		INSERT INTO security_events (
			id, request_id, tenant_id, project_id, event_type, severity,
			rule_id, action_taken, matched_summary, evidence_ref, created_at, principal_key,
			effective_severity, class_key
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10, NOW(), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''))
	`
	if _, err := r.db.Exec(ctx, query,
		eventID,
		record.RequestID,
		record.TenantID,
		defaultReverseProxyProjectID,
		row.EventType,
		row.Severity,
		row.RuleID,
		row.ActionTaken,
		matchedJSON,
		row.EvidenceRef,
		reverseProxyPrincipalKey(record),
		row.EffectiveSeverity,
		row.ClassKey,
	); err != nil {
		forgetBlockRecord(ctx, eventID)
		log.Printf("Failed to write reverse proxy security event request_id=%s event_id=%s: %v", record.RequestID, eventID, err)
	}
}
func (r *reverseProxyDBAuditRecorder) AnnotateReverseProxyTriage(ctx context.Context, record reverseProxyAuditRecord, stage string, findings []SecurityFinding, reviewState, effectiveSeverity string) {
	if r == nil || r.db == nil || record.RequestID == "" || record.TenantID == "" || stage == "" || len(findings) == 0 {
		return
	}
	triageByIdentity := map[string]map[string]any{}
	for _, finding := range findings {
		if len(finding.Triage) == 0 {
			continue
		}
		triageByIdentity[triageIdentityKey(finding.RuleID, finding.MatchedLocation)] = finding.Triage
	}
	if len(triageByIdentity) == 0 {
		return
	}
	if strings.TrimSpace(reviewState) == "" {
		reviewState = "needs_review"
	}
	if strings.TrimSpace(effectiveSeverity) == "" {
		effectiveSeverity = "medium"
	}
	triageJSON, err := json.Marshal(triageByIdentity)
	if err != nil {
		return
	}
	stateJSON, err := json.Marshal(map[string]string{
		"review_state":       reviewState,
		"effective_severity": effectiveSeverity,
	})
	if err != nil {
		return
	}
	if _, err := r.db.Exec(ctx, reverseProxyAnnotateTriageSQL, triageJSON, stateJSON, record.TenantID, record.RequestID, stage); err != nil {
		log.Printf("Failed to annotate reverse proxy triage req=%s stage=%s: %v", record.RequestID, stage, err)
	}
}

// reverseProxyAnnotateTriageSQL 回写反代事件的复核结论：findings 按原序号（WITH ORDINALITY）重组，顺序不变。
const reverseProxyAnnotateTriageSQL = `
		UPDATE security_events
		SET matched_summary = jsonb_set(
			matched_summary || $2::jsonb,
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
		WHERE tenant_id = $3
		  AND request_id = $4
		  AND matched_summary->>'stage' = $5
`

// reverseProxyContentInsertSQL 是反代 access_content_logs 落库语句：在原有列基础上补
// conversation_id/section_id/model 三列（设计文档 1a 评审修正：反代流量首次获得 SP4 分组能力），
// NULLIF 口径与 C 路 proxy-server audit.go 完全一致。抽成函数供 SQL 单测断言。
func reverseProxyContentInsertSQL() string {
	return `
		INSERT INTO access_content_logs (
			id, request_id, tenant_id, provider, product,
			request_content_redacted, response_content_redacted,
			file_metadata_json, decoder_name, decoder_version,
			conversation_id, section_id, model, environment_scope,
			retention_until, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''), $14, NOW() + ($15::int * INTERVAL '1 day'), NOW())
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
			environment_scope = COALESCE(NULLIF(EXCLUDED.environment_scope, ''), access_content_logs.environment_scope),
			retention_until = EXCLUDED.retention_until
	`
}

type reverseProxyRetentionProjection struct {
	RequestText    string
	ResponseText   string
	ConversationID string
	SectionID      string
	Model          string
	DecoderVersion string
}

// buildReverseProxyRetentionProjection 把物理 LLM 请求投影成客户可读的一次用户回合。
// 结构化成功时只展示最后 user 消息；已知 LLM 协议解析失败时保留 v1 遥测但不展示整包。
func buildReverseProxyRetentionProjection(record reverseProxyAuditRecord, parsed aimsg.ParsedChat, structured bool, fallbackRequestText, responseText string) reverseProxyRetentionProjection {
	projection := reverseProxyRetentionProjection{
		RequestText:    redactReverseProxyRetainedText(fallbackRequestText),
		ResponseText:   redactReverseProxyRetainedText(aimsg.NormalizeRetainedAssistantText(responseText)),
		DecoderVersion: "v1",
	}
	if !structured {
		if isReverseProxyChatEndpoint(record.TargetHost, record.TargetPath) {
			projection.RequestText = ""
		}
		return projection
	}

	projection.DecoderVersion = "v2"
	projection.Model = parsed.Model
	if strings.TrimSpace(parsed.LastUserText) == "" || parsed.LastUserSHA == "" {
		// 结构化 LLM 后台任务没有可确认的人类输入时，不把其模型输出单独投影到客户内容页。
		projection.RequestText = ""
		projection.ResponseText = ""
		return projection
	}
	projection.RequestText = redactReverseProxyRetainedText(parsed.LastUserText)
	projection.SectionID = parsed.LastUserSHA
	if strings.TrimSpace(parsed.LastUserText) != "" &&
		parsed.LastUserSHA != "" &&
		parsed.FirstUserSHA != "" {
		callerKey := reverseProxyTurnCallerKey(record)
		projection.ConversationID = aiconvo.ConversationKey(
			record.TenantID,
			callerKey,
			record.AgentType,
			aiconvo.SystemDigest(parsed.SystemText),
			parsed.FirstUserSHA,
		)
	}
	return projection
}

func reverseProxyTurnCallerKey(record reverseProxyAuditRecord) string {
	parts := make([]string, 0, 3)
	for _, value := range []struct {
		label string
		text  string
	}{
		{label: "client", text: record.ClientID},
		{label: "session", text: record.SessionID},
		{label: "source_ip", text: record.SourceIP},
	} {
		if text := strings.TrimSpace(value.text); text != "" {
			parts = append(parts, value.label+"="+text)
		}
	}
	return strings.Join(parts, "\x1f")

}

// reverseProxyMessageRow 是 content_logs 的一行用户可见消息。
type reverseProxyMessageRow struct {
	LogID   string
	Role    string
	Content string
	Tokens  int
}

// buildReverseProxyMessageRows 只保留当前回合最后一条真实 user 消息。
// 系统提示、Skill、工具定义、历史回答和工具结果由安全/工具审计链保留，不进入默认内容页。
func buildReverseProxyMessageRows(record reverseProxyAuditRecord, msgs []aimsg.ConvMessage) []reverseProxyMessageRow {
	var content string
	for i := range msgs {
		if msgs[i].Source != aimsg.SourceUser {
			continue
		}
		normalized, status, _ := aimsg.NormalizeAgentEnvelope(msgs[i].Content)
		if status != aimsg.ParseComplete || strings.TrimSpace(normalized) == "" {
			continue
		}
		content = normalized
	}
	if content == "" {
		return nil
	}
	content = redactReverseProxyRetainedText(content)
	if content == "" {
		return nil
	}
	return []reverseProxyMessageRow{{
		LogID:   "cl_rp_m0_" + hashReverseProxyValue(record.TenantID + "|" + record.RequestID + "|m0")[:16],
		Role:    "user",
		Content: content,
		Tokens:  record.InputTokens,
	}}
}

func (r *reverseProxyDBAuditRecorder) WriteReverseProxyContent(ctx context.Context, record reverseProxyAuditRecord, requestBody []byte, requestContentType string, responseBody []byte, responseContentType string) {
	if r == nil || r.db == nil || !record.ContentRetained || record.RequestID == "" || record.TenantID == "" {
		return
	}
	// 结构化解析（1a 反代路径，不设开关：role 错标是数据质量 bug；access_content_logs 平铺
	// 文本列不动，证据不减量）。注意用完整 requestBody 解析——截断字节会破坏 JSON；
	// 平铺留证文本仍走 extractReverseProxyRetainedText 的原截断口径。
	var parsed aimsg.ParsedChat
	structured := false
	if isReverseProxyChatEndpoint(record.TargetHost, record.TargetPath) {
		parsed, structured = aimsg.ParseChatRequest(record.TargetPath, requestBody)
	}
	fallbackRequestText := extractReverseProxyRetainedText(requestBody, requestContentType)
	responseText := extractReverseProxyRetainedText(responseBody, responseContentType)
	if isReverseProxyChatEndpoint(record.TargetHost, record.TargetPath) {
		if output, ok := extractReverseProxyLLMOutputCaptured(record.TargetPath, responseContentType, responseBody, record.ResponseCaptureTruncated); ok {
			responseText = output
		} else {
			responseText = ""
		}
	}
	if output, ok := parseReverseProxyOutputProjection(record.TargetPath, responseBody); ok {
		parsed.Artifacts = append(parsed.Artifacts, output.Artifacts...)
		if strings.TrimSpace(responseText) == "" {
			responseText = output.ModelOutput
		}
	}
	projection := buildReverseProxyRetentionProjection(
		record, parsed, structured, fallbackRequestText, responseText,
	)
	turnPatch := reverseProxyTurnPatch(record, parsed, structured, requestBody, responseBody, responseText)
	var turnContext retentionturn.Context
	_ = json.Unmarshal(turnPatch, &turnContext)
	continuation := turnContext.Request != nil && turnContext.Request.UserCount == 0 && len(turnContext.Request.Links) > 0
	if continuation && projection.RequestText == "" {
		projection.ResponseText = redactReverseProxyRetainedText(aimsg.NormalizeRetainedAssistantText(responseText))
	}
	if strings.TrimSpace(projection.RequestText) == "" && strings.TrimSpace(projection.ResponseText) == "" && len(parsed.Artifacts) == 0 && !continuation {
		return
	}

	retentionDays := r.retentionDays(ctx)
	retentionUntil := time.Now().UTC().AddDate(0, 0, retentionDays)
	_, err := r.db.Exec(ctx, reverseProxyContentInsertSQL(),
		"acl_"+strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		record.RequestID,
		record.TenantID,
		record.Provider,
		record.Product,
		projection.RequestText,
		projection.ResponseText,
		reverseProxyArtifactMetadataJSON(parsed.Artifacts),
		firstReverseProxyNonEmpty(record.Product, record.Provider, "reverse_proxy"),
		projection.DecoderVersion,
		projection.ConversationID,
		projection.SectionID,
		projection.Model,
		r.environmentScope,
		retentionDays,
	)
	if err != nil {
		log.Printf("Failed to write reverse proxy content retention log: %v", err)
	}
	if patch := turnPatch; patch != nil {
		if _, err := r.db.Exec(ctx, retentionturn.UpdateSQL, record.TenantID, record.RequestID, r.environmentScope, string(patch)); err != nil {
			log.Printf("Failed to write reverse proxy turn correlation: %v", err)
		}
	}

	r.retainReverseProxyArtifacts(ctx, record, parsed.Artifacts, retentionUntil)
	if structured {
		// 默认内容页只写当前用户原话；内部上下文由独立安全/工具审计链保留。
		for _, row := range buildReverseProxyMessageRows(record, parsed.Messages) {
			r.writeReverseProxyConversationRow(ctx, record, row.LogID, row.Role, row.Content, row.Tokens)
		}
	} else if !isReverseProxyChatEndpoint(record.TargetHost, record.TargetPath) {
		// 非 LLM 普通文本流量维持原平铺留证。
		r.writeReverseProxyConversationLog(ctx, record, "user", projection.RequestText, record.InputTokens)
	}
	r.writeReverseProxyConversationLog(ctx, record, "assistant", projection.ResponseText, record.OutputTokens)
}

func (r *reverseProxyDBAuditRecorder) writeReverseProxyConversationLog(ctx context.Context, record reverseProxyAuditRecord, role, content string, tokens int) {
	logID := "cl_rp_" + role[:1] + "_" + hashReverseProxyValue(record.TenantID + "|" + record.RequestID + "|" + role)[:16]
	r.writeReverseProxyConversationRow(ctx, record, logID, role, content, tokens)
}

// writeReverseProxyConversationRow 落一行 content_logs（query 与原 writeReverseProxyConversationLog
// 完全相同，只是 logID 由调用方决定，供结构化逐消息写入复用）。
func (r *reverseProxyDBAuditRecorder) writeReverseProxyConversationRow(ctx context.Context, record reverseProxyAuditRecord, logID, role, content string, tokens int) {
	content = strings.TrimSpace(content)
	if content == "" {
		return
	}
	sessionID := compactReverseProxyAuditID(firstReverseProxyNonEmpty(record.SessionID, record.TraceID, record.RequestID), 64)
	query := `
		WITH request_log AS (
			SELECT id, user_id
			FROM request_logs
			WHERE tenant_id = $1 AND request_id = $2
			LIMIT 1
		-- content_logs 是兼容视图（987），不支持 ON CONFLICT：同一 id 已存在则更新，否则插入。
		), existing AS (
			UPDATE content_logs cl SET session_id = $4, role = $5, content = $6, tokens = $7, created_at = NOW()
			WHERE cl.id = $3 AND EXISTS (SELECT 1 FROM request_log)
			RETURNING cl.id
		)
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, environment_scope, created_at)
		SELECT $3, request_log.id, $1, request_log.user_id, $4, $5, $6, $7, $8, NOW()
		FROM request_log
		WHERE NOT EXISTS (SELECT 1 FROM existing)
	`
	if _, err := r.db.Exec(ctx, query, record.TenantID, record.RequestID, logID, sessionID, role, content, tokens, r.environmentScope); err != nil {
		log.Printf("Failed to write reverse proxy conversation content log: %v", err)
	}
}

func (r *reverseProxyDBAuditRecorder) retentionDays(ctx context.Context) int {
	var raw string
	if err := r.db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = 'log_retention_days'`).Scan(&raw); err != nil {
		return defaultReverseProxyRetentionDays
	}
	// 与 control-plane 清理任务同一口径（最少 30 天）。
	return logretention.Resolve(raw)
}

func matchReverseProxyProvider(host, path string) llmcatalog.MatchResult {
	match := llmcatalog.Match(host, path)
	if match.Known {
		return match
	}
	if !isOpenAICompatibleAPIPath(path) {
		return llmcatalog.MatchResult{}
	}
	return llmcatalog.MatchResult{
		Provider:     "openai_compatible",
		ProviderCN:   "OpenAI 兼容",
		Product:      "openai_compatible_api",
		ProductCN:    "OpenAI 兼容 API",
		Category:     "api",
		EndpointKind: classifyReverseProxyEndpointKind(path),
		RetainLevel:  "content",
		RiskProfile:  "llm_api",
		Known:        true,
	}
}

func reverseProxyAccessPolicy(match llmcatalog.MatchResult) (string, string, bool) {
	if !match.Known {
		return "normal_public", "summary", false
	}
	accessType := "llm"
	if isReverseProxyAgentRisk(match) {
		accessType = "ai_ide"
	}
	retentionLevel := strings.TrimSpace(match.RetainLevel)
	if retentionLevel == "" {
		retentionLevel = "content"
	}
	return accessType, retentionLevel, retentionLevel == "content"
}

func isReverseProxyAgentRisk(match llmcatalog.MatchResult) bool {
	riskProfile := strings.ToLower(strings.TrimSpace(match.RiskProfile))
	category := strings.ToLower(strings.TrimSpace(match.Category))
	return riskProfile == "ai_ide_agent" || riskProfile == "coding_ai" || category == "coding"
}

func isOpenAICompatibleAPIPath(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	patterns := []string{
		"/v1/chat/completions",
		"/v1/responses",
		"/v1/completions",
		"/v1/messages",
		"/v1/embeddings",
		"/v1/images",
		"/v1/files",
		"/api/v3/chat/completions",
		"/api/v3/responses",
		"/api/v3/files",
		"/compatible-mode/v1/chat/completions",
		"/chat/completions",
	}
	for _, pattern := range patterns {
		if strings.HasPrefix(lower, pattern) || strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func classifyReverseProxyEndpointKind(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "file") || strings.Contains(lower, "upload"):
		return "file"
	case strings.Contains(lower, "image") || strings.Contains(lower, "vision"):
		return "multimodal"
	case strings.Contains(lower, "embedding"):
		return "embedding"
	case strings.Contains(lower, "message") || strings.Contains(lower, "response") || strings.Contains(lower, "completion"):
		return "chat"
	default:
		return "api"
	}
}

// inferReverseProxyAgentType 依次看：请求头声明/指纹、messages 协议里的 system/developer 与可信用户上下文、
// 顶层 system / instructions / input 里的 system/developer 提示词。match 与 responseBody 参数保留以减少
// 调用点改动，但不再参与判定。
func inferReverseProxyAgentType(req *http.Request, match llmcatalog.MatchResult, requestBody, responseBody []byte) (string, error) {
	if req != nil {
		agentType, err := agentdetect.InferFromHeaders(req.Header)
		if err != nil {
			return "", err
		}
		if agentType != "" && !isGenericAgentIdentity(agentType) {
			return agentType, nil
		}
	}
	var structured struct {
		Messages []Message `json:"messages"`
	}
	if json.Unmarshal(requestBody, &structured) == nil {
		if inferred := inferAgentTypeFromProtocolMessages(structured.Messages); inferred != "" {
			return inferred, nil
		}
	}
	// 内容兜底只看请求体里协议自有的 system / developer 提示词，按有边界的产品名匹配。
	// 用户文本、响应体和目录匹配（match.*）不参与：它们只说明话题或上游，不说明调用方身份。
	// 逐段判定、先命中先返回，与 messages 路径一致；避免两段各自断言不同产品时拼接成歧义。
	for _, segment := range reverseProxyTrustedPromptSegments(requestBody) {
		if inferred := agentdetect.InferFromContentRole("system", segment); inferred != "" {
			return inferred, nil
		}
	}
	return "", nil
}

// reverseProxyTrustedPromptSegments 取请求体里调用方自己写的系统/开发者提示词，按出现顺序分段：
// 顶层 system（字符串或 [{type:"text",text}]）、顶层 instructions（字符串）、
// Gemini 的 systemInstruction / system_instruction（{parts:[{text}]}）、
// input 数组里 role 为 system/developer 的项。解析的是完整 JSON，不依赖截断。
func reverseProxyTrustedPromptSegments(requestBody []byte) []string {
	if len(requestBody) == 0 {
		return nil
	}
	var payload struct {
		System                 json.RawMessage `json:"system"`
		Instructions           json.RawMessage `json:"instructions"`
		SystemInstruction      json.RawMessage `json:"systemInstruction"`
		SystemInstructionSnake json.RawMessage `json:"system_instruction"`
		Input                  json.RawMessage `json:"input"`
	}
	if json.Unmarshal(requestBody, &payload) != nil {
		return nil
	}
	var parts []string
	add := func(text string) {
		if text = strings.TrimSpace(text); text != "" {
			parts = append(parts, text)
		}
	}
	add(reverseProxyPromptContentText(payload.System))
	var instructions string
	if json.Unmarshal(payload.Instructions, &instructions) == nil {
		add(instructions)
	}
	add(reverseProxyGeminiInstructionText(payload.SystemInstruction))
	add(reverseProxyGeminiInstructionText(payload.SystemInstructionSnake))
	var items []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(payload.Input, &items) == nil {
		for _, item := range items {
			role := strings.ToLower(strings.TrimSpace(item.Role))
			if role == "system" || role == "developer" {
				add(reverseProxyPromptContentText(item.Content))
			}
		}
	}
	return parts
}

// reverseProxyGeminiInstructionText 取 Gemini systemInstruction 的 parts[].text（也接受纯字符串）。
func reverseProxyGeminiInstructionText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var content struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	}
	if json.Unmarshal(raw, &content) != nil {
		return ""
	}
	texts := make([]string, 0, len(content.Parts))
	for _, part := range content.Parts {
		if part.Text != "" {
			texts = append(texts, part.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// reverseProxyPromptContentText 复用 messageText（字符串 / type=text 块数组），
// 并补上 Responses 协议的 input_text 块。
func reverseProxyPromptContentText(content json.RawMessage) string {
	if text := messageText(content); text != "" {
		return text
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	parts := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if block.Type == "input_text" && block.Text != "" {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func parseReverseProxyUsage(body []byte) (int, int) {
	if len(body) == 0 {
		return 0, 0
	}
	var payload struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			InputTokens      int `json:"input_tokens"`
			OutputTokens     int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, 0
	}
	input := payload.Usage.PromptTokens
	if input == 0 {
		input = payload.Usage.InputTokens
	}
	output := payload.Usage.CompletionTokens
	if output == 0 {
		output = payload.Usage.OutputTokens
	}
	return input, output
}

func extractReverseProxyRetainedText(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}
	body = limitReverseProxyBytes(body, maxReverseProxyRetainedBodyBytes)
	if isReverseProxySSE(contentType, body) {
		return extractReverseProxySSEText(body)
	}
	if isReverseProxyJSON(contentType, body) {
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- extractor traverses arbitrary JSON text; encoding/json does not instantiate arbitrary types.
		var decoded interface{}
		if err := json.Unmarshal(body, &decoded); err == nil {
			parts := make([]string, 0, 16)
			collectReverseProxyJSONText(decoded, &parts)
			if len(parts) > 0 {
				return strings.Join(parts, "\n")
			}
		}
	}
	if !isReverseProxyTextual(contentType, body) {
		return "[binary content type=" + firstReverseProxyNonEmpty(contentType, "application/octet-stream") + " size=" + strconv.Itoa(len(body)) + "]"
	}
	return safeReverseProxyText(body)
}

func extractReverseProxySSEText(body []byte) string {
	parts := make([]string, 0, 16)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- SSE data is parsed only as generic JSON text for audit extraction.
		var decoded interface{}
		if err := json.Unmarshal([]byte(payload), &decoded); err == nil {
			collectReverseProxyJSONText(decoded, &parts)
			continue
		}
		parts = append(parts, payload)
	}
	return strings.Join(parts, "\n")
}

// extractReverseProxyResponsesSSEOutput 只保留 Responses 协议中的最终文本事件。
// 通用 SSE 遍历会把 response.created/completed 里的 instructions、schema 和工具描述混入回答，
// 因此 /v1/responses 必须按事件类型取值，优先使用 output_text.done 的完整文本。
func extractReverseProxyResponsesSSEOutput(body []byte) string {
	var deltas, finals []string
	for _, event := range reverseProxySSEEvents(body) {
		var payload struct {
			Type  string `json:"type"`
			Delta string `json:"delta"`
			Text  string `json:"text"`
		}
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			continue
		}
		eventType := event.Name
		if eventType == "" {
			eventType = payload.Type
		}
		if eventType == "response.output_text.done" && strings.TrimSpace(payload.Text) != "" {
			finals = append(finals, payload.Text)
			continue
		}
		if eventType == "response.output_text.delta" && payload.Delta != "" {
			deltas = append(deltas, payload.Delta)
		}
	}
	if len(finals) > 0 {
		return strings.Join(finals, "\n")
	}
	return strings.Join(deltas, "")
}

func collectReverseProxyJSONText(value interface{}, parts *[]string) {
	switch v := value.(type) {
	case map[string]interface{}:
		for _, child := range v {
			collectReverseProxyJSONText(child, parts)
		}
	case []interface{}:
		for _, child := range v {
			collectReverseProxyJSONText(child, parts)
		}
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			*parts = append(*parts, trimmed)
		}
	}
}

var reverseProxySecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

func redactReverseProxyRetainedText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, pattern := range reverseProxySecretPatterns {
		value = pattern.ReplaceAllString(value, "<redacted:secret>")
	}
	if len(value) > maxReverseProxyRetainedTextBytes {
		value = truncateReverseProxyUTF8Text(value, maxReverseProxyRetainedTextBytes) + "...[truncated]"
	}
	return value
}

func truncateReverseProxyUTF8Text(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut]
}

func isReverseProxySSE(contentType string, body []byte) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("data:"))
}

func isReverseProxyJSON(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func isReverseProxyTextual(contentType string, body []byte) bool {
	lower := strings.ToLower(contentType)
	if strings.HasPrefix(lower, "text/") || strings.Contains(lower, "json") || strings.Contains(lower, "xml") || strings.Contains(lower, "yaml") || strings.Contains(lower, "javascript") || strings.Contains(lower, "x-www-form-urlencoded") {
		return true
	}
	probe := body
	if len(probe) > 4096 {
		probe = probe[:4096]
	}
	return utf8.Valid(probe) && !bytes.Contains(probe, []byte{0x00})
}

func safeReverseProxyText(body []byte) string {
	if !utf8.Valid(body) {
		return strings.ToValidUTF8(string(body), "\uFFFD")
	}
	return string(body)
}

func summarizeReverseProxyPathTemplate(rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return "/"
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	parts := strings.Split(rawPath, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		if len(part) >= 16 || strings.Contains(lower, "-") || reverseProxyAllDigits(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func reverseProxyAllDigits(value string) bool {
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

func reverseProxyClientIP(req *http.Request) string {
	// 只读采集源 IP：默认裸暴露场景下用 RemoteAddr，仅当 TCP peer 命中
	// TRUSTED_PROXY_CIDRS 时才采信 XFF/X-Real-IP，杜绝伪造。
	return clientip.ClientIP(req)
}

func hashReverseProxyValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func firstReverseProxyNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func limitReverseProxyBytes(body []byte, limit int) []byte {
	if limit <= 0 || len(body) <= limit {
		return body
	}
	return body[:limit]
}

// headTailReverseProxyCapture keeps both the protocol preamble and final SSE
// events within fixed per-side budgets without encoding trust state in the body.
type headTailReverseProxyCapture struct {
	head  bytes.Buffer
	tail  []byte
	limit int64
	total int64
}

func (c *headTailReverseProxyCapture) Write(p []byte) (int, error) {
	if c == nil || c.limit <= 0 {
		return len(p), nil
	}
	originalLen := len(p)
	c.total += int64(originalLen)
	headLimit := c.limit
	if remaining := headLimit - int64(c.head.Len()); remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		_, _ = c.head.Write(p[:n])
		p = p[n:]
	}
	tailLimit := c.limit
	if tailLimit <= 0 || len(p) == 0 {
		return originalLen, nil
	}
	if int64(len(p)) >= tailLimit {
		c.tail = append(c.tail[:0], p[len(p)-int(tailLimit):]...)
		return originalLen, nil
	}
	overflow := len(c.tail) + len(p) - int(tailLimit)
	if overflow > 0 {
		copy(c.tail, c.tail[overflow:])
		c.tail = c.tail[:len(c.tail)-overflow]
	}
	c.tail = append(c.tail, p...)
	return originalLen, nil
}

func (c *headTailReverseProxyCapture) Bytes() []byte {
	if c == nil {
		return nil
	}
	separator := []byte(nil)
	if c.Truncated() {
		separator = []byte("\n\n")
	}
	out := make([]byte, 0, c.head.Len()+len(separator)+len(c.tail))
	out = append(out, c.head.Bytes()...)
	if len(separator) > 0 {
		out = append(out, separator...)
	}
	out = append(out, c.tail...)
	return out

}
func (c *headTailReverseProxyCapture) Truncated() bool {
	if c == nil {
		return false
	}
	return c.total > int64(c.head.Len()+len(c.tail))
}

type boundedReverseProxyCapture struct {
	buf   bytes.Buffer
	limit int64
}

func (c *boundedReverseProxyCapture) Write(p []byte) (int, error) {
	if c == nil {
		return len(p), nil
	}
	remaining := c.limit - int64(c.buf.Len())
	if remaining > 0 {
		if int64(len(p)) < remaining {
			remaining = int64(len(p))
		}
		_, _ = c.buf.Write(p[:remaining])
	}
	return len(p), nil
}

func (c *boundedReverseProxyCapture) Bytes() []byte {
	if c == nil {
		return nil
	}
	return c.buf.Bytes()
}

type reverseProxyTriageAnnotator interface {
	AnnotateReverseProxyTriage(ctx context.Context, record reverseProxyAuditRecord, stage string, findings []SecurityFinding, reviewState, effectiveSeverity string)
}

func reverseProxyTurnPatch(record reverseProxyAuditRecord, parsed aimsg.ParsedChat, structured bool, requestBody, responseBody []byte, visibleText string) []byte {
	if !record.ContentRetained || !structured {
		return nil
	}
	identity := strings.Join([]string{reverseProxyTurnCallerKey(record), record.AgentType, record.TargetHost}, "\x00")
	request := retentionturn.BuildRequest(parsed.Messages, requestBody, identity)
	if request == nil {
		return nil
	}
	return retentionturn.Patch(request, retentionturn.BuildResponse(responseBody, visibleText))
}
