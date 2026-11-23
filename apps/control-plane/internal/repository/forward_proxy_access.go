package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/internaltitle"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"github.com/jackc/pgx/v5"
)

type ForwardProxyAccessFilter struct {
	RiskState        string
	AccessType       string
	Provider         string
	TargetHost       string
	SourceIP         string
	UserID           string
	Disposition      string
	Keyword          string
	KeywordScope     string
	Direction        string
	RequestID        string
	AgentType        string
	ContentOnly      bool
	Limit            int
	Offset           int
	SkipTotal        bool
	ProbeHasMore     bool
	AllowLargeLimit  bool
	StartTime        time.Time
	EndTime          time.Time
	EnvironmentScope string
}

type ForwardProxyAccessRecord struct {
	RequestID     string
	TenantID      string
	UserID        string
	Username      string
	CreatedAt     time.Time
	SourceIP      string
	TargetHost    string
	TargetPath    string
	Method        string
	Provider      string
	ProviderCN    string
	Product       string
	ProductCN     string
	AccessType    string
	EndpointKind  string
	PathTemplate  string
	Status        string
	StatusCode    int
	ResponseBytes int64
	// RequestBytes 为上行字节；不解密 CONNECT 隧道结束时回写整条隧道的上行总量。
	RequestBytes int64
	// TunnelDurationMS 为不解密隧道持续时长（毫秒）；非隧道或历史记录为 0。
	TunnelDurationMS     int64
	TLSInspected         bool
	RetentionLevel       string
	ContentRetained      bool
	RiskState            string
	RiskReasons          []string
	ActionTaken          string
	SecurityEventCount   int
	ActionableAlertCount int
	DispositionStatus    string
	AccessDirection      string
	AgentType            string
	// ClientID 调用方脱敏身份（反代由 Authorization 派生的 caller_xxx）；正向代理多为空。
	ClientID string
	// ClientName 是租户内网关 Key 的客户可读名称。Chat 门户按账号邮箱命名专属 Key，
	// 因此即使历史 Key 尚未绑定 user_id，也能正确展示发起对话的账号而不是内部 Key ID。
	ClientName string
	// IdentityKind describes the authentication identity available for this row.
	// request_logs.user_id is the bound API-key owner, not proof of the employee
	// who physically initiated the request.
	IdentityKind string
	KeyOwner     string
	// MemberCount 是本逻辑会话聚合到的物理请求数；TurnCount 是按 section_id
	// 去重后的用户对话轮次。conversation_id 为 NULL 的旧记录回退为单条、单轮。
	MemberCount int
	TurnCount   int
	// MemberRequestIDs 是本会话内所有物理请求的 request_id（按 created_at 升序），供详情
	// 合并各轮正文与附件；代表行自身也在其中。NULL 键行只含自身。
	MemberRequestIDs []string
}

type ForwardProxyAccessDimension struct {
	Name      string
	Count     int
	RiskCount int
}

type ForwardProxyEvidenceQuality struct {
	CompleteCount     int
	RequestOnlyCount  int
	ResponseOnlyCount int
	MetadataOnlyCount int
}

type ForwardProxyAccessTimelinePoint struct {
	Bucket       time.Time
	TotalCount   int
	NormalCount  int
	RiskCount    int
	BlockedCount int
}

type ForwardProxyRiskCategory struct {
	Name  string
	Count int
}

type ForwardProxyAccessSummary struct {
	Total                  int
	NormalCount            int
	RiskCount              int
	BlockedCount           int
	LLMCount               int
	AIIdeCount             int
	NormalPublicCount      int
	RetainedContentCount   int
	UndetectedCount        int
	ForwardCount           int
	ReverseCount           int
	DeviceCount            int
	AgentRequestCount      int
	IdentifiedAgentCount   int
	UnidentifiedAgentCount int
	UniqueModelCount       int
	EvidenceQuality        ForwardProxyEvidenceQuality
	TopProviders           []ForwardProxyAccessDimension
	TopTargets             []ForwardProxyAccessDimension
	TopAgents              []ForwardProxyAccessDimension
	Timeline               []ForwardProxyAccessTimelinePoint
	TopRiskCategories      []ForwardProxyRiskCategory
	DataFreshUntil         *time.Time
}

type AccessContentLog struct {
	RequestID        string
	SectionID        string
	RequestContent   string
	ResponseContent  string
	FileMetadataJSON []byte
	// ToolCallMetadataJSON 是本轮工具的机器可读索引（proxy 侧写：名字/种类/阶段/脱敏预览）。
	// 原样透传给 view=raw，不做二次解释。
	ToolCallMetadataJSON []byte
	DecoderVersion       string
	RetentionUntil       *time.Time
	CreatedAt            time.Time
}

const forwardProxyUndetectedSQL = `(COALESCE(rl.proxy_mode, '') = 'forward'
	AND UPPER(COALESCE(rl.proxy_method, '')) = 'CONNECT'
	AND rl.proxy_tls_inspected IS FALSE
	AND COALESCE(rl.request_status, '') = 'success')`

const forwardProxyRiskSQL = `
CASE
	WHEN COALESCE(rl.request_status, '') IN ('blocked', 'egress_denied')
		OR COALESCE(rl.input_audit_result->>'action_taken', '') IN ('block', 'reply')
		OR COALESCE(rl.output_audit_result->>'action_taken', '') IN ('block', 'reply')
		OR EXISTS (
			SELECT 1 FROM security_events se_block
			WHERE se_block.request_id = rl.request_id
				AND EXISTS (SELECT 1 FROM request_logs se_block_scope WHERE se_block_scope.tenant_id = rl.tenant_id AND se_block_scope.request_id = se_block.request_id AND se_block_scope.environment_scope = rl.environment_scope)
				AND se_block.action_taken IN ('block', 'reply')
				AND NOT (ignoredForwardProxySecurityEvent(se_block))
		)
	THEN 'blocked'
	WHEN hasForwardProxyEffectiveFindings(rl.input_audit_result, input)
		OR hasForwardProxyEffectiveFindings(rl.output_audit_result, output)
		OR EXISTS (
			SELECT 1 FROM security_events se_risk
			WHERE se_risk.request_id = rl.request_id
				AND EXISTS (SELECT 1 FROM request_logs se_risk_scope WHERE se_risk_scope.tenant_id = rl.tenant_id AND se_risk_scope.request_id = se_risk.request_id AND se_risk_scope.environment_scope = rl.environment_scope)
				AND NOT (ignoredForwardProxySecurityEvent(se_risk))
		)
	THEN 'risk'
	ELSE 'normal'
END`

func forwardProxyFindingsArrayExpr(column string) string {
	return fmt.Sprintf("CASE WHEN jsonb_typeof(%s->'findings') = 'array' THEN %s->'findings' ELSE '[]'::jsonb END", column, column)
}

func forwardProxySecurityEventFindingsArrayExpr(alias string) string {
	return fmt.Sprintf("CASE WHEN jsonb_typeof(%s.matched_summary->'findings') = 'array' THEN %s.matched_summary->'findings' ELSE '[]'::jsonb END", alias, alias)
}

func forwardProxyFindingReasonExpr(alias string) string {
	return fmt.Sprintf("COALESCE(NULLIF(%s.value->>'category', ''), NULLIF(%s.value->>'rule_id', ''), NULLIF(%s.value->>'type', ''), '')", alias, alias, alias)
}

func forwardProxyRowTargetHostExpr() string {
	return "LOWER(COALESCE(NULLIF(rl.proxy_target_host, ''), rl.model_id, ''))"
}

func forwardProxyEventTargetHostExpr(alias string) string {
	return fmt.Sprintf("LOWER(COALESCE(NULLIF(%s.matched_summary->>'target_host', ''), NULLIF(rl.proxy_target_host, ''), rl.model_id, ''))", alias)
}

func forwardProxyAgentInventoryFindingExpr(alias string) string {
	return fmt.Sprintf(`(
		COALESCE(%s.value->>'category', '') IN (
			'agent_github_copilot',
			'agent_copilot_chat',
			'agent_cursor',
			'agent_claude_code',
			'agent_openai_codex',
			'agent_amazon_q',
			'agent_gemini_code_assist',
			'agent_cline',
			'agent_roo_code',
			'agent_windsurf',
			'agent_continue',
			'agent_aider',
			'agent_tabnine',
			'agent_sourcegraph_cody',
			'agent_replit_ai',
			'agent_coderabbit',
			'agent_langchain',
			'agent_llamaindex',
			'agent_crewai',
			'agent_autogen',
			'agent_dify',
			'agent_coze',
			'agent_autogpt',
			'agent_babyagi',
			'github_copilot',
			'cursor_agent'
		)
		OR COALESCE(%s.value->>'rule_id', '') IN (
			'agent_github_copilot',
			'agent_copilot_chat',
			'agent_cursor',
			'agent_claude_code',
			'agent_openai_codex',
			'agent_amazon_q',
			'agent_gemini_code_assist',
			'agent_cline',
			'agent_roo_code',
			'agent_windsurf',
			'agent_continue',
			'agent_aider',
			'agent_tabnine',
			'agent_sourcegraph_cody',
			'agent_replit_ai',
			'agent_coderabbit',
			'agent_langchain',
			'agent_llamaindex',
			'agent_crewai',
			'agent_autogen',
			'agent_dify',
			'agent_coze',
			'agent_autogpt',
			'agent_babyagi',
			'github_copilot',
			'cursor_agent'
		)
	)`, alias, alias)
}

func forwardProxyWeakAuditFindingExpr(alias string) string {
	return fmt.Sprintf(`(
		COALESCE(%s.value->>'category', '') IN (
			'structured_html_comment',
			'structured_template_injection',
			'file_content_request_oversized',
			'request_body_limit_exceeded',
			'file_unknown_type',
			'file_archive',
			'file_type_mismatch',
			'file_oversized',
			'file_policy_not_allowed',
			'file_policy_review_type'
		)
		OR COALESCE(%s.value->>'rule_id', '') IN (
			'prompt_injection_html_comment',
			'prompt_injection_template_injection',
			'file-unknown',
			'file-archive',
			'file-type-mismatch',
			'file-oversized'
		)
		OR %s
	)`, alias, alias, forwardProxyAgentInventoryFindingExpr(alias))
}

func forwardProxyIgnoredFindingExpr(alias string, stageExpr string, targetHostExpr string) string {
	doubaoProtocolFalsePositive := fmt.Sprintf(`(
		%s = 'output'
		AND %s IN ('www.doubao.com', 'doubao.com')
		AND (
			COALESCE(%s.value->>'category', '') = 'bank_card_cn'
			OR COALESCE(%s.value->>'rule_id', '') = 'regex_bank_card_cn'
		)
		AND NULLIF(BTRIM(COALESCE(%s.value->>'matched_location_preview', '')), '') IS NULL
		AND NULLIF(BTRIM(COALESCE(%s.value->>'redacted_evidence', '')), '') IS NULL
	)`, stageExpr, targetHostExpr, alias, alias, alias, alias)

	weakAuditSignal := fmt.Sprintf(`(
		%s
	)`, forwardProxyWeakAuditFindingExpr(alias))

	return fmt.Sprintf(`(%s OR %s)`, doubaoProtocolFalsePositive, weakAuditSignal)
}

func forwardProxyEffectiveFindingsExpr(column string, stage string) string {
	findingAlias := fmt.Sprintf("fp_%s_finding", stage)
	ignored := forwardProxyIgnoredFindingExpr(findingAlias, fmt.Sprintf("'%s'", stage), forwardProxyRowTargetHostExpr())
	return fmt.Sprintf(`EXISTS (
		SELECT 1
		FROM jsonb_array_elements(%s) %s
		WHERE NOT (%s)
	)`, forwardProxyFindingsArrayExpr(column), findingAlias, ignored)
}

func forwardProxyIgnoredSecurityEventExpr(alias string) string {
	findingAlias := fmt.Sprintf("%s_finding", alias)
	findings := forwardProxySecurityEventFindingsArrayExpr(alias)
	ignored := forwardProxyIgnoredFindingExpr(findingAlias, fmt.Sprintf("COALESCE(%s.matched_summary->>'stage', '')", alias), forwardProxyEventTargetHostExpr(alias))
	weakSignal := forwardProxyWeakAuditFindingExpr(findingAlias)
	return fmt.Sprintf(`(
 COALESCE(%s.event_type,'') = 'security_inspection_completed'
 OR (
		EXISTS (
			SELECT 1 FROM jsonb_array_elements(%s) %s
		)
		AND NOT EXISTS (
			SELECT 1
			FROM jsonb_array_elements(%s) %s
			WHERE NOT (%s)
		)
		AND (
			COALESCE(%s.event_type, '') = 'proxy_output_audit'
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(%s) %s
				WHERE %s
			)
		)
	))`, alias, findings, findingAlias, findings, findingAlias, ignored, alias, findings, findingAlias, weakSignal)
}

func forwardProxyEffectiveSecurityEventCountExpr() string {
	return fmt.Sprintf("(SELECT COUNT(*) FROM security_events se_count WHERE se_count.request_id = rl.request_id AND EXISTS (SELECT 1 FROM request_logs se_count_scope WHERE se_count_scope.tenant_id = rl.tenant_id AND se_count_scope.request_id = se_count.request_id AND se_count_scope.environment_scope = rl.environment_scope) AND NOT (%s))", forwardProxyIgnoredSecurityEventExpr("se_count"))
}

func forwardProxyEffectiveActionableAlertCountExpr() string {
	return fmt.Sprintf("(SELECT COUNT(*) FROM security_events se_alert_count WHERE se_alert_count.request_id = rl.request_id AND se_alert_count.alert_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM request_logs se_alert_scope WHERE se_alert_scope.tenant_id = rl.tenant_id AND se_alert_scope.request_id = se_alert_count.request_id AND se_alert_scope.environment_scope = rl.environment_scope) AND NOT (%s))", forwardProxyIgnoredSecurityEventExpr("se_alert_count"))
}

func forwardProxyRiskReasonsExpr() string {
	return forwardProxyRiskReasonsExprWithLegacyEventCategory(false)
}

// forwardProxyAttentionRiskReasonsExpr 仅为 attention 的类别分面保留历史事件 category fallback。
func forwardProxyAttentionRiskReasonsExpr() string {
	return forwardProxyRiskReasonsExprWithLegacyEventCategory(true)
}

func forwardProxyRiskReasonsExprWithLegacyEventCategory(includeLegacyEventCategory bool) string {
	inputIgnored := forwardProxyIgnoredFindingExpr("fp_input_reason", "'input'", forwardProxyRowTargetHostExpr())
	outputIgnored := forwardProxyIgnoredFindingExpr("fp_output_reason", "'output'", forwardProxyRowTargetHostExpr())
	eventIgnored := forwardProxyIgnoredFindingExpr("se_reason_finding", "COALESCE(se_reason.matched_summary->>'stage', '')", forwardProxyEventTargetHostExpr("se_reason"))
	eventFindings := forwardProxySecurityEventFindingsArrayExpr("se_reason")
	if includeLegacyEventCategory {
		eventFindings = fmt.Sprintf(`CASE
			WHEN jsonb_array_length(%s) > 0 THEN %s
			WHEN NULLIF(BTRIM(se_reason.matched_summary->>'category'), '') IS NOT NULL
				THEN jsonb_build_array(jsonb_build_object('category', se_reason.matched_summary->>'category'))
			ELSE '[]'::jsonb
		END`, eventFindings, eventFindings)
	}
	return fmt.Sprintf(`COALESCE((
		SELECT jsonb_agg(DISTINCT risk_reason)
		FROM (
			SELECT %s AS risk_reason
			FROM jsonb_array_elements(%s) fp_input_reason
			WHERE NOT (%s)
			UNION
			SELECT %s AS risk_reason
			FROM jsonb_array_elements(%s) fp_output_reason
			WHERE NOT (%s)
			UNION
			SELECT %s AS risk_reason
			FROM security_events se_reason
			CROSS JOIN LATERAL jsonb_array_elements(%s) se_reason_finding
			WHERE se_reason.request_id = rl.request_id
				AND se_reason.tenant_id = rl.tenant_id
				AND EXISTS (SELECT 1 FROM request_logs se_reason_scope WHERE se_reason_scope.tenant_id = rl.tenant_id AND se_reason_scope.request_id = se_reason.request_id AND se_reason_scope.environment_scope = rl.environment_scope)
				AND NOT (%s)
		) risk_reasons
		WHERE NULLIF(risk_reason, '') IS NOT NULL
	), '[]'::jsonb)`,
		forwardProxyFindingReasonExpr("fp_input_reason"), forwardProxyFindingsArrayExpr("rl.input_audit_result"), inputIgnored,
		forwardProxyFindingReasonExpr("fp_output_reason"), forwardProxyFindingsArrayExpr("rl.output_audit_result"), outputIgnored,
		forwardProxyFindingReasonExpr("se_reason_finding"), eventFindings, eventIgnored,
	)
}

func forwardProxyRiskExpr() string {
	out := strings.ReplaceAll(forwardProxyRiskSQL, "hasForwardProxyEffectiveFindings(rl.input_audit_result, input)", forwardProxyEffectiveFindingsExpr("rl.input_audit_result", "input"))
	out = strings.ReplaceAll(out, "hasForwardProxyEffectiveFindings(rl.output_audit_result, output)", forwardProxyEffectiveFindingsExpr("rl.output_audit_result", "output"))
	out = strings.ReplaceAll(out, "ignoredForwardProxySecurityEvent(se_block)", forwardProxyIgnoredSecurityEventExpr("se_block"))
	out = strings.ReplaceAll(out, "ignoredForwardProxySecurityEvent(se_risk)", forwardProxyIgnoredSecurityEventExpr("se_risk"))
	return out
}

func decodeForwardProxyRiskReasons(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var reasons []string
	if err := json.Unmarshal(raw, &reasons); err != nil {
		return nil
	}
	return reasons
}

func forwardProxyAccessTypeExpr() string {
	return "rl.proxy_access_type_resolved"
}

// isKnownForwardProxyAccessType 判断 access_type 是否为已知枚举值。
// 其余(空串/未指定)走"内容留证默认只看大模型流量"分支。
func isKnownForwardProxyAccessType(accessType string) bool {
	switch accessType {
	case "llm", "ai_ide", "normal_public", "unknown_ai_candidate":
		return true
	default:
		return false
	}
}

func forwardProxyLegacyAccessTypeExpr() string {
	return `CASE
		WHEN COALESCE(rl.proxy_mode, '') <> 'forward' AND COALESCE(rl.model_id, '') <> '' THEN 'llm'
		WHEN COALESCE(rl.proxy_access_type, '') <> '' THEN rl.proxy_access_type
		WHEN COALESCE(rl.proxy_provider, '') <> '' THEN 'llm'
		ELSE 'normal_public'
	END`
}

func forwardProxyHasRetainedContentExpr() string {
	return `(EXISTS (
		SELECT 1
		FROM access_content_logs acl_content
		WHERE acl_content.tenant_id = rl.tenant_id
			AND acl_content.request_id = rl.request_id
			AND acl_content.environment_scope = rl.environment_scope
			AND (
				COALESCE(acl_content.request_content_redacted, '') <> ''
				OR COALESCE(acl_content.response_content_redacted, '') <> ''
				OR COALESCE(acl_content.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
			)
	)
	OR (
		COALESCE(rl.proxy_mode, '') <> 'forward'
		AND EXISTS (
			SELECT 1
			FROM ` + internaltitle.ContentRows("") + ` cl_content
			WHERE cl_content.tenant_id = rl.tenant_id
				AND cl_content.request_id = rl.id
				AND cl_content.environment_scope = rl.environment_scope
				AND COALESCE(cl_content.content, '') <> ''
		)
	))`
}

func forwardProxyAuditableLLMContentExpr(contentExpr string) string {
	return fmt.Sprintf(`(%s
		AND COALESCE(rl.proxy_endpoint_kind, '') <> 'file'
		AND UPPER(COALESCE(rl.proxy_method, '')) NOT IN ('GET', 'HEAD', 'OPTIONS')
		AND NOT (
			LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%client/settings%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%telemetry%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/collect%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%create_pow_challenge%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%pow_challenge%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%chat_session%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/api/v1/chat/snap%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/backend-api/sentinel/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/backend-api/beacons/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/backend-api/accounts/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/backend-api/canopy/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/backend-api/lat/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/experiences/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) = '/'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/assets/%%'
			OR LOWER(COALESCE(rl.proxy_target_path, '')) LIKE '%%/static/%%'
		))`, contentExpr)
}

// forwardProxyInternalTitlePredicate 排除客户端为任务列表生成标题的内部模型调用。
// 匹配同时约束智能体、端点和完整协议指纹，不会因普通用户提到 title/summarize 就隐藏。
// 历史上已落库的记录只在内容留证读侧隐藏，原始 request_log 和正文底账均不删除。
func forwardProxyInternalTitlePredicate() string {
	return internaltitle.Predicate()
}

// ── 内容留证会话聚合投影 ───────────────────────────────────────────────────
//
// conversation_id 非空时按完整会话聚合；section_id 仅用于统计轮次和详情折叠同轮物理请求。
// 代表行取会话内最新请求；风险、原因、事件数和附件鉴权成员覆盖整个会话。旧数据没有
// conversation_id 时保守回退为单请求、单轮，避免按时间窗口误并不同对话。
// forwardProxyMemberAliasedExpr 把既有 rl 绑定的权威表达式整段改绑到成员别名 rlm，
// 供成员 rollup 子查询逐成员复用同一套「忽略弱信号/误报」判定逻辑，不另起一套口径。
// 既有表达式里 rl. 仅指 request_logs 别名（已核验无 xrl. 之类子串），替换安全。
func forwardProxyMemberAliasedExpr(expr string) string {
	return strings.ReplaceAll(expr, "rl.", "rlm.")
}

// forwardProxyConversationRiskStateExpr 返回会话维度的 risk_state（物理请求成员 MAX 严重度）。
func forwardProxyTurnRiskStateExpr() string {
	const selfRisk = "COALESCE(rl.risk_state, 'normal')"
	return fmt.Sprintf(`(CASE WHEN macl.conversation_id IS NOT NULL THEN (
		SELECT CASE
			WHEN bool_or(COALESCE(rlm.risk_state, 'normal') = 'blocked') THEN 'blocked'
			WHEN bool_or(COALESCE(rlm.risk_state, 'normal') = 'risk') THEN 'risk'
			ELSE 'normal'
		END
		FROM access_content_logs acl_rs
		JOIN request_logs rlm ON rlm.tenant_id = acl_rs.tenant_id AND rlm.request_id = acl_rs.request_id
		WHERE acl_rs.tenant_id = rl.tenant_id
			AND acl_rs.environment_scope = rl.environment_scope
			AND rlm.environment_scope = rl.environment_scope
			AND acl_rs.conversation_id = macl.conversation_id
	) ELSE %s END)`, selfRisk)
}

// forwardProxyAttentionTurnRiskStateExpr 在无 macl 别名的查询中按当前 rl 的 turn 聚合风险。
func forwardProxyAttentionTurnRiskStateExpr() string {
	return `(CASE WHEN EXISTS (
		SELECT 1
		FROM access_content_logs acl_attention_current
		WHERE acl_attention_current.tenant_id = rl.tenant_id
			AND acl_attention_current.request_id = rl.request_id
			AND acl_attention_current.environment_scope = rl.environment_scope
			AND acl_attention_current.conversation_id IS NOT NULL
	) THEN (
		SELECT CASE
			WHEN bool_or(COALESCE(rlm.risk_state, 'normal') = 'blocked') THEN 'blocked'
			WHEN bool_or(COALESCE(rlm.risk_state, 'normal') = 'risk') THEN 'risk'
			ELSE 'normal'
		END
		FROM access_content_logs acl_attention_current
		JOIN access_content_logs acl_attention_member
			ON acl_attention_member.tenant_id = acl_attention_current.tenant_id
			AND acl_attention_member.conversation_id = acl_attention_current.conversation_id
			AND acl_attention_member.section_id IS NOT DISTINCT FROM acl_attention_current.section_id
		JOIN request_logs rlm
			ON rlm.tenant_id = acl_attention_member.tenant_id
			AND rlm.request_id = acl_attention_member.request_id
			AND rlm.environment_scope = rl.environment_scope
		WHERE acl_attention_current.tenant_id = rl.tenant_id
			AND acl_attention_current.request_id = rl.request_id
			AND acl_attention_current.environment_scope = rl.environment_scope
			AND acl_attention_member.environment_scope = rl.environment_scope
			AND acl_attention_current.conversation_id IS NOT NULL
	) ELSE COALESCE(rl.risk_state, 'normal') END)`
}

// forwardProxyAttentionTurnRiskReasonsExpr 聚合当前代表 turn 的成员原因，供 attention 风险类别分面使用。
func forwardProxyAttentionTurnRiskReasonsExpr() string {
	self := forwardProxyAttentionRiskReasonsExpr()
	member := forwardProxyMemberAliasedExpr(self)
	return fmt.Sprintf(`(CASE WHEN EXISTS (
		SELECT 1
		FROM access_content_logs acl_attention_current
		WHERE acl_attention_current.tenant_id = rl.tenant_id
			AND acl_attention_current.request_id = rl.request_id
			AND acl_attention_current.environment_scope = rl.environment_scope
			AND acl_attention_current.conversation_id IS NOT NULL
	) THEN COALESCE((
		SELECT jsonb_agg(DISTINCT turn_reason)
		FROM (
			SELECT jsonb_array_elements_text(%s) AS turn_reason
			FROM access_content_logs acl_attention_current
			JOIN access_content_logs acl_attention_member
				ON acl_attention_member.tenant_id = acl_attention_current.tenant_id
				AND acl_attention_member.conversation_id = acl_attention_current.conversation_id
				AND acl_attention_member.section_id IS NOT DISTINCT FROM acl_attention_current.section_id
		JOIN request_logs rlm
				ON rlm.tenant_id = acl_attention_member.tenant_id
				AND rlm.request_id = acl_attention_member.request_id
				AND rlm.environment_scope = rl.environment_scope
			WHERE acl_attention_current.tenant_id = rl.tenant_id
				AND acl_attention_current.request_id = rl.request_id
				AND acl_attention_current.environment_scope = rl.environment_scope
				AND acl_attention_member.environment_scope = rl.environment_scope
				AND acl_attention_current.conversation_id IS NOT NULL
		) turn_reasons
		WHERE NULLIF(turn_reason, '') IS NOT NULL
	), '[]'::jsonb) ELSE %s END)`, member, self)
}

// forwardProxyAttentionTurnRepresentativePredicate 保留当前 rl 的最新 turn 成员；无分组键时回退自身。
func forwardProxyAttentionTurnRepresentativePredicate() string {
	return `NOT EXISTS (
		SELECT 1
		FROM access_content_logs acl_attention_current
		JOIN access_content_logs acl_attention_newer
			ON acl_attention_newer.tenant_id = acl_attention_current.tenant_id
			AND acl_attention_newer.conversation_id = acl_attention_current.conversation_id
			AND acl_attention_newer.section_id IS NOT DISTINCT FROM acl_attention_current.section_id
			AND acl_attention_newer.environment_scope = acl_attention_current.environment_scope
		WHERE acl_attention_current.tenant_id = rl.tenant_id
			AND acl_attention_current.request_id = rl.request_id
			AND acl_attention_current.conversation_id IS NOT NULL
			AND (acl_attention_newer.created_at, acl_attention_newer.request_id) > (acl_attention_current.created_at, acl_attention_current.request_id)
	)`
}

// forwardProxyTurnRiskReasonsExpr 返回会话维度的 risk_reasons（成员原因并集）。
// 复用 forwardProxyRiskReasonsExpr：代表行自身用 rl 版，会话成员用 rlm 版逐成员展开后
// 去重并集（jsonb_array_elements_text 把每个成员产出的 jsonb 数组拆元素再 agg DISTINCT）。
func forwardProxyTurnRiskReasonsExpr() string {
	// 读预算列 risk_reasons（迁移 1001）；还没算出来的行回退原表达式，结果不变。
	self := "COALESCE(rl.risk_reasons, " + forwardProxyRiskReasonsExpr() + ")"
	member := forwardProxyMemberAliasedExpr(self)
	return fmt.Sprintf(`(CASE WHEN macl.conversation_id IS NOT NULL THEN COALESCE((
		SELECT jsonb_agg(DISTINCT conversation_reason)
		FROM (
			SELECT jsonb_array_elements_text(%s) AS conversation_reason
			FROM access_content_logs acl_rr
			JOIN request_logs rlm ON rlm.tenant_id = acl_rr.tenant_id AND rlm.request_id = acl_rr.request_id
			WHERE acl_rr.tenant_id = rl.tenant_id
				AND acl_rr.environment_scope = rl.environment_scope
				AND rlm.environment_scope = rl.environment_scope
				AND acl_rr.conversation_id = macl.conversation_id
		) conversation_reasons
		WHERE NULLIF(conversation_reason, '') IS NOT NULL
	), '[]'::jsonb) ELSE %s END)`, member, self)
}

// forwardProxyConversationSecurityEventCountExpr 返回会话成员安全事件数之和。
func forwardProxyTurnSecurityEventCountExpr() string {
	self := forwardProxyEffectiveSecurityEventCountExpr()
	member := forwardProxyMemberAliasedExpr(self)
	return fmt.Sprintf(`(CASE WHEN macl.conversation_id IS NOT NULL THEN (
		SELECT COALESCE(SUM(%s), 0)
		FROM access_content_logs acl_sc
		JOIN request_logs rlm ON rlm.tenant_id = acl_sc.tenant_id AND rlm.request_id = acl_sc.request_id
		WHERE acl_sc.tenant_id = rl.tenant_id
			AND acl_sc.environment_scope = rl.environment_scope
			AND rlm.environment_scope = rl.environment_scope
			AND acl_sc.conversation_id = macl.conversation_id
	) ELSE %s END)`, member, self)
}

func forwardProxyTurnActionableAlertCountExpr() string {
	self := forwardProxyEffectiveActionableAlertCountExpr()
	member := forwardProxyMemberAliasedExpr(self)
	return fmt.Sprintf(`(CASE WHEN macl.conversation_id IS NOT NULL THEN (
		SELECT COALESCE(SUM(%s), 0)
		FROM access_content_logs acl_ac
		JOIN request_logs rlm ON rlm.tenant_id = acl_ac.tenant_id AND rlm.request_id = acl_ac.request_id
		WHERE acl_ac.tenant_id = rl.tenant_id
			AND acl_ac.environment_scope = rl.environment_scope
			AND rlm.environment_scope = rl.environment_scope
			AND acl_ac.conversation_id = macl.conversation_id
	) ELSE %s END)`, member, self)
}

// forwardProxyTurnMemberCountExpr 返回本会话聚合到的物理请求数；NULL 键回退 1。
func forwardProxyTurnMemberCountExpr() string {
	return `(CASE WHEN macl.conversation_id IS NOT NULL THEN (
		SELECT COUNT(*)
		FROM access_content_logs acl_mc
		WHERE acl_mc.tenant_id = rl.tenant_id
			AND acl_mc.environment_scope = rl.environment_scope
			AND acl_mc.conversation_id = macl.conversation_id
	) ELSE 1 END)`
}

// forwardProxyConversationTurnCountExpr 按 section_id 统计用户对话轮次；缺失 section_id 的
// 旧成员按 request_id 单独成轮，与详情合并逻辑保持一致。
func forwardProxyConversationTurnCountExpr() string {
	return `(CASE WHEN macl.conversation_id IS NOT NULL THEN GREATEST((
		SELECT COUNT(DISTINCT COALESCE(NULLIF(acl_tc.section_id, ''), acl_tc.request_id))
		FROM access_content_logs acl_tc
		WHERE acl_tc.tenant_id = rl.tenant_id
			AND acl_tc.environment_scope = rl.environment_scope
			AND acl_tc.conversation_id = macl.conversation_id
	), 1) ELSE 1 END)`
}

// forwardProxyTurnMemberIDsExpr 返回本会话全部物理请求 request_id（按 created_at 升序）。
func forwardProxyTurnMemberIDsExpr() string {
	return `(CASE WHEN macl.conversation_id IS NOT NULL THEN (
		SELECT COALESCE(jsonb_agg(acl_mi.request_id ORDER BY acl_mi.created_at, acl_mi.request_id), '[]'::jsonb)
		FROM access_content_logs acl_mi
		WHERE acl_mi.tenant_id = rl.tenant_id
			AND acl_mi.environment_scope = rl.environment_scope
			AND acl_mi.conversation_id = macl.conversation_id
	) ELSE jsonb_build_array(rl.request_id) END)`
}

// forwardProxyTurnAntiJoinPredicate 只保留“当前筛选候选集”内会话最新的代表行；NULL 键行各自保留。
// 不能拿筛选范围外的新请求剔除当前行，否则按时间、来源或服务商筛选时会漏掉整个会话。
func forwardProxyTurnAntiJoinPredicate(candidateWhere []string) string {
	newerWhere := make([]string, 0, len(candidateWhere))
	for _, predicate := range candidateWhere {
		newerWhere = append(newerWhere, strings.ReplaceAll(predicate, "rl.", "rln."))
	}
	return `NOT EXISTS (
		SELECT 1
		FROM access_content_logs acl_newer
		JOIN request_logs rln
			ON rln.tenant_id = acl_newer.tenant_id
			AND rln.request_id = acl_newer.request_id
		WHERE acl_newer.tenant_id = macl.tenant_id
			AND acl_newer.environment_scope = macl.environment_scope
			AND macl.conversation_id IS NOT NULL
			AND acl_newer.conversation_id = macl.conversation_id
			AND (acl_newer.created_at, acl_newer.request_id) > (macl.created_at, macl.request_id)
			AND ` + strings.Join(newerWhere, " AND ") + `
	)`
}

// forwardProxySingleContentLogJoinSQL projects one deterministic content row for
// each request. Historical data can contain more than one row despite the
// current uniqueness constraint; joining all of them duplicates list rows and
// makes OFFSET and COUNT disagree.
func forwardProxySingleContentLogJoinSQL(alias string) string {
	return fmt.Sprintf(`LEFT JOIN LATERAL (
		SELECT
			acl_selected.tenant_id,
			acl_selected.request_id,
			acl_selected.environment_scope,
			acl_selected.conversation_id,
			acl_selected.section_id,
			acl_selected.created_at
		FROM access_content_logs acl_selected
		WHERE acl_selected.tenant_id = rl.tenant_id
			AND acl_selected.request_id = rl.request_id
			AND acl_selected.environment_scope = rl.environment_scope
		ORDER BY acl_selected.created_at DESC, acl_selected.id DESC
		LIMIT 1
	) %s ON TRUE`, alias)
}

func (r *RequestLogRepository) ListForwardProxyAccess(ctx context.Context, tenantID string, filter ForwardProxyAccessFilter) ([]ForwardProxyAccessRecord, int, error) {
	filter = normalizeForwardProxyFilter(filter)
	if filter.Keyword != "" {
		return r.listForwardProxyKeywordAccess(ctx, tenantID, filter)
	}
	requestedRiskState := filter.RiskState
	filter.RiskState = ""
	where, args := buildForwardProxyWhere(tenantID, filter)
	accessTypeExpr := forwardProxyAccessTypeExpr()
	hasContentExpr := "COALESCE(rl.has_retained_content, false)"
	// SP4：风险与安全事件数按 turn rollup（成员 MAX/求和/原因并集），risk_reasons 同理。
	riskExpr := forwardProxyTurnRiskStateExpr()
	riskReasonsExpr := forwardProxyTurnRiskReasonsExpr()
	if requestedRiskState == "attention" {
		riskReasonsExpr = forwardProxyAttentionTurnRiskReasonsExpr()
	}
	secCountExpr := forwardProxyTurnSecurityEventCountExpr()
	actionableAlertCountExpr := forwardProxyTurnActionableAlertCountExpr()
	if filter.Keyword != "" {
		// 关键词检索的职责是快速定位留证。完整规则原因和事件计数会在详情接口
		// 按 request_id 加载；列表阶段不再对每个命中 turn 展开 security_events
		// 与 findings JSON，避免少量命中也被重投影拖到查询超时。
		riskReasonsExpr = "'[]'::jsonb"
		secCountExpr = "0"
		actionableAlertCountExpr = "0"
	}
	memberCountExpr := forwardProxyTurnMemberCountExpr()
	turnCountExpr := forwardProxyConversationTurnCountExpr()
	memberIDsExpr := forwardProxyTurnMemberIDsExpr()
	// SP4：LEFT JOIN turn 分组键来源行（macl），并用反连接谓词只保留 turn 内最新代表行。
	// NULL 键行各自成 turn，谓词恒为真不被剔除（详见 forwardProxyTurnAntiJoinPredicate）。
	groupedWhere := append(append([]string{}, where...), forwardProxyTurnAntiJoinPredicate(where))
	if requestedRiskState == "normal" || requestedRiskState == "risk" || requestedRiskState == "blocked" {
		args = append(args, requestedRiskState)
		groupedWhere = append(groupedWhere, fmt.Sprintf("%s = $%d", riskExpr, len(args)))
	} else if requestedRiskState == "attention" {
		groupedWhere = append(groupedWhere, fmt.Sprintf("%s IN ('risk', 'blocked')", riskExpr))
	}

	queryLimit := filter.Limit
	if filter.ProbeHasMore {
		queryLimit++
	}
	query := fmt.Sprintf(`
		SELECT
			rl.request_id,
			rl.tenant_id,
			COALESCE(rl.user_id, ''),
			COALESCE(u.username, ''),
			rl.created_at,
			COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, ''),
			COALESCE(%s, ''),
			COALESCE(rl.proxy_target_path, ''),
			COALESCE(rl.proxy_method, ''),
			COALESCE(NULLIF(rl.proxy_provider, ''), NULLIF(p.name, ''), ''),
			COALESCE(rl.proxy_product, ''),
			%s AS access_type,
			COALESCE(rl.proxy_endpoint_kind, ''),
			COALESCE(NULLIF(rl.proxy_path_template, ''), rl.proxy_target_path, ''),
			COALESCE(rl.request_status, ''),
			COALESCE(rl.upstream_status_code, 0),
			COALESCE(rl.proxy_response_bytes, 0),
			COALESCE(rl.proxy_request_bytes, 0),
			COALESCE(rl.proxy_tunnel_duration_ms, 0),
			COALESCE(rl.proxy_tls_inspected, false),
			COALESCE(NULLIF(rl.proxy_retention_level, ''), CASE WHEN %s = 'llm' THEN 'content' ELSE 'summary' END),
			%s,
			%s AS risk_reasons,
			%s AS risk_state,
			CASE
				WHEN (%s) = 'blocked' THEN 'block'
				WHEN (%s) = 'risk' THEN 'audit'
				ELSE 'allow'
			END AS action_taken,
			%s AS security_event_count,
			%s AS actionable_alert_count,
			COALESCE(ad.status, 'open'),
			CASE
				WHEN COALESCE(rl.proxy_mode, '') = 'forward' THEN 'forward'
				WHEN COALESCE(rl.proxy_mode, '') = 'reverse' THEN 'reverse'
				ELSE 'chat_completion'
			END AS access_direction,
			COALESCE(rl.agent_type, '') AS agent_type,
				COALESCE(rl.client_id, '') AS client_id,
				COALESCE(NULLIF(k.name, ''), '') AS client_name,
				CASE
					WHEN NULLIF(BTRIM(COALESCE(rl.user_id, '')), '') IS NOT NULL THEN 'key_owner'
					WHEN NULLIF(BTRIM(COALESCE(rl.client_id, '')), '') IS NOT NULL THEN 'api_key'
					ELSE 'unknown'
				END AS identity_kind,
				CASE
					WHEN NULLIF(BTRIM(COALESCE(rl.user_id, '')), '') IS NOT NULL
						THEN COALESCE(NULLIF(u.username, ''), rl.user_id)
					ELSE ''
				END AS key_owner,
				%s AS member_count,
			%s AS turn_count,
			%s AS member_request_ids
		FROM request_logs rl
		LEFT JOIN users u ON u.id = rl.user_id
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN providers p
			ON p.id = COALESCE(NULLIF(rl.provider_id, ''), m.provider_id)
			AND p.tenant_id = rl.tenant_id
		LEFT JOIN internal_keys k
			ON k.id = rl.client_id
			AND k.tenant_id = rl.tenant_id
		%s
		LEFT JOIN audit_dispositions ad
			ON ad.tenant_id = rl.tenant_id
			AND ad.subject_type = 'request'
			AND ad.subject_id = rl.request_id
		WHERE %s
		ORDER BY rl.created_at DESC
		LIMIT $%d OFFSET $%d
	`, forwardProxyPublicTargetExpr(), accessTypeExpr, accessTypeExpr, hasContentExpr, riskReasonsExpr, riskExpr, riskExpr, riskExpr, secCountExpr, actionableAlertCountExpr, memberCountExpr, turnCountExpr, memberIDsExpr, forwardProxySingleContentLogJoinSQL("macl"), strings.Join(groupedWhere, " AND "), len(args)+1, len(args)+2)
	args = append(args, queryLimit, filter.Offset)

	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list forward proxy access: %w", err)
	}
	defer rows.Close()

	records := []ForwardProxyAccessRecord{}
	for rows.Next() {
		var item ForwardProxyAccessRecord
		var riskReasonsJSON []byte
		var memberIDsJSON []byte
		if err := rows.Scan(
			&item.RequestID,
			&item.TenantID,
			&item.UserID,
			&item.Username,
			&item.CreatedAt,
			&item.SourceIP,
			&item.TargetHost,
			&item.TargetPath,
			&item.Method,
			&item.Provider,
			&item.Product,
			&item.AccessType,
			&item.EndpointKind,
			&item.PathTemplate,
			&item.Status,
			&item.StatusCode,
			&item.ResponseBytes,
			&item.RequestBytes,
			&item.TunnelDurationMS,
			&item.TLSInspected,
			&item.RetentionLevel,
			&item.ContentRetained,
			&riskReasonsJSON,
			&item.RiskState,
			&item.ActionTaken,
			&item.SecurityEventCount,
			&item.ActionableAlertCount,
			&item.DispositionStatus,
			&item.AccessDirection,
			&item.AgentType,
			&item.ClientID,
			&item.ClientName,
			&item.IdentityKind,
			&item.KeyOwner,
			&item.MemberCount,
			&item.TurnCount,
			&memberIDsJSON,
		); err != nil {
			return nil, 0, err
		}
		item.RiskReasons = decodeForwardProxyRiskReasons(riskReasonsJSON)
		item.MemberRequestIDs = decodeForwardProxyMemberIDs(memberIDsJSON)
		if item.MemberCount <= 0 {
			item.MemberCount = 1
		}
		if item.TurnCount <= 0 {
			item.TurnCount = 1
		}
		enrichForwardProxyCatalogLabels(&item)
		records = append(records, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed while reading forward proxy access rows: %w", err)
	}

	// 无界 COUNT 是这张表（全表 ~44w 行）最重的一笔；当调用方退订总数
	// (SkipTotal，安全告警页就不显示总数) 时跳过它，total 回退为本页行数。
	// SP4：总数也按 turn 分组口径统计——复用 groupedWhere（含 macl 连接 + 反连接谓词），
	// 与列表返回的「代表行」一一对应，避免「列表去重后总数仍按物理行计」造成翻页错位。
	total := len(records)
	if !filter.SkipTotal {
		countArgs := args[:len(args)-2]
		countQuery := `SELECT COUNT(*) FROM request_logs rl
			` + forwardProxySingleContentLogJoinSQL("macl") + `
			WHERE ` + strings.Join(groupedWhere, " AND ")
		if err := r.retentionRead().QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("failed to count forward proxy access: %w", err)
		}
	}

	return records, total, nil
}

func buildForwardProxyKeywordMatchWhere(
	filter ForwardProxyAccessFilter,
	args []interface{},
) ([]string, []interface{}) {
	where := []string{"keyword_match.tenant_id = $1"}
	if filter.EnvironmentScope != "" {
		args = append(args, EnvironmentScopesForRead(filter.EnvironmentScope))
		where = append(where, fmt.Sprintf("keyword_match.environment_scope = ANY($%d)", len(args)))
	}
	if !filter.StartTime.IsZero() {
		args = append(args, filter.StartTime)
		where = append(where, fmt.Sprintf("keyword_match.created_at >= $%d", len(args)))
	}
	if !filter.EndTime.IsZero() {
		args = append(args, filter.EndTime)
		where = append(where, fmt.Sprintf("keyword_match.created_at < $%d", len(args)))
	}
	return where, args
}

func forwardProxyVisibleFileMetadataKeywordExpr(alias string, keywordArg int) string {
	return fmt.Sprintf(
		"EXISTS (SELECT 1 FROM jsonb_array_elements(CASE jsonb_typeof(COALESCE(%[1]s.file_metadata_json, '[]'::jsonb)) "+
			"WHEN 'array' THEN COALESCE(%[1]s.file_metadata_json, '[]'::jsonb) "+
			"WHEN 'object' THEN jsonb_build_array(%[1]s.file_metadata_json) ELSE '[]'::jsonb END) visible_file "+
			"WHERE COALESCE(visible_file->>'file_name', '') ILIKE $%[2]d ESCAPE E'\\\\' "+
			"OR COALESCE(visible_file->>'filename', '') ILIKE $%[2]d ESCAPE E'\\\\' "+
			"OR COALESCE(visible_file->>'name', '') ILIKE $%[2]d ESCAPE E'\\\\' "+
			"OR COALESCE(visible_file->>'title', '') ILIKE $%[2]d ESCAPE E'\\\\' "+
			"OR COALESCE(visible_file->>'text_preview', '') ILIKE $%[2]d ESCAPE E'\\\\' "+
			"OR COALESCE(visible_file->>'preview', '') ILIKE $%[2]d ESCAPE E'\\\\')",
		alias, keywordArg,
	)
}

func forwardProxyKeywordMatchSourceSQL(accessWhere, contentWhere []string, keywordArg int, scopes ...string) string {
	return forwardProxyKeywordMatchSQL(accessWhere, contentWhere, keywordArg, nil, scopes...)
}

// keywordRecentContent 让正文命中先按时间倒序取够一页：常见词在正文里有上百万条命中，全部物化再排序要好几秒，
// 而时间倒序往下看几十条请求就能凑够一页。
type keywordRecentContent struct {
	// canonicalWhere 是列表口径（不含风险筛选）的条件，别名 keyword_canonical；倒序取到的请求必须都能出现在最终列表里。
	canonicalWhere []string
	// needed 是 offset 加本页条数（含探测下一页的那一条）。
	needed     int
	thresholds keywordRecentThresholds
}

// keywordRecentThresholds 是常见词先走时间倒序的两个阈值。
type keywordRecentThresholds struct {
	// denseEntries：命中的正文条目（按正文去重表引用数粗算，不看时间窗）到这个数才先走时间倒序；少于它时完整匹配本来就快。
	denseEntries int
	// recentScan：时间倒序最多看这么多条请求；凑不够一页说明命中集中在少数旧请求上，回到完整匹配。
	recentScan int
}

// retentionKeywordRecentDefaults 是线上用的阈值（670 万条正文条目的量级下实测）。
var retentionKeywordRecentDefaults = keywordRecentThresholds{denseEntries: 50000, recentScan: 400}

// forwardProxyKeywordMatchSQL 返回关键字命中的来源行：访问留存（按会话归并）与正文留存（按请求）。
// 正文先在去重后的正文表上按 trigram 索引找出命中的正文（customer_text 是写入时算好的客户正文判定），
// 再找引用它们的条目；条目按请求去重后才关联 request_logs。旧表 content_logs_legacy 照旧逐行判断。
// recent 不为空时（调用方只要一页、没有风险筛选），命中条目多的关键字先按请求时间倒序取够 needed 条正文请求，
// 取够了就不再做完整匹配；取不够或命中不多时走完整匹配，结果与完整匹配一致。
func forwardProxyKeywordMatchSQL(accessWhere, contentWhere []string, keywordArg int, recent *keywordRecentContent, scopes ...string) string {
	content := strings.Join(contentWhere, " AND ")
	ctes := []string{fmt.Sprintf(`keyword_bodies AS MATERIALIZED (
			SELECT keyword_body.content_sha256
			FROM content_log_bodies keyword_body
			WHERE keyword_body.tenant_id = $1
				AND keyword_body.content ILIKE $%d ESCAPE E'\\' AND keyword_body.customer_text
		)`, keywordArg)}
	fullGate, recentRows := "", ""
	if recent != nil && recent.needed > 0 {
		ctes = append(ctes, fmt.Sprintf(`keyword_density AS MATERIALIZED (
			SELECT COUNT(*) >= %[1]d AS dense FROM (
				SELECT 1
				FROM keyword_bodies
				JOIN content_log_entries keyword_entry
					ON keyword_entry.tenant_id = $1
					AND keyword_entry.content_sha256 = keyword_bodies.content_sha256
				LIMIT %[1]d
			) keyword_probe
		)`, recent.thresholds.denseEntries), fmt.Sprintf(`keyword_recent AS MATERIALIZED (
			SELECT keyword_canonical.tenant_id, keyword_canonical.environment_scope, keyword_canonical.request_id
			FROM (
				SELECT keyword_canonical.id, keyword_canonical.tenant_id, keyword_canonical.environment_scope,
					keyword_canonical.request_id, keyword_canonical.created_at
				FROM request_logs keyword_canonical
				WHERE (SELECT dense FROM keyword_density) AND %[1]s
				ORDER BY keyword_canonical.created_at DESC
				LIMIT %[2]d
			) keyword_canonical
			WHERE EXISTS (
				SELECT 1
				FROM content_log_entries keyword_content
				WHERE keyword_content.tenant_id = keyword_canonical.tenant_id
					AND keyword_content.request_id = keyword_canonical.id
					AND keyword_content.environment_scope = keyword_canonical.environment_scope
					AND %[3]s
					AND keyword_content.role IN ('user', 'assistant')
					-- OR FALSE 不是多余的：IN 子查询在 AND 顶层时会被改写成以 keyword_bodies 驱动的半连接，对每条候选请求
					-- 都把上万条命中正文逐个去探索引；包在 OR 里就保留为“哈希子计划”，每条正文条目只查一次哈希表。
					AND (keyword_content.content_sha256 IN (SELECT content_sha256 FROM keyword_bodies) OR FALSE)
			) OR EXISTS (
				SELECT 1
				FROM content_logs_legacy keyword_content
				WHERE keyword_content.tenant_id = keyword_canonical.tenant_id
					AND keyword_content.request_id = keyword_canonical.id
					AND keyword_content.environment_scope = keyword_canonical.environment_scope
					AND %[3]s
					AND keyword_content.role IN ('user', 'assistant')
					AND keyword_content.content ILIKE $%[4]d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_content.content)
			)
			ORDER BY keyword_canonical.created_at DESC
			LIMIT %[5]d
		)`, strings.Join(recent.canonicalWhere, " AND "), recent.thresholds.recentScan, content, keywordArg, recent.needed))
		// 两个分支都只有不含列引用的门槛条件，规划成一次性过滤：不满足的分支整段不执行。
		fullGate = fmt.Sprintf("\n\t\tWHERE (SELECT COUNT(*) FROM keyword_recent) < %d", recent.needed)
		recentRows = fmt.Sprintf(`
		UNION
		SELECT tenant_id, environment_scope, request_id, NULL::text AS conversation_id, NULL::text AS section_id
		FROM keyword_recent
		WHERE (SELECT COUNT(*) FROM keyword_recent) >= %d`, recent.needed)
	}
	sql := "WITH " + strings.Join(ctes, ", ") + fmt.Sprintf(`
		SELECT
			keyword_match.tenant_id,
			keyword_match.environment_scope,
			keyword_match.request_id,
			keyword_match.conversation_id,
			keyword_match.section_id
			FROM access_content_logs keyword_match
			WHERE %s
				AND (
					(
						keyword_match.request_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_match.request_content_redacted)
					)
					OR (
						keyword_match.response_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_match.response_content_redacted)
					)
					OR %s
				)
		UNION
		SELECT
			keyword_canonical.tenant_id,
			keyword_canonical.environment_scope,
			keyword_canonical.request_id,
			NULL::text AS conversation_id,
			NULL::text AS section_id
		FROM (
			SELECT keyword_content.tenant_id, keyword_content.environment_scope, keyword_content.request_id
			FROM keyword_bodies
			JOIN content_log_entries keyword_content
				ON keyword_content.tenant_id = $1
				AND keyword_content.content_sha256 = keyword_bodies.content_sha256
			WHERE %s
				AND keyword_content.role IN ('user', 'assistant')
			UNION
			SELECT keyword_content.tenant_id, keyword_content.environment_scope, keyword_content.request_id
			FROM content_logs_legacy keyword_content
			WHERE %s
				AND keyword_content.role IN ('user', 'assistant')
				AND keyword_content.content ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_content.content)
		) keyword_content
		JOIN request_logs keyword_canonical
			ON keyword_canonical.id = keyword_content.request_id
			AND keyword_canonical.tenant_id = keyword_content.tenant_id
			AND keyword_canonical.environment_scope = keyword_content.environment_scope%s%s
	`, strings.Join(accessWhere, " AND "), keywordArg, keywordArg, forwardProxyVisibleFileMetadataKeywordExpr("keyword_match", keywordArg),
		content, content, keywordArg, fullGate, recentRows)
	if len(scopes) > 0 {
		return restrictRetentionKeywordSQL(sql, scopes[0], keywordArg)
	}
	return sql
}

// retentionKeywordIndexPolicy 按关键字定正文匹配的写法。
//   - 不足 3 个字符时 trigram 抽不出词元，走索引要扫全索引再逐行复核，比顺序扫描还慢，所以把正文列包一层空串拼接，
//     让计划保持顺序扫描；3 个字符及以上原样保留，ILIKE 在前，正文表上的 trigram 索引可以直接筛行。
//   - 关键字里没有分大小写的字符（中文、数字、符号）时 ILIKE 与 LIKE 结果相同，改用 LIKE：ILIKE 要把每段正文
//     整体转小写，中文正文上要慢一个数量级。
func retentionKeywordIndexPolicy(sql, keyword string, keywordArg int) string {
	param := fmt.Sprintf(" ILIKE $%d ", keywordArg)
	if utf8.RuneCountInString(strings.TrimSpace(keyword)) < 3 {
		for _, column := range []string{"keyword_content.content", "keyword_body.content"} {
			sql = strings.ReplaceAll(sql, column+param, "("+column+" || '')"+param)
		}
	}
	if !retentionKeywordHasCase(keyword) {
		sql = strings.ReplaceAll(sql, param, fmt.Sprintf(" LIKE $%d ", keywordArg))
	}
	return sql
}

// retentionKeywordHasCase 判断关键字里有没有分大小写的字符：有大小写变体或本身是大小写字母的都算。
func retentionKeywordHasCase(keyword string) bool {
	for _, r := range keyword {
		if unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r) ||
			unicode.ToLower(r) != r || unicode.ToUpper(r) != r || unicode.ToTitle(r) != r {
			return true
		}
	}
	return false
}

func restrictRetentionKeywordSQL(sql, scope string, keywordArg int) string {
	if scope != "response" && scope != "request" {
		return sql
	}
	excluded, role := "request", "assistant"
	if scope == "request" {
		excluded, role = "response", "user"
	}
	sql = strings.ReplaceAll(sql, "jjdguard_customer_content_text(keyword_match."+excluded+"_content_redacted)", "FALSE")
	sql = strings.ReplaceAll(sql, "keyword_content.role IN ('user', 'assistant')", "keyword_content.role = '"+role+"'")
	return strings.ReplaceAll(sql, forwardProxyVisibleFileMetadataKeywordExpr("keyword_match", keywordArg), "FALSE")
}

// listForwardProxyKeywordAccess first materializes matching retained-content rows,
// then resolves only their turn representatives. This keeps keyword search from
// driving the request_logs timeline and evaluating a correlated text predicate
// once per request.
func (r *RequestLogRepository) listForwardProxyKeywordAccess(ctx context.Context, tenantID string, filter ForwardProxyAccessFilter) ([]ForwardProxyAccessRecord, int, error) {
	filter = normalizeForwardProxyFilter(filter)
	requestedRiskState := filter.RiskState
	baseFilter := filter
	baseFilter.Keyword = ""
	baseFilter.RiskState = ""
	baseFilter.ContentOnly = false
	baseFilter.SkipTotal = true
	where, args := buildForwardProxyWhere(tenantID, baseFilter)
	where = append(where, forwardProxyInternalTitlePredicate())
	keywordMatchWhere, args := buildForwardProxyKeywordMatchWhere(filter, args)
	keywordContentWhere := make([]string, 0, len(keywordMatchWhere))
	for _, predicate := range keywordMatchWhere {
		keywordContentWhere = append(keywordContentWhere, strings.ReplaceAll(predicate, "keyword_match.", "keyword_content."))
	}
	args = append(args, "%"+escapePostgresLikeLiteral(filter.Keyword)+"%")
	keywordArg := len(args)
	accessTypeExpr := forwardProxyAccessTypeExpr()
	riskExpr := forwardProxyTurnRiskStateExpr()
	memberCountExpr := forwardProxyTurnMemberCountExpr()
	turnCountExpr := forwardProxyConversationTurnCountExpr()
	memberIDsExpr := forwardProxyTurnMemberIDsExpr()
	representativeWhere := make([]string, 0, len(where))
	canonicalWhere := make([]string, 0, len(where))
	for _, predicate := range where {
		representativeWhere = append(representativeWhere, strings.ReplaceAll(predicate, "rl.", "keyword_request."))
		canonicalWhere = append(canonicalWhere, strings.ReplaceAll(predicate, "rl.", "keyword_canonical."))
	}
	if requestedRiskState == "normal" || requestedRiskState == "risk" || requestedRiskState == "blocked" {
		args = append(args, requestedRiskState)
		where = append(where, fmt.Sprintf("%s = $%d", riskExpr, len(args)))
	} else if requestedRiskState == "attention" {
		where = append(where, fmt.Sprintf("%s IN ('risk', 'blocked')", riskExpr))
	}

	queryLimit := filter.Limit
	if filter.ProbeHasMore {
		queryLimit++
	}
	// 没有风险筛选时，最终列表的条件就是 canonicalWhere：正文命中可以先按时间倒序取够这一页。
	// 有风险筛选时一页里的请求还要再按会话风险过滤，倒序取够的条数不一定够，走完整匹配。
	var recent *keywordRecentContent
	if requestedRiskState == "" && filter.Offset+queryLimit <= 1000 {
		recent = &keywordRecentContent{canonicalWhere: canonicalWhere, needed: filter.Offset + queryLimit, thresholds: retentionKeywordRecentDefaults}
	}
	query := fmt.Sprintf(`
			WITH keyword_matches AS MATERIALIZED (
				%s
			), keyword_representatives AS (
				SELECT tenant_id, environment_scope, request_id
				FROM keyword_matches
				WHERE conversation_id IS NULL
				UNION
				SELECT
					keyword_conversation.tenant_id,
					keyword_conversation.environment_scope,
					(array_agg(keyword_member.request_id ORDER BY keyword_member.created_at DESC, keyword_member.request_id DESC))[1]
				FROM (
					SELECT DISTINCT tenant_id, environment_scope, conversation_id
					FROM keyword_matches
					WHERE conversation_id IS NOT NULL
				) keyword_conversation
				JOIN access_content_logs keyword_member
					ON keyword_member.tenant_id = keyword_conversation.tenant_id
					AND keyword_member.environment_scope = keyword_conversation.environment_scope
					AND keyword_member.conversation_id = keyword_conversation.conversation_id
				JOIN request_logs keyword_request
					ON keyword_request.tenant_id = keyword_member.tenant_id
					AND keyword_request.request_id = keyword_member.request_id
					AND keyword_request.environment_scope = keyword_member.environment_scope
				WHERE %s
				GROUP BY keyword_conversation.tenant_id, keyword_conversation.environment_scope, keyword_conversation.conversation_id
		)
		SELECT
			rl.request_id,
			rl.tenant_id,
			COALESCE(rl.user_id, ''),
			COALESCE(u.username, ''),
			rl.created_at,
			COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, ''),
			COALESCE(%s, ''),
			COALESCE(rl.proxy_target_path, ''),
			COALESCE(rl.proxy_method, ''),
			COALESCE(NULLIF(rl.proxy_provider, ''), NULLIF(p.name, ''), ''),
			COALESCE(rl.proxy_product, ''),
			%s AS access_type,
			COALESCE(rl.proxy_endpoint_kind, ''),
			COALESCE(NULLIF(rl.proxy_path_template, ''), rl.proxy_target_path, ''),
			COALESCE(rl.request_status, ''),
			COALESCE(rl.upstream_status_code, 0),
			COALESCE(rl.proxy_response_bytes, 0),
			COALESCE(rl.proxy_request_bytes, 0),
			COALESCE(rl.proxy_tunnel_duration_ms, 0),
			COALESCE(rl.proxy_tls_inspected, false),
			COALESCE(NULLIF(rl.proxy_retention_level, ''), 'content'),
			TRUE,
			'[]'::jsonb AS risk_reasons,
			%s AS risk_state,
			CASE
				WHEN (%s) = 'blocked' THEN 'block'
				WHEN (%s) = 'risk' THEN 'audit'
				ELSE 'allow'
			END AS action_taken,
			0 AS security_event_count,
			0 AS actionable_alert_count,
			COALESCE(ad.status, 'open'),
			CASE
				WHEN COALESCE(rl.proxy_mode, '') = 'forward' THEN 'forward'
				WHEN COALESCE(rl.proxy_mode, '') = 'reverse' THEN 'reverse'
				ELSE 'chat_completion'
			END AS access_direction,
			COALESCE(rl.agent_type, '') AS agent_type,
				COALESCE(rl.client_id, '') AS client_id,
				COALESCE(NULLIF(k.name, ''), '') AS client_name,
				CASE
					WHEN NULLIF(BTRIM(COALESCE(rl.user_id, '')), '') IS NOT NULL THEN 'key_owner'
					WHEN NULLIF(BTRIM(COALESCE(rl.client_id, '')), '') IS NOT NULL THEN 'api_key'
					ELSE 'unknown'
				END AS identity_kind,
				CASE
					WHEN NULLIF(BTRIM(COALESCE(rl.user_id, '')), '') IS NOT NULL
						THEN COALESCE(NULLIF(u.username, ''), rl.user_id)
					ELSE ''
				END AS key_owner,
				%s AS member_count,
			%s AS turn_count,
			%s AS member_request_ids
		FROM keyword_representatives keyword_rep
		JOIN request_logs rl
			ON rl.tenant_id = $1
			AND rl.request_id = keyword_rep.request_id
			AND rl.environment_scope = keyword_rep.environment_scope
		LEFT JOIN users u ON u.id = rl.user_id
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN providers p
			ON p.id = COALESCE(NULLIF(rl.provider_id, ''), m.provider_id)
			AND p.tenant_id = rl.tenant_id
		LEFT JOIN internal_keys k
			ON k.id = rl.client_id
			AND k.tenant_id = rl.tenant_id
		%s
		LEFT JOIN audit_dispositions ad
			ON ad.tenant_id = rl.tenant_id
			AND ad.subject_type = 'request'
			AND ad.subject_id = rl.request_id
		WHERE %s
		ORDER BY rl.created_at DESC
		LIMIT $%d OFFSET $%d
		`, retentionKeywordIndexPolicy(forwardProxyKeywordMatchSQL(keywordMatchWhere, keywordContentWhere, keywordArg, recent, filter.KeywordScope), filter.Keyword, keywordArg), strings.Join(representativeWhere, " AND "),
		forwardProxyPublicTargetExpr(), accessTypeExpr,
		riskExpr, riskExpr, riskExpr, memberCountExpr, turnCountExpr, memberIDsExpr,
		forwardProxySingleContentLogJoinSQL("macl"), strings.Join(where, " AND "), len(args)+1, len(args)+2)
	args = append(args, queryLimit, filter.Offset)

	rows, err := r.retentionKeywordRead().Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search forward proxy access: %w", err)
	}
	defer rows.Close()
	records := []ForwardProxyAccessRecord{}
	for rows.Next() {
		var item ForwardProxyAccessRecord
		var riskReasonsJSON, memberIDsJSON []byte
		if err := rows.Scan(
			&item.RequestID, &item.TenantID, &item.UserID, &item.Username, &item.CreatedAt,
			&item.SourceIP, &item.TargetHost, &item.TargetPath, &item.Method, &item.Provider,
			&item.Product, &item.AccessType, &item.EndpointKind, &item.PathTemplate, &item.Status,
			&item.StatusCode, &item.ResponseBytes, &item.RequestBytes, &item.TunnelDurationMS, &item.TLSInspected, &item.RetentionLevel,
			&item.ContentRetained, &riskReasonsJSON, &item.RiskState, &item.ActionTaken,
			&item.SecurityEventCount, &item.ActionableAlertCount, &item.DispositionStatus, &item.AccessDirection,
			&item.AgentType, &item.ClientID, &item.ClientName, &item.IdentityKind, &item.KeyOwner,
			&item.MemberCount, &item.TurnCount, &memberIDsJSON,
		); err != nil {
			return nil, 0, err
		}
		item.RiskReasons = decodeForwardProxyRiskReasons(riskReasonsJSON)
		item.MemberRequestIDs = decodeForwardProxyMemberIDs(memberIDsJSON)
		if item.MemberCount <= 0 {
			item.MemberCount = 1
		}
		if item.TurnCount <= 0 {
			item.TurnCount = 1
		}
		enrichForwardProxyCatalogLabels(&item)
		records = append(records, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed while reading keyword access rows: %w", err)
	}
	return records, len(records), nil
}

// decodeForwardProxyMemberIDs 解析 turn 成员 request_id 的 jsonb 数组列。
func decodeForwardProxyMemberIDs(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil
	}
	return ids
}

func (r *RequestLogRepository) GetForwardProxyAccessSummary(ctx context.Context, tenantID string, filter ForwardProxyAccessFilter) (ForwardProxyAccessSummary, error) {
	filter = normalizeForwardProxyFilter(filter)
	filter.Limit = 0
	filter.Offset = 0
	requestedRiskState := filter.RiskState
	filter.RiskState = ""
	where, args := buildForwardProxyWhere(tenantID, filter)
	riskExpr := forwardProxyTurnRiskStateExpr()
	riskReasonsExpr := forwardProxyTurnRiskReasonsExpr()
	if requestedRiskState == "attention" {
		riskReasonsExpr = forwardProxyAttentionTurnRiskReasonsExpr()
	}
	accessTypeExpr := forwardProxyAccessTypeExpr()
	hasContentExpr := "COALESCE(rl.has_retained_content, false)"
	groupedWhere := append(append([]string{}, where...), forwardProxyTurnAntiJoinPredicate(where))
	if requestedRiskState == "normal" || requestedRiskState == "risk" || requestedRiskState == "blocked" {
		args = append(args, requestedRiskState)
		groupedWhere = append(groupedWhere, fmt.Sprintf("%s = $%d", riskExpr, len(args)))
	} else if requestedRiskState == "attention" {
		groupedWhere = append(groupedWhere, fmt.Sprintf("%s IN ('risk', 'blocked')", riskExpr))
	}

	groupedRows := fmt.Sprintf(`
		SELECT
			%s AS risk_state,
			%s AS risk_reasons,
			%s AS access_type,
			%s AS has_retained_content,
			COALESCE(NULLIF(rl.proxy_provider, ''), NULLIF(p.name, ''), 'unknown') AS provider,
			%s AS target_host,
			COALESCE(rl.proxy_mode, '') AS proxy_mode,
			COALESCE(rl.agent_type, '') AS agent_type,
			rl.created_at,
			(CASE WHEN macl.conversation_id IS NOT NULL THEN EXISTS (
				SELECT 1
				FROM access_content_logs acl_request_body
				WHERE acl_request_body.tenant_id = rl.tenant_id
					AND acl_request_body.environment_scope = rl.environment_scope
					AND acl_request_body.conversation_id = macl.conversation_id
					AND NULLIF(BTRIM(COALESCE(acl_request_body.request_content_redacted, '')), '') IS NOT NULL
			) ELSE %s END) AS request_body_exists,
			(CASE WHEN macl.conversation_id IS NOT NULL THEN EXISTS (
				SELECT 1
				FROM access_content_logs acl_response_body
				WHERE acl_response_body.tenant_id = rl.tenant_id
					AND acl_response_body.environment_scope = rl.environment_scope
					AND acl_response_body.conversation_id = macl.conversation_id
					AND NULLIF(BTRIM(COALESCE(acl_response_body.response_content_redacted, '')), '') IS NOT NULL
			) ELSE %s END) AS response_body_exists,
			%s AS undetected
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN providers p
			ON p.id = COALESCE(NULLIF(rl.provider_id, ''), m.provider_id)
			AND p.tenant_id = rl.tenant_id
		%s
		WHERE %s
	`, riskExpr, riskReasonsExpr, accessTypeExpr, hasContentExpr, forwardProxyPublicTargetExpr(),
		forwardProxyPrecomputedRequestBodyExpr(), forwardProxyPrecomputedResponseBodyExpr(), forwardProxyUndetectedSQL,
		forwardProxySingleContentLogJoinSQL("macl"), strings.Join(groupedWhere, " AND "))

	// groupedRows 本身已经完成最昂贵的会话代表行、风险和正文完整性投影。过去为了
	// counts / provider / target / agent / evidence / timeline / category 分别执行七次同一
	// 投影，生产 24h 窗口会累计超过 30 秒。现在只执行一次并在 Go 中做小规模聚合。
	return r.aggregateForwardProxyGroupedSummary(ctx, groupedRows, args, forwardProxyTimelineGranularity(filter))
}

func (r *RequestLogRepository) forwardProxyGroupedTopDimension(ctx context.Context, groupedRows string, dimension string, args []interface{}) ([]ForwardProxyAccessDimension, error) {
	if dimension != "provider" && dimension != "target_host" && dimension != "agent_type" {
		return nil, fmt.Errorf("unsupported forward proxy grouped dimension: %s", dimension)
	}
	where := dimension + " IS NOT NULL"
	if dimension == "agent_type" {
		where += " AND agent_type <> ''"
	}
	query := `WITH grouped AS (` + groupedRows + `)
		SELECT
			` + dimension + ` AS name,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE risk_state IN ('risk', 'blocked')) AS risk_count
		FROM grouped
		WHERE ` + where + `
		GROUP BY name
		ORDER BY total DESC, risk_count DESC`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query grouped forward proxy dimension: %w", err)
	}
	defer rows.Close()

	items := []ForwardProxyAccessDimension{}
	for rows.Next() {
		var item ForwardProxyAccessDimension
		if err := rows.Scan(&item.Name, &item.Count, &item.RiskCount); err != nil {
			return nil, fmt.Errorf("failed to scan grouped forward proxy dimension: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *RequestLogRepository) forwardProxyGroupedEvidenceQuality(ctx context.Context, groupedRows string, args []interface{}) (ForwardProxyEvidenceQuality, error) {
	query := `WITH grouped AS (` + groupedRows + `)
		SELECT
			COUNT(*) FILTER (WHERE request_body_exists AND response_body_exists),
			COUNT(*) FILTER (WHERE request_body_exists AND NOT response_body_exists),
			COUNT(*) FILTER (WHERE NOT request_body_exists AND response_body_exists),
			COUNT(*) FILTER (WHERE NOT request_body_exists AND NOT response_body_exists)
		FROM grouped`
	var out ForwardProxyEvidenceQuality
	if err := r.retentionRead().QueryRow(ctx, query, args...).Scan(&out.CompleteCount, &out.RequestOnlyCount, &out.ResponseOnlyCount, &out.MetadataOnlyCount); err != nil {
		return out, fmt.Errorf("failed to summarize grouped forward proxy evidence quality: %w", err)
	}
	return out, nil
}

func (r *RequestLogRepository) forwardProxyGroupedTimeline(ctx context.Context, groupedRows, granularity string, args []interface{}) ([]ForwardProxyAccessTimelinePoint, error) {
	if granularity != "hour" {
		granularity = "day"
	}
	query := `WITH grouped AS (` + groupedRows + `), latest_buckets AS (
		SELECT
			date_trunc('` + granularity + `', created_at) AS bucket,
			COUNT(*) AS total_count,
			COUNT(*) FILTER (WHERE risk_state = 'normal') AS normal_count,
			COUNT(*) FILTER (WHERE risk_state = 'risk') AS risk_count,
			COUNT(*) FILTER (WHERE risk_state = 'blocked') AS blocked_count
		FROM grouped
		GROUP BY bucket
		ORDER BY bucket DESC
		LIMIT 31
	)
	SELECT bucket, total_count, normal_count, risk_count, blocked_count
	FROM latest_buckets
	ORDER BY bucket ASC`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query grouped forward proxy timeline: %w", err)
	}
	defer rows.Close()
	out := []ForwardProxyAccessTimelinePoint{}
	for rows.Next() {
		var point ForwardProxyAccessTimelinePoint
		if err := rows.Scan(&point.Bucket, &point.TotalCount, &point.NormalCount, &point.RiskCount, &point.BlockedCount); err != nil {
			return nil, fmt.Errorf("failed to scan grouped forward proxy timeline: %w", err)
		}
		out = append(out, point)
	}
	return out, rows.Err()
}

func (r *RequestLogRepository) forwardProxyGroupedTopRiskCategories(ctx context.Context, groupedRows string, args []interface{}) ([]ForwardProxyRiskCategory, error) {
	query := `WITH grouped AS (` + groupedRows + `), conversation_categories AS (
		SELECT reason.value AS name
		FROM grouped
		CROSS JOIN LATERAL jsonb_array_elements_text(grouped.risk_reasons) AS reason(value)
		WHERE NULLIF(BTRIM(reason.value), '') IS NOT NULL
	)
	SELECT name, COUNT(*) AS affected_conversation_count
	FROM conversation_categories
	GROUP BY name
	ORDER BY affected_conversation_count DESC, name ASC
	LIMIT 8`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query grouped forward proxy risk categories: %w", err)
	}
	defer rows.Close()
	out := []ForwardProxyRiskCategory{}
	for rows.Next() {
		var item ForwardProxyRiskCategory
		if err := rows.Scan(&item.Name, &item.Count); err != nil {
			return nil, fmt.Errorf("failed to scan grouped forward proxy risk category: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func forwardProxyTopDimensionQuery(dimExpr string, riskExpr string, where []string) string {
	return fmt.Sprintf(`
		SELECT
			%s AS name,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE %s IN ('risk', 'blocked')) AS risk_count
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		WHERE %s
		GROUP BY name
		ORDER BY total DESC, risk_count DESC
	`, dimExpr, riskExpr, strings.Join(where, " AND "))
}

func (r *RequestLogRepository) forwardProxyTopDimension(ctx context.Context, dimExpr string, riskExpr string, where []string, args []interface{}) ([]ForwardProxyAccessDimension, error) {
	query := forwardProxyTopDimensionQuery(dimExpr, riskExpr, where)
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query forward proxy dimension: %w", err)
	}
	defer rows.Close()

	items := []ForwardProxyAccessDimension{}
	for rows.Next() {
		var item ForwardProxyAccessDimension
		if err := rows.Scan(&item.Name, &item.Count, &item.RiskCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func normalizeForwardProxyFilter(filter ForwardProxyAccessFilter) ForwardProxyAccessFilter {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 500 && !filter.AllowLargeLimit {
		filter.Limit = 100
	}
	if filter.AllowLargeLimit && filter.Limit > 100000 {
		filter.Limit = 100000
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	filter.RiskState = strings.ToLower(strings.TrimSpace(filter.RiskState))
	filter.AccessType = strings.ToLower(strings.TrimSpace(filter.AccessType))
	filter.Provider = strings.TrimSpace(filter.Provider)
	filter.TargetHost = strings.TrimSpace(filter.TargetHost)
	filter.SourceIP = strings.TrimSpace(filter.SourceIP)
	filter.UserID = strings.TrimSpace(filter.UserID)
	filter.Disposition = strings.ToLower(strings.TrimSpace(filter.Disposition))
	filter.Keyword = strings.TrimSpace(filter.Keyword)
	filter.Direction = strings.ToLower(strings.TrimSpace(filter.Direction))
	filter.RequestID = strings.TrimSpace(filter.RequestID)
	filter.AgentType = strings.ToLower(strings.TrimSpace(filter.AgentType))
	filter.EnvironmentScope = NormalizeEnvironmentScope(filter.EnvironmentScope)
	return filter
}

const LegacyEnvironmentScope = "legacy-unclassified"

var allowedEnvironmentScopes = map[string]struct{}{
	"customer":             {},
	"home":                 {},
	"claude":               {},
	"codex":                {},
	LegacyEnvironmentScope: {},
}

func NormalizeEnvironmentScope(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if _, ok := allowedEnvironmentScopes[value]; !ok {
		return LegacyEnvironmentScope
	}
	return value
}

// EnvironmentScopesForRead keeps environments isolated by default. Customer
// reads may include pre-classification rows only when the operator explicitly
// enables the upgrade-compatibility switch for a reviewed legacy installation.
func EnvironmentScopesForRead(value string) []string {
	scope := NormalizeEnvironmentScope(value)
	if scope == "" {
		return nil
	}
	if scope == "customer" && strings.EqualFold(strings.TrimSpace(os.Getenv("RETENTION_INCLUDE_LEGACY_UNCLASSIFIED")), "true") {
		return []string{"customer", LegacyEnvironmentScope}
	}
	return []string{scope}
}

func buildForwardProxyWhere(tenantID string, filter ForwardProxyAccessFilter) ([]string, []interface{}) {
	filter = normalizeForwardProxyFilter(filter)
	args := []interface{}{tenantID}
	where := []string{"rl.tenant_id = $1"}
	if filter.EnvironmentScope != "" {
		args = append(args, EnvironmentScopesForRead(filter.EnvironmentScope))
		where = append(where, fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)))
	}
	switch filter.Direction {
	case "forward":
		where = append(where, "rl.proxy_mode = 'forward'")
	case "reverse":
		where = append(where, "rl.proxy_mode = 'reverse'")
	case "chat_completion":
		where = append(where, "rl.proxy_mode = 'chat_completion'")
	case "device":
		where = append(where, "1 = 0")
	}
	if filter.Provider != "" {
		if filter.Provider == llmcatalog.ThirdPartyLabel {
			// 「第三方」桶：非空、非 unknown、且不在大厂白名单内的所有上游。与
			// mapForwardProxySummaryToInfo 把非大厂 provider 合并成单一「第三方」一格
			// 一一对应，让前端点这一格能筛出对应记录。
			providerExpr := "LOWER(COALESCE(NULLIF(rl.proxy_provider, ''), 'unknown'))"
			placeholders := []string{"'unknown'"}
			for _, vendor := range llmcatalog.BigVendorProviders() {
				args = append(args, vendor)
				placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
			}
			where = append(where, fmt.Sprintf("%s NOT IN (%s)", providerExpr, strings.Join(placeholders, ", ")))
		} else {
			args = append(args, strings.ToLower(filter.Provider))
			where = append(where, fmt.Sprintf("LOWER(COALESCE(NULLIF(rl.proxy_provider, ''), 'unknown')) = $%d", len(args)))
		}
	}
	if isKnownForwardProxyAccessType(filter.AccessType) {
		args = append(args, filter.AccessType)
		where = append(where, fmt.Sprintf("%s = $%d", forwardProxyAccessTypeExpr(), len(args)))
	} else if filter.AccessType != "all" && filter.RequestID == "" {
		// 默认只看大模型流量(llm + ai_ide)，排除 normal_public 噪声(CDN/对象存储/遥测)。
		// 本地 Qwen 等本地模型解析为 llm，不会被误杀；显式传 normal_public 可查看噪声。
		// request_id 深链定位时不叠加此默认限制（目标行可能是任意类型），见下方精确条件。
		where = append(where, fmt.Sprintf("%s IN ('llm', 'ai_ide')", forwardProxyAccessTypeExpr()))
	}
	if filter.RequestID != "" {
		// 深链精确定位（设计 1d-P1）：告警"查看完整留证"按 request_id 直开详情
		args = append(args, filter.RequestID)
		requestIDArg := len(args)
		where = append(where, fmt.Sprintf(`(
			rl.request_id = $%d
			OR EXISTS (
				SELECT 1
				FROM access_content_logs acl_current
				JOIN access_content_logs acl_target
					ON acl_target.tenant_id = acl_current.tenant_id
					AND acl_target.environment_scope = acl_current.environment_scope
					AND acl_target.conversation_id IS NOT NULL
					AND acl_current.conversation_id = acl_target.conversation_id
					AND acl_current.section_id IS NOT DISTINCT FROM acl_target.section_id
				WHERE acl_current.tenant_id = rl.tenant_id
					AND acl_current.request_id = rl.request_id
					AND acl_current.environment_scope = rl.environment_scope
					AND acl_target.request_id = $%d
			)
		)`, requestIDArg, requestIDArg))
	}
	if filter.TargetHost != "" {
		args = append(args, "%"+strings.ToLower(filter.TargetHost)+"%")
		argIndex := len(args)
		where = append(where, fmt.Sprintf(`(
			LOWER(COALESCE(NULLIF(rl.proxy_target_host, ''), rl.model_id, '')) LIKE $%d
			OR EXISTS (
				SELECT 1
				FROM models model_filter
				JOIN providers provider_filter ON provider_filter.id = model_filter.provider_id
				WHERE provider_filter.tenant_id = rl.tenant_id
					AND (model_filter.id = rl.model_id OR model_filter.id = rl.proxy_target_host)
					AND (
						LOWER(COALESCE(model_filter.model_name, '')) LIKE $%d
						OR LOWER(COALESCE(model_filter.model_label, '')) LIKE $%d
					)
			)
		)`, argIndex, argIndex, argIndex))
	}
	if filter.AgentType != "" {
		args = append(args, filter.AgentType)
		where = append(where, fmt.Sprintf("LOWER(COALESCE(rl.agent_type, '')) = $%d", len(args)))
	}
	if filter.UserID != "" {
		args = append(args, filter.UserID)
		where = append(where, fmt.Sprintf("rl.user_id = $%d", len(args)))
	}
	if filter.Disposition != "" {
		args = append(args, filter.Disposition)
		where = append(where, fmt.Sprintf(`COALESCE((
			SELECT disposition_filter.status
			FROM audit_dispositions disposition_filter
			WHERE disposition_filter.tenant_id = rl.tenant_id
				AND disposition_filter.subject_type = 'request'
				AND disposition_filter.subject_id = rl.request_id
			LIMIT 1
		), 'open') = $%d`, len(args)))
	}
	if filter.SourceIP != "" {
		// 来源检索只匹配来源 IP、客户可见应用名称与接入通道。
		// 人员由独立 user_id 精确筛选，避免把来源文本误标为实际员工。
		args = append(args, "%"+filter.SourceIP+"%")
		where = append(where, fmt.Sprintf(`(
			LOWER(COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '')) LIKE LOWER($%d)
			OR EXISTS (
				SELECT 1
				FROM internal_keys responsibility_key
				WHERE responsibility_key.tenant_id = rl.tenant_id
					AND responsibility_key.id = rl.client_id
					AND LOWER(COALESCE(responsibility_key.name, '')) LIKE LOWER($%d)
			)
			OR LOWER(CASE COALESCE(rl.proxy_mode, '')
				WHEN 'forward' THEN '正向代理 forward'
				WHEN 'reverse' THEN '反向代理 reverse'
				WHEN 'chat_completion' THEN '模型中转 chat_completion'
				WHEN 'mcp' THEN 'MCP 网关 mcp'
				ELSE COALESCE(rl.proxy_mode, '')
			END) LIKE LOWER($%d)
		)`, len(args), len(args), len(args)))
	}
	if filter.Keyword != "" {
		args = append(args, "%"+escapePostgresLikeLiteral(filter.Keyword)+"%")
		keywordArg := len(args)
		// 仅检索已脱敏且通过客户正文边界的留证字段。关键词命中同一
		// conversation/section 的任一物理成员时，代表 turn 也应被返回；
		// content_logs.request_id 先映射到外部 request_logs.request_id。
		where = append(where, fmt.Sprintf(`rl.request_id IN (
				SELECT keyword_match.request_id
				FROM access_content_logs keyword_match
				WHERE keyword_match.tenant_id = $1
					AND keyword_match.environment_scope = rl.environment_scope
					AND (
						(
							keyword_match.request_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_match.request_content_redacted)
						)
						OR (
							keyword_match.response_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_match.response_content_redacted)
						)
						OR %s
					)
			UNION
			SELECT keyword_current.request_id
			FROM access_content_logs keyword_match
			JOIN access_content_logs keyword_current
				ON keyword_current.tenant_id = keyword_match.tenant_id
				AND keyword_current.environment_scope = keyword_match.environment_scope
				AND keyword_match.conversation_id IS NOT NULL
				AND keyword_current.conversation_id = keyword_match.conversation_id
				AND keyword_current.section_id IS NOT DISTINCT FROM keyword_match.section_id
			WHERE keyword_match.tenant_id = $1
					AND keyword_match.environment_scope = rl.environment_scope
					AND (
						(
							keyword_match.request_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_match.request_content_redacted)
						)
						OR (
							keyword_match.response_content_redacted ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_match.response_content_redacted)
						)
						OR %s
					)
				UNION
				SELECT keyword_canonical.request_id
				FROM content_logs keyword_content
				JOIN request_logs keyword_canonical
					ON keyword_canonical.id = keyword_content.request_id
					AND keyword_canonical.tenant_id = keyword_content.tenant_id
					AND keyword_canonical.environment_scope = keyword_content.environment_scope
				WHERE keyword_content.tenant_id = $1
					AND keyword_content.environment_scope = rl.environment_scope
					AND keyword_content.role IN ('user', 'assistant')
					AND keyword_content.content ILIKE $%d ESCAPE E'\\' AND jjdguard_customer_content_text(keyword_content.content)
			)`, keywordArg, keywordArg, forwardProxyVisibleFileMetadataKeywordExpr("keyword_match", keywordArg),
			keywordArg, keywordArg, forwardProxyVisibleFileMetadataKeywordExpr("keyword_match", keywordArg), keywordArg))
	}
	if filter.ContentOnly {
		where = append(where, forwardProxyInternalTitlePredicate())
	}
	if filter.Keyword != "" && len(where) > 0 {
		for i := range where {
			where[i] = retentionKeywordIndexPolicy(restrictRetentionKeywordSQL(where[i], filter.KeywordScope, len(args)), filter.Keyword, len(args))
		}
	}
	if filter.ContentOnly && filter.Keyword == "" {
		contentExpr := forwardProxyHasRetainedContentExpr()
		if filter.AccessType == "llm" {
			contentExpr = forwardProxyAuditableLLMContentExpr(contentExpr)
		}
		// 先用预计算列 has_retained_content + 部分索引 idx_request_logs_tenant_content_created
		// 把候选集从全表(50万)缩到留证行(约万级),再跑精确 EXISTS。实测 21s→6ms。
		// 该列为"有留证内容行"的安全超集(count 实证一致),加此前缀不漏任何内容行。
		where = append(where, "rl.has_retained_content = true")
		where = append(where, contentExpr)
	}
	if !filter.StartTime.IsZero() {
		args = append(args, filter.StartTime)
		where = append(where, fmt.Sprintf("rl.created_at >= $%d", len(args)))
	}
	if !filter.EndTime.IsZero() {
		args = append(args, filter.EndTime)
		where = append(where, fmt.Sprintf("rl.created_at < $%d", len(args)))
	}
	switch filter.RiskState {
	case "normal", "risk", "blocked":
		args = append(args, filter.RiskState)
		where = append(where, fmt.Sprintf("rl.risk_state = $%d", len(args)))
	case "attention":
		args = append(args, "risk", "blocked")
		attentionRiskExpr := forwardProxyAttentionTurnRiskStateExpr()
		where = append(where, fmt.Sprintf("%s IN ($%d, $%d)", attentionRiskExpr, len(args)-1, len(args)))
		where = append(where, forwardProxyAttentionTurnRepresentativePredicate())
	}
	return where, args
}

// escapePostgresLikeLiteral makes user input literal inside an ILIKE pattern.
// The surrounding '%' wildcards are added by the caller.
func escapePostgresLikeLiteral(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}

func (r *RequestLogRepository) GetForwardProxyAccessCounts(ctx context.Context, tenantID string, filter ForwardProxyAccessFilter) (ForwardProxyAccessSummary, error) {
	filter = normalizeForwardProxyFilter(filter)
	filter.Limit = 0
	filter.Offset = 0
	filter.SkipTotal = false
	where, args := buildForwardProxyWhere(tenantID, filter)

	// Dashboard 只需要五个基础计数，不能复用 GetForwardProxyAccessSummary：完整汇总还会重复
	// 执行服务商、目标、智能体、证据质量、时间线和风险分类等重聚合，生产 30 天窗口会
	// 在 evidence quality 阶段打满 30 秒超时。这里直接读 request_logs 的预计算列，既保持
	// 租户/环境/时间/访问类型过滤一致，也让首页请求稳定走单次索引范围聚合。
	query := fmt.Sprintf(`
		SELECT
			COUNT(*)::int,
			COUNT(*) FILTER (WHERE rl.proxy_access_type_resolved = 'llm')::int,
			COUNT(*) FILTER (WHERE rl.proxy_access_type_resolved = 'ai_ide')::int,
			COUNT(*) FILTER (WHERE rl.proxy_access_type_resolved = 'normal_public')::int,
			COUNT(*) FILTER (WHERE COALESCE(rl.has_retained_content, false))::int,
			COUNT(*) FILTER (WHERE %s)::int
		FROM request_logs rl
		WHERE %s
	`, forwardProxyUndetectedSQL, strings.Join(where, " AND "))

	out := newForwardProxyAccessSummary()
	if err := r.retentionRead().QueryRow(ctx, query, args...).Scan(
		&out.Total,
		&out.LLMCount,
		&out.AIIdeCount,
		&out.NormalPublicCount,
		&out.RetainedContentCount,
		&out.UndetectedCount,
	); err != nil {
		return out, fmt.Errorf("failed to count forward proxy access: %w", err)
	}
	return out, nil
}

func enrichForwardProxyCatalogLabels(item *ForwardProxyAccessRecord) {
	if item == nil {
		return
	}
	if item.Provider == "" && item.TargetHost == "" {
		return
	}
	match := llmcatalog.Match(item.TargetHost, item.TargetPath)
	if item.ProviderCN == "" {
		if match.ProviderCN != "" {
			item.ProviderCN = match.ProviderCN
		} else {
			item.ProviderCN = item.Provider
		}
	}
	if item.Product == "" && match.Product != "" {
		item.Product = match.Product
	}
	if item.ProductCN == "" {
		if match.ProductCN != "" {
			item.ProductCN = match.ProductCN
		} else {
			item.ProductCN = item.Product
		}
	}

	// 客户可见审计页脱敏：只有白名单大厂保留真实厂商名，其余上游（自营/第三方中转、
	// 聚合平台、小众服务）的服务商与产品名统一显示为「第三方」，只保留目标域名供审计
	// 溯源。空/unknown（未识别、直连调用）不在此列，语义不同、不脱敏。
	effectiveProvider := item.Provider
	if effectiveProvider == "" {
		effectiveProvider = match.Provider
	}
	if llmcatalog.IsMaskedProvider(effectiveProvider) {
		item.ProviderCN = llmcatalog.ThirdPartyLabel
		item.ProductCN = llmcatalog.ThirdPartyLabel
	}
}

func (r *RequestLogRepository) GetAccessContentLog(ctx context.Context, tenantID string, requestID string) (*AccessContentLog, error) {
	query := `
		SELECT
			acl.request_id,
			COALESCE(acl.section_id, ''),
			COALESCE(acl.request_content_redacted, ''),
			COALESCE(acl.response_content_redacted, ''),
			COALESCE(acl.file_metadata_json, '[]'::jsonb),
			COALESCE(acl.tool_call_metadata_json, '[]'::jsonb),
			COALESCE(acl.decoder_version, ''),
			acl.retention_until,
			acl.created_at
		FROM access_content_logs acl
		JOIN request_logs rl
			ON rl.request_id = acl.request_id
			AND rl.tenant_id = acl.tenant_id
		WHERE acl.tenant_id = $1
			AND acl.request_id = $2
		LIMIT 1
	`
	var out AccessContentLog
	var retentionUntil sql.NullTime
	if err := r.retentionRead().QueryRow(ctx, query, tenantID, requestID).Scan(
		&out.RequestID,
		&out.SectionID,
		&out.RequestContent,
		&out.ResponseContent,
		&out.FileMetadataJSON,
		&out.ToolCallMetadataJSON,
		&out.DecoderVersion,
		&retentionUntil,
		&out.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get access content log: %w", err)
	}
	if retentionUntil.Valid {
		out.RetentionUntil = &retentionUntil.Time
	}
	return &out, nil
}

func (r *RequestLogRepository) GetAccessContentLogScoped(
	ctx context.Context,
	tenantID, requestID string,
	start, end time.Time,
	environmentScope string,
) (*AccessContentLog, error) {
	args := []interface{}{tenantID, requestID}
	where := []string{"acl.tenant_id = $1", "acl.request_id = $2"}
	if environmentScope != "" {
		args = append(args, EnvironmentScopesForRead(environmentScope))
		where = append(where, fmt.Sprintf("acl.environment_scope = ANY($%d)", len(args)))
		where = append(where, fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)))
	}
	if !start.IsZero() {
		args = append(args, start)
		where = append(where, fmt.Sprintf("acl.created_at >= $%d", len(args)))
	}
	if !end.IsZero() {
		args = append(args, end)
		where = append(where, fmt.Sprintf("acl.created_at < $%d", len(args)))
	}
	query := `
		SELECT
			acl.request_id,
			COALESCE(acl.section_id, ''),
			COALESCE(acl.request_content_redacted, ''),
			COALESCE(acl.response_content_redacted, ''),
			COALESCE(acl.file_metadata_json, '[]'::jsonb),
			COALESCE(acl.tool_call_metadata_json, '[]'::jsonb),
			COALESCE(acl.decoder_version, ''),
			acl.retention_until,
			acl.created_at
		FROM access_content_logs acl
		JOIN request_logs rl
			ON rl.request_id = acl.request_id
			AND rl.tenant_id = acl.tenant_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY acl.created_at DESC
		LIMIT 1
	`
	var out AccessContentLog
	var retentionUntil sql.NullTime
	if err := r.retentionRead().QueryRow(ctx, query, args...).Scan(
		&out.RequestID,
		&out.SectionID,
		&out.RequestContent,
		&out.ResponseContent,
		&out.FileMetadataJSON,
		&out.ToolCallMetadataJSON,
		&out.DecoderVersion,
		&retentionUntil,
		&out.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get scoped access content log: %w", err)
	}
	if retentionUntil.Valid {
		out.RetentionUntil = &retentionUntil.Time
	}
	return &out, nil
}

// GetAccessContentLogs 批量按 request_id 在「指定租户内」取留证内容，按 created_at 升序返回，
// 供 SP4 turn 详情合并：把同一逻辑 turn 的多个成员（豆包双行/同 section 复用）的请求/响应
// 正文与 file_metadata 合并进同一份四栏详情。安全不变量：强制 tenant_id = $1 收口，
// 跨租户即便复用相同 request_id 也互不可见；空入参直接返回空切片不触发查询。
func (r *RequestLogRepository) GetAccessContentLogs(ctx context.Context, tenantID string, requestIDs []string) ([]AccessContentLog, error) {
	if len(requestIDs) == 0 {
		return nil, nil
	}
	query := `
		SELECT
			acl.request_id,
			COALESCE(acl.section_id, ''),
			COALESCE(acl.request_content_redacted, ''),
			COALESCE(acl.response_content_redacted, ''),
			COALESCE(acl.file_metadata_json, '[]'::jsonb),
			COALESCE(acl.tool_call_metadata_json, '[]'::jsonb),
			COALESCE(acl.decoder_version, ''),
			acl.retention_until,
			acl.created_at
		FROM access_content_logs acl
		JOIN request_logs rl
			ON rl.request_id = acl.request_id
			AND rl.tenant_id = acl.tenant_id
			AND rl.environment_scope = acl.environment_scope
		WHERE acl.tenant_id = $1
			AND acl.request_id = ANY($2)
			AND acl.conversation_id = (
				SELECT anchor.conversation_id
				FROM access_content_logs anchor
				WHERE anchor.tenant_id = $1
					AND anchor.request_id = $3
					AND anchor.environment_scope = acl.environment_scope
				ORDER BY anchor.created_at DESC
				LIMIT 1
			)
		ORDER BY acl.created_at, acl.request_id
	`
	rows, err := r.retentionRead().Query(ctx, query, tenantID, requestIDs, requestIDs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get access content logs: %w", err)
	}
	defer rows.Close()
	out := []AccessContentLog{}
	for rows.Next() {
		var item AccessContentLog
		var retentionUntil sql.NullTime
		if err := rows.Scan(&item.RequestID, &item.SectionID, &item.RequestContent, &item.ResponseContent, &item.FileMetadataJSON, &item.ToolCallMetadataJSON, &item.DecoderVersion, &retentionUntil, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan access content log: %w", err)
		}
		if retentionUntil.Valid {
			item.RetentionUntil = &retentionUntil.Time
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate access content logs: %w", err)
	}
	return out, nil
}

func (r *RequestLogRepository) GetAccessContentLogsScoped(
	ctx context.Context,
	tenantID string,
	requestIDs []string,
	start, end time.Time,
	environmentScope string,
) ([]AccessContentLog, error) {
	if len(requestIDs) == 0 {
		return nil, nil
	}
	args := []interface{}{tenantID, requestIDs, requestIDs[0]}
	where := []string{
		"acl.tenant_id = $1",
		"acl.request_id = ANY($2)",
		`acl.conversation_id = (
			SELECT anchor.conversation_id
			FROM access_content_logs anchor
			WHERE anchor.tenant_id = $1
				AND anchor.request_id = $3
				AND anchor.environment_scope = acl.environment_scope
			ORDER BY anchor.created_at DESC
			LIMIT 1
		)`,
	}
	if environmentScope != "" {
		args = append(args, EnvironmentScopesForRead(environmentScope))
		where = append(where, fmt.Sprintf("acl.environment_scope = ANY($%d)", len(args)))
		where = append(where, fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)))
	}
	if !start.IsZero() {
		args = append(args, start)
		where = append(where, fmt.Sprintf("acl.created_at >= $%d", len(args)))
	}
	if !end.IsZero() {
		args = append(args, end)
		where = append(where, fmt.Sprintf("acl.created_at < $%d", len(args)))
	}
	query := `
		SELECT
			acl.request_id,
			COALESCE(acl.section_id, ''),
			COALESCE(acl.request_content_redacted, ''),
			COALESCE(acl.response_content_redacted, ''),
			COALESCE(acl.file_metadata_json, '[]'::jsonb),
			COALESCE(acl.tool_call_metadata_json, '[]'::jsonb),
			COALESCE(acl.decoder_version, ''),
			acl.retention_until,
			acl.created_at
		FROM access_content_logs acl
		JOIN request_logs rl
			ON rl.request_id = acl.request_id
			AND rl.tenant_id = acl.tenant_id
			AND rl.environment_scope = acl.environment_scope
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY acl.created_at ASC, acl.request_id ASC
	`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get scoped access content logs: %w", err)
	}
	defer rows.Close()
	logs := []AccessContentLog{}
	for rows.Next() {
		var item AccessContentLog
		var retentionUntil sql.NullTime
		if err := rows.Scan(&item.RequestID, &item.SectionID, &item.RequestContent, &item.ResponseContent, &item.FileMetadataJSON, &item.ToolCallMetadataJSON, &item.DecoderVersion, &retentionUntil, &item.CreatedAt); err != nil {
			return nil, err
		}
		if retentionUntil.Valid {
			item.RetentionUntil = &retentionUntil.Time
		}
		logs = append(logs, item)
	}
	return logs, rows.Err()
}

// ResolvedUploadedFile 表示按 reference_id 在租户内解引用得到的上传文件/图片字节。
type ResolvedUploadedFile struct {
	ReferenceID string
	FileName    string
	ContentType string
	SHA256      string
	DataBase64  string
	Size        int64
}

// ResolveUploadedFileBytes 按 reference_id 在「指定租户内」解引用正向代理网页版上传行
// 持有的真实字节。网页版上传是三段式流程：上传行(upload_file)的 file_metadata_json
// 数组里既有 source=multipart 的字节元素(带 data_base64)，又有 source=json_file_object
// 的引用回执元素(带 reference_id)；而对话行只携带 source=json_file_reference 的引用(无
// 字节)。本方法在同一上传行内把「引用回执」与「字节元素」交叉关联，从而用对话行里的
// reference_id 取回上传行里的字节，供后台留存详情展示真实图片/文件。
//
// 安全不变量：查询强制 tenant、scope、时间窗收口，且 JOIN request_logs 同样收口；
// 不同租户或环境即便复用相同的 reference_id 也互不可见。空入参直接返回空映射、不触发查询。
func (r *RequestLogRepository) ResolveUploadedFileBytes(ctx context.Context, tenantID string, referenceIDs []string) (map[string]ResolvedUploadedFile, error) {
	return r.ResolveUploadedFileBytesScoped(ctx, tenantID, referenceIDs, time.Time{}, time.Time{}, "")
}

func (r *RequestLogRepository) ResolveUploadedFileBytesScoped(
	ctx context.Context,
	tenantID string,
	referenceIDs []string,
	start, end time.Time,
	environmentScope string,
) (map[string]ResolvedUploadedFile, error) {
	out := make(map[string]ResolvedUploadedFile)
	if len(referenceIDs) == 0 {
		return out, nil
	}
	args := []interface{}{tenantID, referenceIDs}
	where := []string{
		"acl.tenant_id = $1",
		"ref_elem->>'reference_id' = ANY($2)",
		"length(COALESCE(bytes_elem->>'data_base64', '')) > 0",
	}
	if environmentScope != "" {
		args = append(args, EnvironmentScopesForRead(environmentScope))
		where = append(where,
			fmt.Sprintf("acl.environment_scope = ANY($%d)", len(args)),
			fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)),
		)
	}
	if !start.IsZero() {
		args = append(args, start)
		where = append(where,
			fmt.Sprintf("acl.created_at >= $%d", len(args)),
			fmt.Sprintf("rl.created_at >= $%d", len(args)),
		)
	}
	if !end.IsZero() {
		args = append(args, end)
		where = append(where,
			fmt.Sprintf("acl.created_at < $%d", len(args)),
			fmt.Sprintf("rl.created_at < $%d", len(args)),
		)
	}
	query := `
		SELECT DISTINCT ON (ref_elem->>'reference_id')
			ref_elem->>'reference_id' AS reference_id,
			COALESCE(bytes_elem->>'file_name', ''),
			COALESCE(bytes_elem->>'content_type', ''),
			COALESCE(bytes_elem->>'sha256', ''),
			COALESCE(bytes_elem->>'data_base64', ''),
			COALESCE(NULLIF(bytes_elem->>'size', '')::bigint, 0)
		FROM access_content_logs acl
		JOIN request_logs rl
			ON rl.request_id = acl.request_id
			AND rl.tenant_id = acl.tenant_id
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(acl.file_metadata_json, '[]'::jsonb)) AS ref_elem
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(acl.file_metadata_json, '[]'::jsonb)) AS bytes_elem
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ref_elem->>'reference_id', acl.created_at DESC
	`
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve uploaded file bytes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f ResolvedUploadedFile
		if err := rows.Scan(
			&f.ReferenceID,
			&f.FileName,
			&f.ContentType,
			&f.SHA256,
			&f.DataBase64,
			&f.Size,
		); err != nil {
			return nil, fmt.Errorf("failed to scan resolved uploaded file: %w", err)
		}
		out[f.ReferenceID] = f
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate resolved uploaded files: %w", err)
	}
	return out, nil
}

// DeleteExpiredAccessContentLogs 保持原删除条件，同时使受影响请求的派生标记失效。
func (r *RequestLogRepository) DeleteExpiredAccessContentLogs(ctx context.Context) (int64, error) {
	var total int64
	for {
		tag, err := internaltitle.Prune(ctx, r.db, "access_content_logs", "retention_until IS NOT NULL AND retention_until < NOW()", false, 5000)
		if err != nil {
			return total, fmt.Errorf("failed to delete expired access content logs: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 5000 {
			return total, nil
		}
	}
}

// requestLogPruneBatch 单批删除上限,分批删避免长事务锁表。
const requestLogPruneBatch = 5000

// DeleteRequestLogsOlderThan 按保留天数清理 request_logs 原始明细(WORM 安全):
// 只删超期、且 ① 无 security_events(安全事件=审计留存,绝不删)② 无 tool_events(RESTRICT 外键)
// 引用的行;content_logs(id→CASCADE)与 access_content_logs(request_id→CASCADE)随之自动清理。
// 分批每批 requestLogPruneBatch 行,避免长事务锁表。
func (r *RequestLogRepository) DeleteRequestLogsOlderThan(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays < 1 {
		return 0, nil
	}
	var total int64
	for {
		tag, err := r.db.Exec(ctx, `
			DELETE FROM request_logs
			WHERE id IN (
				SELECT r.id FROM request_logs r
				WHERE r.created_at < (CURRENT_DATE - INTERVAL '1 day' * $1)
				  AND NOT EXISTS (SELECT 1 FROM security_events s WHERE s.request_id = r.request_id)
				  AND NOT EXISTS (SELECT 1 FROM tool_events t WHERE t.request_id = r.request_id)
				ORDER BY r.created_at
				LIMIT $2
			)`, retentionDays, requestLogPruneBatch)
		if err != nil {
			return total, fmt.Errorf("failed to delete old request_logs: %w", err)
		}
		n := tag.RowsAffected()
		total += n
		if n < requestLogPruneBatch {
			break
		}
	}
	return total, nil
}

// forwardProxyRiskColumnsSetClause 返回回填 risk_state / has_retained_content 的
// SET 子句，复用读路径同一套权威表达式，确保预计算列与实时口径一致、不漂移。
func forwardProxyRiskColumnsSetClause() string {
	return fmt.Sprintf("risk_state = %s, has_retained_content = %s, risk_reasons = %s, request_body_exists = %s, response_body_exists = %s",
		forwardProxyRiskExpr(), forwardProxyHasRetainedContentExpr(),
		forwardProxyRiskReasonsExpr(), forwardProxyRequestBodyExistsExpr(), forwardProxyResponseBodyExistsExpr())
}

// BackfillRiskColumns 批量为尚未计算(risk_state IS NULL)的行回填预计算列；
// 返回本批影响行数，0 表示已无待回填。按 ctid 限批、可重复调用、重启安全。
func (r *RequestLogRepository) BackfillRiskColumns(ctx context.Context, batch int) (int64, error) {
	if batch <= 0 {
		batch = 5000
	}
	query := fmt.Sprintf(`UPDATE request_logs rl SET %s
		WHERE rl.ctid IN (SELECT ctid FROM request_logs WHERE risk_state IS NULL OR risk_reasons IS NULL OR request_body_exists IS NULL OR response_body_exists IS NULL LIMIT %d)`,
		forwardProxyRiskColumnsSetClause(), batch)
	tag, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("backfill risk columns: %w", err)
	}
	return tag.RowsAffected(), nil
}

// forwardProxyRiskColumnsChangedClause 返回「至少一列新值与现值不同」的过滤条件。
// 新值表达式与 forwardProxyRiskColumnsSetClause 取自同一对函数,保证比较的就是
// 即将写入的值、不会漂移。必须用 IS DISTINCT FROM 而不是 <>:列为 NULL(尚未计算)
// 时 <> 得 NULL、会被过滤掉,而这类行恰恰必须被写入。
func forwardProxyRiskColumnsChangedClause() string {
	return fmt.Sprintf("(rl.risk_state IS DISTINCT FROM (%s) OR rl.has_retained_content IS DISTINCT FROM (%s) OR rl.risk_reasons IS DISTINCT FROM (%s) OR rl.request_body_exists IS DISTINCT FROM (%s) OR rl.response_body_exists IS DISTINCT FROM (%s))",
		forwardProxyRiskExpr(), forwardProxyHasRetainedContentExpr(),
		forwardProxyRiskReasonsExpr(), forwardProxyRequestBodyExistsExpr(), forwardProxyResponseBodyExistsExpr())
}

// RefreshRecentRiskColumns 重算最近 window 内行的预计算列，吸收延迟到达的
// security_events / 留存内容并覆盖新写入。
//
// 只写至少有一列真正变化的行:值没变的行不再产生新元组版本。此前无条件重写整个窗口,
// 稳态下每轮也要为窗口内每一行写一份完整的新元组(WAL)并留下一份死元组,
// 在慢盘现场放大 I/O。
//
// 返回值是「真正被更新的行数」,不再是窗口内行数;数据稳定时为 0。目前唯一的调用方
// (cmd/server/main.go 的 risk-columns 周期任务)丢弃返回值,所以含义变化不影响调用方。
// 变化行的表达式会被求值两次(WHERE 一次、SET 一次),未变化行只求值一次(与改前相同)。
func (r *RequestLogRepository) RefreshRecentRiskColumns(ctx context.Context, window time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx, recentRiskColumnsRefreshQuery(), time.Now().Add(-window))
	if err != nil {
		return 0, fmt.Errorf("refresh recent risk columns: %w", err)
	}
	return tag.RowsAffected(), nil
}

// recentRiskColumnsRefreshQuery 构造 RefreshRecentRiskColumns 的 UPDATE 语句($1 = 窗口起点)。
// 单独成函数是为了让测试能直接断言最终 SQL 文本。
func recentRiskColumnsRefreshQuery() string {
	return fmt.Sprintf(`UPDATE request_logs rl SET %s
		WHERE rl.tenant_id IN (SELECT id FROM tenants) AND rl.created_at >= $1
			AND %s`, forwardProxyRiskColumnsSetClause(), forwardProxyRiskColumnsChangedClause())
}
