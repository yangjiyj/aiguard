package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/internaltitle"
	"strings"
	"time"
)

type EvidenceRunRecord struct {
	RunID                    string
	Kind                     string
	CorrelationSource        string
	CorrelationConfidence    string
	RepresentativeRequestID  string
	MemberRequestIDs         []string
	Title                    string
	StartedAt                time.Time
	EndedAt                  time.Time
	AgentType                string
	AgentRuntime             string
	AgentDetectionSource     string
	AgentDetectionConfidence float64
	Username                 string
	ClientName               string
	SourceIP                 string
	Models                   []string
	AccessDirections         []string
	RequestCount             int
	EvidenceStatus           string
	RiskState                string
}

type evidenceRunGrouping struct {
	View, KeySQL, SourceSQL, ConfidenceSQL, FilterSQL string
}

const evidenceRunPromptCacheCandidateSourceSQL = `COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')`

func evidenceRunGroupSpec(view string) (evidenceRunGrouping, error) {
	switch strings.TrimSpace(view) {
	case "agent_tasks":
		return evidenceRunGrouping{
			View: "agent_task",
			KeySQL: `CASE
				WHEN COALESCE(evidence_run_id, '') <> '' THEN 'evidence:' || evidence_run_id
				WHEN COALESCE(session_id, '') <> '' THEN 'session:' || session_id
				WHEN COALESCE(conversation_id, '') <> '' THEN 'conversation:' || conversation_id
				WHEN COALESCE(content_session_id, '') <> '' THEN 'content_session:' || content_session_id
				WHEN COALESCE(runtime_context_id, '') <> '' THEN 'runtime_context:' || md5(
					COALESCE(effective_agent_type, '') || chr(31) || COALESCE(target_host, '') || chr(31) ||
					COALESCE(source_ip, '') || chr(31) || runtime_context_id)
				ELSE 'request:' || request_id END`,
			SourceSQL: `CASE
				WHEN COALESCE(evidence_run_id, '') <> '' THEN COALESCE(NULLIF(evidence_run_source, ''), 'protocol_key')
				WHEN COALESCE(session_id, '') <> '' THEN 'session_id'
				WHEN conversation_id ~ '^ck_[0-9a-f]{32}$' THEN 'content_fingerprint'
				WHEN COALESCE(conversation_id, '') <> '' THEN 'conversation_id'
				WHEN COALESCE(content_session_id, '') <> '' THEN 'content_session_id'
				WHEN COALESCE(runtime_context_id, '') <> '' THEN 'runtime_context_id'
				ELSE 'request_id' END`,
			ConfidenceSQL: `CASE
				WHEN COALESCE(evidence_run_id, '') <> '' OR COALESCE(session_id, '') <> '' THEN 'exact'
                WHEN conversation_id ~ '^ck_[0-9a-f]{32}$' THEN 'inferred'
                WHEN COALESCE(conversation_id, '') <> '' OR COALESCE(content_session_id, '') <> '' THEN 'exact'
				WHEN COALESCE(runtime_context_id, '') <> '' THEN 'inferred'
				ELSE 'unlinked' END`,
			FilterSQL: `COALESCE(effective_agent_type, '') <> ''`,
		}, nil
	case "ai_conversations":
		return evidenceRunGrouping{
			View: "ai_conversation",
			KeySQL: `CASE
				WHEN COALESCE(conversation_id, '') <> '' THEN 'conversation:' || conversation_id
				WHEN COALESCE(evidence_run_id, '') <> '' THEN 'evidence:' || evidence_run_id
				WHEN COALESCE(session_id, '') <> '' THEN 'session:' || session_id
				ELSE 'request:' || request_id END`,
			SourceSQL: `CASE
				WHEN conversation_id ~ '^ck_[0-9a-f]{32}$' THEN 'content_fingerprint'
				WHEN COALESCE(conversation_id, '') <> '' THEN 'conversation_id'
				WHEN COALESCE(evidence_run_id, '') <> '' THEN COALESCE(NULLIF(evidence_run_source, ''), 'protocol_key')
				WHEN COALESCE(session_id, '') <> '' THEN 'session_id'
				ELSE 'request_id' END`,
			ConfidenceSQL: `CASE WHEN conversation_id ~ '^ck_[0-9a-f]{32}$' THEN 'inferred'
                WHEN COALESCE(conversation_id, '') <> '' OR COALESCE(evidence_run_id, '') <> '' OR COALESCE(session_id, '') <> '' THEN 'exact' ELSE 'unlinked' END`,
			FilterSQL: `COALESCE(effective_agent_type, '') = ''`,
		}, nil
	default:
		return evidenceRunGrouping{}, fmt.Errorf("unsupported evidence view")
	}
}

func buildEvidenceRunsQuery(spec evidenceRunGrouping, where []string, argCount int) string {
	return buildEvidenceRunsQueryWithTotal(spec, where, argCount, true)
}

func buildEvidenceRunsQueryWithTotal(spec evidenceRunGrouping, where []string, argCount int, includeTotal bool) string {
	effectiveAgentType := `CASE
		WHEN COALESCE(rl.agent_type, '') = 'vscode' AND COALESCE(codex_match.matched, FALSE) THEN 'openai-codex'
		ELSE COALESCE(rl.agent_type, '') END`
	totalExpr := "0::int"
	if includeTotal {
		totalExpr = "COUNT(*) OVER()::int"
	}
	return fmt.Sprintf(`
WITH candidate AS (
	SELECT
		rl.id AS internal_request_id, rl.request_id, rl.created_at, rl.environment_scope,
		COALESCE(rl.session_id, '') AS session_id,
		CASE WHEN `+evidenceRunPromptCacheCandidateSourceSQL+` THEN '' ELSE COALESCE(rl.evidence_run_id, '') END AS evidence_run_id,
		COALESCE(rl.evidence_run_source, '') AS evidence_run_source,
		COALESCE(acl_key.conversation_id, '') AS conversation_id,
		CASE WHEN COALESCE(acl_key.request_content_redacted, '') ~
			'(?is)<system_reminder(?:\s[^>]*)?>.*</system_reminder>'
		THEN COALESCE((regexp_match(
			COALESCE(acl_key.request_content_redacted, ''),
			'(?is)^\s*<current_datetime(?:\s[^>]*)?>([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9TZ:+.\-]+)</current_datetime>'
		))[1], '') ELSE '' END AS runtime_context_id,
		CASE WHEN COALESCE(content_session.session_id, '') IN (rl.request_id, rl.id)
			THEN '' ELSE COALESCE(content_session.session_id, '') END AS content_session_id,
		COALESCE(rl.agent_type, '') AS effective_agent_type,
		COALESCE(rl.proxy_target_host, '') AS target_host,
		COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') AS source_ip,
		COALESCE(rl.risk_state, 'normal') AS risk_state
	FROM request_logs rl
	LEFT JOIN LATERAL (
		SELECT conversation_id, request_content_redacted
		FROM access_content_logs acl_inner
		WHERE acl_inner.tenant_id = rl.tenant_id
		  AND acl_inner.request_id = rl.request_id
		  AND acl_inner.environment_scope = rl.environment_scope
		ORDER BY acl_inner.created_at DESC, acl_inner.id DESC LIMIT 1
	) acl_key ON TRUE
	LEFT JOIN LATERAL (
		SELECT session_id
		FROM `+internaltitle.MetadataRows()+` session_cl
		WHERE session_cl.tenant_id = rl.tenant_id AND session_cl.request_id = rl.id
		  AND session_cl.environment_scope = rl.environment_scope AND session_cl.session_id IS NOT NULL
		ORDER BY session_cl.created_at DESC, session_cl.id DESC LIMIT 1
	) content_session ON TRUE
	WHERE %s
), enriched AS (
	SELECT candidate.*, '' AS derived_chain_root, 0::bigint AS derived_chain_size
	FROM candidate
), keyed AS (
	SELECT enriched.*, %s AS group_key, %s AS correlation_source,
		%s AS correlation_confidence
	FROM enriched WHERE %s
), grouped AS (
	SELECT
		group_key, MIN(created_at) AS started_at, MAX(created_at) AS ended_at,
		(array_agg(request_id ORDER BY created_at DESC, request_id DESC))[1] AS representative_request_id,
		array_agg(request_id ORDER BY created_at, request_id) AS member_request_ids,
		COUNT(*)::int AS request_count,
		CASE WHEN BOOL_OR(risk_state = 'blocked') THEN 'blocked'
			 WHEN BOOL_OR(risk_state = 'risk') THEN 'risk' ELSE 'normal' END AS risk_state,
		(array_agg(correlation_source ORDER BY created_at DESC))[1] AS correlation_source,
		(array_agg(correlation_confidence ORDER BY created_at DESC))[1] AS correlation_confidence
	FROM keyed GROUP BY group_key
), paged AS (
	SELECT grouped.*, %s AS total_count
	FROM grouped
	ORDER BY ended_at DESC
	LIMIT $%d OFFSET $%d
), page_members AS (
	SELECT
		paged.group_key, paged.started_at, paged.ended_at, paged.representative_request_id,
		paged.member_request_ids, paged.request_count, paged.risk_state,
		paged.correlation_source, paged.correlation_confidence, paged.total_count,
		rl.request_id, rl.created_at,
		%s AS effective_agent_type,
		COALESCE(NULLIF(rl.agent_runtime, ''), CASE WHEN rl.agent_type = 'vscode' THEN 'vscode' ELSE '' END) AS effective_agent_runtime,
		CASE WHEN rl.agent_type = 'vscode' AND (%s) = 'openai-codex' THEN 'content' ELSE COALESCE(rl.agent_detection_source, '') END AS effective_detection_source,
		CASE WHEN rl.agent_type = 'vscode' AND (%s) = 'openai-codex' THEN 0.98 ELSE COALESCE(rl.agent_detection_confidence, 0) END AS effective_detection_confidence,
		COALESCE(
			NULLIF(BTRIM((regexp_match(title_cl.content, '<user_query[^>]*>([^<]*)</user_query>'))[1], '"'), ''),
			NULLIF(acl.request_content_redacted, ''),
			NULLIF(BTRIM(title_cl.content, '"'), ''),
			''
		) AS title,
		COALESCE(u.username, '') AS username,
		COALESCE(NULLIF(k.name, ''), '') AS client_name,
		COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') AS source_ip,
		COALESCE(NULLIF(rl.proxy_target_host, ''), NULLIF(m.model_label, ''), NULLIF(m.model_name, ''), rl.model_id, '') AS target,
		CASE WHEN COALESCE(rl.proxy_mode, '') = 'forward' THEN 'forward'
			 WHEN COALESCE(rl.proxy_mode, '') = 'reverse' THEN 'reverse'
			 ELSE 'chat_completion' END AS access_direction,
		(
			COALESCE(NULLIF(acl.request_content_redacted, ''), '') <> '' OR EXISTS (
				SELECT 1 FROM `+internaltitle.ContentRows("'user'")+` req_cl WHERE req_cl.tenant_id = rl.tenant_id
				AND req_cl.environment_scope = rl.environment_scope
				AND req_cl.request_id = rl.id AND req_cl.role = 'user' AND BTRIM(req_cl.content) <> ''
			)
		) AS request_evidence,
		(
			COALESCE(NULLIF(acl.response_content_redacted, ''), '') <> '' OR EXISTS (
				SELECT 1 FROM `+internaltitle.ContentRows("'assistant'")+` resp_cl WHERE resp_cl.tenant_id = rl.tenant_id
				AND resp_cl.environment_scope = rl.environment_scope
				AND resp_cl.request_id = rl.id AND resp_cl.role = 'assistant' AND BTRIM(resp_cl.content) <> ''
			)
		) AS response_evidence
	FROM paged
	JOIN request_logs rl ON rl.tenant_id = $1 AND rl.request_id = ANY(paged.member_request_ids)
	LEFT JOIN users u ON u.id = rl.user_id
	LEFT JOIN models m ON m.id = rl.model_id
	LEFT JOIN internal_keys k ON k.id = rl.client_id AND k.tenant_id = rl.tenant_id
	LEFT JOIN LATERAL (
		SELECT TRUE AS matched
		FROM `+internaltitle.ContentRows("")+` codex_cl
		WHERE COALESCE(rl.agent_type, '') = 'vscode'
		  AND codex_cl.tenant_id = rl.tenant_id AND codex_cl.request_id = rl.id
		  AND codex_cl.environment_scope = rl.environment_scope
		  AND (codex_cl.content ILIKE '%%OpenAI Codex%%' OR codex_cl.content ILIKE '%%Codex Desktop%%')
		ORDER BY codex_cl.created_at DESC, codex_cl.id DESC LIMIT 1
	) codex_match ON TRUE
	LEFT JOIN LATERAL (
		SELECT content FROM `+internaltitle.ContentRows("'user'")+` cl
		WHERE cl.tenant_id = rl.tenant_id AND cl.request_id = rl.id
		  AND cl.environment_scope = rl.environment_scope AND cl.role = 'user'
		  AND BTRIM(cl.content) <> '' AND cl.content NOT LIKE '<environment_context>%%'
		ORDER BY cl.created_at DESC, cl.id DESC LIMIT 1
	) title_cl ON TRUE
	LEFT JOIN LATERAL (
		SELECT request_content_redacted, response_content_redacted
		FROM access_content_logs acl_inner
		WHERE acl_inner.tenant_id = rl.tenant_id AND acl_inner.request_id = rl.request_id
		  AND acl_inner.environment_scope = rl.environment_scope
		ORDER BY acl_inner.created_at DESC, acl_inner.id DESC LIMIT 1
	) acl ON TRUE
), page_enriched AS (
	SELECT
		group_key, started_at, ended_at, representative_request_id, member_request_ids,
		(array_agg(title ORDER BY (title <> '') DESC, created_at ASC))[1] AS title,
		(array_agg(effective_agent_type ORDER BY (effective_agent_type <> '') DESC, created_at DESC))[1] AS effective_agent_type,
		(array_agg(effective_agent_runtime ORDER BY (effective_agent_runtime <> '') DESC, created_at DESC))[1] AS effective_agent_runtime,
		(array_agg(effective_detection_source ORDER BY (effective_detection_source <> '') DESC, created_at DESC))[1] AS effective_detection_source,
		MAX(effective_detection_confidence) AS effective_detection_confidence,
		(array_agg(username ORDER BY (username <> '') DESC, created_at DESC))[1] AS username,
		(array_agg(client_name ORDER BY (client_name <> '') DESC, created_at DESC))[1] AS client_name,
		(array_agg(source_ip ORDER BY (source_ip <> '') DESC, created_at DESC))[1] AS source_ip,
		COALESCE(jsonb_agg(DISTINCT target) FILTER (WHERE target <> ''), '[]'::jsonb) AS models,
		COALESCE(jsonb_agg(DISTINCT access_direction), '[]'::jsonb) AS access_directions,
		request_count, BOOL_OR(request_evidence) AS request_evidence,
		BOOL_OR(response_evidence) AS response_evidence, risk_state,
		correlation_source, correlation_confidence, total_count
	FROM page_members
	GROUP BY group_key, started_at, ended_at, representative_request_id, member_request_ids,
		request_count, risk_state, correlation_source, correlation_confidence, total_count
)
SELECT
	group_key, started_at, ended_at, representative_request_id,
	to_jsonb(member_request_ids) AS member_request_ids,
	LEFT(title, 160), effective_agent_type, effective_agent_runtime,
	effective_detection_source, effective_detection_confidence,
	username, client_name, source_ip, models, access_directions, request_count,
	CASE WHEN request_evidence AND response_evidence THEN 'complete'
		 WHEN request_evidence OR response_evidence THEN 'partial' ELSE 'metadata_only' END AS evidence_status,
	risk_state, correlation_source, correlation_confidence, total_count
FROM page_enriched
ORDER BY ended_at DESC
`, strings.Join(where, " AND "), spec.KeySQL, spec.SourceSQL, spec.ConfidenceSQL, spec.FilterSQL, totalExpr, argCount+1, argCount+2, effectiveAgentType, effectiveAgentType, effectiveAgentType)
}

func buildIndexedEvidenceRunsQueryWithTotal(spec evidenceRunGrouping, where []string, argCount int, includeTotal bool) string {
	totalExpr := "0::int"
	if includeTotal {
		totalExpr = "COUNT(*) OVER()::int"
	}
	return fmt.Sprintf(`
WITH candidate AS MATERIALIZED (
SELECT
rl.id AS internal_request_id, rl.request_id, rl.created_at, rl.environment_scope,
eri.session_id,
eri.evidence_run_id,
eri.evidence_run_source,
eri.conversation_id,
CASE WHEN COALESCE(runtime_acl.request_content_redacted, '') ~
'(?is)<system_reminder(?:\s[^>]*)?>.*</system_reminder>'
THEN COALESCE((regexp_match(
COALESCE(runtime_acl.request_content_redacted, ''),
'(?is)^\s*<current_datetime(?:\s[^>]*)?>([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9TZ:+.\-]+)</current_datetime>'
))[1], '') ELSE '' END AS runtime_context_id,
CASE WHEN COALESCE(content_session.session_id, '') IN (rl.request_id, rl.id)
THEN '' ELSE COALESCE(content_session.session_id, '') END AS content_session_id,
eri.effective_agent_type,
eri.effective_agent_runtime,
eri.effective_detection_source,
eri.effective_detection_confidence,
COALESCE(rl.proxy_target_host, '') AS target_host,
COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') AS source_ip,
COALESCE(rl.risk_state, 'normal') AS risk_state
FROM evidence_run_request_index eri
JOIN request_logs rl
  ON rl.tenant_id = eri.tenant_id AND rl.id = eri.request_log_id
LEFT JOIN LATERAL (
SELECT session_id
FROM `+internaltitle.MetadataRows()+` session_cl
WHERE eri.evidence_run_id = '' AND eri.session_id = '' AND eri.conversation_id = ''
  AND session_cl.tenant_id = rl.tenant_id AND session_cl.request_id = rl.id
  AND session_cl.environment_scope = rl.environment_scope AND session_cl.session_id IS NOT NULL
ORDER BY session_cl.created_at DESC, session_cl.id DESC LIMIT 1
) content_session ON TRUE
LEFT JOIN LATERAL (
SELECT request_content_redacted
FROM access_content_logs acl_inner
WHERE eri.evidence_run_id = '' AND eri.session_id = '' AND eri.conversation_id = ''
  AND content_session.session_id IS NULL
  AND acl_inner.tenant_id = rl.tenant_id
  AND acl_inner.request_id = rl.request_id
  AND acl_inner.environment_scope = rl.environment_scope
ORDER BY acl_inner.created_at DESC, acl_inner.id DESC LIMIT 1
) runtime_acl ON TRUE
WHERE %s
), keyed AS MATERIALIZED (
SELECT candidate.*, %s AS group_key, %s AS correlation_source,
%s AS correlation_confidence
FROM candidate WHERE %s
), grouped AS (
SELECT
group_key, MIN(created_at) AS started_at, MAX(created_at) AS ended_at,
(array_agg(request_id ORDER BY created_at DESC, request_id DESC))[1] AS representative_request_id,
COUNT(*)::int AS request_count,
CASE WHEN BOOL_OR(risk_state = 'blocked') THEN 'blocked'
 WHEN BOOL_OR(risk_state = 'risk') THEN 'risk' ELSE 'normal' END AS risk_state,
(array_agg(correlation_source ORDER BY created_at DESC))[1] AS correlation_source,
(array_agg(correlation_confidence ORDER BY created_at DESC))[1] AS correlation_confidence
FROM keyed GROUP BY group_key
), paged AS MATERIALIZED (
SELECT grouped.*, %s AS total_count
FROM grouped
ORDER BY ended_at DESC
LIMIT $%d OFFSET $%d
), page_members AS (
SELECT
paged.group_key, paged.started_at, paged.ended_at, paged.representative_request_id,
paged.request_count, paged.risk_state, paged.correlation_source,
paged.correlation_confidence, paged.total_count,
keyed_member.request_id, keyed_member.created_at,
keyed_member.effective_agent_type,
keyed_member.effective_agent_runtime,
keyed_member.effective_detection_source,
keyed_member.effective_detection_confidence,
COALESCE(
NULLIF(BTRIM((regexp_match(title_cl.content, '<user_query[^>]*>([^<]*)</user_query>'))[1], '"'), ''),
NULLIF(acl.request_content_redacted, ''),
NULLIF(BTRIM(title_cl.content, '"'), ''),
''
) AS title,
COALESCE(u.username, '') AS username,
COALESCE(NULLIF(k.name, ''), '') AS client_name,
COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') AS source_ip,
COALESCE(NULLIF(rl.proxy_target_host, ''), NULLIF(m.model_label, ''), NULLIF(m.model_name, ''), rl.model_id, '') AS target,
CASE WHEN COALESCE(rl.proxy_mode, '') = 'forward' THEN 'forward'
 WHEN COALESCE(rl.proxy_mode, '') = 'reverse' THEN 'reverse'
 ELSE 'chat_completion' END AS access_direction,
(
COALESCE(NULLIF(acl.request_content_redacted, ''), '') <> '' OR EXISTS (
SELECT 1 FROM `+internaltitle.ContentRows("'user'")+` req_cl WHERE req_cl.tenant_id = rl.tenant_id
AND req_cl.environment_scope = rl.environment_scope
AND req_cl.request_id = rl.id AND req_cl.role = 'user' AND BTRIM(req_cl.content) <> ''
)
) AS request_evidence,
(
COALESCE(NULLIF(acl.response_content_redacted, ''), '') <> '' OR EXISTS (
SELECT 1 FROM `+internaltitle.ContentRows("'assistant'")+` resp_cl WHERE resp_cl.tenant_id = rl.tenant_id
AND resp_cl.environment_scope = rl.environment_scope
AND resp_cl.request_id = rl.id AND resp_cl.role = 'assistant' AND BTRIM(resp_cl.content) <> ''
)
) AS response_evidence
FROM paged
JOIN keyed keyed_member ON keyed_member.group_key = paged.group_key
JOIN request_logs rl
  ON rl.tenant_id = $1 AND rl.id = keyed_member.internal_request_id
LEFT JOIN users u ON u.id = rl.user_id
LEFT JOIN models m ON m.id = rl.model_id
LEFT JOIN internal_keys k ON k.id = rl.client_id AND k.tenant_id = rl.tenant_id
LEFT JOIN LATERAL (
SELECT content FROM `+internaltitle.ContentRows("'user'")+` cl
WHERE cl.tenant_id = rl.tenant_id AND cl.request_id = rl.id
  AND cl.environment_scope = rl.environment_scope AND cl.role = 'user'
  AND BTRIM(cl.content) <> '' AND cl.content NOT LIKE '<environment_context>%%'
ORDER BY cl.created_at DESC, cl.id DESC LIMIT 1
) title_cl ON TRUE
LEFT JOIN LATERAL (
SELECT request_content_redacted, response_content_redacted
FROM access_content_logs acl_inner
WHERE acl_inner.tenant_id = rl.tenant_id AND acl_inner.request_id = rl.request_id
  AND acl_inner.environment_scope = rl.environment_scope
ORDER BY acl_inner.created_at DESC, acl_inner.id DESC LIMIT 1
) acl ON TRUE
), page_enriched AS (
SELECT
group_key, started_at, ended_at, representative_request_id,
array_agg(request_id ORDER BY created_at, request_id) AS member_request_ids,
(array_agg(title ORDER BY (title <> '') DESC, created_at ASC))[1] AS title,
(array_agg(effective_agent_type ORDER BY (effective_agent_type <> '') DESC, created_at DESC))[1] AS effective_agent_type,
(array_agg(effective_agent_runtime ORDER BY (effective_agent_runtime <> '') DESC, created_at DESC))[1] AS effective_agent_runtime,
(array_agg(effective_detection_source ORDER BY (effective_detection_source <> '') DESC, created_at DESC))[1] AS effective_detection_source,
MAX(effective_detection_confidence) AS effective_detection_confidence,
(array_agg(username ORDER BY (username <> '') DESC, created_at DESC))[1] AS username,
(array_agg(client_name ORDER BY (client_name <> '') DESC, created_at DESC))[1] AS client_name,
(array_agg(source_ip ORDER BY (source_ip <> '') DESC, created_at DESC))[1] AS source_ip,
COALESCE(jsonb_agg(DISTINCT target) FILTER (WHERE target <> ''), '[]'::jsonb) AS models,
COALESCE(jsonb_agg(DISTINCT access_direction), '[]'::jsonb) AS access_directions,
request_count, BOOL_OR(request_evidence) AS request_evidence,
BOOL_OR(response_evidence) AS response_evidence, risk_state,
correlation_source, correlation_confidence, total_count
FROM page_members
GROUP BY group_key, started_at, ended_at, representative_request_id,
request_count, risk_state, correlation_source, correlation_confidence, total_count
)
SELECT
group_key, started_at, ended_at, representative_request_id,
to_jsonb(member_request_ids) AS member_request_ids,
LEFT(title, 160), effective_agent_type, effective_agent_runtime,
effective_detection_source, effective_detection_confidence,
username, client_name, source_ip, models, access_directions, request_count,
CASE WHEN request_evidence AND response_evidence THEN 'complete'
 WHEN request_evidence OR response_evidence THEN 'partial' ELSE 'metadata_only' END AS evidence_status,
risk_state, correlation_source, correlation_confidence, total_count
FROM page_enriched
ORDER BY ended_at DESC
`, strings.Join(where, " AND "), spec.KeySQL, spec.SourceSQL, spec.ConfidenceSQL, spec.FilterSQL,
		totalExpr, argCount+1, argCount+2)
}

func evidenceRunPublicID(tenantID, kind, groupKey string) string {
	digest := sha256.Sum256([]byte(tenantID + "\x00" + kind + "\x00" + groupKey))
	return "evr_" + hex.EncodeToString(digest[:16])
}

func decodeEvidenceStringArray(raw []byte) []string {
	var out []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func prepareEvidenceRunFilter(tenantID string, spec evidenceRunGrouping, filter ForwardProxyAccessFilter) (evidenceRunGrouping, []string, []interface{}) {
	filter = normalizeForwardProxyFilter(filter)
	agentType := filter.AgentType
	filter.AgentType = ""
	attention := filter.RiskState == "attention"
	if attention {
		filter.RiskState = ""
	}
	where, args := buildForwardProxyWhere(tenantID, filter)
	if attention {
		args = append(args, "risk", "blocked")
		where = append(where, fmt.Sprintf("COALESCE(rl.risk_state, 'normal') IN ($%d, $%d)", len(args)-1, len(args)))
	}
	if agentType != "" {
		args = append(args, agentType)
		if agentType == "openai-codex" {
			spec.FilterSQL = fmt.Sprintf("(%s) AND LOWER(COALESCE(effective_agent_type, '')) = $%d", spec.FilterSQL, len(args))
		} else {
			// 普通智能体身份由 request_logs.agent_type 精确记录，直接下推到 candidate 阶段。
			where = append(where, fmt.Sprintf("rl.agent_type = $%d", len(args)))
		}
	}
	return spec, where, args
}

func (r *RequestLogRepository) ListEvidenceRuns(ctx context.Context, tenantID, view string, filter ForwardProxyAccessFilter) ([]EvidenceRunRecord, int, error) {
	return r.listEvidenceRunsWithQueryBuilder(ctx, tenantID, view, filter, buildIndexedEvidenceRunsQueryWithTotal)
}

// Materialize the bounded text search once, then resolve matching section
// members before grouping. Tenant and environment are part of every join.
func prepareEvidenceRunKeywordFilter(filter ForwardProxyAccessFilter, where []string, args []interface{}) (string, []string, []interface{}) {
	accessWhere, args := buildForwardProxyKeywordMatchWhere(filter, args)
	contentWhere := make([]string, 0, len(accessWhere))
	for _, predicate := range accessWhere {
		contentWhere = append(contentWhere, strings.ReplaceAll(predicate, "keyword_match.", "keyword_content."))
	}
	args = append(args, "%"+escapePostgresLikeLiteral(filter.Keyword)+"%")
	matches := retentionKeywordIndexPolicy(forwardProxyKeywordMatchSourceSQL(accessWhere, contentWhere, len(args), filter.KeywordScope), filter.Keyword, len(args))
	cte := `WITH evidence_keyword_matches AS MATERIALIZED (` + matches + `
), evidence_keyword_requests AS MATERIALIZED (
SELECT tenant_id, environment_scope, request_id FROM evidence_keyword_matches
UNION
SELECT current_content.tenant_id, current_content.environment_scope, current_content.request_id
FROM evidence_keyword_matches matched
JOIN access_content_logs current_content
  ON current_content.tenant_id = matched.tenant_id
  AND current_content.environment_scope = matched.environment_scope
  AND matched.conversation_id IS NOT NULL
  AND current_content.conversation_id = matched.conversation_id
  AND current_content.section_id IS NOT DISTINCT FROM matched.section_id
)`
	where = append(where, `EXISTS (
SELECT 1 FROM evidence_keyword_requests matched_request
WHERE matched_request.tenant_id = rl.tenant_id
  AND matched_request.environment_scope = rl.environment_scope
  AND matched_request.request_id = rl.request_id
)`)
	if filter.ContentOnly {
		where = append(where, forwardProxyInternalTitlePredicate())
	}
	return cte, where, args
}

type evidenceRunsQueryBuilder func(evidenceRunGrouping, []string, int, bool) string

func (r *RequestLogRepository) listEvidenceRunsWithQueryBuilder(ctx context.Context, tenantID, view string, filter ForwardProxyAccessFilter, buildQuery evidenceRunsQueryBuilder) ([]EvidenceRunRecord, int, error) {
	spec, err := evidenceRunGroupSpec(view)
	if err != nil {
		return nil, 0, err
	}
	filter = normalizeForwardProxyFilter(filter)
	baseFilter := filter
	if filter.Keyword != "" {
		// Keyword matches already enforce the retained-content boundary. Avoid
		// scanning the same text for every candidate in the task timeline.
		baseFilter.Keyword = ""
		baseFilter.ContentOnly = false
	}
	spec, where, args := prepareEvidenceRunFilter(tenantID, spec, baseFilter)
	keywordCTE := ""
	if filter.Keyword != "" {
		keywordCTE, where, args = prepareEvidenceRunKeywordFilter(filter, where, args)
	}
	query := buildQuery(spec, where, len(args), !filter.SkipTotal)
	if keywordCTE != "" {
		query = strings.Replace(query, "WITH candidate AS", keywordCTE+", candidate AS", 1)
	}
	queryLimit := filter.Limit
	if filter.ProbeHasMore {
		queryLimit++
	}
	args = append(args, queryLimit, filter.Offset)
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list evidence runs: %w", err)
	}
	defer rows.Close()
	records := make([]EvidenceRunRecord, 0, filter.Limit)
	total := 0
	for rows.Next() {
		var item EvidenceRunRecord
		var groupKey string
		var membersJSON, modelsJSON, directionsJSON []byte
		if err := rows.Scan(
			&groupKey, &item.StartedAt, &item.EndedAt, &item.RepresentativeRequestID,
			&membersJSON, &item.Title, &item.AgentType, &item.AgentRuntime,
			&item.AgentDetectionSource, &item.AgentDetectionConfidence,
			&item.Username, &item.ClientName, &item.SourceIP, &modelsJSON, &directionsJSON,
			&item.RequestCount, &item.EvidenceStatus, &item.RiskState, &item.CorrelationSource, &item.CorrelationConfidence,
			&total,
		); err != nil {
			return nil, 0, err
		}
		item.Kind = spec.View
		item.RunID = evidenceRunPublicID(tenantID, spec.View, groupKey)
		item.MemberRequestIDs = decodeEvidenceStringArray(membersJSON)
		item.Models = decodeEvidenceStringArray(modelsJSON)
		item.AccessDirections = decodeEvidenceStringArray(directionsJSON)
		records = append(records, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if filter.SkipTotal {
		hasMore := len(records) > filter.Limit
		if hasMore {
			records = records[:filter.Limit]
		}
		total = filter.Offset + len(records)
		if hasMore {
			total++
		}
	}
	return records, total, nil
}
