package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// This is a count of recorded event-level coverage gaps, not attacks or findings.
// A mixed event can contribute real findings and one operational gap independently.
type AlertOperationalSummary struct {
	CountKnown bool   `json:"count_known"`
	EventCount int    `json:"event_count"`
	CountUnit  string `json:"count_unit"`
	ListURL    string `json:"list_url"`
}

type AlertOperationalEvent struct {
	RemediationStatus string    `json:"remediation_status,omitempty"`
	RemediationAt     string    `json:"remediation_at,omitempty"`
	EventID           string    `json:"event_id"`
	RequestID         string    `json:"request_id"`
	ProjectID         string    `json:"project_id"`
	EventType         string    `json:"event_type"`
	ActionTaken       string    `json:"action_taken"`
	Stage             string    `json:"stage"`
	Reason            string    `json:"reason"`
	Blocked           bool      `json:"blocked"`
	Classification    string    `json:"classification"`
	CreatedAt         time.Time `json:"created_at"`
}

type AlertOperationalPage struct {
	Items     []AlertOperationalEvent `json:"items"`
	Total     int                     `json:"total"`
	Limit     int                     `json:"limit"`
	Offset    int                     `json:"offset"`
	CountUnit string                  `json:"count_unit"`
}

// A reason is the recorded runtime cause of a coverage gap (queued judge,
// overflow, malformed body, unavailable engine...). It is never a risk category.
type AlertOperationalReasonCount struct {
	Reason       string `json:"reason"`
	EventCount   int    `json:"event_count"`
	Last24hCount int    `json:"last_24h_count"`
	BlockedCount int    `json:"blocked_count"`
}

// Breakdown of coverage-gap events inside the requested scope and time range.
// Last24h is the part of that range within the past 24 hours. Every number counts
// security_events rows, so it can never be added to the attack occurrence total.
type AlertOperationalBreakdown struct {
	CountUnit    string                        `json:"count_unit"`
	EventCount   int                           `json:"event_count"`
	Last24hCount int                           `json:"last_24h_count"`
	BlockedCount int                           `json:"blocked_count"`
	LatestAt     *time.Time                    `json:"latest_at"`
	Reasons      []AlertOperationalReasonCount `json:"reasons"`
}

// The recorded cause, in precedence order: the runtime's semantic_reason, the
// inspection status of a durable proxy job, the semantic status, the runtime
// finding category, a failure action, then the event type. Only identifier-shaped
// values qualify; a free-text diagnostic is skipped so no detector prose reaches
// the client.
func operationalReasonExpr(alias string) string {
	summary := alias + ".matched_summary"
	identifier := func(expr string) string {
		return fmt.Sprintf(`(SELECT v FROM (SELECT LOWER(TRIM(COALESCE(%s,''))) AS v) candidate WHERE v ~ '^[a-z0-9_]{1,64}$')`, expr)
	}
	return fmt.Sprintf(`COALESCE(
      %[4]s,
      CASE WHEN %[3]s.action_taken='security_check_failed'
        AND COALESCE(%[1]s->>'summary','') ~ '^input security pipeline unavailable; first_failed_message=[0-9]+ [(]failure_mode=(open|close), attachments=[0-9]+, timeout=true[)]$'
        THEN 'security_pipeline_timeout' END,
      CASE WHEN LOWER(TRIM(COALESCE(%[1]s->>'inspection_status',''))) IN ('incomplete','unavailable','failed','error','timeout')
        THEN 'inspection_' || LOWER(TRIM(%[1]s->>'inspection_status')) END,
      CASE WHEN LOWER(TRIM(COALESCE(%[1]s->>'semantic_status',''))) IN ('incomplete','unavailable','failed','error','timeout')
        THEN 'semantic_' || LOWER(TRIM(%[1]s->>'semantic_status')) END,
      (SELECT %[5]s
         FROM jsonb_array_elements(
           (CASE WHEN jsonb_typeof(%[1]s->'findings')='array' THEN %[1]s->'findings' ELSE '[]'::jsonb END)
           || (CASE WHEN jsonb_typeof(%[1]s->'observations')='array' THEN %[1]s->'observations' ELSE '[]'::jsonb END)
         ) gap WHERE %[2]s AND %[5]s IS NOT NULL LIMIT 1),
      CASE WHEN LOWER(TRIM(COALESCE(%[3]s.action_taken,''))) IN ('security_check_failed','security_output_check_failed')
        THEN LOWER(TRIM(%[3]s.action_taken)) END,
      %[6]s,
      'unknown')`, summary, operationalFindingCondition("gap", alias+".action_taken"), alias,
		identifier(summary+"->>'semantic_reason'"),
		identifier("CASE WHEN LOWER(COALESCE(gap->>'type',''))='tool_failure_loop' OR (LOWER(COALESCE(gap->>'category',''))='tool_risk' AND "+legacyToolLoopAction("gap", alias+".action_taken")+") THEN 'agent_tool_failure_loop' END,gap->>'category',gap->>'type'"), identifier(alias+".event_type"))
}

func operationalBlockedExpr(alias string) string {
	return fmt.Sprintf(`LOWER(TRIM(COALESCE(%s.action_taken,''))) IN ('block','blocked','deny','reply','quarantine')`, alias)
}

// Filters are identifiers recorded by the runtime, never user free text.
func validOperationalReason(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// eventAction 是事件级 action_taken 的 SQL 表达式（没有事件上下文时传空串）。
func operationalFindingCondition(value, eventAction string) string {
	return operationalFieldCondition(value+"->>'evidence_kind'", value+"->>'type'", value+"->>'category'",
		legacyToolLoopAction(value, eventAction))
}

// legacyToolLoopAction 用于识别存量「工具连续失败」：2.9.16 及更早把它写成高危、计入告警的
// category=tool_risk 命中，事件或命中的 action 为 tool_failure_loop。
// 必须同时是 tool_risk 类别，其它 tool_risk 告警不受影响。
func legacyToolLoopAction(value, eventAction string) string {
	conds := []string{}
	if value != "" {
		conds = append(conds,
			"LOWER(TRIM(COALESCE("+value+"->>'action_taken','')))='tool_failure_loop'",
			"LOWER(TRIM(COALESCE("+value+"->>'action','')))='tool_failure_loop'")
	}
	if eventAction != "" {
		conds = append(conds, "LOWER(TRIM(COALESCE("+eventAction+",'')))='tool_failure_loop'")
	}
	if len(conds) == 0 {
		return "FALSE"
	}
	return "(" + strings.Join(conds, " OR ") + ")"
}

func operationalFieldCondition(evidenceKind, findingType, category, legacyLoopAction string) string {
	return fmt.Sprintf(`(
      LOWER(TRIM(COALESCE(%[1]s,'')))='runtime'
      OR LOWER(TRIM(COALESCE(%[2]s,''))) IN
        ('system','engine_runtime','runtime','runtime_fault','runtime_failure','engine_error','detector_error','regex_timeout','custom_scan_incomplete','tool_failure_loop')
      OR LOWER(TRIM(COALESCE(%[3]s,''))) IN
        ('system','runtime','runtime_fault','runtime_failure','security_check_failed','security_output_check_failed',
         'security_engine_unavailable','security_engine_error','detector_error','engine_error','regex_timeout',
         'custom_scan_incomplete','file_content_request_oversized','request_body_limit_exceeded')
      OR (LOWER(TRIM(COALESCE(%[3]s,'')))='tool_risk' AND %[4]s)
    )`, evidenceKind, findingType, category, legacyLoopAction)
}

func operationalRootCondition(summary, eventType, action string) string {
	return fmt.Sprintf(`(
      LOWER(TRIM(COALESCE(%s,''))) IN
        ('security_check_failed','security_output_check_failed','runtime_fault','runtime_failure','engine_error','detector_error')
      OR LOWER(TRIM(COALESCE(%s,''))) IN ('security_check_failed','security_output_check_failed')
      OR %s
      OR LOWER(TRIM(COALESCE(%s->>'semantic_status',''))) IN ('incomplete','unavailable','failed','error','timeout')
      OR LOWER(TRIM(COALESCE(%s->>'inspection_status',''))) IN ('incomplete','unavailable','failed','error','timeout')
    )`, eventType, action, operationalFindingCondition(summary, action), summary, summary)
}

func operationalEventCondition(alias string) string {
	summary := alias + ".matched_summary"
	// Decode an external/TOASTed summary once. Repeated ->> on a large compressed
	// source window caused the default operational count alone to take 7 seconds.
	return fmt.Sprintf(`CASE WHEN
      LOWER(TRIM(COALESCE(%[1]s.event_type,''))) IN
        ('security_check_failed','security_output_check_failed','runtime_fault','runtime_failure','engine_error','detector_error')
      OR LOWER(TRIM(COALESCE(%[1]s.action_taken,''))) IN ('security_check_failed','security_output_check_failed')
      THEN TRUE ELSE EXISTS (
        SELECT 1 FROM jsonb_to_record(CASE WHEN jsonb_typeof(%[2]s)='object' THEN %[2]s ELSE '{}'::jsonb END)
          AS root(evidence_kind text,type text,category text,semantic_status text,inspection_status text,findings jsonb,observations jsonb)
        WHERE %[3]s
          OR LOWER(TRIM(COALESCE(root.semantic_status,''))) IN ('incomplete','unavailable','failed','error','timeout')
          OR LOWER(TRIM(COALESCE(root.inspection_status,''))) IN ('incomplete','unavailable','failed','error','timeout')
          OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(
              (CASE WHEN jsonb_typeof(root.findings)='array' THEN root.findings ELSE '[]'::jsonb END)
              || (CASE WHEN jsonb_typeof(root.observations)='array' THEN root.observations ELSE '[]'::jsonb END)
            ) gap WHERE %[4]s
          )
      ) END`, alias, summary, operationalFieldCondition("root.evidence_kind", "root.type", "root.category", legacyToolLoopAction("", alias+".action_taken")), operationalFindingCondition("gap", alias+".action_taken"))
}

// Metadata scope matches the finding list. Attack-only category/severity filters
// deliberately do not hide missing inspections. Avoid joining request histories
// for the common tenant/project/time query over a large operational event ledger.
func operationalScopeJoin(f AlertOccurrenceFilter) string {
	if f.SessionID != "" || f.UserID != "" {
		return alertOccurrenceRequestJoin
	}
	return ""
}

func (r *AlertOccurrenceRepository) ListOperational(ctx context.Context, f AlertOccurrenceFilter) (*AlertOperationalPage, error) {
	if f.TenantID == "" {
		return nil, fmt.Errorf("operational events require tenant scope")
	}
	if f.Limit <= 0 {
		f.Limit = 20
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.Reason != "" && !validOperationalReason(f.Reason) {
		return nil, fmt.Errorf("invalid operational reason filter")
	}
	where, args := alertOccurrenceEventScope(f, []any{f.TenantID, f.Limit, f.Offset})
	reasonWhere := "TRUE"
	if f.Reason != "" {
		args = append(args, f.Reason)
		reasonWhere = fmt.Sprintf("reason = $%d", len(args))
	}
	query := `WITH operational AS MATERIALIZED (
      SELECT se.id AS event_id,COALESCE(se.request_id,'') AS request_id,
        COALESCE(se.project_id,'') AS project_id,COALESCE(se.event_type,'') AS event_type,
        COALESCE(se.action_taken,'') AS action_taken,se.created_at,
        CASE WHEN se.matched_summary->>'stage' IN ('input','output','tool')
          THEN se.matched_summary->>'stage'
          WHEN se.action_taken='security_check_failed' AND COALESCE(se.matched_summary->>'summary','')
            ~ '^input security pipeline unavailable; first_failed_message=[0-9]+ [(]failure_mode=(open|close), attachments=[0-9]+, timeout=(true|false)[)]$'
          THEN 'input' ELSE 'unknown' END AS stage,
        ` + operationalReasonExpr("se") + ` AS reason,
        ` + operationalBlockedExpr("se") + ` AS blocked,
        CASE WHEN se.matched_summary#>>'{remediation,status}' IN ('partial_rechecked','retained_content_unavailable','recheck_incomplete','retry_pending','retry_exhausted','rechecked_complete','retry_not_saved') THEN se.matched_summary#>>'{remediation,status}' ELSE '' END AS remediation_status,
        CASE WHEN (se.matched_summary#>>'{remediation,checked_at}') ~ '^[0-9T:.+Z-]{20,40}$' THEN se.matched_summary#>>'{remediation,checked_at}' ELSE '' END AS remediation_at,
        'operational_gap'::text AS classification
      FROM security_events se ` + operationalScopeJoin(f) + `
      WHERE ` + where + ` AND (` + operationalEventCondition("se") + `)
    ), selected AS (
      SELECT * FROM operational WHERE ` + reasonWhere + `
    ), page AS (
      SELECT * FROM selected ORDER BY created_at DESC,event_id DESC LIMIT $2 OFFSET $3
    )
    SELECT COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY created_at DESC,event_id DESC) FROM page),'[]'::jsonb),
      (SELECT COUNT(*) FROM selected)`
	page := &AlertOperationalPage{Items: []AlertOperationalEvent{}, Limit: f.Limit, Offset: f.Offset, CountUnit: "security_events"}
	var data []byte
	if err := r.queryAlertRead(ctx, query, args, &data, &page.Total); err != nil {
		return nil, fmt.Errorf("list operational events: %w", err)
	}
	if err := json.Unmarshal(data, &page.Items); err != nil {
		return nil, err
	}
	return page, nil
}

// One scan of the scoped ledger feeds every number; the page query is not reused
// because the breakdown needs neither identities nor a LIMIT.
func (r *AlertOccurrenceRepository) SummarizeOperational(ctx context.Context, f AlertOccurrenceFilter) (*AlertOperationalBreakdown, error) {
	if f.TenantID == "" {
		return nil, fmt.Errorf("operational summary requires tenant scope")
	}
	where, args := alertOccurrenceEventScope(f, []any{f.TenantID})
	query := `WITH operational AS MATERIALIZED (
      SELECT se.created_at, ` + operationalReasonExpr("se") + ` AS reason, ` + operationalBlockedExpr("se") + ` AS blocked
      FROM security_events se ` + operationalScopeJoin(f) + `
      WHERE ` + where + ` AND (` + operationalEventCondition("se") + `)
    ), reasons AS (
      SELECT reason, COUNT(*) AS event_count,
        COUNT(*) FILTER (WHERE created_at >= now() - interval '24 hours') AS last_24h_count,
        COUNT(*) FILTER (WHERE blocked) AS blocked_count
      FROM operational GROUP BY reason ORDER BY event_count DESC, reason LIMIT 32
    )
    SELECT (SELECT COUNT(*) FROM operational),
      (SELECT COUNT(*) FROM operational WHERE created_at >= now() - interval '24 hours'),
      (SELECT COUNT(*) FROM operational WHERE blocked),
      (SELECT MAX(created_at) FROM operational),
      COALESCE((SELECT jsonb_agg(to_jsonb(reasons) ORDER BY event_count DESC, reason) FROM reasons),'[]'::jsonb)`
	out := &AlertOperationalBreakdown{CountUnit: "security_events", Reasons: []AlertOperationalReasonCount{}}
	var data []byte
	if err := r.queryAlertRead(ctx, query, args, &out.EventCount, &out.Last24hCount, &out.BlockedCount, &out.LatestAt, &data); err != nil {
		return nil, fmt.Errorf("summarize operational events: %w", err)
	}
	if err := json.Unmarshal(data, &out.Reasons); err != nil {
		return nil, err
	}
	return out, nil
}

const alertOccurrenceRequestJoin = `
 LEFT JOIN LATERAL (
   SELECT r.user_id,r.client_id,r.session_id,r.agent_type,r.source_ip,r.proxy_source_ip,
     r.proxy_mode,r.principal_context_json,
     to_jsonb(r)->>'proxy_target_host' AS proxy_target_host,
     to_jsonb(r)->>'model_id' AS model_id,
     to_jsonb(r)->>'delivery_outcome' AS delivery_outcome,
     to_jsonb(r)->>'request_status' AS request_status,
     COALESCE(NULLIF(to_jsonb(r)->>'proxy_access_type_resolved',''),to_jsonb(r)->>'proxy_access_type') AS access_type,
     to_jsonb(r)->>'proxy_product' AS client_product
   FROM request_logs r
   WHERE r.tenant_id=se.tenant_id AND r.request_id=se.request_id
     AND (COALESCE(se.project_id,'')='' OR r.project_id=se.project_id
       -- Forward- and reverse-proxy audit records omit project_id, while
       -- their security events explicitly use project_default. Never bridge
       -- another tenant, a named project, or an unrelated transport.
       OR (se.project_id='project_default' AND COALESCE(r.project_id,'')='' AND r.proxy_mode IN ('forward','reverse')))
   ORDER BY r.created_at DESC,r.id LIMIT 1
 ) rl ON TRUE
 LEFT JOIN LATERAL (SELECT COALESCE(rl.principal_context_json,'{}'::jsonb) AS value) pc ON TRUE
`
