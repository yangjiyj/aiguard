package repository

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
)

// 告警案件物化：按物化表回答读请求时拼查询（复用实时查询的后半段）。

// errAlertCaseQueryShape：实时查询的结构变了，物化读法赖以拼接的标记找不到（或不唯一）。调用方据此改走实时查询，
// 不能拼出错位的 SQL。
var errAlertCaseQueryShape = errors.New("alert query no longer has the expected structure")

// sqlFromMarker 返回 query 从 marker 开始（含 marker）的部分。
func sqlFromMarker(query, marker string) (string, error) {
	at := strings.Index(query, marker)
	if at < 0 {
		return "", fmt.Errorf("%w: marker %q not found", errAlertCaseQueryShape, marker)
	}
	return query[at:], nil
}

// sqlBeforeMarker 返回 query 在 marker 之前的部分。
func sqlBeforeMarker(query, marker string) (string, error) {
	at := strings.Index(query, marker)
	if at < 0 {
		return "", fmt.Errorf("%w: marker %q not found", errAlertCaseQueryShape, marker)
	}
	return query[:at], nil
}

// replaceOnceInSQL 把恰好出现一次的 old 换成 new；出现零次或多次都报错。
func replaceOnceInSQL(query, old, new string) (string, error) {
	if n := strings.Count(query, old); n != 1 {
		return "", fmt.Errorf("%w: %q found %d times", errAlertCaseQueryShape, old, n)
	}
	return strings.Replace(query, old, new, 1), nil
}

var alertCaseShapeLogOnce sync.Once

// logAlertCaseShapeError 记一次结构不符（进程内只记一次，避免每次读都刷日志）。
func logAlertCaseShapeError(err error) {
	alertCaseShapeLogOnce.Do(func() {
		log.Printf("[alert-cases] WARN materialized query unavailable, using live query: %v", err)
	})
}

// alertCaseMemberColumns 是 alert_case_members 里与实时查询 keyed 同名同义的列，顺序即插入顺序。
var alertCaseMemberColumns = []string{
	"event_id", "request_id", "tenant_id", "project_id", "created_at", "event_action_taken",
	"case_id", "case_category", "evidence_identity", "occurred_at", "time_known", "case_conversation",
	"alert_group_id", "conversation_key", "disposition_status", "member_lane",
	"finding_index", "id", "type", "category", "severity", "rule_id", "finding_rule_name", "action_taken",
	"has_output_anchor", "message_index", "attachment_index", "message_role", "content_source", "stage",
	"matched_location", "review_state", "suppression_reason", "suppressed", "occurrence_key",
}

// alertCaseColumns 是 alert_cases 除 scope / refreshed_at 外的列，聚合 SQL 按此顺序输出。
var alertCaseColumns = []string{
	"tenant_id", "case_id", "project_id", "case_category", "case_lane", "severity",
	"first_seen", "last_seen", "last_detected_at", "new_evidence_at",
	"hit_count", "request_count", "rule_name_count", "blocked_count",
	"all_times_known", "all_suppressed", "all_handled", "all_false_positive", "has_unknown_occurred",
	"grouping_basis", "disposition_status", "rep_event_id", "rep_finding_slot",
}

func prefixedColumns(alias string, columns []string) string {
	out := make([]string, len(columns))
	for i, column := range columns {
		out[i] = alias + "." + column
	}
	return strings.Join(out, ",")
}

// alertCaseMaterializable：这次读能否由物化表回答。
func alertCaseMaterializable(f AlertOccurrenceFilter) bool {
	if strings.TrimSpace(f.TenantID) == "" || f.eventIDs != nil {
		return false
	}
	if f.EventID != "" || f.RequestID != "" || f.Reason != "" {
		return false
	}
	if f.Grouping == "cases" {
		return true
	}
	return f.CaseID != "" && f.Category == ""
}

// alertCaseScope 对应实时查询里的开发作用域折叠：不显示开发流量且不是按案件下钻时只看 customer 范围。
func alertCaseScope(f AlertOccurrenceFilter) string {
	if !f.IncludeDevTraffic && f.CaseID == "" {
		return "customer"
	}
	return "all"
}

// alertCaseAggregateSQL 把一组命中行聚合成案件，口径同实时查询的 alertCaseRollup（alert_cases.go）。
// 改这里必须同步改 alertCaseRollup；两份都算进物化口径指纹，任一边改了物化结果都会重建。
// src 是返回 alert_case_members 全部列的子查询。
func alertCaseAggregateSQL(src string) string {
	return `WITH alert_case_src AS MATERIALIZED (` + src + `),
alert_case_totals AS (
 SELECT tenant_id,case_id,MIN(project_id) AS project_id,MIN(case_category) AS case_category,
   CASE WHEN BOOL_OR(member_lane='action') THEN 'action' WHEN BOOL_OR(member_lane='watch') THEN 'watch' ELSE 'eval' END AS case_lane,
   MIN(occurred_at) AS first_seen,MAX(occurred_at) AS last_seen,MAX(created_at) AS last_detected_at,
   COUNT(DISTINCT CASE WHEN has_output_anchor THEN occurrence_key ELSE jsonb_build_array(event_id,finding_index) END)::int AS hit_count,
   COUNT(DISTINCT NULLIF(request_id,''))::int AS request_count,
   COUNT(DISTINCT NULLIF(finding_rule_name,''))::int AS rule_name_count,
   COUNT(DISTINCT NULLIF(request_id,'')) FILTER(WHERE event_action_taken IN ('block','blocked','deny','security_blocked','tool_attempt_blocked'))::int AS blocked_count,
   BOOL_AND(time_known) AS all_times_known,BOOL_AND(suppressed) AS all_suppressed,
   BOOL_AND(disposition_status<>'open') AS all_handled,
   BOOL_AND(disposition_status='false_positive') AS all_false_positive,
   BOOL_OR(occurred_at IS NULL) AS has_unknown_occurred,
   CASE WHEN MAX(case_conversation)<>'' THEN 'conversation' ELSE 'identity_target_day' END AS grouping_basis,
   BOOL_OR(dev_folded) AS has_dev_folded
 FROM alert_case_src GROUP BY tenant_id,case_id
),
alert_case_novelty AS (
 SELECT case_id,MAX(first_detected_at) AS new_evidence_at FROM (
   SELECT case_id,evidence_identity,MIN(created_at) AS first_detected_at FROM alert_case_src GROUP BY case_id,evidence_identity
 ) seen GROUP BY case_id
),
alert_case_reps AS (
 SELECT DISTINCT ON (case_id) case_id,event_id AS rep_event_id,finding_slot AS rep_finding_slot,severity
 FROM alert_case_src
 ORDER BY case_id,CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
   created_at DESC,event_id DESC,finding_index ASC NULLS LAST
)
SELECT t.tenant_id,t.case_id,t.project_id,t.case_category,t.case_lane,r.severity,
 t.first_seen,t.last_seen,t.last_detected_at,n.new_evidence_at,
 t.hit_count,t.request_count,t.rule_name_count,t.blocked_count,
 t.all_times_known,t.all_suppressed,t.all_handled,t.all_false_positive,t.has_unknown_occurred,
 t.grouping_basis,
 CASE WHEN d.status IS NOT NULL AND n.new_evidence_at<=COALESCE(d.case_seen_through,d.updated_at) THEN d.status
   WHEN d.status IS NOT NULL THEN 'open'
   WHEN t.all_false_positive THEN 'false_positive'
   WHEN t.all_handled THEN 'resolved' ELSE 'open' END AS disposition_status,
 r.rep_event_id,r.rep_finding_slot,t.has_dev_folded
FROM alert_case_totals t JOIN alert_case_novelty n USING(case_id) JOIN alert_case_reps r USING(case_id)
LEFT JOIN audit_dispositions d ON d.tenant_id=t.tenant_id AND d.subject_type='alert_case' AND d.subject_id=t.case_id`
}

// buildMaterializedAlertQuery 生成与 buildAlertOccurrenceQuery(f) 结果一致、但从物化表取案件/命中的查询。
// 调用前须确认 alertCaseMaterializable(f)。实时查询结构变了、拼接标记找不到时返回 errAlertCaseQueryShape。
func buildMaterializedAlertQuery(f AlertOccurrenceFilter) (string, []any, error) {
	tail := f
	tail.ProjectIDs, tail.ProjectID, tail.EndTime = nil, "", nil
	tail.UserID, tail.SessionID, tail.ConversationKey = "", "", ""
	tail.IncludeDevTraffic = true
	query, args := buildAlertOccurrenceQuery(tail)
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	scope := alertCaseScope(f)
	caseWhere := []string{"c.tenant_id=$1", "c.scope='" + scope + "'"}
	memberWhere := []string{"m.tenant_id=$1"}
	if scope == "customer" {
		memberWhere = append(memberWhere, "NOT m.dev_folded")
	}
	if f.ProjectIDs != nil {
		p := add(f.ProjectIDs)
		caseWhere = append(caseWhere, "c.project_id = ANY("+p+"::text[])")
		memberWhere = append(memberWhere, "m.project_id = ANY("+p+"::text[])")
	}
	if f.ProjectID != "" {
		p := add(f.ProjectID)
		caseWhere = append(caseWhere, "c.project_id = "+p)
		memberWhere = append(memberWhere, "m.project_id = "+p)
	}
	// 只作用于部分命中的筛选（与实时查询同口径：操作人、请求会话或端点会话、会话键）。带这些筛选时案件只按
	// 符合条件的命中聚合，存好的案件聚合不能用，改为对筛出的命中现场聚合。
	memberFiltered := false
	if f.UserID != "" {
		memberWhere = append(memberWhere, "m.actor_user_id = "+add(f.UserID))
		memberFiltered = true
	}
	if f.SessionID != "" {
		session := add(f.SessionID)
		memberWhere = append(memberWhere, "(m.filter_session_id = "+session+" OR m.endpoint_session_id = "+session+")")
		memberFiltered = true
	}
	if f.ConversationKey != "" {
		memberWhere = append(memberWhere, "m.conversation_key = "+add(f.ConversationKey))
		memberFiltered = true
	}
	end := ""
	if f.EndTime != nil {
		end = add(f.EndTime.UTC())
	}
	if f.Grouping != "cases" {
		// 单个案件的命中明细：只取这个案件的命中做去重排序；同证据重复检测的计数照旧按整个范围统计。
		if end != "" {
			memberWhere = append(memberWhere, "m.occurred_at < "+end)
		}
		caseID := add(f.CaseID)
		members := strings.Join(memberWhere, " AND ")
		head := "\nWITH keyed AS NOT MATERIALIZED (\n SELECT " + prefixedColumns("m", alertCaseMemberColumns) + "\n FROM alert_case_members m WHERE " + members + "\n),\n" +
			"alert_case_hits AS MATERIALIZED (\n SELECT " + prefixedColumns("m", alertCaseMemberColumns) + "\n FROM alert_case_members m WHERE " + members + " AND m.case_id = " + caseID + "\n),\n"
		rest, err := sqlFromMarker(query, "ranked AS (")
		if err != nil {
			return "", nil, err
		}
		if rest, err = replaceOnceInSQL(rest, " FROM keyed k\n),\neffective AS (", " FROM alert_case_hits k\n),\neffective AS ("); err != nil {
			return "", nil, err
		}
		return head + rest, args, nil
	}
	if f.Category != "" {
		categories := []string{}
		for _, value := range strings.Split(f.Category, ",") {
			if value = strings.TrimSpace(value); value != "" {
				categories = append(categories, canonicalAlertCategory(value))
			}
		}
		c := add(categories)
		caseWhere = append(caseWhere, "c.case_category = ANY("+c+"::text[])")
		memberWhere = append(memberWhere, "m.case_category = ANY("+c+"::text[])")
	}
	scopedMembers := append([]string{}, memberWhere...)
	stored := strings.Join(caseWhere, " AND ")
	var head strings.Builder
	switch {
	case memberFiltered:
		if end != "" {
			scopedMembers = append(scopedMembers, "m.occurred_at < "+end)
		}
		head.WriteString("\nWITH alert_case_all AS (\n" + alertCaseAggregateSQL("SELECT m.* FROM alert_case_members m WHERE "+strings.Join(scopedMembers, " AND ")) + "\n),\n")
	case end != "":
		straddling := "(c.has_unknown_occurred OR c.last_seen IS NULL OR c.last_seen >= " + end + ")"
		head.WriteString("\nWITH alert_case_stored AS (\n SELECT " + prefixedColumns("c", alertCaseColumns) + " FROM alert_cases c WHERE " + stored)
		head.WriteString(" AND NOT " + straddling + "\n),\n")
		scopedMembers = append(scopedMembers, "m.occurred_at < "+end)
		live := "SELECT m.* FROM alert_case_members m WHERE " + strings.Join(scopedMembers, " AND ") +
			" AND m.case_id IN (SELECT c.case_id FROM alert_cases c WHERE " + stored + " AND " + straddling + ")"
		head.WriteString("alert_case_live AS (\n" + alertCaseAggregateSQL(live) + "\n),\n")
		head.WriteString("alert_case_all AS (\n SELECT * FROM alert_case_stored UNION ALL SELECT " + strings.Join(alertCaseColumns, ",") + " FROM alert_case_live\n),\n")
	default:
		head.WriteString("\nWITH alert_case_stored AS (\n SELECT " + prefixedColumns("c", alertCaseColumns) + " FROM alert_cases c WHERE " + stored)
		head.WriteString("\n),\nalert_case_all AS (SELECT * FROM alert_case_stored),\n")
	}
	members := strings.Join(scopedMembers, " AND ")
	head.WriteString(`alert_case_delayed AS MATERIALIZED (
 SELECT DISTINCT m.case_id FROM alert_case_members m WHERE ` + members + `
   AND m.created_at>=now()-interval '24 hours' AND m.time_known AND m.occurred_at<now()-interval '24 hours'
),
keyed AS NOT MATERIALIZED (
 SELECT ` + prefixedColumns("m", alertCaseMemberColumns) + ` FROM alert_case_members m WHERE ` + members + `
),
case_rows AS (
 SELECT ` + prefixedColumns("m", alertCaseMemberColumns) + `,
   1::bigint AS occurrence_rank,0::bigint AS duplicate_count,1::bigint AS case_rank,
   c.first_seen,c.last_seen,c.last_detected_at,c.hit_count,c.request_count,c.blocked_count,c.rule_name_count,
   c.grouping_basis,c.case_lane,c.all_times_known,c.all_suppressed,
   (c.case_id IN (SELECT delayed.case_id FROM alert_case_delayed delayed)) AS has_historical_reinspection,c.new_evidence_at AS case_new_evidence_at,
   c.disposition_status AS case_disposition_status,
   (c.disposition_status='false_positive' OR c.all_suppressed) AS case_suppressed
 FROM alert_case_all c
 JOIN alert_case_members m ON m.tenant_id=c.tenant_id AND m.event_id=c.rep_event_id AND m.finding_slot=c.rep_finding_slot
),`)
	marker := "\nfiltered AS MATERIALIZED ("
	if f.LaneAware {
		marker = "\nlane_all AS MATERIALIZED ("
	}
	rest, err := sqlFromMarker(query, marker)
	if err != nil {
		return "", nil, err
	}
	return head.String() + rest, args, nil
}
