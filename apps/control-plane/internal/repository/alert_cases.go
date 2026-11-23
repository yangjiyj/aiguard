package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

func canonicalAlertCategory(value string) string {
	switch value {
	case "email":
		return "pii_email"
	case "phone_cn":
		return "pii_phone"
	case "id_card_cn", "pii_id_card":
		return "pii_idcard"
	case "bank_card_cn", "pii_bank_card":
		return "pii_bankcard"
	}
	return value
}
func alertCaseCategorySQL() string {
	raw := "COALESCE(NULLIF(finding->>'category',''),NULLIF(finding->>'type',''),event_type,'unknown')"
	return "CASE " + raw + " WHEN 'email' THEN 'pii_email' WHEN 'phone_cn' THEN 'pii_phone' WHEN 'id_card_cn' THEN 'pii_idcard' WHEN 'pii_id_card' THEN 'pii_idcard' WHEN 'bank_card_cn' THEN 'pii_bankcard' WHEN 'pii_bank_card' THEN 'pii_bankcard' ELSE " + raw + " END"
}

var ErrStaleCaseSnapshot = errors.New("case has new evidence since the reviewed snapshot")

const alertCaseJoin = `
 LEFT JOIN LATERAL (
   SELECT r.created_at AS request_created_at,jsonb_build_object('session_id',r.session_id,'client_id',r.client_id,'user_id',r.user_id,'source_ip',r.source_ip,'proxy_target_host',r.proxy_target_host,'model_id',r.model_id,'principal',r.principal_context_json) AS data
   FROM request_logs r WHERE r.tenant_id=se.tenant_id AND r.request_id=se.request_id
   ORDER BY r.created_at,r.id LIMIT 1
 ) cm ON TRUE
 LEFT JOIN LATERAL (
   SELECT a.conversation_id FROM access_content_logs a
   WHERE a.tenant_id=se.tenant_id AND a.request_id=se.request_id AND COALESCE(a.conversation_id,'')<>''
   ORDER BY a.created_at,a.id LIMIT 1
 ) ca ON TRUE
`
const alertCaseEventFields = `
 COALESCE(cm.request_created_at,se.created_at) AS occurred_at,
 (cm.request_created_at IS NOT NULL) AS time_known,
 COALESCE(
   CASE WHEN cm.data#>>'{principal,trust_level}'='authenticated' THEN 'user:'||NULLIF(cm.data#>>'{principal,actor_user_id}','') END,
   CASE WHEN LEFT(COALESCE(se.principal_key,''),9)='upstream:' THEN se.principal_key END,
   'key:'||NULLIF(cm.data#>>'{principal,key_id}',''),
   'key:'||NULLIF(cm.data->>'client_id',''),
   NULLIF(se.principal_key,''),'user:'||NULLIF(cm.data->>'user_id',''),
   'ip:'||NULLIF(cm.data->>'source_ip',''),'request:'||COALESCE(NULLIF(se.request_id,''),se.id)) AS case_subject,
 COALESCE(NULLIF(se.conversation_key,''),NULLIF(cm.data->>'session_id',''),ca.conversation_id,'') AS case_conversation,
 COALESCE(NULLIF(cm.data->>'proxy_target_host',''),cm.data->>'model_id','') AS request_target,
`

// A case is a review container, not a claim that every member is one attack.
// Exact evidence and each request remain independently accessible. Daily buckets
// bound unlinked-session grouping; tenant/project/identity/target/source separate it.
const alertCaseKey = `
 'ac1_'||md5(jsonb_build_array(tenant_id,project_id,case_subject,case_conversation,COALESCE(NULLIF(root_target_host,''),request_target),
   CASE WHEN case_conversation='' THEN to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD') ELSE 'conversation' END,
   @canonical_case_category@,
   COALESCE(NULLIF(finding->>'stage',''),event_stage,''),
   COALESCE(NULLIF(finding->>'content_source',''),finding->>'source',''))::text)
`

// ── 处理车道 ────────────────────────────────────────────────────────────────
// 车道把"需要人看的"和"已知的噪声来源"分开显示，但不删除、不抑制任何告警：
//
//	action 需行动：默认页签；
//	watch  观察：低/中风险，或编程助手流量里的内容规则命中；
//	eval   测评流量：管理员标记为 evaluation 的凭据产生的攻击样本。
//	       升级安装器自检请求用的临时应用（编号以 project_upgrade_verify_ 开头，只有安装器能写出这样的编号）也归这里。
//
// 判定只看三类可信输入：finding 自身的类型/类别/严重度/规则类型，以及请求所用凭据在
// internal_keys.traffic_class 上的管理员标记。凭据名称、请求头、agent_type 都不参与，
// 任何人改名或伪造头都进不了测评/观察车道。
// 以下三类永远是 action，不论凭据标记：硬底线、凭据/密钥类 finding（测评自带的 canary 除外，
// 它在 evaluation 凭据下属于测评样本）、规则类型为 hard_floor 的命中。
const alertLaneKeyJoin = `
 LEFT JOIN LATERAL (
   SELECT COALESCE(to_jsonb(lane_key)->>'traffic_class','') AS traffic_class FROM internal_keys lane_key
   WHERE lane_key.tenant_id=se.tenant_id
     AND lane_key.id=COALESCE(NULLIF(cm.data#>>'{principal,key_id}',''),NULLIF(cm.data->>'client_id',''))
   LIMIT 1
 ) kc ON TRUE
`

const alertLaneMember = `CASE
   WHEN LOWER(COALESCE(finding->>'rule_type',''))='hard_floor' OR LOWER(type)='hard_floor' OR LOWER(category)='hard_floor' THEN 'action'
   WHEN project_id LIKE 'project\_upgrade\_verify\_%' THEN 'eval'
   WHEN LOWER(category) LIKE 'agent\_canary%' THEN CASE WHEN key_traffic_class='evaluation' THEN 'eval' ELSE 'action' END
   WHEN LOWER(type)='secret' THEN 'action'
   WHEN key_traffic_class='evaluation' THEN 'eval'
   WHEN key_traffic_class='coding' AND LOWER(type) IN ('catalog_policy','semantic_attack','prompt_injection','content_safety','pii','custom','code_config') THEN 'watch'
   WHEN LOWER(severity) IN ('low','medium') THEN 'watch'
   ELSE 'action' END`

const alertCaseLaneRollup = `CASE WHEN BOOL_OR(member_lane='action') THEN 'action' WHEN BOOL_OR(member_lane='watch') THEN 'watch' ELSE 'eval' END`

func alertLaneSQL(lane string) string {
	switch lane {
	case "action", "watch", "eval":
		return "case_lane='" + lane + "'"
	case "":
		return "TRUE"
	}
	// 未知车道不可能走到这里（接口层已拒绝），仓储层仍保持闭合：什么都不显示。
	return "FALSE"
}

// alertCaseRollup 是实时查询的案件聚合。改这里必须同步改物化聚合 alertCaseAggregateSQL（alert_case_read.go），
// 两份逐项对应、由等价测试核对；两份都算进物化口径指纹（alertCaseLogicInputs），任一边改了物化结果都会重建。
const alertCaseRollup = `
case_evidence_seen AS MATERIALIZED (
 SELECT case_id,evidence_identity,MIN(created_at) AS first_detected_at FROM effective GROUP BY case_id,evidence_identity
),
case_novelty AS MATERIALIZED (
 SELECT case_id,MAX(first_detected_at) AS last_novel_detected_at FROM case_evidence_seen GROUP BY case_id
),
case_totals AS MATERIALIZED (
 SELECT case_id,MIN(occurred_at) AS first_seen,MAX(occurred_at) AS last_seen,
   MAX(created_at) AS last_detected_at,COUNT(DISTINCT CASE WHEN has_output_anchor THEN occurrence_key ELSE jsonb_build_array(event_id,finding_index) END)::int AS hit_count,
   COUNT(DISTINCT NULLIF(request_id,''))::int AS request_count,
   COUNT(DISTINCT NULLIF(finding_rule_name,''))::int AS rule_name_count,
   COUNT(DISTINCT NULLIF(request_id,'')) FILTER(WHERE event_action_taken IN ('block','blocked','deny','security_blocked','tool_attempt_blocked'))::int AS blocked_count,
   BOOL_OR(time_known AND occurred_at<now()-interval '24 hours' AND created_at>=now()-interval '24 hours') AS has_historical_reinspection,
   BOOL_AND(time_known) AS all_times_known,BOOL_AND(suppressed) AS all_suppressed,
   BOOL_AND(disposition_status<>'open') AS all_handled,
   BOOL_AND(disposition_status='false_positive') AS all_false_positive,
   CASE WHEN MAX(case_conversation)<>'' THEN 'conversation' ELSE 'identity_target_day' END AS grouping_basis
 FROM effective GROUP BY case_id
),
case_representatives AS (
 SELECT e.*,ROW_NUMBER() OVER(PARTITION BY case_id ORDER BY
   CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
   created_at DESC,event_id DESC,finding_index ASC NULLS LAST) AS case_rank
 FROM effective e
),
case_review AS (
 SELECT r.*,c.first_seen,c.last_seen,c.last_detected_at,c.hit_count,c.request_count,c.blocked_count,c.rule_name_count,
   c.grouping_basis,c.all_times_known,c.all_suppressed,c.has_historical_reinspection,cn.last_novel_detected_at AS case_new_evidence_at,
   CASE WHEN d.status IS NOT NULL AND cn.last_novel_detected_at<=COALESCE(d.case_seen_through,d.updated_at)
       THEN d.status
     WHEN d.status IS NOT NULL THEN 'open'
     WHEN c.all_false_positive THEN 'false_positive'
     WHEN c.all_handled THEN 'resolved' ELSE 'open' END AS case_disposition_status
 FROM case_representatives r JOIN case_totals c USING(case_id) JOIN case_novelty cn USING(case_id)
 LEFT JOIN audit_dispositions d ON d.tenant_id=r.tenant_id AND d.subject_type='alert_case' AND d.subject_id=r.case_id
 WHERE r.case_rank=1
),
case_rows AS (
 SELECT *, (case_disposition_status='false_positive' OR all_suppressed) AS case_suppressed
 FROM case_review
),
filtered AS MATERIALIZED (
 SELECT * FROM case_rows WHERE @row_where@
)`

func alertCaseTemplates(f AlertOccurrenceFilter) (cte, projection, fields, join, key string) {
	cte, projection = alertOccurrenceCTE, alertOccurrenceProjection
	if f.Grouping == "cases" || f.EventID != "" {
		cte = strings.Replace(cte, "SELECT * FROM ranked WHERE occurrence_rank=1", "SELECT * FROM ranked", 1)
	}
	if f.CaseID != "" && f.EventID == "" {
		cte = strings.Replace(cte, "SELECT * FROM ranked WHERE occurrence_rank=1", "SELECT * FROM ranked WHERE NOT has_output_anchor OR occurrence_rank=1", 1)
	}
	fields = "se.created_at AS occurred_at,FALSE AS time_known,''::text AS case_conversation,"
	key = "''::text"
	if f.Grouping != "cases" && f.CaseID == "" {
		return
	}
	fields, join, key = alertCaseEventFields, alertCaseJoin, strings.ReplaceAll(alertCaseKey, "@canonical_case_category@", alertCaseCategorySQL())
	laneAware := f.LaneAware && f.Grouping == "cases"
	if laneAware {
		fields += "COALESCE(kc.traffic_class,'') AS key_traffic_class,\n"
		join += alertLaneKeyJoin
		cte = strings.Replace(cte, "   alert_group_id,conversation_key,disposition_status,\n   finding_index,", "   alert_group_id,conversation_key,disposition_status,\n   "+alertLaneMember+" AS member_lane,\n   finding_index,", 1)
	}
	if f.Grouping != "cases" {
		return
	}
	// Cases retain every finding. Occurrence deduplication is only needed for
	// the hit view; page-local stats below preserve duplicate counts/rule IDs.
	start := strings.Index(cte, "ranked AS (")
	end := strings.Index(cte[start:], "effective AS (") + start
	cte = cte[:start] + "ranked AS (SELECT k.*,1::bigint AS occurrence_rank,0::bigint AS duplicate_count FROM keyed k),\n" + cte[end:]
	rollup := alertCaseRollup
	if laneAware {
		rollup = strings.Replace(rollup, "AS grouping_basis\n FROM effective GROUP BY case_id", "AS grouping_basis,\n   "+alertCaseLaneRollup+" AS case_lane\n FROM effective GROUP BY case_id", 1)
		rollup = strings.Replace(rollup, "c.grouping_basis,c.all_times_known", "c.grouping_basis,c.case_lane,c.all_times_known", 1)
		// 每个车道各自保留最近 N 个：测评/观察样本不会把需行动告警挤出窗口。
		window := "TRUE"
		if f.RecentLimit > 0 && f.CaseID == "" && f.EventID == "" {
			limit := f.RecentLimit
			if limit > 100 {
				limit = 100
			}
			window = fmt.Sprintf("lane_rank<=%d", limit)
		}
		// lane_all 是范围内全部案件（页签数字的真实总数，不受窗口截断）；
		// lane_scope 才是每车道最近 N 个的列表窗口。
		rollup = strings.Replace(rollup, "filtered AS MATERIALIZED (\n SELECT * FROM case_rows WHERE @row_where@\n)", `lane_all AS MATERIALIZED (
 SELECT c.*,ROW_NUMBER() OVER(PARTITION BY case_lane ORDER BY last_seen DESC,event_id DESC,finding_index ASC NULLS LAST) AS lane_rank
 FROM case_rows c WHERE @row_where@
),
lane_scope AS MATERIALIZED (
 SELECT * FROM lane_all WHERE `+window+`
),
filtered AS MATERIALIZED (
 SELECT * FROM lane_scope WHERE `+alertLaneSQL(f.Lane)+`
)`, 1)
	}
	cte = strings.Replace(cte, "filtered AS MATERIALIZED (\n SELECT * FROM effective WHERE @row_where@\n)", rollup, 1)
	if f.RecentLimit > 0 && f.CaseID == "" && f.EventID == "" && !laneAware {
		// Apply the cap after tenant/project/user/category filters and complete
		// case aggregation. Counts and all disposition tabs share this set;
		// pagination must never truncate a case's evidence members.
		limit := f.RecentLimit
		if limit > 100 {
			limit = 100
		}
		cte = strings.Replace(cte, "SELECT * FROM case_rows WHERE @row_where@", fmt.Sprintf("SELECT * FROM case_rows WHERE @row_where@ ORDER BY last_seen DESC,event_id DESC,finding_index ASC NULLS LAST LIMIT %d", limit), 1)
	}
	cte = strings.Replace(cte, "SELECT * FROM visible ORDER BY created_at DESC", "SELECT * FROM visible ORDER BY last_seen DESC", 1)
	projection = strings.Replace(projection, "SELECT p.created_at,p.event_id,p.finding_index,", "SELECT p.created_at,p.last_seen AS sort_time,p.event_id,p.finding_index,", 1)
	projection = strings.Replace(projection, "jsonb_agg(payload ORDER BY created_at DESC", "jsonb_agg(payload ORDER BY sort_time DESC", 1)
	projection = strings.Replace(projection, "'time_known',p.time_known", "'time_known',p.all_times_known", 1)
	cte = strings.Replace(cte, "($4::boolean OR NOT suppressed)", "($4::boolean OR NOT case_suppressed)", 1)
	projection = strings.Replace(projection, "'category',p.category", "'category',p.case_category", 1)
	if laneAware {
		projection = strings.Replace(projection, "'category',p.case_category", "'category',p.case_category,'lane',p.case_lane", 1)
	}
	// Presentation status is case-local. Never mutate sibling findings/events.
	projection = strings.ReplaceAll(projection, "'disposition_status',p.disposition_status", "'disposition_status',p.case_disposition_status")
	projection = strings.ReplaceAll(projection, "'suppressed',p.suppressed", "'suppressed',p.case_suppressed")
	projection = strings.Replace(projection, "'case_id',p.case_id,", `
   'first_seen',p.first_seen,'last_seen',p.last_seen,'last_detected_at',p.last_detected_at,
   'hit_count',p.hit_count,'request_count',p.request_count,'blocked_count',p.blocked_count,
   'rule_name_count',p.rule_name_count,
   'grouping_basis',p.grouping_basis,
   'case_id',p.case_id,`, 1)
	// Only counters use the rollup clock. The representative event keeps its
	// original detection time and grade for exact evidence lookups.
	at := strings.Index(projection, "(SELECT jsonb_build_object(")
	head, stats := projection[:at], projection[at:]
	stats = strings.ReplaceAll(stats, "disposition_status", "case_disposition_status")
	stats = strings.ReplaceAll(stats, "WHERE suppressed", "WHERE case_suppressed")
	stats = strings.ReplaceAll(stats, "NOT suppressed", "NOT case_suppressed")
	stats = strings.ReplaceAll(stats, "created_at>=", "first_seen>=")
	stats = strings.ReplaceAll(stats, "created_at<", "first_seen<")
	stats = strings.ReplaceAll(stats, "WHERE first_seen", "WHERE all_times_known AND first_seen")
	stats = strings.Replace(stats, "'handled',", `
   'raw_hits',COALESCE(SUM(hit_count),0),
   'delayed_24h',COUNT(*) FILTER(WHERE has_historical_reinspection),
   'unknown_time',COUNT(*) FILTER(WHERE NOT all_times_known),
   'handled',`, 1)
	stats = strings.ReplaceAll(stats, "AND event_action_taken IN ('block','blocked','deny','security_blocked','tool_attempt_blocked')", "AND blocked_count>0")
	projection = head + stats
	if laneAware {
		// 车道页签计数：同一范围（含处置页签）内按车道分别统计，不随选中的车道变化。
		laneCount := func(lane string) string {
			return "(SELECT COUNT(*) FROM lane_all WHERE case_lane='" + lane + "' AND ($4::boolean OR NOT case_suppressed) AND (@status_where@))"
		}
		projection = strings.Replace(projection, "AND severity='low')\n ) FROM filtered)",
			"AND severity='low'),\n   'lane_action',"+laneCount("action")+",'lane_watch',"+laneCount("watch")+",'lane_eval',"+laneCount("eval")+"\n ) FROM filtered)", 1)
	}
	return
}

// Reuse the exact tenant/project scoped projection for authorization. A guessed
// case hash cannot authorize a different tenant or an out-of-scope project.
func authorizeAlertCase(ctx context.Context, db auditDispositionQueryRower, tenant, id string, projects []string) (bool, error) {
	return authorizeAlertCaseSnapshot(ctx, db, tenant, id, projects, nil)
}
func authorizeAlertCaseSnapshot(ctx context.Context, db auditDispositionQueryRower, tenant, id string, projects []string, seen *time.Time) (bool, error) {
	return authorizeAlertCaseSnapshotWith(ctx, db, tenant, id, projects, seen, false)
}

// authorizeAlertCaseSnapshotWith 的 materialized 由调用方在事务外用 prepareAlertCaseReads 决定：可串行化的
// 处置事务里只读物化结果，不读也不消化待重算队列，避免并发处置之间互相判为串行化冲突。
func authorizeAlertCaseSnapshotWith(ctx context.Context, db auditDispositionQueryRower, tenant, id string, projects []string, seen *time.Time, materialized bool) (bool, error) {
	if len(id) != 36 || !strings.HasPrefix(id, "ac1_") {
		return false, nil
	}
	f := AlertOccurrenceFilter{TenantID: tenant, ProjectIDs: projects, Grouping: "cases", CaseID: id, IncludeSuppressed: true, Limit: 1}
	q, args := buildAlertOccurrenceQuery(f)
	if materialized {
		if mq, margs, err := buildMaterializedAlertQuery(f); err == nil {
			q, args = mq, margs
		} else {
			// 物化读法拼不出来就用实时查询授权：可串行化事务里实时查询同样正确。
			logAlertCaseShapeError(err)
		}
	}
	at := strings.Index(q, ", decorated AS (")
	if at < 0 {
		return false, fmt.Errorf("case authorization query unavailable")
	}
	q = q[:at] + " SELECT EXISTS(SELECT 1 FROM visible) AND ($2::boolean OR NOT $2::boolean) AND ($3::boolean OR NOT $3::boolean),(SELECT MAX(case_new_evidence_at) FROM visible)"
	var allowed bool
	var newest *time.Time
	if err := db.QueryRow(ctx, q, args...).Scan(&allowed, &newest); err != nil {
		return false, err
	}
	if allowed && seen != nil && newest != nil && newest.After(*seen) {
		return false, ErrStaleCaseSnapshot
	}
	return allowed, nil
}
