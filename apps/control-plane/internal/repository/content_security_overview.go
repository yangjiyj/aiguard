package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ContentSecurityOverviewBucket 单个维度的会话计数（key 一律为小写英文枚举）。
type ContentSecurityOverviewBucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// ContentSecurityOverview 安全运营总览的聚合结果。
//
// 口径与内容审计页（/audit/content?alert_only=true，也就是「安全告警」页）完全一致：
// 先按 (session_id, user_id) 归并出会话，再用会话串 conversation_key 去重，
// 得到「窗口内确实产生过可处置告警的会话串」数；各维度分布统计的是
// 「含该维度告警的会话串数」，因此一个会话串可以同时落入多个维度（与前端逐维度计数同义）。
// 这里刻意不返回「处置状态」维度。产品里的人工作业状态（audit_dispositions / alert_groups.status）
// 只有内容留证页与工具审计页能写，安全告警页本身没有处置入口；在总览页展示它等于把「告警总数」
// 换个名字（实测库中 audit_dispositions 0 行、alert_groups.status 100% 为 open），
// 还会让客户以为存在一个并不存在的闭环工单。要处置请在内容留证 / 工具审计页完成。
type ContentSecurityOverview struct {
	Total int `json:"total"`
	// Subjects 是窗口内产生过可处置告警的主体数（去重后的 Key 归属）。
	Subjects int `json:"subjects"`
	// CategoryCount 是命中风险类型的精确去重数。
	// 必须单独算：categories 列表带 LIMIT 24，实测在真实数据上正好被截到 24 条，
	// 直接拿 len(categories) 当"命中风险类型数"会把下限当总数（又是一个假数字）。
	// 剔除规则与前端 isDisplayableRiskCategory 一致：agent_detect / agent_* 属于智能体行为类，不计入。
	CategoryCount int                             `json:"category_count"`
	Severity      []ContentSecurityOverviewBucket `json:"severity"`
	Categories    []ContentSecurityOverviewBucket `json:"categories"`
}

// contentAlertFindingPresentCondition 复刻会话查询里 se_hit 的第二段条件：
// 只有「findings 不是数组、或空数组、或含至少一条计为安全发现的 finding」的事件才参与告警判定。
// 与 buildFastContentSessionListQueryWithAlertOnly / buildContentSessionListQueryScopedWithAlertOnly
// 里的对应片段保持逐字一致。
func contentAlertFindingPresentCondition(alias string) string {
	findings := alias + ".matched_summary->'findings'"
	return fmt.Sprintf(`(
		jsonb_typeof(%s) IS DISTINCT FROM 'array'
		OR jsonb_array_length(%s) = 0
		OR EXISTS (
			SELECT 1
			FROM jsonb_array_elements(%s) finding
			WHERE COALESCE(finding->>'counts_as_security_finding', 'true') <> 'false'
		)
	)`, findings, findings, findings)
}

// buildContentSecurityOverviewQuery 生成一条单次执行的聚合查询，返回一行 JSON：
// { total, subjects, category_count, severity[], categories[] }。
//
// 注意这里不查 audit_dispositions / alert_groups：那两个表只被人工作业写入，
// 而人工作业的入口在内容留证页与工具审计页，本页既不展示也无法闭环（见 ContentSecurityOverview 注释）。
//
// 与会话列表查询的区别（也是性能来源）：
//  1. 只取统计必需的列，不拉 token / 消息数 / 用户 / 密钥 / 供应商 / 模型等展示字段，
//     也不做 page_content、page_group_totals 这些为行渲染服务的聚合。
//  2. first_user（会话串回退键）改成「只对 client_session_id 为空的会话做索引点查」，
//     而不是对整张 content_logs 做一次全表 DISTINCT ON。
//  3. 事件明细只在「已确认计入的会话」上回捞，不再对窗口内全部请求展开。
func buildContentSecurityOverviewQuery(includeDev ...bool) string {
	findingCondition := contentAlertFindingPresentCondition("se")
	if len(includeDev) == 0 || !includeDev[0] {
		findingCondition += " AND NOT (" + developmentFoldedEventExpr("se") + ")"
	}

	return fmt.Sprintf(`
WITH session_request_stats AS (
	SELECT
		cl.session_id,
		cl.user_id,
		cl.request_id,
		NULLIF(MAX(rl.session_id), '') as client_session_id,
		MIN(cl.created_at) as start_time,
		MAX(cl.created_at) as end_time,
		COUNT(*) as message_count,
		COALESCE(NULLIF(MAX(rl.request_id), ''), cl.request_id) as request_key
	FROM content_logs cl
	LEFT JOIN request_logs rl ON rl.id = cl.request_id
	WHERE cl.tenant_id = $1 AND cl.created_at >= $2 AND cl.created_at < $3 AND cl.session_id IS NOT NULL
	GROUP BY cl.session_id, cl.user_id, cl.request_id
),
raw_sessions AS MATERIALIZED (
	SELECT
		srs.session_id,
		srs.user_id,
		NULLIF(MAX(srs.client_session_id), '') as client_session_id,
		MIN(srs.start_time) as start_time,
		MAX(srs.end_time) as end_time,
		SUM(srs.message_count) as message_count,
		bool_or(se_hit.hit) as has_risk
	FROM session_request_stats srs
	LEFT JOIN LATERAL (
		SELECT TRUE as hit
		FROM security_events se
		WHERE se.tenant_id = $1 AND se.request_id = srs.request_key
		  AND %s
		  AND %s
		LIMIT 1
	) se_hit ON TRUE
	GROUP BY srs.session_id, srs.user_id
),
first_user AS (
	SELECT needs.session_id, fu.content as first_user_content
	FROM (
		SELECT DISTINCT session_id FROM raw_sessions WHERE client_session_id IS NULL
	) needs
	LEFT JOIN LATERAL (
		SELECT cl.content
		FROM content_logs cl
		WHERE cl.tenant_id = $1
		  AND cl.session_id = needs.session_id
		  AND cl.role = 'user'
		  AND cl.content !~* '^The user stepped away and is coming back'
		  AND cl.content !~* '^Recap in under [0-9]+ words'
		  AND cl.content !~* '^<system-reminder>'
		ORDER BY cl.created_at ASC
		LIMIT 1
	) fu ON TRUE
),
grouped_sessions AS (
	SELECT
		rs.*,
		CASE
			WHEN rs.client_session_id IS NOT NULL THEN 'client:' || rs.client_session_id
			WHEN fu.first_user_content IS NOT NULL THEN 'fallback:' || md5(fu.first_user_content) || ':' || date_trunc('day', rs.start_time)::text
			ELSE 'request:' || rs.session_id
		END as conversation_key
	FROM raw_sessions rs
	LEFT JOIN first_user fu ON fu.session_id = rs.session_id
),
ranked_sessions AS MATERIALIZED (
	SELECT
		*,
		ROW_NUMBER() OVER (
			PARTITION BY COALESCE(user_id, ''), conversation_key
			ORDER BY end_time DESC, message_count DESC, session_id DESC
		) as row_num
	FROM grouped_sessions
	WHERE has_risk
),
counted_sessions AS MATERIALIZED (
	SELECT session_id, COALESCE(user_id, '') as user_id, conversation_key
	FROM ranked_sessions
	WHERE row_num = 1
),
alert_events AS MATERIALIZED (
	SELECT DISTINCT
		srs.session_id,
		se.id as event_id,
		LOWER(COALESCE(se.severity, '')) as severity,
		se.event_type,
		se.matched_summary->>'category' as summary_category,
		se.rule_id,
		se.matched_summary->'findings' as findings
	FROM session_request_stats srs
	JOIN counted_sessions cs ON cs.session_id = srs.session_id
	JOIN security_events se
	  ON se.tenant_id = $1 AND se.request_id = srs.request_key
	 AND se.alert_group_id IS NOT NULL
	 AND NOT (
		LOWER(TRIM(COALESCE(se.action_taken, ''))) IN ('audit', 'security_audit', 'security_audit_only')
		AND jsonb_typeof(se.matched_summary->'findings') = 'array'
		AND jsonb_array_length(se.matched_summary->'findings') > 0
		AND NOT EXISTS (
			SELECT 1
			FROM jsonb_array_elements(se.matched_summary->'findings') agent_finding
			WHERE LOWER(TRIM(COALESCE(agent_finding->>'rule_type', ''))) <> 'agent_detect'
			   OR LEFT(LOWER(TRIM(COALESCE(agent_finding->>'category', ''))), 6) <> 'agent_'
			   OR LEFT(LOWER(TRIM(COALESCE(agent_finding->>'category', ''))), 12) = 'agent_canary'
		)
	 )
	 AND %s
),
event_category_keys AS MATERIALIZED (
	SELECT DISTINCT ae.session_id, ae.event_id, k.key
	FROM alert_events ae
	LEFT JOIN rules r ON r.id = ae.rule_id
	CROSS JOIN LATERAL (
		SELECT LOWER(COALESCE(ae.event_type, '')) as key
		UNION ALL SELECT LOWER(COALESCE(ae.summary_category, ''))
		UNION ALL SELECT LOWER(COALESCE(r.rule_type, ''))
		UNION ALL SELECT LOWER(COALESCE(NULLIF(f->>'category', ''), f->>'type', ''))
			FROM jsonb_array_elements(
				CASE WHEN jsonb_typeof(ae.findings) = 'array' THEN ae.findings ELSE '[]'::jsonb END
			) f
			WHERE COALESCE(f->>'counts_as_security_finding', 'true') <> 'false'
	) k
	WHERE COALESCE(k.key, '') <> ''
)
SELECT jsonb_build_object(
	'total', (SELECT COUNT(*) FROM counted_sessions),
	'subjects', (SELECT COUNT(DISTINCT cs.user_id) FROM counted_sessions cs WHERE cs.user_id <> ''),
	'category_count', (
		SELECT COUNT(DISTINCT eck.key)
		FROM counted_sessions cs
		JOIN event_category_keys eck ON eck.session_id = cs.session_id
		-- 与前端 isDisplayableRiskCategory 同规则：智能体行为类不计入风险类型数。
		WHERE LEFT(eck.key, 6) <> 'agent_'
	),
	'severity', COALESCE((
		SELECT jsonb_agg(jsonb_build_object('key', severity, 'count', cnt) ORDER BY cnt DESC, severity ASC)
		FROM (
			SELECT ae.severity, COUNT(DISTINCT (cs.user_id, cs.conversation_key)) as cnt
			FROM counted_sessions cs
			JOIN alert_events ae ON ae.session_id = cs.session_id
			WHERE ae.severity <> ''
			GROUP BY ae.severity
		) severity_rows
	), '[]'::jsonb),
	'categories', COALESCE((
		SELECT jsonb_agg(jsonb_build_object('key', key, 'count', cnt) ORDER BY cnt DESC, key ASC)
		FROM (
			SELECT eck.key, COUNT(DISTINCT (cs.user_id, cs.conversation_key)) as cnt
			FROM counted_sessions cs
			JOIN event_category_keys eck ON eck.session_id = cs.session_id
			GROUP BY eck.key
			ORDER BY cnt DESC, eck.key ASC
			LIMIT 24
		) category_rows
	), '[]'::jsonb)
)`,
		contentActionableAlertCondition("se"),
		findingCondition,
		findingCondition,
	)
}

// GetContentSecurityOverview 一次查询算出安全运营总览所需的全部数字。
//
// 只使用窗口、租户与环境范围；其余维度筛选（用户/项目/关键词）不在本端点范围内——
// 调用方需保证已做角色校验，避免越权读取其他范围的内容证据。
//
// 查询本身是一次大 CTE 聚合，估算成本远超 jit_above_cost，Postgres 会为它编译近 300 个
// JIT 函数（实测 7 天窗口 2.7s 中约 2.7s 纯属编译开销）。这里在事务内 SET LOCAL jit = off，
// 只影响这一条查询；实测 7 天 4.3s → 2.2s，30 天 6.5s → 4.4s，结果不变。
func (r *ContentLogRepository) GetContentSecurityOverview(
	ctx context.Context,
	filter ContentSessionListFilter,
) (*ContentSecurityOverview, error) {
	// 复用会话列表查询同一套环境范围改写，保证与内容审计页口径一致。
	// 该改写函数把环境范围列表写成 $6，本查询没有 limit/offset，改挂到 $4，
	// 否则 Postgres 无法推断 $4/$5 的类型。
	query := strings.ReplaceAll(
		scopeContentSessionListQuery(buildContentSecurityOverviewQuery(filter.IncludeDevTraffic), filter.EnvironmentScope),
		"$6", "$4",
	)
	args := []interface{}{filter.TenantID, filter.StartTime, filter.EndTime}
	if strings.TrimSpace(filter.EnvironmentScope) != "" {
		args = append(args, EnvironmentScopesForRead(filter.EnvironmentScope))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("content security overview begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL jit = off"); err != nil {
		return nil, fmt.Errorf("content security overview jit: %w", err)
	}

	var raw []byte
	if err := tx.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
		return nil, fmt.Errorf("content security overview: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("content security overview commit: %w", err)
	}

	overview := &ContentSecurityOverview{}
	if err := json.Unmarshal(raw, overview); err != nil {
		return nil, fmt.Errorf("content security overview decode: %w", err)
	}
	if overview.Severity == nil {
		overview.Severity = []ContentSecurityOverviewBucket{}
	}
	if overview.Categories == nil {
		overview.Categories = []ContentSecurityOverviewBucket{}
	}
	return overview, nil
}
