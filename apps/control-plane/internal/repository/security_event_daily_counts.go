package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// SecurityEventRuleDailyCount 是按「租户 × 日(UTC 归日) × 维度」聚合的当日可告警事件计数，
// 供告警桥的高频规则日聚合闸使用。维度由共享的 SecurityFindingDailyDimension
// 从主导风险选择，与告警桥保持完全相同的归因算法。
type SecurityEventRuleDailyCount struct {
	TenantID  string
	Day       string // YYYY-MM-DD（UTC 归日）
	Dimension string
	Count     int
}

// CountAlertableDaily 用单条分组 SQL 统计 [from,to) 窗口内、给定租户集合的当日
// 可告警事件数（severity 达到收件箱门槛，默认 high/critical，与 ListUnalerted 同源）。
// DB 锚定（照 anomaly scanner 先例），无内存计数器，跨重启/多实例天然一致。
func (r *SecurityEventRepository) CountAlertableDaily(ctx context.Context, tenantIDs []string, from, to time.Time) ([]SecurityEventRuleDailyCount, error) {
	if len(tenantIDs) == 0 {
		return nil, nil
	}
	// Project only attribution metadata. Repeated signatures are counted in SQL;
	// the final dimension is selected by the SAME Go function as the live bridge.
	// Evidence bodies, hashes and raw customer content never leave this query.
	query := `
 WITH facts AS (
 SELECT tenant_id, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
  jsonb_build_object('category',matched_summary->'category','findings',COALESCE((
   SELECT jsonb_agg(CASE WHEN jsonb_typeof(f)='object' THEN jsonb_strip_nulls(jsonb_build_object(
    'type',f->'type','category',f->'category','severity',f->'severity',
    'confidence',f->'confidence','rule_id',f->'rule_id','rule_name',f->'rule_name',
    'verified_fact',f->'verified_fact','counts_as_security_finding',f->'counts_as_security_finding'
   )) ELSE '{"counts_as_security_finding":false}'::jsonb END)
   FROM jsonb_array_elements(CASE WHEN jsonb_typeof(matched_summary->'findings')='array' THEN matched_summary->'findings' ELSE '[]'::jsonb END) f
  ),'[]'::jsonb)) AS attribution
 FROM security_events
 WHERE tenant_id=ANY($1) AND severity=ANY($2::text[]) AND created_at >= $3 AND created_at < $4
 )
 SELECT tenant_id,day,attribution,COUNT(*) FROM facts GROUP BY 1,2,3
 `
	rows, err := r.db.Query(ctx, query, tenantIDs, secEventInboxSeverities(), from, to)
	if err != nil {
		return nil, fmt.Errorf("count alertable security events daily: %w", err)
	}
	defer rows.Close()

	totals := map[string]SecurityEventRuleDailyCount{}
	for rows.Next() {
		var c SecurityEventRuleDailyCount
		var raw []byte
		if err := rows.Scan(&c.TenantID, &c.Day, &raw, &c.Count); err != nil {
			return nil, err
		}
		var summary map[string]any
		if err := json.Unmarshal(raw, &summary); err != nil {
			return nil, err
		}
		c.Dimension = SecurityFindingDailyDimension(summary)
		if c.Dimension == "" {
			continue
		}
		key := c.TenantID + "|" + c.Day + "|" + c.Dimension
		if existing, ok := totals[key]; ok {
			c.Count += existing.Count
		}
		totals[key] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(totals))
	for key := range totals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	counts := make([]SecurityEventRuleDailyCount, 0, len(keys))
	for _, key := range keys {
		counts = append(counts, totals[key])
	}
	return counts, nil
}
