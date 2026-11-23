package repository

import (
	"context"
	"fmt"
)

// Only trusted persisted deployment scopes participate. Agent names and request
// headers cannot opt a group out. Mixed customer/development groups stay visible.
func developmentAlertGroupFoldExpr(alias string) string {
	return fmt.Sprintf(`(NOT COALESCE((to_jsonb(%[1]s)->>'is_canary')::boolean,false)
 AND (LEFT(COALESCE(to_jsonb(%[1]s)->>'class_key',''),9)='semantic_' OR to_jsonb(%[1]s)->>'alert_type'='runtime_fault')
 AND EXISTS(SELECT 1 FROM request_logs ds WHERE ds.tenant_id=%[1]s.tenant_id AND ds.request_id=to_jsonb(%[1]s)->>'request_id' AND to_jsonb(ds)->>'environment_scope' IN ('codex','claude'))
 AND NOT EXISTS(SELECT 1 FROM request_logs ds WHERE ds.tenant_id=%[1]s.tenant_id AND ds.request_id=to_jsonb(%[1]s)->>'request_id' AND COALESCE(to_jsonb(ds)->>'environment_scope','') NOT IN ('codex','claude'))
 AND NOT EXISTS(SELECT 1 FROM security_events de WHERE de.tenant_id=%[1]s.tenant_id AND de.alert_group_id=%[1]s.id AND (
   NOT EXISTS(SELECT 1 FROM request_logs dr WHERE dr.tenant_id=de.tenant_id AND dr.request_id=de.request_id AND to_jsonb(dr)->>'environment_scope' IN ('codex','claude'))
   OR EXISTS(SELECT 1 FROM request_logs dr WHERE dr.tenant_id=de.tenant_id AND dr.request_id=de.request_id AND COALESCE(to_jsonb(dr)->>'environment_scope','') NOT IN ('codex','claude'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(de.matched_summary->'findings')='array' THEN de.matched_summary->'findings' ELSE '[]'::jsonb END) f
     WHERE COALESCE(f->>'counts_as_security_finding','true')<>'false' AND COALESCE(f->>'type','') NOT IN ('semantic_attack','semantic_telemetry','runtime_fault','system','runtime'))
 )))`, alias)
}

func developmentFoldedEventExpr(alias string) string {
	return fmt.Sprintf(`EXISTS(SELECT 1 FROM alert_groups dev_group WHERE dev_group.tenant_id=%[1]s.tenant_id AND dev_group.id=%[1]s.alert_group_id AND %[2]s)`, alias, developmentAlertGroupFoldExpr("dev_group"))
}

// countFoldedDevelopmentGroups 统计范围内被折叠的开发作用域告警组数。materialized 为真时（本次读已确认物化
// 结果是新的）直接用 alert_case_groups 里维护好的折叠标记，再看组里有没有范围内的事件；与逐事件判断
// （countFoldedDevelopmentGroupsByEvent）结果相同，但不再对租户全部事件逐条求折叠条件。
// 按用户、会话筛选时同样关联请求记录，只对折叠组里的事件求筛选条件。
func (r *AlertOccurrenceRepository) countFoldedDevelopmentGroups(ctx context.Context, f AlertOccurrenceFilter, materialized bool) (int, error) {
	if !materialized {
		return r.countFoldedDevelopmentGroupsByEvent(ctx, f)
	}
	f.IncludeDevTraffic = true
	where, args := alertOccurrenceEventScope(f, []any{f.TenantID})
	query := `SELECT COUNT(*) FROM alert_case_groups dev_group WHERE dev_group.tenant_id=$1 AND dev_group.folded
 AND EXISTS(SELECT 1 FROM security_events se ` + operationalScopeJoin(f) + ` WHERE se.tenant_id=dev_group.tenant_id AND se.alert_group_id=dev_group.group_id AND ` + where + `)`
	var n int
	err := r.queryAlertRead(ctx, query, args, &n)
	return n, err
}

func (r *AlertOccurrenceRepository) countFoldedDevelopmentGroupsByEvent(ctx context.Context, f AlertOccurrenceFilter) (int, error) {
	f.IncludeDevTraffic = true
	where, args := alertOccurrenceEventScope(f, []any{f.TenantID})
	query := "SELECT COUNT(DISTINCT se.alert_group_id) FROM security_events se " + operationalScopeJoin(f) + " WHERE " + where + " AND " + developmentFoldedEventExpr("se")
	var n int
	err := r.queryAlertRead(ctx, query, args, &n)
	return n, err
}
