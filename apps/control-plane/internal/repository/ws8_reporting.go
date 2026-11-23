package repository

// W8：统计口径、审计查询与导出所需的读查询。口径定义见
// docs/design/ws8-metrics-definitions.md。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// DefaultReportTimezone 是租户未配置时区时的统计时区。
const DefaultReportTimezone = "Asia/Shanghai"

// ReportLocation 解析 IANA 时区名，非法或空值回退到 Asia/Shanghai。
func ReportLocation(name string) (*time.Location, string) {
	name = strings.TrimSpace(name)
	if name != "" && !strings.EqualFold(name, "local") {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc, name
		}
	}
	loc, err := time.LoadLocation(DefaultReportTimezone)
	if err != nil {
		return time.FixedZone("CST", 8*3600), DefaultReportTimezone
	}
	return loc, DefaultReportTimezone
}

// TenantReportTimezone 读取租户统计时区（tenants.config_json->>'timezone'）。
func (r *StatsRepository) TenantReportTimezone(ctx context.Context, tenantID string) (*time.Location, string) {
	var raw string
	err := r.db.QueryRow(ctx, `SELECT COALESCE(config_json->>'timezone', '') FROM tenants WHERE id = $1`, tenantID).Scan(&raw)
	if err != nil {
		return ReportLocation("")
	}
	return ReportLocation(raw)
}

// EarliestUsageBucket 返回可见范围内最早的 rollup 桶；无数据时 ok=false。
func (r *StatsRepository) EarliestUsageBucket(ctx context.Context, scope UsageScope) (time.Time, bool, error) {
	where, args := statsScopeWhereRollup(scope)
	var earliest *time.Time
	if err := r.db.QueryRow(ctx, fmt.Sprintf(`SELECT MIN(rl.bucket_start) FROM usage_rollup_hourly rl WHERE %s`, where), args...).Scan(&earliest); err != nil {
		return time.Time{}, false, fmt.Errorf("earliest usage bucket: %w", err)
	}
	if earliest == nil {
		return time.Time{}, false, nil
	}
	return *earliest, true, nil
}

// UserUsageTotals 是用户排行占比的分母：同一窗口、同一可见范围内已归属用户的合计。
type UserUsageTotals struct {
	TotalTokens   int64 `json:"total_tokens"`
	TotalRequests int64 `json:"total_requests"`
}

// GetUserUsageTotalsScopedBetween 与 GetUser*RankingScopedBetween 同 WHERE，保证分子分母同口径。
func (r *StatsRepository) GetUserUsageTotalsScopedBetween(ctx context.Context, scope UsageScope, start, end time.Time) (UserUsageTotals, error) {
	where, args := usageScopeWhereRollup(scope, start, end)
	var totals UserUsageTotals
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		SELECT COALESCE(SUM(rl.input_tokens + rl.output_tokens), 0), COALESCE(SUM(rl.request_count), 0)
		FROM usage_rollup_hourly rl
		WHERE %s AND rl.user_id != ''`, where), args...).Scan(&totals.TotalTokens, &totals.TotalRequests)
	if err != nil {
		return UserUsageTotals{}, fmt.Errorf("user usage totals: %w", err)
	}
	return totals, nil
}

// GetUserUsageTotalsScoped 是全历史版本。
func (r *StatsRepository) GetUserUsageTotalsScoped(ctx context.Context, scope UsageScope) (UserUsageTotals, error) {
	start, end := allStatsScopeBounds()
	return r.GetUserUsageTotalsScopedBetween(ctx, scope, start, end)
}

// ---- 操作审计 ----

// AuditOperationFilter 是操作审计列表与导出的筛选条件。
type AuditOperationFilter struct {
	// TenantID 为空表示不限租户（仅平台管理员）。
	TenantID   string
	UserID     string
	ActionType string
	TargetType string
	From       time.Time
	To         time.Time
	Limit      int
	Offset     int
}

// AuditOperationRow 额外带出操作人用户名，导出时不必再逐条查。
type AuditOperationRow struct {
	AuditOperation
	Username string
}

func buildAuditOperationWhere(f AuditOperationFilter) (string, []any) {
	where := []string{"TRUE"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.TenantID != "" {
		// 迁移 137 回填了 tenant_id，但 CreateAuditOperation 不写该列，新行只能靠操作人归属。
		add("(ao.tenant_id = $%[1]d OR (ao.tenant_id IS NULL AND u.tenant_id = $%[1]d))", f.TenantID)
	}
	if f.UserID != "" {
		add("ao.user_id = $%d", f.UserID)
	}
	if f.ActionType != "" {
		add("ao.action_type = $%d", f.ActionType)
	}
	if f.TargetType != "" {
		add("ao.target_type = $%d", f.TargetType)
	}
	if !f.From.IsZero() {
		add("ao.created_at >= $%d", f.From)
	}
	if !f.To.IsZero() {
		add("ao.created_at < $%d", f.To)
	}
	return strings.Join(where, " AND "), args
}

// ListAuditOperationsFiltered 按筛选条件分页；Limit<=0 表示不分页（导出用，调用方负责上限）。
func (r *SystemRepository) ListAuditOperationsFiltered(ctx context.Context, f AuditOperationFilter) ([]*AuditOperationRow, int, error) {
	where, args := buildAuditOperationWhere(f)
	from := `FROM audit_operations ao LEFT JOIN users u ON u.id = ao.user_id`
	var total int
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) "+from+" WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit operations: %w", err)
	}
	q := `SELECT ao.id, COALESCE(ao.user_id, ''), COALESCE(u.username, ''), ao.action_type,
		COALESCE(ao.action_detail::text, '{}'), COALESCE(ao.target_type, ''), COALESCE(ao.target_id, ''),
		COALESCE(ao.ip_address, ''), ao.created_at ` + from + " WHERE " + where + " ORDER BY ao.created_at DESC, ao.id DESC"
	qargs := append([]any{}, args...)
	if f.Limit > 0 {
		qargs = append(qargs, f.Limit, f.Offset)
		q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(qargs)-1, len(qargs))
	}
	rows, err := r.db.Query(ctx, q, qargs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit operations: %w", err)
	}
	defer rows.Close()
	out := []*AuditOperationRow{}
	for rows.Next() {
		var row AuditOperationRow
		var detail string
		if err := rows.Scan(&row.ID, &row.UserID, &row.Username, &row.ActionType, &detail, &row.TargetType, &row.TargetID, &row.IPAddress, &row.CreatedAt); err != nil {
			return nil, 0, err
		}
		row.ActionDetail = map[string]interface{}{}
		_ = json.Unmarshal([]byte(detail), &row.ActionDetail)
		out = append(out, &row)
	}
	return out, total, rows.Err()
}

// ---- 阻断记录导出 ----

// ListBlockRecordsForExport 与 ListBlockRecords 同 WHERE，但不受 200 行分页上限约束。
func (r *SecurityEventRepository) ListBlockRecordsForExport(ctx context.Context, tenantID string, filter SecurityBlockRecordFilter, max int) ([]SecurityBlockRecord, int, error) {
	where, args := buildSecurityBlockRecordWhere(tenantID, filter)
	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM security_events se
		LEFT JOIN request_logs rl ON rl.request_id = se.request_id WHERE %s`, where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count block records: %w", err)
	}
	if total > max {
		return nil, total, nil
	}
	rows, err := r.db.Query(ctx, fmt.Sprintf(`%s WHERE %s ORDER BY se.created_at DESC, se.id DESC`, securityBlockRecordSelect, where), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("export block records: %w", err)
	}
	defer rows.Close()
	out := []SecurityBlockRecord{}
	for rows.Next() {
		rec, err := scanSecurityBlockRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rec)
	}
	return out, total, rows.Err()
}

// ---- 消息中心 ----

// AlertInboxFilter 是消息中心列表与导出的筛选条件。
type AlertInboxFilter struct {
	TenantID   string
	UnreadOnly bool
	Severity   string
	Type       string
	From       time.Time
	To         time.Time
	Limit      int
	Offset     int
}

func buildAlertInboxWhere(f AlertInboxFilter) (string, []any) {
	args := []any{f.TenantID}
	where := []string{"tenant_id = $1"}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.UnreadOnly {
		where = append(where, "read_at IS NULL")
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.Type != "" {
		add("type = $%d", f.Type)
	}
	if !f.From.IsZero() {
		add("created_at >= $%d", f.From)
	}
	if !f.To.IsZero() {
		add("created_at < $%d", f.To)
	}
	return strings.Join(where, " AND "), args
}

// ListFiltered 返回筛选后的消息与总数；Limit<=0 表示不分页。
func (r *AlertInboxRepository) ListFiltered(ctx context.Context, f AlertInboxFilter) ([]*AlertInboxItem, int, error) {
	if f.TenantID == "" {
		return nil, 0, errors.New("tenant required")
	}
	where, args := buildAlertInboxWhere(f)
	var total int
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM alert_inbox WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, tenant_id, severity, type, title, body_json, COALESCE(target_url, '') AS target_url, read_at, created_at
		FROM alert_inbox WHERE ` + where + ` ORDER BY created_at DESC, id DESC`
	qargs := append([]any{}, args...)
	if f.Limit > 0 {
		qargs = append(qargs, f.Limit, f.Offset)
		q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(qargs)-1, len(qargs))
	}
	rows, err := r.db.Query(ctx, q, qargs...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []*AlertInboxItem{}, total, nil
		}
		return nil, 0, err
	}
	defer rows.Close()
	items, err := scanAlertInboxItems(rows)
	if items == nil {
		items = []*AlertInboxItem{}
	}
	return items, total, err
}
