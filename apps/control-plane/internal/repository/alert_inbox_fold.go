package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 消息中心的两项能力，都只读写 alert_inbox（以及批量已读事务里的一条 audit_operations 审计）：
//
//  1. 「同类折叠」：同 type + 同严重度 + 同（去掉计数后缀的）标题 + 同一天 + 同关键字段 合成一组，
//     只做展示层聚合，不删除、不合并任何一行；展开时按同一个分组键取回该组的全部原始消息。
//  2. 「按类别 + 时间范围批量已读」：仅更新 alert_inbox.read_at。绝不触碰 alert_groups / security_events，
//     类别走显式白名单，范围必须带起止时间，条数必须与管理员确认的一致，审计与更新在同一事务里。

const (
	foldMaxPageGroups = 100
	foldMaxItemsLimit = 200
	foldMaxWindow     = 26 * time.Hour // 一天最长 25 小时（夏令时切换日），多留 1 小时余量
	// 批量已读的时间范围上限：管理员要显式选定一段历史，而不是“从有记录以来的全部”。
	bulkReadMaxSpan = 366 * 24 * time.Hour
)

// foldTitleCounterSuffix 去掉安全事件标题尾部随累计次数变化的「 · 独立事发 N 次 · 涉及 N 人」，
// 否则同一规则每次折叠计数变化都会拆成新的一行。业务名里自带数字的标题（员工、模型）不受影响。
const foldTitleCounterSuffix = `' · 独立事发 [0-9]+ 次 · 涉及 [0-9]+ 人$'`

// foldDimExpr 是「同一类事件里仍需区分开」的 body 关键字段：原因、模型、线路、规则、事件类型、处置。
// 缺失的字段按空串参与，保证位置固定。
const foldDimExpr = `concat_ws(chr(31),
	COALESCE(body_json->>'reason',''), COALESCE(body_json->>'model_name',''), COALESCE(body_json->>'provider_ref',''),
	COALESCE(body_json->>'rule_name',''), COALESCE(body_json->>'event_type',''), COALESCE(body_json->>'action',''))`

func foldDayLocalExpr(tzArg string) string {
	return "date_trunc('day', created_at AT TIME ZONE " + tzArg + "::text)"
}

func foldKeyExpr(tzArg string) string {
	return "md5(concat_ws(chr(31), type, severity, to_char(" + foldDayLocalExpr(tzArg) + ", 'YYYY-MM-DD'), regexp_replace(title, " + foldTitleCounterSuffix + ", ''), " + foldDimExpr + "))"
}

// AlertInboxFoldedGroup 是折叠后的一行。Sample 是该组最新的一条完整消息，用来渲染标题与详情。
type AlertInboxFoldedGroup struct {
	Key         string          `json:"key"`
	Type        string          `json:"type"`
	Severity    string          `json:"severity"`
	Day         string          `json:"day"`
	DayStart    time.Time       `json:"day_start"`
	DayEnd      time.Time       `json:"day_end"`
	Count       int             `json:"count"`
	UnreadCount int             `json:"unread_count"`
	FirstAt     time.Time       `json:"first_at"`
	LastAt      time.Time       `json:"last_at"`
	Sample      *AlertInboxItem `json:"sample"`
}

// AlertInboxFoldedPage 按「组」分页；TotalItems 是满足筛选的原始消息总数（所有页合计）。
type AlertInboxFoldedPage struct {
	Groups      []*AlertInboxFoldedGroup `json:"groups"`
	TotalGroups int                      `json:"total_groups"`
	TotalItems  int                      `json:"total_items"`
}

func loadFoldLocation(tz string) (string, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		tz = DefaultReportTimezone
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "", fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	return tz, nil
}

// ListFolded 返回折叠后的分组列表（最近活动在前）。筛选条件与 ListFiltered 完全一致，Limit/Offset 作用于「组」。
func (r *AlertInboxRepository) ListFolded(ctx context.Context, f AlertInboxFilter, tz string) (*AlertInboxFoldedPage, error) {
	if f.TenantID == "" {
		return nil, errors.New("tenant required")
	}
	tz, err := loadFoldLocation(tz)
	if err != nil {
		return nil, err
	}
	limit := f.Limit
	if limit <= 0 || limit > foldMaxPageGroups {
		limit = 20
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := buildAlertInboxWhere(f)
	args = append(args, tz)
	tzArg := fmt.Sprintf("$%d", len(args))
	aggCTE := `
		WITH base AS (
			SELECT id, type, severity, created_at, read_at,
			       ` + foldDayLocalExpr(tzArg) + ` AS day_local,
			       ` + foldKeyExpr(tzArg) + ` AS gkey
			FROM alert_inbox WHERE ` + where + `
		), agg AS (
			SELECT gkey, type, severity, day_local,
			       count(*) AS cnt,
			       count(*) FILTER (WHERE read_at IS NULL) AS unread,
			       min(created_at) AS first_at, max(created_at) AS last_at,
			       (array_agg(id ORDER BY created_at DESC, id DESC))[1] AS sample_id
			FROM base GROUP BY gkey, type, severity, day_local
		)`

	pageArgs := append(append([]any{}, args...), limit, offset)
	pageSQL := aggCTE + `
		SELECT gkey, type, severity, to_char(day_local, 'YYYY-MM-DD'),
		       (day_local AT TIME ZONE ` + tzArg + `::text),
		       ((day_local + interval '1 day') AT TIME ZONE ` + tzArg + `::text),
		       cnt, unread, first_at, last_at, sample_id,
		       count(*) OVER ()::bigint, (sum(cnt) OVER ())::bigint
		FROM agg ORDER BY last_at DESC, gkey
		LIMIT $` + fmt.Sprint(len(pageArgs)-1) + ` OFFSET $` + fmt.Sprint(len(pageArgs))
	rows, err := r.db.Query(ctx, pageSQL, pageArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	page := &AlertInboxFoldedPage{Groups: []*AlertInboxFoldedGroup{}}
	sampleIDs := make([]string, 0, limit)
	sampleOf := map[string]string{} // group key -> sample id
	for rows.Next() {
		g := &AlertInboxFoldedGroup{}
		var sampleID string
		var totalGroups, totalItems int64
		if err := rows.Scan(&g.Key, &g.Type, &g.Severity, &g.Day, &g.DayStart, &g.DayEnd,
			&g.Count, &g.UnreadCount, &g.FirstAt, &g.LastAt, &sampleID, &totalGroups, &totalItems); err != nil {
			return nil, err
		}
		g.DayStart, g.DayEnd, g.FirstAt, g.LastAt = g.DayStart.UTC(), g.DayEnd.UTC(), g.FirstAt.UTC(), g.LastAt.UTC()
		page.TotalGroups, page.TotalItems = int(totalGroups), int(totalItems)
		page.Groups = append(page.Groups, g)
		sampleIDs = append(sampleIDs, sampleID)
		sampleOf[g.Key] = sampleID
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	if len(page.Groups) == 0 {
		// 翻过头的空页拿不到窗口函数的合计，单独补一次，保证分页控件的总数正确。
		var tg, ti int64
		if err := r.db.QueryRow(ctx, aggCTE+` SELECT count(*)::bigint, COALESCE(sum(cnt), 0)::bigint FROM agg`, args...).Scan(&tg, &ti); err != nil {
			return nil, err
		}
		page.TotalGroups, page.TotalItems = int(tg), int(ti)
		return page, nil
	}

	sampleRows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, severity, type, title, body_json, COALESCE(target_url, '') AS target_url, read_at, created_at
		FROM alert_inbox WHERE tenant_id = $1 AND id = ANY($2)`, f.TenantID, sampleIDs)
	if err != nil {
		return nil, err
	}
	defer sampleRows.Close()
	samples, err := scanAlertInboxItems(sampleRows)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*AlertInboxItem, len(samples))
	for _, s := range samples {
		byID[s.ID] = s
	}
	for _, g := range page.Groups {
		g.Sample = byID[sampleOf[g.Key]]
	}
	return page, nil
}

// AlertInboxFoldedItemsFilter 用来取回「某一组」的全部原始消息：分组键 + 当天窗口 + 类型/严重度，缺一不可。
type AlertInboxFoldedItemsFilter struct {
	TenantID   string
	Key        string
	Type       string
	Severity   string
	DayStart   time.Time
	DayEnd     time.Time
	TZ         string
	UnreadOnly bool
	Limit      int
	Offset     int
}

// ListFoldedItems 返回某一组的原始消息（新到旧）与总数。分组键由库里按同一表达式重算比对，
// 因此伪造或过期的 key 只会得到 0 条，不会越权看到别的组或别的租户。
func (r *AlertInboxRepository) ListFoldedItems(ctx context.Context, f AlertInboxFoldedItemsFilter) ([]*AlertInboxItem, int, error) {
	if f.TenantID == "" {
		return nil, 0, errors.New("tenant required")
	}
	if f.Key == "" || f.Type == "" || f.Severity == "" {
		return nil, 0, errors.New("key, type and severity required")
	}
	if f.DayStart.IsZero() || f.DayEnd.IsZero() || !f.DayStart.Before(f.DayEnd) || f.DayEnd.Sub(f.DayStart) > foldMaxWindow {
		return nil, 0, errors.New("invalid day window")
	}
	tz, err := loadFoldLocation(f.TZ)
	if err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > foldMaxItemsLimit {
		limit = 20
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where := `tenant_id = $1 AND type = $2 AND severity = $3 AND created_at >= $4 AND created_at < $5 AND ` +
		foldKeyExpr("$6") + ` = $7`
	args := []any{f.TenantID, f.Type, f.Severity, f.DayStart, f.DayEnd, tz, f.Key}
	if f.UnreadOnly {
		where += ` AND read_at IS NULL`
	}
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_inbox WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, severity, type, title, body_json, COALESCE(target_url, '') AS target_url, read_at, created_at
		FROM alert_inbox WHERE `+where+` ORDER BY created_at DESC, id DESC LIMIT $8 OFFSET $9`,
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items, err := scanAlertInboxItems(rows)
	if items == nil {
		items = []*AlertInboxItem{}
	}
	return items, total, err
}

// AlertInboxTypeSummary 是「批量已读」弹窗里每个类别的未读概况。
type AlertInboxTypeSummary struct {
	Type            string    `json:"type"`
	Unread          int       `json:"unread"`
	Total           int       `json:"total"`
	FirstAt         time.Time `json:"first_at"`
	LastAt          time.Time `json:"last_at"`
	BulkReadAllowed bool      `json:"bulk_read_allowed"`
}

// TypeSummary 按类别汇总本租户的消息；首末时间优先取未读消息的跨度（便于选择范围），没有未读则取全部。
func (r *AlertInboxRepository) TypeSummary(ctx context.Context, tenantID string) ([]*AlertInboxTypeSummary, error) {
	if tenantID == "" {
		return nil, errors.New("tenant required")
	}
	rows, err := r.db.Query(ctx, `
		SELECT type,
		       count(*) FILTER (WHERE read_at IS NULL)::bigint,
		       count(*)::bigint,
		       COALESCE(min(created_at) FILTER (WHERE read_at IS NULL), min(created_at)),
		       COALESCE(max(created_at) FILTER (WHERE read_at IS NULL), max(created_at))
		FROM alert_inbox WHERE tenant_id = $1
		GROUP BY type ORDER BY 2 DESC, type`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AlertInboxTypeSummary{}
	for rows.Next() {
		s := &AlertInboxTypeSummary{}
		var unread, total int64
		if err := rows.Scan(&s.Type, &unread, &total, &s.FirstAt, &s.LastAt); err != nil {
			return nil, err
		}
		s.Unread, s.Total = int(unread), int(total)
		s.FirstAt, s.LastAt = s.FirstAt.UTC(), s.LastAt.UTC()
		s.BulkReadAllowed = BulkReadAllowedType(s.Type)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------- 批量已读 ----------

// bulkReadAllowedTypes 是允许批量已读的消息类别白名单（精确匹配）。
// 只放「治理 / 线路状态」这类通知；安全事件、运行故障、工具与审计、计费、线路不可用/熔断等
// 需要有人看的类别一律不在其中，新增的未知类别默认也不在其中。
var bulkReadAllowedTypes = map[string]struct{}{
	"alert":                               {},
	"governor.model_downgraded":           {},
	"governor.downgrade_fallback_alert":   {},
	"quota.admission.reservation_overrun": {},
	"model_route_degraded":                {},
	"model_route_recovered":               {},
	"model_route_fallback":                {},
	"model_route_flapping":                {},
}

// BulkReadAllowedType 报告某个消息类别是否允许批量已读。
func BulkReadAllowedType(typ string) bool {
	_, ok := bulkReadAllowedTypes[typ]
	return ok
}

var (
	// ErrBulkReadTypeProtected 表示所选类别不在批量已读白名单内。
	ErrBulkReadTypeProtected = errors.New("bulk read is not allowed for this message type")
	// ErrBulkReadInvalid 表示批量已读的范围参数不完整或不合法。
	ErrBulkReadInvalid = errors.New("invalid bulk read scope")
)

// BulkReadCountChangedError 表示实际命中的条数与管理员确认的条数不一致，整体已回滚。
type BulkReadCountChangedError struct{ Current int }

func (e *BulkReadCountChangedError) Error() string {
	return fmt.Sprintf("unread count changed: now %d", e.Current)
}

// 批量已读用到的全部 SQL。测试会检查它们：只能 UPDATE alert_inbox SET read_at，且 WHERE 必须带
// 租户、类别、时间范围与「未读」条件；不得出现 alert_groups / security_events / DELETE。
const (
	bulkMarkReadUpdateSQL = `UPDATE alert_inbox SET read_at = $1
		WHERE tenant_id = $2 AND type = $3 AND read_at IS NULL AND created_at >= $4 AND created_at < $5`

	bulkReadPreviewSQL = `SELECT severity, count(*)::bigint, min(created_at), max(created_at)
		FROM alert_inbox
		WHERE tenant_id = $1 AND type = $2 AND read_at IS NULL AND created_at >= $3 AND created_at < $4
		GROUP BY severity`

	bulkReadAuditInsertSQL = `INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, ip_address)
		VALUES ($1, NULLIF($2,''), $3, $4::jsonb, $5, $6, $7)`
)

// ValidateBulkReadScope 是批量已读范围的唯一校验规则（类别白名单、起止时间必填且有序、跨度上限）。
// handler 在到达仓储之前先调用它，仓储在写入之前再调用一次，两层用同一份规则。
func ValidateBulkReadScope(tenantID, typ string, from, to time.Time) error {
	return validateBulkReadScope(tenantID, typ, from, to)
}

func validateBulkReadScope(tenantID, typ string, from, to time.Time) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant required", ErrBulkReadInvalid)
	}
	if !BulkReadAllowedType(typ) {
		return ErrBulkReadTypeProtected
	}
	if from.IsZero() || to.IsZero() {
		return fmt.Errorf("%w: both from and to are required", ErrBulkReadInvalid)
	}
	if !from.Before(to) {
		return fmt.Errorf("%w: from must be earlier than to", ErrBulkReadInvalid)
	}
	if to.Sub(from) > bulkReadMaxSpan {
		return fmt.Errorf("%w: range must not exceed 366 days", ErrBulkReadInvalid)
	}
	return nil
}

// BulkReadPreview 是批量已读前的试算：范围内有多少条未读、时间跨度、各严重度各多少。
type BulkReadPreview struct {
	Matched        int
	FirstAt        *time.Time
	LastAt         *time.Time
	SeverityCounts map[string]int
}

// PreviewBulkRead 只读试算，不修改任何数据。
func (r *AlertInboxRepository) PreviewBulkRead(ctx context.Context, tenantID, typ string, from, to time.Time) (*BulkReadPreview, error) {
	if err := validateBulkReadScope(tenantID, typ, from, to); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, bulkReadPreviewSQL, tenantID, typ, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &BulkReadPreview{SeverityCounts: map[string]int{}}
	for rows.Next() {
		var sev string
		var n int64
		var mn, mx time.Time
		if err := rows.Scan(&sev, &n, &mn, &mx); err != nil {
			return nil, err
		}
		out.Matched += int(n)
		out.SeverityCounts[sev] = int(n)
		mn, mx = mn.UTC(), mx.UTC()
		if out.FirstAt == nil || mn.Before(*out.FirstAt) {
			out.FirstAt = &mn
		}
		if out.LastAt == nil || mx.After(*out.LastAt) {
			out.LastAt = &mx
		}
	}
	return out, rows.Err()
}

// BulkReadParams 描述一次批量已读。ExpectedCount 是管理员在预览后亲手确认的条数；Audit 在同一事务内落库。
type BulkReadParams struct {
	TenantID      string
	Type          string
	From, To      time.Time
	ExpectedCount int
	Audit         *AuditOperation
}

// BulkMarkRead 把 [From, To) 内、指定类别的未读消息标为已读，返回实际条数。
//
// 单个事务：UPDATE（只改 read_at）→ 条数与 ExpectedCount 比对（不符则回滚）→ 写审计 → 提交。
// 审计写不进去同样回滚，所以不存在「改了但没记录」。不碰 alert_groups / security_events。
func (r *AlertInboxRepository) BulkMarkRead(ctx context.Context, p BulkReadParams) (int, error) {
	if err := validateBulkReadScope(p.TenantID, p.Type, p.From, p.To); err != nil {
		return 0, err
	}
	if p.ExpectedCount <= 0 {
		return 0, fmt.Errorf("%w: expected count must be positive", ErrBulkReadInvalid)
	}
	if p.Audit == nil || p.Audit.ID == "" || p.Audit.ActionType == "" {
		return 0, fmt.Errorf("%w: audit record required", ErrBulkReadInvalid)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // 提交之后调用是空操作

	tag, err := tx.Exec(ctx, bulkMarkReadUpdateSQL, time.Now().UTC(), p.TenantID, p.Type, p.From, p.To)
	if err != nil {
		return 0, err
	}
	marked := int(tag.RowsAffected())
	if marked != p.ExpectedCount {
		return 0, &BulkReadCountChangedError{Current: marked}
	}

	detail := make(map[string]any, len(p.Audit.ActionDetail)+6)
	for k, v := range p.Audit.ActionDetail {
		detail[k] = v
	}
	detail["tenant_id"] = p.TenantID
	detail["type"] = p.Type
	detail["from"] = p.From.UTC().Format(time.RFC3339)
	detail["to"] = p.To.UTC().Format(time.RFC3339)
	detail["expected_count"] = p.ExpectedCount
	detail["marked_read"] = marked
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, bulkReadAuditInsertSQL, p.Audit.ID, p.Audit.UserID, p.Audit.ActionType,
		string(detailJSON), p.Audit.TargetType, p.Audit.TargetID, p.Audit.IPAddress); err != nil {
		return 0, fmt.Errorf("write audit operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return marked, nil
}
