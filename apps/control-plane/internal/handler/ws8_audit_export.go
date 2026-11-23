package handler

// W8 8.7：操作审计、阻断记录、消息中心的时间/主体/动作筛选与服务端全量导出。
// 导出动作本身写操作审计留痕。口径见 docs/design/ws8-metrics-definitions.md §4。

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func reportLocationFor(r *http.Request, deps *Dependencies, tenantID string) (*time.Location, string) {
	if deps != nil && deps.UsageDailyRepo != nil && deps.UsageDailyRepo.DB() != nil {
		return repository.NewStatsRepository(deps.UsageDailyRepo.DB()).TenantReportTimezone(r.Context(), tenantID)
	}
	return repository.ReportLocation("")
}

func parseAuditOperationFilter(r *http.Request, user *repository.User, loc *time.Location) (repository.AuditOperationFilter, error) {
	q := r.URL.Query()
	f := repository.AuditOperationFilter{
		UserID:     strings.TrimSpace(q.Get("user_id")),
		ActionType: strings.TrimSpace(q.Get("action_type")),
		TargetType: strings.TrimSpace(q.Get("target_type")),
		Limit:      parseIntParam(q.Get("limit"), 100),
	}
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o > 0 {
		f.Offset = o
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	// 平台管理员看全局；其余角色只看本租户（原实现不按租户过滤）。
	if user.Role != "platform_admin" {
		f.TenantID = user.TenantID
	}
	from, to, err := parseReportRange(r, loc)
	if err != nil {
		return f, err
	}
	f.From, f.To = from, to
	return f, nil
}

func systemRepoFiltered(deps *Dependencies) (*repository.SystemRepository, bool) {
	if deps == nil || deps.SystemRepo == nil {
		return nil, false
	}
	repo, ok := deps.SystemRepo.(*repository.SystemRepository)
	return repo, ok && repo != nil
}

// ListAuditOperationsW8 serves GET /admin/v1/system/audit-operations with
// from/to/user_id/action_type/target_type filters and tenant scoping.
func ListAuditOperationsW8(deps *Dependencies) http.HandlerFunc {
	legacy := ListAuditOperations(deps)
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		repo, ok := systemRepoFiltered(deps)
		if !ok {
			legacy(w, r)
			return
		}
		loc, tz := reportLocationFor(r, deps, user.TenantID)
		f, err := parseAuditOperationFilter(r, user, loc)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		rows, total, err := repo.ListAuditOperationsFiltered(r.Context(), f)
		if err != nil {
			log.Printf("ListAuditOperationsW8: %v", err)
			writeError(w, "internal_error", "failed to list audit operations")
			return
		}
		data := make([]map[string]any, len(rows))
		for i, op := range rows {
			data[i] = map[string]any{
				"id": op.ID, "user_id": op.UserID, "username": op.Username, "action_type": op.ActionType,
				"action_detail": op.ActionDetail, "target_type": op.TargetType, "target_id": op.TargetID,
				"ip_address": op.IPAddress, "created_at": op.CreatedAt.Format(time.RFC3339),
			}
		}
		writeJSON(w, map[string]any{"data": data, "total": total, "limit": f.Limit, "offset": f.Offset, "timezone": tz})
	}
}

// ExportAuditOperations serves GET /admin/v1/system/audit-operations/export?format=csv|xlsx.
func ExportAuditOperations(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		format, ok := parseExportFormat(r)
		if !ok {
			writeError(w, "invalid_request", "format must be csv or xlsx")
			return
		}
		repo, ok := systemRepoFiltered(deps)
		if !ok {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "audit operations are unavailable")
			return
		}
		loc, tz := reportLocationFor(r, deps, user.TenantID)
		f, err := parseAuditOperationFilter(r, user, loc)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		f.Limit, f.Offset = reportExportMaxRows+1, 0
		rows, total, err := repo.ListAuditOperationsFiltered(r.Context(), f)
		if err != nil {
			log.Printf("ExportAuditOperations: %v", err)
			writeError(w, "internal_error", "failed to export audit operations")
			return
		}
		if total > reportExportMaxRows {
			writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "export_too_large", "too many rows; narrow the time range")
			return
		}
		table := reportTable{Sheet: "operation_audit", Headers: []string{"时间（" + tz + "）", "操作人", "操作人ID", "操作类型", "对象类型", "对象ID", "来源IP", "详情", "记录ID"}}
		for _, op := range rows {
			table.Rows = append(table.Rows, []string{
				formatReportTime(op.CreatedAt, loc), op.Username, op.UserID, op.ActionType, op.TargetType,
				op.TargetID, op.IPAddress, compactJSON(op.ActionDetail), op.ID,
			})
		}
		logExport(r, deps, "export_operation_audit", format, len(table.Rows), map[string]any{
			"from": f.From, "to": f.To, "user_id": f.UserID, "action_type": f.ActionType, "target_type": f.TargetType,
		})
		if err := writeReportTable(w, format, "operation_audit_"+time.Now().In(loc).Format("20060102_150405"), table); err != nil {
			log.Printf("ExportAuditOperations write: %v", err)
		}
	}
}

func parseBlockRecordExportFilter(r *http.Request, deps *Dependencies, loc *time.Location) (repository.SecurityBlockRecordFilter, bool, error) {
	q := r.URL.Query()
	f := repository.SecurityBlockRecordFilter{Query: strings.TrimSpace(q.Get("q")), Layer: strings.TrimSpace(q.Get("layer"))}
	if len(f.Query) > 256 {
		return f, false, errors.New("q must be at most 256 characters")
	}
	from, to, err := parseReportRange(r, loc)
	if err != nil {
		return f, false, err
	}
	f.From, f.To = from, to
	if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant {
		if len(scope.ProjectIDs) == 0 {
			return f, true, nil
		}
		f.ProjectIDs = scope.ProjectIDs
	}
	return f, false, nil
}

// ExportSecurityBlockRecords serves GET /admin/v1/security/block-records/export.
func ExportSecurityBlockRecords(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		format, ok := parseExportFormat(r)
		if !ok {
			writeError(w, "invalid_request", "format must be csv or xlsx")
			return
		}
		if deps == nil || deps.SecurityEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "block records are unavailable")
			return
		}
		loc, tz := reportLocationFor(r, deps, user.TenantID)
		f, empty, err := parseBlockRecordExportFilter(r, deps, loc)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		var records []repository.SecurityBlockRecord
		if !empty {
			var total int
			records, total, err = deps.SecurityEventRepo.ListBlockRecordsForExport(r.Context(), user.TenantID, f, reportExportMaxRows)
			if err != nil {
				log.Printf("ExportSecurityBlockRecords: %v", err)
				writeError(w, "internal_error", "failed to export block records")
				return
			}
			if total > reportExportMaxRows {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "export_too_large", "too many rows; narrow the time range")
				return
			}
		}
		// “命中原文”列（2.9.22 起入库）只给有内容证据权限的角色；“命中内容”列照旧是打码展示值。
		canReadEvidence := canReadFullTenantContentEvidence(user)
		headers := []string{"时间（" + tz + "）", "阻断编号", "阻断位置", "阻断原因", "规则ID", "规则名称", "命中内容"}
		if canReadEvidence {
			headers = append(headers, "命中原文")
		}
		table := reportTable{Sheet: "block_records", Headers: append(headers, "处置依据", "处置动作", "风险等级", "用户", "应用", "模型", "智能体", "来源", "来源IP", "请求ID", "Trace ID", "操作编号")}
		for _, rec := range records {
			row := []string{
				formatReportTime(rec.CreatedAt, loc), rec.BlockID, rec.Layer, rec.Reason, rec.RuleID, rec.RuleName, rec.Detail,
			}
			if canReadEvidence {
				row = append(row, rec.RawEvidence)
			}
			table.Rows = append(table.Rows, append(row,
				rec.Basis, rec.ActionTaken, rec.Severity, firstNonEmpty(rec.UserName, rec.UserID),
				firstNonEmpty(rec.ProjectName, rec.ProjectID), rec.Model, rec.AgentType, rec.Source, rec.SourceIP,
				rec.RequestID, rec.TraceID, rec.OperationID,
			))
		}
		logExport(r, deps, "export_block_records", format, len(table.Rows), map[string]any{
			"from": f.From, "to": f.To, "q": f.Query, "layer": f.Layer,
		})
		if err := writeReportTable(w, format, "block_records_"+time.Now().In(loc).Format("20060102_150405"), table); err != nil {
			log.Printf("ExportSecurityBlockRecords write: %v", err)
		}
	}
}

func parseAlertInboxFilter(r *http.Request, tenantID string, loc *time.Location) (repository.AlertInboxFilter, error) {
	q := r.URL.Query()
	f := repository.AlertInboxFilter{
		TenantID:   tenantID,
		UnreadOnly: q.Get("unread") == "true",
		Severity:   strings.TrimSpace(q.Get("severity")),
		Type:       strings.TrimSpace(q.Get("type")),
		Limit:      parseIntParam(q.Get("limit"), 20),
	}
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o > 0 {
		f.Offset = o
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	from, to, err := parseReportRange(r, loc)
	f.From, f.To = from, to
	return f, err
}

func alertInboxFiltersRequested(r *http.Request) bool {
	q := r.URL.Query()
	for _, k := range []string{"from", "to", "from_time", "to_time", "severity", "type", "offset"} {
		if q.Get(k) != "" {
			return true
		}
	}
	return false
}

// ListAlertInboxW8 keeps the legacy response shape (items + unread_count) and
// adds total when time/severity/type filters or offset are supplied.
func ListAlertInboxW8(deps *Dependencies) http.HandlerFunc {
	legacy := ListAlertInbox(deps)
	return func(w http.ResponseWriter, r *http.Request) {
		if !alertInboxFiltersRequested(r) {
			legacy(w, r)
			return
		}
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		loc, tz := reportLocationFor(r, deps, user.TenantID)
		f, err := parseAlertInboxFilter(r, user.TenantID, loc)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		items, total, err := deps.AlertInboxRepo.ListFiltered(r.Context(), f)
		if err != nil {
			log.Printf("ListAlertInboxW8: %v", err)
			writeError(w, "internal_error", "failed to list alerts")
			return
		}
		inboxItemsForViewer(items, canReadFullTenantContentEvidence(user))
		unread, _ := deps.AlertInboxRepo.CountUnread(r.Context(), user.TenantID)
		writeJSON(w, map[string]any{"items": items, "unread_count": unread, "total": total, "timezone": tz})
	}
}

// ExportAlertInbox serves GET /admin/v1/alerts/inbox/export.
func ExportAlertInbox(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		format, ok := parseExportFormat(r)
		if !ok {
			writeError(w, "invalid_request", "format must be csv or xlsx")
			return
		}
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		loc, tz := reportLocationFor(r, deps, user.TenantID)
		f, err := parseAlertInboxFilter(r, user.TenantID, loc)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		f.Limit, f.Offset = reportExportMaxRows+1, 0
		items, total, err := deps.AlertInboxRepo.ListFiltered(r.Context(), f)
		if err != nil {
			log.Printf("ExportAlertInbox: %v", err)
			writeError(w, "internal_error", "failed to export alerts")
			return
		}
		if total > reportExportMaxRows {
			writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "export_too_large", "too many rows; narrow the time range")
			return
		}
		table := reportTable{Sheet: "alert_inbox", Headers: []string{"时间（" + tz + "）", "严重度", "类型", "标题", "状态", "已读时间", "链接", "详情", "消息ID"}}
		inboxItemsForViewer(items, canReadFullTenantContentEvidence(user))
		for _, item := range items {
			status, readAt := "unread", ""
			if item.ReadAt != nil {
				status, readAt = "read", formatReportTime(*item.ReadAt, loc)
			}
			table.Rows = append(table.Rows, []string{
				formatReportTime(item.CreatedAt, loc), item.Severity, item.Type, item.Title, status, readAt,
				item.TargetURL, compactJSON(item.BodyJSON), item.ID,
			})
		}
		logExport(r, deps, "export_alert_inbox", format, len(table.Rows), map[string]any{
			"from": f.From, "to": f.To, "severity": f.Severity, "type": f.Type, "unread": f.UnreadOnly,
		})
		if err := writeReportTable(w, format, "alert_inbox_"+time.Now().In(loc).Format("20060102_150405"), table); err != nil {
			log.Printf("ExportAlertInbox write: %v", err)
		}
	}
}

// logExport 把导出动作写进操作审计：格式、筛选条件、行数。
func logExport(r *http.Request, deps *Dependencies, action, format string, rows int, filters map[string]any) {
	detail := map[string]interface{}{"format": format, "rows": rows}
	for k, v := range filters {
		switch value := v.(type) {
		case time.Time:
			if !value.IsZero() {
				detail[k] = value.UTC().Format(time.RFC3339)
			}
		case string:
			if value != "" {
				detail[k] = value
			}
		case bool:
			if value {
				detail[k] = value
			}
		}
	}
	logAudit(r, deps, action, detail, "export", action)
}

func compactJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "{}" || string(b) == "null" {
		return ""
	}
	return string(b)
}
