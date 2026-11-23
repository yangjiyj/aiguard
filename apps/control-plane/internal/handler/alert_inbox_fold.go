package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// 消息中心「同类折叠」视图与管理员「按类别 + 时间范围批量已读」。
//
// 红线（与 repository/alert_inbox_fold.go 一致）：
//   - 批量已读只改 alert_inbox.read_at；不碰 alert_groups / security_events，不删除，不改检测与执行模式；
//   - 类别走白名单、范围必须带起止时间、条数必须与管理员确认的一致；
//   - 审计与更新在同一个事务里，审计写不进去就不执行。

type inboxFoldReader interface {
	ListFolded(ctx context.Context, f repository.AlertInboxFilter, tz string) (*repository.AlertInboxFoldedPage, error)
	CountUnread(ctx context.Context, tenantID string) (int, error)
}

type inboxFoldItemsReader interface {
	ListFoldedItems(ctx context.Context, f repository.AlertInboxFoldedItemsFilter) ([]*repository.AlertInboxItem, int, error)
}

type inboxTypeSummaryReader interface {
	TypeSummary(ctx context.Context, tenantID string) ([]*repository.AlertInboxTypeSummary, error)
}

type inboxBulkReadPreviewer interface {
	PreviewBulkRead(ctx context.Context, tenantID, typ string, from, to time.Time) (*repository.BulkReadPreview, error)
}

type inboxBulkReader interface {
	BulkMarkRead(ctx context.Context, p repository.BulkReadParams) (int, error)
}

type reportLocFn func(r *http.Request, tenantID string) (*time.Location, string)

const (
	// 折叠明细接口的窗口上限：一天最长 25 小时（夏令时），多留 1 小时。
	foldedItemsMaxWindow = 26 * time.Hour
	// 单次确认请求体上限：字段很少，4KB 足够。
	bulkReadBodyLimit = 4096
)

// bulkReadActionType 是审计里的操作类型；前端「操作审计」页有对应中文标签。
const bulkReadActionType = "alert_inbox.bulk_read"

func tenantReportLoc(deps *Dependencies) reportLocFn {
	return func(r *http.Request, tenantID string) (*time.Location, string) {
		return reportLocationFor(r, deps, tenantID)
	}
}

// ---------- 读：折叠列表 / 折叠明细（所有登录用户可读，范围等同现有消息中心列表） ----------

// ListAlertInboxFolded handles GET /admin/v1/alerts/inbox/folded
func ListAlertInboxFolded(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		listAlertInboxFoldedHandler(deps.AlertInboxRepo, tenantReportLoc(deps))(w, r)
	}
}

func listAlertInboxFoldedHandler(repo inboxFoldReader, locFor reportLocFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		loc, tz := locFor(r, user.TenantID)
		f, err := parseAlertInboxFilter(r, user.TenantID, loc)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		if f.Limit > 100 {
			f.Limit = 100
		}
		page, err := repo.ListFolded(r.Context(), f, tz)
		if err != nil {
			log.Printf("ListAlertInboxFolded: %v", err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list alerts")
			return
		}
		canReadEvidence := canReadFullTenantContentEvidence(user)
		for _, group := range page.Groups {
			if group != nil && group.Sample != nil {
				inboxItemsForViewer([]*repository.AlertInboxItem{group.Sample}, canReadEvidence)
			}
		}
		unread, _ := repo.CountUnread(r.Context(), user.TenantID)
		writeJSON(w, map[string]any{
			"groups":       page.Groups,
			"total_groups": page.TotalGroups,
			"total_items":  page.TotalItems,
			"unread_count": unread,
			"timezone":     tz,
		})
	}
}

// ListAlertInboxFoldedItems handles GET /admin/v1/alerts/inbox/folded/items
func ListAlertInboxFoldedItems(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		listAlertInboxFoldedItemsHandler(deps.AlertInboxRepo, tenantReportLoc(deps))(w, r)
	}
}

func listAlertInboxFoldedItemsHandler(repo inboxFoldItemsReader, locFor reportLocFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		q := r.URL.Query()
		f := repository.AlertInboxFoldedItemsFilter{
			TenantID:   user.TenantID, // 租户只取会话，绝不读请求里的 tenant_id
			Key:        strings.TrimSpace(q.Get("key")),
			Type:       strings.TrimSpace(q.Get("type")),
			Severity:   strings.TrimSpace(q.Get("severity")),
			UnreadOnly: q.Get("unread") == "true",
			Limit:      parseIntParam(q.Get("limit"), 20),
		}
		if o, err := strconv.Atoi(q.Get("offset")); err == nil && o > 0 {
			f.Offset = o
		}
		if f.Limit > 200 {
			f.Limit = 200
		}
		if f.Key == "" || f.Type == "" || f.Severity == "" {
			writeError(w, "invalid_request", "key, type and severity are required")
			return
		}
		var err error
		if f.DayStart, err = time.Parse(time.RFC3339, q.Get("day_start")); err != nil {
			writeError(w, "invalid_request", "day_start must be RFC3339")
			return
		}
		if f.DayEnd, err = time.Parse(time.RFC3339, q.Get("day_end")); err != nil {
			writeError(w, "invalid_request", "day_end must be RFC3339")
			return
		}
		if !f.DayStart.Before(f.DayEnd) || f.DayEnd.Sub(f.DayStart) > foldedItemsMaxWindow {
			writeError(w, "invalid_request", "day window must be a single day")
			return
		}
		_, f.TZ = locFor(r, user.TenantID)
		items, total, err := repo.ListFoldedItems(r.Context(), f)
		if err != nil {
			log.Printf("ListAlertInboxFoldedItems: %v", err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list alerts")
			return
		}
		inboxItemsForViewer(items, canReadFullTenantContentEvidence(user))
		writeJSON(w, map[string]any{"items": items, "total": total})
	}
}

// ---------- 管理员专用：类别汇总 / 预览 / 批量已读 ----------

func requireConsoleAdministrator(w http.ResponseWriter, r *http.Request) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "no user")
		return nil
	}
	if !roles.IsConsoleAdministrator(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return nil
	}
	return user
}

// AlertInboxTypeSummary handles GET /admin/v1/alerts/inbox/type-summary
func AlertInboxTypeSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		alertInboxTypeSummaryHandler(deps.AlertInboxRepo)(w, r)
	}
}

func alertInboxTypeSummaryHandler(repo inboxTypeSummaryReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireConsoleAdministrator(w, r)
		if user == nil {
			return
		}
		types, err := repo.TypeSummary(r.Context(), user.TenantID)
		if err != nil {
			log.Printf("AlertInboxTypeSummary: %v", err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to summarize alerts")
			return
		}
		writeJSON(w, map[string]any{"types": types})
	}
}

// parseBulkReadInstant 解析预览请求里的时间：精确的 RFC3339，或前端日期控件给的 YYYY-MM-DD（按租户时区，
// 结束日含当天）。预览会把归一化后的精确时刻回显，确认请求只接受这种精确时刻。
func parseBulkReadInstant(raw string, endOfDay bool, loc *time.Location) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("required")
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	t, err := time.ParseInLocation("2006-01-02", raw, loc)
	if err != nil {
		return time.Time{}, errors.New("must be RFC3339 or YYYY-MM-DD")
	}
	if endOfDay {
		t = t.AddDate(0, 0, 1)
	}
	return t.UTC(), nil
}

// bulkReadScopeError 把仓储层对范围的拒绝映射为 400 的稳定错误码。
func writeBulkReadScopeError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, repository.ErrBulkReadTypeProtected):
		writeError(w, "type_protected", "该类别的消息不支持批量已读，请逐条处理或到告警页按告警组处置")
	case errors.Is(err, repository.ErrBulkReadInvalid):
		writeError(w, "invalid_request", err.Error())
	default:
		return false
	}
	return true
}

// PreviewBulkReadAlertInbox handles GET /admin/v1/alerts/inbox/bulk-read/preview
func PreviewBulkReadAlertInbox(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		previewBulkReadHandler(deps.AlertInboxRepo, tenantReportLoc(deps))(w, r)
	}
}

func previewBulkReadHandler(repo inboxBulkReadPreviewer, locFor reportLocFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireConsoleAdministrator(w, r)
		if user == nil {
			return
		}
		q := r.URL.Query()
		typ := strings.TrimSpace(q.Get("type"))
		if typ == "" {
			writeError(w, "invalid_request", "type is required")
			return
		}
		loc, tz := locFor(r, user.TenantID)
		from, err := parseBulkReadInstant(q.Get("from"), false, loc)
		if err != nil {
			writeError(w, "invalid_request", "from "+err.Error())
			return
		}
		to, err := parseBulkReadInstant(q.Get("to"), true, loc)
		if err != nil {
			writeError(w, "invalid_request", "to "+err.Error())
			return
		}
		if err := repository.ValidateBulkReadScope(user.TenantID, typ, from, to); err != nil {
			writeBulkReadScopeError(w, err)
			return
		}
		preview, err := repo.PreviewBulkRead(r.Context(), user.TenantID, typ, from, to)
		if err != nil || preview == nil {
			if err != nil && writeBulkReadScopeError(w, err) {
				return
			}
			log.Printf("PreviewBulkReadAlertInbox: %v", err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to preview")
			return
		}
		writeJSON(w, map[string]any{
			"type":            typ,
			"from":            from.Format(time.RFC3339),
			"to":              to.Format(time.RFC3339),
			"matched_unread":  preview.Matched,
			"first_at":        preview.FirstAt,
			"last_at":         preview.LastAt,
			"severity_counts": preview.SeverityCounts,
			"timezone":        tz,
		})
	}
}

type bulkReadRequest struct {
	Type          string `json:"type"`
	From          string `json:"from"`
	To            string `json:"to"`
	ExpectedCount *int   `json:"expected_count"`
	Confirm       *bool  `json:"confirm"`
}

// BulkReadAlertInbox handles POST /admin/v1/alerts/inbox/bulk-read
func BulkReadAlertInbox(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}
		bulkReadAlertInboxHandler(deps, deps.AlertInboxRepo)(w, r)
	}
}

func bulkReadAlertInboxHandler(deps *Dependencies, repo inboxBulkReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireConsoleAdministrator(w, r)
		if user == nil {
			return
		}
		var req bulkReadRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, bulkReadBodyLimit))
		dec.DisallowUnknownFields() // 包括试图自带 tenant_id 的请求
		if err := dec.Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid request body")
			return
		}
		if req.Confirm == nil || !*req.Confirm {
			writeError(w, "invalid_request", "confirm must be true")
			return
		}
		typ := strings.TrimSpace(req.Type)
		if typ == "" {
			writeError(w, "invalid_request", "type is required")
			return
		}
		if req.ExpectedCount == nil || *req.ExpectedCount <= 0 {
			writeError(w, "invalid_request", "expected_count must be a positive number")
			return
		}
		// 确认请求只接受预览回显的精确时刻（RFC3339），不接受有歧义的日期形式。
		from, err := time.Parse(time.RFC3339, strings.TrimSpace(req.From))
		if err != nil {
			writeError(w, "invalid_request", "from must be RFC3339")
			return
		}
		to, err := time.Parse(time.RFC3339, strings.TrimSpace(req.To))
		if err != nil {
			writeError(w, "invalid_request", "to must be RFC3339")
			return
		}
		from, to = from.UTC(), to.UTC()
		// 到达仓储之前先按同一份规则校验：受保护类别、倒置/过长的范围在这里就被拒绝。
		if err := repository.ValidateBulkReadScope(user.TenantID, typ, from, to); err != nil {
			writeBulkReadScopeError(w, err)
			return
		}

		opID := uuid.New().String()
		marked, err := repo.BulkMarkRead(r.Context(), repository.BulkReadParams{
			TenantID: user.TenantID, Type: typ, From: from, To: to, ExpectedCount: *req.ExpectedCount,
			Audit: &repository.AuditOperation{
				ID: opID, UserID: user.ID, ActionType: bulkReadActionType,
				TargetType: "alert_inbox", TargetID: typ, IPAddress: r.RemoteAddr,
				ActionDetail: map[string]interface{}{"scope_note": "仅更新消息中心已读状态，不关闭告警、不删除数据"},
			},
		})
		if err != nil {
			var changed *repository.BulkReadCountChangedError
			switch {
			case errors.As(err, &changed):
				writeErrorWithStatusAndDetails(w, http.StatusConflict, "count_changed",
					fmt.Sprintf("范围内的未读数已变化（现为 %d 条），请重新查询后再确认", changed.Current),
					map[string]any{"current_count": changed.Current})
			case writeBulkReadScopeError(w, err):
			default:
				log.Printf("BulkReadAlertInbox tenant=%s type=%s: %v", user.TenantID, typ, err)
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to mark messages as read")
			}
			return
		}
		// 审计已随事务落库；这里把同一条记录追加进审计链（链路异常不影响已提交的结果）。
		if deps != nil {
			appendAuditChain(r.Context(), deps, user.TenantID, bulkReadActionType, opID, map[string]interface{}{
				"tenant_id": user.TenantID, "type": typ, "marked_read": marked,
				"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339),
			})
		}
		writeJSON(w, map[string]any{
			"ok": true, "marked_read": marked, "type": typ,
			"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339),
		})
	}
}
