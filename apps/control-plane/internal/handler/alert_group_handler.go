package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type alertGroupDTO struct {
	ID                    string                      `json:"id"`
	Severity              string                      `json:"severity"`
	Status                repository.AlertGroupStatus `json:"status"`
	Type                  string                      `json:"type"`
	Title                 string                      `json:"title"`
	OccurrenceCount       int                         `json:"occurrence_count"`
	FirstSeenAt           string                      `json:"first_seen_at"`
	LastSeenAt            string                      `json:"last_seen_at"`
	RepresentativeEventID string                      `json:"representative_event_id,omitempty"`
	RequestID             string                      `json:"request_id,omitempty"`
	SourceIP              string                      `json:"source_ip,omitempty"`
	PrincipalKey          string                      `json:"principal_key,omitempty"`
	AccessDirection       string                      `json:"access_direction,omitempty"`
	// P0-A/C 生命周期与情境字段（供收件箱三档/按类折叠/置信·执法 chip）：
	EffectiveSeverity string `json:"effective_severity,omitempty"`
	DispositionClass  string `json:"disposition_class,omitempty"`
	ClassKey          string `json:"class_key,omitempty"`
	Stage             string `json:"stage,omitempty"`
	IsCanary          bool   `json:"is_canary"`
	// Domain 风险域维度（迁移 941）：content | tool | skill | mcp | access | system。
	Domain string `json:"domain,omitempty"`
	// RuleName 取自组 body_json.rule_name（中文规则名），供积压处置列表展示与筛选。
	RuleName string `json:"rule_name,omitempty"`
	// P1-D 主指标：last_calc_at 为空 = 存量回算未覆盖（前端显示 occurrence_count + "回算中"）
	DistinctOccurrences int    `json:"distinct_occurrences"`
	AffectedUsers       int    `json:"affected_users"`
	LastCalcAt          string `json:"last_calc_at,omitempty"`
}

func ListAlertGroups(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AlertGroupRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert groups not configured")
			return
		}
		limit, offset := 20, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
				offset = n
			}
		}
		filter := repository.AlertGroupListFilter{
			TenantID:         user.TenantID,
			Status:           repository.AlertGroupStatus(r.URL.Query().Get("status")),
			Severity:         r.URL.Query().Get("severity"),
			DispositionClass: r.URL.Query().Get("disposition_class"),
			AccessDirection:  r.URL.Query().Get("access_direction"),
			Domain:           strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain"))),
			AlertType:        strings.TrimSpace(r.URL.Query().Get("type")),
			Rule:             strings.TrimSpace(r.URL.Query().Get("rule")),
			Limit:            limit,
			Offset:           offset,
		}
		// 时间范围按最近发生时间（last_seen_at）过滤，只接受 RFC3339（前端已按租户时区换算）。
		for key, dst := range map[string]*time.Time{"from": &filter.LastSeenFrom, "to": &filter.LastSeenTo} {
			if raw := strings.TrimSpace(r.URL.Query().Get(key)); raw != "" {
				parsed, err := time.Parse(time.RFC3339, raw)
				if err != nil {
					writeError(w, "invalid_request", key+" must be RFC3339")
					return
				}
				*dst = parsed
			}
		}
		// 显式展开受信开发作用域的语义/运行组；其它风险类别始终可见。
		if raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_dev"))); raw == "true" || raw == "1" || raw == "yes" {
			filter.IncludeDevTraffic = true
		}
		// dept_manager 等非管理员：告警只看本部门（本人团队的 project 集）。
		// 本部门无 project → 直接空（fail-closed）。
		if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant {
			if len(scope.ProjectIDs) == 0 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"items": []alertGroupDTO{}, "total": 0, "has_alert_groups": false,
					"limit": limit, "offset": offset,
				})
				return
			}
			filter.ProjectIDs = scope.ProjectIDs
		}
		if pager, ok := deps.AlertGroupRepo.(AlertGroupPageRepo); ok {
			page, err := pager.ListPage(r.Context(), filter)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
				return
			}
			items := make([]alertGroupDTO, 0, len(page.Items))
			for _, group := range page.Items {
				items = append(items, toAlertGroupDTO(group))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": items, "total": page.Total, "has_alert_groups": page.HasAny,
				"limit": page.Limit, "offset": page.Offset, "folded_development_groups": page.FoldedDevelopmentGroups,
			})
			return
		}
		// Backward-compatible fallback for old adapters/test doubles.
		groups, err := deps.AlertGroupRepo.List(r.Context(), filter)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		items := make([]alertGroupDTO, 0, len(groups))
		for _, group := range groups {
			items = append(items, toAlertGroupDTO(group))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": items, "total": len(items), "has_alert_groups": len(items) > 0,
			"limit": limit, "offset": offset,
		})
	}
}

func GetAlertGroup(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AlertGroupRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert groups not configured")
			return
		}
		group, err := deps.AlertGroupRepo.GetByID(r.Context(), user.TenantID, chi.URLParam(r, "id"))
		if errors.Is(err, repository.ErrNotFound) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "alert group not found")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		// dept_manager 等非管理员：越权看别部门告警组 404。
		if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant && !containsStr(scope.ProjectIDs, group.ProjectID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "alert group not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"item": toAlertGroupDTO(group)})
	}
}

func UpdateAlertGroupStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AlertGroupRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert groups not configured")
			return
		}
		var body struct {
			Status repository.AlertGroupStatus `json:"status"`
			Note   string                      `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, "invalid_request", "invalid json body")
			return
		}
		if !isAllowedAlertGroupStatus(body.Status) {
			writeError(w, "invalid_request", "invalid alert group status")
			return
		}
		group, err := deps.AlertGroupRepo.UpdateStatus(r.Context(), user.TenantID, chi.URLParam(r, "id"), body.Status, user.ID, body.Note)
		if errors.Is(err, repository.ErrNotFound) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "alert group not found")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "alert_group.status", map[string]any{"alert_group_id": group.ID, "status": group.Status}, "alert_group", group.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"item": toAlertGroupDTO(group)})
	}
}

func toAlertGroupDTO(group *repository.AlertGroup) alertGroupDTO {
	if group == nil {
		return alertGroupDTO{}
	}
	return alertGroupDTO{
		ID:                    group.ID,
		Severity:              group.Severity,
		Status:                group.Status,
		Type:                  group.AlertType,
		Title:                 group.Title,
		OccurrenceCount:       group.OccurrenceCount,
		FirstSeenAt:           group.FirstSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		LastSeenAt:            group.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		RepresentativeEventID: group.RepresentativeEventID,
		RequestID:             group.RequestID,
		SourceIP:              group.SourceIP,
		AccessDirection:       group.AccessDirection,
		PrincipalKey:          customerVisibleCorrelationValue(group.PrincipalKey),
		EffectiveSeverity:     group.EffectiveSeverity,
		DispositionClass:      group.DispositionClass,
		ClassKey:              group.ClassKey,
		Stage:                 group.Stage,
		IsCanary:              group.IsCanary,
		Domain:                group.Domain,
		DistinctOccurrences:   group.DistinctOccurrences,
		AffectedUsers:         group.AffectedUsers,
		LastCalcAt:            formatAlertGroupCalcAt(group.LastCalcAt),
		RuleName:              alertGroupRuleName(group.BodyJSON),
	}
}

func alertGroupRuleName(body map[string]any) string {
	name, _ := body["rule_name"].(string)
	return strings.TrimSpace(name)
}

// formatAlertGroupCalcAt 把 to_timestamp(0) 哨兵（未回算）格式化为空串。
func formatAlertGroupCalcAt(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z07:00")
}

func isAllowedAlertGroupStatus(status repository.AlertGroupStatus) bool {
	switch status {
	case repository.AlertGroupStatusOpen, repository.AlertGroupStatusAcknowledged, repository.AlertGroupStatusResolved, repository.AlertGroupStatusFalsePositive:
		return true
	}
	return false
}

// ListAlertGroupEvents 返回告警组"发生明细"分页时间线（3b 详情第三段）。
// 口径：仅含已回填 alert_group_id 的进组事件；被抑制/FP 静默事件不在此列（留证照存）。
func ListAlertGroupEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AlertGroupRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert groups not configured")
			return
		}
		limit, offset := 20, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
				offset = n
			}
		}
		view := repository.AlertGroupEventView(r.URL.Query().Get("view"))
		if view == "" {
			view = repository.AlertGroupEventViewEvents
		}
		if view != repository.AlertGroupEventViewEvents && view != repository.AlertGroupEventViewConversations {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "view must be events or conversations")
			return
		}
		conversationKey := strings.TrimSpace(r.URL.Query().Get("conversation_key"))
		if conversationKey != "" && view != repository.AlertGroupEventViewEvents {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "conversation_key is only supported for events view")
			return
		}
		// dept_manager 等非管理员：先校验该告警组属本部门，否则 404（防按 id 掏别部门明细）。
		if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant {
			g, gerr := deps.AlertGroupRepo.GetByID(r.Context(), user.TenantID, chi.URLParam(r, "id"))
			if gerr != nil || !containsStr(scope.ProjectIDs, g.ProjectID) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "alert group not found")
				return
			}
		}
		events, total, err := deps.AlertGroupRepo.ListGroupEvents(r.Context(), user.TenantID, chi.URLParam(r, "id"), repository.AlertGroupEventListFilter{
			View:            view,
			ConversationKey: conversationKey,
			Limit:           limit,
			Offset:          offset,
		})
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		items := make([]alertGroupEventDTO, 0, len(events))
		for _, event := range events {
			items = append(items, toAlertGroupEventDTO(event))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "total": total})
	}
}
