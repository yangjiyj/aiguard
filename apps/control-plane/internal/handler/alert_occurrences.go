package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type AlertOccurrenceReader interface {
	List(context.Context, repository.AlertOccurrenceFilter) (*repository.AlertOccurrencePage, error)
}

type AlertCaseSummaryReader interface {
	SummarizeCases(context.Context, repository.AlertOccurrenceFilter) (*repository.AlertCaseSummary, error)
}

type AlertOperationalEventReader interface {
	ListOperational(context.Context, repository.AlertOccurrenceFilter) (*repository.AlertOperationalPage, error)
}

type AlertOperationalSummaryReader interface {
	SummarizeOperational(context.Context, repository.AlertOccurrenceFilter) (*repository.AlertOperationalBreakdown, error)
}

const (
	alertViewOccurrences = iota
	alertViewOperationalList
	alertViewOperationalSummary
	alertViewCaseSummary
)

func SummarizeAlertCases(deps *Dependencies) http.HandlerFunc {
	return listAlertOccurrenceView(deps, alertViewCaseSummary)
}

func ListAlertOccurrences(deps *Dependencies) http.HandlerFunc {
	return listAlertOccurrenceView(deps, alertViewOccurrences)
}

func ListAlertOperationalEvents(deps *Dependencies) http.HandlerFunc {
	return listAlertOccurrenceView(deps, alertViewOperationalList)
}

// SummarizeAlertOperationalEvents serves the coverage-gap breakdown for the same
// scope as the list: range total, last 24 hours, blocked requests and reasons.
func SummarizeAlertOperationalEvents(deps *Dependencies) http.HandlerFunc {
	return listAlertOccurrenceView(deps, alertViewOperationalSummary)
}

func listAlertOccurrenceView(deps *Dependencies, view int) http.HandlerFunc {
	operational := view == alertViewOperationalList || view == alertViewOperationalSummary
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if user.DepartmentAssignmentMode == "emergency" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "alert occurrences not found")
			return
		}
		f, err := parseAlertOccurrenceFilter(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if view == alertViewCaseSummary {
			if f.Grouping != "" && f.Grouping != "cases" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "case summary requires cases grouping")
				return
			}
			f.Grouping = "cases"
			f.IncludeRaw = false
			f.RecentLimit = 0
		}
		f.TenantID = user.TenantID
		if operational && (f.Grouping != "" || f.CaseID != "") {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "operational events are separate from risk cases")
			return
		}
		if operational && f.Disposition != "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "operational events do not have disposition tabs")
			return
		}
		if operational && (f.Severity != "" || f.Category != "") {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "operational events do not have attack severity/category filters")
			return
		}
		if !operational && f.Reason != "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "attack occurrences do not have a runtime reason filter")
			return
		}
		if view == alertViewOperationalSummary && f.Reason != "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "operational summary is not filtered by reason")
			return
		}
		f.CanReadEvidence = canReadFullTenantContentEvidence(user)
		f.CanViewRawEvidence = canViewRawEvidenceUser(user)
		if f.IncludeRaw && !f.CanReadEvidence {
			if operational {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "content evidence not found")
				return
			}
			// 列表、汇总、命中明细：前端按角色带了 include_raw 但账号没有内容证据权限（旧 admin 角色、部门
			// 管理员等）时按不带原文返回，不让整页 404；响应里的 evidence_readable 告诉前端不能看证据。
			f.IncludeRaw = false
		}
		w.Header().Set("Cache-Control", "no-store")
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "invalid scope")
			return
		}
		if !scope.FullTenant {
			// Empty authorization is an empty result, never an omitted filter.
			f.ProjectIDs = append([]string{}, scope.ProjectIDs...)
			if len(f.ProjectIDs) == 0 {
				if view == alertViewCaseSummary {
					writeJSON(w, repository.AlertCaseSummary{CountUnit: "triage_cases", Categories: []repository.AlertCaseCategoryCount{}})
				} else if view == alertViewOperationalSummary {
					writeJSON(w, repository.AlertOperationalBreakdown{CountUnit: "security_events", Reasons: []repository.AlertOperationalReasonCount{}})
				} else if operational {
					writeJSON(w, repository.AlertOperationalPage{Items: []repository.AlertOperationalEvent{}, Limit: f.Limit, Offset: f.Offset, CountUnit: "security_events"})
				} else {
					writeJSON(w, repository.AlertOccurrencePage{Items: []repository.AlertOccurrence{}, Limit: f.Limit, Offset: f.Offset, Operational: repository.AlertOperationalSummary{CountUnit: "security_events", ListURL: alertOperationalListURL(r)}})
				}
				return
			}
		}
		if deps == nil || deps.AlertOccurrenceRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert occurrences not configured")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if view == alertViewCaseSummary {
			reader, ok := deps.AlertOccurrenceRepo.(AlertCaseSummaryReader)
			if !ok {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert summary not configured")
				return
			}
			summary, err := reader.SummarizeCases(ctx, f)
			if err != nil {
				log.Printf("SummarizeAlertCases: %v", err)
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to summarize alert cases")
				return
			}
			writeJSON(w, summary)
			return
		}
		if view == alertViewOperationalSummary {
			reader, ok := deps.AlertOccurrenceRepo.(AlertOperationalSummaryReader)
			if !ok {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "operational summary not configured")
				return
			}
			summary, err := reader.SummarizeOperational(ctx, f)
			if err != nil {
				log.Printf("SummarizeAlertOperationalEvents: %v", err)
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to summarize operational events")
				return
			}
			writeJSON(w, summary)
			return
		}
		if operational {
			reader, ok := deps.AlertOccurrenceRepo.(AlertOperationalEventReader)
			if !ok {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "operational events not configured")
				return
			}
			page, err := reader.ListOperational(ctx, f)
			if err != nil {
				log.Printf("ListAlertOperationalEvents: %v", err)
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list operational events")
				return
			}
			writeJSON(w, page)
			return
		}
		page, err := deps.AlertOccurrenceRepo.List(ctx, f)
		if err != nil {
			log.Printf("ListAlertOccurrences: %v", err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list alert occurrences")
			return
		}
		// Enforce the content contract at the HTTP boundary as well as in SQL.
		page.EvidenceReadable = f.CanReadEvidence
		page.Operational.CountUnit = "security_events"
		page.Operational.CountKnown = f.Grouping != "cases" && f.CaseID == ""
		page.Operational.ListURL = alertOperationalListURL(r)
		for i := range page.Items {
			if !f.IncludeRaw || !f.CanReadEvidence {
				page.Items[i].RawEvidence = ""
				page.Items[i].RawEvidenceTruncated = false
				page.Items[i].MatchedTextPreview = ""
				page.Items[i].EvidenceContext = ""
			}
			if !f.CanReadEvidence {
				page.Items[i].Reason = ""
				if page.Items[i].ReasonStatus == "available" {
					page.Items[i].ReasonStatus = "restricted"
				}
				page.Items[i].RawEvidenceStatus = "restricted"
			}
		}
		writeJSON(w, page)
	}
}

// Preserve only metadata scope; attack filters and raw-content flags do not
// belong on a coverage-gap link. Authorization is re-evaluated when it is read.
func alertOperationalListURL(r *http.Request) string {
	q := url.Values{}
	for _, key := range []string{"project_id", "request_id", "conversation_key", "session_id", "user_id", "start_time", "end_time"} {
		if value := strings.TrimSpace(r.URL.Query().Get(key)); value != "" {
			q.Set(key, value)
		}
	}
	path := "/admin/v1/security/alert-occurrences/operational"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return path
}

func parseAlertOccurrenceFilter(r *http.Request) (repository.AlertOccurrenceFilter, error) {
	q := r.URL.Query()
	f := repository.AlertOccurrenceFilter{IncludeDevTraffic: q.Get("include_dev") == "true", Grouping: strings.TrimSpace(q.Get("grouping")), CaseID: strings.TrimSpace(q.Get("case_id")), EventID: strings.TrimSpace(q.Get("event_id")), Disposition: strings.TrimSpace(q.Get("disposition")), Limit: 20, RequestID: strings.TrimSpace(q.Get("request_id")),
		ProjectID: strings.TrimSpace(q.Get("project_id")), ConversationKey: strings.TrimSpace(q.Get("conversation_key")),
		SessionID: strings.TrimSpace(q.Get("session_id")), UserID: strings.TrimSpace(q.Get("user_id")),
		Severity: strings.ToLower(strings.TrimSpace(q.Get("severity"))), Category: strings.TrimSpace(q.Get("category")),
		Reason: strings.ToLower(strings.TrimSpace(q.Get("reason")))}
	if f.Grouping != "" && f.Grouping != "cases" && f.Grouping != "hits" {
		return f, fmt.Errorf("invalid grouping")
	}
	// lane 参数打开车道分流；缺省保持全局口径（老客户端、导出、下钻都不受影响）。
	// 车道只作用于 cases 视图，其它视图带 lane 一律拒绝，避免静默忽略后被当成"该车道无告警"。
	if _, present := q["lane"]; present {
		if f.Grouping != "cases" {
			return f, fmt.Errorf("lane requires grouping=cases")
		}
		switch lane := strings.TrimSpace(q.Get("lane")); lane {
		case "all", "":
			f.LaneAware = true
		case "action", "watch", "eval":
			f.LaneAware, f.Lane = true, lane
		default:
			return f, fmt.Errorf("invalid lane")
		}
	}
	if raw := q.Get("recent_limit"); raw != "" {
		if raw != "100" || f.Grouping != "cases" {
			return f, fmt.Errorf("recent_limit requires grouping=cases and value 100")
		}
		f.RecentLimit = 100
	}
	if f.CaseID != "" {
		if len(f.CaseID) != 36 || !strings.HasPrefix(f.CaseID, "ac1_") {
			return f, fmt.Errorf("invalid case id")
		}
		for _, c := range f.CaseID[4:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return f, fmt.Errorf("invalid case id")
			}
		}
	}
	switch f.Disposition {
	case "", "all", "pending", "handled", "false_positive":
	default:
		return f, fmt.Errorf("invalid disposition")
	}
	if f.Disposition == "all" || f.Disposition == "false_positive" {
		f.IncludeSuppressed = true
	}
	if f.Reason != "" {
		for _, r := range f.Reason {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
				return f, fmt.Errorf("invalid reason")
			}
		}
		if len(f.Reason) > 64 {
			return f, fmt.Errorf("invalid reason")
		}
	}
	for _, field := range []struct {
		key string
		dst *int
		min int
	}{{"limit", &f.Limit, 1}, {"offset", &f.Offset, 0}} {
		if raw := q.Get(field.key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < field.min {
				return f, fmt.Errorf("invalid %s", field.key)
			}
			*field.dst = n
		}
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	for _, field := range []struct {
		key string
		dst *bool
	}{{"include_raw", &f.IncludeRaw}, {"include_suppressed", &f.IncludeSuppressed}} {
		if raw := q.Get(field.key); raw != "" {
			value, err := strconv.ParseBool(raw)
			if err != nil {
				return f, fmt.Errorf("invalid %s", field.key)
			}
			*field.dst = value
		}
	}
	switch f.Severity {
	case "", "critical", "high", "medium", "low", "unknown":
	default:
		return f, fmt.Errorf("invalid severity")
	}
	for _, field := range []struct {
		key string
		dst **time.Time
	}{{"start_time", &f.StartTime}, {"end_time", &f.EndTime}} {
		if raw := q.Get(field.key); raw != "" {
			value, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return f, fmt.Errorf("invalid %s: expected RFC3339", field.key)
			}
			*field.dst = &value
		}
	}
	if f.StartTime != nil && f.EndTime != nil && !f.StartTime.Before(*f.EndTime) {
		return f, fmt.Errorf("start_time must be before end_time")
	}
	return f, nil
}

// AlertCaseStoreStatusReader 给出告警案件物化表的诊断状态（能否使用、原因、触发器定义摘要、队列与隔离条目）。
type AlertCaseStoreStatusReader interface {
	AlertCaseStoreStatus(ctx context.Context, tenant string) (repository.AlertCaseStoreStatus, error)
}

// GetAlertCaseStoreStatus 只给平台管理员：告警读接口为什么在走实时查询（触发器定义摘要不一致、回填未完成、
// 有隔离的坏条目、积压超限等），排查与运维核对用。tenant_id 为空时只看全局状态。
func GetAlertCaseStoreStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can read the alert case store status")
			return
		}
		var reader AlertCaseStoreStatusReader
		if deps != nil && deps.AlertOccurrenceRepo != nil {
			reader, _ = deps.AlertOccurrenceRepo.(AlertCaseStoreStatusReader)
		}
		if reader == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "unavailable", "alert case store status is unavailable")
			return
		}
		status, err := reader.AlertCaseStoreStatus(r.Context(), strings.TrimSpace(r.URL.Query().Get("tenant_id")))
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "read alert case store status failed")
			return
		}
		writeJSON(w, status)
	}
}
