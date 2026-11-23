package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/go-chi/chi/v5"
)

type contentAlertEvidenceChain struct {
	Event       types.SecurityEventInfo             `json:"event"`
	Attribution *repository.RequestEvidenceMetadata `json:"attribution,omitempty"`
	Context     []repository.ContentLog             `json:"context"`
}

type contentAlertExport struct {
	SessionID      string                      `json:"session_id"`
	ExportedAt     string                      `json:"exported_at"`
	EvidenceChains []contentAlertEvidenceChain `json:"evidence_chains"`
	ContentLogs    []repository.ContentLog     `json:"content_logs"`
}

func exportableSecurityEvent(event *repository.SecurityEvent) bool {
	findings, ok := event.MatchedSummary["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		return true
	}
	for _, raw := range findings {
		finding, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if value, exists := finding["counts_as_security_finding"]; exists {
			if counted, ok := value.(bool); ok && !counted {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(contentAuditString(value)), "false") {
				continue
			}
		}
		category := strings.ToLower(strings.TrimSpace(contentAuditString(finding["category"])))
		ruleType := strings.ToLower(strings.TrimSpace(contentAuditString(finding["rule_type"])))
		if ruleType == "agent_detect" && strings.HasPrefix(category, "agent_") && !strings.HasPrefix(category, "agent_canary") {
			continue
		}
		return true
	}
	return false
}

func contentAuditString(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func contentAuditKeywordSearchFilter(
	tenantID, keyword string,
	startTime, endTime time.Time,
	limit, offset int,
) repository.ContentLogSearchFilter {
	return repository.ContentLogSearchFilter{
		TenantID: tenantID, Keyword: keyword, StartTime: startTime, EndTime: endTime,
		Limit: limit, Offset: offset, SkipTotal: true,
	}
}

// ListContentAudit returns content logs with pagination
func ListContentAudit(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, authOK := authenticatedContentEvidenceUser(w, r)
		if !authOK {
			return
		}
		if user.DepartmentAssignmentMode == "emergency" {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "content evidence not found")
			return
		}

		// Check if content audit is enabled
		enabled, err := deps.SystemRepo.GetBool(r.Context(), "content_audit_enabled")
		if err != nil || !enabled {
			writeError(w, "feature_disabled", "内容审计功能未启用")
			return
		}

		alertOnly := parseBoolParam(r.URL.Query().Get("alert_only"))
		var visibleProjectIDs []string
		if !canReadFullTenantContentEvidence(user) {
			if !scopedContentAlertMetadataRequestAllowed(r) {
				writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "content evidence is not available for this role")
				return
			}
			scope, ok := resolveUsageScope(r, deps)
			if !ok || len(scope.ProjectIDs) == 0 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]interface{}{}, "total": 0, "type": "sessions", "has_more": false})
				return
			}
			visibleProjectIDs = scope.ProjectIDs
		}

		scope, windowStart, windowEnd, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}

		limit := 20
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		if limit > 100 {
			limit = 100
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		// Filter by user or session
		userID := r.URL.Query().Get("user_id")
		sessionID := r.URL.Query().Get("session_id")
		keyword, keywordOK := validatedAuditKeyword(w, r.URL.Query().Get("keyword"))
		if !keywordOK {
			return
		}
		categories, severities, dispositions, filtersOK := parseContentAuditAlertFilters(w, r)
		if !filtersOK {
			return
		}

		var logs []repository.ContentLog
		var total int

		if !alertOnly && sessionID != "" {
			logs, err = deps.ContentLogRepo.ListBySessionScoped(r.Context(), user.TenantID, sessionID, windowStart, windowEnd, scope)
			total = len(logs)
		} else if !alertOnly && userID != "" {
			logs, total, err = deps.ContentLogRepo.ListByUserScoped(r.Context(), user.TenantID, userID, limit, offset, windowStart, windowEnd, scope)
		} else if !alertOnly && keyword != "" {
			if !validateAuditKeywordWindow(w, keyword, windowStart, windowEnd) {
				return
			}
			queryCtx, finishSearch, searchOK := beginAuditKeywordSearch(w, r, user.TenantID, keyword)
			if !searchOK {
				return
			}
			defer finishSearch()
			searchFilter := contentAuditKeywordSearchFilter(
				user.TenantID, keyword, windowStart, windowEnd, limit, offset,
			)
			searchFilter.EnvironmentScope = scope
			logs, total, err = deps.ContentLogRepo.SearchPage(queryCtx, searchFilter)
		} else {
			queryCtx := r.Context()
			finishSearch := func() {}
			if keyword != "" {
				if !validateAuditKeywordWindow(w, keyword, windowStart, windowEnd) {
					return
				}
				var searchOK bool
				queryCtx, finishSearch, searchOK = beginAuditKeywordSearch(w, r, user.TenantID, keyword)
				if !searchOK {
					return
				}
			}
			defer finishSearch()
			fetchLimit := limit
			if alertOnly {
				// One extra row is enough to expose a truthful next page without making
				// the first screen wait for a 10M-row exact session count.
				fetchLimit++
			}
			sessions, sessionTotal, err := deps.ContentLogRepo.ListSessionsFiltered(queryCtx, repository.ContentSessionListFilter{
				TenantID: user.TenantID, EnvironmentScope: scope,
				ProjectIDs:   visibleProjectIDs,
				UserID:       userID,
				Keyword:      keyword,
				Categories:   categories,
				Severities:   severities,
				Dispositions: dispositions,
				StartTime:    windowStart,
				EndTime:      windowEnd,
				Limit:        fetchLimit,
				Offset:       offset,
				SkipTotal:    alertOnly || parseBoolParam(r.URL.Query().Get("skip_total")),
				AlertOnly:    alertOnly,
			})
			if err != nil {
				if keyword != "" {
					writeAuditKeywordQueryError(w, err, "failed to list sessions")
				} else {
					writeError(w, "internal_error", "failed to list sessions")
				}
				return
			}
			if alertOnly {
				hasMore := len(sessions) > limit
				if hasMore {
					sessions = sessions[:limit]
				}
				sessionTotal = offset + len(sessions)
				if hasMore {
					sessionTotal++
				}
			}
			// alert_only 已在服务端候选集分页前完成过滤，禁止取一页审计会话后再在浏览器里筛。
			filtered := make([]map[string]interface{}, 0, len(sessions))
			for _, s := range sessions {
				customerVisibleSession(s)
				if alertOnly {
					filtered = append(filtered, s)
					continue
				}
				secCount, _ := s["security_event_count"].(int)
				ruleCount, _ := s["matched_rule_count"].(int)
				if secCount > 0 || ruleCount > 0 {
					filtered = append(filtered, s)
				}
			}
			resp := map[string]interface{}{
				"data":     filtered,
				"total":    sessionTotal,
				"type":     "sessions",
				"has_more": alertOnly && sessionTotal > offset+len(filtered),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		if err != nil {
			writeAuditKeywordQueryError(w, err, "failed to list content logs")
			return
		}

		resp := map[string]interface{}{
			"data":  logs,
			"total": total,
			"type":  "messages",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

const (
	sessionContentPreviewBytes    = 64 * 1024
	sessionContentTruncatedSuffix = "\n\n[内容过长，当前显示预览；完整原文请使用导出]"
)

func truncateSessionContent(content string) (string, bool) {
	if len(content) <= sessionContentPreviewBytes {
		return content, false
	}

	end := sessionContentPreviewBytes
	for end > 0 && !utf8.ValidString(content[:end]) {
		end--
	}
	return content[:end] + sessionContentTruncatedSuffix, true
}

func contentAuditPageParams(r *http.Request, defaultLimit int) (int, int) {
	limit := defaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 100 {
		limit = 100
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return limit, offset
}

func contentAuditTotalValue(total int) (interface{}, bool) {
	if total < 0 {
		return nil, false
	}
	return total, true
}

// GetSessionContent returns full conversation for a session

// GetSessionContent 返回带证据读取审计的 handler（Low-2）：读取成功后写 evidence.read，见 AuditEvidenceRead。
func GetSessionContent(deps *Dependencies) http.HandlerFunc {
	return auditedEvidenceHandler(deps, "session_content", getSessionContentInner(deps))
}

func getSessionContentInner(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}

		enabled, err := deps.SystemRepo.GetBool(r.Context(), "content_audit_enabled")
		if err != nil || !enabled {
			writeError(w, "feature_disabled", "内容审计功能未启用")
			return
		}

		sessionID := chi.URLParam(r, "session_id")
		if sessionID == "" {
			writeError(w, "invalid_request", "session_id required")
			return
		}

		scope, windowStart, windowEnd, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		view := strings.TrimSpace(r.URL.Query().Get("view"))
		if view == "" {
			view = "manager"
		}
		if view != "manager" && view != "all" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "view must be manager or all")
			return
		}
		defaultLimit := 100
		if view == "all" {
			defaultLimit = 20
		}
		limit, offset := contentAuditPageParams(r, defaultLimit)
		logs, total, err := deps.ContentLogRepo.ListBySessionPageScoped(r.Context(), user.TenantID, sessionID, view == "all", limit, offset, windowStart, windowEnd, scope)
		if err != nil {
			writeError(w, "internal_error", "failed to get session content")
			return
		}
		for i := range logs {
			logs[i].Content, logs[i].ContentTruncated = truncateSessionContent(logs[i].Content)
		}
		totalValue, totalKnown := contentAuditTotalValue(total)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": logs, "total": totalValue, "total_known": totalKnown, "limit": limit, "offset": offset,
			"has_more": totalKnown && offset < total && len(logs) < total-offset, "type": "messages",
		})
	}
}

// GetSessionSecurityEvents returns security findings tied to a content audit session.
func GetSessionSecurityEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}

		enabled, err := deps.SystemRepo.GetBool(r.Context(), "content_audit_enabled")
		if err != nil || !enabled {
			writeError(w, "feature_disabled", "内容审计功能未启用")
			return
		}

		sessionID := chi.URLParam(r, "session_id")
		if sessionID == "" {
			writeError(w, "invalid_request", "session_id required")
			return
		}

		scope, windowStart, windowEnd, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		limit, offset := contentAuditPageParams(r, 20)
		events, hasMore, err := deps.SecurityEventRepo.ListByContentSessionPageScoped(
			r.Context(), user.TenantID, sessionID, windowStart, windowEnd, scope, limit, offset,
		)
		if err != nil {
			writeError(w, "internal_error", "failed to get session security events")
			return
		}

		canReadEvidence := canReadFullTenantContentEvidence(user)
		data := make([]types.SecurityEventInfo, len(events))
		for i, event := range events {
			data[i] = securityEventInfoForViewer(event, canReadEvidence)
		}

		w.Header().Set("Content-Type", "application/json")
		var total interface{}
		totalKnown := !hasMore
		if totalKnown {
			total = offset + len(data)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": data, "total": total, "total_known": totalKnown, "limit": limit,
			"offset": offset, "has_more": hasMore, "type": "events",
		})
	}
}

// ExportSessionContent exports session content as JSON or plain text

// ExportSessionContent 返回带证据读取审计的 handler（Low-2）：读取成功后写 evidence.read，见 AuditEvidenceRead。
func ExportSessionContent(deps *Dependencies) http.HandlerFunc {
	return auditedEvidenceHandler(deps, "session_export", exportSessionContentInner(deps))
}

func exportSessionContentInner(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}

		enabled, err := deps.SystemRepo.GetBool(r.Context(), "content_audit_enabled")
		if err != nil || !enabled {
			writeError(w, "feature_disabled", "内容审计功能未启用")
			return
		}

		sessionID := chi.URLParam(r, "session_id")
		scope, windowStart, windowEnd, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}

		logs, err := deps.ContentLogRepo.ListBySessionScoped(r.Context(), user.TenantID, sessionID, windowStart, windowEnd, scope)
		if err != nil {
			writeError(w, "internal_error", "failed to get session content")
			return
		}

		var events []*repository.SecurityEvent
		if scoped, ok := interface{}(deps.SecurityEventRepo).(interface {
			ListByContentSessionScoped(context.Context, string, string, time.Time, time.Time, string) ([]*repository.SecurityEvent, error)
		}); ok {
			events, err = scoped.ListByContentSessionScoped(r.Context(), user.TenantID, sessionID, windowStart, windowEnd, scope)
		} else {
			events, err = deps.SecurityEventRepo.ListByContentSession(r.Context(), user.TenantID, sessionID)
		}
		if err != nil {
			writeError(w, "internal_error", "failed to get session security events")
			return
		}

		chains := make([]contentAlertEvidenceChain, 0, len(events))
		for _, event := range events {
			if !exportableSecurityEvent(event) {
				continue
			}
			contextLogs := make([]repository.ContentLog, 0)
			for _, item := range logs {
				if item.RequestID == event.RequestID {
					contextLogs = append(contextLogs, item)
				}
			}
			var attribution *repository.RequestEvidenceMetadata
			if deps.RequestLogRepo != nil {
				attribution, err = deps.RequestLogRepo.GetEvidenceMetadataScoped(
					r.Context(), user.TenantID, event.RequestID, windowStart, windowEnd, scope,
				)
				if err != nil {
					writeError(w, "internal_error", "failed to get request attribution")
					return
				}
			}
			chains = append(chains, contentAlertEvidenceChain{
				Event:       securityEventInfoForViewer(event, canReadFullTenantContentEvidence(user)),
				Attribution: attribution,
				Context:     contextLogs,
			})
		}

		exported := contentAlertExport{
			SessionID:      sessionID,
			ExportedAt:     time.Now().UTC().Format(time.RFC3339),
			EvidenceChains: chains,
			ContentLogs:    logs,
		}

		if format == "text" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=session_"+sessionID+".txt")
			_, _ = fmt.Fprintf(w, "安全告警证据链\n会话 ID: %s\n导出时间: %s\n有效告警: %d 条\n\n", exported.SessionID, exported.ExportedAt, len(chains))
			for index, chain := range chains {
				_, _ = fmt.Fprintf(w, "========== 告警证据 %d ==========\n", index+1)
				_, _ = fmt.Fprintf(w, "发生时间: %s\n", chain.Event.CreatedAt)
				if chain.Attribution != nil {
					_, _ = fmt.Fprintf(w, "使用人: %s (%s)\n", chain.Attribution.Username, chain.Attribution.UserID)
					_, _ = fmt.Fprintf(w, "调用凭据: %s (%s)\n", chain.Attribution.ClientName, chain.Attribution.ClientID)
					_, _ = fmt.Fprintf(w, "来源 IP: %s\n智能体: %s\n访问目标: %s / %s\n", chain.Attribution.SourceIP, chain.Attribution.AgentType, chain.Attribution.Provider, chain.Attribution.Target)
				}
				_, _ = fmt.Fprintf(w, "请求 ID: %s\n风险等级: %s\n处置: %s\n规则: %s (%s)\n", chain.Event.RequestID, chain.Event.Severity, chain.Event.ActionTaken, chain.Event.RuleName, chain.Event.RuleID)
				summary, _ := json.MarshalIndent(chain.Event.MatchedSummary, "", "  ")
				_, _ = fmt.Fprintf(w, "命中证据（原文，不脱敏）:\n%s\n", summary)
				_, _ = fmt.Fprintln(w, "关联上下文:")
				for _, item := range chain.Context {
					_, _ = fmt.Fprintf(w, "%s [%s] 消息序号=%v\n%s\n\n", item.CreatedAt.Format(time.RFC3339), item.Role, item.MessageIndex, item.Content)
				}
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=session_"+sessionID+".json")
			json.NewEncoder(w).Encode(exported)
		}
	}
}
