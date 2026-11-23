package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

func ListEvidenceRuns(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		repo := deps.EvidenceRunRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "evidence run repository is not configured")
			return
		}
		view := strings.TrimSpace(r.URL.Query().Get("view"))
		if view == "" {
			view = "agent_tasks"
		}
		if view != "agent_tasks" && view != "ai_conversations" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "unsupported evidence view")
			return
		}
		keyword, ok := validatedAuditKeyword(w, r.URL.Query().Get("keyword"))
		if !ok {
			return
		}
		filter := repository.ForwardProxyAccessFilter{
			EnvironmentScope: "customer",
			RiskState:        r.URL.Query().Get("risk_state"), Provider: r.URL.Query().Get("provider"),
			TargetHost: r.URL.Query().Get("target_host"), SourceIP: r.URL.Query().Get("source_ip"),
			Direction: r.URL.Query().Get("direction"), AgentType: r.URL.Query().Get("agent_type"),
			Keyword: keyword, SkipTotal: keyword != "",
			ContentOnly: true, Limit: parseIntParam(r.URL.Query().Get("limit"), 20),
			Offset: parseIntParam(r.URL.Query().Get("offset"), 0),
		}
		filter.SkipTotal = filter.SkipTotal || parseBoolParam(r.URL.Query().Get("skip_total"))
		filter.ProbeHasMore = filter.SkipTotal
		if err := applyForwardProxyAccessTimeWindow(r, &filter); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid UTC window")
			return
		}
		if !validateAuditKeywordWindow(w, keyword, filter.StartTime, filter.EndTime) {
			return
		}
		queryCtx, finishSearch, ok := beginAuditKeywordSearch(w, r, user.TenantID, keyword)
		if !ok {
			return
		}
		defer finishSearch()
		items, total, err := repo.ListEvidenceRuns(queryCtx, user.TenantID, view, filter)
		if err != nil {
			writeAuditKeywordQueryError(w, err, "failed to list evidence runs")
			return
		}
		data := make([]types.EvidenceRunInfo, 0, len(items))
		hidden := 0
		for _, item := range items {
			mapped := mapEvidenceRunInfo(item)
			if mapped.TaskClass == "codex_background_memory" || mapped.TaskClass == "agent_background_poll" {
				hidden++
				continue
			}
			data = append(data, mapped)
		}
		if hidden > 0 {
			if total >= hidden {
				total -= hidden
			} else {
				total = 0
			}
		}
		hasMore := total > filter.Offset+len(data)
		// A first page with no look-ahead row contains every matching task.
		// This remains exact after removing background tasks from that complete page.
		totalKnown := !filter.SkipTotal || (filter.Offset == 0 && !hasMore)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.EvidenceRunListResponse{
			Data: data, Total: total, TotalKnown: totalKnown, HasMore: hasMore,
		})
	}
}

func evidenceRunTaskClass(agentType, title string) string {
	normalizedAgent := strings.TrimSpace(strings.ToLower(agentType))
	normalizedTitle := strings.ToLower(strings.TrimSpace(title))
	if isRetentionHeartbeat(title) {
		return "agent_background_poll"
	}
	if normalizedAgent == "openai-codex" && ((strings.HasPrefix(normalizedTitle, "analyze this rollout") && strings.Contains(normalizedTitle, "memory")) || strings.HasPrefix(normalizedTitle, "## memory writing agent:")) {
		return "codex_background_memory"
	}
	return ""
}

func mapEvidenceRunInfo(item repository.EvidenceRunRecord) types.EvidenceRunInfo {
	title := item.Title
	postgresTitleTruncated := utf8.RuneCountInString(title) == 160
	taskClass := evidenceRunTaskClass(item.AgentType, title)
	if taskClass != "codex_background_memory" {
		if projected, matched := retentionfmt.ProjectAgentTaskTitle(item.AgentType, title, postgresTitleTruncated); matched {
			title = projected
		}
		title = strings.TrimSpace(title)
	}
	if title != "" && taskClass != "codex_background_memory" {
		if visible, status := safeRetentionUserInput(title); status == "complete" {
			title = strings.TrimSpace(visible)
		} else {
			title = ""
		}
	}
	if title == "" {
		if item.Kind == "agent_task" {
			title = agentdetect.Label(item.AgentType)
			if title == "" {
				title = "未识别智能体"
			}
			title += " 智能体任务"
		} else {
			title = "AI 对话"
		}
	}
	if taskClass == "codex_background_memory" {
		title = "Codex 后台记忆整理"
	}
	duration := item.EndedAt.Sub(item.StartedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return types.EvidenceRunInfo{
		RunID: item.RunID, Kind: item.Kind, TaskClass: taskClass, CorrelationSource: item.CorrelationSource,
		CorrelationConfidence:   item.CorrelationConfidence,
		RepresentativeRequestID: item.RepresentativeRequestID, MemberRequestIDs: item.MemberRequestIDs,
		Title: title, StartedAt: item.StartedAt.Format(timeRFC3339Nano), EndedAt: item.EndedAt.Format(timeRFC3339Nano), DurationMs: duration,
		AgentType: item.AgentType, AgentLabel: agentdetect.Label(item.AgentType), AgentRuntime: item.AgentRuntime,
		AgentDetectionSource: item.AgentDetectionSource, AgentDetectionConfidence: item.AgentDetectionConfidence,
		Username: item.Username, ClientName: item.ClientName, SourceIP: item.SourceIP,
		Models: item.Models, AccessDirections: item.AccessDirections, RequestCount: item.RequestCount,
		EvidenceStatus: item.EvidenceStatus, RiskState: item.RiskState,
	}
}

const timeRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"

// GetEvidenceTimeline 返回带证据读取审计的时间线 handler（时间线含请求/响应事件摘要，属证据读取）。
func GetEvidenceTimeline(deps *Dependencies) http.HandlerFunc {
	return auditedEvidenceHandler(deps, "timeline", getEvidenceTimelineInner(deps))
}

func getEvidenceTimelineInner(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		repo := deps.EvidenceTimelineRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "evidence timeline repository is not configured")
			return
		}
		requestID := strings.TrimSpace(chi.URLParam(r, "request_id"))
		if requestID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request_id is required")
			return
		}
		members, err := readEvidenceMemberIDs(w, r, requestID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		scope, start, end, err := retentionScopeAndWindow(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "from/to must be a valid non-empty UTC window")
			return
		}
		var events []repository.EvidenceTimelineEvent
		if scoped, ok := repo.(interface {
			ListEvidenceTimelineScoped(context.Context, string, []string, time.Time, time.Time, string) ([]repository.EvidenceTimelineEvent, error)
		}); ok {
			events, err = scoped.ListEvidenceTimelineScoped(r.Context(), user.TenantID, members, start, end, scope)
		} else {
			events, err = repo.ListEvidenceTimeline(r.Context(), user.TenantID, members)
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load evidence timeline")
			return
		}
		data := make([]types.EvidenceTimelineEventInfo, len(events))
		for i, event := range events {
			data[i] = types.EvidenceTimelineEventInfo{
				ID: event.ID, RequestID: event.RequestID, Type: event.Type, Title: event.Title,
				Detail: event.Detail, Status: event.Status, EventKind: event.EventKind,
				FactLabel: event.FactLabel, Timestamp: event.Timestamp.Format(timeRFC3339Nano), Count: event.Count,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	}
}
