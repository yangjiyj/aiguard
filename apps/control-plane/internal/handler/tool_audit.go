package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
	"github.com/yangjiyj/aiguard/packages/shared-go/ratelog"
	"github.com/go-chi/chi/v5"
)

// toolLogRejectLog 给内部工具日志接口的 400 拒绝限频记日志。
// 现场 24 小时 13374 次 400（单秒最多 562 次）却没有任何服务端日志可查原因；
// 这里只记原因类别、租户与累计次数，绝不记请求内容。
var toolLogRejectLog = ratelog.New(100)

// toolLogWriteFailLog 给「已通过校验、但写库失败」的工具日志限频记日志。
// 客户现场约束违约（SQLSTATE 23514）曾每小时 5897 次，却没有任何服务端日志，只能从 PostgreSQL 日志里发现。
// 这里只记原因类别、约束名、租户与累计次数；绝不记请求内容，也不记 pg 的 DETAIL（里面带整行数据）。
var toolLogWriteFailLog = ratelog.New(100)

// respondToolLogWriteError 把写库失败映射成响应，并区分「确定性拒绝」与「可能是暂时的」：
//   - 约束违约（SQLSTATE 23514）/ 事实自相矛盾：数据本身决定的，重试一万次结果不变 -> 422 + tool_log_rejected，
//     网关据此丢弃、不再重投；
//   - 其余（连接池耗尽、超时等）：保持原有 400 internal_error，调用方照旧可重试。
func respondToolLogWriteError(w http.ResponseWriter, tenantID string, err error) {
	if repository.IsPermanentToolCallLogError(err) {
		reason := "facts_inconsistent"
		if constraint, ok := repository.ToolCallLogCheckViolation(err); ok {
			reason = "check_violation:" + constraint
		}
		toolLogWriteFailLog.Printf(tenantID+"|"+reason,
			"component=tool_audit stage=internal_tool_log event=tool_log_write_rejected reason=%s tenant=%s action=drop_no_retry",
			reason, tenantID)
		writeErrorWithStatus(w, http.StatusUnprocessableEntity, "tool_log_rejected",
			"tool call log violates lifecycle fact constraints and is not retryable")
		return
	}
	toolLogWriteFailLog.Printf(tenantID+"|write_failed",
		"component=tool_audit stage=internal_tool_log event=tool_log_write_failed reason=write_failed tenant=%s", tenantID)
	writeError(w, "internal_error", "failed to create tool call log")
}

func logToolLogRejected(r *http.Request, tenantID, reason string) {
	toolLogRejectLog.Printf(tenantID+"|"+reason,
		"component=tool_audit stage=internal_tool_log event=tool_log_rejected reason=%s tenant=%s content_length=%d",
		reason, tenantID, r.ContentLength)
}

// InternalToolLogRequest 是网关写入工具事实的内部 API 请求。
// EventKind=definition_exposed 仅表示网关观察到客户端提交工具定义，不证明定义已送达模型。
type InternalToolLogRequest struct {
	RequestID              string                              `json:"request_id"`
	SessionID              string                              `json:"session_id"`
	PromptID               string                              `json:"prompt_id"`
	EndpointID             string                              `json:"endpoint_id"`
	IntentTaskID           string                              `json:"intent_task_id,omitempty"`
	MCPServer              string                              `json:"mcp_server,omitempty"`
	IntentTaskSources      []agentintent.IntentTaskSourceClaim `json:"intent_task_sources,omitempty"`
	TenantID               string                              `json:"tenant_id"`
	ApplicationID          string                              `json:"application_id"`
	AgentType              string                              `json:"agent_type"`
	Model                  string                              `json:"model"`
	Protocol               string                              `json:"protocol"`
	UserID                 string                              `json:"user_id"`
	ToolName               string                              `json:"tool_name"`
	ToolType               string                              `json:"tool_type"`
	RiskLevel              string                              `json:"risk_level"`
	Parameters             map[string]interface{}              `json:"parameters"`
	Result                 string                              `json:"result"`
	Status                 string                              `json:"status"`
	MatchedPolicyID        string                              `json:"matched_policy_id"`
	MatchedPolicyName      string                              `json:"matched_policy_name"`
	MatchedAction          string                              `json:"matched_action"`
	MatchReason            string                              `json:"match_reason"`
	RawDecision            string                              `json:"raw_decision"`
	EffectiveDecision      string                              `json:"effective_decision"`
	Mode                   string                              `json:"mode"`
	EffectiveReason        string                              `json:"effective_reason"`
	PolicyVersion          string                              `json:"policy_version"`
	TraceID                string                              `json:"trace_id"`
	Confidence             float64                             `json:"confidence"`
	EvidenceJSON           json.RawMessage                     `json:"evidence_json"`
	NormalizedTarget       string                              `json:"normalized_target"`
	Provenance             string                              `json:"provenance"`
	TaintedArguments       json.RawMessage                     `json:"tainted_arguments"`
	EventKind              string                              `json:"event_kind"`
	ExecutionObserved      bool                                `json:"execution_observed"`
	ResultObserved         bool                                `json:"result_observed"`
	ToolCallID             string                              `json:"tool_call_id"`
	AssetID                string                              `json:"asset_id"`
	SkillInvocationID      string                              `json:"skill_invocation_id"`
	MCPServerID            string                              `json:"mcp_server_id"`
	MCPToolID              string                              `json:"mcp_tool_id"`
	DefinitionHash         string                              `json:"definition_hash"`
	AttributionMode        string                              `json:"attribution_mode"`
	AttributionConfidence  float64                             `json:"attribution_confidence"`
	OperationID            string                              `json:"operation_id"`
	EventType              string                              `json:"event_type"`
	RiskCategory           string                              `json:"risk_category"`
	RiskSubcategory        string                              `json:"risk_subcategory"`
	ReasonSummary          string                              `json:"reason_summary"`
	TargetSummary          string                              `json:"target_summary"`
	ModeDefaultAction      string                              `json:"mode_default_action"`
	CustomAction           string                              `json:"custom_action"`
	FinalAction            string                              `json:"final_action"`
	NotificationRequired   bool                                `json:"notification_required"`
	NotifyChannelIDs       []string                            `json:"notify_channel_ids"`
	NotificationStatus     string                              `json:"notification_status"`
	DiscardablePathMatched bool                                `json:"discardable_path_matched"`
	DiscardablePathReason  string                              `json:"discardable_path_reason"`
	ExecutionForwarded     bool                                `json:"execution_forwarded"`
}

// normalizeToolLogLifecycleTuple 保证 operation_id / event_type 不会只出现一半。
// 数据库约束要求二者同有同无；只有 operation_id（普通 MCP 调用的关联号）时，
// 它没有破坏性生命周期，应按普通日志落库而不是被破坏性分支拒绝并丢行。
func normalizeToolLogLifecycleTuple(operationID, eventType string) (string, string) {
	if strings.TrimSpace(eventType) == "" {
		return "", ""
	}
	return operationID, eventType
}

func CreateToolCallLogInternal(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}

		var req InternalToolLogRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logToolLogRejected(r, tenantID, "invalid_json")
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		missingName := req.ToolName == "" // 与改造前一致：只拒绝严格空串，不比以前多拒绝（纯空白名仍入库）
		missingType := req.ToolType == ""
		if missingName || missingType {
			reason := "missing_tool_name_and_type"
			switch {
			case missingName && !missingType:
				reason = "missing_tool_name"
			case missingType && !missingName:
				reason = "missing_tool_type"
			}
			logToolLogRejected(r, tenantID, reason)
			writeError(w, "invalid_request", "tool_name and tool_type are required")
			return
		}

		if req.RiskLevel == "" {
			req.RiskLevel = "medium"
		}
		if req.Status == "" {
			if req.Provenance == "agent_endpoint" {
				req.Status = "audited"
			} else {
				req.Status = "success"
			}
		}
		if req.EventKind == "" {
			req.EventKind = "legacy_unknown"
		}

		req.OperationID, req.EventType = normalizeToolLogLifecycleTuple(req.OperationID, req.EventType)

		logEntry := &repository.ToolCallLog{
			RequestID:              req.RequestID,
			SessionID:              req.SessionID,
			PromptID:               req.PromptID,
			EndpointID:             req.EndpointID,
			IntentTaskID:           req.IntentTaskID,
			MCPServer:              req.MCPServer,
			IntentTaskSources:      req.IntentTaskSources,
			TenantID:               tenantID,
			ApplicationID:          req.ApplicationID,
			AgentType:              req.AgentType,
			Model:                  req.Model,
			Protocol:               req.Protocol,
			UserID:                 req.UserID,
			ToolName:               req.ToolName,
			ToolType:               req.ToolType,
			RiskLevel:              req.RiskLevel,
			Parameters:             req.Parameters,
			Result:                 req.Result,
			Status:                 req.Status,
			MatchedPolicyID:        req.MatchedPolicyID,
			MatchedPolicyName:      req.MatchedPolicyName,
			MatchedAction:          req.MatchedAction,
			MatchReason:            req.MatchReason,
			RawDecision:            req.RawDecision,
			EffectiveDecision:      req.EffectiveDecision,
			Mode:                   req.Mode,
			EffectiveReason:        req.EffectiveReason,
			PolicyVersion:          req.PolicyVersion,
			TraceID:                req.TraceID,
			Confidence:             req.Confidence,
			EvidenceJSON:           req.EvidenceJSON,
			NormalizedTarget:       req.NormalizedTarget,
			Provenance:             req.Provenance,
			TaintedArguments:       req.TaintedArguments,
			EventKind:              req.EventKind,
			ExecutionObserved:      req.ExecutionObserved,
			ResultObserved:         req.ResultObserved,
			ToolCallID:             req.ToolCallID,
			AssetID:                req.AssetID,
			SkillInvocationID:      req.SkillInvocationID,
			MCPServerID:            req.MCPServerID,
			MCPToolID:              req.MCPToolID,
			DefinitionHash:         req.DefinitionHash,
			AttributionMode:        req.AttributionMode,
			AttributionConfidence:  req.AttributionConfidence,
			OperationID:            req.OperationID,
			EventType:              req.EventType,
			RiskCategory:           req.RiskCategory,
			RiskSubcategory:        req.RiskSubcategory,
			ReasonSummary:          req.ReasonSummary,
			TargetSummary:          req.TargetSummary,
			ModeDefaultAction:      req.ModeDefaultAction,
			CustomAction:           req.CustomAction,
			FinalAction:            req.FinalAction,
			NotifyChannelIDs:       req.NotifyChannelIDs,
			NotificationRequired:   req.NotificationRequired,
			NotificationStatus:     req.NotificationStatus,
			DiscardablePathMatched: req.DiscardablePathMatched,
			DiscardablePathReason:  req.DiscardablePathReason,
			ExecutionForwarded:     req.ExecutionForwarded,
		}

		var createErr error
		if req.Provenance == "agent_endpoint" {
			if req.EndpointID == "" || req.SessionID == "" || req.ToolCallID == "" || req.AttributionMode != "endpoint_hook" ||
				req.EventKind != "invocation_proposed" || (req.Status != "audited" && req.Status != "blocked") || req.RequestID != "" || req.ExecutionObserved || req.ResultObserved || req.ExecutionForwarded {
				writeError(w, "invalid_request", "invalid endpoint proposal identity or lifecycle facts")
				return
			}
			createErr = deps.ToolCallLogRepo.UpsertEndpointToolProposal(r.Context(), logEntry)
		} else if req.ToolCallID != "" && (req.EventKind == "tool_post" || req.EventKind == "result_observed") {
			_, createErr = deps.ToolCallLogRepo.UpsertByToolCallID(r.Context(), logEntry)
		} else if logEntry.OperationID != "" || logEntry.EventType != "" {
			createErr = deps.ToolCallLogRepo.CreateDestructiveLifecycle(r.Context(), logEntry)
		} else {
			createErr = deps.ToolCallLogRepo.Create(r.Context(), logEntry)
		}

		if createErr != nil {
			respondToolLogWriteError(w, tenantID, createErr)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(logEntry)
	}
}

// GetToolCallStats returns aggregated statistics for tool calls
func GetToolCallStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		start, end, err := defaultBoundedTimeWindow(r, 24*time.Hour)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		if !end.After(start) {
			writeError(w, "invalid_request", "end date must be after start date")
			return
		}
		windowSource := "default_24h"
		if firstQuery(r, "start_time", "start", "start_date", "from") != "" ||
			firstQuery(r, "end_time", "end", "end_date", "to") != "" {
			windowSource = "explicit"
		}
		stats, err := deps.ToolCallLogRepo.GetStatsWindow(r.Context(), session.TenantID, start, end)
		if err != nil {
			writeError(w, "internal_error", "failed to get tool call stats")
			return
		}

		// Calculate totals
		totalCount := 0
		totalHigh := 0
		totalCritical := 0
		for _, s := range stats {
			totalCount += s.Count
			totalHigh += s.HighCount
			totalCritical += s.CriticalCount
		}

		resp := map[string]interface{}{
			"stats":          stats,
			"total_count":    totalCount,
			"total_high":     totalHigh,
			"total_critical": totalCritical,
			"window": map[string]interface{}{
				"start":  start,
				"end":    end,
				"source": windowSource,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ListHighRiskToolCalls returns high risk tool calls
func ListHighRiskToolCalls(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		filter, err := parseToolCallFilter(r, session.TenantID)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		keyword, ok := validatedAuditKeyword(w, filter.Keyword)
		if !ok {
			return
		}
		filter.Keyword = keyword
		if !validateAuditKeywordWindow(w, keyword, filter.StartDate, filter.EndDate) {
			return
		}
		queryCtx, finishSearch, ok := beginAuditKeywordSearch(w, r, session.TenantID, keyword)
		if !ok {
			return
		}
		defer finishSearch()
		if keyword != "" {
			filter.SkipTotal = true
		}
		page, err := deps.ToolCallLogRepo.ListAuditPage(queryCtx, filter)
		if err != nil {
			writeError(w, "internal_error", "failed to list high risk tool calls")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(page)
	}
}

// ListSessionToolCalls returns all tool calls in a session
func ListSessionToolCalls(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		sessionID := chi.URLParam(r, "session_id")
		if sessionID == "" {
			writeError(w, "invalid_request", "session_id required")
			return
		}

		limit := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed <= 0 {
				writeError(w, "invalid_request", "invalid limit")
				return
			}
			if parsed > 100 {
				parsed = 100
			}
			limit = parsed
		}
		logs, err := deps.ToolCallLogRepo.ListBySessionLimited(r.Context(), session.TenantID, sessionID, limit)
		if err != nil {
			writeError(w, "internal_error", "failed to list session tool calls")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}
}

// GetUserToolCalls returns tool calls for a specific user
func GetUserToolCalls(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		userID := chi.URLParam(r, "user_id")
		if userID == "" {
			writeError(w, "invalid_request", "user_id required")
			return
		}

		limit := 100
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		logs, total, err := deps.ToolCallLogRepo.ListByUser(r.Context(), session.TenantID, userID, limit, offset)
		if err != nil {
			writeError(w, "internal_error", "failed to list user tool calls")
			return
		}

		resp := map[string]interface{}{
			"data":  logs,
			"total": total,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// GetRiskTrend returns risk trend over time
func GetRiskTrend(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		days := 7
		if d := r.URL.Query().Get("days"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 30 {
				days = parsed
			}
		}

		trend, err := deps.ToolCallLogRepo.GetRiskTrend(r.Context(), session.TenantID, days)
		if err != nil {
			writeError(w, "internal_error", "failed to get risk trend")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(trend)
	}
}
