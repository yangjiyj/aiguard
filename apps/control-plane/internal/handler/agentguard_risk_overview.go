package handler

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func parseAgentRiskRange(r *http.Request) (time.Time, time.Time, error) {
	return defaultBoundedTimeWindow(r, 24*time.Hour)
}

func tenantIDFromRequestContext(r *http.Request) string {
	if session := auth.GetSession(r.Context()); session != nil {
		return session.TenantID
	}
	if user := auth.GetUser(r.Context()); user != nil {
		return user.TenantID
	}
	return ""
}

func parseToolCallFilter(r *http.Request, tenantID string) (repository.ToolCallFilter, error) {
	start, end, err := parseAgentRiskRange(r)
	if err != nil {
		return repository.ToolCallFilter{}, err
	}
	q := r.URL.Query()
	riskLevel := q.Get("risk_level")
	allRiskLevels := riskLevel == "all"
	if allRiskLevels {
		riskLevel = ""
	}
	filter := repository.ToolCallFilter{
		TenantID:  tenantID,
		StartDate: start,
		RequestID: q.Get("request_id"),
		EndDate:   end,
		UserID:    q.Get("user_id"),
		ClientID:  q.Get("client_id"),
		ProjectID: q.Get("project_id"),
		SessionID: q.Get("session_id"),
		Mode:      q.Get("mode"),
		RiskLevel: riskLevel,
		ToolName:  q.Get("tool_name"),
		ToolType:  q.Get("tool_type"), // MCP 调用审计页按 tool_type='mcp' 过滤（向后兼容：不传=不过滤）
		EventKind: q.Get("event_kind"),
		AgentType: q.Get("agent_type"),
		PolicyID:  q.Get("policy_id"),
		// MCP 审计页双决策维度 + 服务名服务端过滤（不传=不过滤，向后兼容 AgentGuard）
		RawDecision:       q.Get("raw_decision"),
		EffectiveDecision: q.Get("effective_decision"),
		Server:            q.Get("server"),
		Keyword:           q.Get("keyword"),
		DispositionStatus: q.Get("disposition_status"),
		AttentionOnly:     parseBoolParam(q.Get("attention_only")),
		Limit:             50,
		Offset:            0,
		SkipTotal:         parseBoolParam(q.Get("skip_total")),
	}
	if filter.RiskLevel == "" && !allRiskLevels {
		filter.RiskLevel = "high+"
	}
	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 {
			return filter, fmt.Errorf("invalid limit")
		}
		if parsed > 100 {
			parsed = 100
		}
		filter.Limit = parsed
	}
	if o := q.Get("offset"); o != "" {
		parsed, err := strconv.Atoi(o)
		if err != nil || parsed < 0 {
			return filter, fmt.Errorf("invalid offset")
		}
		filter.Offset = parsed
	}
	if filter.DispositionStatus != "" {
		switch filter.DispositionStatus {
		case "open", "resolved", "false_positive", "accepted", "escalated":
		default:
			return filter, fmt.Errorf("invalid disposition_status")
		}
	}
	return filter, nil
}

type agentRiskRawSettingReader interface {
	GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error)
}

const (
	agentRiskModeSourceUnavailable = "settings_unavailable"
	agentRiskEffectiveModeSource   = "runtime_status_unavailable"
)

// agentRiskConfiguredModeSources 是“配置意图”的来源标签（控制台 statusSource.ts 有对应中文）。
var agentRiskConfiguredModeSources = map[string]string{
	executionmode.SourceAdminSettings: "system_settings.security_execution_mode",
	executionmode.SourceDeployment:    "deployment",
	executionmode.SourceLegacy:        "system_settings.security_audit_only",
	executionmode.SourceSafeDefault:   "safe_default",
}

// resolveAgentRiskConfiguredMode 与其他地方同口径：两个键一次读出交给 executionmode.FromValues（控制台
// 显式模式优先；没有显式模式时部署变量 SECURITY_AUDIT_ONLY=true 作初值；其次旧键；都没有按记录）。
// 读不到配置时只说 unknown，不冒充某个模式。
func resolveAgentRiskConfiguredMode(ctx context.Context, reader agentRiskRawSettingReader) (string, *bool, string) {
	if reader == nil {
		return "unknown", nil, agentRiskModeSourceUnavailable
	}
	settings, err := reader.GetByKeys(ctx, executionmode.Keys())
	if err != nil {
		return "unknown", nil, agentRiskModeSourceUnavailable
	}
	values := map[string]string{}
	for _, setting := range settings {
		if setting != nil {
			values[setting.Key] = setting.Value
		}
	}
	auditOnly, source := executionmode.FromValues(values, executionmode.DeploymentRecordInitialValue())
	mode := "per_policy"
	if auditOnly {
		mode = "audit_only"
	}
	return mode, &auditOnly, agentRiskConfiguredModeSources[source]
}

func applyAgentRiskModeMetadata(ctx context.Context, overview *repository.AgentRiskOverview, reader agentRiskRawSettingReader) {
	overview.ConfiguredMode, overview.ConfiguredAuditCeiling, overview.ConfiguredModeSource = resolveAgentRiskConfiguredMode(ctx, reader)
	// 控制面只能证明配置意图；没有来自执行热路径的运行状态时，不冒充实际生效模式。
	overview.EffectiveMode = "unknown"
	overview.AuditCeiling = nil
	overview.EffectiveModeSource = agentRiskEffectiveModeSource
	overview.RuntimeModeVerified = false
}

func GetAgentRiskOverview(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.ToolCallLogRepo == nil {
			writeError(w, "internal_error", "tool call repository is not configured")
			return
		}
		tenantID := tenantIDFromRequestContext(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		start, end, err := parseAgentRiskRange(r)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		// tool_type 非空时只看该类调用：MCP 态势页传 ?tool_type=mcp 复用本端点得 MCP 专属看板；
		// 不传=全部工具调用（AgentGuard 原口径，向后兼容）。
		overview, err := deps.ToolCallLogRepo.GetRiskOverview(r.Context(), tenantID, start, end, r.URL.Query().Get("tool_type"))
		if err != nil {
			writeError(w, "internal_error", "failed to get agent risk overview")
			return
		}
		applyAgentRiskModeMetadata(r.Context(), overview, deps.SystemRepo)
		writeJSON(w, overview)
	}
}
