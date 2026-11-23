package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

const agentOperationExecutionIntentNotice = "网关检测到模型准备调用删除或破坏性工具。这是执行意图记录，不代表目标数据已经删除。"

func GetAgentOperationProtection(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		tenantScope, tenantID, ok := resolveAgentOperationTarget(w, r, deps, user, r.URL.Query().Get("tenant_scope"), r.URL.Query().Get("tenant_id"))
		if !ok {
			return
		}
		scopeType := strings.TrimSpace(r.URL.Query().Get("scope_type"))
		if scopeType == "" {
			scopeType = "tenant"
		}
		scopeRef := strings.TrimSpace(r.URL.Query().Get("scope_ref"))
		if !validAgentOperationScopeQuery(scopeType, scopeRef) {
			writeError(w, "invalid_request", "invalid policy scope")
			return
		}
		policy, err := deps.AgentOperationRepo.GetPolicy(r.Context(), tenantID, scopeType, scopeRef)
		configured := true
		if errors.Is(err, repository.ErrAgentOperationNotFound) {
			// 这个范围还没保存过策略不是错误，而是「未配置」。设计里 404 只留给目标租户不存在、系统租户、跨租户引用
			//（resolveAgentOperationTarget 已处理）。返回与前端新建范围一致的默认值（审计/记录，version=1），
			// 保存时带的 ExpectedVersion=1 也能对上；configured=false 让调用方明确知道这不是已保存的策略。
			policy, err, configured = unconfiguredAgentOperationPolicy(scopeType, scopeRef), nil, false
		}
		if err != nil {
			writeAgentOperationRepositoryError(w, err)
			return
		}
		writeAgentOperationPolicy(w, r, deps, tenantScope, tenantID, policy, configured)
	}
}

func restrictedFileScopesOrDefault(scopes []string) []string {
	if scopes == nil {
		return repository.DefaultRestrictedFileScopes()
	}
	return scopes
}

// unconfiguredAgentOperationPolicy 是某个范围尚未保存任何策略时的有效默认值，与 web-console 的 defaultPolicy 保持一致。
func unconfiguredAgentOperationPolicy(scopeType, scopeRef string) *repository.AgentOperationPolicy {
	p := &repository.AgentOperationPolicy{
		ScopeType: scopeType, ScopeRef: scopeRef, Mode: "audit", Action: "record",
		DiscardablePaths: []string{}, NotifyChannelIDs: []string{}, RestrictedFilePatterns: []string{},
		RestrictedFileAction: "block", Version: 1,
	}
	p.ModeDefaultAction = "record"
	p.CurrentAction = "record"
	p.ConfigSource = "new_scope"
	return p
}

func PutAgentOperationProtection(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		req, err := decodeAgentOperationPolicyRequest(r.Body)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		tenantScope, tenantID, ok := resolveAgentOperationTarget(w, r, deps, user, req.TenantScope, req.TenantID)
		if !ok {
			return
		}
		policy, err := deps.AgentOperationRepo.SavePolicy(r.Context(), repository.AgentOperationPolicyMutation{
			TenantID: tenantID, ActorID: user.ID, Source: "admin_api",
			ScopeType: req.ScopeType, ScopeRef: req.ScopeRef, Mode: req.Mode, Action: req.Action,
			Protocol: req.Protocol, DiscardablePaths: req.DiscardablePaths,
			NotifyChannelIDs:       req.NotifyChannelIDs,
			RestrictedFilePatterns: req.RestrictedFilePatterns,
			RestrictedFileAction:   req.RestrictedFileAction,
			ExpectedVersion:        req.Version,
		})
		if err != nil {
			writeAgentOperationRepositoryError(w, err)
			return
		}
		writeAgentOperationPolicy(w, r, deps, tenantScope, tenantID, policy, true)
	}
}

func ListAgentOperationEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		filter, err := parseAgentOperationEventFilter(r)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		events, total, err := deps.AgentOperationRepo.ListEvents(r.Context(), user.TenantID, filter)
		if err != nil {
			writeAgentOperationRepositoryError(w, err)
			return
		}
		items := make([]map[string]any, 0, len(events))
		for i := range events {
			items = append(items, agentOperationEventProjection(&events[i]))
		}
		writeJSON(w, map[string]any{"items": items, "total": total, "limit": filter.Limit, "offset": filter.Offset})
	}
}

func GetAgentOperationEvent(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		publicEventID := strings.TrimSpace(chi.URLParam(r, "public_event_id"))
		if publicEventID == "" || len(publicEventID) > 128 {
			writeError(w, "invalid_request", "invalid public event id")
			return
		}
		event, err := deps.AgentOperationRepo.GetEvent(r.Context(), user.TenantID, publicEventID)
		if err != nil {
			writeAgentOperationRepositoryError(w, err)
			return
		}
		writeJSON(w, agentOperationEventProjection(event))
	}
}

// agentOperationCrossTenant 判定调用者能否跨租户或配置全局基线。只有系统管理员可以：该能力（308e08f55，2026-08-02）的设计是
// 「平台管理员默认配置全局基线，也可切换具体租户；普通用户继续固定在当前租户」。W4（6da5a2770）曾把这里的 platform_admin
// 机械替换成 roles.CanManageSecurityPolicy，顺带把跨租户与全局基线权限给了 security_officer——但安全员属于某个租户，
// 不是平台级角色（矩阵：安全策略、告警处置、证据查阅）。permission.Middleware 对三员的 SoD 放行路由整体跳过 RBAC 矩阵，
// 这里的租户校验是唯一一道关，不能让 A 租户的安全员读写 B 租户或全局。
func agentOperationCrossTenant(role string) bool { return roles.IsSystemAdmin(role) }

func resolveAgentOperationTarget(w http.ResponseWriter, r *http.Request, deps *Dependencies, user *repository.User, requestedScope, requestedTenantID string) (string, string, bool) {
	scope := strings.ToLower(strings.TrimSpace(requestedScope))
	tenantID := strings.TrimSpace(requestedTenantID)
	if scope == "" {
		if tenantID != "" {
			scope = "tenant"
		} else if agentOperationCrossTenant(user.Role) {
			scope = "all"
		} else {
			scope = "tenant"
		}
	}
	if scope == "all" {
		if !agentOperationCrossTenant(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can use all tenants")
			return "", "", false
		}
		if tenantID != "" {
			writeError(w, "invalid_request", "tenant_id is not allowed for all tenants")
			return "", "", false
		}
		return "all", "", true
	}
	if scope != "tenant" {
		writeError(w, "invalid_request", "tenant_scope must be all or tenant")
		return "", "", false
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(user.TenantID)
	}
	if tenantID == "" {
		writeError(w, "invalid_request", "tenant_id is required")
		return "", "", false
	}
	if !agentOperationCrossTenant(user.Role) && tenantID != user.TenantID {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "cannot access another tenant")
		return "", "", false
	}
	if !agentOperationCrossTenant(user.Role) {
		return "tenant", tenantID, true
	}
	if tenantID == repository.SystemTenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "tenant not found")
		return "", "", false
	}
	if !agentOperationTenantExists(w, r, deps, tenantID) {
		return "", "", false
	}
	return "tenant", tenantID, true
}

func agentOperationTenantExists(w http.ResponseWriter, r *http.Request, deps *Dependencies, tenantID string) bool {
	var lookup TenantLookup
	if deps != nil {
		lookup = deps.TenantLookup
		if lookup == nil && deps.TenantRepo != nil {
			lookup = deps.TenantRepo
		}
	}
	if lookup == nil {
		writeError(w, "internal_error", "tenant lookup is unavailable")
		return false
	}
	tenant, err := lookup.GetByID(r.Context(), tenantID)
	if err != nil || tenant == nil || tenant.ID == repository.SystemTenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "tenant not found")
		return false
	}
	return true
}

func writeAgentOperationPolicy(w http.ResponseWriter, r *http.Request, deps *Dependencies, tenantScope, tenantID string, policy *repository.AgentOperationPolicy, configured bool) {
	channels := []repository.AgentOperationChannel{}
	notifyChannelIDs := append([]string{}, policy.NotifyChannelIDs...)
	if tenantScope == "tenant" && len(notifyChannelIDs) != 0 {
		var err error
		channels, err = deps.AgentOperationRepo.ListChannels(r.Context(), tenantID, notifyChannelIDs)
		if err != nil {
			writeAgentOperationRepositoryError(w, err)
			return
		}
	} else if tenantScope == "all" {
		notifyChannelIDs = []string{}
	}
	// 已停用的策略再保存会新建一条启用行（版本从 1 开始），所以对外的 version 是「下一次保存应带的版本」=1；
	// 被停用行自己的版本号放在 stored_version，供排查。
	responseVersion := policy.Version
	if policy.Disabled {
		responseVersion = 1
	}
	response := map[string]any{
		"tenant_scope": tenantScope,
		"scope_type":   policy.ScopeType, "scope_ref": policy.ScopeRef,
		"mode": policy.Mode, "action": policy.Action, "protocol": policy.Protocol,
		"mode_default_action": policy.ModeDefaultAction, "current_action": policy.CurrentAction,
		"config_source": policy.ConfigSource, "discardable_paths": policy.DiscardablePaths,
		"restricted_file_patterns": policy.RestrictedFilePatterns,
		"restricted_file_action":   policy.RestrictedFileAction,
		"restricted_file_scopes":   restrictedFileScopesOrDefault(policy.RestrictedFileScopes),
		"notify_channel_ids":       notifyChannelIDs, "channels": channels,
		"version": responseVersion, "updated_at": policy.UpdatedAt,
		"configured": configured,
		// enabled=false 表示这个范围有一条已保存但被停用的策略（configured 仍为 true）：页面显示「已停用」，
		// 不能把它当成「未配置」去展示系统默认值。未配置的默认值本身视为启用。
		"enabled": !policy.Disabled,
	}
	if policy.Disabled {
		response["stored_version"] = policy.Version
	}
	if tenantScope == "tenant" {
		response["tenant_id"] = tenantID
	}
	writeJSON(w, response)
}

func agentOperationEventProjection(event *repository.AgentOperationEvent) map[string]any {
	return map[string]any{
		"public_event_id": event.PublicEventID, "operation_id": event.OperationID,
		"request_id": event.RequestID, "trace_id": event.TraceID,
		"application_id": event.ApplicationID, "agent_type": event.AgentType,
		"model": event.Model, "protocol": event.Protocol, "tool_name": event.ToolName,
		"tool_call_id": event.ToolCallID, "target_summary": event.TargetSummary,
		"category_code": event.CategoryCode, "category_label": event.CategoryLabel,
		"subcategory_code": event.SubcategoryCode, "basis_code": event.BasisCode,
		"confidence": event.Confidence, "mode_default_action": event.ModeDefaultAction,
		"custom_action": event.CustomAction, "current_action": event.CurrentAction,
		"status_code": event.StatusCode, "status_label": event.StatusLabel,
		"notification_code": event.NotificationCode, "noise_reduction": event.NoiseReduction,
		"created_at": event.CreatedAt, "fact_code": "execution_intent_not_deletion",
		"fact_message": agentOperationExecutionIntentNotice,
	}
}

func parseAgentOperationEventFilter(r *http.Request) (repository.AgentOperationEventFilter, error) {
	query := r.URL.Query()
	limit, err := parseBoundedAgentOperationInt(query.Get("limit"), 50, 1, 100)
	if err != nil {
		return repository.AgentOperationEventFilter{}, errors.New("limit must be between 0 and 100")
	}
	offset, err := parseBoundedAgentOperationInt(query.Get("offset"), 0, 0, 10000)
	if err != nil {
		return repository.AgentOperationEventFilter{}, errors.New("offset must be between 0 and 10000")
	}
	action := strings.TrimSpace(query.Get("action"))
	if action != "" && action != "record" && action != "alert_allow" && action != "confirm" && action != "block" {
		return repository.AgentOperationEventFilter{}, errors.New("invalid action")
	}
	status := strings.TrimSpace(query.Get("status"))
	validStatuses := map[string]bool{
		"": true, "recorded": true, "alert_allowed": true, "awaiting_confirmation": true,
		"blocked": true, "execution_forwarded": true, "result_observed": true,
	}
	if !validStatuses[status] {
		return repository.AgentOperationEventFilter{}, errors.New("invalid status")
	}
	to := time.Now().UTC()
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		to, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return repository.AgentOperationEventFilter{}, errors.New("to must be RFC3339")
		}
	}
	from := to.Add(-90 * 24 * time.Hour)
	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		from, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return repository.AgentOperationEventFilter{}, errors.New("from must be RFC3339")
		}
	}
	if from.After(to) || to.Sub(from) > 90*24*time.Hour {
		return repository.AgentOperationEventFilter{}, errors.New("event time range must not exceed 90 days")
	}
	return repository.AgentOperationEventFilter{
		ApplicationID: strings.TrimSpace(query.Get("application_id")),
		AgentType:     strings.TrimSpace(query.Get("agent_type")), Action: action, Status: status,
		From: &from, To: &to, Limit: limit, Offset: offset,
	}, nil
}

func parseBoundedAgentOperationInt(raw string, fallback, min, max int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, errors.New("out of range")
	}
	return value, nil
}

func validAgentOperationScopeQuery(scopeType, scopeRef string) bool {
	return (scopeType == "tenant" && scopeRef == "") ||
		((scopeType == "application" || scopeType == "agent") && scopeRef != "")
}

func writeAgentOperationRepositoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrAgentOperationNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent operation object not found")
	case errors.Is(err, repository.ErrAgentOperationConflict):
		writeErrorWithStatus(w, http.StatusConflict, "version_conflict", "policy version conflict")
	case errors.Is(err, repository.ErrAgentOperationInvalidScope):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid policy scope")
	default:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "agent operation request failed")
	}
}
