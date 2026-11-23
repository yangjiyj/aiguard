package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// mcpContractRuntimeRedlines 是 gateway-core 运行时红线类目的契约镜像（权威源是
// gateway-core mcp_proxy.go 的 mcpRedlineRules，此处按名同步供 LSE 生成运行时攻击样本）。
// 这些红线对任意工具的 tools/call 参数生效（非按工具配置）；默认只留证告警，
// 租户在 mcp_redline_settings 配为 block 后防护模式下阻断（W1 1.11）。
var mcpContractRuntimeRedlines = append([]string(nil), repository.MCPConfigurableRedlines...)

// MCP 权限策略管理台 CRUD + 内部生效策略下发（gateway-core 拉取）。
// 范式对齐 agentguard_policy.go：canManageAgentGuard 同款角色门禁、
// TenantID 强制取 session 用户（绝不从请求体收）、写操作 logAudit。

// mcpPolicyRequest 是创建/更新策略的请求体（tenant_id/created_by 一律服务端注入）。
type mcpPolicyRequest struct {
	ScopeType     string `json:"scope_type"`
	ScopeRef      string `json:"scope_ref"`
	ServerID      string `json:"server_id"`
	ToolPattern   string `json:"tool_pattern"`
	TargetKind    string `json:"target_kind"`
	Mode          string `json:"mode"`
	DefaultAction string `json:"default_action"`
	Priority      int    `json:"priority"`
	Enabled       *bool  `json:"enabled"`
	Note          string `json:"note"`
	// ArgConditions 参数条件（W1 1.12），仅 target_kind=tool 可用。
	ArgConditions []repository.MCPArgCondition `json:"arg_conditions"`
}

// validateMCPPolicyRequest 校验枚举（空串放行，由 repository 落默认值）。
func validateMCPPolicyRequest(req *mcpPolicyRequest) string {
	if req.ScopeType != "" && !repository.IsMCPPolicyScopeType(req.ScopeType) {
		return "scope_type must be one of tenant/project/department/user/key/agent/session"
	}
	switch req.Mode {
	case "", "observe", "audit", "strict":
	default:
		return "mode must be one of observe/audit/strict"
	}
	switch req.DefaultAction {
	case "", "allow", "audit", "confirm", "block":
	default:
		return "default_action must be one of allow/audit/confirm/block"
	}
	kind, ok := repository.NormalizeMCPTargetKind(req.TargetKind)
	if !ok {
		return "target_kind must be one of tool/resource/prompt/method"
	}
	// confirm 依赖批准后重放，只有 tools/call 支持；其他类别配 confirm 会静默降级，直接拒绝。
	if kind != "tool" && req.DefaultAction == "confirm" {
		return "default_action confirm is only supported for target_kind tool"
	}
	// 参数条件只对 tools/call 的 arguments 求值；其他类别没有参数，配了等于永不命中。
	if len(req.ArgConditions) > 0 && kind != "tool" {
		return "arg_conditions are only supported for target_kind tool"
	}
	if err := repository.ValidateMCPArgConditions(req.ArgConditions); err != nil {
		return err.Error()
	}
	return ""
}

// ListMCPPolicies handles GET /admin/v1/mcp-policies?server_id=
// 响应: {items:[Policy]}；server_id 过滤时连带 server 通配（”）策略一并返回。
func ListMCPPolicies(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		policies, err := deps.MCPPolicyRepo.ListByTenant(r.Context(), user.TenantID, r.URL.Query().Get("server_id"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if policies == nil {
			policies = []*repository.MCPPolicy{}
		}
		writeJSON(w, map[string]interface{}{"items": policies})
	}
}

// CreateMCPPolicy handles POST /admin/v1/mcp-policies
func CreateMCPPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) && user.Role != "platform_connector" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage MCP policies")
			return
		}
		if deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		var req mcpPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if msg := validateMCPPolicyRequest(&req); msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		p := &repository.MCPPolicy{
			TenantID:      user.TenantID, // 租户强制取 session 用户，绝不信任请求体
			ScopeType:     req.ScopeType,
			ScopeRef:      req.ScopeRef,
			ServerID:      req.ServerID,
			ToolPattern:   req.ToolPattern,
			TargetKind:    req.TargetKind,
			Mode:          req.Mode,
			DefaultAction: req.DefaultAction,
			Priority:      req.Priority,
			Enabled:       enabled,
			Note:          req.Note,
			ArgConditions: req.ArgConditions,
			CreatedBy:     user.ID,
		}
		if err := deps.MCPPolicyRepo.Create(r.Context(), p); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "mcp_policy.create", map[string]interface{}{
			"policy_id": p.ID, "scope_type": p.ScopeType, "scope_ref": p.ScopeRef,
			"server_id": p.ServerID, "tool_pattern": p.ToolPattern,
			"mode": p.Mode, "default_action": p.DefaultAction,
			"arg_conditions": p.ArgConditions,
		}, "mcp_policy", p.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(p)
	}
}

// UpdateMCPPolicy handles PUT /admin/v1/mcp-policies/{id}
func UpdateMCPPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) && user.Role != "platform_connector" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage MCP policies")
			return
		}
		if deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}
		var req mcpPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if msg := validateMCPPolicyRequest(&req); msg != "" {
			writeError(w, "invalid_request", msg)
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		p := &repository.MCPPolicy{
			ID:            id,
			TenantID:      user.TenantID, // 租户硬隔离：跨租户 id 在 repository 层打不到行
			ScopeType:     req.ScopeType,
			ScopeRef:      req.ScopeRef,
			ServerID:      req.ServerID,
			ToolPattern:   req.ToolPattern,
			TargetKind:    req.TargetKind,
			Mode:          req.Mode,
			DefaultAction: req.DefaultAction,
			Priority:      req.Priority,
			Enabled:       enabled,
			Note:          req.Note,
			ArgConditions: req.ArgConditions,
		}
		if err := deps.MCPPolicyRepo.Update(r.Context(), p); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp policy not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "mcp_policy.update", map[string]interface{}{
			"policy_id": p.ID, "scope_type": p.ScopeType, "scope_ref": p.ScopeRef,
			"server_id": p.ServerID, "tool_pattern": p.ToolPattern,
			"mode": p.Mode, "default_action": p.DefaultAction, "enabled": p.Enabled,
			"arg_conditions": p.ArgConditions,
		}, "mcp_policy", p.ID)
		writeJSON(w, p)
	}
}

// DeleteMCPPolicy handles DELETE /admin/v1/mcp-policies/{id}
func DeleteMCPPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage MCP policies")
			return
		}
		if deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}
		if err := deps.MCPPolicyRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp policy not found")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "mcp_policy.delete", map[string]interface{}{"policy_id": id}, "mcp_policy", id)
		writeJSON(w, map[string]interface{}{"ok": true})
	}
}

// mcpSimulateRequest 是策略预演请求体：给定作用域档位 + 具体六元组 + server/tool，
// 服务端在租户策略集上跑 ResolveMCPPolicy，返回胜出者与全排序候选。零 DB 副作用。
type mcpSimulateRequest struct {
	ScopeType string `json:"scope_type"`
	ScopeRef  string `json:"scope_ref"`
	ServerID  string `json:"server_id"`
	ToolName  string `json:"tool_name"`
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`
	KeyPrefix string `json:"key_prefix"`
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
	// DepartmentID 部门档位（W1 1.12）；为空且给了 user_id 时按用户所在部门反查。
	DepartmentID string `json:"department_id"`
	// Arguments 可选的 tools/call 参数；给出时带参数条件的策略按参数求值参与预演。
	Arguments json.RawMessage `json:"arguments"`
}

// SimulateMCPPolicy handles POST /admin/v1/mcp-policies/simulate
// 逐条预演：在当前租户策略集上解析给定调用场景的生效策略，返回 {winning, candidates}。
// 强制 tenant=session 用户，绝不信任请求体租户；零 DB 写入（只读 ListByTenant + 纯函数解析）。
func SimulateMCPPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		var req mcpSimulateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		policies, err := deps.MCPPolicyRepo.ListByTenant(r.Context(), user.TenantID, "")
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		// 具体六元组打底，再把 scope_type+scope_ref 落到对应档位字段（便于「就某档位预演」）。
		scope := repository.MCPPolicyScope{
			TenantID:  user.TenantID, // 租户强制取 session 用户
			ProjectID: req.ProjectID,
			UserID:    req.UserID,
			KeyPrefix: req.KeyPrefix,
			AgentID:   req.AgentID,
			SessionID: req.SessionID,
			ServerID:  req.ServerID,
			ToolName:  req.ToolName,

			DepartmentID: req.DepartmentID,
		}
		if len(req.Arguments) > 0 && string(req.Arguments) != "null" {
			args := string(req.Arguments)
			scope.ArgumentsJSON = &args
		}
		if req.ScopeRef != "" {
			switch req.ScopeType {
			case "department":
				scope.DepartmentID = req.ScopeRef
			case "project":
				scope.ProjectID = req.ScopeRef
			case "user":
				scope.UserID = req.ScopeRef
			case "key":
				scope.KeyPrefix = req.ScopeRef
			case "agent":
				scope.AgentID = req.ScopeRef
			case "session":
				scope.SessionID = req.ScopeRef
			}
		}
		if scope.DepartmentID == "" && scope.UserID != "" && repository.MCPPoliciesUseDepartmentScope(policies) {
			dept, err := resolveMCPUserDepartment(r.Context(), deps, user.TenantID, scope.UserID)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to resolve user department")
				return
			}
			scope.DepartmentID = dept
		}
		candidates := repository.ResolveMCPPolicyCandidates(policies, scope)
		var winning *repository.MCPPolicy
		if len(candidates) > 0 {
			winning = candidates[0]
		}
		if candidates == nil {
			candidates = []*repository.MCPPolicy{}
		}
		writeJSON(w, map[string]interface{}{"winning": winning, "candidates": candidates})
	}
}

// MCPPolicyShadowCheck handles GET|POST /admin/v1/mcp-policies/shadow-check
// 返回被更宽松 allow 遮蔽的 block 策略清单（口径与网关运行时解析同源）。零 DB 写入。
func MCPPolicyShadowCheck(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		policies, err := deps.MCPPolicyRepo.ListByTenant(r.Context(), user.TenantID, "")
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		warnings := repository.DetectMCPPolicyShadows(policies)
		writeJSON(w, map[string]interface{}{"warnings": warnings})
	}
}

// GetInternalMCPEffectivePolicy handles GET /admin/v1/internal/mcp/effective-policy
// gateway-core 数据面按六元组拉生效策略（InternalAPIMiddleware 组，共享密钥认证）。
// query: server_id(必填), tool_name(必填), project_id, user_id, key_prefix, agent_id, session_id
//
// 普通租户策略 mode 原样解析；quarantined/revoked/removed/unverified/unknown 则由
// supply-chain admission 在此合成为 {mode:strict,action:block,structural_block:true}。
// 结构阻断不受显式 allow 或 SECURITY_AUDIT_ONLY 降级；普通策略全 miss 仍为 audit，
// 两类判定分别留证，避免把治理开关误当供应链准入。
func GetInternalMCPEffectivePolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		if deps.MCPPolicyRepo == nil || deps.MCPSupplyChainRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
			return
		}
		q := r.URL.Query()
		serverID := q.Get("server_id")
		toolName := q.Get("tool_name")
		if serverID == "" || toolName == "" {
			writeError(w, "invalid_request", "server_id and tool_name are required")
			return
		}
		targetKind, ok := repository.NormalizeMCPTargetKind(q.Get("target_kind"))
		if !ok {
			writeError(w, "invalid_request", "target_kind must be one of tool/resource/prompt/method")
			return
		}
		supply, err := deps.MCPSupplyChainRepo.ResolveMCPSupplyChain(r.Context(), tenantID, serverID, toolName)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to resolve MCP supply-chain admission")
			return
		}
		if targetKind != "tool" {
			// 供应链准入按工具建档；非工具目标只继承服务器级隔离/撤销（网关侧同口径再过滤一次）。
			supply = repository.MCPServerLevelSupplyChain(supply)
		}
		policies, err := deps.MCPPolicyRepo.ListByTenant(r.Context(), tenantID, "")
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		scope := repository.MCPPolicyScope{
			TenantID:   tenantID,
			ProjectID:  q.Get("project_id"),
			UserID:     q.Get("user_id"),
			KeyPrefix:  q.Get("key_prefix"),
			AgentID:    q.Get("agent_id"),
			SessionID:  q.Get("session_id"),
			ServerID:   serverID,
			ToolName:   toolName,
			TargetKind: targetKind,
		}
		// 部门档位（W1 1.12）：网关不知道部门，由控制面按 user_id 反查；租户没有部门策略时不查。
		// 反查失败返回 5xx，网关按 D1 沿用 last-known-good，而不是静默丢掉部门策略。
		if scope.UserID != "" && repository.MCPPoliciesUseDepartmentScope(policies) {
			dept, err := resolveMCPUserDepartment(r.Context(), deps, tenantID, scope.UserID)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to resolve user department")
				return
			}
			scope.DepartmentID = dept
		}
		// 参数条件（W1 1.12）：参数不出网关。这里下发「不看参数的胜出者」+ 排在它前面的
		// 带条件策略（arg_chain），网关按顺序求值取第一条成立的。
		policy, argChain := repository.ResolveMCPPolicyWithArgChain(policies, scope)
		response := buildMCPEffectivePolicyResponse(policy, supply)
		// 2.9.22：供应链发现由网关按防护项处置，参数条件策略照常下发。
		if len(argChain) > 0 {
			response["arg_chain"] = argChain
		}
		writeJSON(w, response)
	}
}

// mcpAuditOnlyCeiling 读 SECURITY_AUDIT_ONLY 的真源（system_settings 动态设置优先，
// env 兜底），与 gateway-core securityAuditOnly 同口径。audit-only 为真时该租户任何
// MCP 决策的 effective 都被钳到 audit（clampModeToCeiling），故契约据此告诉 LSE：
// 期望 block 的样本在此租户下不会真拦，验证「堵」只看 raw_decision 留痕。
func mcpAuditOnlyCeiling(ctx context.Context, deps *Dependencies) bool {
	auditOnly, _ := resolveSecurityExecutionMode(ctx, deps)
	return auditOnly
}

// mcpPolicyContractVersion 用 manifest_hash ⊕ 策略集最新 updated_at 生成契约版本指纹。
// 网关策略或 server manifest 任一变更即失效，LSE 缓存契约时带此版本、变更后重拉，
// 避免用陈旧策略断言测-堵-验结果。
func mcpPolicyContractVersion(manifestHash string, latestPolicyUpdate time.Time) string {
	seed := manifestHash + "|"
	if !latestPolicyUpdate.IsZero() {
		seed += latestPolicyUpdate.UTC().Format(time.RFC3339Nano)
	}
	sum := sha256.Sum256([]byte(seed))
	return "mcpc_" + hex.EncodeToString(sum[:])[:16]
}

// buildMCPToolContracts 是策略契约的纯函数装配核心（无 DB / 无 HTTP，可单测）：
// 逐个在册（未 removed）工具跑 ResolveMCPPolicy，输出期望裁决 + 静态风险标注 +
// audit-only 天花板下的实际生效动作 + 证据核对位置。契约按「无特定主体」的
// 租户+server+tool 维度解析默认裁决快照；per-subject（project/user/key/agent/session）
// 策略在运行时按调用方六元组另行命中，不在整表契约里逐一展开。
func buildMCPToolContracts(tenantID, serverID, serverName string, tools []*repository.MCPTool, policies []*repository.MCPPolicy, auditOnlyCeiling bool) []map[string]interface{} {
	toolContracts := make([]map[string]interface{}, 0, len(tools))
	for _, t := range tools {
		if t == nil || t.Removed {
			continue
		}
		policy := repository.ResolveMCPPolicy(policies, repository.MCPPolicyScope{
			TenantID: tenantID,
			ServerID: serverID,
			ToolName: t.ToolName,
		})
		mode := string(repository.AgentGuardModeAudit)
		expectedAction := string(repository.AgentGuardActionAudit)
		policyID := ""
		scopeType := ""
		priority := 0
		matched := false
		var updatedAt interface{}
		if policy != nil {
			matched = true
			mode = policy.Mode
			expectedAction = policy.DefaultAction
			policyID = policy.ID
			scopeType = policy.ScopeType
			priority = policy.Priority
			updatedAt = policy.UpdatedAt
		}
		// effective_action_ceiling：audit-only 天花板下 block/confirm 被钳到 audit，
		// 告知 LSE 期望的「实际生效」动作（与 raw 留痕解耦，守 audit-only 铁律）。
		effectiveActionCeiling := expectedAction
		if auditOnlyCeiling && (expectedAction == "block" || expectedAction == "confirm") {
			effectiveActionCeiling = "audit"
		}
		riskTags := t.RiskTags
		if riskTags == nil {
			riskTags = []string{}
		}
		poisonFlags := t.PoisonFlags
		if poisonFlags == nil {
			poisonFlags = []string{}
		}
		toolContracts = append(toolContracts, map[string]interface{}{
			"tool_name":                t.ToolName,
			"qualified_name":           serverName + "__" + t.ToolName,
			"risk_tags":                riskTags,
			"poison_flags":             poisonFlags,
			"schema_hash":              t.SchemaHash,
			"policy_matched":           matched,
			"policy_id":                policyID,
			"mode":                     mode,
			"expected_action":          expectedAction,
			"effective_action_ceiling": effectiveActionCeiling,
			"scope_type":               scopeType,
			"priority":                 priority,
			"updated_at":               updatedAt,
			"redline_triggers":         mcpContractRuntimeRedlines,
			"evidence_requirements": map[string]interface{}{
				"runtime": map[string]interface{}{
					"tool_call_logs":  map[string]string{"tool_type": "mcp"},
					"security_events": map[string]string{"source": "gateway_mcp", "written_when": "raw=block|confirm"},
					"request_logs":    map[string]string{"endpoint_type": "proxy", "proxy_mode": "mcp"},
				},
				"registry": map[string]interface{}{
					"table":         "mcp_tools",
					"fields":        []string{"poison_flags", "manifest_hash", "schema_hash"},
					"sync_response": []string{"poisoned_tool_count", "changed", "previous_hash"},
				},
			},
		})
	}
	return toolContracts
}

// GetInternalMCPPolicyContract handles GET /admin/v1/internal/mcp/policy-contract?server_id=
// 机器可读策略契约导出（InternalAPIMiddleware 组，共享密钥认证；LSE 用内部密钥拉，
// 不走管理员会话）。逐 server 遍历在册工具跑 ResolveMCPPolicy，输出解析后的期望裁决 +
// 注册期静态标注（risk_tags/poison_flags）+ 运行时红线类目 + audit-only 天花板 +
// 证据核对位置。零新表、零 DB 写——只读 ListByServer + ListByTenant + 纯函数解析。
func GetInternalMCPPolicyContract(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		if deps == nil || deps.MCPServerRepo == nil || deps.MCPToolRepo == nil || deps.MCPPolicyRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp repositories not configured")
			return
		}
		serverID := strings.TrimSpace(r.URL.Query().Get("server_id"))
		if serverID == "" {
			writeError(w, "invalid_request", "server_id is required")
			return
		}
		server, err := deps.MCPServerRepo.Get(r.Context(), tenantID, serverID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if server == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found or not owned by tenant")
			return
		}
		tools, err := deps.MCPToolRepo.ListByServer(r.Context(), tenantID, serverID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		policies, err := deps.MCPPolicyRepo.ListByTenant(r.Context(), tenantID, "")
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		auditOnlyCeiling := mcpAuditOnlyCeiling(r.Context(), deps)

		var latestPolicyUpdate time.Time
		for _, p := range policies {
			if p != nil && p.UpdatedAt.After(latestPolicyUpdate) {
				latestPolicyUpdate = p.UpdatedAt
			}
		}

		toolContracts := buildMCPToolContracts(tenantID, serverID, server.Name, tools, policies, auditOnlyCeiling)

		writeJSON(w, map[string]interface{}{
			"schema_version":     "gateway-mcp-policy-contract/v1",
			"contract_version":   mcpPolicyContractVersion(server.ManifestHash, latestPolicyUpdate),
			"tenant_id":          tenantID,
			"server_id":          server.ID,
			"server_name":        server.Name,
			"server_status":      server.Status,
			"manifest_hash":      server.ManifestHash,
			"audit_only_ceiling": auditOnlyCeiling,
			"generated_at":       time.Now().UTC().Format(time.RFC3339),
			"runtime_redlines":   mcpContractRuntimeRedlines,
			"tools":              toolContracts,
		})
	}
}

// resolveMCPUserDepartment 反查调用者所在部门（users.department_id）。用户不存在或不属于
// 该租户时返回空串（部门档位不命中）；仓储不可用时同样返回空串。
func resolveMCPUserDepartment(ctx context.Context, deps *Dependencies, tenantID, userID string) (string, error) {
	if deps == nil || deps.UserRepo == nil || userID == "" {
		return "", nil
	}
	u, err := deps.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil || u.TenantID != tenantID {
		return "", nil
	}
	return u.DepartmentID, nil
}
