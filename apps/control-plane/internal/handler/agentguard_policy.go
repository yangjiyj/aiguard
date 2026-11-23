package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpprotocol"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func ListAgentGuardPolicies(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		policies, err := deps.AgentGuardPolicyRepo.ListPolicies(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if policies == nil {
			policies = []*repository.AgentGuardPolicy{}
		}
		writeAgentGuardJSON(w, map[string]any{"data": policies})
	}
}

type agentGuardPolicyRequest struct {
	Name          string         `json:"name"`
	ScopeType     string         `json:"scope_type"`
	ScopeRef      string         `json:"scope_ref"`
	Mode          string         `json:"mode"`
	DefaultAction string         `json:"default_action"`
	FailPolicy    string         `json:"fail_policy"`
	Priority      int            `json:"priority"`
	Enabled       *bool          `json:"enabled"`
	TemplateID    string         `json:"template_id"`
	RulesJSON     map[string]any `json:"rules_json"`
	BehaviorJSON  map[string]any `json:"behavior_json"`
	DLPJSON       map[string]any `json:"dlp_json"`
}

func (req agentGuardPolicyRequest) policy(id, tenantID, actorID string) *repository.AgentGuardPolicy {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	mode := req.Mode
	if mode == "" {
		mode = repository.AgentGuardModeAudit
	}
	defaultAction := req.DefaultAction
	if defaultAction == "" {
		defaultAction = repository.AgentGuardActionAudit
	}
	failPolicy := req.FailPolicy
	if failPolicy == "" {
		failPolicy = repository.AgentGuardFailClosed
	}
	return &repository.AgentGuardPolicy{
		ID:            id,
		TenantID:      tenantID,
		Name:          req.Name,
		ScopeType:     req.ScopeType,
		ScopeRef:      req.ScopeRef,
		Mode:          mode,
		DefaultAction: defaultAction,
		FailPolicy:    failPolicy,
		Priority:      req.Priority,
		Enabled:       enabled,
		TemplateID:    req.TemplateID,
		RulesJSON:     req.RulesJSON,
		BehaviorJSON:  req.BehaviorJSON,
		DLPJSON:       req.DLPJSON,
		CreatedBy:     actorID,
		UpdatedBy:     actorID,
	}
}

func CreateAgentGuardPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) && user.Role != "platform_connector" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage AgentGuard policies")
			return
		}
		var req agentGuardPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		policy := req.policy("", user.TenantID, user.ID)
		if err := repository.ValidateAgentGuardPolicy(policy); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := validateAgentGuardBehaviorThresholds(req.BehaviorJSON); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		stored, version, err := deps.AgentGuardPolicyRepo.CreatePolicyWithVersion(r.Context(), policy, user.ID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if stored == nil || version == nil {
			writeError(w, "internal_error", "created AgentGuard policy state is incomplete")
			return
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "agentguard_policy.create", map[string]any{"policy_id": stored.ID, "policy_version": version.PolicyVersion}, "agentguard_policy", stored.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"policy": stored, "version": version})
	}
}

func UpdateAgentGuardPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) && user.Role != "platform_connector" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage AgentGuard policies")
			return
		}
		policyID := chi.URLParam(r, "id")
		if policyID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "policy id is required")
			return
		}
		var req agentGuardPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		policy := req.policy(policyID, user.TenantID, user.ID)
		if err := repository.ValidateAgentGuardPolicy(policy); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := validateAgentGuardBehaviorThresholds(req.BehaviorJSON); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		stored, version, updated, err := deps.AgentGuardPolicyRepo.UpdatePolicyWithVersion(r.Context(), policy, user.ID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if !updated {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "AgentGuard policy not found")
			return
		}
		if stored == nil || version == nil {
			writeError(w, "internal_error", "updated AgentGuard policy state is incomplete")
			return
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "agentguard_policy.update", map[string]any{"policy_id": stored.ID, "policy_version": version.PolicyVersion}, "agentguard_policy", stored.ID)
		writeAgentGuardJSON(w, map[string]any{"policy": stored, "version": version})
	}
}

func ListAgentGuardPolicyVersions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		policyID := chi.URLParam(r, "id")
		versions, err := deps.AgentGuardPolicyRepo.ListVersions(r.Context(), user.TenantID, policyID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		writeAgentGuardJSON(w, map[string]any{"data": versions})
	}
}

func RollbackAgentGuardPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can rollback AgentGuard policies")
			return
		}
		var req struct {
			VersionID string `json:"version_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.VersionID == "" {
			writeError(w, "invalid_request", "version_id is required")
			return
		}
		policyID := chi.URLParam(r, "id")
		policy, err := deps.AgentGuardPolicyRepo.RollbackPolicy(r.Context(), user.TenantID, policyID, req.VersionID, user.ID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if policy == nil {
			writeError(w, "not_found", "policy version not found")
			return
		}
		regenerateEndpointBundle(r.Context(), deps, user.TenantID, user.ID)
		logAudit(r, deps, "agentguard_policy.rollback", map[string]any{"policy_id": policyID, "version_id": req.VersionID}, "agentguard_policy", policyID)
		writeAgentGuardJSON(w, policy)
	}
}

func ListAgentGuardExceptions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		exceptions, err := deps.AgentGuardPolicyRepo.ListActiveExceptions(r.Context(), user.TenantID, time.Now())
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		writeAgentGuardJSON(w, map[string]any{"data": exceptions})
	}
}

func CreateAgentGuardException(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage AgentGuard exceptions")
			return
		}
		var req repository.AgentGuardException
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = user.TenantID
		req.CreatedBy = user.ID
		if err := deps.AgentGuardPolicyRepo.CreateException(r.Context(), &req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		logAudit(r, deps, "agentguard_exception.create", map[string]any{"exception_id": req.ID, "scope_type": req.ScopeType, "scope_ref": req.ScopeRef}, "agentguard_exception", req.ID)
		w.WriteHeader(http.StatusCreated)
		writeAgentGuardJSON(w, req)
	}
}

func DeleteAgentGuardException(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can delete AgentGuard exceptions")
			return
		}
		exceptionID := chi.URLParam(r, "id")
		deleted, err := deps.AgentGuardPolicyRepo.DeleteException(r.Context(), user.TenantID, exceptionID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if !deleted {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "AgentGuard exception not found")
			return
		}
		logAudit(r, deps, "agentguard_exception.delete", map[string]any{"exception_id": exceptionID}, "agentguard_exception", exceptionID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func ListAgentGuardConfirmations(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		// source 非空按来源过滤：MCP 审批页传 ?source=mcp 只看 MCP 网关来源的确认单；
		// 不传=旧口径（该租户全部确认单），AgentGuard 审批页行为不变。
		source := r.URL.Query().Get("source")
		confirmations, err := deps.AgentGuardPolicyRepo.ListConfirmations(r.Context(), user.TenantID, r.URL.Query().Get("status"), source)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		mcpIDs := make([]string, 0, len(confirmations))
		for _, confirmation := range confirmations {
			if confirmation.Source == "mcp" {
				confirmation.ToolCallArguments = ""
				mcpIDs = append(mcpIDs, confirmation.ID)
			}
		}
		states, stateErr := deps.AgentGuardPolicyRepo.ListMCPConfirmationExecutions(r.Context(), user.TenantID, mcpIDs)
		if stateErr != nil {
			writeError(w, "internal_error", stateErr.Error())
			return
		}
		for _, confirmation := range confirmations {
			if confirmation.Source == "mcp" {
				confirmation.MCPExecution = states[confirmation.ID]
			}
		}
		writeAgentGuardJSON(w, map[string]any{"data": confirmations})
	}
}

func ResolveAgentGuardConfirmation(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can resolve AgentGuard confirmations")
			return
		}
		var req struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.Status != "approved" && req.Status != "rejected" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "status must be approved or rejected")
			return
		}
		// 本人批准的审计由仓库用事务审计写：请求上下文带上审计链出口与来源地址（requestClientIP）。
		r = withOperationAudit(r, deps)
		confirmation, err := resolveAgentGuardConfirmationWS5(r.Context(), deps, user.TenantID, chi.URLParam(r, "id"), req.Status, user.ID, req.Note)
		if err != nil {
			if writeAgentGuardApproverError(w, err) {
				return
			}
			switch {
			case errors.Is(err, repository.ErrAgentGuardConfirmationResolutionConflict):
				writeErrorWithStatus(w, http.StatusConflict, "confirmation_resolution_conflict", err.Error())
			case errors.Is(err, repository.ErrAgentGuardConfirmationExpired):
				writeErrorWithStatus(w, http.StatusConflict, "confirmation_expired", err.Error())
			default:
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			}
			return
		}
		if confirmation == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "confirmation not found")
			return
		}
		// 本人批准的审计（agentguard_confirmation.self_approved）由仓库在批准的同一事务里写，提交后进审计链。
		if confirmation.AwaitingSecondApproval {
			writeAgentGuardAwaitingSecondApproval(w, r, deps, confirmation)
			return
		}
		if confirmation.Source == "mcp" {
			confirmation.ToolCallArguments = ""
			var state *repository.MCPConfirmationExecution
			if confirmation.Status == "approved" {
				claimedState, claimed, claimErr := deps.AgentGuardPolicyRepo.ClaimMCPConfirmationExecution(r.Context(), user.TenantID, confirmation.ID)
				if claimErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "mcp_execution_state_unavailable", "confirmation was approved, but MCP execution could not be claimed")
					return
				}
				state = claimedState
				if claimed {
					executeErr := error(nil)
					if deps.MCPConfirmationExecutor == nil {
						executeErr = errors.New("mcp confirmation executor is unavailable")
					} else {
						executeErr = deps.MCPConfirmationExecutor.ExecuteMCPConfirmation(r.Context(), user.TenantID, confirmation.ID, state.AttemptID)
					}
					if executeErr != nil {
						markCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
						markErr := deps.AgentGuardPolicyRepo.MarkMCPConfirmationUnknown(markCtx, user.TenantID, confirmation.ID, state.AttemptID, "gateway_response_unknown")
						cancel()
						if markErr != nil {
							writeErrorWithStatus(w, http.StatusServiceUnavailable, "mcp_execution_state_unavailable", "MCP execution outcome is uncertain and could not be persisted")
							return
						}
					}
				}
				state, claimErr = deps.AgentGuardPolicyRepo.GetMCPConfirmationExecution(r.Context(), user.TenantID, confirmation.ID)
				if claimErr != nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "mcp_execution_state_unavailable", "MCP execution outcome could not be loaded")
					return
				}
				confirmation.MCPExecution = state
			}
			if state == nil {
				var loadErr error
				state, loadErr = deps.AgentGuardPolicyRepo.GetMCPConfirmationExecution(r.Context(), user.TenantID, confirmation.ID)
				if loadErr != nil || state == nil {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "mcp_execution_state_unavailable", "MCP execution outcome could not be loaded")
					return
				}
			}
			state.ConfirmationStatus = confirmation.Status
			confirmation.MCPExecution = state
			if confirmation.ResolutionApplied {
				logAudit(r, deps, "agentguard_confirmation.resolve", map[string]any{
					"confirmation_id": confirmation.ID,
					"status":          confirmation.Status,
					"mcp_execution_status": func() string {
						if confirmation.MCPExecution != nil {
							return confirmation.MCPExecution.ExecutionStatus
						}
						return ""
					}(),
				}, "agentguard_confirmation", confirmation.ID)
			}
			writeMCPConfirmationResolution(w, state)
			return
		}

		// 同一处置的重复请求 only returns persisted local-tool retry state.
		// MCP confirmations use the single-use state machine above.
		if !confirmation.ResolutionApplied {
			// approved 已落库但批准证据与 tool log 的关联未完成时，不能用
			// 200 掩盖 Mark 失败。客户端可重试查询/处置，但服务端不会重放。
			if confirmation.Status == "approved" && confirmation.ToolCallID != "" &&
				(confirmation.ReplayStatus == "" || confirmation.ReplayStatus == "pending") && confirmation.ReplayToolLogID == "" {
				w.Header().Set("Retry-After", "1")
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "confirmation_replay_state_unavailable", "confirmation is approved, but replay evidence linkage is incomplete")
				return
			}
			writeAgentGuardJSON(w, confirmation)
			return
		}
		logAudit(r, deps, "agentguard_confirmation.resolve", map[string]any{"confirmation_id": confirmation.ID, "status": confirmation.Status}, "agentguard_confirmation", confirmation.ID)
		if confirmation.Status == "approved" && confirmation.ToolCallID != "" && deps.ConfirmationReplayer != nil {
			toolLogID, replayErr := deps.ConfirmationReplayer.ReplayConfirmation(r.Context(), confirmation)
			replayStatus := "pending"
			auditAction := "agentguard_confirmation.client_retry"
			auditMessage := "批准已记录，等待客户端使用同一调用重试；中心端未执行工具"
			if replayErr != nil {
				replayStatus = "failed"
				toolLogID = ""
				auditAction = "agentguard_confirmation.audit_failed"
				auditMessage = "批准已保存，但等待重试的审计记录写入失败；中心端未执行工具"
			}
			if err := deps.AgentGuardPolicyRepo.MarkConfirmationReplayed(r.Context(), user.TenantID, confirmation.ID, replayStatus, toolLogID); err != nil {
				w.Header().Set("Retry-After", "1")
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "confirmation_replay_state_unavailable", "confirmation was resolved, but replay state could not be persisted")
				return
			}
			confirmation.ReplayStatus = replayStatus
			confirmation.ReplayToolLogID = toolLogID
			logAudit(r, deps, auditAction, map[string]any{
				"confirmation_id":    confirmation.ID,
				"replay_status":      replayStatus,
				"tool_log_id":        toolLogID,
				"execution_observed": false,
				"message":            auditMessage,
			}, "agentguard_confirmation", confirmation.ID)
		}
		writeAgentGuardJSON(w, confirmation)
	}
}

func ListAgentGuardTemplates(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		writeAgentGuardJSON(w, map[string]any{"data": repository.AgentGuardPolicyTemplates()})
	}
}

func GetAgentGuardFalsePositiveStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		days := intQueryDefault(r, "days", 7)
		stats, err := deps.AgentGuardPolicyRepo.GetFalsePositiveStats(r.Context(), user.TenantID, days)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		writeAgentGuardJSON(w, stats)
	}
}

func SuggestAgentGuardException(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can suggest AgentGuard exceptions")
			return
		}
		var req struct {
			ToolCallID string `json:"tool_call_id"`
			Reason     string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.ToolCallID == "" || req.Reason == "" {
			writeError(w, "invalid_request", "tool_call_id and reason are required")
			return
		}
		suggestion, err := deps.AgentGuardPolicyRepo.SuggestException(r.Context(), user.TenantID, req.ToolCallID, req.Reason, user.ID, time.Now().UTC())
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		writeAgentGuardJSON(w, suggestion)
	}
}

func SimulateAgentGuardPolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can simulate AgentGuard policies")
			return
		}
		var req repository.AgentGuardPolicySimulationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		result, err := deps.AgentGuardPolicyRepo.SimulatePolicy(r.Context(), user.TenantID, req)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		writeAgentGuardJSON(w, result)
	}
}

func GetAgentGuardBehaviorBaseline(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		days := intQueryDefault(r, "days", 7)
		baseline, err := deps.AgentGuardPolicyRepo.GetBehaviorBaseline(r.Context(), user.TenantID, days)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		writeAgentGuardJSON(w, baseline)
	}
}

func ListAgentGuardRollouts(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		rollouts, err := deps.AgentGuardPolicyRepo.ListRollouts(r.Context(), user.TenantID, r.URL.Query().Get("status"))
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		writeAgentGuardJSON(w, map[string]any{"data": rollouts})
	}
}

func CreateAgentGuardRollout(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can create AgentGuard rollouts")
			return
		}
		var req repository.AgentGuardRollout
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = user.TenantID
		req.CreatedBy = user.ID
		if err := deps.AgentGuardPolicyRepo.CreateRollout(r.Context(), &req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		logAudit(r, deps, "agentguard_rollout.create", map[string]any{"rollout_id": req.ID, "policy_id": req.PolicyID, "scope_type": req.ScopeType, "scope_ref": req.ScopeRef}, "agentguard_rollout", req.ID)
		w.WriteHeader(http.StatusCreated)
		writeAgentGuardJSON(w, req)
	}
}

// canManageAgentGuard 判定能否管理 AgentGuard / MCP / Skill 等安全设置。
// 三员分立下 security_officer 按 SoD 对 SecurityWrite / SecurityConfigRead 类路由是 SoDAllow，handler 层不得比 SoD 更严，
// 否则安全员在 SoD 通过后又被这里二次拦截，管不了红线、白名单模板、MCP 策略与准入等本职设置。
// 与规则、检测器、内容安全、工具风险、回复策略等同类 handler 一致（roles.CanManageSecurityPolicy 含 security_officer）。
// 其余角色不变；auditor、developer、viewer、dept_manager 等仍然拒绝（SoD 对 auditor 同样拒绝）。
func canManageAgentGuard(role string) bool {
	return role == "platform_admin" || role == "tenant_owner" || role == "tenant_admin" || role == "admin" || roles.IsSecurityOfficer(role)
}

func intQueryDefault(r *http.Request, key string, fallback int) int {
	value := r.URL.Query().Get(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func writeAgentGuardJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func GetInternalAgentGuardEffectivePolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		policies, err := deps.AgentGuardPolicyRepo.ListPolicies(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		policy := repository.ResolveAgentGuardPolicy(policies, repository.AgentGuardPolicyScope{
			TenantID:  tenantID,
			ProjectID: r.URL.Query().Get("project_id"),
			UserID:    r.URL.Query().Get("user_id"),
			KeyPrefix: r.URL.Query().Get("key_prefix"),
			AgentID:   r.URL.Query().Get("agent_id"),
			SessionID: r.URL.Query().Get("session_id"),
		})
		legacyMode := ""
		if policy != nil {
			legacyMode = policy.Mode
		}
		effective := &repository.AgentOperationEffectivePolicy{
			Mode: "audit", Action: "record", ConfigSource: "system_default",
		}
		switch strings.ToLower(strings.TrimSpace(legacyMode)) {
		case "observe", "audit":
			effective.Mode, effective.Action, effective.ConfigSource = "audit", "record", "mode_preset"
		case "light":
			effective.Mode, effective.Action, effective.ConfigSource = "light", "alert_allow", "mode_preset"
		case "strict":
			effective.Mode, effective.Action, effective.ConfigSource = "strict", "block", "mode_preset"
		}
		if deps.AgentOperationRepo != nil {
			effective, err = deps.AgentOperationRepo.ResolveEffectivePolicy(r.Context(), tenantID, repository.AgentOperationEffectivePolicyInput{
				ApplicationID: r.URL.Query().Get("project_id"),
				AgentType:     r.URL.Query().Get("agent_id"),
				Protocol:      r.URL.Query().Get("protocol"),
				Mode:          legacyMode,
			})
			if err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
		}
		if policy == nil {
			protections, err := protectionsForEffectivePolicy(r.Context(), deps, tenantID, nil, nil)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load protection settings")
				return
			}
			// 例外是租户级的：没有 AgentGuard 策略时也下发，指向防护项（受限文件、兜底项等）的例外照样生效。
			exceptions, err := deps.AgentGuardPolicyRepo.ListActiveExceptions(r.Context(), tenantID, time.Now())
			if err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
			data := map[string]any{
				"protections": protections,
				"mode":        effective.Mode, "default_action": "audit", "fail_policy": "fail_open",
				// 确认单在控制台审批、重试由网关兑现一次，每个租户都有这条通道（与有 AgentGuard 策略的租户
				// 一致）；以前只对 MCP 为真，非 MCP 协议的确认一律当成没通道。
				"confirm_channel_enabled": true,
				"rules":                   []any{}, "exceptions": agentGuardExceptionsForPolicy(exceptions),
			}
			applyAgentOperationEffectivePolicy(data, effective)
			writeAgentGuardJSON(w, map[string]any{"data": data})
			return
		}
		versions, _ := deps.AgentGuardPolicyRepo.ListVersions(r.Context(), tenantID, policy.ID)
		policyVersion := ""
		for _, version := range versions {
			if version.Active {
				policyVersion = version.PolicyVersion
				break
			}
		}
		if policyVersion == "" && len(versions) > 0 {
			policyVersion = versions[0].PolicyVersion
		}
		exceptions, err := deps.AgentGuardPolicyRepo.ListActiveExceptions(r.Context(), tenantID, time.Now())
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		data := map[string]any{
			"id":                      policy.ID,
			"name":                    policy.Name,
			"policy_version":          policyVersion,
			"mode":                    policy.Mode,
			"default_action":          policy.DefaultAction,
			"fail_policy":             policy.FailPolicy,
			"confirm_channel_enabled": true,
			"rules":                   agentGuardRulesFromJSON(policy.RulesJSON),
			"exceptions":              agentGuardExceptionsForPolicy(exceptions),
		}
		behavior := agentGuardBehaviorFromJSON(policy.BehaviorJSON)
		if behavior != nil {
			data["behavior"] = behavior
		}
		dlp := agentGuardDLPFromJSON(policy.DLPJSON)
		if dlp != nil {
			data["dlp"] = dlp
		}
		protections, err := protectionsForEffectivePolicy(r.Context(), deps, tenantID, dlp, behavior)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load protection settings")
			return
		}
		data["protections"] = protections
		applyAgentOperationEffectivePolicy(data, effective)
		writeAgentGuardJSON(w, map[string]any{"data": data})
	}
}

func applyAgentOperationEffectivePolicy(data map[string]any, effective *repository.AgentOperationEffectivePolicy) {
	if effective == nil {
		return
	}
	data["mode"] = effective.Mode
	data["config_source"] = effective.ConfigSource
	data["protocol"] = effective.Protocol
	data["discardable_paths"] = effective.DiscardablePaths
	data["notify_channel_ids"] = effective.NotifyChannelIDs
	data["restricted_file_patterns"] = effective.RestrictedFilePatterns
	data["restricted_file_action"] = effective.RestrictedFileAction
	scopes := effective.RestrictedFileScopes
	if scopes == nil {
		scopes = repository.DefaultRestrictedFileScopes()
	}
	data["restricted_file_scopes"] = scopes
	data["destructive"] = map[string]any{
		"mode": effective.Mode, "action": effective.Action,
		"scope_type": effective.ScopeType, "scope_ref": effective.ScopeRef,
		"protocol": effective.Protocol,
	}
}

const maxMCPConfirmationRequestBodyBytes = 4 << 20

func CreateAgentGuardConfirmationInternal(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		var req struct {
			repository.AgentGuardConfirmation
			MCPReplayContext json.RawMessage `json:"mcp_replay_context"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMCPConfirmationRequestBodyBytes+64*1024))
		if err := decoder.Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = tenantID
		switch req.Source {
		case "":
			if len(req.MCPReplayContext) != 0 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "mcp_replay_context is only valid for MCP confirmations")
				return
			}
			if err := deps.AgentGuardPolicyRepo.CreateConfirmation(r.Context(), &req.AgentGuardConfirmation); err != nil {
				writeError(w, "internal_error", err.Error())
				return
			}
		case "mcp":
			if req.ToolCallArguments != "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "plaintext_mcp_arguments_forbidden", "MCP arguments must only be supplied inside encrypted replay context")
				return
			}
			ciphertext, contextHash, identity, err := encryptMCPReplayContext(
				deps.MCPConfirmationScopeSecret, tenantID, req.ToolCallID, req.MCPReplayContext,
			)
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_mcp_replay_context", err.Error())
				return
			}
			state, created, createErr := deps.AgentGuardPolicyRepo.CreateMCPConfirmationDeduplicated(
				r.Context(), &req.AgentGuardConfirmation, identity, ciphertext, contextHash,
			)
			if errors.Is(createErr, repository.ErrMCPReplayConflict) {
				writeMCPConfirmationError(w, http.StatusConflict, "replay_conflict", "MCP invocation already exists with different request content", state)
				return
			}
			if createErr != nil {
				writeError(w, "internal_error", "failed to create MCP confirmation")
				return
			}
			if created {
				recordMCPConfirmationRequester(r.Context(), deps, tenantID, req.ID, req.MCPReplayContext)
			}
			status := http.StatusOK
			if created {
				status = http.StatusCreated
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(safeMCPConfirmationState(state))
			return
		default:
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "unsupported confirmation source")
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeAgentGuardJSON(w, req.AgentGuardConfirmation)
	}
}

func agentGuardRulesFromJSON(raw map[string]any) []map[string]any {
	items, _ := raw["rules"].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"id":                   m["id"],
			"name":                 m["name"],
			"tool_pattern":         m["tool_pattern"],
			"action":               m["action"],
			"enabled":              m["enabled"],
			"policy_center_action": m[policyCenterRuleActionKey],
		})
	}
	return out
}

// maxBehaviorBurstThreshold 是行为基线突发阈值的上限，与注册表“次数”参数的上限（1000）一致。
const maxBehaviorBurstThreshold = 1000

// validateAgentGuardBehaviorThresholds：保存行为基线时，三类突发阈值（*_burst_10s）若是数字，须是
// 0 到 maxBehaviorBurstThreshold 的整数。只在管理员提交 behavior_json 的创建、更新接口校验，
// 策略中心改卡片时原样带回的旧值不因此保存失败。
func validateAgentGuardBehaviorThresholds(behavior map[string]any) error {
	for _, key := range []string{"file_read_burst_10s", "network_egress_burst_10s", "command_execute_burst_10s"} {
		value, ok := behavior[key].(float64)
		if !ok {
			continue
		}
		if value < 0 || value > maxBehaviorBurstThreshold || value != math.Trunc(value) {
			return fmt.Errorf("behavior_json.%s must be an integer between 0 and %d", key, maxBehaviorBurstThreshold)
		}
	}
	return nil
}

// agentGuardBehaviorFromJSON 从持久化的行为基线 JSON 中白名单提取三类突发阈值，下发给网关执行面；
// 入参为空或无任何已知键时返回 nil，调用方据此不下发 behavior 键（网关退回内置默认阈值）。
func agentGuardBehaviorFromJSON(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, key := range []string{"file_read_burst_10s", "network_egress_burst_10s", "command_execute_burst_10s", agentGuardSequenceWindowKey} {
		if v, ok := raw[key]; ok {
			out[key] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// agentGuardDLPFromJSON 从持久化的 DLP JSON 中提取高可信密钥外泄处置动作，下发给网关执行面；
// 入参为空或缺该键时返回 nil，调用方据此不下发 dlp 键（网关退回默认 block）。
func agentGuardDLPFromJSON(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	out := map[string]any{}
	if v, ok := raw["high_confidence_secret_egress"]; ok {
		out["high_confidence_secret_egress"] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func agentGuardExceptionsForPolicy(exceptions []*repository.AgentGuardException) []map[string]any {
	out := make([]map[string]any, 0, len(exceptions))
	for _, e := range exceptions {
		out = append(out, map[string]any{
			"id":             e.ID,
			"rule_id":        e.RuleID,
			"target_pattern": e.TargetPattern,
			"decision":       e.Decision,
			"expires_at":     e.ExpiresAt,
		})
	}
	return out
}

func encryptMCPReplayContext(scopeSecret, tenantID, toolCallID string, raw json.RawMessage) (string, string, repository.MCPConfirmationIdentity, error) {
	if len(raw) == 0 || len(raw) > maxMCPConfirmationRequestBodyBytes+32*1024 {
		return "", "", repository.MCPConfirmationIdentity{}, errors.New("MCP replay context is missing or too large")
	}
	var replay mcpconfirmation.ReplayContext
	if err := json.Unmarshal(raw, &replay); err != nil {
		return "", "", repository.MCPConfirmationIdentity{}, errors.New("MCP replay context is not valid JSON")
	}
	if replay.Version != mcpconfirmation.ReplayContextVersion ||
		replay.TenantID != tenantID || replay.ServerID == "" || replay.ToolName == "" ||
		replay.ToolCallID == "" || replay.ToolCallID != toolCallID ||
		len(replay.RequestBody) == 0 || len(replay.RequestBody) > maxMCPConfirmationRequestBodyBytes ||
		!json.Valid(replay.RequestBody) {
		return "", "", repository.MCPConfirmationIdentity{}, errors.New("MCP replay context identity is incomplete or inconsistent")
	}
	if !mcpprotocol.IsSupported(replay.ProtocolVersion) {
		return "", "", repository.MCPConfirmationIdentity{}, errors.New("MCP replay context protocol version is unsupported")
	}
	if replay.ToolID == "" || replay.SupplyChainRevision == "" || replay.ApprovedSchemaHash == "" || replay.ServerRouteHash == "" {
		return "", "", repository.MCPConfirmationIdentity{}, errors.New("MCP approved supply-chain context is incomplete")
	}
	scopeKey, err := mcpconfirmation.ScopeKey(scopeSecret, replay)
	if err != nil {
		return "", "", repository.MCPConfirmationIdentity{}, err
	}
	requestHash, err := mcpconfirmation.CanonicalRequestHash(replay)
	if err != nil {
		return "", "", repository.MCPConfirmationIdentity{}, err
	}
	principalHash, err := mcpconfirmation.PrincipalFingerprint(scopeSecret, replay)
	if err != nil {
		return "", "", repository.MCPConfirmationIdentity{}, err
	}
	identity := repository.MCPConfirmationIdentity{
		ScopeKey: scopeKey, CanonicalRequestHash: requestHash, PrincipalHash: principalHash,
		ToolID: replay.ToolID, SupplyChainRevision: replay.SupplyChainRevision,
		ApprovedSchemaHash: replay.ApprovedSchemaHash, ServerRouteHash: replay.ServerRouteHash,
	}
	plaintext, err := json.Marshal(replay)
	if err != nil {
		return "", "", repository.MCPConfirmationIdentity{}, err
	}
	ciphertext, _, err := secrets.EncryptProviderSecret(string(plaintext))
	if err != nil {
		return "", "", repository.MCPConfirmationIdentity{}, err
	}
	if !strings.HasPrefix(ciphertext, "enc:v1:") {
		return "", "", repository.MCPConfirmationIdentity{}, errors.New("MCP replay context encryption is unavailable")
	}
	digest := sha256.Sum256(plaintext)
	return ciphertext, hex.EncodeToString(digest[:]), identity, nil
}

func writeMCPConfirmationResolution(w http.ResponseWriter, state *repository.MCPConfirmationExecution) {
	if state == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "mcp_execution_state_unavailable", "MCP execution state is unavailable")
		return
	}
	if state.ErrorCode == "approval_expired" {
		writeMCPConfirmationError(w, http.StatusConflict, "approval_expired", "confirmation approval expired before execution", state)
		return
	}
	status := http.StatusOK
	if state.ConfirmationStatus == "approved" {
		switch state.ExecutionStatus {
		case "pending", "executing", "":
			status = http.StatusAccepted
			w.Header().Set("Retry-After", "1")
		case "executed", "failed", "unknown":
			status = http.StatusOK
		default:
			status = http.StatusAccepted
			w.Header().Set("Retry-After", "1")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(safeMCPConfirmationState(state))
}

func safeMCPConfirmationState(state *repository.MCPConfirmationExecution) map[string]any {
	if state == nil {
		return map[string]any{}
	}
	status := state.ConfirmationStatus
	if status == "" {
		status = state.ExecutionStatus
	}
	executionForwarded, _ := state.ResponseSummary["execution_forwarded"].(bool)
	out := map[string]any{
		"confirmation_id":     state.ConfirmationID,
		"invocation_id":       state.InvocationID,
		"status":              status,
		"execution_status":    state.ExecutionStatus,
		"evidence_status":     state.EvidenceStatus,
		"expires_at":          state.ExpiresAt,
		"retry_after_ms":      100,
		"result_available":    state.ResultAvailable,
		"error_code":          state.ErrorCode,
		"execution_forwarded": executionForwarded,
	}
	if state.EvidenceStatus == "complete" {
		out["audit_request_id"] = state.AuditRequestID
		out["tool_log_id"] = state.ToolLogID
	}
	return out
}

func writeMCPConfirmationError(w http.ResponseWriter, status int, code, message string, state *repository.MCPConfirmationExecution) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"code": code, "message": message, "data": safeMCPConfirmationState(state)},
	})
}

// Source writes already committed; regeneration failure must not alter their response.
func regenerateEndpointBundle(ctx context.Context, deps *Dependencies, tenant, actor string) {
	if deps.AgentEndpointBundleRepo == nil {
		return
	}
	if _, err := deps.AgentEndpointBundleRepo.RegenerateIfChanged(ctx, tenant, actor); err != nil {
		log.Printf("endpoint policy bundle regeneration failed tenant=%s: %v", tenant, err)
	}
}
