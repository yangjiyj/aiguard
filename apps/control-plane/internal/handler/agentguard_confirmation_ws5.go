package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// W5 5.2 / 5.3: single-use consumption of approved non-MCP confirmations and
// approver separation. Kept in its own file so the shared handler/interface
// files stay untouched; optional repository capabilities are discovered by
// type assertion, so older fakes keep their legacy behaviour.

// agentGuardDualApprovalSettingKey (system_settings) turns on two-person
// approval for AgentGuard / MCP confirmations. Default off.
const agentGuardDualApprovalSettingKey = "agentguard_dual_approval"

// agentGuardAllowSelfApprovalSettingKey (system_settings) 允许触发调用的人批准自己的确认单
// （2.9.22，true/false，默认 false 即保持禁止）。本人批准写审计 agentguard_confirmation.self_approved。
const agentGuardAllowSelfApprovalSettingKey = "agentguard_allow_self_approval"

type agentGuardConfirmationPolicyResolver interface {
	ResolveConfirmationWithPolicy(ctx context.Context, tenantID, id, status, actorID, note string, policy repository.AgentGuardApprovalPolicy) (*repository.AgentGuardConfirmation, error)
}

type agentGuardConfirmationConsumer interface {
	ConsumeApprovedConfirmation(ctx context.Context, req repository.AgentGuardConfirmationConsumeRequest) (*repository.AgentGuardConfirmation, error)
}

type agentGuardConfirmationRequesterSetter interface {
	SetConfirmationRequester(ctx context.Context, tenantID, id, userID, clientID string) error
}

func agentGuardApprovalPolicyFor(ctx context.Context, deps *Dependencies) repository.AgentGuardApprovalPolicy {
	policy := repository.AgentGuardApprovalPolicy{}
	if deps == nil || deps.SystemRepo == nil {
		return policy
	}
	dual, err := deps.SystemRepo.GetBool(ctx, agentGuardDualApprovalSettingKey)
	if err == nil {
		policy.RequireDualApproval = dual
	}
	// 读失败按默认（禁止本人批准）处理。
	if allowSelf, err := deps.SystemRepo.GetBool(ctx, agentGuardAllowSelfApprovalSettingKey); err == nil {
		policy.AllowSelfApproval = allowSelf
	}
	return policy
}

// resolveAgentGuardConfirmationWS5 applies the approval policy when the
// repository supports it; otherwise it falls back to the legacy resolver
// (which, in the production repository, still rejects self-approval).
func resolveAgentGuardConfirmationWS5(ctx context.Context, deps *Dependencies, tenantID, id, status, actorID, note string) (*repository.AgentGuardConfirmation, error) {
	if resolver, ok := deps.AgentGuardPolicyRepo.(agentGuardConfirmationPolicyResolver); ok {
		return resolver.ResolveConfirmationWithPolicy(ctx, tenantID, id, status, actorID, note, agentGuardApprovalPolicyFor(ctx, deps))
	}
	return deps.AgentGuardPolicyRepo.ResolveConfirmation(ctx, tenantID, id, status, actorID, note)
}

// writeAgentGuardApproverError maps the 5.3 approver errors. It reports
// whether err was one of them.
func writeAgentGuardApproverError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, repository.ErrAgentGuardConfirmationSelfApproval):
		writeErrorWithStatus(w, http.StatusForbidden, "confirmation_self_approval_forbidden", "审批人不能批准自己触发的工具调用")
		return true
	case errors.Is(err, repository.ErrAgentGuardConfirmationSameApprover):
		writeErrorWithStatus(w, http.StatusConflict, "confirmation_second_approver_required", "已开启双人审批，第二次批准必须由另一位审批人完成")
		return true
	}
	return false
}

// writeAgentGuardAwaitingSecondApproval answers a first approval under dual
// approval: nothing is executed or released yet.
func writeAgentGuardAwaitingSecondApproval(w http.ResponseWriter, r *http.Request, deps *Dependencies, c *repository.AgentGuardConfirmation) {
	logAudit(r, deps, "agentguard_confirmation.first_approval", map[string]any{
		"confirmation_id": c.ID,
		"status":          c.Status,
	}, "agentguard_confirmation", c.ID)
	out := *c
	if out.Source == "mcp" {
		out.ToolCallArguments = ""
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(out)
}

// recordMCPConfirmationRequester copies the requester from the MCP replay
// context onto the confirmation row so 5.3 applies to MCP approvals too.
func recordMCPConfirmationRequester(ctx context.Context, deps *Dependencies, tenantID, confirmationID string, rawReplay json.RawMessage) {
	setter, ok := deps.AgentGuardPolicyRepo.(agentGuardConfirmationRequesterSetter)
	if !ok || confirmationID == "" {
		return
	}
	var identity struct {
		UserID   string `json:"user_id"`
		ClientID string `json:"client_id"`
	}
	if json.Unmarshal(rawReplay, &identity) != nil {
		return
	}
	_ = setter.SetConfirmationRequester(ctx, tenantID, confirmationID, identity.UserID, identity.ClientID)
}

type agentGuardConfirmationConsumeBody struct {
	ToolCallID        string `json:"tool_call_id"`
	ToolName          string `json:"tool_name"`
	ToolCallArguments string `json:"tool_call_arguments"`
	RequesterUserID   string `json:"requester_user_id"`
	RequesterClientID string `json:"requester_client_id"`
	RequestID         string `json:"request_id"`
}

// ConsumeAgentGuardConfirmationInternal lets the gateway redeem an approved
// non-MCP confirmation exactly once when the client retries the same call.
// Response: {"data":{"consumed":bool,"confirmation_id":...}}.
func ConsumeAgentGuardConfirmationInternal(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		var body agentGuardConfirmationConsumeBody
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMCPConfirmationRequestBodyBytes+64*1024))
		if err := decoder.Decode(&body); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if strings.TrimSpace(body.ToolName) == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "tool_name is required")
			return
		}
		consumer, ok := deps.AgentGuardPolicyRepo.(agentGuardConfirmationConsumer)
		if !ok {
			writeAgentGuardJSON(w, map[string]any{"data": map[string]any{"consumed": false}})
			return
		}
		c, err := consumer.ConsumeApprovedConfirmation(r.Context(), repository.AgentGuardConfirmationConsumeRequest{
			TenantID:          tenantID,
			ToolCallID:        body.ToolCallID,
			ToolName:          body.ToolName,
			ArgumentsHash:     repository.AgentGuardArgumentsHash(body.ToolCallArguments),
			RequesterUserID:   body.RequesterUserID,
			RequesterClientID: body.RequesterClientID,
			RequestID:         body.RequestID,
		})
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "confirmation_consume_unavailable", "approved confirmation lookup failed")
			return
		}
		if c == nil {
			writeAgentGuardJSON(w, map[string]any{"data": map[string]any{"consumed": false}})
			return
		}
		writeAgentGuardJSON(w, map[string]any{"data": map[string]any{
			"consumed":        true,
			"confirmation_id": c.ID,
			"resolved_by":     c.ResolvedBy,
		}})
	}
}
