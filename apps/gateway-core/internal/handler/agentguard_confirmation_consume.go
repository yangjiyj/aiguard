package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// W5 5.2: a non-MCP tool call that needs human confirmation used to be
// rejected forever: the admin approval promised "the client may retry", but
// nothing on the gateway ever looked the approval up. On retry the gateway now
// asks the control plane to redeem one approved, unused confirmation bound to
// the same tenant, requester (user + API key), tool name and canonical
// arguments. Redemption is single-use and atomic on the control plane.

const agentGuardConfirmationConsumedReason = "human_approved_confirmation_consumed"

// ConsumeApprovedAgentGuardConfirmation returns the redeemed confirmation ID,
// or "" when nothing matched. Any transport error is returned so the caller
// keeps the confirm decision (fail closed).
func (c *ToolRiskClient) ConsumeApprovedAgentGuardConfirmation(ctx context.Context, envelope *modelrouter.RequestEnvelope, toolName, toolCallID, toolCallArguments string) (string, error) {
	if c == nil || envelope == nil || envelope.TenantID == "" || strings.TrimSpace(toolName) == "" {
		return "", nil
	}
	if envelope.UserID == "" && envelope.ClientID == "" {
		return "", nil
	}
	body, err := json.Marshal(map[string]any{
		"tool_call_id":        toolCallID,
		"tool_name":           toolName,
		"tool_call_arguments": toolCallArguments,
		"requester_user_id":   envelope.UserID,
		"requester_client_id": envelope.ClientID,
		"request_id":          envelope.RequestID,
	})
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/admin/v1/internal/agentguard/confirmations/consume", strings.TrimRight(c.controlPlaneURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		// Older control plane without the consume endpoint.
		return "", nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("agentguard confirmation consume status %d", resp.StatusCode)
	}
	var payload struct {
		Data struct {
			Consumed       bool   `json:"consumed"`
			ConfirmationID string `json:"confirmation_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("decode agentguard confirmation consume: %w", err)
	}
	if !payload.Data.Consumed {
		return "", nil
	}
	if payload.Data.ConfirmationID == "" {
		return "consumed", nil
	}
	return payload.Data.ConfirmationID, nil
}

// redeemApprovedAgentGuardConfirmation downgrades a confirm decision to a
// recorded pass when an approved confirmation for this exact call exists.
// It returns the decision unchanged when nothing is redeemed.
func (h *ChatCompletionsHandler) redeemApprovedAgentGuardConfirmation(ctx context.Context, envelope *modelrouter.RequestEnvelope, tc ToolCall, decision agentguard.Decision) agentguard.Decision {
	if decision.EffectiveDecision != agentguard.DecisionConfirm || h.toolRiskClient == nil {
		return decision
	}
	confirmationID, err := h.toolRiskClient.ConsumeApprovedAgentGuardConfirmation(ctx, envelope, tc.Function.Name, tc.ID, tc.Function.Arguments)
	if err != nil || confirmationID == "" {
		return decision
	}
	decision.EffectiveDecision = agentguard.DecisionAudit
	decision.EffectiveReason = agentGuardConfirmationConsumedReason
	if decision.FinalAction == agentguard.DestructiveActionConfirm {
		decision.FinalAction = agentguard.DestructiveActionAlertAllow
	}
	decision.Evidence = append(decision.Evidence, agentguard.Evidence{
		RuleID:        "agentguard_confirmation",
		SourceField:   "confirmation_id",
		MaskedPreview: confirmationID,
	})
	if h.auditWriter != nil {
		h.auditWriter.WriteSecurityEvent(withSecurityEventStage(ctx, "tool"), envelope, []SecurityFinding{{
			Type: "security_audit", Severity: normalizeAgentGuardRiskLevel(decision.RiskLevel),
			Category: "agentguard_confirmation", RuleName: tc.Function.Name, Action: "audit",
			MatchedLocation: "tool", EvidenceReason: agentGuardConfirmationConsumedReason,
		}}, "security_audit", fmt.Sprintf("tool %q released once by approved confirmation %s", tc.Function.Name, confirmationID))
	}
	return decision
}
