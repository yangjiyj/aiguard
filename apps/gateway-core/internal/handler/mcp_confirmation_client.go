package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
)

type MCPConfirmationTicket struct {
	ConfirmationID     string    `json:"confirmation_id"`
	InvocationID       string    `json:"invocation_id"`
	Status             string    `json:"status"`
	ExecutionStatus    string    `json:"execution_status"`
	EvidenceStatus     string    `json:"evidence_status"`
	ExpiresAt          time.Time `json:"expires_at"`
	ExecutionForwarded bool      `json:"execution_forwarded"`
	RetryAfterMS       int       `json:"retry_after_ms"`
	ResultAvailable    bool      `json:"result_available"`
	ErrorCode          string    `json:"error_code"`
	AuditRequestID     string    `json:"audit_request_id,omitempty"`
	ToolLogID          string    `json:"tool_log_id,omitempty"`
}

type MCPConfirmationCreateError struct {
	HTTPStatus int
	Code       string
	Ticket     MCPConfirmationTicket
}

func (e *MCPConfirmationCreateError) Error() string {
	return fmt.Sprintf("MCP confirmation status %d: %s", e.HTTPStatus, e.Code)
}

func IsMCPReplayConflict(err error) bool {
	var typed *MCPConfirmationCreateError
	return errors.As(err, &typed) && typed.Code == "replay_conflict"
}

// CreateMCPConfirmation persists the exact single tools/call request only inside
// the encrypted replay-context field. The ordinary plaintext arguments column is
// intentionally omitted.
func (c *ToolRiskClient) CreateMCPConfirmation(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	decision agentguard.Decision,
	serverID, qualifiedToolName, toolName, toolCallID string,
	toolID, supplyChainRevision, approvedSchemaHash, serverRouteHash string,
	requestBody []byte,
	protocolVersion, mcpSessionID string,
) (*MCPConfirmationTicket, error) {
	if c == nil || envelope == nil || envelope.TenantID == "" {
		return nil, fmt.Errorf("MCP confirmation identity is incomplete")
	}
	if len(requestBody) == 0 || len(requestBody) > maxMCPRequestBodyBytes {
		return nil, fmt.Errorf("MCP confirmation request body is invalid")
	}
	if strings.TrimSpace(protocolVersion) == "" {
		protocolVersion = mcpProtocolVersionLatest
	}
	replay := buildMCPConfirmationReplayContext(
		envelope, serverID, toolName, toolCallID, decision.OperationID, toolID, supplyChainRevision,
		approvedSchemaHash, serverRouteHash, requestBody, protocolVersion, mcpSessionID,
	)
	traceID := decision.TraceID
	if traceID == "" {
		traceID = envelope.TraceID
	}
	payload := map[string]any{
		"tool_call_id":       toolCallID,
		"choice_index":       0,
		"request_id":         envelope.RequestID,
		"trace_id":           traceID,
		"tool_name":          qualifiedToolName,
		"raw_decision":       decision.RawDecision,
		"effective_decision": decision.EffectiveDecision,
		"timeout_action":     "block",
		"reason":             decision.Reason,
		"evidence_json":      map[string]any{"evidence": decision.Evidence},
		"expires_at":         time.Now().Add(10 * time.Minute),
		"source":             "mcp",
		"mcp_replay_context": replay,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/admin/v1/internal/agentguard/confirmations", strings.TrimRight(c.controlPlaneURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode >= http.StatusBadRequest {
		var failure struct {
			Error struct {
				Code string                `json:"code"`
				Data MCPConfirmationTicket `json:"data"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &failure)
		return nil, &MCPConfirmationCreateError{HTTPStatus: resp.StatusCode, Code: failure.Error.Code, Ticket: failure.Error.Data}
	}
	var ticket MCPConfirmationTicket
	if err := json.Unmarshal(responseBody, &ticket); err != nil {
		return nil, fmt.Errorf("decode MCP confirmation ticket: %w", err)
	}
	if ticket.ConfirmationID == "" || ticket.InvocationID == "" {
		return nil, errors.New("MCP confirmation ticket is incomplete")
	}
	return &ticket, nil
}

func buildMCPConfirmationReplayContext(
	envelope *modelrouter.RequestEnvelope,
	serverID, toolName, toolCallID, operationID, toolID, supplyChainRevision, approvedSchemaHash, serverRouteHash string,
	requestBody []byte, protocolVersion, mcpSessionID string,
) mcpconfirmation.ReplayContext {
	return mcpconfirmation.ReplayContext{
		Version:  mcpconfirmation.ReplayContextVersion,
		TenantID: envelope.TenantID, ProjectID: envelope.ProjectID, UserID: envelope.UserID,
		ClientID: envelope.ClientID, KeyPrefix: envelope.KeyPrefix, AgentType: envelope.AgentType,
		EnvironmentScope: envelope.EnvironmentScope,
		AgentSessionID:   envelope.SessionID, SourceIP: envelope.SourceIP, TraceID: envelope.TraceID,
		OriginalRequest: envelope.RequestID, ServerID: serverID, ToolName: toolName,
		ToolCallID: toolCallID, ProtocolVersion: protocolVersion, MCPSessionID: mcpSessionID,
		OperationID: operationID,
		ToolID:      toolID, SupplyChainRevision: supplyChainRevision,
		ApprovedSchemaHash: approvedSchemaHash, ServerRouteHash: serverRouteHash,
		RequestBody: append(json.RawMessage(nil), requestBody...),
	}
}
