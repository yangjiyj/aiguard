package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type mcpConfirmationPollResult struct {
	Ticket     MCPConfirmationTicket
	Body       []byte
	HTTPStatus int
	MediaType  string
	ErrorCode  string
	Terminal   bool
}

func mcpConfirmationWaitTimeout() time.Duration {
	value := strings.TrimSpace(os.Getenv("MCP_CONFIRM_WAIT_TIMEOUT"))
	if value == "" {
		return 2 * time.Second
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 || duration > 10*time.Second {
		return 2 * time.Second
	}
	return duration
}

func ticketFromExecution(record *mcpConfirmationExecutionRecord) MCPConfirmationTicket {
	if record == nil {
		return MCPConfirmationTicket{}
	}
	executionForwarded, _ := record.ResponseSummary["execution_forwarded"].(bool)
	resultAvailable := record.ExecutionStatus == "executed" && record.ResultCiphertext != "" &&
		record.ResultExpiresAt != nil && record.ResultExpiresAt.After(time.Now())
	ticket := MCPConfirmationTicket{
		ConfirmationID: record.ConfirmationID, InvocationID: record.InvocationID,
		Status: record.ConfirmationState, ExecutionStatus: record.ExecutionStatus,
		ExecutionForwarded: executionForwarded,
		EvidenceStatus:     record.EvidenceStatus, ExpiresAt: record.ExpiresAt,
		RetryAfterMS: 100, ResultAvailable: resultAvailable, ErrorCode: record.ErrorCode,
	}
	if record.EvidenceStatus == "complete" {
		ticket.AuditRequestID = record.AuditRequestID
		ticket.ToolLogID = record.ToolLogID
	}
	return ticket
}

func (h *MCPProxyHandler) waitMCPConfirmationResult(
	ctx context.Context,
	ticket MCPConfirmationTicket,
	replay mcpconfirmation.ReplayContext,
	wait time.Duration,
) mcpConfirmationPollResult {
	initial := mcpConfirmationPollResult{Ticket: ticket}
	if h == nil || h.toolRiskClient == nil || h.confirmationExecutionStore == nil {
		return initial
	}
	store := h.confirmationExecutionStore
	deadline := time.Now().Add(wait)
	for {
		record, err := store.GetGatewayExecution(ctx, replay.TenantID, ticket.ConfirmationID)
		if err != nil {
			initial.ErrorCode = "confirmation_state_unavailable"
			return initial
		}
		if record == nil || record.InvocationID != ticket.InvocationID {
			initial.ErrorCode = "confirmation_identity_mismatch"
			initial.Terminal = true
			return initial
		}
		result := mcpConfirmationPollResult{Ticket: ticketFromExecution(record)}
		if !mcpConfirmationRecordMatches(h.toolRiskClient.mcpConfirmationSecret(), replay, record) {
			result.ErrorCode = "confirmation_identity_mismatch"
			result.Terminal = true
			return result
		}
		switch record.ConfirmationState {
		case "rejected":
			// W1 1.9：审批人已拒绝，不会再执行，立即结束等待。
			result.Terminal = true
			result.ErrorCode = "confirmation_rejected"
			return result
		case "expired":
			result.Terminal = true
			result.ErrorCode = "confirmation_expired"
			return result
		case "pending":
			if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now()) {
				result.Terminal = true
				result.ErrorCode = "confirmation_expired"
				return result
			}
		}
		switch record.ExecutionStatus {
		case "executed":
			result.Terminal = true
			if record.ResultCiphertext == "" {
				result.ErrorCode = firstNonEmpty(record.ErrorCode, "result_unavailable")
				return result
			}
			if record.ResultExpiresAt == nil || !record.ResultExpiresAt.After(time.Now()) {
				result.ErrorCode = "result_expired"
				result.Ticket.ResultAvailable = false
				return result
			}
			plaintext, decryptErr := decryptMCPConfirmationResult(h.toolRiskClient.mcpConfirmationSecret(), replay, record)
			if decryptErr != nil {
				result.ErrorCode = "result_integrity_failed"
				return result
			}
			result.Body = plaintext
			result.HTTPStatus = record.ResultHTTPStatus
			if result.HTTPStatus < 100 || result.HTTPStatus > 599 {
				result.HTTPStatus = http.StatusOK
			}
			result.MediaType = "application/json"
			return result
		case "failed":
			result.Terminal = true
			result.ErrorCode = firstNonEmpty(record.ErrorCode, "execution_failed")
			return result
		case "unknown":
			result.Terminal = true
			result.ErrorCode = firstNonEmpty(record.ErrorCode, "execution_unknown")
			return result
		}
		if wait <= 0 || !time.Now().Before(deadline) {
			return result
		}
		delay := 50 * time.Millisecond
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			result.ErrorCode = "confirmation_wait_cancelled"
			return result
		case <-timer.C:
		}
	}
}

func mcpConfirmationRecordMatches(secret string, replay mcpconfirmation.ReplayContext, record *mcpConfirmationExecutionRecord) bool {
	scopeKey, scopeErr := mcpconfirmation.ScopeKey(secret, replay)
	requestHash, requestErr := mcpconfirmation.CanonicalRequestHash(replay)
	principalHash, principalErr := mcpconfirmation.PrincipalFingerprint(secret, replay)
	if scopeErr != nil || requestErr != nil || principalErr != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(scopeKey), []byte(record.ScopeKey)) == 1 &&
		subtle.ConstantTimeCompare([]byte(requestHash), []byte(record.CanonicalRequestHash)) == 1 &&
		subtle.ConstantTimeCompare([]byte(principalHash), []byte(record.PrincipalHash)) == 1 &&
		replay.ToolID == record.ToolID && replay.SupplyChainRevision == record.SupplyChainRevision &&
		replay.ApprovedSchemaHash == record.ApprovedSchemaHash && replay.ServerRouteHash == record.ServerRouteHash
}

func decryptMCPConfirmationResult(secret string, replay mcpconfirmation.ReplayContext, record *mcpConfirmationExecutionRecord) ([]byte, error) {
	if record.ResultPlaintextBytes < 1 || record.ResultPlaintextBytes > maxMCPNonStreamingResponseBytes ||
		record.ResultRPCID != replay.ToolCallID || record.ResultProtocol != replay.ProtocolVersion ||
		record.ResultSessionID != replay.MCPSessionID || record.ResultMediaType != "application/json" ||
		len(record.ResultHash) != 64 {
		return nil, errors.New("MCP result metadata mismatch")
	}
	aad, err := mcpconfirmation.ResponseAAD(
		secret, replay, record.InvocationID, record.ConfirmationID,
		record.CanonicalRequestHash, record.ResultHash,
	)
	if err != nil {
		return nil, err
	}
	plaintext, err := secrets.DecryptMCPResult(record.ResultCiphertext, aad)
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) != record.ResultPlaintextBytes {
		return nil, errors.New("MCP result length mismatch")
	}
	sum := sha256.Sum256(plaintext)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(record.ResultHash)) != 1 {
		return nil, errors.New("MCP result hash mismatch")
	}
	if !json.Valid(plaintext) {
		return nil, errors.New("MCP result JSON invalid")
	}
	observations := parseMCPJSONRPCResponseItems(bytes.TrimSpace(plaintext))
	if len(observations) != 1 || observations[0].idKey != replay.ToolCallID {
		return nil, errors.New("MCP result typed id mismatch")
	}
	return plaintext, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
