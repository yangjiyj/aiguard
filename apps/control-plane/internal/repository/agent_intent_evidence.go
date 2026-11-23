package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
	"github.com/jackc/pgx/v5"
)

func prepareEndpointProposalEvidence(log *ToolCallLog, logID string, currentParameters, currentEvidence []byte, existingRow bool, uniqueIdentity bool) ([]byte, bool, error) {
	if log == nil || len(log.EvidenceJSON) == 0 || !agentintent.IntentEvidencePresent(log.EvidenceJSON) {
		return currentEvidence, false, nil
	}
	argsHash, err := agentintent.ArgumentsHash(log.Parameters)
	if err != nil {
		return currentEvidence, false, nil
	}
	identity := agentintent.IntentCorrelation{
		EndpointID: log.EndpointID, SessionID: log.SessionID, PromptID: log.PromptID,
		ToolCallID: log.ToolCallID, ToolName: log.ToolName, ToolType: log.ToolType,
		ArgumentsHash: argsHash,
	}
	if !agentintent.IntentProposalMatches(log.EvidenceJSON, identity) || !uniqueIdentity {
		if existingRow {
			updated, changed, markErr := agentintent.MarkIntentUncertainEvidence(currentEvidence, "proposal_identity_mismatch")
			return updated, changed, markErr
		}
		stripped, stripErr := agentintent.RemoveIntentEvidence(log.EvidenceJSON)
		return stripped, true, stripErr
	}

	if existingRow && !emptyJSONObject(currentParameters) {
		storedHash, hashErr := hashStoredParameters(currentParameters)
		if hashErr != nil || storedHash != argsHash {
			updated, changed, markErr := agentintent.MarkIntentUncertainEvidence(currentEvidence, "proposal_identity_mismatch")
			return updated, changed, markErr
		}
	}
	if existingRow {
		return agentintent.MergeIntentEvidence(currentEvidence, log.EvidenceJSON, logID)
	}
	return agentintent.BindIntentEvidence(log.EvidenceJSON, logID)
}

func emptyJSONObject(raw []byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed == "" || trimmed == "null" || trimmed == "{}"
}

func hashStoredParameters(raw []byte) (string, error) {
	var parameters map[string]any
	if err := json.Unmarshal(raw, &parameters); err != nil || parameters == nil {
		return "", fmt.Errorf("stored tool parameters are invalid")
	}
	return agentintent.ArgumentsHash(parameters)
}

func attachT16TerminalFromAcceptedEvent(ctx context.Context, tx pgx.Tx, tenantID, endpointID, eventID, toolCallLogID string) error {
	var eventType, storedEndpointID, sessionID, promptID, toolUseID, toolName, toolType string
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT event_type,endpoint_id,COALESCE(session_id,''),COALESCE(prompt_id,''),
	       COALESCE(tool_use_id,''),COALESCE(tool_name,''),COALESCE(tool_type,''),payload
		FROM agent_events WHERE tenant_id=$1 AND id=$2 AND endpoint_id=$3 AND tool_call_log_id=$4 FOR UPDATE`,
		tenantID, eventID, endpointID, toolCallLogID).Scan(&eventType, &storedEndpointID, &sessionID, &promptID,
		&toolUseID, &toolName, &toolType, &payload)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if eventType != "tool.post" && eventType != "tool.failure" && eventType != "tool.denied" {
		return nil
	}
	if err := attachIntentTaskTerminalFromAcceptedEvent(ctx, tx, tenantID, endpointID, eventID, toolCallLogID,
		eventType, storedEndpointID, sessionID, promptID, toolUseID, toolName, toolType, payload); err != nil {
		return fmt.Errorf("attach approved task terminal event: %w", err)
	}

	var logParameters, evidence []byte
	var logEndpointID, logSessionID, logToolCallID, logToolName, logToolType string
	err = tx.QueryRow(ctx, `SELECT COALESCE(parameters,'{}'::jsonb)::text,COALESCE(evidence_json,'[]'::jsonb)::text,
	       endpoint_id,COALESCE(session_id,''),COALESCE(tool_call_id,''),tool_name,tool_type
		FROM tool_call_logs WHERE id=$1 AND tenant_id=$2 AND endpoint_id=$3 AND COALESCE(session_id,'')=$4
		  AND attribution_mode='endpoint_hook' FOR UPDATE`,
		toolCallLogID, tenantID, endpointID, sessionID).Scan(&logParameters, &evidence,
		&logEndpointID, &logSessionID, &logToolCallID, &logToolName, &logToolType)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !agentintent.IntentEvidencePresent(evidence) {
		return nil
	}

	markUncertain := func() error {
		updated, changed, markErr := agentintent.MarkIntentUncertainEvidence(evidence, "terminal_identity_mismatch")
		if markErr != nil || !changed {
			return markErr
		}
		_, updateErr := tx.Exec(ctx, `UPDATE tool_call_logs SET evidence_json=$1::jsonb
			WHERE id=$2 AND tenant_id=$3 AND endpoint_id=$4 AND COALESCE(session_id,'')=$5 AND tool_call_id=$6 AND attribution_mode='endpoint_hook'`,
			updated, toolCallLogID, tenantID, endpointID, sessionID, logToolCallID)
		return updateErr
	}
	var duplicateRows int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tool_call_logs WHERE tenant_id=$1 AND endpoint_id=$2
		AND COALESCE(session_id,'')=$3 AND tool_call_id=$4 AND attribution_mode='endpoint_hook'`,
		tenantID, endpointID, sessionID, logToolCallID).Scan(&duplicateRows); err != nil {
		return err
	}
	if duplicateRows != 1 {
		return markUncertain()
	}

	var event map[string]any
	if decodeErr := decodeAcceptedT02EventPayload(payload, &event); decodeErr != nil || event == nil {
		return markUncertain()
	}
	toolUseClaim, toolCallClaim, argsHash, resultHash, resultLength, hasResultLength, resultSuccess, hasResultSuccess := agentIntentEventMetadata(event)
	if storedEndpointID != logEndpointID || sessionID == "" || sessionID != logSessionID || promptID == "" ||
		toolUseID == "" || toolUseClaim != toolUseID || toolCallClaim != toolUseID ||
		logToolCallID != toolUseID || toolName == "" || toolName != logToolName || toolType == "" || toolType != logToolType {
		return markUncertain()
	}
	if len(argsHash) != len("sha256:")+64 || !strings.HasPrefix(argsHash, "sha256:") {
		return markUncertain()
	}
	storedArgsHash, hashErr := hashStoredParameters(logParameters)
	if hashErr != nil || storedArgsHash != argsHash {
		return markUncertain()
	}
	identity := agentintent.IntentCorrelation{
		EndpointID: logEndpointID, SessionID: logSessionID, PromptID: promptID,
		ToolCallID: logToolCallID, ToolCallLogID: toolCallLogID, ToolName: logToolName,
		ToolType: logToolType, ArgumentsHash: storedArgsHash,
	}
	if !agentintent.IntentProposalMatches(evidence, identity) {
		return markUncertain()
	}
	terminal := terminalResultFromAcceptedEvent(eventID, eventType, resultHash, resultLength, hasResultLength, resultSuccess, hasResultSuccess)
	updated, changed, attachErr := agentintent.AttachTerminalResult(evidence, identity, terminal)
	if attachErr != nil {
		return markUncertain()
	}
	if !changed {
		return nil
	}
	_, err = tx.Exec(ctx, `UPDATE tool_call_logs SET evidence_json=$1::jsonb
		WHERE id=$2 AND tenant_id=$3 AND endpoint_id=$4 AND COALESCE(session_id,'')=$5 AND tool_call_id=$6 AND attribution_mode='endpoint_hook'`,
		updated, toolCallLogID, tenantID, endpointID, sessionID, logToolCallID)
	return err
}

func decodeAcceptedT02EventPayload(payload []byte, event *map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	return decoder.Decode(event)
}

func terminalResultFromAcceptedEvent(eventID, eventType, resultHash string, resultLength int, hasResultLength, resultSuccess, hasResultSuccess bool) agentintent.TerminalResult {
	outcome := "uncertain"
	switch eventType {
	case "tool.failure":
		outcome = "failed"
	case "tool.denied":
		outcome = "denied"
	case "tool.post":
		if hasResultSuccess {
			if resultSuccess {
				outcome = "succeeded"
			} else {
				outcome = "failed"
			}
		}
	}
	return agentintent.TerminalResult{
		EventID: eventID, EventType: eventType, Outcome: outcome,
		ResultHash: resultHash, Length: resultLength, HasLength: hasResultLength,
	}
}

func agentIntentEventMetadata(event map[string]any) (toolUseID, toolCallID, argsHash, resultHash string, resultLength int, hasResultLength, resultSuccess, hasResultSuccess bool) {
	payload := agentEventMap(event["payload"])
	tool := agentEventMap(event["tool"])
	if tool == nil {
		tool = agentEventMap(payload["tool"])
	}
	toolUseID = agentEventString(event["tool_use_id"], payload["tool_use_id"], tool["tool_use_id"])
	toolCallID = agentEventString(event["tool_call_id"], payload["tool_call_id"], tool["tool_call_id"], toolUseID)
	argsHash = agentEventString(event["arguments_hash"], event["args_hash"], payload["arguments_hash"], payload["args_hash"], tool["args_hash"])
	result := agentEventMap(tool["result"])
	if result == nil {
		result = agentEventMap(event["result_metadata"])
	}
	if result == nil {
		result = agentEventMap(payload["result_metadata"])
	}
	resultHash = agentEventString(result["hash"], event["result_hash"], payload["result_hash"])
	resultLength, hasResultLength = agentEventInt(result["len"], event["result_length"], payload["result_length"])
	resultSuccess, hasResultSuccess = result["success"].(bool)
	return
}

func reconcileT16TerminalEventsForProposal(ctx context.Context, tx pgx.Tx, tenantID, endpointID, sessionID, toolCallLogID string) error {
	rows, err := tx.Query(ctx, `SELECT id FROM agent_events WHERE tenant_id=$1 AND endpoint_id=$2 AND COALESCE(session_id,'')=$3
		AND tool_call_log_id=$4 AND event_type IN ('tool.post','tool.failure','tool.denied')
		ORDER BY occurred_at,id FOR UPDATE`, tenantID, endpointID, sessionID, toolCallLogID)
	if err != nil {
		return err
	}
	var eventIDs []string
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			rows.Close()
			return err
		}
		eventIDs = append(eventIDs, eventID)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	for _, eventID := range eventIDs {
		if err := attachT16TerminalFromAcceptedEvent(ctx, tx, tenantID, endpointID, eventID, toolCallLogID); err != nil {
			return err
		}
	}
	return nil
}
