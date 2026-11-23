package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/endpointevents"
)

func decodeNestedAgentEvent(event map[string]any, endpoint string) (*agentEventRecord, error) {
	// Capture permission is checked by the authenticated handler. This layer still
	// validates the exact shape for repository callers and preserves the raw claim.
	if err := endpointevents.ValidateEvent(event, time.Now(), "full"); err != nil {
		return nil, err
	}
	get := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	session := agentEventMap(event["session"])
	turn := agentEventMap(event["turn"])
	tool := agentEventMap(event["tool"])
	local := agentEventMap(event["local_decision"])
	occurred, _ := time.Parse(time.RFC3339Nano, get(event, "occurred_at"))
	canonical, _ := json.Marshal(event)
	normalized := map[string]any{}
	for k, v := range local {
		normalized[k] = v
	}
	if v, ok := local["raw"]; ok {
		normalized["raw_decision"] = v
	}
	if v, ok := local["effective"]; ok {
		normalized["effective_decision"] = v
	}
	decision := get(local, "effective")
	if get(local, "mode") == "would_block" && get(local, "raw") == "block" && decision != "block" {
		decision = "would_block"
		normalized["effective_decision"] = decision
	}
	decisionJSON, _ := json.Marshal(normalized)
	record := &agentEventRecord{
		ID: strings.ToLower(get(event, "event_id")), EventType: get(event, "event_type"), OccurredAt: occurred.UTC(),
		EndpointID: endpoint, SessionID: get(session, "session_id"), PromptID: get(turn, "prompt_id"),
		ToolUseID: get(tool, "tool_use_id"), ToolCallID: get(tool, "tool_use_id"),
		ToolName: get(tool, "name"), ToolType: get(tool, "type"), MCPServer: get(tool, "mcp_server"),
		ArgumentsHash: get(tool, "args_hash"),
		Decision:      decision, Payload: canonical, LocalDecision: decisionJSON, ServerDecision: []byte("{}"),
		Native: event,
	}
	switch record.EventType {
	case "tool.pre":
		record.Status = "proposed"
	case "tool.post":
		record.Status = "completed"
	case "tool.denied":
		record.Status = "blocked"
	case "tool.failure":
		record.Status = "failed"
	}
	if result, ok := tool["result"].(map[string]any); ok {
		record.HasResult = true
		if success, ok := result["success"].(bool); ok {
			record.ResultSuccess, record.HasResultSuccess = success, true
			if success {
				record.Status = "success"
			} else {
				record.Status = "failed"
			}
		}
		record.ResultHash = get(result, "hash")
		record.ResultLength, record.HasResultLength = agentEventInt(result["len"])
		resultJSON, _ := json.Marshal(result)
		record.Result = string(resultJSON)
	}
	if record.EventType == "tool.pre" && agentEventIsBlockDecision(decision) {
		record.Status = "blocked"
	}
	assets, _ := event["assets"].([]any)
	for _, raw := range assets {
		asset := raw.(map[string]any)
		present := true // Each entry is positive presence; omitted entries never delete.
		if v, ok := asset["present"].(bool); ok {
			present = v
		}
		evidence, _ := json.Marshal(asset["detail"])
		if string(evidence) == "null" {
			evidence = []byte("{}")
		}
		record.Assets = append(record.Assets, &agentEventAsset{
			AssetType: get(asset, "asset_type"), Name: get(asset, "name"), Version: get(asset, "version"),
			Source: get(asset, "source"), Hash: get(asset, "hash"), Present: present, Evidence: evidence,
		})
	}
	if agentEventPlaceholderSessionID(record.SessionID) {
		// A present-but-unusable session id ("unknown", blank) would merge unrelated runs into one
		// session row shared across endpoints; reject rather than store it (F-UNKSESS).
		return nil, fmt.Errorf("session_id %q is a placeholder, not a session identity: %w", record.SessionID, errAgentEventInvalidSession)
	}
	if record.SessionID == "" && (record.EventType == "session.start" || record.EventType == "session.end" || record.EventType == "turn.start" || record.EventType == "turn.end" || record.ToolUseID != "") {
		return nil, fmt.Errorf("session identity required for lifecycle projection")
	}
	return record, nil
}

// errAgentEventInvalidSession marks a placeholder session id; AcceptEventBatch rejects that event
// alone (rejected[] + code invalid_session) instead of failing the batch.
var errAgentEventInvalidSession = errors.New("invalid_session")

// agentEventPlaceholderSessionID reports a non-empty session id that carries no identity:
// whitespace only, or "unknown" in any case with surrounding whitespace.
func agentEventPlaceholderSessionID(sessionID string) bool {
	trimmed := strings.TrimSpace(sessionID)
	return sessionID != "" && (trimmed == "" || strings.EqualFold(trimmed, "unknown"))
}

func upsertNestedSessionMetadata(ctx context.Context, tx pgx.Tx, tenant, endpoint string, r *agentEventRecord) error {
	agent := agentEventMap(r.Native["agent"])
	session := agentEventMap(r.Native["session"])
	contextFields := agentEventMap(r.Native["context"])
	detail := agentEventMap(r.Native["detail"])
	get := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	ended := r.EventType == "session.end"
	_, err := tx.Exec(ctx, `UPDATE agent_sessions SET
 product=COALESCE(NULLIF(product,''),NULLIF($4,'')),
 client_version=COALESCE(NULLIF(client_version,''),NULLIF($5,'')),
 parent_session_id=COALESCE(NULLIF(parent_session_id,''),NULLIF($6,'')),
 agent_id=COALESCE(NULLIF(agent_id,''),NULLIF($7,'')),
 agent_type=COALESCE(NULLIF(agent_type,''),NULLIF($8,'')),
 model=COALESCE(NULLIF($9,''),model),cwd_hash=COALESCE(NULLIF($10,''),cwd_hash),
 project_label=COALESCE(NULLIF($11,''),project_label),
 permission_mode=COALESCE(NULLIF($12,''),permission_mode),
 start_source=COALESCE(NULLIF(start_source,''),NULLIF($13,'')),
 ended_at=CASE WHEN $14 THEN GREATEST(COALESCE(ended_at,$15),$15) ELSE ended_at END,
 end_reason=CASE WHEN $14 AND (ended_at IS NULL OR ended_at<=$15) THEN NULLIF($16,'') ELSE end_reason END,
 status=CASE WHEN $14 THEN 'ended' ELSE status END,updated_at=now()
 WHERE tenant_id=$1 AND session_id=$2 AND endpoint_id=$3`,
		tenant, r.SessionID, endpoint, get(agent, "product"), get(agent, "version"),
		get(session, "parent_session_id"), get(session, "agent_id"), get(session, "agent_type"),
		get(contextFields, "model"), get(contextFields, "cwd_hash"), get(contextFields, "project_label"),
		get(contextFields, "permission_mode"), get(detail, "start_source"), ended, r.OccurredAt, get(detail, "end_reason"))
	return err
}
func upsertNestedTurnMetadata(ctx context.Context, tx pgx.Tx, tenant string, r *agentEventRecord) error {
	content := agentEventMap(r.Native["content"])
	detail := agentEventMap(r.Native["detail"])
	get := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	_, err := tx.Exec(ctx, `UPDATE agent_turns SET
 prompt_hash=CASE WHEN $4<>'' THEN $4 ELSE prompt_hash END,
 prompt_preview=CASE WHEN $5<>'' THEN $5 ELSE prompt_preview END,
 assistant_preview=CASE WHEN $6<>'' THEN $6 ELSE assistant_preview END,
 ended_at=CASE WHEN $7 THEN GREATEST(COALESCE(ended_at,$8),$8) ELSE ended_at END,
 stop_reason=CASE WHEN $7 AND (ended_at IS NULL OR ended_at<=$8) THEN $9 ELSE stop_reason END
 WHERE tenant_id=$1 AND session_id=$2 AND prompt_id=$3`,
		tenant, r.SessionID, r.PromptID, get(content, "prompt_hash"), get(content, "user_prompt"),
		get(content, "assistant_text"), r.EventType == "turn.end", r.OccurredAt, get(detail, "stop_reason"))
	return err
}
