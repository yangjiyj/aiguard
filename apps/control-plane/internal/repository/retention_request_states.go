package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// RetentionRequestState is request-level telemetry, not an agent completion event.
type RetentionRequestState struct {
	TurnContext    json.RawMessage
	ConversationID string
	RequestID      string
	Status         string
	CreatedAt      time.Time
	LatencyMS      int64
}

func (r *ContentLogRepository) ListRetentionRequestStatesScoped(ctx context.Context, tenantID string, requestIDs []string, start, end time.Time, scope string) ([]RetentionRequestState, error) {
	if len(requestIDs) == 0 {
		return []RetentionRequestState{}, nil
	}
	rows, err := r.retentionRead().Query(ctx, `
 SELECT request_id, COALESCE(request_status,''), created_at, GREATEST(COALESCE(latency_ms,0),0), COALESCE(to_jsonb(rl)->'retention_turn_context','{}'::jsonb),
 COALESCE((SELECT acl.conversation_id FROM access_content_logs acl WHERE acl.request_id=rl.request_id AND acl.tenant_id=rl.tenant_id AND acl.environment_scope=ANY($3) AND acl.created_at >= $4 AND acl.created_at < $5 LIMIT 1),'')
 FROM request_logs rl
 WHERE tenant_id=$1 AND request_id=ANY($2)
   AND environment_scope=ANY($3) AND created_at >= $4 AND created_at < $5
 ORDER BY created_at, request_id`, tenantID, requestIDs, EnvironmentScopesForRead(scope), start, end)
	if err != nil {
		return nil, fmt.Errorf("read retained request states: %w", err)
	}
	defer rows.Close()
	states := []RetentionRequestState{}
	for rows.Next() {
		var state RetentionRequestState
		if err := rows.Scan(&state.RequestID, &state.Status, &state.CreatedAt, &state.LatencyMS, &state.TurnContext, &state.ConversationID); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}
