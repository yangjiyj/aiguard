package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/google/uuid"
)

func resolveAgentInstanceID(bound, claimed string) (string, error) {
	if claimed == "" {
		return bound, nil
	}
	if !ai.ValidID(claimed) {
		return "", errors.New("invalid agent identity")
	}
	if bound == "" {
		return "", errors.New("agent identity does not match credential")
	}
	if bound != claimed {
		return "", errors.New("agent identity does not match credential")
	}
	return bound, nil
}

func (a *AuthMiddleware) recordAgentBindingDenial(parent context.Context, key *KeyRecord, requestID string) {
	if a.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer cancel()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id,agent_instance_id,request_status,upstream_status_code)
		VALUES($1,$2,$3,$4,NULLIF($5,''),$6,NULLIF($7,''),'agent_identity_mismatch',403) ON CONFLICT(request_id) DO NOTHING`, "log_"+uuid.NewString(), requestID, key.TenantID, key.ProjectID, key.UserID, key.ID, key.AgentInstanceID)
	if err != nil {
		return
	}
	metadata, _ := json.Marshal(map[string]string{"agent_instance_id": key.AgentInstanceID, "category": "identity_spoofing"})
	_, err = tx.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,agent_instance_id,principal_key)
		VALUES($1,$2,$3,$4,NULLIF($5,''),'agent_identity_mismatch','high','deny',$6,NULLIF($7,''),$8)`, "evt_"+uuid.NewString(), requestID, key.TenantID, key.ProjectID, key.UserID, metadata, key.AgentInstanceID, key.ID)
	if err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

func rejectAgentInstanceBinding(w http.ResponseWriter, r *http.Request, requestID string) {
	if isAnthropicMessagesRequest(r) {
		writeAnthropicAuthError(w, 403, "permission_error", "agent identity does not match credential", requestID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "agent_identity_mismatch", "message": "agent identity does not match credential", "request_id": requestID}})
}
