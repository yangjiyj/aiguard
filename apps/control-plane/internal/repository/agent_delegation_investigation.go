package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AgentDelegationTreeNode is one parent->child edge of a delegation tree as
// seen by a tenant administrator. EffectiveStatus folds in every ancestor:
// a child under a revoked or expired ancestor is reported inactive even if its
// own row has not been touched yet.
type AgentDelegationTreeNode struct {
	DelegationID      string     `json:"delegation_id"`
	ParentPrincipalID string     `json:"parent_principal_id"`
	ChildPrincipalID  string     `json:"child_principal_id"`
	ChildName         string     `json:"child_name"`
	ProjectID         string     `json:"project_id"`
	Depth             int        `json:"depth"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ChildStatus       string     `json:"child_status"`
	ChildExpiresAt    time.Time  `json:"child_expires_at"`
	Status            string     `json:"status"`
	EffectiveStatus   string     `json:"effective_status"`
}

// AgentDelegationInvestigationCall is one delegated authorization decision,
// reported once (on the calling principal's own edge) with the full principal
// chain from the investigated root down to the caller.
type AgentDelegationInvestigationCall struct {
	AgentDelegationCall
	Depth          int      `json:"depth"`
	PrincipalChain []string `json:"principal_chain"`
}

type AgentDelegationInvestigation struct {
	RootPrincipalID string                             `json:"root_principal_id"`
	RootName        string                             `json:"root_name"`
	RootStatus      string                             `json:"root_status"`
	RootExpiresAt   time.Time                          `json:"root_expires_at"`
	ObservedAt      time.Time                          `json:"observed_at"`
	Delegations     []AgentDelegationTreeNode          `json:"delegations"`
	Calls           []AgentDelegationInvestigationCall `json:"calls"`
}

var ErrAgentDelegationRootNotFound = errors.New("agent delegation root principal not found")

// InvestigateTree returns the complete delegation subtree below rootPrincipalID
// inside tenantID, plus the most recent delegated calls made anywhere in it.
// Every query is tenant scoped; a principal of another tenant is not found.
func (r *AgentDelegationRepository) InvestigateTree(ctx context.Context, tenantID, rootPrincipalID string, callLimit int) (*AgentDelegationInvestigation, error) {
	tenantID = strings.TrimSpace(tenantID)
	rootPrincipalID = strings.TrimSpace(rootPrincipalID)
	if tenantID == "" || callLimit < 1 || callLimit > 200 {
		return nil, fmt.Errorf("%w: invalid delegation investigation query", ErrAgentAuthorizationInvalid)
	}
	if _, err := uuid.Parse(rootPrincipalID); err != nil {
		return nil, fmt.Errorf("%w: invalid root principal id", ErrAgentAuthorizationInvalid)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
		return nil, err
	}

	result := &AgentDelegationInvestigation{RootPrincipalID: rootPrincipalID}
	var rootRevoked *time.Time
	err = tx.QueryRow(ctx, "SELECT name,status,expires_at,revoked_at,clock_timestamp() FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2::uuid",
		tenantID, rootPrincipalID).Scan(&result.RootName, &result.RootStatus, &result.RootExpiresAt, &rootRevoked, &result.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentDelegationRootNotFound
	}
	if err != nil {
		return nil, err
	}
	rootActive := result.RootStatus == "active" && rootRevoked == nil && result.RootExpiresAt.After(result.ObservedAt)

	rows, err := tx.Query(ctx, "WITH RECURSIVE tree AS (SELECT d.id,d.parent_principal_id,d.child_principal_id,d.project_id,d.expires_at,d.revoked_at,d.created_at,1 AS depth FROM agent_delegations d WHERE d.tenant_id=$1 AND d.parent_principal_id=$2::uuid UNION ALL SELECT d.id,d.parent_principal_id,d.child_principal_id,d.project_id,d.expires_at,d.revoked_at,d.created_at,t.depth+1 FROM agent_delegations d JOIN tree t ON d.parent_principal_id=t.child_principal_id WHERE d.tenant_id=$1 AND t.depth<$3) SELECT t.id::text,t.parent_principal_id::text,t.child_principal_id::text,p.name,t.project_id,t.depth,t.expires_at,t.revoked_at,t.created_at,p.status,p.expires_at,p.revoked_at FROM tree t JOIN agent_authorization_principals p ON p.tenant_id=$1 AND p.id=t.child_principal_id ORDER BY t.depth,t.created_at,t.id",
		tenantID, rootPrincipalID, AgentDelegationMaxDepth)
	if err != nil {
		return nil, err
	}
	nodes := make([]AgentDelegationTreeNode, 0)
	for rows.Next() {
		var node AgentDelegationTreeNode
		var childRevoked *time.Time
		if err := rows.Scan(&node.DelegationID, &node.ParentPrincipalID, &node.ChildPrincipalID, &node.ChildName, &node.ProjectID, &node.Depth,
			&node.ExpiresAt, &node.RevokedAt, &node.CreatedAt, &node.ChildStatus, &node.ChildExpiresAt, &childRevoked); err != nil {
			rows.Close()
			return nil, err
		}
		switch {
		case node.RevokedAt != nil || node.ChildStatus == "revoked" || childRevoked != nil:
			node.Status = "revoked"
		case !node.ExpiresAt.After(result.ObservedAt) || !node.ChildExpiresAt.After(result.ObservedAt) || node.ChildStatus != "active":
			node.Status = "expired"
		default:
			node.Status = "active"
		}
		nodes = append(nodes, node)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Nodes are ordered by depth, so every parent is resolved before its children.
	active := map[string]bool{rootPrincipalID: rootActive}
	parentOf := make(map[string]string, len(nodes))
	depthOf := make(map[string]int, len(nodes))
	delegationIDs := make([]string, 0, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		node.EffectiveStatus = node.Status
		if node.Status == "active" && !active[node.ParentPrincipalID] {
			node.EffectiveStatus = "ancestor_inactive"
		}
		active[node.ChildPrincipalID] = node.EffectiveStatus == "active"
		parentOf[node.ChildPrincipalID] = node.ParentPrincipalID
		depthOf[node.ChildPrincipalID] = node.Depth
		delegationIDs = append(delegationIDs, node.DelegationID)
	}
	result.Delegations = nodes
	result.Calls = make([]AgentDelegationInvestigationCall, 0)
	if len(delegationIDs) == 0 {
		return result, tx.Commit(ctx)
	}

	callRows, err := tx.Query(ctx, "SELECT c.id::text,c.delegation_id::text,c.parent_principal_id::text,c.child_principal_id::text,c.calling_principal_id::text,c.project_id,c.action,c.resource_type,c.resource_id,c.authorization_idempotency_key,c.request_hash,COALESCE(c.run_id,''),COALESCE(c.instance_id,''),COALESCE(c.tool_call_id,''),c.allowed,c.reason,c.created_at FROM agent_delegation_calls c WHERE c.tenant_id=$1 AND c.delegation_id=ANY($2::text[]::uuid[]) AND c.calling_principal_id=c.child_principal_id ORDER BY c.created_at DESC,c.id LIMIT $3",
		tenantID, delegationIDs, callLimit)
	if err != nil {
		return nil, err
	}
	defer callRows.Close()
	for callRows.Next() {
		var call AgentDelegationInvestigationCall
		if err := callRows.Scan(&call.ID, &call.DelegationID, &call.ParentPrincipalID, &call.ChildPrincipalID, &call.CallingPrincipalID, &call.ProjectID,
			&call.Action, &call.ResourceType, &call.ResourceID, &call.AuthorizationIdempotencyKey, &call.RequestHash,
			&call.RunID, &call.InstanceID, &call.ToolCallID, &call.Allowed, &call.Reason, &call.CreatedAt); err != nil {
			return nil, err
		}
		call.Depth = depthOf[call.CallingPrincipalID]
		chain := []string{call.CallingPrincipalID}
		for current := call.CallingPrincipalID; current != rootPrincipalID; {
			parent, ok := parentOf[current]
			if !ok || len(chain) > AgentDelegationMaxDepth {
				break
			}
			chain = append(chain, parent)
			current = parent
		}
		for left, right := 0, len(chain)-1; left < right; left, right = left+1, right-1 {
			chain[left], chain[right] = chain[right], chain[left]
		}
		call.PrincipalChain = chain
		result.Calls = append(result.Calls, call)
	}
	if err := callRows.Err(); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}
