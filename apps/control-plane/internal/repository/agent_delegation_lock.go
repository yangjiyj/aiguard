package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// lockAgentDelegationHierarchy serializes authorization, creation and revocation
// for a delegation tree before those operations acquire row locks.
func lockAgentDelegationHierarchy(ctx context.Context, tx pgx.Tx, tenantID, principalID string) error {
	root := principalID
	seen := map[string]bool{root: true}
	for depth := 0; depth < AgentDelegationMaxDepth; depth++ {
		var parentID string
		err := tx.QueryRow(ctx, "SELECT parent_principal_id::text FROM agent_delegations WHERE tenant_id=$1 AND child_principal_id=$2", tenantID, root).Scan(&parentID)
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenantID+"/"+root)
			return err
		}
		if err != nil {
			return err
		}
		if seen[parentID] {
			return fmt.Errorf("%w: delegation cycle", ErrAgentAuthorizationInvalid)
		}
		seen[parentID] = true
		root = parentID
	}
	var more bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agent_delegations WHERE tenant_id=$1 AND child_principal_id=$2)", tenantID, root).Scan(&more)
	if err != nil {
		return err
	}
	if more {
		return fmt.Errorf("%w: delegation depth exceeds limit", ErrAgentAuthorizationInvalid)
	}
	_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenantID+"/"+root)
	return err
}
