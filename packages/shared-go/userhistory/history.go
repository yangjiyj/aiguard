// Package userhistory expands authorized historical ownership without changing
// immutable audit or billing facts. $1 and $2 bind tenant and current user.
package userhistory

const OwnersCTE = `WITH RECURSIVE user_history(user_id) AS (
 SELECT id FROM users WHERE tenant_id=$1 AND id=$2 AND status='active'
 UNION
 SELECT m.source_user_id FROM user_account_merges m
 JOIN user_history owner ON m.target_user_id=owner.user_id
 WHERE m.tenant_id=$1
)`

// AuditOwnersCTE preserves evidence for disabled and merged source accounts.
const AuditOwnersCTE = `WITH RECURSIVE user_history(user_id) AS (
 SELECT id FROM users WHERE tenant_id=$1 AND id=$2
 UNION
 SELECT m.source_user_id FROM user_account_merges m
 JOIN user_history owner ON m.target_user_id=owner.user_id
 WHERE m.tenant_id=$1
)`
