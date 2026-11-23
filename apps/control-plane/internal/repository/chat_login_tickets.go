package repository

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ChatLoginIdentity comes only from the current user and trusted local link.
type ChatLoginIdentity struct {
	UserID                 string `json:"user_id"`
	TenantID               string `json:"tenant_id"`
	Username               string `json:"username"`
	Email                  string `json:"email"`
	ExternalSubject        string `json:"external_subject"`
	DepartmentID           string `json:"department_id"`
	DepartmentName         string `json:"department_name"`
	DepartmentVersion      int64  `json:"department_version"`
	ChatAllowed            bool   `json:"chat_allowed"`
	PortalAllowed          bool   `json:"portal_allowed"`
	LocalCredentialVersion int64  `json:"local_credential_version"`
}
type ChatLoginTicketRepository struct{ db *pgxpool.Pool }

func NewChatLoginTicketRepository(db *pgxpool.Pool) *ChatLoginTicketRepository {
	return &ChatLoginTicketRepository{db: db}
}

// Also revoke local logins when directory credentials take over the account.
const localChatEligibleSQL = `
 u.status='active' AND NOT u.must_change_password
 AND u.department_assignment_mode <> 'service'
 AND u.department_version > 0 AND tenant.status='active'
 AND NOT EXISTS(SELECT 1 FROM user_identity_links external
   WHERE external.tenant_id=u.tenant_id AND external.user_id=u.id
    AND external.source_type IN ('ldap','ad'))
 AND NOT EXISTS(SELECT 1 FROM directory_user_links external
   JOIN directory_sources source ON source.tenant_id=external.tenant_id AND source.id=external.directory_source_id
   WHERE external.tenant_id=u.tenant_id AND external.user_id=u.id AND source.kind IN ('ldap','ad'))
`
const localChatIdentityColumns = `u.id,u.tenant_id,u.username,COALESCE(u.email,''),link.external_subject,
 COALESCE(u.department_id,''),COALESCE(department.name,''),u.department_version,
 (u.department_assignment_mode<>'emergency' AND department.id IS NOT NULL),u.local_credential_version,TRUE`
const localChatIdentityJoins = `
 JOIN user_identity_links link ON link.tenant_id=u.tenant_id AND link.user_id=u.id
 LEFT JOIN teams department ON department.tenant_id=u.tenant_id AND department.id=u.department_id
 JOIN tenants tenant ON tenant.id=u.tenant_id`

// Issue persists only SHA-256, with the original identity link bound to the ticket.
func (r *ChatLoginTicketRepository) Issue(ctx context.Context, hash, tenantID, userID, issuer string, expectedPasswordHash ...string) (bool, error) {
	proofHash := ""
	if len(expectedPasswordHash) > 1 || (len(expectedPasswordHash) == 1 && expectedPasswordHash[0] == "") {
		return false, nil
	}
	if len(expectedPasswordHash) == 1 {
		proofHash = expectedPasswordHash[0]
	}
	_, err := r.db.Exec(ctx, `DELETE FROM chat_login_tickets WHERE expires_at<=NOW()`)
	if err != nil {
		return false, err
	}
	tag, err := r.db.Exec(ctx, `
 INSERT INTO chat_login_tickets(ticket_hash,tenant_id,user_id,identity_link_id,identity_issuer,identity_subject,local_credential_version)
 SELECT $1,u.tenant_id,u.id,link.id,link.issuer,link.external_subject,u.local_credential_version FROM users u`+localChatIdentityJoins+`
 WHERE u.tenant_id=$2 AND u.id=$3 AND link.source_type='local' AND u.role=ANY($6)
 AND (NOT link.local_runtime_managed OR ($4<>'' AND link.issuer=$4)) AND ($5='' OR u.password_hash=$5) AND link.external_subject<>'' AND `+localChatEligibleSQL+`
 ORDER BY link.created_at DESC,link.id DESC LIMIT 1
 `, hash, tenantID, userID, issuer, proofHash, roles.PortalRoles())
	return tag.RowsAffected() == 1, err
}
func scanChatLoginIdentity(row pgx.Row) (*ChatLoginIdentity, error) {
	var identity ChatLoginIdentity
	err := row.Scan(&identity.UserID, &identity.TenantID, &identity.Username, &identity.Email,
		&identity.ExternalSubject, &identity.DepartmentID, &identity.DepartmentName, &identity.DepartmentVersion, &identity.ChatAllowed, &identity.LocalCredentialVersion, &identity.PortalAllowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

// Consume deletes and rechecks the ORIGINAL link in one atomic statement.
// Concurrent redeems have at most one winner; a revoked user is never returned.
func (r *ChatLoginTicketRepository) Consume(ctx context.Context, hash, tenantID, issuer string) (*ChatLoginIdentity, error) {
	return scanChatLoginIdentity(r.db.QueryRow(ctx, `
 WITH consumed AS (
  DELETE FROM chat_login_tickets WHERE ticket_hash=$1 AND tenant_id=$2 AND expires_at>NOW()
  RETURNING user_id,tenant_id,identity_link_id,identity_issuer,identity_subject,local_credential_version
 )
 SELECT `+localChatIdentityColumns+` FROM consumed ticket
 JOIN users u ON u.id=ticket.user_id AND u.tenant_id=ticket.tenant_id`+localChatIdentityJoins+`
 WHERE link.id=ticket.identity_link_id AND link.source_type='local' AND u.role=ANY($4) AND u.local_credential_version=ticket.local_credential_version
 AND link.issuer=ticket.identity_issuer AND link.external_subject=ticket.identity_subject
 AND (NOT link.local_runtime_managed OR ($3<>'' AND link.issuer=$3)) AND link.external_subject<>'' AND `+localChatEligibleSQL,
		hash, tenantID, issuer, roles.PortalRoles()))
}

// CurrentIdentity is the authority used to recheck local Chat JWT sessions.
func (r *ChatLoginTicketRepository) CurrentIdentity(ctx context.Context, tenantID, userID, issuer string) (*ChatLoginIdentity, error) {
	return scanChatLoginIdentity(r.db.QueryRow(ctx, `
 SELECT `+localChatIdentityColumns+` FROM users u`+localChatIdentityJoins+`
 WHERE u.tenant_id=$1 AND u.id=$2 AND link.source_type='local' AND u.role=ANY($4)
 AND (NOT link.local_runtime_managed OR ($3<>'' AND link.issuer=$3)) AND link.external_subject<>'' AND `+localChatEligibleSQL+`
 ORDER BY link.created_at DESC,link.id DESC LIMIT 1`, tenantID, userID, issuer, roles.PortalRoles()))
}

// RevokeByUser removes all pending proofs before a new password-authenticated
// handoff is signed. Clearing must_change_password must not revive older tickets.
func (r *ChatLoginTicketRepository) RevokeByUser(ctx context.Context, tenantID, userID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM chat_login_tickets WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID)
	return err
}
