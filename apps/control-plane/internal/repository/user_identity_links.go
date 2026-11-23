package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type identityBindingDBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type UserIdentityLinkRepository struct {
	db *pgxpool.Pool
}

func NewUserIdentityLinkRepository(db *pgxpool.Pool) *UserIdentityLinkRepository {
	return &UserIdentityLinkRepository{db: db}
}

func (r *UserIdentityLinkRepository) GetByStableKey(
	ctx context.Context,
	identity identitybinding.ExternalIdentity,
) (*identitybinding.UserIdentityLink, error) {
	return getIdentityLink(ctx, r.db, identity)
}

func (r *UserIdentityLinkRepository) Create(
	ctx context.Context,
	link identitybinding.UserIdentityLink,
) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_identity_links (
			id, tenant_id, user_id, issuer, source_type, source_id, external_subject
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, link.ID, link.TenantID, link.UserID, link.Issuer, link.SourceType, link.SourceID, link.ExternalSubject)
	if err != nil {
		return fmt.Errorf("create identity link: %w", err)
	}
	return nil
}

func (r *UserIdentityLinkRepository) Bind(
	ctx context.Context,
	link identitybinding.UserIdentityLink,
) (identitybinding.UserIdentityLink, bool, error) {
	return bindIdentityLink(ctx, r.db, link)
}

func (r *UserIdentityLinkRepository) HasExternalCredentialOwner(
	ctx context.Context,
	tenantID, userID string,
) (bool, error) {
	var managedExternally bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM user_identity_links
			WHERE tenant_id=$1 AND user_id=$2 AND source_type IN ('ldap','ad')
			UNION ALL
			SELECT 1
			FROM directory_user_links link
			JOIN directory_sources source
			  ON source.tenant_id=link.tenant_id
			 AND source.id=link.directory_source_id
			WHERE link.tenant_id=$1 AND link.user_id=$2 AND source.kind IN ('ldap','ad')
		)
	`, tenantID, userID).Scan(&managedExternally)
	if err != nil {
		return false, fmt.Errorf("check external credential owner: %w", err)
	}
	return managedExternally, nil
}

func (r *UserIdentityLinkRepository) FindSubjectByUser(
	ctx context.Context,
	tenantID, userID string,
) (string, error) {
	var subject string
	err := r.db.QueryRow(ctx, `
		SELECT external_subject
		FROM user_identity_links
		WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, tenantID, userID).Scan(&subject)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find local identity subject by user: %w", err)
	}
	return strings.TrimSpace(subject), nil
}

func (r *UserIdentityLinkRepository) BindLoginSources(
	ctx context.Context,
	tenantID, userID, issuer, externalSubject string,
) error {
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	externalSubject = strings.TrimSpace(externalSubject)
	if tenantID == "" || userID == "" || issuer == "" || externalSubject == "" {
		return identitybinding.ErrInvalidIdentity
	}
	return r.InTransaction(ctx, func(tx identitybinding.Transaction) error {
		for _, sourceType := range []string{"local", "oidc"} {
			winner, _, err := tx.CreateLinkOrGet(ctx, identitybinding.UserIdentityLink{
				ID: "uil_" + uuid.NewString(), TenantID: tenantID, UserID: userID,
				Issuer: issuer, SourceType: sourceType, ExternalSubject: externalSubject,
			})
			if err != nil {
				return err
			}
			if winner.UserID != userID {
				return identitybinding.ErrConflict
			}
		}
		return nil
	})
}

func (r *UserIdentityLinkRepository) InTransaction(
	ctx context.Context,
	fn func(identitybinding.Transaction) error,
) error {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin identity binding transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(&identityBindingTx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit identity binding transaction: %w", err)
	}
	return nil
}

type identityBindingTx struct {
	tx pgx.Tx
}

func (t *identityBindingTx) GetLink(
	ctx context.Context,
	identity identitybinding.ExternalIdentity,
) (*identitybinding.UserIdentityLink, error) {
	// Serialize first binding before username uniqueness is evaluated. The source
	// lock also covers the same subject across a configured issuer origin change.
	keys := []string{}
	for _, scope := range []string{"issuer", "source"} {
		value := identity.Issuer
		if scope == "source" {
			value = identity.SourceID
			if value == "" {
				continue
			}
		}
		encoded, _ := json.Marshal([]string{"identity-binding", identity.TenantID, scope, value, identity.SourceType, identity.ExternalSubject})
		keys = append(keys, string(encoded))
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := t.tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", key); err != nil {
			return nil, fmt.Errorf("lock identity binding: %w", err)
		}
	}
	return getIdentityLink(ctx, t.tx, identity)
}

func (t *identityBindingTx) CreateUser(ctx context.Context, user identitybinding.User) error {
	username := strings.TrimSpace(user.Username)
	tag, err := t.tx.Exec(ctx, `
		INSERT INTO users (
			id, tenant_id, username, email, role, status,
			department_id, department_assignment_mode,
			department_assignment_source, department_assignment_rule_id,
			department_resolved_at
		) VALUES (
			$1,$2,$3,NULLIF($4,''),$5,$6,NULLIF($7,''),$8,$9,NULLIF($10,''),NOW()
		)
		ON CONFLICT (tenant_id, username) DO NOTHING
	`, user.ID, user.TenantID, username, user.Email, user.Role, user.Status,
		user.DepartmentID, user.AssignmentMode, user.AssignmentSource, user.AssignmentRuleID)
	if err != nil {
		return fmt.Errorf("create identity candidate user: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// A collision needs an administrator to merge or rebind identities; never
	// hide a second account behind a synthesized username.
	return identitybinding.ErrConflict
}

func boundedIdentityUsername(username, userID string) string {
	suffixRunes := []rune(userID)
	if len(suffixRunes) > 12 {
		suffixRunes = suffixRunes[len(suffixRunes)-12:]
	}
	maxBase := 255 - len(suffixRunes) - 1
	usernameRunes := []rune(username)
	if len(usernameRunes) > maxBase {
		usernameRunes = usernameRunes[:maxBase]
	}
	return string(usernameRunes) + "-" + string(suffixRunes)
}

func (t *identityBindingTx) CreateLinkOrGet(
	ctx context.Context,
	link identitybinding.UserIdentityLink,
) (identitybinding.UserIdentityLink, bool, error) {
	return bindIdentityLink(ctx, t.tx, link)
}

func (t *identityBindingTx) DeleteCandidateUser(ctx context.Context, tenantID, userID string) error {
	tag, err := t.tx.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID)
	if err != nil {
		return fmt.Errorf("delete losing identity candidate: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identitybinding.ErrNotFound
	}
	return nil
}

func (t *identityBindingTx) GetUser(
	ctx context.Context,
	tenantID, userID string,
) (*identitybinding.User, error) {
	var user identitybinding.User
	err := t.tx.QueryRow(ctx, `
		SELECT id, tenant_id, username, COALESCE(email,''), role, status,
		       COALESCE(department_id,''), department_assignment_mode,
		       department_assignment_source, COALESCE(department_assignment_rule_id,''),
		       COALESCE(department_resolved_at, 'epoch'::timestamptz),
		       department_version
		FROM users
		WHERE tenant_id=$1 AND id=$2
		FOR UPDATE
	`, tenantID, userID).Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&user.Email,
		&user.Role,
		&user.Status,
		&user.DepartmentID,
		&user.AssignmentMode,
		&user.AssignmentSource,
		&user.AssignmentRuleID,
		&user.DepartmentResolvedAt,
		&user.DepartmentVersion,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant identity user: %w", err)
	}
	return &user, nil
}

func (t *identityBindingTx) FindMappings(
	ctx context.Context,
	identity identitybinding.ExternalIdentity,
) ([]identitybinding.DepartmentMapping, error) {
	return findIdentityDepartmentMappings(ctx, t.tx, identity)
}

func (t *identityBindingTx) GetUnassignedDepartment(
	ctx context.Context,
	tenantID string,
) (*identitybinding.Department, error) {
	var department identitybinding.Department
	err := t.tx.QueryRow(ctx, `
		SELECT id, tenant_id, TRUE
		FROM teams
		WHERE tenant_id=$1 AND system_key='unassigned'
	`, tenantID).Scan(&department.ID, &department.TenantID, &department.IsUnassigned)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant unassigned department: %w", err)
	}
	return &department, nil
}

func (t *identityBindingTx) GetDepartment(
	ctx context.Context,
	tenantID, departmentID string,
) (*identitybinding.Department, error) {
	var department identitybinding.Department
	err := t.tx.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(system_key='unassigned',FALSE)
		FROM teams
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, departmentID).Scan(&department.ID, &department.TenantID, &department.IsUnassigned)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant department: %w", err)
	}
	return &department, nil
}

func (t *identityBindingTx) UpdateAssignment(
	ctx context.Context,
	tenantID, userID string,
	assignment identitybinding.Assignment,
) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE users
		SET department_id=NULLIF($3,''),
		    department_assignment_mode=$4,
		    department_assignment_source=$5,
		    department_assignment_rule_id=NULLIF($6,''),
		    department_resolved_at=NOW(),
		    updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, userID, assignment.DepartmentID, assignment.Mode, assignment.Source, assignment.RuleID)
	if err != nil {
		return fmt.Errorf("update tenant user department assignment: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identitybinding.ErrNotFound
	}
	return nil
}

func (t *identityBindingTx) UpdatePlatformRole(
	ctx context.Context,
	tenantID, userID, role string,
) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE users
		SET role=$3, updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, userID, role)
	if err != nil {
		return fmt.Errorf("update tenant user platform role: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return identitybinding.ErrNotFound
	}
	return nil
}

func (t *identityBindingTx) ReplaceTenantPermissionGrant(
	ctx context.Context,
	tenantID, userID, role, actorID string,
) error {
	if _, err := t.tx.Exec(ctx, `
		DELETE FROM permission_grants
		WHERE tenant_id=$1
		  AND user_id=$2
		  AND scope_type='tenant'
		  AND scope_id=$1
	`, tenantID, userID); err != nil {
		return fmt.Errorf("delete previous tenant permission grants: %w", err)
	}
	if _, err := t.tx.Exec(ctx, `
		INSERT INTO permission_grants (
			id,tenant_id,user_id,scope_type,scope_id,role,granted_by,granted_at
		) VALUES ($1,$2,$3,'tenant',$2,$4,$5,NOW())
	`, "grant_"+uuid.NewString(), tenantID, userID, role, actorID); err != nil {
		return fmt.Errorf("create replacement tenant permission grant: %w", err)
	}
	return nil
}

func (t *identityBindingTx) UpdateDepartmentRole(
	ctx context.Context,
	tenantID, userID, departmentID, role string,
) (string, bool, error) {
	var oldRole string
	var changed bool
	err := t.tx.QueryRow(ctx, `
		WITH current_membership AS MATERIALIZED (
			SELECT membership.role
			FROM team_members membership
			JOIN teams department
			  ON department.tenant_id=$1
			 AND department.id=$3
			JOIN users target_user
			  ON target_user.tenant_id=$1
			 AND target_user.id=$2
			 AND target_user.department_id=department.id
			WHERE membership.team_id=department.id
			  AND membership.user_id=target_user.id
			FOR UPDATE OF membership
		), updated AS (
			UPDATE team_members membership
			SET role=$4
			FROM current_membership
			WHERE membership.team_id=$3
			  AND membership.user_id=$2
			  AND membership.role IS DISTINCT FROM $4
			RETURNING TRUE
		)
		SELECT current_membership.role, EXISTS(SELECT 1 FROM updated)
		FROM current_membership
	`, tenantID, userID, departmentID, role).Scan(&oldRole, &changed)
	if err == pgx.ErrNoRows {
		return "", false, identitybinding.ErrNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("update department membership role: %w", err)
	}
	return oldRole, changed, nil
}

func (t *identityBindingTx) RecordDepartmentChange(
	ctx context.Context,
	event identitybinding.DepartmentChangeEvent,
) error {
	if event.ActorID != "" && event.ActorID != identitybinding.ActorPortalUserSync {
		var actorExists bool
		if err := t.tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM users
				WHERE id=$2
				  AND (tenant_id=$1 OR (tenant_id=$3 AND role='platform_admin'))
			)
		`, event.TenantID, event.ActorID, SystemTenantID).Scan(&actorExists); err != nil {
			return fmt.Errorf("validate identity assignment actor: %w", err)
		}
		if !actorExists {
			return identitybinding.ErrNotFound
		}
	}
	detailFields := map[string]string{
		"user_id":           event.UserID,
		"old_department_id": event.OldDepartmentID,
		"new_department_id": event.NewDepartmentID,
		"source_id":         event.SourceID,
		"rule_id":           event.RuleID,
		"actor_id":          event.ActorID,
	}
	if event.OldRole != "" || event.NewRole != "" {
		detailFields["old_role"] = event.OldRole
		detailFields["new_role"] = event.NewRole
	}
	detail, err := json.Marshal(detailFields)
	if err != nil {
		return fmt.Errorf("encode identity assignment audit: %w", err)
	}
	_, err = t.tx.Exec(ctx, `
		INSERT INTO audit_operations (
			id, tenant_id, user_id, action_type, action_detail, target_type, target_id, ip_address
		) VALUES (
			$1,
			$2::varchar,
			(SELECT id FROM users WHERE tenant_id=$2::varchar AND id=NULLIF($3::varchar,'')),
			'identity.department.changed',
			$4::jsonb,
			'user',
			$5,
			''
		)
	`, uuid.NewString(), event.TenantID, event.ActorID, detail, event.UserID)
	if err != nil {
		return fmt.Errorf("record identity assignment audit: %w", err)
	}
	_, err = t.tx.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id, tenant_id, user_id, old_department_id, new_department_id, status
		) VALUES (
			$1,$2,$3,$4,$5,'pending'
		)
	`, event.EventID, event.TenantID, event.UserID, event.OldDepartmentID, event.NewDepartmentID)
	if err != nil {
		return fmt.Errorf("enqueue identity cache invalidation: %w", err)
	}
	return nil
}

func getIdentityLink(
	ctx context.Context,
	db identityBindingDBTX,
	identity identitybinding.ExternalIdentity,
) (*identitybinding.UserIdentityLink, error) {
	var link identitybinding.UserIdentityLink
	err := db.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, issuer, source_id, source_type, external_subject
		FROM user_identity_links
		WHERE tenant_id=$1 AND issuer=$2 AND source_type=$3 AND external_subject=$4
	`, identity.TenantID, identity.Issuer, identity.SourceType, identity.ExternalSubject).Scan(
		&link.ID,
		&link.TenantID,
		&link.UserID,
		&link.Issuer,
		&link.SourceID,
		&link.SourceType,
		&link.ExternalSubject,
	)
	if err == nil {
		return &link, nil
	}
	if err != pgx.ErrNoRows {
		return nil, fmt.Errorf("get identity link by stable key: %w", err)
	}

	// The public OIDC issuer can legitimately change when the same configured
	// identity source moves behind a different reverse-proxy origin. source_id
	// is the control-plane-owned identifier for that source, so source-scoped
	// subject matching safely preserves the existing user/department binding
	// without falling back to mutable email or username claims.
	sourceID := strings.TrimSpace(identity.SourceID)
	if sourceID == "" {
		return nil, nil
	}
	rows, err := db.Query(ctx, `
		SELECT id, tenant_id, user_id, issuer, source_id, source_type, external_subject
		FROM user_identity_links
		WHERE tenant_id=$1 AND source_id=$2 AND source_type=$3 AND external_subject=$4
		ORDER BY created_at, id
	`, identity.TenantID, sourceID, identity.SourceType, identity.ExternalSubject)
	if err != nil {
		return nil, fmt.Errorf("get identity link by source-scoped subject: %w", err)
	}
	defer rows.Close()

	var winner *identitybinding.UserIdentityLink
	for rows.Next() {
		var candidate identitybinding.UserIdentityLink
		if err := rows.Scan(
			&candidate.ID,
			&candidate.TenantID,
			&candidate.UserID,
			&candidate.Issuer,
			&candidate.SourceID,
			&candidate.SourceType,
			&candidate.ExternalSubject,
		); err != nil {
			return nil, fmt.Errorf("scan source-scoped identity link: %w", err)
		}
		if winner != nil && winner.UserID != candidate.UserID {
			return nil, identitybinding.ErrConflict
		}
		if winner == nil {
			copy := candidate
			winner = &copy
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate source-scoped identity links: %w", err)
	}
	return winner, nil
}

func bindIdentityLink(
	ctx context.Context,
	db identityBindingDBTX,
	link identitybinding.UserIdentityLink,
) (identitybinding.UserIdentityLink, bool, error) {
	existing, err := getIdentityLink(ctx, db, identitybinding.ExternalIdentity{
		TenantID:        link.TenantID,
		Issuer:          link.Issuer,
		SourceID:        link.SourceID,
		SourceType:      link.SourceType,
		ExternalSubject: link.ExternalSubject,
	})
	if err != nil {
		return identitybinding.UserIdentityLink{}, false, err
	}
	if existing != nil {
		return *existing, false, nil
	}

	var inserted identitybinding.UserIdentityLink
	err = db.QueryRow(ctx, `
		INSERT INTO user_identity_links (
			id, tenant_id, user_id, issuer, source_type, source_id, external_subject
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id, issuer, source_type, external_subject) DO NOTHING
		RETURNING id, tenant_id, user_id, issuer, source_id, source_type, external_subject
	`, link.ID, link.TenantID, link.UserID, link.Issuer, link.SourceType, link.SourceID, link.ExternalSubject).Scan(
		&inserted.ID,
		&inserted.TenantID,
		&inserted.UserID,
		&inserted.Issuer,
		&inserted.SourceID,
		&inserted.SourceType,
		&inserted.ExternalSubject,
	)
	if err == nil {
		return inserted, true, nil
	}
	if err != pgx.ErrNoRows {
		return identitybinding.UserIdentityLink{}, false, fmt.Errorf("bind identity stable key: %w", err)
	}
	winner, err := getIdentityLink(ctx, db, identitybinding.ExternalIdentity{
		TenantID:        link.TenantID,
		Issuer:          link.Issuer,
		SourceID:        link.SourceID,
		SourceType:      link.SourceType,
		ExternalSubject: link.ExternalSubject,
	})
	if err != nil {
		return identitybinding.UserIdentityLink{}, false, err
	}
	if winner == nil {
		return identitybinding.UserIdentityLink{}, false, identitybinding.ErrConflict
	}
	return *winner, false, nil
}

// LocalPasswordOwnership reads proof written by the official native account
// provisioner. An issuer coordinate alone never assigns credential ownership.
func (r *UserIdentityLinkRepository) LocalPasswordOwnership(ctx context.Context, tenant, user string) (bool, string, error) {
	var allowed bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local')`, tenant, user).Scan(&allowed); err != nil {
		return false, "", err
	}
	var subject string
	err := r.db.QueryRow(ctx, `SELECT external_subject FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local' AND local_runtime_managed ORDER BY created_at DESC,id DESC LIMIT 1`, tenant, user).Scan(&subject)
	if err == pgx.ErrNoRows {
		return allowed, "", nil
	}
	return allowed, subject, err
}
