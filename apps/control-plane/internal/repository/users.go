package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User represents a user record
type User struct {
	ID                         string
	TenantID                   string
	Username                   string
	Email                      string
	Phone                      string
	PasswordHash               string
	MustChangePassword         bool
	Role                       string
	Status                     string
	ExternalSubject            string
	DepartmentID               string
	DepartmentName             string
	DepartmentAssignmentMode   string
	DepartmentAssignmentSource string
	DepartmentAssignmentRuleID string
	DepartmentResolvedAt       *time.Time
	DepartmentVersion          int64
}

// UserWithStats extends User with aggregated stats for the list view (spec §7.2)
type UserWithStats struct {
	User
	TeamsCSV      string
	TeamsJSON     string // JSON array [{id, name}]
	ProjectsCount int64
	GrantsCount   int64
	LastLoginAt   string
}

type ContentAuditUserOption struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	IdentityKind   string `json:"identity_kind"`
	DepartmentID   string `json:"department_id,omitempty"`
	DepartmentName string `json:"department_name,omitempty"`
}

type ContentAuditUserSelectorFilter struct {
	TenantID      string
	DepartmentIDs []string
	Query         string
	CursorName    string
	CursorID      string
	Limit         int
	Offset        int
}

// UserRepository handles user database operations
type UserRepository struct {
	db *pgxpool.Pool
}

// UserDeleteBlockerItem is a concrete occupied resource that should be shown to operators.
type UserDeleteBlockerItem struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Route string `json:"route"`
}

// UserDeleteBlocker describes durable data that prevents physical user deletion.
type UserDeleteBlocker struct {
	Kind    string                  `json:"kind"`
	Label   string                  `json:"label"`
	Count   int                     `json:"count"`
	Samples string                  `json:"samples"`
	Entry   string                  `json:"entry"`
	Action  string                  `json:"action"`
	Route   string                  `json:"route"`
	Items   []UserDeleteBlockerItem `json:"items"`
}

// UserRetirement records whether a user row was physically deleted or safely
// retired because immutable billing/identity history still references it.
type UserRetirement struct {
	Retired bool
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) HasEmergencyAdmin(ctx context.Context, tenantID string) (bool, error) {
	var available bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE tenant_id=$1
			  AND status='active'
			  AND btrim(COALESCE(password_hash,''))<>''
			  AND role IN ('platform_admin','tenant_owner','tenant_admin','admin')
		)`, tenantID).Scan(&available)
	if err != nil {
		return false, fmt.Errorf("check emergency administrator: %w", err)
	}
	return available, nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject,
		       COALESCE(u.department_id, ''), COALESCE(d.name, ''), u.department_assignment_mode, u.department_assignment_source,
		       COALESCE(u.department_assignment_rule_id, ''), u.department_resolved_at, u.department_version
		FROM users u
		LEFT JOIN teams d ON d.id = u.department_id AND d.tenant_id = u.tenant_id
		WHERE u.id = $1
	`

	row := r.db.QueryRow(ctx, query, id)
	user, err := scanUserWithDepartment(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetByUsername retrieves a user by username within a tenant
func (r *UserRepository) GetByUsername(ctx context.Context, tenantID, username string) (*User, error) {
	query := `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject,
		       COALESCE(u.department_id, ''), COALESCE(d.name, ''), u.department_assignment_mode, u.department_assignment_source,
		       COALESCE(u.department_assignment_rule_id, ''), u.department_resolved_at, u.department_version
		FROM users u
		LEFT JOIN teams d ON d.id = u.department_id AND d.tenant_id = u.tenant_id
		WHERE u.tenant_id = $1 AND u.username = $2
	`

	row := r.db.QueryRow(ctx, query, tenantID, username)
	user, err := scanUserWithDepartment(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetByUsernameGlobal retrieves a user by username globally (for platform admins)
func (r *UserRepository) GetByUsernameGlobal(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject,
		       COALESCE(u.department_id, ''), COALESCE(d.name, ''), u.department_assignment_mode, u.department_assignment_source,
		       COALESCE(u.department_assignment_rule_id, ''), u.department_resolved_at, u.department_version
		FROM users u
		LEFT JOIN teams d ON d.id = u.department_id AND d.tenant_id = u.tenant_id
		WHERE u.username = $1
	`

	row := r.db.QueryRow(ctx, query, username)
	user, err := scanUserWithDepartment(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user '%s': %w", username, err)
	}
	return user, nil
}

// GetByExternalSubject retrieves a user by (tenant_id, external_subject).
// external_subject is the SSO subject used by chat-portal as the idempotency key
// for lazily provisioned portal users. Returns nil, nil when not found.
func (r *UserRepository) GetByExternalSubject(ctx context.Context, tenantID, subject string) (*User, error) {
	query := `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject,
		       COALESCE(u.department_id, ''), COALESCE(d.name, ''), u.department_assignment_mode, u.department_assignment_source,
		       COALESCE(u.department_assignment_rule_id, ''), u.department_resolved_at, u.department_version
		FROM users u
		LEFT JOIN teams d ON d.id = u.department_id AND d.tenant_id = u.tenant_id
		WHERE u.tenant_id = $1 AND u.external_subject = $2
	`

	row := r.db.QueryRow(ctx, query, tenantID, subject)
	user, err := scanUserWithDepartment(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by external subject: %w", err)
	}
	return user, nil
}

// List retrieves users for a tenant
func (r *UserRepository) List(ctx context.Context, tenantID string) ([]*User, error) {
	query := `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject,
		       COALESCE(u.department_id, ''), COALESCE(d.name, ''), u.department_assignment_mode, u.department_assignment_source,
		       COALESCE(u.department_assignment_rule_id, ''), u.department_resolved_at, u.department_version
		FROM users u
		LEFT JOIN teams d ON d.id = u.department_id AND d.tenant_id = u.tenant_id
		WHERE u.tenant_id = $1 AND u.status <> 'deleted'
		ORDER BY u.username
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users := []*User{}
	for rows.Next() {
		user, err := scanUserWithDepartmentFromRows(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func buildContentAuditUserSelectorQuery(filter ContentAuditUserSelectorFilter) (string, []interface{}) {
	args := []interface{}{filter.TenantID}
	where := []string{"u.tenant_id = $1", "u.status <> 'deleted'"}
	if filter.DepartmentIDs != nil {
		args = append(args, filter.DepartmentIDs)
		where = append(where, fmt.Sprintf("u.department_id = ANY($%d)", len(args)))
	}
	if strings.TrimSpace(filter.Query) != "" {
		args = append(args, "%"+escapePostgresLikeLiteral(strings.TrimSpace(filter.Query))+"%")
		where = append(where, fmt.Sprintf("(u.username ILIKE $%d ESCAPE E'\\\\' OR u.id ILIKE $%d ESCAPE E'\\\\')", len(args), len(args)))
	}
	if filter.CursorID != "" {
		args = append(args, strings.ToLower(filter.CursorName), filter.CursorID)
		where = append(where, fmt.Sprintf("(LOWER(u.username), u.id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, filter.Limit+1, filter.Offset)
	query := fmt.Sprintf(`
		SELECT u.id, u.username, COALESCE(u.department_id, ''), COALESCE(d.name, '')
		FROM users u
		LEFT JOIN teams d ON d.tenant_id = u.tenant_id AND d.id = u.department_id
		WHERE %s
		ORDER BY LOWER(u.username), u.id
		LIMIT $%d OFFSET $%d
	`, strings.Join(where, " AND "), len(args)-1, len(args))
	return query, args
}

func (r *UserRepository) ListContentAuditUsers(ctx context.Context, filter ContentAuditUserSelectorFilter) ([]ContentAuditUserOption, bool, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Offset < 0 || filter.CursorID != "" {
		filter.Offset = 0
	}
	query, args := buildContentAuditUserSelectorQuery(filter)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("list content audit users: %w", err)
	}
	defer rows.Close()
	items := make([]ContentAuditUserOption, 0, filter.Limit+1)
	for rows.Next() {
		var item ContentAuditUserOption
		if err := rows.Scan(&item.ID, &item.Username, &item.DepartmentID, &item.DepartmentName); err != nil {
			return nil, false, err
		}
		item.IdentityKind = "key_owner"
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(items) > filter.Limit
	if hasMore {
		items = items[:filter.Limit]
	}
	return items, hasMore, nil
}

// ListAll retrieves all users across visible tenants, ordered by created_at DESC
func (r *UserRepository) ListAll(ctx context.Context) ([]*User, error) {
	query := `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject,
		       COALESCE(u.department_id, ''), COALESCE(d.name, ''), u.department_assignment_mode, u.department_assignment_source,
		       COALESCE(u.department_assignment_rule_id, ''), u.department_resolved_at, u.department_version
		FROM users u
		LEFT JOIN teams d ON d.id = u.department_id AND d.tenant_id = u.tenant_id
		JOIN tenants t ON t.id = u.tenant_id AND t.is_test = FALSE
		WHERE u.status <> 'deleted'
		ORDER BY u.created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user, err := scanUserWithDepartmentFromRows(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// ListAllWithStats retrieves visible users with aggregated stats (teams_csv, projects_count, grants_count, last_login_at)
func (r *UserRepository) ListAllWithStats(ctx context.Context) ([]*UserWithStats, error) {
	return r.listScopedStats(ctx, "", 0, 0)
}
func (r *UserRepository) ListScopedWithStats(ctx context.Context, tenant string, limit, offset int) ([]*UserWithStats, int, error) {
	var total int
	err := r.db.QueryRow(ctx, `SELECT count(*) FROM users u JOIN tenants t ON t.id=u.tenant_id AND NOT t.is_test WHERE u.status<>'deleted' AND ($1::text='' OR u.tenant_id=$1::text)`, tenant).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.listScopedStats(ctx, tenant, limit, offset)
	return rows, total, err
}
func (r *UserRepository) listScopedStats(ctx context.Context, tenant string, limit, offset int) ([]*UserWithStats, error) {
	query := `
		SELECT
			u.id,
			u.tenant_id,
			u.username,
			COALESCE(u.email, '') AS email,
			COALESCE(u.phone, '') AS phone,
			u.password_hash,
			u.must_change_password,
			u.role,
			u.status,
			COALESCE(u.external_subject, '') AS external_subject,
			COALESCE(u.department_id, '') AS department_id,
			COALESCE(department.name, '') AS department_name,
			u.department_assignment_mode,
			u.department_assignment_source,
			COALESCE(u.department_assignment_rule_id, '') AS department_assignment_rule_id,
			u.department_resolved_at, u.department_version,
			COALESCE(
				(SELECT string_agg(t.name, ',')
				 FROM team_members tm
				 JOIN teams t ON t.id = tm.team_id
				 WHERE tm.user_id = u.id),
				''
			) AS teams_csv,
			COALESCE(
				(SELECT json_agg(json_build_object('id', t.id, 'name', t.name))::text
				 FROM team_members tm
				 JOIN teams t ON t.id = tm.team_id
				 WHERE tm.user_id = u.id),
				'[]'
			) AS teams_json,
			COALESCE(
				(SELECT count(*)
				 FROM (
					 SELECT pu.project_id AS project_id
					 FROM project_users pu
					 JOIN projects p ON p.id = pu.project_id AND p.status <> 'deleted'
					 JOIN tenants pt ON pt.id = p.tenant_id AND pt.is_test = FALSE
					 WHERE pu.user_id = u.id
					 UNION
					 SELECT p.id AS project_id
					 FROM projects p
					 JOIN tenants pt ON pt.id = p.tenant_id AND pt.is_test = FALSE
					 WHERE p.owner_user_id = u.id AND p.status <> 'deleted'
				 ) visible_projects),
				0
			) AS projects_count,
			COALESCE(
				(SELECT count(*) FROM permission_grants g WHERE g.user_id = u.id),
				0
			) AS grants_count,
			COALESCE(u.last_login_at::text, '') AS last_login_at
		FROM users u
		LEFT JOIN teams department ON department.id = u.department_id AND department.tenant_id = u.tenant_id
		JOIN tenants tenant_filter ON tenant_filter.id = u.tenant_id AND tenant_filter.is_test = FALSE
		WHERE u.status <> 'deleted' AND ($1::text='' OR u.tenant_id=$1::text)
		ORDER BY u.created_at DESC,u.id
 LIMIT NULLIF($2::int,0) OFFSET $3::int
	`

	rows, err := r.db.Query(ctx, query, tenant, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users with stats: %w", err)
	}
	defer rows.Close()

	var users []*UserWithStats
	for rows.Next() {
		var u UserWithStats
		var email sql.NullString
		var phone sql.NullString
		var passwordHash sql.NullString
		var externalSubject sql.NullString
		err := rows.Scan(
			&u.ID,
			&u.TenantID,
			&u.Username,
			&email,
			&phone,
			&passwordHash,
			&u.MustChangePassword,
			&u.Role,
			&u.Status,
			&externalSubject,
			&u.DepartmentID,
			&u.DepartmentName,
			&u.DepartmentAssignmentMode,
			&u.DepartmentAssignmentSource,
			&u.DepartmentAssignmentRuleID,
			&u.DepartmentResolvedAt,
			&u.DepartmentVersion,
			&u.TeamsCSV,
			&u.TeamsJSON,
			&u.ProjectsCount,
			&u.GrantsCount,
			&u.LastLoginAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user with stats: %w", err)
		}
		if email.Valid {
			u.Email = email.String
		}
		if phone.Valid {
			u.Phone = phone.String
		}
		if passwordHash.Valid {
			u.PasswordHash = passwordHash.String
		}
		if externalSubject.Valid {
			u.ExternalSubject = externalSubject.String
		}
		users = append(users, &u)
	}
	return users, nil
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (id, tenant_id, username, email, phone, password_hash, must_change_password, role, status, external_subject,
			department_id, department_assignment_mode, department_assignment_source, department_assignment_rule_id, department_resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), NULLIF($11, ''),
			COALESCE(NULLIF($12, ''), 'unassigned'), COALESCE(NULLIF($13, ''), 'migration'), NULLIF($14, ''), $15)
	`

	_, err := r.db.Exec(ctx, query,
		user.ID,
		user.TenantID,
		user.Username,
		user.Email,
		user.Phone,
		user.PasswordHash,
		user.MustChangePassword,
		user.Role,
		user.Status,
		user.ExternalSubject,
		user.DepartmentID,
		user.DepartmentAssignmentMode,
		user.DepartmentAssignmentSource,
		user.DepartmentAssignmentRuleID,
		user.DepartmentResolvedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

var ErrUserReconciliationRequired = errors.New("user identity reconciliation is required")

// Ordinary writes may never clear a pause imposed by password synchronization.
// Lock the actual row so stale metadata snapshots cannot restore sign-in.
func lockOrdinaryUserWrite(ctx context.Context, tx pgx.Tx, userID, tenantID string) (bool, error) {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 AND ($2='' OR tenant_id=$2) FOR UPDATE`, userID, tenantID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if status == "reconciliation_required" {
		return false, ErrUserReconciliationRequired
	}
	return true, nil
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *User) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin user update: %w", err)
	}
	defer tx.Rollback(ctx)
	exists, err := lockOrdinaryUserWrite(ctx, tx, user.ID, user.TenantID)
	if err != nil {
		return fmt.Errorf("lock user update: %w", err)
	}
	if !exists {
		return nil
	}
	query := `
		UPDATE users
		SET username = $2, email = $3, phone = $4, must_change_password = $5, role = $6, status = $7,
		    external_subject = NULLIF($8, '')
		WHERE id = $1
	`

	_, err = tx.Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.Phone,
		user.MustChangePassword,
		user.Role,
		user.Status,
		user.ExternalSubject,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return tx.Commit(ctx)
}

// UpdateStatusForTenant changes one user's status only when the target belongs
// to the caller's tenant. It is used by security disposition enforcement, where
// a global user lookup must never become a cross-tenant write primitive.
func (r *UserRepository) UpdateStatusForTenant(ctx context.Context, tenantID, userID, status string) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tenant user status: %w", err)
	}
	defer tx.Rollback(ctx)
	exists, err := lockOrdinaryUserWrite(ctx, tx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("lock tenant user status: %w", err)
	}
	if !exists {
		return false, nil
	}
	result, err := tx.Exec(ctx, `
		UPDATE users
		SET status = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID, status)
	if err != nil {
		return false, fmt.Errorf("update tenant user status: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit tenant user status: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// UpdatePassword updates a user's password hash
func (r *UserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string, mustChangePassword bool) error {
	query := `UPDATE users SET password_hash = $1, must_change_password = $2, local_credential_version = local_credential_version + 1, updated_at = NOW() WHERE id = $3`
	_, err := r.db.Exec(ctx, query, passwordHash, mustChangePassword, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

// ListDeleteBlockers returns business-facing blockers that must be handled before hard deletion.
// Only resources that still exist count: a key deleted or disabled in key management, a key whose app
// was deleted afterwards, and an app that is already deleted are all gone as far as the operator can
// tell, so listing them would send the operator to a page where they cannot be found.
func (r *UserRepository) ListDeleteBlockers(ctx context.Context, userID string) ([]UserDeleteBlocker, error) {
	type blockerSpec struct {
		kind   string
		label  string
		entry  string
		action string
		query  string
		route  func(id, extra string) string
	}

	specs := []blockerSpec{
		{
			kind:   "project_owner",
			label:  "应用负责人",
			entry:  "应用管理",
			action: "先移交负责人给其他用户，或删除该应用",
			query: `
				SELECT p.id, p.name AS sample, '' AS extra, count(*) OVER()::int AS total
				FROM projects p
				JOIN tenants t ON t.id = p.tenant_id AND t.is_test = FALSE
				WHERE p.owner_user_id = $1
				  AND p.status <> 'deleted'
				ORDER BY p.updated_at DESC, p.name
				LIMIT 5
			`,
			route: func(id, _ string) string {
				return "/apps?project_id=" + url.QueryEscape(id)
			},
		},
		{
			kind:   "internal_key",
			label:  "内部密钥",
			entry:  "密钥管理",
			action: "删除或禁用该用户名下密钥；需要继续使用时请用新负责人重新创建",
			query: `
				SELECT ik.id, COALESCE(NULLIF(ik.key_prefix, ''), ik.id) AS sample, COALESCE(ik.project_id, '') AS extra, count(*) OVER()::int AS total
				FROM internal_keys ik
				JOIN tenants t ON t.id = ik.tenant_id AND t.is_test = FALSE
				LEFT JOIN projects kp ON kp.id = ik.project_id
				WHERE ik.user_id = $1
				  AND ik.deleted_at IS NULL
				  AND ik.status <> 'revoked'
				  AND (kp.id IS NULL OR kp.status <> 'deleted')
				ORDER BY ik.created_at DESC, ik.id
				LIMIT 5
			`,
			route: func(id, projectID string) string {
				return "/keys?project_id=" + url.QueryEscape(projectID) + "&key_id=" + url.QueryEscape(id)
			},
		},
	}

	blockers := make([]UserDeleteBlocker, 0, len(specs))
	for _, spec := range specs {
		rows, err := r.db.Query(ctx, spec.query, userID)
		if err != nil {
			return nil, fmt.Errorf("list user delete blockers %s: %w", spec.label, err)
		}

		var count int
		items := make([]UserDeleteBlockerItem, 0, 5)
		for rows.Next() {
			var id, sample, extra string
			if err := rows.Scan(&id, &sample, &extra, &count); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan user delete blockers %s: %w", spec.label, err)
			}
			items = append(items, UserDeleteBlockerItem{ID: id, Name: sample, Route: spec.route(id, extra)})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("iterate user delete blockers %s: %w", spec.label, err)
		}
		rows.Close()

		if count == 0 {
			continue
		}
		samples := make([]string, 0, len(items))
		for _, item := range items {
			samples = append(samples, item.Name)
		}
		route := ""
		if len(items) > 0 {
			route = items[0].Route
		}
		blockers = append(blockers, UserDeleteBlocker{
			Kind:    spec.kind,
			Label:   spec.label,
			Count:   count,
			Samples: strings.Join(samples, "、"),
			Entry:   spec.entry,
			Action:  spec.action,
			Route:   route,
			Items:   items,
		})
	}
	return blockers, nil
}

// Delete removes a user when PostgreSQL can safely do so. If immutable billing
// or identity history still owns a strict foreign key, it falls back to a safe
// retirement: revoke access, anonymize personal fields, and hide the row from
// all operator/customer user lists while preserving referential integrity.
func (r *UserRepository) Delete(ctx context.Context, userID string) (*UserRetirement, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin delete user: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, query := range []string{
		`UPDATE projects SET owner_user_id = NULL WHERE owner_user_id = $1 AND tenant_id IN (SELECT id FROM tenants WHERE is_test = TRUE)`,
		`UPDATE internal_keys SET user_id = NULL WHERE user_id = $1 AND tenant_id IN (SELECT id FROM tenants WHERE is_test = TRUE)`,
	} {
		if _, err := tx.Exec(ctx, query, userID); err != nil {
			return nil, fmt.Errorf("detach hidden test user references: %w", err)
		}
	}

	for _, query := range []string{
		`DELETE FROM project_users WHERE user_id = $1`,
		`DELETE FROM permission_grants WHERE user_id = $1`,
	} {
		if _, err := tx.Exec(ctx, query, userID); err != nil {
			return nil, fmt.Errorf("delete user relationships: %w", err)
		}
	}

	for _, query := range []string{
		`UPDATE request_logs SET user_id = NULL WHERE user_id = $1`,
		`UPDATE audit_operations SET user_id = NULL WHERE user_id = $1`,
		`UPDATE security_events SET user_id = NULL WHERE user_id = $1`,
		`UPDATE usage_daily SET user_id = NULL WHERE user_id = $1`,
		`UPDATE agent_sessions SET user_id = NULL WHERE user_id = $1`,
	} {
		if _, err := tx.Exec(ctx, query, userID); err != nil {
			return nil, fmt.Errorf("detach user historical references: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `SAVEPOINT before_user_hard_delete`); err != nil {
		return nil, fmt.Errorf("create user delete savepoint: %w", err)
	}
	retired := false
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			return nil, fmt.Errorf("delete user: %w", err)
		}
		if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_user_hard_delete`); rollbackErr != nil {
			return nil, fmt.Errorf("recover user delete transaction: %w", rollbackErr)
		}

		// A wallet and its immutable ledger are normal product data, not an
		// operator error. Preserve those rows while retiring the login identity.
		// The synthetic username keeps the tenant-level unique key reusable.
		if _, retireErr := tx.Exec(ctx, `
			UPDATE users
			SET username = '__deleted__' || id,
			    email = NULL,
			    phone = NULL,
			    password_hash = NULL,
			    must_change_password = FALSE,
			    role = 'viewer',
			    status = 'deleted',
			    external_subject = NULL,
			    department_id = NULL,
			    department_assignment_mode = 'emergency',
			    department_assignment_source = 'admin',
			    department_assignment_rule_id = NULL,
			    department_resolved_at = NOW(),
			    updated_at = NOW()
			WHERE id = $1
		`, userID); retireErr != nil {
			return nil, fmt.Errorf("retire referenced user: %w", retireErr)
		}
		for _, query := range []string{
			`DELETE FROM project_users WHERE user_id = $1`,
			`DELETE FROM team_members WHERE user_id = $1`,
			`DELETE FROM permission_grants WHERE user_id = $1`,
			`DELETE FROM quota_policies WHERE user_id = $1`,
			`DELETE FROM directory_user_links WHERE user_id = $1`,
			`DELETE FROM user_identity_links WHERE user_id = $1`,
			`DELETE FROM user_login_history WHERE user_id = $1`,
			`DELETE FROM billing_customer_group_memberships WHERE user_id = $1`,
			`DELETE FROM billing_customer_limits WHERE user_id = $1`,
			`DELETE FROM billing_limit_counters WHERE user_id = $1`,
			`DELETE FROM billing_request_leases WHERE user_id = $1`,
		} {
			if _, cleanupErr := tx.Exec(ctx, query, userID); cleanupErr != nil {
				return nil, fmt.Errorf("revoke retired user access: %w", cleanupErr)
			}
		}
		retired = true
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit delete user: %w", err)
	}
	return &UserRetirement{Retired: retired}, nil
}

func scanUser(row pgx.Row) (*User, error) {
	var user User
	var email sql.NullString
	var externalSubject sql.NullString
	var phone sql.NullString
	var passwordHash sql.NullString
	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&email,
		&phone,
		&passwordHash,
		&user.MustChangePassword,
		&user.Role,
		&user.Status,
		&externalSubject,
	)
	if phone.Valid {
		user.Phone = phone.String
	}
	if email.Valid {
		user.Email = email.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if externalSubject.Valid {
		user.ExternalSubject = externalSubject.String
	}
	return &user, err
}

func scanUserWithDepartment(row pgx.Row) (*User, error) {
	var user User
	var email sql.NullString
	var externalSubject sql.NullString
	var phone sql.NullString
	var passwordHash sql.NullString
	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&email,
		&phone,
		&passwordHash,
		&user.MustChangePassword,
		&user.Role,
		&user.Status,
		&externalSubject,
		&user.DepartmentID,
		&user.DepartmentName,
		&user.DepartmentAssignmentMode,
		&user.DepartmentAssignmentSource,
		&user.DepartmentAssignmentRuleID,
		&user.DepartmentResolvedAt,
		&user.DepartmentVersion,
	)
	setNullableUserFields(&user, email, phone, passwordHash, externalSubject)
	return &user, err
}

func scanUserWithDepartmentFromRows(rows pgx.Rows) (*User, error) {
	var user User
	var email sql.NullString
	var externalSubject sql.NullString
	var phone sql.NullString
	var passwordHash sql.NullString
	err := rows.Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&email,
		&phone,
		&passwordHash,
		&user.MustChangePassword,
		&user.Role,
		&user.Status,
		&externalSubject,
		&user.DepartmentID,
		&user.DepartmentName,
		&user.DepartmentAssignmentMode,
		&user.DepartmentAssignmentSource,
		&user.DepartmentAssignmentRuleID,
		&user.DepartmentResolvedAt,
		&user.DepartmentVersion,
	)
	setNullableUserFields(&user, email, phone, passwordHash, externalSubject)
	return &user, err
}

func scanUserFromRows(rows pgx.Rows) (*User, error) {
	var user User
	var email sql.NullString
	var externalSubject sql.NullString
	var phone sql.NullString
	var passwordHash sql.NullString
	err := rows.Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&email,
		&phone,
		&passwordHash,
		&user.MustChangePassword,
		&user.Role,
		&user.Status,
		&externalSubject,
	)
	if phone.Valid {
		user.Phone = phone.String
	}
	if email.Valid {
		user.Email = email.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if externalSubject.Valid {
		user.ExternalSubject = externalSubject.String
	}
	return &user, err
}

func setNullableUserFields(user *User, email, phone, passwordHash, externalSubject sql.NullString) {
	if phone.Valid {
		user.Phone = phone.String
	}
	if email.Valid {
		user.Email = email.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if externalSubject.Valid {
		user.ExternalSubject = externalSubject.String
	}
}

// UpdatePersonalBudget sets a user's personal monthly budget cap (nil = unconstrained).
func (r *UserRepository) UpdatePersonalBudget(ctx context.Context, userID string, amountCNY *float64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE users SET personal_monthly_budget_cny = $1 WHERE id = $2`,
		amountCNY, userID)
	if err != nil {
		return fmt.Errorf("update personal budget: %w", err)
	}
	return nil
}

// CountByStatus 统计租户内处于指定状态的账号数。
// 用于身份源总览统计 reconciliation_required 等待对账的用户数。
func (r *UserRepository) CountByStatus(ctx context.Context, tenantID, status string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND status=$2`, tenantID, status).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count users by status: %w", err)
	}
	return count, nil
}
