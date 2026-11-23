package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TeamMember represents a single user's membership in a team.
type TeamMember struct {
	TeamID    string
	UserID    string
	Role      string
	CreatedAt time.Time
}

// TeamMembershipWithName 是带部门显示名的用户部门归属，用于用户详情页展示，
// 避免前端只拿到 team_id（UUID）而显示不出部门中文名。
type TeamMembershipWithName struct {
	TeamID    string
	TeamName  string
	Role      string
	CreatedAt time.Time
}

// TeamMemberRepository handles team membership database operations.
type TeamMemberRepository struct {
	db *pgxpool.Pool
}

// NewTeamMemberRepository creates a new TeamMemberRepository.
func NewTeamMemberRepository(db *pgxpool.Pool) *TeamMemberRepository {
	return &TeamMemberRepository{db: db}
}

// Add keeps the legacy membership API compatible with users.department_id as
// the single authority. Migration 137's trigger owns the team_members projection.
//
// Deprecated: use identitybinding.BindingService.AssignManyManually.
func (r *TeamMemberRepository) Add(ctx context.Context, teamID, userID, role string) error {
	if !validTeamMemberRole(role) {
		return fmt.Errorf("add team member: invalid role")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("add team member: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := assignProjectedTeamMember(ctx, tx, teamID, userID, role); err != nil {
		return fmt.Errorf("add team member: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("add team member: commit transaction: %w", err)
	}
	return nil
}

// Remove moves a non-emergency user to the tenant's system unassigned
// department. Deleting the projection directly would be restored by migration
// 137's trigger and would leave users.department_id unchanged.
//
// Deprecated: use identitybinding.BindingService.Unassign.
func (r *TeamMemberRepository) Remove(ctx context.Context, teamID, userID string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users u
		SET department_id=unassigned.id,
		    department_assignment_mode='unassigned',
		    department_assignment_source='admin',
		    department_assignment_rule_id=NULL,
		    department_resolved_at=NOW(),
		    updated_at=NOW()
		FROM teams current_department, teams unassigned
		WHERE current_department.id=$1
		  AND current_department.tenant_id=u.tenant_id
		  AND u.id=$2
		  AND u.department_id=current_department.id
		  AND u.department_assignment_mode <> 'emergency'
		  AND unassigned.tenant_id=u.tenant_id
		  AND unassigned.system_key='unassigned'
	`, teamID, userID)
	if err != nil {
		return fmt.Errorf("remove team member: %w", err)
	}
	return nil
}

func validTeamMemberRole(role string) bool {
	switch role {
	case "owner", "member", "viewer":
		return true
	default:
		return false
	}
}

func assignProjectedTeamMember(ctx context.Context, tx pgx.Tx, teamID, userID, role string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE users u
		SET department_id=department.id,
		    department_assignment_mode='manual',
		    department_assignment_source='admin',
		    department_assignment_rule_id=NULL,
		    department_resolved_at=NOW(),
		    updated_at=NOW()
		FROM teams department
		WHERE department.id=$1
		  AND department.tenant_id=u.tenant_id
		  AND u.id=$2
		  AND u.department_assignment_mode <> 'emergency'
	`, teamID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("target not found")
	}
	tag, err = tx.Exec(ctx, `
		UPDATE team_members
		SET role=$3
		WHERE team_id=$1 AND user_id=$2
	`, teamID, userID, role)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("department projection not created")
	}
	return nil
}

// ListByTeam returns all members of a team, ordered by creation time.
func (r *TeamMemberRepository) ListByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	rows, err := r.db.Query(ctx, `
		SELECT team_id, user_id, role, created_at
		FROM team_members
		WHERE team_id = $1
		ORDER BY created_at
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list team members: %w", err)
	}
	defer rows.Close()
	return scanMemberRows(rows)
}

// ListByUser returns all team memberships for a user, ordered by creation time.
func (r *TeamMemberRepository) ListByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	rows, err := r.db.Query(ctx, `
		SELECT team_id, user_id, role, created_at
		FROM team_members
		WHERE user_id = $1
		ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user teams: %w", err)
	}
	defer rows.Close()
	return scanMemberRows(rows)
}

// ListByUserWithTeamName returns a user's team memberships joined with each
// team's display name, ordered by creation time. A LEFT JOIN is used so a
// membership pointing at a since-deleted team still surfaces (with empty
// TeamName), letting the caller fall back to the team_id for display.
func (r *TeamMemberRepository) ListByUserWithTeamName(ctx context.Context, userID string) ([]*TeamMembershipWithName, error) {
	rows, err := r.db.Query(ctx, `
		SELECT tm.team_id, COALESCE(t.name, ''), tm.role, tm.created_at
		FROM team_members tm
		LEFT JOIN teams t ON t.id = tm.team_id
		WHERE tm.user_id = $1
		ORDER BY tm.created_at
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user teams with name: %w", err)
	}
	defer rows.Close()

	var out []*TeamMembershipWithName
	for rows.Next() {
		var m TeamMembershipWithName
		if err := rows.Scan(&m.TeamID, &m.TeamName, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// ListTeamIDsByUser returns the team IDs a user belongs to.
//
// Authority source: users.department_id (migration 137). team_members is a
// one-row compatibility projection maintained by trigger and is NOT consulted
// for authorization — a stale team_members row left after a department move
// must never expand a user's scope. Returns at most one ID (the user's single
// authoritative department); returns nothing for emergency users who have no
// department assignment.
func (r *TeamMemberRepository) ListTeamIDsByUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT department_id
		FROM users
		WHERE id = $1
		  AND department_id IS NOT NULL
		  AND department_assignment_mode <> 'emergency'
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list team ids by user: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListProjectIDsByUserTeams returns projects assigned to the user's
// department and its descendant departments.
//
// Authority source: users.department_id (migration 137). The root department is
// read from users, never from team_members, so a stale projection row after a
// department migration cannot grant access to the previous department's
// projects. Emergency users (no department) get nothing.
func (r *TeamMemberRepository) ListProjectIDsByUserTeams(ctx context.Context, tenantID, userID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT p.id
		FROM users u
		JOIN teams root ON root.id = u.department_id AND root.tenant_id = $1
		JOIN teams project_team ON project_team.tenant_id = $1
			AND (project_team.id = root.id OR project_team.path LIKE root.path || '/%')
		JOIN projects p ON p.tenant_id = $1 AND p.team_id = project_team.id
		WHERE u.id = $2
		  AND u.tenant_id = $1
		  AND u.department_id IS NOT NULL
		  AND u.department_assignment_mode <> 'emergency'
		ORDER BY p.id
	`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("list project ids by user teams: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListTeamSubtreeIDsByUser returns the user's department plus descendant
// departments.
//
// Authority source: users.department_id (migration 137). team_members is not
// consulted; a department migration takes effect immediately for scope
// computation. Emergency users get nothing.
func (r *TeamMemberRepository) ListTeamSubtreeIDsByUser(ctx context.Context, tenantID, userID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT scoped.id
		FROM users u
		JOIN teams root ON root.id = u.department_id AND root.tenant_id = $1
		JOIN teams scoped ON scoped.tenant_id = $1
			AND (scoped.id = root.id OR scoped.path LIKE root.path || '/%')
		WHERE u.id = $2
		  AND u.tenant_id = $1
		  AND u.department_id IS NOT NULL
		  AND u.department_assignment_mode <> 'emergency'
		ORDER BY scoped.id
	`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("list team subtree ids by user: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CountUsersByTeams returns distinct users assigned to the provided team IDs.
func (r *TeamMemberRepository) CountUsersByTeams(ctx context.Context, tenantID string, teamIDs []string) (int, error) {
	if len(teamIDs) == 0 {
		return 0, nil
	}
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT tm.user_id)
		FROM team_members tm
		JOIN teams t ON t.id = tm.team_id
		WHERE t.tenant_id = $1 AND tm.team_id = ANY($2::text[])
	`, tenantID, teamIDs).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count users by teams: %w", err)
	}
	return count, nil
}

// CountProjectsByTeams returns projects assigned to the provided team IDs.
func (r *TeamMemberRepository) CountProjectsByTeams(ctx context.Context, tenantID string, teamIDs []string) (int, error) {
	if len(teamIDs) == 0 {
		return 0, nil
	}
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM projects
		WHERE tenant_id = $1 AND team_id = ANY($2::text[]) AND status <> 'deleted'
	`, tenantID, teamIDs).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count projects by teams: %w", err)
	}
	return count, nil
}

// UpdateRole changes the role of a user in a team.
func (r *TeamMemberRepository) UpdateRole(ctx context.Context, teamID, userID, role string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE team_members SET role = $1 WHERE team_id = $2 AND user_id = $3
	`, role, teamID, userID)
	if err != nil {
		return fmt.Errorf("update team member role: %w", err)
	}
	return nil
}

func scanMemberRows(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*TeamMember, error) {
	var members []*TeamMember
	for rows.Next() {
		var m TeamMember
		if err := rows.Scan(&m.TeamID, &m.UserID, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		members = append(members, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return members, nil
}

// BatchAdd updates users.department_id for all users in one transaction and
// lets the database trigger maintain the compatibility projection.
//
// Deprecated: use identitybinding.BindingService.AssignManyManually.
func (r *TeamMemberRepository) BatchAdd(ctx context.Context, teamID string, userIDs []string, role string) error {
	if len(userIDs) == 0 {
		return nil
	}
	if !validTeamMemberRole(role) {
		return fmt.Errorf("batch add team members: invalid role")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, uid := range userIDs {
		if err := assignProjectedTeamMember(ctx, tx, teamID, uid, role); err != nil {
			return fmt.Errorf("batch add member %s: %w", uid, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit batch add team members: %w", err)
	}
	return nil
}
