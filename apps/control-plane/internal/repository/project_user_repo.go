package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ProjectUser struct {
	ID        string // Primary key
	ProjectID string
	UserID    string
	Role      string // owner, developer, viewer
	CreatedAt time.Time
}

type ProjectUserRepository struct {
	db *pgxpool.Pool
}

func NewProjectUserRepository(db *pgxpool.Pool) *ProjectUserRepository {
	return &ProjectUserRepository{db: db}
}

// GetUsersByProject returns user IDs bound to a project
func (r *ProjectUserRepository) GetUsersByProject(ctx context.Context, projectID string) ([]string, error) {
	query := `SELECT user_id FROM project_users WHERE project_id = $1 ORDER BY created_at`
	rows, err := r.db.Query(ctx, query, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project users: %w", err)
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, userID)
	}
	return userIDs, nil
}

// GetUsersByProjectWithRole returns ProjectUser records with role information
func (r *ProjectUserRepository) GetUsersByProjectWithRole(ctx context.Context, projectID string) ([]*ProjectUser, error) {
	query := `SELECT id, project_id, user_id, role, created_at FROM project_users WHERE project_id = $1 ORDER BY created_at`
	rows, err := r.db.Query(ctx, query, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project users with role: %w", err)
	}
	defer rows.Close()

	var projectUsers []*ProjectUser
	for rows.Next() {
		var pu ProjectUser
		if err := rows.Scan(&pu.ID, &pu.ProjectID, &pu.UserID, &pu.Role, &pu.CreatedAt); err != nil {
			return nil, err
		}
		projectUsers = append(projectUsers, &pu)
	}
	return projectUsers, nil
}

// GetProjectsByUser returns project IDs bound to a user
func (r *ProjectUserRepository) GetProjectsByUser(ctx context.Context, userID string) ([]string, error) {
	query := `SELECT project_id FROM project_users WHERE user_id = $1 ORDER BY created_at`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user projects: %w", err)
	}
	defer rows.Close()

	var projectIDs []string
	for rows.Next() {
		var projectID string
		if err := rows.Scan(&projectID); err != nil {
			return nil, err
		}
		projectIDs = append(projectIDs, projectID)
	}
	return projectIDs, nil
}

// BindUser binds a user to a project with a default role (developer)
func (r *ProjectUserRepository) BindUser(ctx context.Context, projectID, userID string) error {
	query := `INSERT INTO project_users (project_id, user_id, role) VALUES ($1, $2, 'developer') ON CONFLICT DO NOTHING`
	_, err := r.db.Exec(ctx, query, projectID, userID)
	if err != nil {
		return fmt.Errorf("failed to bind user to project: %w", err)
	}
	return nil
}

// BindUserWithRole binds a user to a project with a specific role
func (r *ProjectUserRepository) BindUserWithRole(ctx context.Context, projectID, userID, role string) error {
	query := `INSERT INTO project_users (project_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (project_id, user_id) DO UPDATE SET role = $3`
	_, err := r.db.Exec(ctx, query, projectID, userID, role)
	if err != nil {
		return fmt.Errorf("failed to bind user to project with role: %w", err)
	}
	return nil
}

// GetUserRole returns the role of a user in a project
func (r *ProjectUserRepository) GetUserRole(ctx context.Context, projectID, userID string) (string, error) {
	query := `SELECT role FROM project_users WHERE project_id = $1 AND user_id = $2`
	var role string
	err := r.db.QueryRow(ctx, query, projectID, userID).Scan(&role)
	if err != nil {
		return "", fmt.Errorf("failed to get user role: %w", err)
	}
	return role, nil
}

// UpdateUserRole updates the role of a user in a project
func (r *ProjectUserRepository) UpdateUserRole(ctx context.Context, projectID, userID, role string) error {
	query := `UPDATE project_users SET role = $3 WHERE project_id = $1 AND user_id = $2`
	_, err := r.db.Exec(ctx, query, projectID, userID, role)
	if err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}
	return nil
}

// UnbindUser unbinds a user from a project
func (r *ProjectUserRepository) UnbindUser(ctx context.Context, projectID, userID string) error {
	query := `DELETE FROM project_users WHERE project_id = $1 AND user_id = $2`
	_, err := r.db.Exec(ctx, query, projectID, userID)
	if err != nil {
		return fmt.Errorf("failed to unbind user from project: %w", err)
	}
	return nil
}

// BindPortalDefaultProject adds only the current department/default Chat app.
// The department revision fences a change between handler reads and this write.
// Existing roles are preserved; this path only creates a developer membership.
func (r *ProjectUserRepository) BindPortalDefaultProject(ctx context.Context, tenantID, userID, projectID, departmentID string, departmentVersion int64) (bool, error) {
	tag, err := r.db.Exec(ctx, `
        INSERT INTO project_users(project_id,user_id,role)
        SELECT p.id,u.id,'developer'
        FROM users u
        JOIN teams department ON department.tenant_id=u.tenant_id AND department.id=u.department_id
        JOIN projects p ON p.tenant_id=u.tenant_id AND p.id=$3 AND p.status='active'
        WHERE u.tenant_id=$1 AND u.id=$2 AND u.department_id=$4 AND u.department_version=$5
          AND u.status='active' AND u.department_assignment_mode NOT IN ('emergency','service')
          AND (
            p.team_id=u.department_id OR (
              department.system_key='unassigned'
              AND EXISTS(SELECT 1 FROM teams fallback WHERE fallback.tenant_id=u.tenant_id AND fallback.id=p.team_id AND fallback.system_key='chat_default')
              AND NOT EXISTS(SELECT 1 FROM projects own WHERE own.tenant_id=u.tenant_id AND own.team_id=u.department_id AND own.status='active')
            )
          )
          AND p.id=(SELECT chosen.id FROM projects chosen WHERE chosen.tenant_id=u.tenant_id AND chosen.team_id=p.team_id AND chosen.status='active' ORDER BY chosen.created_at,chosen.id LIMIT 1)
        ON CONFLICT(project_id,user_id) DO UPDATE SET role=project_users.role
    `, tenantID, userID, projectID, departmentID, departmentVersion)
	if err != nil {
		return false, fmt.Errorf("bind current portal application: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
