package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SystemRole represents a system_roles row
type SystemRole struct {
	ID          string
	Name        string
	Code        string
	Description string
	IsBuiltin   bool
	IsSystem    bool
	CreatedAt   time.Time
}

// SystemPermission represents a system_permissions row with RBAC fields
type SystemPermission struct {
	ID       string
	Code     string
	RoleName string
	Resource string
	Action   string
}

// SystemRolesRepository handles system_roles and system_permissions reads
type SystemRolesRepository struct {
	db *pgxpool.Pool
}

// NewSystemRolesRepository creates a new repository
func NewSystemRolesRepository(db *pgxpool.Pool) *SystemRolesRepository {
	return &SystemRolesRepository{db: db}
}

// ListBuiltin returns all builtin system roles
func (r *SystemRolesRepository) ListBuiltin(ctx context.Context) ([]*SystemRole, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, code, COALESCE(description, ''), COALESCE(is_builtin, FALSE), COALESCE(is_system, FALSE), created_at
		FROM system_roles
		WHERE is_builtin = TRUE OR is_system = TRUE
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("list builtin roles: %w", err)
	}
	defer rows.Close()

	var roles []*SystemRole
	for rows.Next() {
		sr := &SystemRole{}
		if err := rows.Scan(&sr.ID, &sr.Name, &sr.Code, &sr.Description, &sr.IsBuiltin, &sr.IsSystem, &sr.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, sr)
	}
	return roles, rows.Err()
}

// ListAll returns all system roles
func (r *SystemRolesRepository) ListAll(ctx context.Context) ([]*SystemRole, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, code, COALESCE(description, ''), COALESCE(is_builtin, FALSE), COALESCE(is_system, FALSE), created_at
		FROM system_roles
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("list all roles: %w", err)
	}
	defer rows.Close()

	var roles []*SystemRole
	for rows.Next() {
		sr := &SystemRole{}
		if err := rows.Scan(&sr.ID, &sr.Name, &sr.Code, &sr.Description, &sr.IsBuiltin, &sr.IsSystem, &sr.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, sr)
	}
	return roles, rows.Err()
}

// GetPermissionsByRole returns all (resource, action) for a given role
func (r *SystemRolesRepository) GetPermissionsByRole(ctx context.Context, roleName string) ([]*SystemPermission, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, code, COALESCE(role_name, ''), COALESCE(resource, ''), COALESCE(action, '')
		FROM system_permissions
		WHERE role_name = $1
		  AND resource IS NOT NULL
		  AND action IS NOT NULL
		ORDER BY resource, action
	`, roleName)
	if err != nil {
		return nil, fmt.Errorf("get permissions by role: %w", err)
	}
	defer rows.Close()

	var perms []*SystemPermission
	for rows.Next() {
		p := &SystemPermission{}
		if err := rows.Scan(&p.ID, &p.Code, &p.RoleName, &p.Resource, &p.Action); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}
