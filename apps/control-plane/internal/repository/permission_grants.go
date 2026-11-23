package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PermissionGrant represents a permission_grants row
type PermissionGrant struct {
	ID        string
	TenantID  string
	UserID    string
	ScopeType string
	ScopeID   string
	Role      string
	GrantedBy string
	GrantedAt time.Time
}

// PermissionGrantRepository handles permission_grants CRUD
type PermissionGrantRepository struct {
	db *pgxpool.Pool
}

// NewPermissionGrantRepository creates a new repository
func NewPermissionGrantRepository(db *pgxpool.Pool) *PermissionGrantRepository {
	return &PermissionGrantRepository{db: db}
}

// Create inserts a new permission grant (idempotent via ON CONFLICT DO NOTHING)
func (r *PermissionGrantRepository) Create(ctx context.Context, g *PermissionGrant) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO permission_grants (id, tenant_id, user_id, scope_type, scope_id, role, granted_by, granted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (user_id, scope_type, scope_id, role) DO NOTHING
	`, g.ID, g.TenantID, g.UserID, g.ScopeType, g.ScopeID, g.Role, g.GrantedBy)
	if err != nil {
		return fmt.Errorf("create permission grant: %w", err)
	}
	return nil
}

// Delete removes a permission grant by ID
func (r *PermissionGrantRepository) Delete(ctx context.Context, grantID, tenantID string) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM permission_grants WHERE id = $1 AND tenant_id = $2
	`, grantID, tenantID)
	if err != nil {
		return fmt.Errorf("delete permission grant: %w", err)
	}
	return nil
}

// ListByUser returns all grants for a user within a tenant
func (r *PermissionGrantRepository) ListByUser(ctx context.Context, userID, tenantID string) ([]*PermissionGrant, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, user_id, scope_type, scope_id, role, COALESCE(granted_by, ''), granted_at
		FROM permission_grants
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY granted_at DESC
	`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list grants by user: %w", err)
	}
	defer rows.Close()

	var grants []*PermissionGrant
	for rows.Next() {
		g := &PermissionGrant{}
		if err := rows.Scan(&g.ID, &g.TenantID, &g.UserID, &g.ScopeType, &g.ScopeID, &g.Role, &g.GrantedBy, &g.GrantedAt); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}

// ListByScope returns all grants for a specific scope
func (r *PermissionGrantRepository) ListByScope(ctx context.Context, tenantID, scopeType, scopeID string) ([]*PermissionGrant, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, user_id, scope_type, scope_id, role, COALESCE(granted_by, ''), granted_at
		FROM permission_grants
		WHERE tenant_id = $1 AND scope_type = $2 AND scope_id = $3
		ORDER BY granted_at DESC
	`, tenantID, scopeType, scopeID)
	if err != nil {
		return nil, fmt.Errorf("list grants by scope: %w", err)
	}
	defer rows.Close()

	var grants []*PermissionGrant
	for rows.Next() {
		g := &PermissionGrant{}
		if err := rows.Scan(&g.ID, &g.TenantID, &g.UserID, &g.ScopeType, &g.ScopeID, &g.Role, &g.GrantedBy, &g.GrantedAt); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}

// EnsureAdminGrant creates a platform_admin grant for the admin user if not exists
func (r *PermissionGrantRepository) EnsureAdminGrant(ctx context.Context, userID, tenantID string) error {
	id := fmt.Sprintf("grant_admin_%s", tenantID)
	_, err := r.db.Exec(ctx, `
		INSERT INTO permission_grants (id, tenant_id, user_id, scope_type, scope_id, role, granted_by)
		VALUES ($1, $2, $3, 'tenant', $4, 'platform_admin', 'system')
		ON CONFLICT (user_id, scope_type, scope_id, role) DO NOTHING
	`, id, tenantID, userID, tenantID)
	if err != nil {
		return fmt.Errorf("ensure admin grant: %w", err)
	}
	return nil
}
