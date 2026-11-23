package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Tenant represents a tenant record
type Tenant struct {
	ID        string
	Name      string
	Edition   string
	Status    string
	Industry  string // 行业（generic/medical_imaging/finance…），驱动行业预置数据安全规则包自动挂载
	Config    map[string]interface{}
	CreatedAt time.Time
	UpdatedAt time.Time
}

// defaultIndustry 把空行业归一为 generic，确保下发逻辑恒有一个确定行业可用。
func defaultIndustry(s string) string {
	if s == "" {
		return "generic"
	}
	return s
}

// TenantRepository handles tenant database operations
type TenantRepository struct {
	db *pgxpool.Pool
}

// NewTenantRepository creates a new tenant repository
func NewTenantRepository(db *pgxpool.Pool) *TenantRepository {
	return &TenantRepository{db: db}
}

// GetByID retrieves a tenant by ID
func (r *TenantRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	query := `
		SELECT id, name, edition, status, COALESCE(industry, 'generic'), config_json, created_at, updated_at
		FROM tenants
		WHERE id = $1 AND status <> 'deleted'
	`

	row := r.db.QueryRow(ctx, query, id)
	var tenant Tenant
	var configJSON []byte
	err := row.Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Edition,
		&tenant.Status,
		&tenant.Industry,
		&configJSON,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	if len(configJSON) > 0 {
		tenant.Config = map[string]interface{}{}
	}

	return &tenant, nil
}

// List retrieves all non-test tenants (单位列表对管理员可见的真实单位)
func (r *TenantRepository) List(ctx context.Context) ([]*Tenant, error) {
	query := `
		SELECT id, name, edition, status, COALESCE(industry, 'generic'), config_json, created_at, updated_at
		FROM tenants
		WHERE is_test = FALSE AND status <> 'deleted'
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	tenants := []*Tenant{}
	for rows.Next() {
		var tenant Tenant
		var configJSON []byte
		err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.Edition,
			&tenant.Status,
			&tenant.Industry,
			&configJSON,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, &tenant)
	}
	return tenants, nil
}

// ListSecurityPolicyTenantIDs returns every customer tenant that must own the
// preloaded policy catalog. The reserved platform tenant only hosts shared
// executable rules and must never receive a customer catalog copy.
func (r *TenantRepository) ListSecurityPolicyTenantIDs(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id FROM tenants
		WHERE id <> $1 AND status <> 'deleted'
		ORDER BY id`, SystemTenantID)
	if err != nil {
		return nil, fmt.Errorf("list tenants for security policy initialization: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant for security policy initialization: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants for security policy initialization: %w", err)
	}
	return ids, nil
}

// Create creates a new tenant
func (r *TenantRepository) Create(ctx context.Context, tenant *Tenant) error {
	if tenant.ID == "" {
		tenant.ID = "tenant_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO tenants (id, name, edition, status, config_json)
		VALUES ($1, $2, $3, $4, '{}')
	`

	_, err := r.db.Exec(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Edition,
		tenant.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}
	return nil
}

// Update updates a tenant
func (r *TenantRepository) Update(ctx context.Context, tenant *Tenant) error {
	query := `
		UPDATE tenants
		SET name = $2, edition = $3, status = $4, industry = $5, updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Edition,
		tenant.Status,
		defaultIndustry(tenant.Industry),
	)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}
	return nil
}

// Delete 软删除单位（调用方负责前置安全校验：非本单位、无活动用户/应用）。
// 保留单位及其历史资源行，避免破坏调用日志、安全事件等审计引用。
func (r *TenantRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.Exec(ctx, `
		UPDATE tenants
		SET status = 'deleted', updated_at = NOW()
		WHERE id = $1 AND status <> 'deleted'
	`, id)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("failed to delete tenant: tenant %s was not found", id)
	}
	return nil
}

// CleanupFailedPolicyInitialization removes only the objects that can be
// created during a brand-new tenant's policy bootstrap, in dependency order.
// It is used after Create has committed but rule-set/catalog initialization
// fails, so the API never leaves an active half-created tenant behind.
func (r *TenantRepository) CleanupFailedPolicyInitialization(ctx context.Context, tenantID string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin failed tenant cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		DELETE FROM rules
		WHERE rule_set_id IN (SELECT id FROM rule_sets WHERE tenant_id=$1)`, tenantID); err != nil {
		return fmt.Errorf("delete failed tenant policy rules: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM rule_sets WHERE tenant_id=$1`, tenantID); err != nil {
		return fmt.Errorf("delete failed tenant rule sets: %w", err)
	}
	result, err := tx.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	if err != nil {
		return fmt.Errorf("delete failed tenant: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("delete failed tenant: tenant %s was not found", tenantID)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit failed tenant cleanup: %w", err)
	}
	return nil
}
