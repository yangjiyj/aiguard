package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RoutingPolicy represents a routing_policies table row.
type RoutingPolicy struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	ScopeType  string         `json:"scope_type"`
	ScopeRef   string         `json:"scope_ref"`
	Layer      string         `json:"layer"`
	Strategy   string         `json:"strategy"`
	ConfigJSON map[string]any `json:"config_json"`
	Enabled    bool           `json:"enabled"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// RoutingPolicyRepository handles routing_policies DB operations.
type RoutingPolicyRepository struct {
	db *pgxpool.Pool
}

// NewRoutingPolicyRepository creates a new RoutingPolicyRepository.
func NewRoutingPolicyRepository(db *pgxpool.Pool) *RoutingPolicyRepository {
	return &RoutingPolicyRepository{db: db}
}

// Upsert inserts or updates a routing policy.
// p.ID must be set by the caller before calling Upsert.
func (r *RoutingPolicyRepository) Upsert(ctx context.Context, p *RoutingPolicy) error {
	configBytes, err := json.Marshal(p.ConfigJSON)
	if err != nil {
		return fmt.Errorf("marshal config_json: %w", err)
	}
	now := time.Now()
	_, err = r.db.Exec(ctx, `
		INSERT INTO routing_policies
			(id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			scope_type  = EXCLUDED.scope_type,
			scope_ref   = EXCLUDED.scope_ref,
			layer       = EXCLUDED.layer,
			strategy    = EXCLUDED.strategy,
			config_json = EXCLUDED.config_json,
			enabled     = EXCLUDED.enabled,
			updated_at  = EXCLUDED.updated_at
	`,
		p.ID, p.TenantID, p.ScopeType, p.ScopeRef, p.Layer, p.Strategy,
		configBytes, p.Enabled, now, now,
	)
	if err != nil {
		return fmt.Errorf("upsert routing_policy: %w", err)
	}
	p.CreatedAt = now
	p.UpdatedAt = now
	return nil
}

// ListByScope returns all policies for a given tenant + scope.
func (r *RoutingPolicyRepository) ListByScope(ctx context.Context, tenantID, scopeType, scopeRef string) ([]*RoutingPolicy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, created_at, updated_at
		FROM routing_policies
		WHERE tenant_id = $1 AND scope_type = $2 AND scope_ref = $3
		ORDER BY created_at DESC
	`, tenantID, scopeType, scopeRef)
	if err != nil {
		return nil, fmt.Errorf("list routing_policies: %w", err)
	}
	defer rows.Close()
	return scanRoutingPolicyRows(rows)
}

// ListByTenant returns all policies for a given tenant (no scope filter).
func (r *RoutingPolicyRepository) ListByTenant(ctx context.Context, tenantID string) ([]*RoutingPolicy, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, created_at, updated_at
		FROM routing_policies
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list routing_policies by tenant: %w", err)
	}
	defer rows.Close()
	return scanRoutingPolicyRows(rows)
}

// GetByID returns a single policy. Returns nil, nil when not found.
func (r *RoutingPolicyRepository) GetByID(ctx context.Context, id string) (*RoutingPolicy, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, created_at, updated_at
		FROM routing_policies WHERE id = $1
	`, id)
	p, err := scanRoutingPolicyRow(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// Delete removes a routing policy by ID. Idempotent (no error when not found).
func (r *RoutingPolicyRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM routing_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete routing_policy: %w", err)
	}
	return nil
}

// --- helpers ---

func scanRoutingPolicyRows(rows pgx.Rows) ([]*RoutingPolicy, error) {
	var result []*RoutingPolicy
	for rows.Next() {
		var p RoutingPolicy
		var configBytes []byte
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.ScopeType, &p.ScopeRef,
			&p.Layer, &p.Strategy, &configBytes, &p.Enabled,
			&p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan routing_policy row: %w", err)
		}
		if len(configBytes) > 0 {
			_ = json.Unmarshal(configBytes, &p.ConfigJSON)
		}
		result = append(result, &p)
	}
	return result, rows.Err()
}

func scanRoutingPolicyRow(row pgx.Row) (*RoutingPolicy, error) {
	var p RoutingPolicy
	var configBytes []byte
	err := row.Scan(
		&p.ID, &p.TenantID, &p.ScopeType, &p.ScopeRef,
		&p.Layer, &p.Strategy, &configBytes, &p.Enabled,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(configBytes) > 0 {
		_ = json.Unmarshal(configBytes, &p.ConfigJSON)
	}
	return &p, nil
}
