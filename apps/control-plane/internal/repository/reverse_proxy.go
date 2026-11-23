package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ReverseProxyRoute struct {
	ID                 string   `json:"id"`
	TenantID           string   `json:"tenant_id"`
	Name               string   `json:"name"`
	PathPrefix         string   `json:"path_prefix"`
	TargetURL          string   `json:"target_url"`
	TargetPathPrefix   string   `json:"target_path_prefix"`
	AllowPrivateEgress bool     `json:"allow_private_egress"`
	PrivateEgressCIDRs []string `json:"private_egress_cidrs"`
	// EgressOverrides 是路由的对象级出站放行（迁移 999 的 egress_overrides 列，默认全拒）。
	EgressOverrides safetarget.EgressOverrides `json:"egress_overrides"`
	SecurityEnabled bool                       `json:"security_enabled"`
	StatsEnabled    bool                       `json:"stats_enabled"`
	Status          string                     `json:"status"`
	Description     string                     `json:"description"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

// parseStoredEgressOverrides 解析库里的 egress_overrides；坏值按默认（全部拒绝）处理。
func parseStoredEgressOverrides(raw string) safetarget.EgressOverrides {
	overrides, err := safetarget.ParseEgressOverrides([]byte(raw))
	if err != nil {
		log.Printf("stored egress_overrides invalid, treated as defaults: %v", err)
		return safetarget.EgressOverrides{}
	}
	return overrides
}

type ReverseProxyRouteRepository struct {
	db *pgxpool.Pool
}

func NewReverseProxyRouteRepository(db *pgxpool.Pool) *ReverseProxyRouteRepository {
	return &ReverseProxyRouteRepository{db: db}
}

func (r *ReverseProxyRouteRepository) GetByID(ctx context.Context, tenantID, id string) (*ReverseProxyRoute, error) {
	query := `
		SELECT id, tenant_id, name, path_prefix, target_url, target_path_prefix,
		       allow_private_egress, private_egress_cidrs,
		       security_enabled, stats_enabled, status, description, created_at, updated_at,
		       COALESCE(egress_overrides, '{}'::jsonb)::text
		FROM reverse_proxy_routes
		WHERE tenant_id = $1 AND id = $2
	`

	row := r.db.QueryRow(ctx, query, tenantID, id)
	var entry ReverseProxyRoute
	var overridesText string
	err := row.Scan(
		&entry.ID,
		&entry.TenantID,
		&entry.Name,
		&entry.PathPrefix,
		&entry.TargetURL,
		&entry.TargetPathPrefix,
		&entry.AllowPrivateEgress,
		&entry.PrivateEgressCIDRs,
		&entry.SecurityEnabled,
		&entry.StatsEnabled,
		&entry.Status,
		&entry.Description,
		&entry.CreatedAt,
		&entry.UpdatedAt,
		&overridesText,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get reverse proxy route: %w", err)
	}
	entry.EgressOverrides = parseStoredEgressOverrides(overridesText)
	return &entry, nil
}

func (r *ReverseProxyRouteRepository) List(ctx context.Context, tenantID string) ([]ReverseProxyRoute, error) {
	query := `
		SELECT id, tenant_id, name, path_prefix, target_url, target_path_prefix,
		       allow_private_egress, private_egress_cidrs,
		       security_enabled, stats_enabled, status, description, created_at, updated_at,
		       COALESCE(egress_overrides, '{}'::jsonb)::text
		FROM reverse_proxy_routes
		WHERE tenant_id = $1
		ORDER BY path_prefix, name
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list reverse proxy routes: %w", err)
	}
	defer rows.Close()

	var entries []ReverseProxyRoute
	for rows.Next() {
		var entry ReverseProxyRoute
		var overridesText string
		if err := rows.Scan(
			&entry.ID,
			&entry.TenantID,
			&entry.Name,
			&entry.PathPrefix,
			&entry.TargetURL,
			&entry.TargetPathPrefix,
			&entry.AllowPrivateEgress,
			&entry.PrivateEgressCIDRs,
			&entry.SecurityEnabled,
			&entry.StatsEnabled,
			&entry.Status,
			&entry.Description,
			&entry.CreatedAt,
			&entry.UpdatedAt,
			&overridesText,
		); err != nil {
			return nil, err
		}
		entry.EgressOverrides = parseStoredEgressOverrides(overridesText)
		entries = append(entries, entry)
	}
	return entries, nil
}

func (r *ReverseProxyRouteRepository) Create(ctx context.Context, entry *ReverseProxyRoute) error {
	if entry.ID == "" {
		entry.ID = "rpr_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO reverse_proxy_routes (
			id, tenant_id, name, path_prefix, target_url, target_path_prefix,
			allow_private_egress, private_egress_cidrs,
			security_enabled, stats_enabled, status, description, egress_overrides
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)
		RETURNING created_at, updated_at
	`
	overridesJSON, _ := json.Marshal(entry.EgressOverrides)

	err := r.db.QueryRow(ctx, query,
		entry.ID,
		entry.TenantID,
		entry.Name,
		entry.PathPrefix,
		entry.TargetURL,
		entry.TargetPathPrefix,
		entry.AllowPrivateEgress,
		entry.PrivateEgressCIDRs,
		entry.SecurityEnabled,
		entry.StatsEnabled,
		entry.Status,
		entry.Description,
		string(overridesJSON),
	).Scan(&entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy route: %w", err)
	}
	return nil
}

func (r *ReverseProxyRouteRepository) Update(ctx context.Context, entry *ReverseProxyRoute) error {
	query := `
		UPDATE reverse_proxy_routes
		SET name = $3,
		    path_prefix = $4,
		    target_url = $5,
		    target_path_prefix = $6,
		    allow_private_egress = $7,
		    private_egress_cidrs = $8,
		    security_enabled = $9,
		    stats_enabled = $10,
		    status = $11,
		    description = $12,
		    egress_overrides = $13::jsonb,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
	`
	overridesJSON, _ := json.Marshal(entry.EgressOverrides)

	result, err := r.db.Exec(ctx, query,
		entry.TenantID,
		entry.ID,
		entry.Name,
		entry.PathPrefix,
		entry.TargetURL,
		entry.TargetPathPrefix,
		entry.AllowPrivateEgress,
		entry.PrivateEgressCIDRs,
		entry.SecurityEnabled,
		entry.StatsEnabled,
		entry.Status,
		entry.Description,
		string(overridesJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to update reverse proxy route: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("reverse proxy route not found")
	}
	return nil
}

func (r *ReverseProxyRouteRepository) Delete(ctx context.Context, tenantID, id string) error {
	query := `DELETE FROM reverse_proxy_routes WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.Exec(ctx, query, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed to delete reverse proxy route: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("reverse proxy route not found")
	}
	return nil
}
