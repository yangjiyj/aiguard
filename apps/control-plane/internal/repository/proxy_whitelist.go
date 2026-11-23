package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProxyWhitelist struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	HostPattern  string    `json:"host_pattern"`
	Port         int       `json:"port"`
	AuditEnabled bool      `json:"audit_enabled"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ProxyWhitelistRepository struct {
	db *pgxpool.Pool
}

func NewProxyWhitelistRepository(db *pgxpool.Pool) *ProxyWhitelistRepository {
	return &ProxyWhitelistRepository{db: db}
}

func (r *ProxyWhitelistRepository) GetByID(ctx context.Context, tenantID, id string) (*ProxyWhitelist, error) {
	query := `
		SELECT id, tenant_id, host_pattern, port, audit_enabled, description, created_at, updated_at
		FROM proxy_whitelist
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.db.QueryRow(ctx, query, tenantID, id)
	var entry ProxyWhitelist
	err := row.Scan(&entry.ID, &entry.TenantID, &entry.HostPattern, &entry.Port, &entry.AuditEnabled, &entry.Description, &entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get proxy whitelist entry: %w", err)
	}
	return &entry, nil
}

func (r *ProxyWhitelistRepository) List(ctx context.Context, tenantID string) ([]ProxyWhitelist, error) {
	query := `
		SELECT id, tenant_id, host_pattern, port, audit_enabled, description, created_at, updated_at
		FROM proxy_whitelist
		WHERE tenant_id = $1
		ORDER BY host_pattern
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list proxy whitelist entries: %w", err)
	}
	defer rows.Close()

	var entries []ProxyWhitelist
	for rows.Next() {
		var entry ProxyWhitelist
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.HostPattern, &entry.Port, &entry.AuditEnabled, &entry.Description, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (r *ProxyWhitelistRepository) ListActive(ctx context.Context, tenantID string) ([]ProxyWhitelist, error) {
	query := `
		SELECT id, tenant_id, host_pattern, port, audit_enabled, description, created_at, updated_at
		FROM proxy_whitelist
		WHERE tenant_id = $1 AND audit_enabled = true
		ORDER BY host_pattern
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active proxy whitelist entries: %w", err)
	}
	defer rows.Close()

	var entries []ProxyWhitelist
	for rows.Next() {
		var entry ProxyWhitelist
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.HostPattern, &entry.Port, &entry.AuditEnabled, &entry.Description, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (r *ProxyWhitelistRepository) Create(ctx context.Context, entry *ProxyWhitelist) error {
	if entry.ID == "" {
		entry.ID = "pw_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO proxy_whitelist (id, tenant_id, host_pattern, port, audit_enabled, description)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		entry.ID, entry.TenantID, entry.HostPattern, entry.Port, entry.AuditEnabled, entry.Description,
	).Scan(&entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create proxy whitelist entry: %w", err)
	}
	return nil
}

func (r *ProxyWhitelistRepository) Update(ctx context.Context, entry *ProxyWhitelist) error {
	query := `
		UPDATE proxy_whitelist
		SET host_pattern = $3, port = $4, audit_enabled = $5, description = $6, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
	`
	result, err := r.db.Exec(ctx, query, entry.TenantID, entry.ID, entry.HostPattern, entry.Port, entry.AuditEnabled, entry.Description)
	if err != nil {
		return fmt.Errorf("failed to update proxy whitelist entry: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("proxy whitelist entry not found")
	}
	return nil
}

func (r *ProxyWhitelistRepository) Delete(ctx context.Context, tenantID, id string) error {
	query := `DELETE FROM proxy_whitelist WHERE tenant_id = $1 AND id = $2`
	result, err := r.db.Exec(ctx, query, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed to delete proxy whitelist entry: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("proxy whitelist entry not found")
	}
	return nil
}