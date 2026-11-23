package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NotifyChannel represents a row in the notify_channels table.
type NotifyChannel struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	Type       string         `json:"type"` // email | webhook | dingtalk | wecom | feishu
	Name       string         `json:"name"`
	ConfigJSON map[string]any `json:"config_json"`
	Enabled    bool           `json:"enabled"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// NotifyChannelsRepository handles notify_channels database operations.
type NotifyChannelsRepository struct {
	db *pgxpool.Pool
}

// NewNotifyChannelsRepository creates a new NotifyChannelsRepository.
func NewNotifyChannelsRepository(db *pgxpool.Pool) *NotifyChannelsRepository {
	return &NotifyChannelsRepository{db: db}
}

// Create inserts a new notify channel.
func (r *NotifyChannelsRepository) Create(ctx context.Context, ch *NotifyChannel) error {
	cfgBytes, err := json.Marshal(ch.ConfigJSON)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = r.db.Exec(ctx, `
		INSERT INTO notify_channels (id, tenant_id, type, name, config_json, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, ch.ID, ch.TenantID, ch.Type, ch.Name, string(cfgBytes), ch.Enabled, now, now)
	return err
}

// Update updates name, config_json, and enabled for the given channel.
// Update 修改告警渠道。WHERE 带 tenant_id 防跨租户 IDOR（改指他租 webhook）。
func (r *NotifyChannelsRepository) Update(ctx context.Context, tenantID, id, name string, configJSON map[string]any, enabled bool) error {
	cfgBytes, err := json.Marshal(configJSON)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
		UPDATE notify_channels
		SET name = $1, config_json = $2, enabled = $3, updated_at = $4
		WHERE id = $5 AND tenant_id = $6
	`, name, string(cfgBytes), enabled, time.Now().UTC(), id, tenantID)
	return err
}

// Delete removes a notify channel by ID（带 tenant_id 防跨租户删除）。
func (r *NotifyChannelsRepository) Delete(ctx context.Context, tenantID, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM notify_channels WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

// Get returns a single notify channel by ID.
func (r *NotifyChannelsRepository) Get(ctx context.Context, id string) (*NotifyChannel, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, type, name, config_json, enabled, created_at, updated_at
		FROM notify_channels
		WHERE id = $1
	`, id)
	return scanNotifyChannel(row)
}

// ListByTenant returns all channels for the tenant.
func (r *NotifyChannelsRepository) GetForTenant(ctx context.Context, tenantID, id string) (*NotifyChannel, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, type, name, config_json, enabled, created_at, updated_at
		FROM notify_channels
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	return scanNotifyChannel(row)
}

func (r *NotifyChannelsRepository) ListByTenant(ctx context.Context, tenantID string) ([]*NotifyChannel, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, type, name, config_json, enabled, created_at, updated_at
		FROM notify_channels
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotifyChannels(rows)
}

// ListEnabled returns only enabled channels for the tenant.
func (r *NotifyChannelsRepository) ListEnabled(ctx context.Context, tenantID string) ([]*NotifyChannel, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, type, name, config_json, enabled, created_at, updated_at
		FROM notify_channels
		WHERE tenant_id = $1 AND enabled = true
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotifyChannels(rows)
}

type notifyChannelScanner interface {
	Scan(dest ...any) error
}

func scanNotifyChannel(row notifyChannelScanner) (*NotifyChannel, error) {
	var ch NotifyChannel
	var cfgStr string
	if err := row.Scan(
		&ch.ID, &ch.TenantID, &ch.Type, &ch.Name,
		&cfgStr, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if cfgStr != "" {
		_ = json.Unmarshal([]byte(cfgStr), &ch.ConfigJSON)
	}
	return &ch, nil
}

func scanNotifyChannels(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]*NotifyChannel, error) {
	var out []*NotifyChannel
	for rows.Next() {
		var ch NotifyChannel
		var cfgStr string
		if err := rows.Scan(
			&ch.ID, &ch.TenantID, &ch.Type, &ch.Name,
			&cfgStr, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if cfgStr != "" {
			_ = json.Unmarshal([]byte(cfgStr), &ch.ConfigJSON)
		}
		out = append(out, &ch)
	}
	return out, rows.Err()
}
