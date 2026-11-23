package repository

// 2.9.22：租户级防护项设置（迁移 999 protection_settings）。
// 缺行 = 注册表默认动作；注册表里已不存在的键读出时丢弃。

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// ProtectionSettingRow 是一条已保存的防护项设置。
type ProtectionSettingRow struct {
	Key       string         `json:"key"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	UpdatedBy string         `json:"updated_by,omitempty"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty"`
}

type ProtectionSettingsRepository struct {
	db *pgxpool.Pool
}

func NewProtectionSettingsRepository(db *pgxpool.Pool) *ProtectionSettingsRepository {
	return &ProtectionSettingsRepository{db: db}
}

// StoredRows 返回租户已保存的行（仅注册表里仍存在的键），按注册表顺序。
func (r *ProtectionSettingsRepository) StoredRows(ctx context.Context, tenantID string) ([]ProtectionSettingRow, error) {
	rs, err := r.db.Query(ctx, `SELECT item_key, action, params_json, updated_by, updated_at FROM protection_settings WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	stored := map[string]ProtectionSettingRow{}
	for rs.Next() {
		var row ProtectionSettingRow
		var raw []byte
		var at time.Time
		if err := rs.Scan(&row.Key, &row.Action, &raw, &row.UpdatedBy, &at); err != nil {
			return nil, err
		}
		row.Params = map[string]any{}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &row.Params); err != nil || row.Params == nil {
				row.Params = map[string]any{}
			}
		}
		row.UpdatedAt = &at
		stored[row.Key] = row
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	out := make([]ProtectionSettingRow, 0, len(stored))
	for _, item := range protection.All() {
		if row, ok := stored[item.Key]; ok {
			out = append(out, row)
		}
	}
	return out, nil
}

// Settings 返回可直接交给网关的键 → 设置映射。
func (r *ProtectionSettingsRepository) Settings(ctx context.Context, tenantID string) (protection.Settings, error) {
	rows, err := r.StoredRows(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(protection.Settings, len(rows))
	for _, row := range rows {
		out[row.Key] = protection.Setting{Action: protection.Action(row.Action), Params: row.Params}
	}
	return out, nil
}

// Upsert 在一个事务内写入多项，返回变更前的旧值（缺行的键不在返回里），供审计留痕。
func (r *ProtectionSettingsRepository) Upsert(ctx context.Context, tenantID, actor string, in map[string]protection.Setting) (map[string]protection.Setting, error) {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 同一租户的写入串行化（锁种子 2922 专用于防护项设置，其他已用种子见 grep hashtextextended），避免并发更新互相覆盖、审计里的旧值失真。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 2922))`, tenantID); err != nil {
		return nil, err
	}
	before := make(map[string]protection.Setting, len(keys))
	rs, err := tx.Query(ctx, `SELECT item_key, action, params_json FROM protection_settings
		WHERE tenant_id=$1 AND item_key = ANY($2) ORDER BY item_key FOR UPDATE`, tenantID, keys)
	if err != nil {
		return nil, err
	}
	for rs.Next() {
		var key, prevAction string
		var prevRaw []byte
		if err := rs.Scan(&key, &prevAction, &prevRaw); err != nil {
			rs.Close()
			return nil, err
		}
		prev := map[string]any{}
		_ = json.Unmarshal(prevRaw, &prev)
		before[key] = protection.Setting{Action: protection.Action(prevAction), Params: prev}
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return nil, err
	}
	for _, key := range keys {
		params := in[key].Params
		if params == nil {
			params = map[string]any{}
		}
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO protection_settings (tenant_id, item_key, action, params_json, updated_by, updated_at)
			VALUES ($1,$2,$3,$4::jsonb,$5,NOW())
			ON CONFLICT (tenant_id, item_key) DO UPDATE
			  SET action=EXCLUDED.action, params_json=EXCLUDED.params_json, updated_by=EXCLUDED.updated_by, updated_at=NOW()`,
			tenantID, key, string(in[key].Action), string(raw), actor); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return before, nil
}
