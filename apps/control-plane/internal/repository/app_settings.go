package repository

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AppSettingsRepository struct{ db *pgxpool.Pool }

func NewAppSettingsRepository(db *pgxpool.Pool) *AppSettingsRepository {
	return &AppSettingsRepository{db: db}
}

// GetMany 返回给定 key 的现值；缺失的 key 不在返回 map 中。
func (r *AppSettingsRepository) GetMany(ctx context.Context, keys []string) (map[string]string, error) {
	rows, err := r.db.Query(ctx, `SELECT key, value FROM app_settings WHERE key = ANY($1)`, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (r *AppSettingsRepository) Set(ctx context.Context, key, value string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, key, value)
	return err
}
