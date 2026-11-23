package handler

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
)

// SystemSettingLoader 按键读 system_settings，供文件引用处置读取器使用（2.9.22 任务 4.2）。
func SystemSettingLoader(db *pgxpool.Pool) filereference.Loader {
	if db == nil {
		return nil
	}
	return func(ctx context.Context, key string) (string, bool, error) {
		var value string
		err := db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = $1`, key).Scan(&value)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return value, true, nil
	}
}
