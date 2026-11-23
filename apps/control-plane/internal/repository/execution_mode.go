package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
)

// executionModeQuerier 是读执行模式所需的最小查询接口；连接池和事务都满足。
type executionModeQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// loadExecutionModeValues 一次查询读出 executionmode.Keys() 两个键，交给 executionmode.FromValues 判定；
// 仓储层判定执行模式都走这里，不要各自解析两个键或读部署变量。
func loadExecutionModeValues(ctx context.Context, q executionModeQuerier) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT key, value FROM system_settings WHERE key = ANY($1)`, executionmode.Keys())
	if err != nil {
		return nil, fmt.Errorf("load execution mode settings: %w", err)
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan execution mode setting: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read execution mode settings: %w", err)
	}
	return values, nil
}
