package handler

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DBProxyUsageRecorder records 免Token代理 usage into proxy_usage_daily (阶段二 2.5).
type DBProxyUsageRecorder struct {
	db *pgxpool.Pool
}

// NewDBProxyUsageRecorder constructs a DB-backed proxy usage recorder.
func NewDBProxyUsageRecorder(db *pgxpool.Pool) *DBProxyUsageRecorder {
	return &DBProxyUsageRecorder{db: db}
}

// RecordProxyUsage upserts a daily usage row for the given model.
func (r *DBProxyUsageRecorder) RecordProxyUsage(ctx context.Context, modelID string, inputTokens, outputTokens int) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("proxy usage recorder not configured")
	}
	if modelID == "" {
		return nil
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO proxy_usage_daily (date, model_id, request_count, input_tokens, output_tokens)
         VALUES (CURRENT_DATE, $1, 1, $2, $3)
         ON CONFLICT (date, model_id) DO UPDATE SET
           request_count = proxy_usage_daily.request_count + 1,
           input_tokens  = proxy_usage_daily.input_tokens + EXCLUDED.input_tokens,
           output_tokens = proxy_usage_daily.output_tokens + EXCLUDED.output_tokens`,
		modelID, inputTokens, outputTokens,
	)
	if err != nil {
		return fmt.Errorf("record proxy usage: %w", err)
	}
	return nil
}
