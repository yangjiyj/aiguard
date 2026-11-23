package repository

import (
	"context"
	"fmt"
	"strings"
)

// PortalCallRecordsSummary 只含面向个人的总耗时与结果统计。
type PortalCallRecordsSummary struct {
	Requests         int      `json:"requests"`
	AverageLatencyMS *float64 `json:"average_latency_ms"`
	SuccessRate      *float64 `json:"success_rate"`
}

func buildPortalCallRecordsSummaryQuery(filter PortalCallRecordFilter) (string, []interface{}) {
	// 复用完整窗口计数条件及历史账号归属，不受分页游标影响。
	_, _, query, args := buildPortalCallRecordQueries(filter)
	return strings.Replace(query, "SELECT COUNT(*) FROM request_logs rl", `SELECT COUNT(*)::int,
 AVG(rl.latency_ms) FILTER (WHERE rl.latency_ms >= 0),
 COUNT(*) FILTER (WHERE rl.request_status IN ('success','security_replied'))::float8 / NULLIF(COUNT(*),0)
 FROM request_logs rl`, 1), args
}

func (r *RequestLogRepository) SummarizePortalCallRecords(ctx context.Context, filter PortalCallRecordFilter) (PortalCallRecordsSummary, error) {
	query, args := buildPortalCallRecordsSummaryQuery(filter)
	var result PortalCallRecordsSummary
	if err := r.db.QueryRow(ctx, query, args...).Scan(&result.Requests, &result.AverageLatencyMS, &result.SuccessRate); err != nil {
		return result, fmt.Errorf("读取个人调用汇总失败: %w", err)
	}
	return result, nil
}
