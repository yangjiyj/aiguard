package billing

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// BudgetOutcomeExhausted 等是被预算断流拒绝的请求写入 request_logs.billing_outcome 的取值。
const (
	BudgetOutcomeExhausted   = "budget_exhausted"
	BudgetOutcomeUnpriced    = "budget_unpriced"
	BudgetOutcomeUnavailable = "budget_unavailable"
)

// CountBudgetBlockedToday 统计今天（按 timezone 的自然日）因预算用尽被拒的请求数；tenantID 为空统计全部租户。
func (s *Store) CountBudgetBlockedToday(ctx context.Context, tenantID string, now time.Time, timezone string) (int64, error) {
	loc, err := time.LoadLocation(strings.TrimSpace(timezone))
	if err != nil {
		loc, _ = time.LoadLocation("Asia/Shanghai")
	}
	local := now.In(loc)
	dayStart := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc).UTC()
	var count int64
	err = s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM request_logs
		WHERE billing_outcome IN ('budget_exhausted', 'budget_unpriced', 'budget_unavailable')
		  AND created_at >= $2 AND ($1 = '' OR tenant_id = $1)
	`, tenantID, dayStart).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count budget blocked requests: %w", err)
	}
	return count, nil
}
