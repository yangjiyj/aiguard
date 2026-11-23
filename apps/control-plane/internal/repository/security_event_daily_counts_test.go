package repository

import (
	"fmt"
	"testing"
	"time"
)

// 集成测试(需 CONTENT_LOGS_TEST_DATABASE_URL):按「租户×日×维度」的分组计数,
// 维度=COALESCE(matched_summary 顶层 category, findings[0].rule_id)。
func TestCountAlertableDailyGroupsByDimension(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM security_events WHERE tenant_id = $1", tenantID)
	})

	now := time.Now().UTC()
	requestID := fmt.Sprintf("req_daily_cnt_%d", now.UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'anthropic_messages', 'success', $6)
	`, requestID, requestID, tenantID, projectID, userID, now); err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	insert := func(id, severity, matched string) {
		if _, err := db.Exec(ctx, `
			INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, action_taken, matched_summary, created_at)
			VALUES ($1, $2, $3, $4, $5, 'security_check', $6, 'security_audit_only', $7::jsonb, $8)
		`, id, requestID, tenantID, projectID, userID, severity, matched, now); err != nil {
			t.Fatalf("insert security event %s: %v", id, err)
		}
	}
	sfx := now.UnixNano()
	// 结构化主导 rule_id 优先，旧顶层 category 仅供无 findings 的历史事件兜底。
	insert(fmt.Sprintf("se_cat1_%d", sfx), "high", `{"category":"cat_db","findings":[{"rule_id":"rule_ignored"}]}`)
	insert(fmt.Sprintf("se_cat2_%d", sfx), "critical", `{"category":"cat_db"}`)
	// 无顶层 category → 退 findings[0].rule_id。
	insert(fmt.Sprintf("se_rule_%d", sfx), "high", `{"findings":[{"rule_id":"rule_db"}]}`)
	// medium 不计入(收件箱门槛默认 high/critical)。
	insert(fmt.Sprintf("se_med_%d", sfx), "medium", `{"category":"cat_db"}`)

	repo := NewSecurityEventRepository(db)
	from := now.Truncate(24 * time.Hour)
	counts, err := repo.CountAlertableDaily(ctx, []string{tenantID}, from, from.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CountAlertableDaily: %v", err)
	}
	got := map[string]int{}
	day := now.Format("2006-01-02")
	for _, c := range counts {
		if c.TenantID != tenantID || c.Day != day {
			t.Fatalf("unexpected tenant/day in %+v", c)
		}
		got[c.Dimension] = c.Count
	}
	if got["cat_db"] != 1 || got["rule_ignored"] != 1 {
		t.Fatalf("expected cat_db=1 and dominant rule_ignored=1 (medium excluded), got %+v", got)
	}
	if got["rule_db"] != 1 {
		t.Fatalf("expected rule_db=1 (fallback to findings[0].rule_id), got %+v", got)
	}

	// 空租户集合 → 空结果不报错。
	empty, err := repo.CountAlertableDaily(ctx, nil, from, from.Add(24*time.Hour))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty tenant set should be a no-op, got %v err=%v", empty, err)
	}
}
