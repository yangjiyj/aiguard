package repository

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// 预算列算出之后数据又变了：正文被清理（保留期、标题请求清理）、留存正文置空、超出 15 分钟刷新窗口才到的
// 安全事件。触发器把相关请求的预算列置空，读路径回退原表达式；周期补算后列值重新等于原表达式。
func TestRetentionSummaryColumnsFollowLateChanges(t *testing.T) {
	db, ctx, tenantID, _, projectID := setupAuditStatsRegressionFixture(t)
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM access_content_logs WHERE tenant_id = $1`, tenantID)
	})
	suffix := time.Now().UnixNano()
	old := time.Now().UTC().Add(-3 * time.Hour)
	reverse, forward := fmt.Sprintf("late_rev_%d", suffix), fmt.Sprintf("late_fwd_%d", suffix)
	for _, row := range []struct{ id, mode string }{{reverse, ""}, {forward, "forward"}} {
		var mode any
		if row.mode != "" {
			mode = row.mode
		}
		if _, err := db.Exec(ctx, `INSERT INTO request_logs (id, request_id, tenant_id, project_id, endpoint_type, request_status, proxy_mode,
			proxy_target_host, proxy_access_type, proxy_access_type_resolved, environment_scope, created_at)
			VALUES ($1, $1, $2, $3, 'proxy', 'success', $4, 'chat.example.test', 'llm', 'llm', 'customer', $5)`, row.id, tenantID, projectID, mode, old); err != nil {
			t.Fatal(err)
		}
	}
	for i, role := range []string{"user", "assistant"} {
		if _, err := db.Exec(ctx, `INSERT INTO content_logs (id, request_id, tenant_id, session_id, role, content, tokens, environment_scope, created_at)
			VALUES ($1, $2, $3, 's', $4, $5, 1, 'customer', $6)`, fmt.Sprintf("%s_%d", reverse, i), reverse, tenantID, role, "正文 "+role, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO access_content_logs (request_id, tenant_id, request_content_redacted, response_content_redacted, environment_scope, created_at)
		VALUES ($1, $2, '请求正文', '响应正文', 'customer', $3)`, forward, tenantID, old); err != nil {
		t.Fatal(err)
	}
	repo := NewRequestLogRepository(db)
	backfill := func() {
		t.Helper()
		for {
			n, err := repo.BackfillRiskColumns(ctx, 5000)
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				return
			}
		}
	}
	matchesLive := func(stage string) {
		t.Helper()
		var stale int
		if err := db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM request_logs rl WHERE rl.tenant_id = $1 AND (
			COALESCE(rl.risk_reasons, %[1]s) IS DISTINCT FROM (%[1]s)
			OR COALESCE(rl.request_body_exists, %[2]s) IS DISTINCT FROM (%[2]s)
			OR COALESCE(rl.response_body_exists, %[3]s) IS DISTINCT FROM (%[3]s))`,
			forwardProxyRiskReasonsExpr(), forwardProxyRequestBodyExistsExpr(), forwardProxyResponseBodyExistsExpr()), tenantID).Scan(&stale); err != nil {
			t.Fatal(err)
		}
		if stale != 0 {
			t.Fatalf("%s: %d rows read stale precomputed values", stage, stale)
		}
	}
	backfill()
	matchesLive("after backfill")

	// 正文清理（保留期、标题请求清理都是删正文条目）。
	if _, err := db.Exec(ctx, `DELETE FROM content_logs WHERE request_id = $1 AND role = 'assistant'`, reverse); err != nil {
		t.Fatal(err)
	}
	matchesLive("after content prune")
	// 留存正文置空。
	if _, err := db.Exec(ctx, `UPDATE access_content_logs SET response_content_redacted = NULL WHERE request_id = $1`, forward); err != nil {
		t.Fatal(err)
	}
	matchesLive("after retained body cleared")
	// 超出 15 分钟刷新窗口才到的安全事件。
	if _, err := db.Exec(ctx, `INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, 'security_check', 'high', 'flag', '{"findings":[{"type":"secret","category":"api_key","severity":"high","rule_id":"r_key","action":"audit","redacted_evidence":"sk-***"}]}', now())`,
		fmt.Sprintf("late_event_%d", suffix), reverse, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RefreshRecentRiskColumns(ctx, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	matchesLive("after late event")
	var pending int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM request_logs WHERE tenant_id = $1 AND (risk_reasons IS NULL OR request_body_exists IS NULL OR response_body_exists IS NULL)`, tenantID).Scan(&pending); err != nil || pending == 0 {
		t.Fatalf("late changes must clear the precomputed values: pending=%d err=%v", pending, err)
	}
	backfill()
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM request_logs WHERE tenant_id = $1 AND (risk_reasons IS NULL OR request_body_exists IS NULL OR response_body_exists IS NULL)`, tenantID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("backfill must recompute cleared values: pending=%d err=%v", pending, err)
	}
	matchesLive("after recompute")
}
