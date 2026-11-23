package repository

import (
	"fmt"
	"testing"
	"time"
)

// 按请求读正文时，请求条件要以 request_logs.id 下推进 content_logs 视图；改写只加过滤，
// 结果必须与原来一致：日志编号和外部请求编号两种写法都能读到，时间窗口和作用域照旧生效。
func TestContentLogRequestReadsKeepBothIdentifierForms(t *testing.T) {
	db, ctx, tenantID, _, projectID := setupAuditStatsRegressionFixture(t)
	suffix := time.Now().UnixNano()
	now := time.Now().UTC()
	logX, extX := fmt.Sprintf("log_pushdown_x_%d", suffix), fmt.Sprintf("ext_pushdown_x_%d", suffix)
	logY, extY := fmt.Sprintf("log_pushdown_y_%d", suffix), fmt.Sprintf("ext_pushdown_y_%d", suffix)
	for _, row := range [][2]string{{logX, extX}, {logY, extY}} {
		if _, err := db.Exec(ctx, `INSERT INTO request_logs (id, request_id, tenant_id, project_id, endpoint_type, request_status, environment_scope, created_at)
			VALUES ($1, $2, $3, $4, 'chat', 'success', 'customer', $5)`, row[0], row[1], tenantID, projectID, now); err != nil {
			t.Fatal(err)
		}
		for i, role := range []string{"user", "assistant"} {
			if _, err := db.Exec(ctx, `INSERT INTO content_logs (id, request_id, tenant_id, session_id, role, content, tokens, environment_scope, created_at)
				VALUES ($1, $2, $3, 's', $4, $5, 1, 'customer', $6)`, fmt.Sprintf("%s_%d", row[0], i), row[0], tenantID, role, role+" of "+row[1], now.Add(time.Duration(i)*time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
	repo := NewContentLogRepository(db)
	for _, id := range []string{logX, extX} {
		logs, err := repo.ListByRequest(ctx, tenantID, id)
		if err != nil || len(logs) != 2 || logs[0].RequestID != extX || logs[0].Role != "user" {
			t.Fatalf("ListByRequest(%s) = %+v, %v", id, logs, err)
		}
		scoped, err := repo.ListByRequestScoped(ctx, tenantID, id, now.Add(-time.Hour), now.Add(time.Hour), "customer")
		if err != nil || len(scoped) != 2 || scoped[1].Role != "assistant" {
			t.Fatalf("ListByRequestScoped(%s) = %+v, %v", id, scoped, err)
		}
	}
	if old, err := repo.ListByRequestScoped(ctx, tenantID, extX, now.Add(-48*time.Hour), now.Add(-24*time.Hour), "customer"); err != nil || len(old) != 0 {
		t.Fatalf("window must still apply: %+v, %v", old, err)
	}
	if other, err := repo.ListByRequestScoped(ctx, "tenant_pushdown_other", extX, now.Add(-time.Hour), now.Add(time.Hour), "customer"); err != nil || len(other) != 0 {
		t.Fatalf("tenant must still apply: %+v, %v", other, err)
	}
	both, err := repo.ListByRequests(ctx, tenantID, []string{extX, extY})
	if err != nil || len(both) != 4 {
		t.Fatalf("ListByRequests = %+v, %v", both, err)
	}
	scopedBoth, err := repo.ListByRequestsScoped(ctx, tenantID, []string{extX, extY}, now.Add(-time.Hour), now.Add(time.Hour), "customer")
	if err != nil || len(scopedBoth) != 4 {
		t.Fatalf("ListByRequestsScoped = %+v, %v", scopedBoth, err)
	}
}
