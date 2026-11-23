package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 泄露溯源只检索助手回复：Role 过滤要在 SQL 里生效，并且仍受租户隔离约束。
func TestContentLogSearchPageRoleFilterPostgres(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_role_%d", suffix)
	otherTenant := fmt.Sprintf("tenant_role_other_%d", suffix)
	t.Cleanup(func() {
		for _, tenant := range []string{tenantID, otherTenant} {
			for _, stmt := range []string{
				"DELETE FROM content_logs WHERE tenant_id = $1",
				"DELETE FROM request_logs WHERE tenant_id = $1",
				"DELETE FROM tenants WHERE id = $1",
			} {
				if _, err := db.Exec(ctx, stmt, tenant); err != nil {
					t.Logf("cleanup %q: %v", stmt, err)
				}
			}
		}
		db.Close()
	})

	now := time.Now().UTC()
	phrase := fmt.Sprintf("泄露溯源角色过滤测试短语%d", suffix)
	for _, tenant := range []string{tenantID, otherTenant} {
		if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, tenant); err != nil {
			t.Fatalf("insert tenant: %v", err)
		}
	}
	insert := func(tenant, requestID, role string) {
		t.Helper()
		logID := "log_" + requestID
		if _, err := db.Exec(ctx, `INSERT INTO request_logs (id, request_id, tenant_id, environment_scope, created_at) VALUES ($1, $2, $3, 'customer', $4)`,
			logID, requestID, tenant, now); err != nil {
			t.Fatalf("insert request log: %v", err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO content_logs (request_id, tenant_id, session_id, role, content, environment_scope, created_at) VALUES ($1, $2, '', $3, $4, 'customer', $5)`,
			logID, tenant, role, "回答里有"+phrase+"这句话", now); err != nil {
			t.Fatalf("insert content log: %v", err)
		}
	}
	insert(tenantID, fmt.Sprintf("req_user_%d", suffix), "user")
	insert(tenantID, fmt.Sprintf("req_assistant_%d", suffix), "assistant")
	insert(otherTenant, fmt.Sprintf("req_other_%d", suffix), "assistant")

	repo := NewContentLogRepository(db)
	search := func(role string) []ContentLog {
		t.Helper()
		logs, _, err := repo.SearchPage(ctx, ContentLogSearchFilter{
			TenantID: tenantID, EnvironmentScope: "customer", Keyword: phrase, Role: role,
			StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour), Limit: 100, SkipTotal: true,
		})
		if err != nil {
			t.Fatalf("search role=%q: %v", role, err)
		}
		return logs
	}
	if got := search(""); len(got) != 2 {
		t.Fatalf("no role filter: got %d rows, want user+assistant of own tenant", len(got))
	}
	got := search("assistant")
	if len(got) != 1 || got[0].Role != "assistant" || got[0].RequestID != fmt.Sprintf("req_assistant_%d", suffix) {
		t.Fatalf("assistant filter: %+v", got)
	}
	if got := search("system"); len(got) != 2 {
		t.Fatalf("unknown role must be ignored, got %d", len(got))
	}
}
