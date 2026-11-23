package backfill

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 迁移 987 之后的环境标记回填：库需完整 schema 且已应用 986/987（JJD_BACKFILL_987_TEST_DATABASE_URL）。
// 新消息行在 content_log_entries、升级前的行在 content_logs_legacy，两边都要被标记，被别的事务锁住的行要进重试表。
func TestCustomerEnvironmentScopeDedupBatchOnMigratedSchema(t *testing.T) {
	url := os.Getenv("JJD_BACKFILL_987_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JJD_BACKFILL_987_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var dedup bool
	if err = db.QueryRow(ctx, `SELECT to_regclass('content_log_entries') IS NOT NULL`).Scan(&dedup); err != nil || !dedup {
		t.Fatalf("database must have migration 987 applied: dedup=%v err=%v", dedup, err)
	}
	_, err = db.Exec(ctx, `
INSERT INTO tenants(id,name,is_test) VALUES ('bf987_t','bf987',true) ON CONFLICT DO NOTHING;
INSERT INTO migration_backfill_tasks(task_name,task_version,state)
VALUES ('customer_environment_scope_v1',1,'paused') ON CONFLICT DO NOTHING;
INSERT INTO request_logs(id,request_id,tenant_id,created_at,proxy_mode,environment_scope) VALUES
 ('bf987_a','bf987_ra','bf987_t',timestamp '2019-03-01 10:00','chat_completion','legacy-unclassified'),
 ('bf987_b','bf987_rb','bf987_t',timestamp '2019-03-01 10:01','chat_completion','legacy-unclassified');
INSERT INTO content_logs_legacy(id,request_id,tenant_id,role,content,created_at,environment_scope)
VALUES ('bf987_old','bf987_a','bf987_t','user','升级前的历史行',timestamp '2019-03-01 10:00','legacy-unclassified');
INSERT INTO content_logs(id,request_id,tenant_id,role,content,created_at,environment_scope) VALUES
 ('bf987_new','bf987_a','bf987_t','assistant','新写入的行',timestamp '2019-03-01 10:00','legacy-unclassified'),
 ('bf987_lockd','bf987_b','bf987_t','user','被锁住的行',timestamp '2019-03-01 10:01','legacy-unclassified');`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `
DELETE FROM migration_backfill_retry_rows WHERE row_id IN ('bf987_a','bf987_b');
DELETE FROM content_logs WHERE tenant_id='bf987_t';
DELETE FROM request_logs WHERE tenant_id='bf987_t';`)

	// 另一个事务锁住 bf987_b 的消息行：这一批必须跳过它并登记重试，不能阻塞也不能报错。
	holder, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if _, err = holder.Exec(ctx, `SELECT 1 FROM content_log_entries WHERE id='bf987_lockd' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}

	// 游标从测试行之前开始，模板库里的其它请求行不进入本批。
	checkpoint := time.Date(2019, 3, 1, 9, 59, 59, 0, time.UTC)
	upper := time.Date(2019, 3, 1, 10, 1, 0, 0, time.UTC)
	run := func() (scanned, updated, skipped int64) {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var cursor *time.Time
		var cursorID string
		if err = tx.QueryRow(ctx, customerEnvironmentScopeDedupBatchSQL, 10, CustomerEnvironmentScopeTask, 1, checkpoint, "", false, upper, "bf987_b").
			Scan(&scanned, &updated, &skipped, &cursor, &cursorID); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return
	}
	scanned, updated, skipped := run()
	if scanned != 2 || updated != 4 || skipped != 1 {
		t.Fatalf("first batch scanned=%d updated=%d skipped=%d; want 2 parents scanned, 2 request rows + 2 content rows updated, the locked parent retried", scanned, updated, skipped)
	}
	scope := func(table, id string) string {
		var value string
		if err := db.QueryRow(ctx, `SELECT environment_scope FROM `+table+` WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if scope("content_logs_legacy", "bf987_old") != "customer" || scope("content_log_entries", "bf987_new") != "customer" {
		t.Fatalf("both base tables must be marked customer")
	}
	if scope("content_log_entries", "bf987_lockd") != "legacy-unclassified" || scope("request_logs", "bf987_b") == "" {
		t.Fatalf("locked row must be left for retry")
	}
	if err = holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var retried int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM migration_backfill_retry_rows WHERE task_name=$1 AND row_id='bf987_b'`,
		CustomerEnvironmentScopeTask).Scan(&retried); err != nil || retried != 1 {
		t.Fatalf("locked parent must be queued for retry: rows=%d err=%v", retried, err)
	}
	var viewScope string
	if err = db.QueryRow(ctx, `SELECT string_agg(id||'='||environment_scope, ',' ORDER BY id) FROM content_logs WHERE tenant_id='bf987_t'`).Scan(&viewScope); err != nil {
		t.Fatal(err)
	}
	if viewScope != "bf987_lockd=legacy-unclassified,bf987_new=customer,bf987_old=customer" {
		t.Fatalf("view must reflect base table updates: %s", viewScope)
	}
}
