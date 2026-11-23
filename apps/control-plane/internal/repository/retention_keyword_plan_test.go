package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 关键字检索的计划高度依赖关键字本身（命中多少正文、走倒序还是完整匹配）。连接池里的预备语句执行
// 五次后 PostgreSQL 可能改用通用计划，按“不知道关键字”估算，常见词从 0.1 秒退化到 1 秒以上；
// 关键字检索的读事务里强制每次按实际参数规划。
func TestRetentionKeywordReadPlansWithActualParameters(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRequestLogRepository(db)
	var mode, jit string
	if err := repo.retentionKeywordRead().QueryRow(ctx, "SELECT current_setting('plan_cache_mode'), current_setting('jit')").Scan(&mode, &jit); err != nil {
		t.Fatal(err)
	}
	if mode != "force_custom_plan" || jit != "off" {
		t.Fatalf("keyword read plan_cache_mode=%q jit=%q", mode, jit)
	}
	// 只影响这次事务：普通留存读不变。
	if err := repo.retentionRead().QueryRow(ctx, "SELECT current_setting('plan_cache_mode')").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode == "force_custom_plan" {
		t.Fatalf("plain retention read must keep the default plan cache mode")
	}
}
