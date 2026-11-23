package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func t2NewExec(t *testing.T) *Exec {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatalf("NewExec: %v", err)
	}
	t.Cleanup(x.Close)
	return x
}

func TestT2ReadOnlyRejectsInsert(t *testing.T) {
	x := t2NewExec(t)
	_, err := x.Query(context.Background(), "INSERT INTO request_logs DEFAULT VALUES")
	if err == nil {
		t.Fatal("只读事务里 INSERT 应该报错")
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "25006" {
		t.Fatalf("期望 25006 read_only_sql_transaction，得到 %v", err)
	}
}

func TestT2StatementTimeout(t *testing.T) {
	x := t2NewExec(t)
	start := time.Now()
	_, err := x.Query(context.Background(), "SELECT pg_sleep(6)")
	el := time.Since(start)
	if err == nil {
		t.Fatal("pg_sleep(6) 应该超时报错")
	}
	if el >= 6*time.Second {
		t.Fatalf("应在 6 秒内返回，实际 %v", el)
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "57014" {
		t.Fatalf("期望 57014 超时错误，得到 %v", err)
	}
}

func TestT2AcquirePerTenant(t *testing.T) {
	x := t2NewExec(t)
	ctx := context.Background()
	rel1, ok := x.Acquire(ctx, "t2-a")
	if !ok {
		t.Fatal("第一次 Acquire 应成功")
	}
	if _, ok := x.Acquire(ctx, "t2-a"); ok {
		t.Fatal("同租户第二次 Acquire 应失败")
	}
	rel2, ok := x.Acquire(ctx, "t2-b")
	if !ok {
		t.Fatal("不同租户应互不影响")
	}
	rel2()
	rel1()
	rel1() // 重复释放不应 panic
	rel3, ok := x.Acquire(ctx, "t2-a")
	if !ok {
		t.Fatal("释放后应可再次获取")
	}
	rel3()
}

func TestT2JSONSerializable(t *testing.T) {
	x := t2NewExec(t)
	rows, err := x.Query(context.Background(),
		`SELECT 12.50::numeric AS n, 'NaN'::numeric AS nan, TIMESTAMPTZ '2026-10-24 10:00:00+08' AS ts,
		 '8f14e45f-ceea-467a-9575-8d8d3c1b2a11'::uuid AS u, '{"a":1}'::jsonb AS j, 7::bigint AS i,
		 NULL::text AS z, ARRAY[1,2]::int[] AS arr, DATE '2026-10-24' AS d`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	r := rows[0]
	if f, ok := r["n"].(float64); !ok || f != 12.5 {
		t.Fatalf("numeric 应转 float64 12.5，得到 %#v", r["n"])
	}
	if s, ok := r["nan"].(string); !ok || s != "NaN" {
		t.Fatalf("NaN 应转字符串，得到 %#v", r["nan"])
	}
	if s, ok := r["ts"].(string); !ok || s != "2026-10-24T02:00:00Z" {
		t.Fatalf("时间应为 RFC3339 UTC，得到 %#v", r["ts"])
	}
	if s, ok := r["u"].(string); !ok || s != "8f14e45f-ceea-467a-9575-8d8d3c1b2a11" {
		t.Fatalf("uuid 应为字符串，得到 %#v", r["u"])
	}
	t.Log(string(b))
}

func TestT2RowLimit500(t *testing.T) {
	x := t2NewExec(t)
	rows, err := x.Query(context.Background(), "SELECT g FROM generate_series(1, 1000) g")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 500 {
		t.Fatalf("应限制 500 行，得到 %d", len(rows))
	}
}

func TestT2Busy(t *testing.T) {
	x := t2NewExec(t)
	busy, reason := x.Busy(context.Background())
	t.Logf("busy=%v reason=%q", busy, reason)
}

// t2BusyLoad 用非诊断 application_name 的独立连接池发起负载。
func t2BusyLoad(t *testing.T, conns int) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("DIAG_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = int32(conns)
	cfg.ConnConfig.RuntimeParams["application_name"] = "t2-busy-load"
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func t2SetBusyThresholds(t *testing.T) {
	ol, oc, ok := execBusyLongSeconds, execBusyLongCount, execBusyLockSeconds
	execBusyLongSeconds, execBusyLockSeconds = 1, 1
	t.Cleanup(func() { execBusyLongSeconds, execBusyLongCount, execBusyLockSeconds = ol, oc, ok })
}

func TestT2BusyLongQueries(t *testing.T) {
	x := t2NewExec(t)
	if busy, why := x.Busy(context.Background()); busy {
		t.Skipf("测试库基线已繁忙: %s", why)
	}
	t2SetBusyThresholds(t)
	load := t2BusyLoad(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := func(n int) {
		for i := 0; i < n; i++ {
			go func() { _, _ = load.Exec(ctx, "SELECT pg_sleep(8)") }()
		}
	}
	run(1)
	time.Sleep(2500 * time.Millisecond)
	if busy, why := x.Busy(context.Background()); busy {
		t.Fatalf("1 条长查询不应繁忙: %s", why)
	}
	run(2)
	time.Sleep(2500 * time.Millisecond)
	if busy, _ := x.Busy(context.Background()); !busy {
		t.Fatal("3 条长查询应繁忙")
	}
}

func TestT2BusyLockWait(t *testing.T) {
	x := t2NewExec(t)
	if busy, why := x.Busy(context.Background()); busy {
		t.Skipf("测试库基线已繁忙: %s", why)
	}
	t2SetBusyThresholds(t)
	execBusyLongCount = 100 // 只验证锁等待这一条
	load := t2BusyLoad(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := load.Exec(ctx, "CREATE TABLE IF NOT EXISTS t2_busy_lock (id int)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = load.Exec(context.Background(), "DROP TABLE IF EXISTS t2_busy_lock") })
	holder, err := load.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(ctx, "LOCK TABLE t2_busy_lock IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = load.Exec(ctx, "SELECT count(*) FROM t2_busy_lock") }()
	time.Sleep(2500 * time.Millisecond)
	if busy, _ := x.Busy(context.Background()); !busy {
		t.Fatal("有查询等锁超过阈值应繁忙")
	}
}
