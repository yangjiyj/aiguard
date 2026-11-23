package fpclean

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type fakeDB struct {
	tags []pgconn.CommandTag // 依次返回
	sql  []string
	args [][]any
}

func (f *fakeDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.sql = append(f.sql, sql)
	f.args = append(f.args, args)
	if len(f.tags) == 0 {
		return pgconn.NewCommandTag("DELETE 0"), nil
	}
	tag := f.tags[0]
	f.tags = f.tags[1:]
	return tag, nil
}

func TestRunOnceBatchesUntilDrained(t *testing.T) {
	db := &fakeDB{tags: []pgconn.CommandTag{
		pgconn.NewCommandTag("DELETE 5000"), // 旧版本批 1（打满 → 继续）
		pgconn.NewCommandTag("DELETE 10"),   // 旧版本批 2（未打满 → 停）
		pgconn.NewCommandTag("DELETE 3"),    // 过期批 1（未打满 → 停）
	}}
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	r := NewRunner(db, Config{
		Interval:  time.Hour,
		Retention: 30 * 24 * time.Hour,
		BatchSize: 5000,
		Now:       func() time.Time { return now },
	})
	n, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 5013 {
		t.Fatalf("总删除数 = %d, want 5013", n)
	}
	if len(db.sql) != 3 {
		t.Fatalf("应执行 3 条删除, got %d", len(db.sql))
	}
	if !strings.Contains(db.sql[0], "rule_pack_version <> c.rule_pack_version") {
		t.Fatalf("前两条应为旧版本删除, sql=%s", db.sql[0])
	}
	if !strings.Contains(db.sql[2], "last_seen_at < $1") {
		t.Fatalf("第三条应为过期删除, sql=%s", db.sql[2])
	}
	cutoff := db.args[2][0].(time.Time)
	if !cutoff.Equal(now.Add(-30 * 24 * time.Hour)) {
		t.Fatalf("cutoff = %v", cutoff)
	}
	if db.args[2][1].(int) != 5000 {
		t.Fatalf("batch 参数 = %v", db.args[2][1])
	}
}

func TestRunDisabledWhenIntervalZero(t *testing.T) {
	db := &fakeDB{}
	r := NewRunner(db, Config{Interval: 0})
	r.Run(context.Background()) // interval<=0 → 立即返回，不触碰 DB
	if len(db.sql) != 0 {
		t.Fatal("禁用时不得执行删除")
	}
}
