package repository

// 语义检测配置的并发控制：SetMultipleIfVersion 必须是真正的原子「比较并交换」。
// 真实 Postgres（CONTENT_LOGS_TEST_DATABASE_URL，未设置时跳过）。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupSettingsDB(t *testing.T) (*SystemRepository, []string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	keys := []string{"cas_a_" + suffix, "cas_b_" + suffix}
	t.Cleanup(func() { db.Exec(context.Background(), `DELETE FROM system_settings WHERE key = ANY($1)`, keys) })
	return NewSystemRepository(db), keys
}

func versionOfTest(m map[string]time.Time) string {
	s := ""
	for _, k := range []string{"a", "b"} {
		_ = k
	}
	// 与键名无关的稳定摘要：按插入顺序不可靠，所以拼接排序后的时间戳。
	var parts []string
	for _, v := range m {
		parts = append(parts, v.UTC().Format(time.RFC3339Nano))
	}
	for i := 0; i < len(parts); i++ {
		for j := i + 1; j < len(parts); j++ {
			if parts[j] < parts[i] {
				parts[i], parts[j] = parts[j], parts[i]
			}
		}
	}
	for _, p := range parts {
		s += p + "|"
	}
	return s
}

func readVersion(t *testing.T, r *SystemRepository, keys []string) string {
	t.Helper()
	m, err := r.GetUpdatedAt(context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}
	return versionOfTest(m)
}

func TestSetMultipleIfVersionRejectsAStaleVersionAndWritesNothing(t *testing.T) {
	r, keys := setupSettingsDB(t)
	ctx := context.Background()
	v0 := readVersion(t, r, keys) // 键都还不存在：空版本
	if err := r.SetMultipleIfVersion(ctx, keys, v0, versionOfTest, map[string]string{keys[0]: "first"}); err != nil {
		t.Fatalf("版本一致时应成功：%v", err)
	}
	err := r.SetMultipleIfVersion(ctx, keys, v0, versionOfTest, map[string]string{keys[0]: "second", keys[1]: "x"})
	if !errors.Is(err, ErrSystemSettingsVersionConflict) {
		t.Fatalf("带旧版本必须冲突：%v", err)
	}
	got, _ := r.Get(ctx, keys[0])
	other, _ := r.Get(ctx, keys[1])
	if got == nil || got.Value != "first" {
		t.Fatalf("冲突时不得覆盖先保存的值：%+v", got)
	}
	if other != nil && other.Value != "" {
		t.Fatalf("冲突时不得写入任何键：%+v", other)
	}
}

// 只改了「别的键」的并发写入也必须能被发现：A 改 key0、B 改 key1，B 带的是 A 保存之前的版本 => 冲突。
func TestSetMultipleIfVersionDetectsConcurrentWritesToDifferentKeys(t *testing.T) {
	r, keys := setupSettingsDB(t)
	ctx := context.Background()
	v0 := readVersion(t, r, keys)
	if err := r.SetMultipleIfVersion(ctx, keys, v0, versionOfTest, map[string]string{keys[0]: "a"}); err != nil {
		t.Fatal(err)
	}
	err := r.SetMultipleIfVersion(ctx, keys, v0, versionOfTest, map[string]string{keys[1]: "b"})
	if !errors.Is(err, ErrSystemSettingsVersionConflict) {
		t.Fatalf("改不同键的并发写入也应冲突：%v", err)
	}
}

// 真正的并发：多个写入者拿到同一个版本同时提交，恰好一个成功，其余全部冲突（行锁保证了比较与写入的原子性）。
func TestSetMultipleIfVersionOnlyOneConcurrentWriterWins(t *testing.T) {
	r, keys := setupSettingsDB(t)
	ctx := context.Background()
	v0 := readVersion(t, r, keys)
	const writers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, conflicts := 0, 0
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := r.SetMultipleIfVersion(ctx, keys, v0, versionOfTest, map[string]string{keys[0]: fmt.Sprintf("w%d", i)})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrSystemSettingsVersionConflict):
				conflicts++
			default:
				t.Errorf("意外错误：%v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if wins != 1 || conflicts != writers-1 {
		t.Fatalf("同一版本的并发提交应恰好一个成功：wins=%d conflicts=%d", wins, conflicts)
	}
}
