// Package fpclean 周期清理 scan_fingerprints（安全三视图重构 模块 2a 清理项）：
// 删除 (rule_pack_version, engine_build) != 当前版本对 或 last_seen_at 超留存期的行。
// "当前版本对" = 表内 last_seen_at 最新一行的版本对（引擎升级后新写入即接管；
// 空表时 current CTE 为空 → 版本删除自然无行）。分批 ctid 删除避免长事务。
package fpclean

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// DB 是清理任务的最小数据库依赖（*pgxpool.Pool 满足）。
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type Config struct {
	Interval  time.Duration    // <=0 = 禁用
	Retention time.Duration    // last_seen_at 超过该时长的行被删；<=0 用默认 30 天
	BatchSize int              // 单批删除行数上限；<=0 用默认 5000
	Now       func() time.Time // 测试注入
	Logger    *slog.Logger
}

type Runner struct {
	db        DB
	interval  time.Duration
	retention time.Duration
	batchSize int
	now       func() time.Time
	logger    *slog.Logger
}

func NewRunner(db DB, cfg Config) *Runner {
	retention := cfg.Retention
	if retention <= 0 {
		retention = 30 * 24 * time.Hour
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 5000
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Runner{db: db, interval: cfg.Interval, retention: retention, batchSize: batch, now: now, logger: cfg.Logger}
}

func (r *Runner) Run(ctx context.Context) {
	if r == nil || r.db == nil || r.interval <= 0 {
		return
	}
	r.runAndLog(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runAndLog(ctx)
		}
	}
}

func (r *Runner) runAndLog(ctx context.Context) {
	n, err := r.RunOnce(ctx)
	if err != nil && r.logger != nil {
		r.logger.Error("scan fingerprint clean failed", "error", err)
		return
	}
	if n > 0 && r.logger != nil {
		r.logger.Info("scan fingerprints cleaned", "rows", n)
	}
}

const staleVersionDeleteSQL = `
WITH current AS (
    SELECT rule_pack_version, engine_build
    FROM scan_fingerprints
    ORDER BY last_seen_at DESC
    LIMIT 1
)
DELETE FROM scan_fingerprints
WHERE ctid IN (
    SELECT s.ctid
    FROM scan_fingerprints s, current c
    WHERE s.rule_pack_version <> c.rule_pack_version
       OR s.engine_build <> c.engine_build
    LIMIT $1
)`

const expiredDeleteSQL = `
DELETE FROM scan_fingerprints
WHERE ctid IN (
    SELECT ctid FROM scan_fingerprints
    WHERE last_seen_at < $1
    LIMIT $2
)`

// RunOnce 两阶段清理，返回删除总行数：① 版本对 != 当前；② last_seen_at 超留存期。
func (r *Runner) RunOnce(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("fpclean runner requires db")
	}
	var total int64
	for {
		tag, err := r.db.Exec(ctx, staleVersionDeleteSQL, r.batchSize)
		if err != nil {
			return total, err
		}
		n := tag.RowsAffected()
		total += n
		if n < int64(r.batchSize) {
			break
		}
	}
	cutoff := r.now().Add(-r.retention)
	for {
		tag, err := r.db.Exec(ctx, expiredDeleteSQL, cutoff, r.batchSize)
		if err != nil {
			return total, err
		}
		n := tag.RowsAffected()
		total += n
		if n < int64(r.batchSize) {
			break
		}
	}
	return total, nil
}
