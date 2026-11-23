package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionRead 返回在只读事务里先 SET LOCAL jit = off 再执行的查询入口。留存页的报表查询要展开告警
// JSON、判断正文有无，JIT 会先花数秒编译几百个函数（客户现场留存页大部分时间耗在这里）。设置只在
// 本次事务里生效，不影响连接池里的其他查询；部署的 PostgreSQL 另以 -c jit=off 启动。
func (r *RequestLogRepository) retentionRead() jitOffReader {
	return jitOffReader{db: r.db}
}

// retentionKeywordRead 在 retentionRead 之外还让本次事务里的语句按实际参数规划。关键字检索的计划取决于
// 关键字本身（命中多少正文、先按时间倒序还是完整匹配）；预备语句执行几次后 PostgreSQL 可能改用通用计划，
// 按“不知道关键字”估算，常见词会从 0.1 秒退化到 1 秒以上。规划多花几毫秒。
func (r *RequestLogRepository) retentionKeywordRead() jitOffReader {
	return jitOffReader{db: r.db, customPlan: true}
}

type jitOffReader struct {
	db         *pgxpool.Pool
	customPlan bool
}

func (q jitOffReader) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := q.db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	setting := "SET LOCAL jit = off"
	if q.customPlan {
		setting += "; SET LOCAL plan_cache_mode = force_custom_plan"
	}
	if _, err := tx.Exec(ctx, setting); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	return tx, nil
}

func (q jitOffReader) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx, err := q.begin(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	return &jitOffRows{Rows: rows, tx: tx, ctx: ctx}, nil
}

func (q jitOffReader) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return jitOffRow{reader: q, ctx: ctx, sql: sql, args: args}
}

// jitOffRows 在结果读完或关闭时结束事务，调用方照常 defer rows.Close() 即可。
type jitOffRows struct {
	pgx.Rows
	tx   pgx.Tx
	ctx  context.Context
	done bool
}

func (r *jitOffRows) Next() bool {
	if r.Rows.Next() {
		return true
	}
	r.finish()
	return false
}

func (r *jitOffRows) Close() {
	r.finish()
}

func (r *jitOffRows) finish() {
	if r.done {
		return
	}
	r.done = true
	r.Rows.Close()
	_ = r.tx.Rollback(context.WithoutCancel(r.ctx))
}

type jitOffRow struct {
	reader jitOffReader
	ctx    context.Context
	sql    string
	args   []any
}

func (r jitOffRow) Scan(dest ...any) error {
	tx, err := r.reader.begin(r.ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(r.ctx)) }()
	return tx.QueryRow(r.ctx, r.sql, r.args...).Scan(dest...)
}

// retentionRead 同上，供留存详情里按请求读状态的查询使用。
func (r *ContentLogRepository) retentionRead() jitOffReader {
	return jitOffReader{db: r.db}
}
