package diagnostics

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	execMaxRows          = 500
	execStatementTimeout = "5s"
	execAppName          = "jjdguard-diagnostics"
)

var _ Querier = (*Exec)(nil)

// Exec 是只读执行器：独立连接池，每次查询都在只读事务里执行并设置语句超时。
type Exec struct {
	pool *pgxpool.Pool

	mu     sync.Mutex
	active map[string]struct{} // 正在诊断的租户
}

// NewExec 用独立连接池（MaxConns=2）连接数据库，不占用业务连接池。
func NewExec(dsn string) (*Exec, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: 解析数据库连接串: %w", err)
	}
	cfg.MaxConns = 2
	cfg.ConnConfig.RuntimeParams["application_name"] = execAppName
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("diagnostics: 创建连接池: %w", err)
	}
	return &Exec{pool: pool, active: map[string]struct{}{}}, nil
}

func (x *Exec) Close() { x.pool.Close() }

// Query 在只读事务中执行 SQL，最多返回 500 行，结束后一律回滚。
func (x *Exec) Query(ctx context.Context, sql string, args ...any) ([]map[string]any, error) {
	tx, err := x.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(rbCtx)
	}()
	// 诊断查询都是短时的聚合：关闭 JIT（大表聚合时编译就要 1 秒以上），
	// 并让规划器更愿意走租户+时间索引而不是全表扫描。只对本事务生效，不改库的配置。
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '"+execStatementTimeout+"'; SET LOCAL jit = off; SET LOCAL random_page_cost = 1.1"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	out := make([]map[string]any, 0, 16)
	for len(out) < execMaxRows && rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		m := make(map[string]any, len(fields))
		for i, f := range fields {
			m[f.Name] = jsonSafe(vals[i])
		}
		out = append(out, m)
	}
	if len(out) < execMaxRows {
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// jsonSafe 把 pgx 返回的值转成可被 json.Marshal 序列化的形式。
func jsonSafe(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case pgtype.Numeric:
		if !t.Valid {
			return nil
		}
		if t.NaN {
			return "NaN"
		}
		if t.InfinityModifier != pgtype.Finite {
			if t.InfinityModifier == pgtype.Infinity {
				return "Infinity"
			}
			return "-Infinity"
		}
		f, err := t.Float64Value()
		if err != nil || !f.Valid || math.IsInf(f.Float64, 0) || math.IsNaN(f.Float64) {
			return numericString(t)
		}
		return f.Float64
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano)
	case [16]byte:
		return pgtype.UUID{Bytes: t, Valid: true}.String()
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = jsonSafe(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = jsonSafe(e)
		}
		return out
	case []byte:
		return string(t)
	case pgtype.Interval:
		return fmt.Sprintf("%dmo %dd %dus", t.Months, t.Days, t.Microseconds)
	case fmt.Stringer:
		return t.String()
	default:
		return v
	}
}

func numericString(n pgtype.Numeric) string {
	if n.Int == nil {
		return "0"
	}
	s := new(big.Int).Set(n.Int).String()
	if n.Exp == 0 {
		return s
	}
	return fmt.Sprintf("%se%d", s, n.Exp)
}

// 繁忙判定阈值；测试里会调小。
var (
	execBusyLongSeconds = 30 // 视为“长查询”的运行秒数
	execBusyLongCount   = 3  // 长查询达到该数量才算繁忙
	execBusyLockSeconds = 10 // 等锁超过该秒数算繁忙
)

// Busy 判断库是否真的有压力，满足任一条件即繁忙：
//  1. 活跃连接数超过 max_connections 的 70%；
//  2. 运行超过 30 秒的非诊断查询 >= 3 条；
//  3. 有非诊断查询在等锁（wait_event_type='Lock'）且已超过 10 秒。
//
// 单条后台长查询不算繁忙：网关的对账协程每分钟会跑一条 30~55 秒的聚合查询，
// 它只占一个连接、不阻塞别人，若算繁忙会让诊断约一半概率被误降级为轻量检查。
// 多条长查询并发（资源被挤占）或有人被锁卡住，才是诊断该退让的信号。
func (x *Exec) Busy(ctx context.Context) (bool, string) {
	rows, err := x.Query(ctx, `
SELECT
  (SELECT count(*) FROM pg_stat_activity WHERE state = 'active')::bigint AS active,
  current_setting('max_connections')::bigint AS max_conn,
  (SELECT count(*) FROM pg_stat_activity
     WHERE state = 'active' AND pid <> pg_backend_pid()
       AND application_name <> $1
       AND now() - query_start > make_interval(secs => $2))::bigint AS long_running,
  (SELECT count(*) FROM pg_stat_activity
     WHERE pid <> pg_backend_pid() AND application_name <> $1
       AND wait_event_type = 'Lock'
       AND now() - query_start > make_interval(secs => $3))::bigint AS lock_waiting`,
		execAppName, float64(execBusyLongSeconds), float64(execBusyLockSeconds))
	if err != nil || len(rows) != 1 {
		return true, "无法读取数据库负载，暂不诊断"
	}
	active, _ := rows[0]["active"].(int64)
	maxConn, _ := rows[0]["max_conn"].(int64)
	long, _ := rows[0]["long_running"].(int64)
	lock, _ := rows[0]["lock_waiting"].(int64)
	if maxConn > 0 && float64(active) > 0.7*float64(maxConn) {
		return true, fmt.Sprintf("数据库活跃连接 %d，超过上限 %d 的 70%%", active, maxConn)
	}
	if int(long) >= execBusyLongCount {
		return true, fmt.Sprintf("数据库有 %d 个运行超过 %d 秒的查询", long, execBusyLongSeconds)
	}
	if lock > 0 {
		return true, fmt.Sprintf("数据库有 %d 个查询等锁超过 %d 秒", lock, execBusyLockSeconds)
	}
	return false, ""
}

// Acquire 按租户单飞：同一租户同时只允许一个诊断。release 可重复调用。
func (x *Exec) Acquire(ctx context.Context, tenantID string) (release func(), ok bool) {
	if ctx.Err() != nil {
		return func() {}, false
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, busy := x.active[tenantID]; busy {
		return func() {}, false
	}
	x.active[tenantID] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			x.mu.Lock()
			delete(x.active, tenantID)
			x.mu.Unlock()
		})
	}, true
}
