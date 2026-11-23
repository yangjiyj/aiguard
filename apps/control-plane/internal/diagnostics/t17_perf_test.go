package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 任务 17 压测与 Busy 退让。只在设置了 T17_PERF_DSN（独立压测库，含 t17perf 租户的 200 万行数据）时运行；
// 刻意不读 DIAG_TEST_DATABASE_URL，避免误在共享测试库上跑。

const t17Tenant = "t17perf"

func t17Dsn(t *testing.T) string {
	t.Helper()
	d := os.Getenv("T17_PERF_DSN")
	if d == "" {
		t.Skip("T17_PERF_DSN 未设置")
	}
	return d
}

// t17Rec 包一层 Querier：记录每条 SQL 的耗时；开启 explain 时对每条 SQL 另跑 EXPLAIN (ANALYZE, BUFFERS)。
type t17Rec struct {
	inner   Querier
	mu      sync.Mutex
	log     []t17Q
	explain bool
}

type t17Q struct {
	SQL  string
	Args []any
	Ms   float64
	Plan string
}

func (r *t17Rec) Query(ctx context.Context, sql string, args ...any) ([]map[string]any, error) {
	st := time.Now()
	rows, err := r.inner.Query(ctx, sql, args...)
	q := t17Q{SQL: sql, Args: args, Ms: float64(time.Since(st).Microseconds()) / 1000}
	if r.explain && err == nil {
		if pr, perr := r.inner.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+sql, args...); perr == nil {
			var sb strings.Builder
			for _, row := range pr {
				sb.WriteString(fmt.Sprint(row["QUERY PLAN"]) + "\n")
			}
			q.Plan = sb.String()
		} else {
			q.Plan = "EXPLAIN 失败: " + perr.Error()
		}
	}
	r.mu.Lock()
	r.log = append(r.log, q)
	r.mu.Unlock()
	return rows, err
}

func (r *t17Rec) reset() { r.mu.Lock(); r.log = nil; r.mu.Unlock() }

type t17Case struct {
	name string
	run  func(ctx context.Context, q Querier) error
}

func t17Tools() *Registry {
	var ts []Tool
	ts = append(ts, RequestTools()...)
	ts = append(ts, ConfigTools()...)
	ts = append(ts, ChangeTools()...)
	return NewRegistry(ts...)
}

func t17Call(reg *Registry, s Scope, name, args string) func(ctx context.Context, q Querier) error {
	return func(ctx context.Context, q Querier) error {
		st := reg.Call(ctx, q, s, name, json.RawMessage(args))
		if st.Err != "" {
			return fmt.Errorf("%s: %s", name, st.Err)
		}
		return nil
	}
}

func TestT17Perf(t *testing.T) {
	dsn := t17Dsn(t)
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	ctx := context.Background()
	reg := t17Tools()
	admin := Scope{TenantID: t17Tenant, IsAdmin: true}
	staff := Scope{TenantID: t17Tenant, UserID: "t17u_5"}
	host := &HostView{Err: ErrAgentMissing}

	// 找几个真实请求编号
	pick := func(where string) string {
		rows, err := x.Query(ctx, `SELECT request_id FROM request_logs WHERE tenant_id = $1 AND created_at > now() - interval '30 minutes' AND `+where+` ORDER BY created_at DESC LIMIT 1`, t17Tenant)
		if err != nil || len(rows) == 0 {
			t.Fatalf("找不到样本 %s: %v", where, err)
		}
		return rows[0]["request_id"].(string)
	}
	id429 := pick(`request_status = 'provider_error' AND upstream_status_code = 429`)
	id400 := pick(`request_status = 'provider_error' AND upstream_status_code = 400`)
	id500 := pick(`request_status = 'provider_error' AND upstream_status_code = 500`)
	idQuota := pick(`request_status = 'quota_exceeded'`)
	idOK := pick(`request_status = 'success'`)

	win := func(h int) Input { return Input{Kind: "health", WindowH: h} }
	cases := []t17Case{
		{"RunChecks health admin 1h", func(c context.Context, q Querier) error { _, _, _ = RunChecks(c, q, admin, win(1), host); return nil }},
		{"RunChecks health admin 24h", func(c context.Context, q Querier) error { _, _, _ = RunChecks(c, q, admin, win(24), host); return nil }},
		{"RunChecks health 员工 24h", func(c context.Context, q Querier) error { _, _, _ = RunChecks(c, q, staff, win(24), host); return nil }},
		{"get_request(失败 429)", t17Call(reg, admin, "get_request", fmt.Sprintf(`{"request_id":%q}`, id429))},
		{"get_request(成功)", t17Call(reg, admin, "get_request", fmt.Sprintf(`{"request_id":%q}`, idOK))},
		{"search_requests 1h 无过滤", t17Call(reg, admin, "search_requests", `{"window_hours":1}`)},
		{"search_requests 24h 无过滤", t17Call(reg, admin, "search_requests", `{"window_hours":24}`)},
		{"search_requests 1h model", t17Call(reg, admin, "search_requests", `{"window_hours":1,"model":"t17-model-03"}`)},
		{"search_requests 24h model", t17Call(reg, admin, "search_requests", `{"window_hours":24,"model":"t17-model-03"}`)},
		{"search_requests 1h provider", t17Call(reg, admin, "search_requests", `{"window_hours":1,"provider":"t17渠道-02"}`)},
		{"search_requests 24h provider", t17Call(reg, admin, "search_requests", `{"window_hours":24,"provider":"t17渠道-02"}`)},
		{"search_requests 1h user", t17Call(reg, admin, "search_requests", `{"window_hours":1,"user":"t17user005"}`)},
		{"search_requests 24h user", t17Call(reg, admin, "search_requests", `{"window_hours":24,"user":"t17user005"}`)},
		{"compare_windows 1h", t17Call(reg, admin, "compare_windows", `{"window_hours":1}`)},
		{"compare_windows 24h", t17Call(reg, admin, "compare_windows", `{"window_hours":24}`)},
		{"compare_windows 24h model", t17Call(reg, admin, "compare_windows", `{"window_hours":24,"model":"t17-model-03"}`)},
		{"get_user_access", t17Call(reg, admin, "get_user_access", `{"user":"t17user005","model":"t17-model-03"}`)},
		{"get_quota_policies", t17Call(reg, admin, "get_quota_policies", `{"user":"t17user005"}`)},
		{"change_timeline 24h", t17Call(reg, admin, "change_timeline", `{}`)},
		{"change_timeline 168h", t17Call(reg, admin, "change_timeline", `{"window_hours":168}`)},
		{"RunTree 编号树(429)", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "request", Ref: id429, WindowH: 1}, host)
			return err
		}},
		{"RunTree 编号树(400 hint)", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "request", Ref: id400, WindowH: 1}, host)
			return err
		}},
		{"RunTree 编号树(500)", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "request", Ref: id500, WindowH: 1}, host)
			return err
		}},
		{"RunTree 编号树(quota)", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "request", Ref: idQuota, WindowH: 1}, host)
			return err
		}},
		{"RunTree 用户树 1h", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "user", Ref: "t17user005", WindowH: 1}, host)
			return err
		}},
		{"RunTree 用户树 24h", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "user", Ref: "t17user005", WindowH: 24}, host)
			return err
		}},
		{"RunTree 用户树 24h(重度用户 t17user000)", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "user", Ref: "t17user000", WindowH: 24}, host)
			return err
		}},
		{"RunTree 模型树 24h", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, admin, Input{Kind: "model", Ref: "t17-model-03", WindowH: 24}, host)
			return err
		}},
		{"RunTree 员工用户树 24h", func(c context.Context, q Querier) error {
			_, err := RunTree(c, q, reg, staff, Input{Kind: "user", Ref: "t17user005", WindowH: 24}, host)
			return err
		}},
	}
	only := os.Getenv("T17_ONLY")
	explain := os.Getenv("T17_EXPLAIN") == "1"
	var report strings.Builder
	var plans strings.Builder
	over := 0
	for _, c := range cases {
		if only != "" && !strings.Contains(c.name, only) {
			continue
		}
		var durs []float64
		var lastLog []t17Q
		for i := 0; i < 3; i++ {
			rec := &t17Rec{inner: x}
			cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			st := time.Now()
			err := c.run(cctx, rec)
			ms := float64(time.Since(st).Microseconds()) / 1000
			cancel()
			if err != nil {
				t.Logf("%s 出错: %v", c.name, err)
			}
			durs = append(durs, ms)
			lastLog = rec.log
		}
		sorted := append([]float64(nil), durs...)
		sort.Float64s(sorted)
		med := sorted[1]
		flag := "OK"
		if med > 2000 {
			flag = "超标"
			over++
		}
		line := fmt.Sprintf("%-40s 中位数 %8.1f ms  三次 [%.0f, %.0f, %.0f]  SQL %d 条  %s", c.name, med, durs[0], durs[1], durs[2], len(lastLog), flag)
		t.Log(line)
		report.WriteString(line + "\n")
		sort.Slice(lastLog, func(i, j int) bool { return lastLog[i].Ms > lastLog[j].Ms })
		for i, q := range lastLog {
			if i >= 3 {
				break
			}
			one := strings.Join(strings.Fields(q.SQL), " ")
			if len(one) > 140 {
				one = one[:140] + "..."
			}
			report.WriteString(fmt.Sprintf("    SQL#%d %.1f ms  %s\n", i+1, q.Ms, one))
		}
		if explain && len(lastLog) > 0 {
			rec := &t17Rec{inner: x, explain: true}
			cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
			_ = c.run(cctx, rec)
			cancel()
			sort.Slice(rec.log, func(i, j int) bool { return rec.log[i].Ms > rec.log[j].Ms })
			for i, q := range rec.log {
				if i >= 2 || q.Ms < 50 {
					break
				}
				plans.WriteString(fmt.Sprintf("=== %s  SQL#%d (%.1f ms) ===\n%s\nargs=%v\n%s\n", c.name, i+1, q.Ms, strings.TrimSpace(q.SQL), q.Args, q.Plan))
			}
		}
	}
	label := os.Getenv("T17_LABEL")
	if label == "" {
		label = "run"
	}
	_ = os.WriteFile("/tmp/t17/result-"+label+".txt", []byte(report.String()), 0o644)
	if plans.Len() > 0 {
		_ = os.WriteFile("/tmp/t17/plans-"+label+".txt", []byte(plans.String()), 0o644)
	}
	if over > 0 {
		t.Errorf("%d 项超过 2s", over)
	}
}

// 30 个并发长查询（application_name 不是诊断；>=3 条长查询或连接占比过高才算繁忙）→ Exec.Busy 必须为 true，Engine 走轻量路径。
func TestT17BusyBackoff(t *testing.T) {
	dsn := t17Dsn(t)
	ctx := context.Background()
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if busy, why := x.Busy(ctx); busy {
		t.Fatalf("基线不应繁忙: %s", why)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 30
	cfg.ConnConfig.RuntimeParams["application_name"] = "t17-busy-load"
	load, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer load.Close()
	lctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = load.Exec(lctx, "SELECT pg_sleep(40)")
		}()
	}
	time.Sleep(3 * time.Second)
	b1, w1 := x.Busy(ctx)
	t.Logf("3 秒后 Busy=%v 原因=%q（长查询未满 30 秒，只看连接数占比与锁等待）", b1, w1)
	time.Sleep(30 * time.Second)
	b2, w2 := x.Busy(ctx)
	t.Logf("33 秒后 Busy=%v 原因=%q", b2, w2)
	if !b2 {
		t.Fatalf("30 个长查询跑过 30 秒后 Busy 应为 true")
	}

	// Engine 在繁忙时走轻量路径：不应调用 RunL2
	called := false
	e := &Engine{
		Exec: x, DB: load, Tools: t17Tools(), Now: time.Now,
		RunL2: func(context.Context, Querier, *Registry, Scope, Input, *HostView) (*Report, error) {
			called = true
			return &Report{Tier: TierL2}, nil
		},
	}
	r := &t10Round{c: Caller{TenantID: t17Tenant, IsAdmin: true}, scope: Scope{TenantID: t17Tenant, IsAdmin: true},
		input: Input{Kind: "request", Ref: "t17req_1", WindowH: 1}}
	rep, err := e.execute(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Engine.execute: Tier=%s Degraded=%q findings=%d steps=%d RunL2被调用=%v", rep.Tier, rep.Degraded, len(rep.Findings), len(rep.Steps), called)
	if called || rep.Degraded != t10BusyDegraded || len(rep.Findings) != 1 || rep.Findings[0].CheckID != "diag_busy" {
		t.Fatalf("繁忙时应走轻量诊断: called=%v degraded=%q", called, rep.Degraded)
	}
	cancel()
	wg.Wait()
	time.Sleep(2 * time.Second)
	if busy, why := x.Busy(ctx); busy {
		t.Logf("长查询取消后仍繁忙（等待回收）: %s", why)
	}
}
