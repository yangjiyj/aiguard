package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------- 夹具 ----------

type t10Fix struct {
	db     *pgxpool.Pool
	x      *Exec
	eng    *Engine
	tenant string
	admin  Caller
	emp    Caller
	empB   Caller
	other  Caller // 另一个租户的管理员
	sfx    string

	mu      sync.Mutex
	l1Calls int
	l2Calls int
	l3Calls int
	l3Hist  [][]Msg
	l3Scope []Scope
	picked  *ModelChoice
	sc      SelfCheckResult
	scCalls int
	release chan struct{} // 非 nil 时 RunL2 阻塞到收到信号
	gate    *t10Gate
}

type t10Gate struct {
	mu     sync.Mutex
	busy   bool
	active map[string]bool
}

func (g *t10Gate) Busy(context.Context) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.busy, "测试繁忙"
}

func (g *t10Gate) Acquire(_ context.Context, key string) (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[key] {
		return func() {}, false
	}
	g.active[key] = true
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); delete(g.active, key); g.mu.Unlock() }) }, true
}

type t10LLM struct{}

func (t10LLM) Chat(context.Context, []Msg, []ToolSpec) (Reply, error) { return Reply{}, nil }

func t10Exec(t *testing.T, db *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("夹具 SQL 失败: %v\n%s", err, sql)
	}
}

func t10NewFix(t *testing.T) *t10Fix {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sfx := fmt.Sprintf("%08x", mrand.Uint32())
	f := &t10Fix{db: db, x: x, sfx: sfx, tenant: "t10ten_" + sfx}
	f.admin = Caller{TenantID: f.tenant, UserID: "t10adm_" + sfx, IsAdmin: true}
	f.emp = Caller{TenantID: f.tenant, UserID: "t10emp_" + sfx}
	f.empB = Caller{TenantID: f.tenant, UserID: "t10empb_" + sfx}
	f.other = Caller{TenantID: "t10oth_" + sfx, UserID: "t10othadm_" + sfx, IsAdmin: true}

	for _, id := range []string{f.tenant, f.other.TenantID} {
		t10Exec(t, db, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, id)
	}
	for _, u := range []Caller{f.admin, f.emp, f.empB, f.other} {
		t10Exec(t, db, `INSERT INTO users (id, tenant_id, username, department_assignment_mode) VALUES ($1, $2, $3, 'emergency')`,
			u.UserID, u.TenantID, "name_"+u.UserID)
	}
	t10Exec(t, db, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url) VALUES ($1, $2, $3, 'openai', 'https://x.example.com')`,
		"t10p_"+sfx, f.tenant, "渠道名-"+sfx)
	t10Exec(t, db, `INSERT INTO models (id, provider_id, model_name) VALUES ($1, $2, $3)`, "t10m_"+sfx, "t10p_"+sfx, "t10-model-"+sfx)
	t10Exec(t, db, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, "t10proj_"+sfx, f.tenant)
	t10Exec(t, db, `INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
		"t10k_"+sfx, f.tenant, "t10proj_"+sfx, f.emp.UserID, "hash_"+sfx, "jjd-t10-"+sfx)

	t.Cleanup(func() {
		c := context.Background()
		for _, s := range []string{
			`DELETE FROM audit_operations WHERE tenant_id = $1 OR user_id IN (SELECT id FROM users WHERE tenant_id = $1)`,
			`DELETE FROM diag_sessions WHERE tenant_id = $1`,
			`DELETE FROM diag_settings WHERE tenant_id = $1`,
			`DELETE FROM internal_keys WHERE tenant_id = $1`,
			`DELETE FROM projects WHERE tenant_id = $1`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			for _, tid := range []string{f.tenant, f.other.TenantID} {
				if _, err := db.Exec(c, s, tid); err != nil {
					t.Errorf("清理失败: %v (%s)", err, s)
				}
			}
		}
		db.Close()
		x.Close()
	})

	f.gate = &t10Gate{active: map[string]bool{}}
	f.sc = SelfCheckResult{Passed: true, Score: 5, Total: 5, TestedAt: time.Now().UTC(), Details: []string{}}
	f.eng = &Engine{
		DB: db, Q: x, Gate: f.gate,
		Tools: NewRegistry(RequestTools()...),
		Now:   time.Now,
		RunL1: func(ctx context.Context, q Querier, s Scope, in Input, host *HostView) ([]Finding, int, []Step) {
			f.mu.Lock()
			f.l1Calls++
			f.mu.Unlock()
			return []Finding{{CheckID: "gw_quota", Severity: SevError, Level: LevelConfirmed, Title: "额度已用完"}}, 3,
				[]Step{{Tool: "check:gw_quota", Args: json.RawMessage(`{}`), Summary: "检查额度与预算", Output: json.RawMessage(`{"n":1}`)}}
		},
		RunL2: func(ctx context.Context, q Querier, reg *Registry, s Scope, in Input, host *HostView) (*Report, error) {
			f.mu.Lock()
			f.l2Calls++
			rel := f.release
			f.mu.Unlock()
			if rel != nil {
				select {
				case <-rel:
				case <-ctx.Done():
				}
			}
			return &Report{Tier: TierL2, Findings: []Finding{{CheckID: "up_param", Severity: SevError, Level: LevelConfirmed, Title: "上游拒绝了参数"}},
				Steps: []Step{{Tool: "get_request", Args: json.RawMessage(`{"request_id":"x"}`), Summary: "查这条请求", Output: json.RawMessage(`{"found":true}`)}}}, nil
		},
		RunL3: func(ctx context.Context, m LLM, q Querier, reg *Registry, s Scope, in Input, history []Msg, progress func(Step)) (*Report, error) {
			f.mu.Lock()
			f.l3Calls++
			f.l3Hist = append(f.l3Hist, history)
			f.l3Scope = append(f.l3Scope, s)
			f.mu.Unlock()
			st := Step{Tool: "get_request", Args: json.RawMessage(`{"request_id":"x"}`), Summary: "正在查这条请求的完整链路", Output: json.RawMessage(`{"password":"hunter2 sk-abcdef1234567890abcd","found":true}`)}
			if progress != nil {
				progress(st)
			}
			return &Report{Tier: TierL3, Findings: []Finding{{CheckID: "ai", Severity: SevWarn, Level: LevelSuspected, Title: "疑似上游限流"}}, Steps: []Step{st}}, nil
		},
		Polish: func(ctx context.Context, m LLM, r *Report) *Report {
			out := *r
			out.Findings = append([]Finding{}, r.Findings...)
			out.Findings[0].Title = "润色后：" + out.Findings[0].Title
			return &out
		},
		Pick: func(ctx context.Context, q Querier, tenantID, preferred string) (*ModelChoice, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.picked, nil
		},
		LoadModel: func(ctx context.Context, c *ModelChoice) (LLM, error) { return t10LLM{}, nil },
		SelfCheck: func(ctx context.Context, m LLM) SelfCheckResult {
			f.mu.Lock()
			f.scCalls++
			r := f.sc
			f.mu.Unlock()
			return r
		},
	}
	t.Cleanup(f.eng.Wait)
	return f
}

func (f *t10Fix) setChoice() {
	f.mu.Lock()
	f.picked = &ModelChoice{ModelID: "t10m_" + f.sfx, ModelName: "t10-model-" + f.sfx, ProviderID: "t10p_" + f.sfx}
	f.mu.Unlock()
}

// setSelfCheck 写入某个模型的自检结果。
func (f *t10Fix) setSelfCheck(t *testing.T, modelID string, passed bool, at time.Time) {
	t.Helper()
	b, _ := json.Marshal(t10SC{SelfCheckResult: SelfCheckResult{Passed: passed, Score: 5, Total: 5, TestedAt: at, Details: []string{}}, ModelID: modelID})
	t10Exec(t, f.db, `INSERT INTO diag_settings (tenant_id, selfcheck_json) VALUES ($1, $2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET selfcheck_json = EXCLUDED.selfcheck_json`, f.tenant, string(b))
}

func (f *t10Fix) waitDone(t *testing.T, c Caller, id string) *SessionView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		v, err := f.eng.Get(context.Background(), c, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if v.Status != "running" {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("等待诊断完成超时")
	return nil
}

func (f *t10Fix) calls() (l1, l2, l3 int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.l1Calls, f.l2Calls, f.l3Calls
}

func t10Req(n string) string {
	return "req_" + strings.Repeat(n, 8) + "-1111-4111-8111-" + strings.Repeat(n, 12)
}

// ---------- 输入解析 ----------

func TestT10ParseInput(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	adm, emp := f.admin.Scope(), f.emp.Scope()
	id := t10Req("a")
	cases := []struct {
		name     string
		s        Scope
		text     string
		kind     string
		wantKind string
		wantRef  string
		wantH    int
	}{
		{"请求编号", adm, "我的请求 " + id + " 报错了", "", "request", id, 1},
		{"正向代理裸编号", adm, "代理请求 5fab4b9b-554e-42d3-b9b5-67306e5f5a7a 失败", "", "request", "5fab4b9b-554e-42d3-b9b5-67306e5f5a7a", 1},
		{"用户名", adm, "name_" + f.emp.UserID, "", "user", "name_" + f.emp.UserID, 1},
		{"key前缀", adm, "key jjd-t10-" + f.sfx + " 用不了", "", "user", "jjd-t10-" + f.sfx, 1},
		{"模型名", adm, "t10-model-" + f.sfx + " 很慢", "", "model", "t10-model-" + f.sfx, 1},
		{"渠道名", adm, "渠道名-" + f.sfx, "", "provider", "渠道名-" + f.sfx, 1},
		{"匹配不上是问题", adm, "为什么今天特别慢", "", "question", "", 1},
		{"体检直接体检", adm, "随便写点什么", "health", "health", "", 1},
		{"员工不借此探测用户名", emp, "name_" + f.empB.UserID, "", "question", "", 1},
		{"员工不借此探测渠道名", emp, "渠道名-" + f.sfx, "", "question", "", 1},
		{"员工可识别模型名", emp, "t10-model-" + f.sfx, "", "model", "t10-model-" + f.sfx, 1},
		{"别的租户查不到", f.other.Scope(), "t10-model-" + f.sfx, "", "question", "", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ParseInput(ctx, f.x, c.s, c.text, c.kind, 0)
			if in.Kind != c.wantKind || in.Ref != c.wantRef || in.WindowH != c.wantH {
				t.Fatalf("得到 %+v，期望 kind=%s ref=%s h=%d", in, c.wantKind, c.wantRef, c.wantH)
			}
		})
	}
	for _, c := range []struct{ in, want int }{{0, 1}, {-3, 1}, {1, 1}, {12, 12}, {24, 24}, {99, 24}} {
		if got := ParseInput(ctx, f.x, adm, "x问题", "", c.in).WindowH; got != c.want {
			t.Errorf("窗口 %d 应收敛为 %d，得到 %d", c.in, c.want, got)
		}
	}
}

// ---------- 选档 ----------

func TestT10TierSelection(t *testing.T) {
	ctx := context.Background()
	t.Run("无模型走L2", func(t *testing.T) {
		f := t10NewFix(t)
		id, err := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
		if err != nil {
			t.Fatal(err)
		}
		v := f.waitDone(t, f.admin, id)
		if v.Report == nil || v.Report.Tier != TierL2 {
			t.Fatalf("应为 L2：%+v", v.Report)
		}
		if _, l2, l3 := f.calls(); l2 != 1 || l3 != 0 {
			t.Fatalf("l2=%d l3=%d", l2, l3)
		}
	})
	t.Run("体检只跑L1", func(t *testing.T) {
		f := t10NewFix(t)
		f.setChoice()
		id, err := f.eng.Start(ctx, f.admin, Input{Kind: "health"})
		if err != nil {
			t.Fatal(err)
		}
		v := f.waitDone(t, f.admin, id)
		if v.Report.Tier != TierL1 || v.Report.OKCount != 3 || len(v.Report.Findings) != 1 {
			t.Fatalf("体检结果不对：%+v", v.Report)
		}
		if l1, l2, l3 := f.calls(); l1 != 1 || l2 != 0 || l3 != 0 {
			t.Fatalf("l1=%d l2=%d l3=%d", l1, l2, l3)
		}
	})
	t.Run("有模型且自检通过走L3", func(t *testing.T) {
		f := t10NewFix(t)
		f.setChoice()
		f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
		id, err := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
		if err != nil {
			t.Fatal(err)
		}
		v := f.waitDone(t, f.admin, id)
		if v.Report.Tier != TierL3 || v.Report.Model != f.picked.ModelName {
			t.Fatalf("应为 L3 且带模型名：%+v", v.Report)
		}
		if _, l2, l3 := f.calls(); l2 != 0 || l3 != 1 {
			t.Fatalf("l2=%d l3=%d", l2, l3)
		}
	})
	t.Run("自检未通过走L2并润色", func(t *testing.T) {
		f := t10NewFix(t)
		f.setChoice()
		f.setSelfCheck(t, f.picked.ModelID, false, time.Now().UTC())
		id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
		v := f.waitDone(t, f.admin, id)
		if v.Report.Tier != TierL2 || !strings.HasPrefix(v.Report.Findings[0].Title, "润色后：") {
			t.Fatalf("应为润色后的 L2：%+v", v.Report)
		}
		if v.Report.Degraded == "" {
			t.Fatal("应说明本次为什么没用智能排查")
		}
	})
	t.Run("ai_enabled关闭不用模型", func(t *testing.T) {
		f := t10NewFix(t)
		f.setChoice()
		f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
		t10Exec(t, f.db, `UPDATE diag_settings SET ai_enabled = FALSE WHERE tenant_id = $1`, f.tenant)
		id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
		v := f.waitDone(t, f.admin, id)
		if v.Report.Tier != TierL2 {
			t.Fatalf("应为 L2：%+v", v.Report)
		}
		if _, _, l3 := f.calls(); l3 != 0 {
			t.Fatal("关闭 AI 后不应调用 L3")
		}
	})
	t.Run("没有自检结果时后台自检且本次走L2", func(t *testing.T) {
		f := t10NewFix(t)
		f.setChoice()
		id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
		v := f.waitDone(t, f.admin, id)
		if v.Report.Tier != TierL2 {
			t.Fatalf("自检尚未完成时应按未通过处理：%+v", v.Report)
		}
		f.eng.Wait()
		f.mu.Lock()
		n := f.scCalls
		f.mu.Unlock()
		if n != 1 {
			t.Fatalf("应触发 1 次后台自检，实际 %d", n)
		}
		st := f.eng.loadSettings(ctx, f.tenant)
		if !st.passes(f.picked.ModelID, time.Now()) {
			t.Fatalf("自检结果应写回：%+v", st.Selfcheck)
		}
		// 下一次诊断就能走 L3
		id2, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "再问一次"})
		if v2 := f.waitDone(t, f.admin, id2); v2.Report.Tier != TierL3 {
			t.Fatalf("自检写回后应走 L3：%+v", v2.Report)
		}
	})
	t.Run("模型变化或超过7天重新自检", func(t *testing.T) {
		f := t10NewFix(t)
		f.setChoice()
		f.setSelfCheck(t, "别的模型", true, time.Now().UTC())
		st := f.eng.loadSettings(ctx, f.tenant)
		if !st.stale(f.picked.ModelID, time.Now()) {
			t.Fatal("模型变化应视为需要重新自检")
		}
		f.setSelfCheck(t, f.picked.ModelID, true, time.Now().Add(-8*24*time.Hour).UTC())
		st = f.eng.loadSettings(ctx, f.tenant)
		if !st.stale(f.picked.ModelID, time.Now()) || st.passes(f.picked.ModelID, time.Now()) {
			t.Fatal("超过 7 天应视为过期且不算通过")
		}
		f.setSelfCheck(t, f.picked.ModelID, false, time.Now().Add(-2*time.Hour).UTC())
		st = f.eng.loadSettings(ctx, f.tenant)
		if !st.stale(f.picked.ModelID, time.Now()) {
			t.Fatal("未通过的自检超过 1 小时应重测")
		}
		f.setSelfCheck(t, f.picked.ModelID, false, time.Now().Add(-10*time.Minute).UTC())
		st = f.eng.loadSettings(ctx, f.tenant)
		if st.stale(f.picked.ModelID, time.Now()) {
			t.Fatal("刚测过的未通过结果不应立刻重测")
		}
	})
}

// ---------- 降级、单飞 ----------

func TestT10BusyDegrades(t *testing.T) {
	f := t10NewFix(t)
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
	f.gate.busy = true
	reqID := t10Req("b")
	id, err := f.eng.Start(context.Background(), f.admin, Input{Kind: "request", Text: reqID})
	if err != nil {
		t.Fatal(err)
	}
	v := f.waitDone(t, f.admin, id)
	if v.Report.Degraded != "系统繁忙，已降级为轻量诊断" {
		t.Fatalf("Degraded=%q", v.Report.Degraded)
	}
	if l1, l2, l3 := f.calls(); l1+l2+l3 != 0 {
		t.Fatalf("繁忙时不应跑 L1/L2/L3：%d %d %d", l1, l2, l3)
	}
	tools := map[string]bool{}
	for _, s := range v.Report.Steps {
		tools[s.Tool] = true
	}
	if !tools["get_request"] {
		t.Fatalf("应只执行 get_request（加快照）：%+v", v.Report.Steps)
	}
	for name := range tools {
		if name != "get_request" && name != "host_snapshot" {
			t.Fatalf("轻量诊断不应执行 %s", name)
		}
	}
}

func TestT10SingleFlight409(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.release = make(chan struct{})
	id, err := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "第一个"})
	if err != nil {
		t.Fatal(err)
	}
	// 同租户第二个：拿不到名额
	_, err = f.eng.Start(ctx, f.emp, Input{Kind: "question", Text: "第二个"})
	if !errors.Is(err, ErrDiagBusy) {
		t.Fatalf("应返回 ErrDiagBusy，得到 %v", err)
	}
	if ErrDiagBusy.Error() != "已有诊断在进行，请稍候" {
		t.Fatalf("提示文案不对：%s", ErrDiagBusy)
	}
	// 被拒绝的请求不应留下会话
	var n int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM diag_sessions WHERE tenant_id = $1`, f.tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("被拒绝的请求不应创建会话：n=%d err=%v", n, err)
	}
	// 另一个租户不受影响
	otherID, err := f.eng.Start(ctx, f.other, Input{Kind: "health"})
	if err != nil {
		t.Fatalf("别的租户不应被占用：%v", err)
	}
	f.waitDone(t, f.other, otherID)
	close(f.release)
	f.waitDone(t, f.admin, id)
	f.eng.Wait()
	// 结束后名额释放
	id3, err := f.eng.Start(ctx, f.emp, Input{Kind: "question", Text: "第三个"})
	if err != nil {
		t.Fatalf("结束后应可再次发起：%v", err)
	}
	f.waitDone(t, f.emp, id3)
}

// ---------- 进度与持久化 ----------

func TestT10ProgressAndPersistence(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
	v := f.waitDone(t, f.admin, id)
	if len(v.Steps) != 1 || v.Steps[0].Tool != "get_request" || v.Steps[0].Summary == "" {
		t.Fatalf("steps=%+v", v.Steps)
	}
	// Report.Steps[].Output 不下发前端
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), `"output"`) {
		t.Fatalf("响应里不应出现工具输出：%s", b)
	}
	// 落库：状态、档位、完成时间、steps_json（已脱敏）
	var status, tier string
	var fin *time.Time
	var steps []byte
	if err := f.db.QueryRow(ctx, `SELECT status, tier, finished_at, steps_json FROM diag_sessions WHERE id = $1`, id).Scan(&status, &tier, &fin, &steps); err != nil {
		t.Fatal(err)
	}
	if status != "done" || tier != "L3" || fin == nil {
		t.Fatalf("status=%s tier=%s fin=%v", status, tier, fin)
	}
	if strings.Contains(string(steps), "hunter2") || strings.Contains(string(steps), "sk-abcdef1234567890abcd") {
		t.Fatalf("steps_json 里的凭据应已脱敏：%s", steps)
	}
	if !strings.Contains(string(steps), `"found"`) {
		t.Fatalf("steps_json 应保留工具输出供诊断包使用：%s", steps)
	}
}

func TestT10ProgressWrittenWhileRunning(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
	hold := make(chan struct{})
	f.eng.RunL3 = func(ctx context.Context, m LLM, q Querier, reg *Registry, s Scope, in Input, h []Msg, progress func(Step)) (*Report, error) {
		progress(Step{Tool: "search_requests", Summary: "正在统计同类请求的分布"})
		<-hold
		return &Report{Tier: TierL3, Findings: []Finding{}}, nil
	}
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "问题"})
	var seen *SessionView
	for i := 0; i < 200; i++ {
		v, _ := f.eng.Get(ctx, f.admin, id)
		if v != nil && v.Status == "running" && len(v.Steps) == 1 {
			seen = v
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(hold)
	if seen == nil || seen.Steps[0].Summary != "正在统计同类请求的分布" {
		t.Fatalf("运行中应能读到进度：%+v", seen)
	}
	f.waitDone(t, f.admin, id)
}

// ---------- 追问 ----------

func TestT10FollowUp(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()

	if err := f.eng.AddMessage(ctx, f.admin, id, "那 t10 的上游呢"); err != nil {
		t.Fatal(err)
	}
	v := f.waitDone(t, f.admin, id)
	if v.Report == nil || v.Report.Tier != TierL3 {
		t.Fatalf("追问应在同一会话开新一轮：%+v", v)
	}
	f.mu.Lock()
	hist := f.l3Hist[len(f.l3Hist)-1]
	f.mu.Unlock()
	if len(hist) < 2 || hist[0].Content != "为什么慢" || hist[len(hist)-1].Role != "assistant" {
		t.Fatalf("L3 应带上同一会话的历史：%+v", hist)
	}
	var msgs []byte
	if err := f.db.QueryRow(ctx, `SELECT messages_json FROM diag_sessions WHERE id = $1`, id).Scan(&msgs); err != nil {
		t.Fatal(err)
	}
	var ms []t10Msg
	_ = json.Unmarshal(msgs, &ms)
	if len(ms) != 3 || ms[0].Role != "assistant" || ms[1].Role != "user" || ms[1].Text != "那 t10 的上游呢" || ms[2].Role != "assistant" {
		t.Fatalf("messages_json 应依次记录回复、追问、回复：%+v", ms)
	}
	// 同一会话的追问沿用原来的排查对象
	if l1, _, _ := f.calls(); l1 != 0 {
		t.Fatal("追问不应改成体检")
	}
}

func TestT10FollowUpL2ReparsesInput(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	var seen []Input
	var mu sync.Mutex
	inner := f.eng.RunL2
	f.eng.RunL2 = func(ctx context.Context, q Querier, reg *Registry, s Scope, in Input, host *HostView) (*Report, error) {
		mu.Lock()
		seen = append(seen, in)
		mu.Unlock()
		return inner(ctx, q, reg, s, in, host)
	}
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()
	req := t10Req("c")
	if err := f.eng.AddMessage(ctx, f.admin, id, "看下 "+req); err != nil {
		t.Fatal(err)
	}
	f.waitDone(t, f.admin, id)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[1].Kind != "request" || seen[1].Ref != req {
		t.Fatalf("L2 追问应根据新文本重新解析：%+v", seen)
	}
}

func TestT10FollowUpRules(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.release = make(chan struct{})
	id, _ := f.eng.Start(ctx, f.emp, Input{Kind: "question", Text: "为什么慢"})
	// 运行中不能追问
	if err := f.eng.AddMessage(ctx, f.emp, id, "再问"); !errors.Is(err, ErrDiagBusy) && !errors.Is(err, ErrSessionRunning) {
		t.Fatalf("运行中的会话不能追问：%v", err)
	}
	close(f.release)
	f.waitDone(t, f.emp, id)
	f.eng.Wait()
	// 别人的会话：员工追问他人会话是不存在；管理员也不能替别人追问
	if err := f.eng.AddMessage(ctx, f.empB, id, "我来问"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("员工追问他人会话应是不存在：%v", err)
	}
	if err := f.eng.AddMessage(ctx, f.admin, id, "管理员代问"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("管理员不能在别人的会话里追问：%v", err)
	}
	if err := f.eng.AddMessage(ctx, f.emp, id, "   "); !errors.Is(err, ErrInputEmpty) {
		t.Fatalf("空追问：%v", err)
	}
}

// ---------- 审计 ----------

func TestT10Audit(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())
	secret := "我的口令是 topsecretpw " + t10Req("d")
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: secret})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()

	var actionType, targetType, targetID, tenant string
	var detail []byte
	var n int
	err := f.db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE action_type = 'diagnostics_run' AND tenant_id = $1`, f.tenant).Scan(&n)
	if err != nil || n != 1 {
		t.Fatalf("应写入 1 条审计：n=%d err=%v", n, err)
	}
	if err := f.db.QueryRow(ctx, `SELECT action_type, target_type, target_id, tenant_id, action_detail FROM audit_operations WHERE target_id = $1`, id).
		Scan(&actionType, &targetType, &targetID, &tenant, &detail); err != nil {
		t.Fatal(err)
	}
	if actionType != "diagnostics_run" || targetType != "diag_session" || targetID != id || tenant != f.tenant {
		t.Fatalf("审计字段不对：%s %s %s %s", actionType, targetType, targetID, tenant)
	}
	var d struct {
		Kind  string   `json:"kind"`
		Tier  string   `json:"tier"`
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(detail, &d); err != nil {
		t.Fatal(err)
	}
	if d.Kind != "request" && d.Kind != "question" {
		t.Fatalf("kind=%s", d.Kind)
	}
	if d.Tier != "L3" || len(d.Tools) != 1 || d.Tools[0] != "get_request" {
		t.Fatalf("detail=%s", detail)
	}
	if strings.Contains(string(detail), "topsecretpw") || strings.Contains(string(detail), "req_") {
		t.Fatalf("审计不得包含原文：%s", detail)
	}
	var keys []string
	var m map[string]json.RawMessage
	_ = json.Unmarshal(detail, &m)
	for k := range m {
		keys = append(keys, k)
	}
	if len(keys) != 3 {
		t.Fatalf("action_detail 只应包含 kind、tier、tools：%v", keys)
	}
}

func TestT10AuditWrittenForFailedRun(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.eng.RunL2 = func(context.Context, Querier, *Registry, Scope, Input, *HostView) (*Report, error) {
		panic("boom")
	}
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "问题"})
	v := f.waitDone(t, f.admin, id)
	f.eng.Wait()
	if v.Status != "failed" {
		t.Fatalf("panic 应让会话失败而不是卡在进行中：%s", v.Status)
	}
	var n int
	_ = f.db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE action_type = 'diagnostics_run' AND target_id = $1`, id).Scan(&n)
	if n != 1 {
		t.Fatalf("失败的诊断也应有审计：%d", n)
	}
	// 失败后名额已释放
	if _, err := f.eng.Start(ctx, f.admin, Input{Kind: "health"}); err != nil {
		t.Fatalf("失败后应释放名额：%v", err)
	}
}

// ---------- 员工隔离 ----------

func TestT10EmployeeIsolation(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())

	idEmp, _ := f.eng.Start(ctx, f.emp, Input{Kind: "question", Text: "员工A的问题"})
	f.waitDone(t, f.emp, idEmp)
	f.eng.Wait()
	idB, _ := f.eng.Start(ctx, f.empB, Input{Kind: "question", Text: "员工B的问题"})
	f.waitDone(t, f.empB, idB)
	f.eng.Wait()
	idAdm, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "管理员的问题"})
	f.waitDone(t, f.admin, idAdm)
	f.eng.Wait()

	// 员工传给 L3 的 Scope：强制本人、非管理员
	f.mu.Lock()
	sc := f.l3Scope[0]
	f.mu.Unlock()
	if sc.IsAdmin || sc.UserID != f.emp.UserID || sc.TenantID != f.tenant {
		t.Fatalf("员工 Scope 不对：%+v", sc)
	}
	// 管理员 Scope
	f.mu.Lock()
	asc := f.l3Scope[2]
	f.mu.Unlock()
	if !asc.IsAdmin || asc.UserID != "" {
		t.Fatalf("管理员 Scope 不对：%+v", asc)
	}

	// 员工读不到他人的会话（含管理员的）
	if _, err := f.eng.Get(ctx, f.emp, idB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("员工读他人会话应是不存在：%v", err)
	}
	if _, err := f.eng.Get(ctx, f.emp, idAdm); !errors.Is(err, ErrNotFound) {
		t.Fatalf("员工读管理员会话应是不存在：%v", err)
	}
	// 管理员可读全租户
	if _, err := f.eng.Get(ctx, f.admin, idEmp); err != nil {
		t.Fatalf("管理员应能读员工会话：%v", err)
	}
	// 跨租户读不到
	if _, err := f.eng.Get(ctx, f.other, idEmp); !errors.Is(err, ErrNotFound) {
		t.Fatalf("跨租户应是不存在：%v", err)
	}

	// 列表：员工只有自己的；管理员默认只有自己的，all 时看到全租户
	list, _ := f.eng.List(ctx, f.emp, true) // 员工传 all 无效
	if len(list) != 1 || list[0].ID != idEmp {
		t.Fatalf("员工只能看到自己的：%+v", list)
	}
	list, _ = f.eng.List(ctx, f.admin, false)
	if len(list) != 1 || list[0].ID != idAdm {
		t.Fatalf("管理员默认只看自己的：%+v", list)
	}
	list, _ = f.eng.List(ctx, f.admin, true)
	if len(list) != 3 {
		t.Fatalf("管理员 all 应看到本租户全部：%+v", list)
	}
	if list[0].Input.Kind == "" || list[0].Status == "" || list[0].CreatedAt.IsZero() {
		t.Fatalf("列表项应带输入、状态和时间：%+v", list[0])
	}

	// 诊断包只给管理员
	if _, err := f.eng.BundleFor(ctx, f.emp, idEmp); !errors.Is(err, ErrForbidden10) {
		t.Fatalf("员工不能取诊断包：%v", err)
	}
	bs, err := f.eng.BundleFor(ctx, f.admin, idEmp)
	if err != nil || bs.ID != idEmp || bs.Report == nil || len(bs.Steps) != 1 {
		t.Fatalf("管理员取诊断包数据：%+v err=%v", bs, err)
	}
	if strings.Contains(string(bs.Steps[0].Output), "hunter2") {
		t.Fatal("诊断包里的工具输出应已脱敏")
	}
}

// ---------- 设置 ----------

func TestT10Settings(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()

	v, err := f.eng.GetSettings(ctx, f.admin)
	if err != nil || !v.AIEnabled || v.ModelID != nil || v.SelfCheck != nil {
		t.Fatalf("默认设置：%+v err=%v", v, err)
	}
	mid := "t10m_" + f.sfx
	if err := f.eng.PutSettings(ctx, f.emp, true, &mid); !errors.Is(err, ErrForbidden10) {
		t.Fatalf("员工不能改设置：%v", err)
	}
	foreign := "不属于本租户的模型"
	if err := f.eng.PutSettings(ctx, f.admin, true, &foreign); !errors.Is(err, ErrModelNotInTenant) {
		t.Fatalf("model_id 必须属于本租户：%v", err)
	}
	if err := f.eng.PutSettings(ctx, f.other, true, &mid); !errors.Is(err, ErrModelNotInTenant) {
		t.Fatalf("别的租户的管理员不能引用本租户的模型：%v", err)
	}
	if err := f.eng.PutSettings(ctx, f.admin, false, &mid); err != nil {
		t.Fatal(err)
	}
	v, _ = f.eng.GetSettings(ctx, f.emp) // 员工可读
	if v.AIEnabled || v.ModelID == nil || *v.ModelID != mid || v.ModelName != "t10-model-"+f.sfx {
		t.Fatalf("保存后读取：%+v", v)
	}
	f.eng.Wait()
	f.mu.Lock()
	n := f.scCalls
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("关闭 AI 时不应触发自检：%d", n)
	}
	// 开启并换模型：触发自检并写回
	if err := f.eng.PutSettings(ctx, f.admin, true, &mid); err != nil {
		t.Fatal(err)
	}
	f.eng.Wait()
	v, _ = f.eng.GetSettings(ctx, f.admin)
	if v.SelfCheck == nil || !v.SelfCheck.Passed || v.SelfCheck.Score != 5 {
		t.Fatalf("换模型应触发自检并写回：%+v", v.SelfCheck)
	}
	// 清空 model_id 表示自动选择
	if err := f.eng.PutSettings(ctx, f.admin, true, nil); err != nil {
		t.Fatal(err)
	}
	v, _ = f.eng.GetSettings(ctx, f.admin)
	if v.ModelID != nil {
		t.Fatalf("应回到自动选择：%+v", v)
	}
	if v.EffectiveModelName != "t10-model-"+f.sfx || v.Models == nil {
		t.Fatalf("自动选择时应返回当前实际使用的模型名且 models 不为 null：%+v", v)
	}
	if v2, _ := f.eng.GetSettings(ctx, f.admin); v2.ModelID == nil && v2.EffectiveModelName == "" {
		t.Fatalf("自动选择时 effective_model_name 为空")
	}
}

// ---------- 红点 ----------

func TestT10Badge(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	has, err := f.eng.Badge(ctx, f.admin)
	if err != nil || has {
		t.Fatalf("首次没有缓存：has=%v err=%v", has, err)
	}
	f.eng.Wait()
	// 后台触发了一次只跑 L1 的体检
	deadline := time.Now().Add(5 * time.Second)
	for {
		has, err = f.eng.Badge(ctx, f.admin)
		if err != nil {
			t.Fatal(err)
		}
		if has || time.Now().After(deadline) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !has {
		t.Fatal("体检发现 error 级别问题后红点应为 true")
	}
	if l1, l2, l3 := f.calls(); l1 != 1 || l2 != 0 || l3 != 0 {
		t.Fatalf("红点体检只跑一次 L1：%d %d %d", l1, l2, l3)
	}
	// 缓存 10 分钟：再读不会重复体检
	for i := 0; i < 3; i++ {
		_, _ = f.eng.Badge(ctx, f.admin)
	}
	f.eng.Wait()
	if l1, _, _ := f.calls(); l1 != 1 {
		t.Fatalf("10 分钟内不应重复体检：%d", l1)
	}
	// 超过 10 分钟的结果不再采用
	t10Exec(t, f.db, `UPDATE diag_sessions SET created_at = NOW() - interval '11 minutes' WHERE tenant_id = $1`, f.tenant)
	if has, _ := f.eng.Badge(ctx, f.admin); has {
		t.Fatal("过期缓存不应继续亮红点")
	}
	f.eng.Wait()
	// 自动体检不进入“最近诊断”列表，也不写审计
	list, _ := f.eng.List(ctx, f.admin, true)
	if len(list) != 0 {
		t.Fatalf("自动体检不应出现在最近诊断里：%+v", list)
	}
	var n int
	_ = f.db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE action_type = 'diagnostics_run' AND tenant_id = $1`, f.tenant).Scan(&n)
	if n != 0 {
		t.Fatalf("自动体检不写审计：%d", n)
	}
}

func TestT10BadgeEmployeeSeesOnlyOwn(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	// 管理员的体检有问题
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "health"})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()
	if has, _ := f.eng.Badge(ctx, f.admin); !has {
		t.Fatal("管理员应看到红点")
	}
	// 员工不借用管理员的体检结果，而是为自己触发一次
	f.mu.Lock()
	before := f.l1Calls
	f.mu.Unlock()
	if has, _ := f.eng.Badge(ctx, f.emp); has {
		t.Fatal("员工首次读取没有自己的体检，不应亮红点")
	}
	f.eng.Wait()
	f.mu.Lock()
	after := f.l1Calls
	f.mu.Unlock()
	if after != before+1 {
		t.Fatalf("应为员工单独跑一次体检：%d -> %d", before, after)
	}
	var isAdmin bool
	if err := f.db.QueryRow(ctx, `SELECT is_admin FROM diag_sessions WHERE tenant_id = $1 AND user_id = $2`, f.tenant, f.emp.UserID).Scan(&isAdmin); err != nil || isAdmin {
		t.Fatalf("员工的体检会话 is_admin 应为 false：%v %v", isAdmin, err)
	}
}

func TestT10BadgeIgnoresMissingAgent(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.eng.RunL1 = func(context.Context, Querier, Scope, Input, *HostView) ([]Finding, int, []Step) {
		return []Finding{{CheckID: "agent_missing", Severity: SevWarn, Level: LevelUnknown, Title: "未安装采集器"}}, 5, nil
	}
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "health"})
	f.waitDone(t, f.admin, id)
	if has, _ := f.eng.Badge(ctx, f.admin); has {
		t.Fatal("未安装采集器只是安装状态，不应亮红点")
	}
}

// ---------- 清理 ----------

func TestT10Prune(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	for i, age := range []string{"31 days", "29 days", "1 hour"} {
		t10Exec(t, f.db, `INSERT INTO diag_sessions (id, tenant_id, user_id, is_admin, input_json, status, created_at)
VALUES ($1, $2, $3, TRUE, '{"kind":"health"}', 'done', NOW() - $4::interval)`, fmt.Sprintf("t10old%d_%s", i, f.sfx), f.tenant, f.admin.UserID, age)
	}
	if _, err := f.eng.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var ids []string
	rows, _ := f.db.Query(ctx, `SELECT id FROM diag_sessions WHERE tenant_id = $1 ORDER BY id`, f.tenant)
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 2 || strings.HasPrefix(ids[0], "t10old0") || strings.HasPrefix(ids[1], "t10old0") {
		t.Fatalf("只应删除 30 天前的：%v", ids)
	}
}

func TestT10SweepStuck(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	t10Exec(t, f.db, `INSERT INTO diag_sessions (id, tenant_id, user_id, is_admin, input_json, status, created_at)
VALUES ($1, $2, $3, TRUE, '{"kind":"health"}', 'running', NOW() - interval '30 minutes')`, "t10stuck_"+f.sfx, f.tenant, f.admin.UserID)
	t10Exec(t, f.db, `INSERT INTO diag_sessions (id, tenant_id, user_id, is_admin, input_json, status)
VALUES ($1, $2, $3, TRUE, '{"kind":"health"}', 'running')`, "t10fresh_"+f.sfx, f.tenant, f.admin.UserID)
	if _, err := f.eng.SweepStuck(ctx); err != nil {
		t.Fatal(err)
	}
	var s1, s2 string
	_ = f.db.QueryRow(ctx, `SELECT status FROM diag_sessions WHERE id = $1`, "t10stuck_"+f.sfx).Scan(&s1)
	_ = f.db.QueryRow(ctx, `SELECT status FROM diag_sessions WHERE id = $1`, "t10fresh_"+f.sfx).Scan(&s2)
	if s1 != "failed" || s2 != "running" {
		t.Fatalf("卡住的应标失败、新的保持进行中：%s %s", s1, s2)
	}
}

// ---------- 退化与不可用 ----------

func TestT10NilHooksDegrade(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	f.setChoice()
	f.setSelfCheck(t, f.picked.ModelID, true, time.Now().UTC())

	f.eng.RunL3 = nil // L3 不可用 → L2
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "问题"})
	if v := f.waitDone(t, f.admin, id); v.Report.Tier != TierL2 {
		t.Fatalf("L3 为 nil 应退到 L2：%+v", v.Report)
	}
	f.eng.Wait()

	f.eng.RunL2 = nil // L2 为 nil → L1
	id, _ = f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "问题"})
	if v := f.waitDone(t, f.admin, id); v.Report.Tier != TierL1 || v.Report.Degraded == "" {
		t.Fatalf("L2 为 nil 应退到 L1 并说明：%+v", v.Report)
	}
	f.eng.Wait()

	f.eng.RunL1 = nil // L1 为 nil → 空报告
	id, _ = f.eng.Start(ctx, f.admin, Input{Kind: "health"})
	v := f.waitDone(t, f.admin, id)
	if v.Status != "done" || v.Report == nil || len(v.Report.Findings) != 0 {
		t.Fatalf("L1 为 nil 应返回空报告：%+v", v)
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"findings":[]`) {
		t.Fatalf("findings 应序列化为空数组而不是 null：%s", b)
	}
}

func TestT10UnavailableEngine(t *testing.T) {
	var e *Engine
	ctx := context.Background()
	c := Caller{TenantID: "t", UserID: "u", IsAdmin: true}
	if _, err := e.Start(ctx, c, Input{Kind: "health"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	e = &Engine{}
	if _, err := e.Get(ctx, c, "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if _, err := e.Badge(ctx, c); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

func TestT10InputValidation(t *testing.T) {
	f := t10NewFix(t)
	ctx := context.Background()
	if _, err := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "  "}); !errors.Is(err, ErrInputEmpty) {
		t.Fatalf("空输入：%v", err)
	}
	// 超长文本被截断而不是报错或写爆库
	long := strings.Repeat("长", 20000)
	id, err := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: long})
	if err != nil {
		t.Fatal(err)
	}
	f.waitDone(t, f.admin, id)
	var in []byte
	_ = f.db.QueryRow(ctx, `SELECT input_json FROM diag_sessions WHERE id = $1`, id).Scan(&in)
	var got Input
	_ = json.Unmarshal(in, &got)
	if len([]rune(got.Text)) != t10MaxText {
		t.Fatalf("文本应截断到 %d：%d", t10MaxText, len([]rune(got.Text)))
	}
}
