package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 会话编排：解析输入 → 选档 → 后台执行 → 进度/结果落库 → 审计。
// 诊断读取业务数据一律走只读的 Exec（Querier）；diag_sessions / diag_settings / audit_operations 的写入走业务连接池 DB。

var (
	ErrDiagBusy         = errors.New("已有诊断在进行，请稍候")
	ErrNotFound         = errors.New("诊断会话不存在")
	ErrForbidden10      = errors.New("仅管理员可执行该操作")
	ErrInputEmpty       = errors.New("请输入要诊断的内容")
	ErrSessionRunning   = errors.New("该会话正在诊断中，请稍候")
	ErrModelNotInTenant = errors.New("所选模型不存在或不属于当前租户")
	ErrNoReport         = errors.New("该会话还没有诊断报告")
	ErrUnavailable      = errors.New("诊断功能暂不可用")
)

const (
	t10RunTimeout       = 4 * time.Minute
	t10MaxText          = 4000
	t10MaxRef           = 128
	t10SelfCheckMaxAge  = 7 * 24 * time.Hour
	t10SelfCheckRetry   = 5 * time.Minute
	t10SelfCheckFailAge = time.Hour // 未通过的自检超过该时长即重测，让自动选型有机会换候选

	t10SelfCheckCandidates = 4                // 自动选型最多自检的候选数
	t10SelfCheckPerModel   = 3 * time.Minute  // 每个候选的自检时限
	t10SelfCheckAllTimeout = 12 * time.Minute // 整体时限
	t10BadgeTTL            = 10 * time.Minute
	t10Retention           = 30 * 24 * time.Hour
	t10StuckAfter          = 10 * time.Minute
	t10ListLimit           = 20
	t10BusyDegraded        = "系统繁忙，已降级为轻量诊断"
)

// Gate 提供单飞与负载退让；*Exec 实现了它，测试里可替换。
type Gate interface {
	Busy(ctx context.Context) (bool, string)
	Acquire(ctx context.Context, tenantID string) (release func(), ok bool)
}

// Caller 是发起诊断的人。管理员的 Scope.UserID 为空，但会话归属需要用户 ID，所以单独带上。
type Caller struct {
	TenantID string
	UserID   string
	IsAdmin  bool
}

func (c Caller) Scope() Scope {
	if c.IsAdmin {
		return Scope{TenantID: c.TenantID, IsAdmin: true}
	}
	return Scope{TenantID: c.TenantID, UserID: c.UserID}
}

// Engine 是会话编排器。RunL1/RunL2/RunL3/Polish 为 nil 时退化：L3 不可用、L2 退到 L1、L1 返回空报告。
type Engine struct {
	Exec   *Exec // 只读执行器（诊断查询、负载与单飞）
	Agent  *AgentClient
	Tools  *Registry
	RunL1  func(ctx context.Context, q Querier, s Scope, in Input, host *HostView) ([]Finding, int, []Step)
	RunL2  func(ctx context.Context, q Querier, reg *Registry, s Scope, in Input, host *HostView) (*Report, error)
	RunL3  func(ctx context.Context, m LLM, q Querier, reg *Registry, s Scope, in Input, history []Msg, progress func(Step)) (*Report, error)
	Polish func(ctx context.Context, m LLM, r *Report) *Report
	Now    func() time.Time

	DB        *pgxpool.Pool // 业务连接池（可写）：会话、设置、审计
	Q         Querier       // 非 nil 时替代 Exec 作为诊断查询入口（测试）
	Gate      Gate          // 非 nil 时替代 Exec 做单飞与负载判断（测试）
	Pick      func(ctx context.Context, q Querier, tenantID, preferredModelID string) (*ModelChoice, error)
	LoadModel func(ctx context.Context, c *ModelChoice) (LLM, error)
	SelfCheck func(ctx context.Context, m LLM) SelfCheckResult
	// Candidates 非 nil 时替代 PickCandidates（测试）。
	Candidates func(ctx context.Context, q Querier, tenantID string, limit int) ([]*ModelChoice, error)

	mu        sync.Mutex
	scRunning map[string]bool
	scLast    map[string]time.Time
	wg        sync.WaitGroup
}

// NewEngine 用生产依赖构造引擎；L1/L2/L3/Polish 取包内默认实现。
func NewEngine(db *pgxpool.Pool, exec *Exec, agent *AgentClient) *Engine {
	var tools []Tool
	tools = append(tools, RequestTools()...)
	tools = append(tools, ConfigTools()...)
	tools = append(tools, ChangeTools()...)
	if agent != nil {
		tools = append(tools, HostTools(agent)...)
	}
	return &Engine{
		Exec: exec, Agent: agent, DB: db, Tools: NewRegistry(tools...),
		RunL1: RunChecks, RunL2: RunTree, RunL3: RunAgent, Polish: Polish,
		Now: time.Now,
	}
}

// Wait 等待所有后台任务结束（测试清理用）。
func (e *Engine) Wait() { e.wg.Wait() }

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) q() Querier {
	if e.Q != nil {
		return e.Q
	}
	if e.Exec != nil {
		return e.Exec
	}
	return nil
}

func (e *Engine) ready() bool { return e != nil && e.DB != nil && e.q() != nil }

func (e *Engine) acquire(ctx context.Context, key string) (func(), bool) {
	if e.Gate != nil {
		return e.Gate.Acquire(ctx, key)
	}
	if e.Exec != nil {
		return e.Exec.Acquire(ctx, key)
	}
	return func() {}, true
}

func (e *Engine) busy(ctx context.Context) (bool, string) {
	if e.Gate != nil {
		return e.Gate.Busy(ctx)
	}
	if e.Exec != nil {
		return e.Exec.Busy(ctx)
	}
	return false, ""
}

func (e *Engine) pick(ctx context.Context, tenantID, preferred string) (*ModelChoice, error) {
	if e.Pick != nil {
		return e.Pick(ctx, e.q(), tenantID, preferred)
	}
	return PickModel(ctx, e.q(), tenantID, preferred)
}

func (e *Engine) candidates(ctx context.Context, tenantID string, limit int) ([]*ModelChoice, error) {
	if e.Candidates != nil {
		return e.Candidates(ctx, e.q(), tenantID, limit)
	}
	return PickCandidates(ctx, e.q(), tenantID, limit)
}

// pickFor 选实际使用的模型：手动指定时行为不变；自动选择时优先用自检通过且仍可用的模型，否则回到成功率排序。
func (e *Engine) pickFor(ctx context.Context, tenantID, modelID string, sc *t10SC) (*ModelChoice, error) {
	if modelID == "" && sc != nil && sc.Passed && sc.ModelID != "" {
		if c, err := e.pick(ctx, tenantID, sc.ModelID); err == nil && c != nil && c.ModelID == sc.ModelID {
			return c, nil
		}
	}
	return e.pick(ctx, tenantID, modelID)
}

func (e *Engine) loadModel(ctx context.Context, c *ModelChoice) (LLM, error) {
	if e.LoadModel != nil {
		return e.LoadModel(ctx, c)
	}
	return LoadLLM(ctx, e.DB, c)
}

func (e *Engine) selfCheck(ctx context.Context, m LLM) SelfCheckResult {
	if e.SelfCheck != nil {
		return e.SelfCheck(ctx, m)
	}
	return SelfCheck(ctx, m)
}

func t10NewID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func t10Trunc(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// ---------- 输入解析 ----------

var t10Split = regexp.MustCompile(`[\s,，。;；!！?？"'“”‘’（）()\[\]【】<>《》=、]+`)

func t10Window(h int) int {
	if h < 1 {
		return 1
	}
	if h > 24 {
		return 24
	}
	return h
}

func t10Tokens(text string) []string {
	text = strings.TrimSpace(text)
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.Trim(s, ".:/")
		if len(s) < 2 || len(s) > t10MaxRef || seen[s] || len(out) >= 40 {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(text)
	for _, p := range t10Split.Split(text, -1) {
		add(p)
	}
	return out
}

// ParseInput 把用户输入解析成 Input：先找请求编号；再按租户精确匹配用户名、key 前缀、模型名、渠道名；都不中则为 question。
// kind=health 直接体检。员工只识别请求编号与模型名（不借此探测他人账号或渠道是否存在）。
func ParseInput(ctx context.Context, q Querier, s Scope, text, kind string, windowH int) Input {
	text = t10Trunc(strings.TrimSpace(text), t10MaxText)
	in := Input{Kind: "question", Text: text, WindowH: t10Window(windowH)}
	if kind == "health" {
		in.Kind = "health"
		return in
	}
	if m := reqIDRe.FindString(text); m != "" {
		in.Kind, in.Ref = "request", m
		return in
	}
	if q == nil || s.TenantID == "" {
		return in
	}
	toks := t10Tokens(text)
	if len(toks) == 0 {
		return in
	}
	type look struct{ kind, sql string }
	var looks []look
	if s.IsAdmin {
		looks = append(looks,
			look{"user", `SELECT username AS v FROM users WHERE tenant_id = $1 AND username = ANY($2::text[])`},
			look{"user", `SELECT key_prefix AS v FROM internal_keys WHERE tenant_id = $1 AND key_prefix = ANY($2::text[])`})
	}
	looks = append(looks, look{"model", `SELECT DISTINCT m.model_name AS v FROM models m JOIN providers p ON p.id = m.provider_id
WHERE p.tenant_id = $1 AND m.model_name = ANY($2::text[])`})
	if s.IsAdmin {
		looks = append(looks, look{"provider", `SELECT name AS v FROM providers WHERE tenant_id = $1 AND name = ANY($2::text[])`})
	}
	for _, l := range looks {
		rows, err := q.Query(ctx, l.sql, s.TenantID, toks)
		if err != nil || len(rows) == 0 {
			continue
		}
		hit := map[string]bool{}
		for _, r := range rows {
			if v, ok := r["v"].(string); ok {
				hit[v] = true
			}
		}
		for _, t := range toks {
			if hit[t] {
				in.Kind, in.Ref = l.kind, t
				return in
			}
		}
	}
	return in
}

var t10Kinds = map[string]bool{"request": true, "user": true, "model": true, "provider": true, "health": true, "question": true}

// resolveInput 处理客户端传来的 Input：显式给了合法 kind+ref 的直接采用，否则按文本解析。
func (e *Engine) resolveInput(ctx context.Context, s Scope, in Input) Input {
	in.Kind = strings.TrimSpace(in.Kind)
	in.Ref = t10Trunc(strings.TrimSpace(in.Ref), t10MaxRef)
	if t10Kinds[in.Kind] && in.Kind != "question" && in.Kind != "health" && in.Ref != "" {
		in.Text = t10Trunc(strings.TrimSpace(in.Text), t10MaxText)
		in.WindowH = t10Window(in.WindowH)
		if in.Kind == "request" && !reqIDRe.MatchString(in.Ref) {
			return ParseInput(ctx, e.q(), s, in.Text, "", in.WindowH)
		}
		return in
	}
	return ParseInput(ctx, e.q(), s, in.Text, in.Kind, in.WindowH)
}

// ---------- 设置与选档 ----------

type t10SC struct {
	SelfCheckResult
	ModelID   string `json:"model_id"`
	ModelName string `json:"model_name,omitempty"`
}

type t10Settings struct {
	AIEnabled bool
	ModelID   string
	Selfcheck *t10SC
}

func (s t10Settings) passes(modelID string, now time.Time) bool {
	c := s.Selfcheck
	return c != nil && c.ModelID == modelID && c.Passed && now.Sub(c.TestedAt) <= t10SelfCheckMaxAge
}

func (s t10Settings) stale(modelID string, now time.Time) bool {
	c := s.Selfcheck
	return c == nil || c.ModelID != modelID || now.Sub(c.TestedAt) > t10SelfCheckMaxAge ||
		(!c.Passed && now.Sub(c.TestedAt) > t10SelfCheckFailAge)
}

func (e *Engine) loadSettings(ctx context.Context, tenantID string) t10Settings {
	st := t10Settings{AIEnabled: true}
	var ai bool
	var model *string
	var sc []byte
	err := e.DB.QueryRow(ctx, `SELECT ai_enabled, model_id, selfcheck_json FROM diag_settings WHERE tenant_id = $1`, tenantID).Scan(&ai, &model, &sc)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Printf("[diagnostics] 读取设置失败: %v", err)
		}
		return st
	}
	st.AIEnabled = ai
	if model != nil {
		st.ModelID = *model
	}
	if len(sc) > 0 {
		var c t10SC
		if json.Unmarshal(sc, &c) == nil {
			st.Selfcheck = &c
		}
	}
	return st
}

// ensureSelfCheck 在后台跑能力自检并写回；不阻塞调用方。
// auto=true（未手动指定模型）时在候选里逐个自检直到有一个通过；手动指定则只测 choice。
func (e *Engine) ensureSelfCheck(tenantID string, choice *ModelChoice, auto, force bool) {
	now := e.now()
	e.mu.Lock()
	if e.scRunning == nil {
		e.scRunning, e.scLast = map[string]bool{}, map[string]time.Time{}
	}
	if e.scRunning[tenantID] || (!force && now.Sub(e.scLast[tenantID]) < t10SelfCheckRetry) {
		e.mu.Unlock()
		return
	}
	e.scRunning[tenantID], e.scLast[tenantID] = true, now
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.scRunning, tenantID)
			e.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), t10SelfCheckAllTimeout)
		defer cancel()
		list := []*ModelChoice{choice}
		if auto {
			if cs, err := e.candidates(ctx, tenantID, t10SelfCheckCandidates); err == nil {
				for _, c := range cs {
					if len(list) >= t10SelfCheckCandidates {
						break
					}
					if c.ModelID != choice.ModelID {
						list = append(list, c)
					}
				}
			}
		}
		var best *t10SC
		for _, c := range list {
			if ctx.Err() != nil {
				break
			}
			llm, err := e.loadModel(ctx, c)
			if err != nil {
				log.Printf("[diagnostics] 自检加载模型失败: %v", err)
				continue
			}
			cctx, ccancel := context.WithTimeout(ctx, t10SelfCheckPerModel)
			res := e.selfCheck(cctx, llm)
			ccancel()
			cur := &t10SC{SelfCheckResult: res, ModelID: c.ModelID, ModelName: c.ModelName}
			if best == nil || (cur.Passed && !best.Passed) || (cur.Passed == best.Passed && cur.Score > best.Score) {
				best = cur
			}
			if res.Passed {
				break
			}
		}
		if best == nil {
			return
		}
		b, _ := json.Marshal(best)
		if _, err := e.DB.Exec(ctx, `INSERT INTO diag_settings (tenant_id, selfcheck_json) VALUES ($1, $2::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET selfcheck_json = EXCLUDED.selfcheck_json, updated_at = NOW()`, tenantID, string(b)); err != nil {
			log.Printf("[diagnostics] 写回自检结果失败: %v", err)
		}
	}()
}

// ---------- 会话生命周期 ----------

type t10Round struct {
	id      string
	c       Caller
	scope   Scope
	input   Input
	history []Msg
	release func()
	auto    bool

	mu    sync.Mutex
	steps []Step
}

type t10Msg struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// Start 创建会话并在后台开始诊断，拿不到单飞名额时返回 ErrDiagBusy。
func (e *Engine) Start(ctx context.Context, c Caller, in Input) (string, error) {
	return e.start(ctx, c, in, false)
}

func (e *Engine) start(ctx context.Context, c Caller, in Input, auto bool) (string, error) {
	if !e.ready() {
		return "", ErrUnavailable
	}
	key := c.TenantID
	if auto {
		key += "#badge" // 后台体检不占用户的诊断名额
	}
	release, ok := e.acquire(ctx, key)
	if !ok {
		return "", ErrDiagBusy
	}
	started := false
	defer func() {
		if !started {
			release()
		}
	}()
	scope := c.Scope()
	in = e.resolveInput(ctx, scope, in)
	if in.Kind != "health" && in.Ref == "" && strings.TrimSpace(in.Text) == "" {
		return "", ErrInputEmpty
	}
	id := t10NewID("dgs_")
	inMap := map[string]any{"kind": in.Kind, "text": in.Text, "ref": in.Ref, "window_hours": in.WindowH}
	if auto {
		inMap["auto"] = true
	}
	inJSON, _ := json.Marshal(inMap)
	startJSON, _ := json.Marshal(map[string]any{"steps": []any{}, "started_at": e.now().UTC().Format(time.RFC3339)})
	if _, err := e.DB.Exec(ctx, `INSERT INTO diag_sessions (id, tenant_id, user_id, is_admin, input_json, status, report_json, messages_json)
VALUES ($1, $2, $3, $4, $5::jsonb, 'running', $6::jsonb, '[]'::jsonb)`, id, c.TenantID, c.UserID, c.IsAdmin, string(inJSON), string(startJSON)); err != nil {
		return "", fmt.Errorf("创建诊断会话失败: %w", err)
	}
	started = true
	e.launch(&t10Round{id: id, c: c, scope: scope, input: in, release: release, auto: auto})
	return id, nil
}

// AddMessage 在同一会话上追问，开新一轮。只有会话本人可以追问。
func (e *Engine) AddMessage(ctx context.Context, c Caller, id, text string) error {
	if !e.ready() {
		return ErrUnavailable
	}
	text = t10Trunc(strings.TrimSpace(text), t10MaxText)
	if text == "" {
		return ErrInputEmpty
	}
	row, err := e.loadRow(ctx, c, id, true)
	if err != nil {
		return err
	}
	release, ok := e.acquire(ctx, c.TenantID)
	if !ok {
		return ErrDiagBusy
	}
	started := false
	defer func() {
		if !started {
			release()
		}
	}()
	scope := c.Scope()
	in := e.resolveInput(ctx, scope, Input{Kind: "question", Text: text, WindowH: row.Input.WindowH})
	if in.Kind == "question" && row.Input.Ref != "" && row.Input.Kind != "question" && row.Input.Kind != "health" {
		in.Kind, in.Ref = row.Input.Kind, row.Input.Ref // 追问沿用原来的排查对象
	}
	msg, _ := json.Marshal([]t10Msg{{Role: "user", Text: text}})
	startJSON, _ := json.Marshal(map[string]any{"steps": []any{}, "started_at": e.now().UTC().Format(time.RFC3339)})
	var msgs []byte
	err = e.DB.QueryRow(ctx, `UPDATE diag_sessions SET status = 'running', finished_at = NULL, tier = NULL,
  messages_json = messages_json || $3::jsonb, report_json = $4::jsonb
WHERE id = $1 AND tenant_id = $2 AND user_id = $5 AND status <> 'running' RETURNING messages_json`,
		id, c.TenantID, string(msg), string(startJSON), c.UserID).Scan(&msgs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionRunning
		}
		return fmt.Errorf("追加追问失败: %w", err)
	}
	started = true
	e.launch(&t10Round{id: id, c: c, scope: scope, input: in, history: t10History(row.Input.Text, msgs), release: release})
	return nil
}

// t10History 把会话里的往来变成 L3 的对话历史；最后一条用户消息就是本轮输入，不在历史里。
func t10History(first string, raw []byte) []Msg {
	var ms []t10Msg
	_ = json.Unmarshal(raw, &ms)
	if n := len(ms); n > 0 && ms[n-1].Role == "user" {
		ms = ms[:n-1]
	}
	var out []Msg
	if strings.TrimSpace(first) != "" {
		out = append(out, Msg{Role: "user", Content: first})
	}
	for _, m := range ms {
		if m.Role == "user" || m.Role == "assistant" {
			out = append(out, Msg{Role: m.Role, Content: m.Text})
		}
	}
	return out
}

func (e *Engine) launch(r *t10Round) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer r.release()
		ctx, cancel := context.WithTimeout(context.Background(), t10RunTimeout)
		defer cancel()
		var rep *Report
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("诊断过程异常: %v", p)
					log.Printf("[diagnostics] panic: %v", p)
				}
			}()
			rep, err = e.execute(ctx, r)
		}()
		e.finish(r, rep, err)
	}()
}

func (e *Engine) progress(r *t10Round) func(Step) {
	return func(st Step) {
		r.mu.Lock()
		r.steps = append(r.steps, st)
		views := make([]StepView, len(r.steps))
		for i, s := range r.steps {
			views[i] = StepView{Tool: s.Tool, Summary: s.Summary}
		}
		r.mu.Unlock()
		b, _ := json.Marshal(views)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := e.DB.Exec(ctx, `UPDATE diag_sessions SET report_json = jsonb_set(COALESCE(report_json, '{}'::jsonb), '{steps}', $2::jsonb)
WHERE id = $1 AND status = 'running'`, r.id, string(b)); err != nil {
			log.Printf("[diagnostics] 写回进度失败: %v", err)
		}
	}
}

func (e *Engine) hostView(s Scope) *HostView {
	if !s.IsAdmin {
		return nil
	}
	if e.Agent == nil {
		return &HostView{Err: ErrAgentMissing}
	}
	snap, err := e.Agent.Snapshot()
	return &HostView{Snapshot: snap, Err: err}
}

// ---------- 执行与选档 ----------

func (e *Engine) execute(ctx context.Context, r *t10Round) (*Report, error) {
	host := e.hostView(r.scope)
	if busy, _ := e.busy(ctx); busy {
		return e.light(ctx, r), nil
	}
	if r.input.Kind == "health" {
		return e.l1(ctx, r, host), nil
	}

	st := e.loadSettings(ctx, r.c.TenantID)
	var choice *ModelChoice
	if st.AIEnabled {
		choice, _ = e.pickFor(ctx, r.c.TenantID, st.ModelID, st.Selfcheck)
	}
	passed := false
	if choice != nil {
		now := e.now()
		passed = st.passes(choice.ModelID, now)
		if st.stale(choice.ModelID, now) {
			e.ensureSelfCheck(r.c.TenantID, choice, st.ModelID == "", false) // 不阻塞本次；本次按“未通过”处理
			passed = false
		}
	}

	var note string
	if choice != nil && passed && e.RunL3 != nil {
		llm, err := e.loadModel(ctx, choice)
		if err == nil {
			rep, err := e.RunL3(ctx, llm, e.q(), e.Tools, r.scope, r.input, r.history, e.progress(r))
			if rep != nil {
				if rep.Tier == TierL3 {
					rep.Model = choice.ModelName
				}
				return rep, nil
			}
			if err != nil {
				return nil, err
			}
			note = "智能排查没有返回结果，已改用固定排查"
		} else {
			note = "无法加载诊断模型，已改用固定排查"
		}
	} else if choice != nil && !passed {
		note = "诊断模型尚未通过能力自检，本次使用固定排查"
	}

	rep, err := e.l2(ctx, r, host)
	if err != nil {
		return nil, err
	}
	if note != "" && rep.Degraded == "" {
		rep.Degraded = note
	}
	if choice != nil && !passed && e.Polish != nil && rep.Tier == TierL2 {
		if llm, lerr := e.loadModel(ctx, choice); lerr == nil {
			if out := e.Polish(ctx, llm, rep); out != nil && out != rep {
				out.Model = choice.ModelName
				rep = out
			}
		}
	}
	return rep, nil
}

func (e *Engine) l1(ctx context.Context, r *t10Round, host *HostView) *Report {
	rep := &Report{Tier: TierL1, Findings: []Finding{}, Steps: []Step{}, StartedAt: e.now()}
	if e.RunL1 != nil {
		f, ok, steps := e.RunL1(ctx, e.q(), r.scope, r.input, host)
		if f != nil {
			rep.Findings = f
		}
		if steps != nil {
			rep.Steps = steps
		}
		rep.OKCount = ok
	}
	rep.FinishedAt = e.now()
	return rep
}

func (e *Engine) l2(ctx context.Context, r *t10Round, host *HostView) (*Report, error) {
	if e.RunL2 == nil {
		rep := e.l1(ctx, r, host)
		rep.Degraded = "固定排查树不可用，已改为全局体检"
		return rep, nil
	}
	rep, err := e.RunL2(ctx, e.q(), e.Tools, r.scope, r.input, host)
	if err != nil || rep == nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			log.Printf("[diagnostics] 固定排查未通过校验: %v", err)
		}
		l1 := e.l1(ctx, r, host)
		l1.Degraded = "固定排查结果未通过校验，已改为全局体检"
		return l1, nil
	}
	return rep, nil
}

// light 是系统繁忙时的轻量诊断：只读取请求记录（如有编号）和宿主机快照。
func (e *Engine) light(ctx context.Context, r *t10Round) *Report {
	rep := &Report{Tier: TierL1, Degraded: t10BusyDegraded, Findings: []Finding{}, Steps: []Step{}, StartedAt: e.now()}
	if r.auto {
		rep.FinishedAt = e.now()
		return rep
	}
	var ev []Evidence
	if r.input.Kind == "request" && r.input.Ref != "" && e.Tools != nil {
		args, _ := json.Marshal(map[string]string{"request_id": r.input.Ref})
		st := e.Tools.Call(ctx, e.q(), r.scope, "get_request", args)
		st.Summary = "读取这条请求的记录"
		rep.Steps = append(rep.Steps, st)
		var out struct {
			Found bool `json:"found"`
		}
		if st.Err == "" && json.Unmarshal(st.Output, &out) == nil && out.Found {
			ev = append(ev, Evidence{Kind: "request", Ref: r.input.Ref, Summary: "已读取该请求的记录"})
		}
	}
	if r.scope.IsAdmin && e.Agent != nil && e.Tools != nil {
		st := e.Tools.Call(ctx, e.q(), r.scope, "host_snapshot", json.RawMessage(`{}`))
		st.Summary = "读取宿主机快照"
		rep.Steps = append(rep.Steps, st)
	}
	rep.Findings = append(rep.Findings, Finding{
		CheckID: "diag_busy", Severity: SevWarn, Level: LevelUnknown,
		Title:    "数据库当前较忙，本次只做了轻量检查",
		Impact:   "没有展开完整排查，结论可能不全",
		Advice:   []Advice{{Text: "稍后重新发起诊断"}},
		Excluded: []string{}, Evidence: ev,
	})
	rep.FinishedAt = e.now()
	return rep
}

// ---------- 收尾：落库与审计 ----------

type t10StepRec struct {
	Tool    string          `json:"tool"`
	Args    json.RawMessage `json:"args,omitempty"`
	Summary string          `json:"summary"`
	Output  json.RawMessage `json:"output,omitempty"`
	Err     string          `json:"error,omitempty"`
}

func t10Valid(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	return raw
}

func t10RedactJSON(raw json.RawMessage) json.RawMessage {
	raw = t10Valid(raw)
	if raw == nil {
		return nil
	}
	red := Redact(string(raw))
	if json.Valid([]byte(red)) {
		return json.RawMessage(red)
	}
	b, _ := json.Marshal(red)
	return b
}

func t10CleanReport(rep *Report) {
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	if rep.Steps == nil {
		rep.Steps = []Step{}
	}
	for i := range rep.Steps {
		rep.Steps[i].Args = t10Valid(rep.Steps[i].Args)
	}
	for i := range rep.Findings {
		f := &rep.Findings[i]
		if f.Advice == nil {
			f.Advice = []Advice{}
		}
		if f.Excluded == nil {
			f.Excluded = []string{}
		}
		if f.Evidence == nil {
			f.Evidence = []Evidence{}
		}
	}
}

func (e *Engine) finish(r *t10Round, rep *Report, runErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if runErr != nil || rep == nil {
		if runErr != nil {
			log.Printf("[diagnostics] 会话 %s 失败: %v", r.id, runErr)
		}
		if _, err := e.DB.Exec(ctx, `UPDATE diag_sessions SET status = 'failed', finished_at = NOW() WHERE id = $1`, r.id); err != nil {
			log.Printf("[diagnostics] 写回失败状态出错: %v", err)
		}
		e.audit(ctx, r, "", nil)
		return
	}
	t10CleanReport(rep)
	rep.ID = r.id
	if rep.StartedAt.IsZero() {
		rep.StartedAt = e.now()
	}
	if rep.FinishedAt.IsZero() {
		rep.FinishedAt = e.now()
	}
	recs := make([]t10StepRec, 0, len(rep.Steps))
	for _, s := range rep.Steps {
		recs = append(recs, t10StepRec{Tool: s.Tool, Args: s.Args, Summary: s.Summary, Output: t10RedactJSON(s.Output), Err: s.Err})
	}
	repJSON, err1 := json.Marshal(rep)
	stepsJSON, err2 := json.Marshal(recs)
	if err1 != nil || err2 != nil {
		log.Printf("[diagnostics] 序列化报告失败: %v %v", err1, err2)
		_, _ = e.DB.Exec(ctx, `UPDATE diag_sessions SET status = 'failed', finished_at = NOW() WHERE id = $1`, r.id)
		e.audit(ctx, r, "", nil)
		return
	}
	reply, _ := json.Marshal([]t10Msg{{Role: "assistant", Text: t10Summary(rep)}})
	if _, err := e.DB.Exec(ctx, `UPDATE diag_sessions SET status = 'done', tier = $2, report_json = $3::jsonb, steps_json = $4::jsonb,
  messages_json = messages_json || $5::jsonb, finished_at = NOW() WHERE id = $1`,
		r.id, string(rep.Tier), string(repJSON), string(stepsJSON), string(reply)); err != nil {
		log.Printf("[diagnostics] 写回结果失败: %v", err)
		return
	}
	e.audit(ctx, r, string(rep.Tier), rep.Steps)
}

func t10Summary(rep *Report) string {
	var parts []string
	for _, f := range rep.Findings {
		if f.Title != "" {
			parts = append(parts, f.Title)
		}
	}
	if len(parts) == 0 {
		return "未发现异常"
	}
	return t10Trunc(strings.Join(parts, "；"), 500)
}

// audit 写一条 diagnostics_run；action_detail 只含输入类型、档位和工具名，不含原文。后台自动体检不写审计（避免噪声）。
func (e *Engine) audit(ctx context.Context, r *t10Round, tier string, steps []Step) {
	if r.auto {
		return
	}
	tools := []string{}
	seen := map[string]bool{}
	for _, s := range steps {
		if s.Tool != "" && !seen[s.Tool] {
			seen[s.Tool] = true
			tools = append(tools, s.Tool)
		}
	}
	detail, _ := json.Marshal(map[string]any{"kind": r.input.Kind, "tier": tier, "tools": tools})
	if _, err := e.DB.Exec(ctx, `INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, tenant_id)
VALUES ($1, $2, 'diagnostics_run', $3::jsonb, 'diag_session', $4, $5)`,
		t10NewID("audit_"), r.c.UserID, string(detail), r.id, r.c.TenantID); err != nil {
		log.Printf("[diagnostics] 写审计失败: %v", err)
	}
}

// ---------- 查询 ----------

type StepView struct {
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
}

type SessionView struct {
	Status string     `json:"status"`
	Steps  []StepView `json:"steps"`
	Report *Report    `json:"report,omitempty"`
}

type SessionSummary struct {
	ID        string    `json:"id"`
	Input     Input     `json:"input"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type t10Row struct {
	ID, TenantID, UserID string
	IsAdmin              bool
	Input                Input
	Status               string
	Tier                 *string
	Report, Steps        []byte
	Messages             []byte
	CreatedAt            time.Time
	FinishedAt           *time.Time
}

// loadRow 读取一个会话。员工（或 ownOnly）只能读到自己的，别人的当作不存在。
func (e *Engine) loadRow(ctx context.Context, c Caller, id string, ownOnly bool) (*t10Row, error) {
	var r t10Row
	var in []byte
	err := e.DB.QueryRow(ctx, `SELECT id, tenant_id, user_id, is_admin, input_json, status, tier, report_json, steps_json, messages_json, created_at, finished_at
FROM diag_sessions WHERE id = $1 AND tenant_id = $2 AND ($3 OR user_id = $4)`,
		id, c.TenantID, c.IsAdmin && !ownOnly, c.UserID).
		Scan(&r.ID, &r.TenantID, &r.UserID, &r.IsAdmin, &in, &r.Status, &r.Tier, &r.Report, &r.Steps, &r.Messages, &r.CreatedAt, &r.FinishedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(in, &r.Input)
	return &r, nil
}

// Get 返回会话状态与进度；done 时带完整报告。
func (e *Engine) Get(ctx context.Context, c Caller, id string) (*SessionView, error) {
	if !e.ready() {
		return nil, ErrUnavailable
	}
	row, err := e.loadRow(ctx, c, id, false)
	if err != nil {
		return nil, err
	}
	v := &SessionView{Status: row.Status, Steps: []StepView{}}
	if row.Status == "done" {
		var rep Report
		if json.Unmarshal(row.Report, &rep) == nil {
			for _, s := range rep.Steps {
				v.Steps = append(v.Steps, StepView{Tool: s.Tool, Summary: s.Summary})
			}
			if rep.Findings == nil {
				rep.Findings = []Finding{}
			}
			v.Report = &rep
			return v, nil
		}
		v.Status = "failed"
		return v, nil
	}
	var live struct {
		Steps []StepView `json:"steps"`
	}
	if json.Unmarshal(row.Report, &live) == nil && live.Steps != nil {
		v.Steps = live.Steps
	}
	return v, nil
}

// List 返回最近 20 条会话；all 仅对管理员有效（本租户全部）。后台自动体检不在其中。
func (e *Engine) List(ctx context.Context, c Caller, all bool) ([]SessionSummary, error) {
	if !e.ready() {
		return nil, ErrUnavailable
	}
	rows, err := e.DB.Query(ctx, `SELECT id, input_json, status, created_at FROM diag_sessions
WHERE tenant_id = $1 AND ($2 OR user_id = $3) AND NOT (input_json ? 'auto')
ORDER BY created_at DESC LIMIT $4`, c.TenantID, c.IsAdmin && all, c.UserID, t10ListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionSummary{}
	for rows.Next() {
		var s SessionSummary
		var in []byte
		if err := rows.Scan(&s.ID, &in, &s.Status, &s.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(in, &s.Input)
		out = append(out, s)
	}
	return out, rows.Err()
}

// BundleFor 组装诊断包所需的会话数据（仅管理员）。
func (e *Engine) BundleFor(ctx context.Context, c Caller, id string) (BundleSession, error) {
	if !e.ready() {
		return BundleSession{}, ErrUnavailable
	}
	if !c.IsAdmin {
		return BundleSession{}, ErrForbidden10
	}
	row, err := e.loadRow(ctx, c, id, false)
	if err != nil {
		return BundleSession{}, err
	}
	var rep Report
	if row.Status != "done" || json.Unmarshal(row.Report, &rep) != nil {
		return BundleSession{}, ErrNoReport
	}
	var recs []t10StepRec
	_ = json.Unmarshal(row.Steps, &recs)
	steps := make([]Step, 0, len(recs))
	for _, s := range recs {
		steps = append(steps, Step{Tool: s.Tool, Args: s.Args, Summary: s.Summary, Output: s.Output, Err: s.Err})
	}
	bs := BundleSession{
		ID: row.ID, TenantID: row.TenantID, UserID: row.UserID, Input: row.Input,
		Report: &rep, Steps: steps, Messages: json.RawMessage(row.Messages), CreatedAt: row.CreatedAt,
	}
	if row.FinishedAt != nil {
		bs.FinishedAt = *row.FinishedAt
	}
	if e.Agent != nil {
		if snap, err := e.Agent.Snapshot(); err == nil {
			bs.Host = snap
		}
	}
	return bs, nil
}

// ---------- 设置 ----------

type SelfCheckView struct {
	ModelName string    `json:"model_name,omitempty"`
	Passed    bool      `json:"passed"`
	Score     int       `json:"score"`
	TestedAt  time.Time `json:"tested_at"`
}

type SettingsView struct {
	AIEnabled bool    `json:"ai_enabled"`
	ModelID   *string `json:"model_id"`
	ModelName string  `json:"model_name"`
	// EffectiveModelName 是自动选择时当前实际使用的模型名（手动指定时为空）。
	EffectiveModelName string         `json:"effective_model_name,omitempty"`
	Models             []ModelOption  `json:"models"`
	SelfCheck          *SelfCheckView `json:"selfcheck"`
	AgentInstalled     bool           `json:"agent_installed"`
	AgentLastSeen      *string        `json:"agent_last_seen"`
}

func (e *Engine) GetSettings(ctx context.Context, c Caller) (*SettingsView, error) {
	if !e.ready() {
		return nil, ErrUnavailable
	}
	st := e.loadSettings(ctx, c.TenantID)
	v := &SettingsView{AIEnabled: st.AIEnabled}
	if st.ModelID != "" {
		id := st.ModelID
		v.ModelID = &id
		rows, err := e.q().Query(ctx, `SELECT m.model_name FROM models m JOIN providers p ON p.id = m.provider_id WHERE m.id = $1 AND p.tenant_id = $2`, st.ModelID, c.TenantID)
		if err == nil && len(rows) == 1 {
			v.ModelName, _ = rows[0]["model_name"].(string)
		}
	}
	v.Models = []ModelOption{}
	if ms, err := ListUsableModels(ctx, e.q(), c.TenantID); err == nil {
		v.Models = ms
	}
	if st.ModelID == "" && st.AIEnabled {
		if ch, err := e.pickFor(ctx, c.TenantID, "", st.Selfcheck); err == nil && ch != nil {
			v.EffectiveModelName = ch.ModelName
		}
	}
	if st.Selfcheck != nil {
		v.SelfCheck = &SelfCheckView{ModelName: st.Selfcheck.ModelName, Passed: st.Selfcheck.Passed, Score: st.Selfcheck.Score, TestedAt: st.Selfcheck.TestedAt}
	}
	if e.Agent != nil {
		if snap, err := e.Agent.Snapshot(); err == nil && snap != nil {
			v.AgentInstalled = true
			if snap.At != "" {
				at := snap.At
				v.AgentLastSeen = &at
			}
		}
	}
	return v, nil
}

// PutSettings 保存设置；换模型（或首次启用）时在后台触发能力自检。modelID 为空表示自动选择。
func (e *Engine) PutSettings(ctx context.Context, c Caller, aiEnabled bool, modelID *string) error {
	if !e.ready() {
		return ErrUnavailable
	}
	if !c.IsAdmin {
		return ErrForbidden10
	}
	mid := ""
	if modelID != nil {
		mid = strings.TrimSpace(*modelID)
	}
	if mid != "" {
		rows, err := e.q().Query(ctx, `SELECT 1 AS ok FROM models m JOIN providers p ON p.id = m.provider_id WHERE m.id = $1 AND p.tenant_id = $2`, mid, c.TenantID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrModelNotInTenant
		}
	}
	prev := e.loadSettings(ctx, c.TenantID)
	var arg any
	if mid != "" {
		arg = mid
	}
	if _, err := e.DB.Exec(ctx, `INSERT INTO diag_settings (tenant_id, ai_enabled, model_id) VALUES ($1, $2, $3)
ON CONFLICT (tenant_id) DO UPDATE SET ai_enabled = EXCLUDED.ai_enabled, model_id = EXCLUDED.model_id, updated_at = NOW()`,
		c.TenantID, aiEnabled, arg); err != nil {
		return err
	}
	if aiEnabled {
		if choice, err := e.pickFor(ctx, c.TenantID, mid, prev.Selfcheck); err == nil && choice != nil {
			changed := prev.ModelID != mid
			if changed || prev.stale(choice.ModelID, e.now()) {
				e.ensureSelfCheck(c.TenantID, choice, mid == "", changed)
			}
		}
	}
	return nil
}

// ---------- 红点 ----------

// Badge 读本租户（员工则限本人）最近 10 分钟内的体检结果；没有就在后台触发一次只跑 L1 的体检，缓存 10 分钟。
// 红点只看 error/warn；“未安装采集器”是安装状态而不是故障，不计入。
func (e *Engine) Badge(ctx context.Context, c Caller) (bool, error) {
	if !e.ready() {
		return false, ErrUnavailable
	}
	var status string
	var rep []byte
	err := e.DB.QueryRow(ctx, `SELECT status, report_json FROM diag_sessions
WHERE tenant_id = $1 AND input_json->>'kind' = 'health' AND created_at > $2
  AND (($3 AND is_admin) OR user_id = $4)
ORDER BY created_at DESC LIMIT 1`, c.TenantID, e.now().Add(-t10BadgeTTL), c.IsAdmin, c.UserID).Scan(&status, &rep)
	if errors.Is(err, pgx.ErrNoRows) {
		_, serr := e.start(ctx, c, Input{Kind: "health", WindowH: 1}, true)
		if serr != nil && !errors.Is(serr, ErrDiagBusy) {
			return false, serr
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if status != "done" {
		return false, nil
	}
	var r Report
	if json.Unmarshal(rep, &r) != nil {
		return false, nil
	}
	for _, f := range r.Findings {
		if f.CheckID == "agent_missing" {
			continue
		}
		if f.Severity == SevError || f.Severity == SevWarn {
			return true, nil
		}
	}
	return false, nil
}

// ---------- 清理 ----------

// Prune 删除 30 天前的会话。
func (e *Engine) Prune(ctx context.Context) (int64, error) {
	tag, err := e.DB.Exec(ctx, `DELETE FROM diag_sessions WHERE created_at < $1`, e.now().Add(-t10Retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SweepStuck 把超过 10 分钟仍在“进行中”的会话（进程重启遗留）标为失败。
func (e *Engine) SweepStuck(ctx context.Context) (int64, error) {
	tag, err := e.DB.Exec(ctx, `UPDATE diag_sessions SET status = 'failed', finished_at = NOW()
WHERE status = 'running' AND COALESCE((report_json->>'started_at')::timestamptz, created_at) < $1`, e.now().Add(-t10StuckAfter))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// StartMaintenance 启动后台维护：每 5 分钟清理卡住的会话，每天删除过期会话。
func (e *Engine) StartMaintenance(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		var lastPrune time.Time
		tick := func() {
			if n, err := e.SweepStuck(ctx); err != nil {
				log.Printf("[diagnostics] 清理卡住会话失败: %v", err)
			} else if n > 0 {
				log.Printf("[diagnostics] 已将 %d 个卡住的会话标为失败", n)
			}
			if time.Since(lastPrune) >= 24*time.Hour {
				if n, err := e.Prune(ctx); err != nil {
					log.Printf("[diagnostics] 清理过期会话失败: %v", err)
				} else {
					lastPrune = time.Now()
					if n > 0 {
						log.Printf("[diagnostics] 已删除 %d 个过期会话", n)
					}
				}
			}
		}
		tick()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick()
			}
		}
	}()
}
