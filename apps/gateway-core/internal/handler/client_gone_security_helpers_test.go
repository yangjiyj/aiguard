package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 本文件是「安全检测期间客户端断开」系列测试共用的夹具。
//
// 场景：Claude Code 按 Esc、Codex 中断时，请求 ctx 被取消，安全引擎调用随之返回
// context.Canceled。这不是检测失败，必须记 client_canceled，不能写
// security_output_check_failed / security_check_failed，fail-closed 下也不能变 503。
// 对照场景（超时、引擎不可用、引擎内部自己 cancel 但请求 ctx 未取消）仍按检测失败处理。

// goneSecurity 是脚本化的安全引擎：input / output 钩子决定 CheckInput / CheckOutput 的返回。
// 刻意不实现 detailedInputChecker 等可选接口，调用方一律走 CheckInput / CheckOutput。
type goneSecurity struct {
	mu            sync.Mutex
	input, output func(ctx context.Context) error
	// outputMatch 非空时，只有内容包含它的 CheckOutput 调用才会触发 output 钩子；
	// outputSkip 是触发钩子前先放行的匹配调用次数。用来把断开精确落在实时流的某一次扫描上。
	outputMatch string
	// outputExact 非空时，只有内容恰好等于它的 CheckOutput 调用才会触发 output 钩子（用来精确命中某个工具调用的参数扫描）。
	outputExact string
	outputSkip  int
	matched     int
}

func (s *goneSecurity) hook(stage string) func(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stage == "input" {
		return s.input
	}
	return s.output
}

func (s *goneSecurity) CheckInput(ctx context.Context, _ *modelrouter.RequestEnvelope, _ string, _ int, _ string, _ string) (string, string, []SecurityFinding, error) {
	if hook := s.hook("input"); hook != nil {
		if err := hook(ctx); err != nil {
			return "", "", nil, err
		}
	}
	return "allow", "", nil, nil
}

func (s *goneSecurity) CheckOutput(ctx context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	s.mu.Lock()
	hooked := s.output != nil
	if hooked && s.outputExact != "" && content != s.outputExact {
		hooked = false
	}
	if hooked && s.outputMatch != "" && !strings.Contains(content, s.outputMatch) {
		hooked = false
	}
	if hooked {
		s.matched++
		if s.matched <= s.outputSkip {
			hooked = false
		}
	}
	hook := s.output
	s.mu.Unlock()
	if hooked {
		if err := hook(ctx); err != nil {
			return "", "", nil, err
		}
	}
	return "allow", "", nil, nil
}

func (s *goneSecurity) CheckSemanticOnly(context.Context, *modelrouter.RequestEnvelope, string) ([]SecurityFinding, error) {
	return nil, nil
}

func (s *goneSecurity) CheckTriage(_ context.Context, _ *modelrouter.RequestEnvelope, _ string, findings []SecurityFinding) ([]SecurityFinding, error) {
	return findings, nil
}

// blockUntilClientGone 模拟「引擎正在检测，客户端此时断开」：先通知 entered，然后阻塞到请求 ctx
// 被取消，再把 ctx.Err() 原样返回（wrap=true 时像真实 HTTP 客户端那样再包一层）。
func blockUntilClientGone(entered chan struct{}, wrap bool) func(context.Context) error {
	var once sync.Once
	return func(ctx context.Context) error {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			if wrap {
				return fmt.Errorf("failed to call security engine: %w", ctx.Err())
			}
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return errors.New("test timeout: request ctx was never canceled")
		}
	}
}

func constantFailure(err error) func(chan struct{}) func(context.Context) error {
	return func(chan struct{}) func(context.Context) error {
		return func(context.Context) error { return err }
	}
}

type goneScenario struct {
	name string
	// gone=true：请求 ctx 在检测期间被取消（客户端断开）；false 是对照组，行为必须保持原样。
	gone bool
	hook func(entered chan struct{}) func(context.Context) error
}

var goneScenarios = []goneScenario{
	{"client_gone", true, func(entered chan struct{}) func(context.Context) error {
		return blockUntilClientGone(entered, false)
	}},
	{"client_gone_wrapped", true, func(entered chan struct{}) func(context.Context) error {
		return blockUntilClientGone(entered, true)
	}},
	{"deadline", false, constantFailure(context.DeadlineExceeded)},
	{"engine_down", false, constantFailure(errors.New("engine down"))},
	// 引擎内部自己 cancel：返回 Canceled，但请求 ctx 仍然存活，仍是检测失败。
	{"engine_internal_cancel", false, constantFailure(context.Canceled)},
}

type goneConfig struct {
	name                  string
	auditOnly, failClosed bool
}

// goneConfigs 覆盖「护栏失败」的四种有效组合。record_failclosed 是不变量：只审计模式即便
// 打开了 fail-closed 也永不拦截。
var goneConfigs = []goneConfig{
	{"protect", false, false},
	{"protect_failclosed", false, true},
	{"record", true, false},
	{"record_failclosed", true, true},
}

// clientGoneForbiddenEvents 是客户端断开时绝不能出现的事件（误标成检测失败/拦截）。
var clientGoneForbiddenEvents = map[string]bool{
	"security_output_check_failed": true,
	"security_check_failed":        true,
	"output_scan_incomplete":       true,
	"security_blocked":             true,
	"stream_blocked":               true,
}

// goneDB 记录每次 Exec 的 ctx、SQL 与参数，用真实的 RealAuditWriter 验证最终落库的内容。
//
// 为什么不复用 sqlRecordingDB（audit_detach_all_writes_test.go）：sqlRecordingDB 像真实 pgx 一样，
// 收到已取消的 ctx 就让 Exec 失败。本组用例要验证的是「客户端断开后，收尾写库拿到的 ctx 没被取消」，
// 如果底层遇到已取消 ctx 就失败，收尾写入会被吞掉，就看不出来写入的内容对不对了。
// goneDB 在 ctx 已取消时也不失败，而是把当时的 ctx 状态交给 probe 记录，
// 由 probe.require 断言「每次落库的 ctx 都未取消、有限时、value 还在」；落库内容则在这里取出来核对。
type goneExec struct {
	query string
	args  []interface{}
}

type goneDB struct {
	probe *ctxProbe
	// t 非空时，按列下标取不到预期类型的值会 t.Fatalf 指明是哪一列，而不是悄悄当成零值
	// （零值会让「断言没写进去」和「断言写进去了但列错位」混在一起）。
	t     *testing.T
	mu    sync.Mutex
	execs []goneExec
}

func (d *goneDB) Exec(ctx context.Context, query string, args ...interface{}) (execResult, error) {
	d.mu.Lock()
	d.execs = append(d.execs, goneExec{query: query, args: append([]interface{}(nil), args...)})
	d.mu.Unlock()
	switch {
	case isRequestLogFinalizeSQL(query):
		d.probe.record("db.finalize", ctx)
	case strings.Contains(query, "INSERT INTO security_events"):
		d.probe.record("db.event", ctx)
	}
	return &mockExecResult{rowsAffected: 1}, nil
}

func isRequestLogFinalizeSQL(query string) bool {
	return strings.Contains(query, "INSERT INTO request_logs") && strings.Contains(query, "DO UPDATE SET")
}

type goneFinalize struct {
	status string
	code   int
}

// 列下标（参数从 $1 起，下标 = 序号 - 1）：
//
//	request_logs 收尾 INSERT：$14 = request_status，$15 = upstream_status_code；
//	security_events INSERT：$6 = event_type，$9 = action_taken。
const (
	goneFinalizeStatusArg   = 13
	goneFinalizeCodeArg     = 14
	goneEventTypeArg        = 5
	goneEventActionTakenArg = 8
)

func (d *goneDB) stringArg(exec goneExec, index int, column string) string {
	value, ok := exec.args[index].(string)
	if !ok && d.t != nil {
		d.t.Helper()
		d.t.Fatalf("落库参数 $%d (%s) 不是 string, got %T(%v)：SQL 列顺序可能变了, query=%.80s",
			index+1, column, exec.args[index], exec.args[index], strings.Join(strings.Fields(exec.query), " "))
	}
	return value
}

// requestStatusArg 取 request_status 并校验它是网关已知的收尾状态。光有类型检查挡不住「同为 string 的列错位」
// （例如下标偏一位读成 trace_id），所以值也要在已知集合里，否则明确指出是 $N 这一列取错了。
func (d *goneDB) requestStatusArg(exec goneExec) string {
	value := d.stringArg(exec, goneFinalizeStatusArg, "request_status")
	if d.t != nil && !knownGoneRequestStatuses[value] {
		d.t.Helper()
		d.t.Fatalf("落库参数 $%d (request_status) = %q 不是已知的收尾状态：SQL 列顺序可能变了, query=%.80s",
			goneFinalizeStatusArg+1, value, strings.Join(strings.Fields(exec.query), " "))
	}
	return value
}

// knownGoneRequestStatuses 是本组用例里会出现的收尾状态；新增状态时在这里补充。
var knownGoneRequestStatuses = map[string]bool{
	"received": true, "success": true, "completed": true, "client_canceled": true, "security_blocked": true,
	"provider_unavailable": true, "provider_error": true, "provider_timeout": true, "stream_aborted": true,
	"incomplete": true,
}

func (d *goneDB) intArg(exec goneExec, index int, column string) int {
	value, ok := exec.args[index].(int)
	if !ok && d.t != nil {
		d.t.Helper()
		d.t.Fatalf("落库参数 $%d (%s) 不是 int, got %T(%v)：SQL 列顺序可能变了, query=%.80s",
			index+1, column, exec.args[index], exec.args[index], strings.Join(strings.Fields(exec.query), " "))
	}
	return value
}

// finalizes 返回 request_logs 收尾写入的 (request_status, upstream_status_code)。
func (d *goneDB) finalizes() []goneFinalize {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []goneFinalize
	for _, exec := range d.execs {
		if !isRequestLogFinalizeSQL(exec.query) {
			continue
		}
		if len(exec.args) <= goneFinalizeCodeArg {
			if d.t != nil {
				d.t.Helper()
				d.t.Fatalf("request_logs 收尾 INSERT 只有 %d 个参数，取不到 $%d/$%d (request_status/upstream_status_code)",
					len(exec.args), goneFinalizeStatusArg+1, goneFinalizeCodeArg+1)
			}
			continue
		}
		out = append(out, goneFinalize{
			status: d.requestStatusArg(exec),
			code:   d.intArg(exec, goneFinalizeCodeArg, "upstream_status_code"),
		})
	}
	return out
}

// eventNames 返回 security_events 写入的 event_type 与 action_taken（两者都可能带出失败标记）。
func (d *goneDB) eventNames() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, exec := range d.execs {
		if !strings.Contains(exec.query, "INSERT INTO security_events") {
			continue
		}
		if len(exec.args) <= goneEventActionTakenArg {
			if d.t != nil {
				d.t.Helper()
				d.t.Fatalf("security_events INSERT 只有 %d 个参数，取不到 $%d/$%d (event_type/action_taken)",
					len(exec.args), goneEventTypeArg+1, goneEventActionTakenArg+1)
			}
			continue
		}
		out = append(out,
			d.stringArg(exec, goneEventTypeArg, "event_type"),
			d.stringArg(exec, goneEventActionTakenArg, "action_taken"))
	}
	return out
}

// goneEnv 是一次端到端用例的运行环境。
type goneEnv struct {
	probe    *ctxProbe
	db       *goneDB
	writer   *RealAuditWriter
	sec      *goneSecurity
	client   *ToolRiskClient
	metrics  *relay.Metrics
	ctx      context.Context // 原始请求 ctx：带 probe 标记，gone 场景下检测一开始就会被取消
	scenario goneScenario
}

// newGoneEnv 的 stage 取 input 或 output，决定脚本钩子挂在哪个检测阶段。
func newGoneEnv(t *testing.T, sc goneScenario, cfg goneConfig, stage string) *goneEnv {
	t.Helper()
	entered := make(chan struct{})
	probe := &ctxProbe{}
	db := &goneDB{probe: probe, t: t}
	sec := &goneSecurity{}
	if stage == "input" {
		sec.input = sc.hook(entered)
	} else {
		sec.output = sc.hook(entered)
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
	t.Cleanup(cancel)
	if sc.gone {
		go func() {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
			}
			cancel()
		}()
	}
	return &goneEnv{
		probe: probe, db: db, writer: &RealAuditWriter{db: db}, sec: sec,
		client:  failClosedClient(t, cfg.auditOnly, cfg.failClosed),
		metrics: relay.NewMetrics(), ctx: ctx, scenario: sc,
	}
}

type goneResult struct {
	httpCode int
	body     string
}

type goneExpect struct {
	status string   // 对照组（非断开）的预期收尾状态
	code   int      // 对照组的预期状态码
	events []string // 对照组必须出现的事件（event_type 或 action_taken）
	anyOf  []string // 对照组至少出现其中一个事件（实时流：增量检测与最终检测谁先失败取决于走哪条路径）
	// metricGone=true：实时流路径额外校验断开时 security_check_failed 指标必须为 0。
	metricGone bool
	// metricControl=true：对照组 security_check_failed 指标必须大于 0（仅增量检测失败的路径累加该指标）。
	metricControl bool
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// check 校验：客户端断开 -> client_canceled/408、没有误标事件、没有 503、收尾写库 ctx 未取消；
// 对照组 -> 原有的收尾状态与失败事件。
func (e *goneEnv) check(t *testing.T, res goneResult, want goneExpect) {
	t.Helper()
	fin := e.db.finalizes()
	if len(fin) == 0 {
		t.Fatalf("request_logs 没有收尾写入 (events=%v body=%q)", e.db.eventNames(), res.body)
	}
	last := fin[len(fin)-1]
	names := e.db.eventNames()
	if e.scenario.gone {
		if last.status != "client_canceled" || last.code != http.StatusRequestTimeout {
			t.Errorf("收尾=%s/%d, want client_canceled/408 (events=%v body=%q)", last.status, last.code, names, res.body)
		}
		for _, f := range fin {
			if f.status == "security_blocked" {
				t.Errorf("客户端断开被记成 security_blocked/%d", f.code)
			}
		}
		for _, name := range names {
			if clientGoneForbiddenEvents[name] {
				t.Errorf("客户端断开不应写事件 %q (全部事件=%v)", name, names)
			}
		}
		if res.httpCode == http.StatusServiceUnavailable || strings.Contains(res.body, guardrailDetectionUnavailableCode) {
			t.Errorf("客户端断开不应走 fail-closed 拒绝: http=%d body=%q", res.httpCode, res.body)
		}
		if want.metricGone {
			if got := e.metrics.Snapshot()["security_check_failed"]; got != 0 {
				t.Errorf("客户端断开不应累加 security_check_failed 指标, got %d", got)
			}
		}
		e.probe.require(t, "db.finalize")
		return
	}
	if last.status != want.status || last.code != want.code {
		t.Errorf("对照组收尾=%s/%d, want %s/%d (events=%v body=%q)", last.status, last.code, want.status, want.code, names, res.body)
	}
	for _, name := range want.events {
		if !containsString(names, name) {
			t.Errorf("对照组应写事件 %q, got %v", name, names)
		}
	}
	if len(want.anyOf) > 0 {
		found := false
		for _, name := range want.anyOf {
			found = found || containsString(names, name)
		}
		if !found {
			t.Errorf("对照组应至少写事件之一 %v, got %v", want.anyOf, names)
		}
	}
	if want.metricControl {
		if got := e.metrics.Snapshot()["security_check_failed"]; got == 0 {
			t.Errorf("对照组应累加 security_check_failed 指标, got 0")
		}
	}
}

func runGoneMatrix(t *testing.T, stage string, configs []goneConfig, fn func(t *testing.T, e *goneEnv, cfg goneConfig)) {
	t.Helper()
	for _, sc := range goneScenarios {
		for _, cfg := range configs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				fn(t, newGoneEnv(t, sc, cfg, stage), cfg)
			})
		}
	}
}
