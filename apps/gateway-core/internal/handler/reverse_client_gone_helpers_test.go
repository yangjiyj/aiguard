package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

// 本文件是「反向代理：安全检测期间客户端断开」系列测试（reverse_client_gone_*_test.go）的夹具。
//
// 场景：Claude Code 按 Esc、Codex 中断时，请求 ctx 被取消，安全引擎调用随之返回 context.Canceled。
// 这不是检测失败，反代必须记 cancelled/408，不写 security_check_failed / incomplete，不入重试队列，
// 不走 fail-closed 的 503。对照组（引擎 500、连接拒绝、检测超时、引擎内部 cancel 而请求 ctx 仍然存活）
// 行为必须保持原样。
//
// 命名约定：helper 与类型统一用 rcg 前缀，避免和 client_gone_security_* 系列冲突。

const (
	rcgAllowJSON = `{"action":"allow","inspection_status":"completed","engine_build":"rcg","findings":[]}`

	// 单分组（只有最新 user）与双分组（system + user，配合 rcgClient 的全量检测范围）的 chat 请求。
	rcgChatRequest  = `{"model":"m","messages":[{"role":"user","content":"hello client gone"}]}`
	rcgMultiRequest = `{"model":"m","messages":[{"role":"system","content":"you are a helper"},{"role":"user","content":"hello client gone"}]}`
	rcgChatResponse = `{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"upstream answer text"},"finish_reason":"stop"}]}`
	rcgSSEDone      = "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
)

func rcgSSEChunk(content string) string {
	raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": content}}}})
	return "data: " + string(raw) + "\n\n"
}

// rcgSmallSSE 太短，流中不会触发增量扫描，只有流末 checkStreamInspection 会扫。
func rcgSmallSSE() string { return rcgSSEChunk("hello stream") + rcgSSEDone }

// rcgBigSSE 的单个 delta 超过 1021 字节，livePendingOutput 会在流中立刻触发一次增量扫描。
func rcgBigSSE() string { return rcgSSEChunk(strings.Repeat("a", 1500)) + rcgSSEDone }

type rcgKind int

const (
	// rcgKindBlock：引擎收到请求后一直阻塞，直到网关侧放弃（请求 ctx 被取消，或检测自己的超时到期）。
	rcgKindBlock rcgKind = iota
	// rcgKindHTTP500：引擎返回 500。
	rcgKindHTTP500
	// rcgKindRefused：目标阶段的引擎调用连接被拒（只作用于出故障的阶段，另一阶段仍正常返回 allow）。
	rcgKindRefused
	// rcgKindInternalCancel：引擎调用返回 context.Canceled，但请求 ctx 仍然存活（引擎自己 cancel）。
	rcgKindInternalCancel
)

type rcgScenario struct {
	name string
	kind rcgKind
	// gone=true：引擎收到请求后，请求 ctx 被取消（客户端断开）；false 是对照组，行为必须保持原样。
	gone bool
	// timeout=true：把检测自己的超时调小，让它在引擎阻塞期间到期（DeadlineExceeded）。
	timeout bool
}

var rcgScenarios = []rcgScenario{
	{name: "client_gone", kind: rcgKindBlock, gone: true},
	{name: "engine_500", kind: rcgKindHTTP500},
	{name: "engine_refused", kind: rcgKindRefused},
	{name: "engine_timeout", kind: rcgKindBlock, timeout: true},
	{name: "engine_internal_cancel", kind: rcgKindInternalCancel},
}

type rcgConfig struct {
	name                  string
	auditOnly, failClosed bool
}

// rcgConfigs 覆盖「护栏失败」的四种有效组合。record_failclosed 是不变量：只审计模式即便
// 打开了 fail-closed 也永不拦截。
var rcgConfigs = []rcgConfig{
	{"protect", false, false},
	{"protect_failclosed", false, true},
	{"record", true, false},
	{"record_failclosed", true, true},
}

// enforcing 表示这套配置下「检测失败」会被 fail-closed 拒绝（503）。
func (c rcgConfig) enforcing() bool { return !c.auditOnly && c.failClosed }

// rcgClient 在 failClosedClient 之上放开检测范围（系统提示、历史也检），让 chat 请求能分成多个分组。
func rcgClient(t *testing.T, auditOnly, failClosed bool) *ToolRiskClient {
	t.Helper()
	client := failClosedClient(t, auditOnly, failClosed)
	policy := inspectionscope.Default()
	policy.InspectBuiltinContext = true
	policy.InspectHistory = true
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: "00000000000000000000000000000000", Enabled: true, InputEnabled: true, AgentEnabled: true,
		SecurityAuditOnly: auditOnly, SecurityExecutionModeManaged: true, GuardrailFailClosedEnabled: failClosed,
		InspectionPolicy: &policy,
	})
	return client
}

// rcgEngine 是脚本化的假安全引擎。stage 指定出故障的检测阶段（/check-input/ 或 /check-output/），
// 其余阶段一律返回 allow。calls 统计的是客户端侧的调用尝试次数（包含 ctx 已取消、请求根本没发出去的
// 那几次），这样「断开后还继续扫下一组」才测得出来。
type rcgEngine struct {
	kind    rcgKind
	stage   string
	server  *httptest.Server
	entered chan struct{}
	once    sync.Once

	mu       sync.Mutex
	attempts map[string]int
}

func newRCGEngine(t *testing.T, kind rcgKind, stage string) *rcgEngine {
	t.Helper()
	e := &rcgEngine{kind: kind, stage: stage, entered: make(chan struct{}), attempts: map[string]int{}}
	e.server = httptest.NewServer(http.HandlerFunc(e.handle))
	t.Cleanup(e.server.Close)
	return e
}

func (e *rcgEngine) handle(w http.ResponseWriter, r *http.Request) {
	// 先读完请求体：服务端只有读到 EOF 后才会监测客户端断开并取消 r.Context()。
	_, _ = io.Copy(io.Discard, r.Body)
	if r.URL.Path == e.stage {
		switch e.kind {
		case rcgKindHTTP500:
			http.Error(w, "engine exploded", http.StatusInternalServerError)
			return
		case rcgKindBlock:
			e.once.Do(func() { close(e.entered) })
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, rcgAllowJSON)
}

type rcgTransport struct {
	e    *rcgEngine
	base *http.Transport
}

func (tr *rcgTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.e.mu.Lock()
	tr.e.attempts[req.URL.Path]++
	tr.e.mu.Unlock()
	if req.URL.Path == tr.e.stage {
		switch tr.e.kind {
		case rcgKindInternalCancel:
			// 引擎侧自己 cancel：返回 Canceled，但请求 ctx 仍然存活。
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, context.Canceled
		case rcgKindRefused:
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: errors.New("dial tcp 127.0.0.1:9: connect: connection refused")}
		}
	}
	return tr.base.RoundTrip(req)
}

func (e *rcgEngine) client(t *testing.T) *http.Client {
	t.Helper()
	base := &http.Transport{}
	t.Cleanup(base.CloseIdleConnections)
	return &http.Client{Transport: &rcgTransport{e: e, base: base}}
}

func (e *rcgEngine) calls(path string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attempts[path]
}

// rcgQueue 是假的持久化重试队列：只记录入队次数，不依赖 Postgres。
type rcgQueue struct {
	mu    sync.Mutex
	paths []string
}

func (q *rcgQueue) enqueue(_, path string, _ []byte, _ ...bool) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.paths = append(q.paths, path)
	return fmt.Sprintf("rcg-task-%d", len(q.paths)), nil
}

func (q *rcgQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.paths)
}

// rcgRecorder 在 fakeReverseProxyAuditRecorder 之上记录每次审计写入时 ctx 是否已被取消：
// 收尾写库必须脱离请求取消（context.WithoutCancel），否则断开后 request_logs 会停在 received。
type rcgRecorder struct {
	fakeReverseProxyAuditRecorder
	ctxErrs []error
}

func (r *rcgRecorder) WriteReverseProxyAccess(ctx context.Context, record reverseProxyAuditRecord) {
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	r.fakeReverseProxyAuditRecorder.WriteReverseProxyAccess(ctx, record)
}

func (r *rcgRecorder) WriteReverseProxyContent(ctx context.Context, record reverseProxyAuditRecord, requestBody []byte, requestContentType string, responseBody []byte, responseContentType string) {
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	r.fakeReverseProxyAuditRecorder.WriteReverseProxyContent(ctx, record, requestBody, requestContentType, responseBody, responseContentType)
}

func (r *rcgRecorder) WriteReverseProxySecurityEvent(ctx context.Context, record reverseProxyAuditRecord, stage, actionTaken string, findings []SecurityFinding) {
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	r.fakeReverseProxyAuditRecorder.WriteReverseProxySecurityEvent(ctx, record, stage, actionTaken, findings)
}

type rcgEnv struct {
	t             *testing.T
	h             *ReverseProxyHandler
	engine        *rcgEngine
	audit         *rcgRecorder
	queue         *rcgQueue
	upstream      *httptest.Server
	upstreamCalls *atomic.Int64
	route         *ReverseProxyRoute
	ctx           context.Context
	cancel        context.CancelFunc
	sc            rcgScenario
	cfg           rcgConfig
}

// newRCGEnv 搭一个反代 + 假引擎 + 假上游。stage 是引擎出故障的检测阶段；上游固定回 upstreamBody。
// gone 场景下，引擎收到请求后会自动取消请求 ctx（模拟客户端断开）。
func newRCGEnv(t *testing.T, sc rcgScenario, cfg rcgConfig, stage, upstreamContentType, upstreamBody string) *rcgEnv {
	t.Helper()
	if sc.timeout {
		t.Setenv("SECURITY_ENGINE_TIMEOUT", "150ms")
	}
	engine := newRCGEngine(t, sc.kind, stage)
	calls := &atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", upstreamContentType)
		_, _ = io.WriteString(w, upstreamBody)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(upstream.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if sc.gone {
		go func() {
			select {
			case <-engine.entered:
			case <-time.After(10 * time.Second):
			}
			cancel()
		}()
	}
	audit := &rcgRecorder{}
	queue := &rcgQueue{}
	h := &ReverseProxyHandler{
		tenantID: "tenant_default", securityURL: engine.server.URL, client: engine.client(t),
		runtimeConfigClient: rcgClient(t, cfg.auditOnly, cfg.failClosed),
		resolveEgressTarget: testEgressResolver(upstream.URL), auditRecorder: audit, retryQueue: queue,
	}
	route := &ReverseProxyRoute{ID: "rcg", PathPrefix: "/proxy", TargetURL: upstream.URL + "/v1/chat/completions", SecurityEnabled: true, Status: "active"}
	return &rcgEnv{t: t, h: h, engine: engine, audit: audit, queue: queue, upstream: upstream, upstreamCalls: calls,
		route: route, ctx: ctx, cancel: cancel, sc: sc, cfg: cfg}
}

// setTargetPath 把路由目标路径换成别的（例如非 chat 端点），用于覆盖通用扫描分支。
func (e *rcgEnv) setTargetPath(path string) {
	e.route.TargetURL = e.upstream.URL + path
}

// forward 把请求打进 forwardRequest（和 ServeHTTP 同一入口，去掉路由匹配与 502 兜底）。
func (e *rcgEnv) forward(body string) (*httptest.ResponseRecorder, error) {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(body)).WithContext(e.ctx)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	err := e.h.forwardRequest(e.ctx, e.route, w, r)
	return w, err
}

func (e *rcgEnv) lastRecord() reverseProxyAuditRecord {
	e.t.Helper()
	if len(e.audit.records) == 0 {
		e.t.Fatalf("没有写入任何审计记录")
	}
	return e.audit.records[len(e.audit.records)-1]
}

// incompleteEvents 统计某阶段「语义检测未完成」类安全事件（对应 security_check_failed）。
func (e *rcgEnv) incompleteEvents(stage string) int {
	n := 0
	for _, ev := range e.audit.securityEvents {
		if ev.stage != stage {
			continue
		}
		status := ev.record.InputSemanticStatus
		if stage == "output" {
			status = ev.record.OutputSemanticStatus
		}
		if status == "incomplete" {
			n++
		}
	}
	return n
}

// requireCleanGone 校验「客户端断开」的统一结果：408 cancelled、没有任何误标事件、没有 fail-closed 拒绝。
func (e *rcgEnv) requireCleanGone(w *httptest.ResponseRecorder, err error) {
	e.t.Helper()
	if err != nil {
		e.t.Errorf("forwardRequest 返回了错误 %v（断开应干净结束）", err)
	}
	rec := e.lastRecord()
	if w.Code != http.StatusRequestTimeout {
		e.t.Errorf("http=%d, want 408 (body=%q)", w.Code, w.Body.String())
	}
	if rec.Status != "cancelled" || rec.StatusCode != http.StatusRequestTimeout {
		e.t.Errorf("审计状态=%s/%d, want cancelled/408", rec.Status, rec.StatusCode)
	}
	if rec.InputSemanticStatus == "incomplete" || rec.OutputSemanticStatus == "incomplete" {
		e.t.Errorf("断开不应记 incomplete: input=%q output=%q", rec.InputSemanticStatus, rec.OutputSemanticStatus)
	}
	if len(e.audit.securityEvents) != 0 {
		e.t.Errorf("断开不应写安全事件: %+v", e.audit.securityEvents)
	}
	if w.Code == http.StatusServiceUnavailable || w.Code == http.StatusForbidden || strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
		e.t.Errorf("断开不应走 fail-closed/拦截: http=%d body=%q", w.Code, w.Body.String())
	}
}

// requireNothingForwarded 校验断开时：上游未被调用（输入侧）、没有任何东西入重试队列。
func (e *rcgEnv) requireNothingForwarded() {
	e.t.Helper()
	if got := e.upstreamCalls.Load(); got != 0 {
		e.t.Errorf("断开后不应转发上游, upstream calls=%d", got)
	}
	e.requireNoRetryQueued()
}

func (e *rcgEnv) requireNoRetryQueued() {
	e.t.Helper()
	if got := e.queue.count(); got != 0 {
		e.t.Errorf("断开不应入重试队列, queued=%d", got)
	}
}

// requireDetachedAuditWrites 校验每次审计写入时 ctx 都没有被取消。
func (e *rcgEnv) requireDetachedAuditWrites() {
	e.t.Helper()
	if len(e.audit.ctxErrs) == 0 {
		e.t.Errorf("没有任何审计写入")
	}
	for _, err := range e.audit.ctxErrs {
		if err != nil {
			e.t.Errorf("审计写入的 ctx 已被取消: %v（收尾写库必须脱离请求取消）", err)
		}
	}
}

// requireFailureUnchanged 校验对照组（引擎真的检测失败，请求 ctx 没取消）的行为与修复前一致。
// stage 是出故障的阶段：input 时 enforcing 配置在转发前 503；output 时 enforcing 配置在回包前 503。
func (e *rcgEnv) requireFailureUnchanged(w *httptest.ResponseRecorder, err error, stage string, wantQueued int) {
	e.t.Helper()
	rec := e.lastRecord()
	if got := e.incompleteEvents(stage); got != 1 {
		e.t.Errorf("对照组应写 1 条 %s 阶段 incomplete 事件, got %d (events=%+v)", stage, got, e.audit.securityEvents)
	}
	if got := e.queue.count(); got != wantQueued {
		e.t.Errorf("对照组应入重试队列 %d 次, got %d", wantQueued, got)
	}
	if e.cfg.enforcing() {
		if err != nil {
			e.t.Errorf("fail-closed 拒绝不应返回错误: %v", err)
		}
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
			e.t.Errorf("fail-closed 下应 503 %s, got http=%d body=%q", guardrailDetectionUnavailableCode, w.Code, w.Body.String())
		}
		if rec.Status != "blocked" || rec.StatusCode != http.StatusServiceUnavailable {
			e.t.Errorf("审计状态=%s/%d, want blocked/503", rec.Status, rec.StatusCode)
		}
		return
	}
	if err != nil {
		e.t.Errorf("放行场景不应返回错误: %v", err)
	}
	if w.Code != http.StatusOK || rec.Status != "success" {
		e.t.Errorf("非 fail-closed 配置应放行: http=%d status=%s body=%q", w.Code, rec.Status, w.Body.String())
	}
	if e.cfg.auditOnly && (w.Code == http.StatusServiceUnavailable || w.Code == http.StatusForbidden) {
		e.t.Errorf("只审计模式绝不能拦截: http=%d", w.Code)
	}
}

// stream 直接驱动 copyGuardedReverseSSE，返回 (写给客户端的内容, received, decision, blocked, err)。
func (e *rcgEnv) stream(sse string) (*httptest.ResponseRecorder, int64, reverseProxySecurityDecision, bool, error) {
	e.t.Helper()
	return e.streamFrom(e.ctx, strings.NewReader(sse))
}

func (e *rcgEnv) streamFrom(ctx context.Context, body io.Reader) (*httptest.ResponseRecorder, int64, reverseProxySecurityDecision, bool, error) {
	e.t.Helper()
	w := httptest.NewRecorder()
	capture := &headTailReverseProxyCapture{limit: maxReverseProxyRetainedBodyBytes}
	n, d, blocked, err := e.h.copyGuardedReverseSSE(ctx, w, body, capture, "req-rcg", "api.openai.com", "/v1/chat/completions")
	return w, n, d, blocked, err
}
