package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

// 原则：任何审计/留证写入都不依赖客户端连接是否还在。
// 本文件把 audit_finalize_detached_ctx_test.go 的断言推广到收尾之外的全部审计写入：
// 安全事件、内容日志、保留上下文、会话、triage、入队，以及处理器层的内容日志/用量记录。

// ---- 记录 ctx 的假实现 ----

func (w *ctxRecordingAuditWriter) WriteSecurityEvent(ctx context.Context, _ *modelrouter.RequestEnvelope, _ []SecurityFinding, _, _ string) {
	w.probe.record("inner.security", ctx)
}

func (w *ctxRecordingAuditWriter) WriteContentLog(ctx context.Context, _ *modelrouter.RequestEnvelope, _, _ string, _ int) {
	w.probe.record("inner.content", ctx)
}

func (w *ctxRecordingAuditWriter) WriteRetentionTurnContext(ctx context.Context, _ *modelrouter.RequestEnvelope, _ []byte) {
	w.probe.record("inner.retention", ctx)
}

type ctxRecordingOutbox struct {
	probe *ctxProbe
}

func (o *ctxRecordingOutbox) Enqueue(ctx context.Context, _ eventbus.Event) error {
	o.probe.record("outbox.enqueue", ctx)
	return nil
}

type ctxRecordingProxyUsage struct {
	probe *ctxProbe
}

func (r *ctxRecordingProxyUsage) RecordProxyUsage(ctx context.Context, _ string, _, _ int) error {
	r.probe.record("proxy.usage", ctx)
	return nil
}

// ---- RealAuditWriter：每个写库方法 ----

func TestRealAuditWriter_AuditWritesDetachFromRequestCancel(t *testing.T) {
	findings := []SecurityFinding{{Type: "pii", Severity: "high", Category: "dlp"}}
	triaged := []SecurityFinding{{RuleID: "rule-1", MatchedLocation: "msg", Triage: map[string]any{"verdict": "fp"}}}
	cases := []struct {
		name   string
		labels []string
		call   func(w *RealAuditWriter, ctx context.Context)
	}{
		{"WriteSecurityEvent", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.WriteSecurityEvent(ctx, detachTestEnvelope("req-sec"), findings, "security_audit", "摘要")
		}},
		{"RecordSecurityEventOccurrence", []string{"db.exec", "db.recalc"}, func(w *RealAuditWriter, ctx context.Context) {
			_ = w.RecordSecurityEventOccurrence(ctx, detachTestEnvelope("req-occ"), "evt-1", "ctx-key")
		}},
		{"AnnotateTriage", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.AnnotateTriage(ctx, detachTestEnvelope("req-triage"), triaged)
		}},
		{"WriteContentLog", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.WriteContentLog(ctx, detachTestEnvelope("req-cl"), "assistant", "你好", 3)
		}},
		{"WriteContentLogAnchored", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.WriteContentLogAnchored(ctx, detachTestEnvelope("req-cla"), "user", "你好", 3, 1)
		}},
		{"WriteContentLogsBatch", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.WriteContentLogsBatch(ctx, detachTestEnvelope("req-batch"), []ContentLogEntry{
				{Role: "user", Content: "问", Tokens: 1, MessageIndex: 0},
				{Role: "assistant", Content: "答", Tokens: 1, MessageIndex: 1},
			})
		}},
		{"WriteRetentionTurnContext", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.WriteRetentionTurnContext(ctx, detachTestEnvelope("req-ret"), []byte(`{"version":1}`))
		}},
		{"UpsertAgentSession", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			e := detachTestEnvelope("req-sess")
			e.SessionID = "sess-detach"
			w.UpsertAgentSession(ctx, e)
		}},
		{"BackfillRequestAgentType", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.BackfillRequestAgentType(ctx, "tenant-detach", "req-bf", "claude-code")
		}},
		{"EnsureRequestLog", []string{"db.exec"}, func(w *RealAuditWriter, ctx context.Context) {
			w.EnsureRequestLog(ctx, detachTestEnvelope("req-ensure"))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probe := &ctxProbe{}
			c.call(&RealAuditWriter{db: &ctxRecordingDB{probe: probe}}, canceledRequestCtx())
			probe.require(t, c.labels...)
		})
	}
}

// ---- AsyncAuditWriter：outbox 入队 ----

func TestAsyncAuditWriter_EnqueueDetachesFromRequestCancel(t *testing.T) {
	findings := []SecurityFinding{{Type: "pii", Severity: "high", Category: "dlp"}}
	cases := []struct {
		name string
		call func(w *AsyncAuditWriter, ctx context.Context)
	}{
		{"WriteSecurityEvent", func(w *AsyncAuditWriter, ctx context.Context) {
			w.WriteSecurityEvent(ctx, asyncAuditTestEnvelope(), findings, "security_audit", "摘要")
		}},
		{"WriteContentLog", func(w *AsyncAuditWriter, ctx context.Context) {
			w.WriteContentLog(ctx, asyncAuditTestEnvelope(), "assistant", "你好", 3)
		}},
		{"WriteContentLogAnchored", func(w *AsyncAuditWriter, ctx context.Context) {
			w.WriteContentLogAnchored(ctx, asyncAuditTestEnvelope(), "user", "你好", 3, 1)
		}},
		{"WriteContentLogsBatch", func(w *AsyncAuditWriter, ctx context.Context) {
			w.WriteContentLogsBatch(ctx, asyncAuditTestEnvelope(), []ContentLogEntry{{Role: "user", Content: "问", MessageIndex: 0}})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probe := &ctxProbe{}
			c.call(NewAsyncAuditWriter(&fakeSyncAuditWriter{}, &ctxRecordingOutbox{probe: probe}), canceledRequestCtx())
			probe.require(t, "outbox.enqueue")
		})
	}
}

// ---- 处理器层：内容日志、保留上下文、代理用量 ----

const detachChatResponse = `{"id":"chatcmpl-detach","object":"chat.completion","created":1716399600,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"phone 13800000000"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":12,"total_tokens":22}}`

func TestChatHandler_WriteResponseContentLogsDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	h := &ChatCompletionsHandler{auditWriter: &ctxRecordingAuditWriter{probe: probe}}

	h.writeResponseContentLogs(canceledRequestCtx(), detachTestEnvelope("req-resp-logs"), []byte(detachChatResponse))

	probe.require(t, "inner.content", "inner.retention")
}

func TestChatHandler_RecordProxyUsageDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	h := &ChatCompletionsHandler{proxyUsageRecorder: &ctxRecordingProxyUsage{probe: probe}}
	envelope := detachTestEnvelope("req-proxy-usage")
	envelope.ModelID = "model-detach"
	ctx := context.WithValue(canceledRequestCtx(), auth.ProxyRequestKey, true)

	h.recordProxyUsageIfNeeded(ctx, envelope, []byte(detachChatResponse))

	probe.require(t, "proxy.usage")
}

// 实时流 pending.finish 之后的 mask 不可解析告警走 h.writeSecurityEvent。
func TestChatHandler_WriteSecurityEventDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	h := &ChatCompletionsHandler{auditWriter: &RealAuditWriter{db: &ctxRecordingDB{probe: probe}}}

	h.writeSecurityEvent(withMaskUnavailable(withSecurityEventStage(canceledRequestCtx(), "output")), detachTestEnvelope("req-mask-unavailable"), nil,
		"security_audit", "live output mask could not be resolved; forwarded unmasked")

	probe.require(t, "db.exec")
}

// 回退事件窗口很小，但同样是审计写入。
func TestRecordFallbackEventDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	writer := &RealAuditWriter{db: &ctxRecordingDB{probe: probe}}

	recordFallbackEvent(canceledRequestCtx(), writer, detachTestEnvelope("req-fallback"), FallbackAttemptResult{Attempted: true, TriggerKind: "network"})

	probe.require(t, "db.exec")
}

// ---- 端到端：上游返回时客户端已断开 ----

type sqlObservation struct {
	query           string
	args            []interface{}
	ctxErr          error
	hasDeadline     bool
	afterClientGone bool
}

// sqlRecordingDB 像真实 pgx 一样：收到已取消的 ctx 就失败；同时记录每条语句与当时的 ctx 状态。
type sqlRecordingDB struct {
	mu         sync.Mutex
	clientGone *atomic.Bool
	obs        []sqlObservation
}

func (d *sqlRecordingDB) Exec(ctx context.Context, query string, args ...interface{}) (execResult, error) {
	_, hasDeadline := ctx.Deadline()
	d.mu.Lock()
	d.obs = append(d.obs, sqlObservation{query: query, args: args, ctxErr: ctx.Err(), hasDeadline: hasDeadline, afterClientGone: d.clientGone.Load()})
	d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &mockExecResult{rowsAffected: 1}, nil
}

// clientGoneProvider 在返回上游结果前让客户端断开（取消请求 ctx），模拟“上游慢、客户端读超时先走”。
type clientGoneProvider struct {
	MockProviderCaller
	cancel context.CancelFunc
	gone   *atomic.Bool
	fail   bool
}

func (p *clientGoneProvider) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	p.gone.Store(true)
	p.cancel()
	if p.fail {
		return nil, context.Canceled
	}
	return p.MockProviderCaller.Call(ctx, envelope, providerReq)
}

func (p *clientGoneProvider) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, providerReq []byte) ([]byte, error) {
	return p.Call(ctx, envelope, providerReq)
}

func runChatRequestWhereClientLeavesDuringUpstream(t *testing.T, upstreamFails bool) *sqlRecordingDB {
	t.Helper()
	gone := &atomic.Bool{}
	db := &sqlRecordingDB{clientGone: gone}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &clientGoneProvider{
		MockProviderCaller: MockProviderCaller{CallResponse: []byte(detachChatResponse)},
		cancel:             cancel, gone: gone, fail: upstreamFails,
	}
	security := &MockSecurityChecker{
		OutputAction: "mask", OutputMasked: "phone [MASKED]",
		OutputFindings: []SecurityFinding{{Type: "pii", Severity: "medium"}},
	}
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, security,
		&RealAuditWriter{db: db}, fixedAdapterFactory{caller: provider}, nil, nil)

	body, _ := json.Marshal(ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(setAuthInfo(base, "tenant-123", "project-123", "user-123", "key-123", ""))

	h.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if !gone.Load() {
		t.Fatal("上游没有被调用，用例没有走到客户端断开的场景")
	}
	return db
}

// requireWritesAfterClientGone 要求：客户端断开之后发出的每条写库语句 ctx 都未取消且有限时，
// 并且每一类审计语句都至少发出过一次（子串匹配 SQL）。
func (d *sqlRecordingDB) requireWritesAfterClientGone(t *testing.T, kinds map[string]string) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, o := range d.obs {
		if !o.afterClientGone {
			continue
		}
		head := strings.Join(strings.Fields(o.query), " ")
		if len(head) > 60 {
			head = head[:60]
		}
		if o.ctxErr != nil {
			t.Errorf("客户端断开后的写入收到已取消的 ctx（%v）: %s", o.ctxErr, head)
		}
		if !o.hasDeadline {
			t.Errorf("客户端断开后的写入没有限时: %s", head)
		}
	}
	for label, substr := range kinds {
		seen := false
		for _, o := range d.obs {
			if o.afterClientGone && strings.Contains(o.query, substr) {
				seen = true
			}
		}
		if !seen {
			t.Errorf("客户端断开之后没有发出 %s 写入（SQL 含 %q）", label, substr)
		}
	}
}

func (d *sqlRecordingDB) finalizeStatuses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, o := range d.obs {
		if !o.afterClientGone || !strings.Contains(o.query, "ON CONFLICT (request_id) DO UPDATE SET") {
			continue
		}
		for _, a := range o.args {
			if s, ok := a.(string); ok && (s == "success" || s == "client_canceled") {
				out = append(out, s)
			}
		}
	}
	return out
}

// 上游成功返回、此时客户端已断开：输出扫描产生的安全事件、内容日志、保留上下文和收尾记录
// 都必须落库，不能出现“有 success 行却没有内容日志”。
func TestChatCompletions_UpstreamReturnsAfterClientGone_AllAuditWritesLand(t *testing.T) {
	db := runChatRequestWhereClientLeavesDuringUpstream(t, false)

	db.requireWritesAfterClientGone(t, map[string]string{
		"收尾记录":  "ON CONFLICT (request_id) DO UPDATE SET",
		"安全事件":  "INSERT INTO security_events",
		"内容日志":  "INSERT INTO content_logs",
		"保留上下文": "retention_turn_context",
	})
	if got := db.finalizeStatuses(); len(got) == 0 || got[0] != "success" {
		t.Fatalf("收尾状态=%v，想要 success", got)
	}
}

// 上游因客户端取消而失败：必须记成 client_canceled，而不是停在 received。
func TestChatCompletions_ClientCanceledDuringUpstream_FinalizeLands(t *testing.T) {
	db := runChatRequestWhereClientLeavesDuringUpstream(t, true)

	db.requireWritesAfterClientGone(t, map[string]string{"收尾记录": "ON CONFLICT (request_id) DO UPDATE SET"})
	if got := db.finalizeStatuses(); len(got) == 0 || got[0] != "client_canceled" {
		t.Fatalf("收尾状态=%v，想要 client_canceled", got)
	}
}
