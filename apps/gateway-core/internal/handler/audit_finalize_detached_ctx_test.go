package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 客户端断开会取消 r.Context()。请求收尾（审计落库、计费结算、计费结果标记）
// 必须脱离这个取消，否则 request_logs 会停在 received、计费收尾丢失。
// 本文件的用例统一用“已取消且带自定义值”的 ctx 调用各层 writer，断言下游收到的 ctx：
// 未取消、有限时、值仍可读。

type detachProbeKey struct{}

const detachProbeMarker = "tenant-marker"

type ctxObservation struct {
	label       string
	err         error
	hasDeadline bool
	marker      any
}

type ctxProbe struct {
	mu  sync.Mutex
	obs []ctxObservation
}

func (p *ctxProbe) record(label string, ctx context.Context) {
	_, hasDeadline := ctx.Deadline()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.obs = append(p.obs, ctxObservation{label: label, err: ctx.Err(), hasDeadline: hasDeadline, marker: ctx.Value(detachProbeKey{})})
}

// require 要求每个 label 至少被观察到一次，且每次观察到的 ctx 都满足脱离取消的约束。
func (p *ctxProbe) require(t *testing.T, labels ...string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, label := range labels {
		seen := false
		for _, o := range p.obs {
			if o.label != label {
				continue
			}
			seen = true
			if o.err != nil {
				t.Errorf("%s 收到的 ctx 已被取消: %v", label, o.err)
			}
			if !o.hasDeadline {
				t.Errorf("%s 收到的 ctx 没有限时，收尾写入可能无限挂起", label)
			}
			if o.marker != detachProbeMarker {
				t.Errorf("%s 收到的 ctx 丢了 context value: got %v", label, o.marker)
			}
		}
		if !seen {
			t.Errorf("%s 没有被调用", label)
		}
	}
}

// canceledRequestCtx 模拟客户端已断开的请求上下文：已取消，且带一个 context value
// （detachProbeKey -> detachProbeMarker）。与 model_route_execution_test.go 里的
// canceledContext 不同：那个只是已取消、不带任何 value，无法验证脱离取消后 value 仍可读。
func canceledRequestCtx() context.Context {
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
	cancel()
	return ctx
}

type ctxRecordingDB struct {
	probe *ctxProbe
}

func (d *ctxRecordingDB) RecalculateSecurityOccurrences(ctx context.Context, _, _ string) error {
	d.probe.record("db.recalc", ctx)
	return nil
}

func (d *ctxRecordingDB) Exec(ctx context.Context, _ string, _ ...interface{}) (execResult, error) {
	d.probe.record("db.exec", ctx)
	return &mockExecResult{rowsAffected: 1}, nil
}

type ctxRecordingAuditWriter struct {
	MockAuditWriter
	probe *ctxProbe
}

func (w *ctxRecordingAuditWriter) FinalizeRequestLog(ctx context.Context, e *modelrouter.RequestEnvelope, body []byte, status string, code int, latency int, result *AuditResult) {
	w.probe.record("inner.finalize", ctx)
	w.MockAuditWriter.FinalizeRequestLog(ctx, e, body, status, code, latency, result)
}

func (w *ctxRecordingAuditWriter) MarkBillingOutcome(ctx context.Context, _ *modelrouter.RequestEnvelope, _ string) {
	w.probe.record("inner.mark", ctx)
}

func (w *ctxRecordingAuditWriter) PersistBillingRoute(ctx context.Context, _ *modelrouter.RequestEnvelope) error {
	w.probe.record("inner.route", ctx)
	return nil
}

func detachTestEnvelope(requestID string) *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{
		RequestID:    requestID,
		TenantID:     "tenant-detach",
		ProjectID:    "proj-detach",
		EndpointType: "chat",
	}
}

func TestRealAuditWriter_FinalizeRequestLogDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	writer := &RealAuditWriter{db: &ctxRecordingDB{probe: probe}}

	writer.FinalizeRequestLog(canceledRequestCtx(), detachTestEnvelope("req-detach-real-finalize"), nil, "client_canceled", 0, 30, nil)

	probe.require(t, "db.exec")
}

func TestRealAuditWriter_MarkBillingOutcomeDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	writer := &RealAuditWriter{db: &ctxRecordingDB{probe: probe}}

	writer.MarkBillingOutcome(canceledRequestCtx(), detachTestEnvelope("req-detach-real-mark"), "settled")

	probe.require(t, "db.exec")
}

// AsyncAuditWriter 的 Finalize/MarkBillingOutcome 只转发，脱离取消由内层 RealAuditWriter 负责。
// 所以这里按真实组装（Async 包 Real）断言“最终落到 db 的 ctx”。
func TestAsyncAuditWriter_FinalizeRequestLogDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	writer := NewAsyncAuditWriter(&RealAuditWriter{db: &ctxRecordingDB{probe: probe}}, &fakeOutboxEnqueuer{})

	writer.FinalizeRequestLog(canceledRequestCtx(), detachTestEnvelope("req-detach-async-finalize"), nil, "client_canceled", 0, 30, nil)

	probe.require(t, "db.exec")
}

func TestAsyncAuditWriter_MarkBillingOutcomeDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	writer := NewAsyncAuditWriter(&RealAuditWriter{db: &ctxRecordingDB{probe: probe}}, &fakeOutboxEnqueuer{})

	writer.MarkBillingOutcome(canceledRequestCtx(), detachTestEnvelope("req-detach-async-mark"), "settled")

	probe.require(t, "db.exec")
}

// 直连计费请求：客户端断开后，结算仍要发出，审计落库与结果标记都用脱离取消的 ctx。
func TestBillingAuditWriter_FinalizeRequestLogDetachesFromRequestCancel(t *testing.T) {
	var settlements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements":
			settlements.Add(1)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-detach", UserID: "user-detach", RequestID: "req-detach-billing", Model: "model-a"}
	if err := client.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 12, OutputTokens: 4}); err != nil {
		t.Fatal(err)
	}
	probe := &ctxProbe{}
	inner := &ctxRecordingAuditWriter{probe: probe}
	writer := NewBillingAuditWriter(inner, client)

	writer.FinalizeRequestLog(canceledRequestCtx(), envelope, []byte(`{"id":"chatcmpl-detach"}`), "success", http.StatusOK, 10, nil)

	if got := settlements.Load(); got != 1 {
		t.Fatalf("settlement calls=%d, want 1（客户端取消后计费结算仍须发出）", got)
	}
	if len(inner.RequestLogFinalizes) != 1 {
		t.Fatalf("inner finalize calls=%d, want 1", len(inner.RequestLogFinalizes))
	}
	probe.require(t, "inner.route", "inner.finalize", "inner.mark")
}

// 非直连计费（反向代理入口）走提前返回分支，同样要脱离取消。
func TestBillingAuditWriter_NonDirectFinalizeDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	inner := &ctxRecordingAuditWriter{probe: probe}
	writer := NewBillingAuditWriter(inner, nil)
	envelope := detachTestEnvelope("req-detach-billing-nondirect")
	envelope.BillingIngress = "reverse_proxy"

	writer.FinalizeRequestLog(canceledRequestCtx(), envelope, nil, "client_canceled", 0, 30, nil)

	probe.require(t, "inner.finalize")
}

// 收尾的限时应是有界的：不能因为请求 ctx 的取消而丢失，也不能无限等待。
func TestDetachAuditContext_BoundedAndKeepsValues(t *testing.T) {
	ctx, cancel := detachAuditContext(canceledRequestCtx())
	defer cancel()

	if ctx.Err() != nil {
		t.Fatalf("ctx 不应继承取消: %v", ctx.Err())
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("ctx 应有限时")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > auditWriteTimeout {
		t.Fatalf("剩余限时=%v，应在 (0, %v] 内", remaining, auditWriteTimeout)
	}
	if ctx.Value(detachProbeKey{}) != detachProbeMarker {
		t.Fatal("ctx value 丢失")
	}
}
