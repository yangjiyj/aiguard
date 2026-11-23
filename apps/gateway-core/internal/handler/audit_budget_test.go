package handler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 审计写库的预算不能被前置的慢操作挤占：
//  1. FinalizeRequestLog 里先同步跑的配额结算（最长 12s）不能耗尽后面 INSERT 的限时；
//  2. 批量内容日志写失败后逐条回退，总耗时必须受同一个整体预算约束，而不是 (N+1) 个限时。

// shrinkAuditTimeout 临时调小审计写入限时让测试变快，Cleanup 恢复。
func shrinkAuditTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := auditWriteTimeout
	auditWriteTimeout = d
	t.Cleanup(func() { auditWriteTimeout = old })
}

// ---- 重要 1：配额结算不挤占审计写库预算 ----

func TestRealAuditWriter_SlowQuotaFinalizeDoesNotStarveRequestLogInsert(t *testing.T) {
	const timeout = 80 * time.Millisecond
	shrinkAuditTimeout(t, timeout)

	probe := &ctxProbe{}
	writer := &RealAuditWriter{db: &ctxRecordingDB{probe: probe}}
	envelope := detachTestEnvelope("req-slow-quota")
	envelope.QuotaAdmissionManaged = true
	var quotaCtxValue atomic.Value
	envelope.QuotaFinalize = func(ctx context.Context, _, _ int64, _, _ bool) error {
		quotaCtxValue.Store(ctx.Value(detachProbeKey{}))
		// 模拟 Redis 慢：阻塞到超过审计写入限时（生产里最长约 12s，大于 10s）。
		time.Sleep(timeout + 60*time.Millisecond)
		return nil
	}

	writer.FinalizeRequestLog(canceledRequestCtx(), envelope, nil, "client_canceled", 0, 30, nil)

	if got := quotaCtxValue.Load(); got != detachProbeMarker {
		t.Errorf("QuotaFinalize 收到的 ctx 丢了 context value: %v", got)
	}
	// 配额结算耗时已超过 auditWriteTimeout，INSERT 仍要拿到全新、未过期、有限时的 ctx。
	probe.require(t, "db.exec")
	probe.mu.Lock()
	defer probe.mu.Unlock()
	for _, o := range probe.obs {
		if o.label == "db.exec" && errors.Is(o.err, context.DeadlineExceeded) {
			t.Fatalf("request_logs INSERT 收到已过期的 ctx（被配额结算吃掉了预算）: %v", o.err)
		}
	}
}

// ---- 重要 2：批量回退总耗时有界 ----

// blockingDB 的 Exec 一直阻塞到 ctx 结束，并记录每次调用的返回时机。
type blockingDB struct {
	mu    sync.Mutex
	calls int
}

func (d *blockingDB) Exec(ctx context.Context, _ string, _ ...interface{}) (execResult, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRealAuditWriter_ContentLogsBatchFallbackSharesOneBudget(t *testing.T) {
	const timeout = 120 * time.Millisecond
	shrinkAuditTimeout(t, timeout)

	db := &blockingDB{}
	writer := &RealAuditWriter{db: db}
	entries := []ContentLogEntry{
		{Role: "user", Content: "一", MessageIndex: 0},
		{Role: "assistant", Content: "二", MessageIndex: 1},
		{Role: "user", Content: "三", MessageIndex: 2},
	}

	started := time.Now()
	writer.WriteContentLogsBatch(canceledRequestCtx(), detachTestEnvelope("req-batch-block"), entries)
	elapsed := time.Since(started)

	// 主断言（确定性）：数据库一直卡住，批量写耗尽预算后不应再逐条回退写库。
	db.mu.Lock()
	calls := db.calls
	db.mu.Unlock()
	if calls != 1 {
		t.Fatalf("预算耗尽后不应再逐条回退写库: db.Exec 调用 %d 次，想要 1 次", calls)
	}
	// 辅助断言：总耗时约等于一个限时，而不是 (N+1) 个；余量放宽到 2 倍以免机器慢时偶发失败。
	if limit := timeout * 2; elapsed > limit {
		t.Fatalf("批量写 + 逐条回退总耗时 %v 超过整体预算 %v（应不超过约一个 auditWriteTimeout=%v）", elapsed, limit, timeout)
	}
}

// 批量写立刻失败（预算还没耗尽），逐条回退时每条 Exec 都带上调用方的 ctx：
// 三条回退必须共用批量入口那一个 ctx（同一个 deadline），而不是各自重新计时。
type failFirstThenRecordDB struct {
	mu        sync.Mutex
	calls     int
	deadlines []time.Time
}

func (d *failFirstThenRecordDB) Exec(ctx context.Context, _ string, _ ...interface{}) (execResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	deadline, _ := ctx.Deadline()
	d.deadlines = append(d.deadlines, deadline)
	if d.calls == 1 {
		return nil, errors.New("batch insert failed")
	}
	return &mockExecResult{rowsAffected: 1}, nil
}

func TestRealAuditWriter_ContentLogsBatchFallbackReusesBatchContext(t *testing.T) {
	db := &failFirstThenRecordDB{}
	writer := &RealAuditWriter{db: db}
	entries := []ContentLogEntry{
		{Role: "user", Content: "一", MessageIndex: 0},
		{Role: "assistant", Content: "二", MessageIndex: 1},
		{Role: "user", Content: "三", MessageIndex: 2},
	}

	writer.WriteContentLogsBatch(canceledRequestCtx(), detachTestEnvelope("req-batch-reuse"), entries)

	db.mu.Lock()
	defer db.mu.Unlock()
	if db.calls != 1+len(entries) {
		t.Fatalf("db.Exec 调用 %d 次，想要 1 次批量 + %d 次逐条回退", db.calls, len(entries))
	}
	for i, d := range db.deadlines {
		if d.IsZero() {
			t.Fatalf("第 %d 次写入没有限时", i)
		}
		if !d.Equal(db.deadlines[0]) {
			t.Fatalf("第 %d 次写入的 deadline %v 与批量入口 %v 不同：逐条回退重新计时了", i, d, db.deadlines[0])
		}
	}
}
