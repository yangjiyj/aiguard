package handler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// blockingRawEvidenceDB 模拟写库慢/挂死：Exec 阻塞到 release 关闭或 ctx 到期，并记录每次调用与时限。
type blockingRawEvidenceDB struct {
	mu        sync.Mutex
	calls     int
	full, ref int     // 写全文（含密文）与写引用行的次数
	refArgs   [][]any // 引用行的参数（核对它指向哪个请求、带哪个阻断编号）
	deadlines []time.Duration
	release   chan struct{}
	err       error
	refZero   bool // 引用 SQL 写 0 行（模拟首条已过保留期被删）
}

func (d *blockingRawEvidenceDB) Exec(ctx context.Context, query string, args ...interface{}) (execResult, error) {
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	d.calls++
	switch query {
	case rawEvidenceInsertSQL:
		d.full++
	case rawEvidenceRefInsertSQL:
		d.ref++
		d.refArgs = append(d.refArgs, args)
	}
	d.deadlines = append(d.deadlines, time.Until(deadline))
	refZero := d.refZero
	d.mu.Unlock()
	if d.release != nil {
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	if refZero && query == rawEvidenceRefInsertSQL {
		return &mockExecResult{rowsAffected: 0}, nil
	}
	return &mockExecResult{rowsAffected: 1}, nil
}

func (d *blockingRawEvidenceDB) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func rawEvidenceAsyncEnvelope(requestID, session string) *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{RequestID: requestID, TenantID: "tenant-async", SessionID: session, UserID: "u1"}
}

func setRawEvidenceTestKey(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "gateway-raw-evidence-async-secret-0123")
	t.Setenv("JJD_SECRETS_CIPHER", "")
}

// B-3：写库挂住时业务请求不等待；写库有自己的短时限，失败只记日志。
func TestRawEvidenceWriteDoesNotBlockRequestPath(t *testing.T) {
	setRawEvidenceTestKey(t)
	old := rawEvidenceWriteTimeout
	rawEvidenceWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { rawEvidenceWriteTimeout = old })

	db := &blockingRawEvidenceDB{release: make(chan struct{})} // 永不放行：只能靠时限结束
	w := &RealAuditWriter{db: db}
	started := time.Now()
	for i := 0; i < 5; i++ {
		w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-"+string(rune('a'+i)), ""),
			RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: strings.Repeat("身份证 110101199003071234 ", 1000) + string(rune('a'+i))})
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("request path waited %v for raw evidence writes", elapsed)
	}
	w.flushRawEvidence()
	if db.callCount() != 5 {
		t.Fatalf("calls=%d want 5", db.callCount())
	}
	for _, d := range db.deadlines {
		if d <= 0 || d > rawEvidenceWriteTimeout {
			t.Fatalf("write deadline %v must be bounded by rawEvidenceWriteTimeout %v", d, rawEvidenceWriteTimeout)
		}
	}
}

// 请求已结束（ctx 取消）也照样写入；写库报错不 panic、不影响后续留证。
func TestRawEvidenceWriteSurvivesCanceledRequestAndErrors(t *testing.T) {
	setRawEvidenceTestKey(t)
	db := &blockingRawEvidenceDB{err: errors.New("db down")}
	w := &RealAuditWriter{db: db}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.WriteRawEvidence(ctx, rawEvidenceAsyncEnvelope("req-1", "s"), RawEvidenceRecord{Direction: rawEvidenceOutput, Role: "assistant", Disposition: rawEvidenceBlocked, Text: "原文一"})
	w.WriteRawEvidence(ctx, rawEvidenceAsyncEnvelope("req-2", "s"), RawEvidenceRecord{Direction: rawEvidenceOutput, Role: "assistant", Disposition: rawEvidenceBlocked, Text: "原文二"})
	w.flushRawEvidence()
	if db.callCount() != 2 {
		t.Fatalf("calls=%d want 2", db.callCount())
	}
}

// 同一会话里多轮重发同一段原文只存一份密文；后续每轮只写一行不含密文的引用（按该轮请求 ID 可定位）。
// 不同会话、不同原文各存各的。
func TestRawEvidenceDedupWithinSession(t *testing.T) {
	setRawEvidenceTestKey(t)
	db := &blockingRawEvidenceDB{}
	w := &RealAuditWriter{db: db}
	toolResult := "工具结果：客户手机 13800138000 身份证 110101199003071234"
	for round := 0; round < 50; round++ {
		w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-round-"+strings.Repeat("x", round), "agent-session"),
			RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Index: round, Disposition: rawEvidenceMasked, Text: toolResult, BlockID: ""})
		w.flushRawEvidence()
	}
	if db.full != 1 || db.ref != 49 {
		t.Fatalf("50 rounds: full=%d ref=%d want 1 full + 49 references", db.full, db.ref)
	}
	for i, args := range db.refArgs {
		if args[1] != "req-round-"+strings.Repeat("x", i+1) || args[2] != "agent-session" {
			t.Fatalf("reference %d points at wrong request/session: %v %v", i, args[1], args[2])
		}
		for _, a := range args {
			if s, ok := a.(string); ok && (strings.Contains(s, "13800138000") || strings.HasPrefix(s, "enc:v3:")) {
				t.Fatalf("reference row must carry neither plaintext nor ciphertext: %q", s)
			}
		}
	}
	w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-other-session", "another-session"),
		RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: toolResult})
	w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-new-text", "agent-session"),
		RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: toolResult + "（新内容）"})
	w.flushRawEvidence()
	if db.full != 3 || db.ref != 49 {
		t.Fatalf("full=%d ref=%d want 3 full + 49 references", db.full, db.ref)
	}
}

// 排队字节超出上限时丢弃（不阻塞、不占满内存）。
func TestRawEvidenceQueueByteBudget(t *testing.T) {
	setRawEvidenceTestKey(t)
	oldBytes := rawEvidenceQueueMaxBytes
	rawEvidenceQueueMaxBytes = 1024
	t.Cleanup(func() { rawEvidenceQueueMaxBytes = oldBytes })
	db := &blockingRawEvidenceDB{release: make(chan struct{})}
	w := &RealAuditWriter{db: db}
	w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-big", ""), RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: strings.Repeat("a", 2048)})
	w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-small", ""), RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: "small"})
	close(db.release)
	w.flushRawEvidence()
	if db.callCount() != 1 {
		t.Fatalf("calls=%d want only the small record", db.callCount())
	}
}

// 进程内去重缓存命中后只写引用行；首条已过保留期被删时引用写 0 行，不能悄悄丢证：
// 清掉缓存键并退回完整插入。
func TestRawEvidenceReferenceMissFallsBackToFullInsert(t *testing.T) {
	setRawEvidenceTestKey(t)
	db := &blockingRawEvidenceDB{}
	w := &RealAuditWriter{db: db}
	text := "工具结果：手机 13800138000"
	write := func(req string) {
		w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope(req, "sess"), RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: text})
		w.flushRawEvidence()
	}
	write("req-1") // 首条：全文
	db.mu.Lock()
	db.refZero = true // 首条随后过期被删：引用找不到首条
	db.mu.Unlock()
	write("req-2")
	if db.full != 2 || db.ref != 1 {
		t.Fatalf("reference miss must fall back to a full insert: full=%d ref=%d", db.full, db.ref)
	}
	db.mu.Lock()
	db.refZero = false
	db.mu.Unlock()
	write("req-3") // 新首条已写入并记住：之后照常写引用
	if db.full != 2 || db.ref != 2 {
		t.Fatalf("after fallback the new first row is remembered: full=%d ref=%d", db.full, db.ref)
	}
}

// 优雅退出：关停时在关闭连接池之前带超时排空留证队列。排得空返回 true；
// 写库挂住时到时限返回 false，不无限等待。
func TestRawEvidenceDrainOnShutdown(t *testing.T) {
	setRawEvidenceTestKey(t)
	db := &blockingRawEvidenceDB{release: make(chan struct{})}
	w := &RealAuditWriter{db: db}
	if !w.DrainRawEvidence(10 * time.Millisecond) {
		t.Fatal("empty queue must drain immediately")
	}
	w.WriteRawEvidence(context.Background(), rawEvidenceAsyncEnvelope("req-drain", "s"), RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceMasked, Text: "排队中的原文"})
	started := time.Now()
	if w.DrainRawEvidence(100 * time.Millisecond) {
		t.Fatal("blocked write must not report drained")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("drain must respect its timeout, waited %v", elapsed)
	}
	close(db.release)
	if !w.DrainRawEvidence(2 * time.Second) {
		t.Fatal("queue must drain once the write completes")
	}
	if db.full != 1 {
		t.Fatalf("queued evidence was not written before shutdown: full=%d", db.full)
	}
}
