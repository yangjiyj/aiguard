package audit_chain

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

type blockingWriter struct {
	release chan struct{}
	count   int64
	err     error
}

func (b *blockingWriter) Append(ctx context.Context, _, _, _ string, _ map[string]any) error {
	<-b.release
	atomic.AddInt64(&b.count, 1)
	return b.err
}

// 缓冲满时非关键事件被丢弃，丢弃数按租户计数，TakeDropped 取走后清零。
func TestAppenderCountsDroppedEntriesPerTenant(t *testing.T) {
	w := &blockingWriter{release: make(chan struct{})}
	a := NewAppender(w, false)
	defer close(w.release)
	for i := 0; i < 1100; i++ {
		a.Enqueue("tenant-a", "audit_op", "evt", map[string]any{"i": i})
	}
	dropped := a.TakeDropped()
	if dropped["tenant-a"] < 99 {
		t.Fatalf("dropped=%v want >=99", dropped)
	}
	if again := a.TakeDropped(); len(again) != 0 {
		t.Fatalf("TakeDropped must reset: %v", again)
	}
}

// 关键事件同步写入，不经过可丢弃的队列；存储失败返回错误而不是静默丢失。
func TestAppendSyncWritesDurablyOrFails(t *testing.T) {
	ok := &mockWriter{done: make(chan struct{}, 1)}
	a := NewAppender(ok, false)
	if err := a.AppendSync(context.Background(), "t", "audit_op", "op-1", map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&ok.count) != 1 {
		t.Fatalf("sync append calls=%d", ok.count)
	}
	failing := &blockingWriter{release: make(chan struct{}), err: errors.New("db down")}
	close(failing.release)
	b := NewAppender(failing, false)
	if err := b.AppendSync(context.Background(), "t", "audit_op", "op-2", nil); !errors.Is(err, ErrCriticalAuditUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if atomic.LoadInt64(&failing.count) != 3 {
		t.Fatalf("retries=%d want 3", failing.count)
	}
	if err := NewAppender(ok, true).AppendSync(context.Background(), "t", "audit_op", "op-3", nil); !errors.Is(err, ErrCriticalAuditUnavailable) {
		t.Fatalf("disabled chain must report unavailable: %v", err)
	}
}
