package audit_chain

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// ChainWriter is the interface for writing to the audit chain.
type ChainWriter interface {
	Append(ctx context.Context, tenantID, eventType, eventID string, payload map[string]any) error
}

var ErrCriticalAuditUnavailable = errors.New("critical audit unavailable")

type criticalChainWriter interface {
	AppendHeaderContractConflictOnce(ctx context.Context, tenantID, eventID string, payload map[string]any) error
}

type entry struct {
	tenantID, eventType, eventID string
	payload                      map[string]any
}

// Appender is an asynchronous, fire-and-forget audit chain writer.
// It buffers entries and retries up to 3 times on failure.
//
// 非关键事件在缓冲满或重试耗尽时会丢失；丢失按租户计数，由 TakeDropped 取走并产生“审计记录丢失”告警。
// 关键事件（改执行模式、价格、预算、断流开关、资费、钱包调账）必须走 AppendSync 同步写入。
type Appender struct {
	repo     ChainWriter
	ch       chan entry
	disabled bool

	dropMu  sync.Mutex
	dropped map[string]int64
}

// NewAppender creates an Appender. When disabled=true all Enqueue calls are no-ops.
func NewAppender(repo ChainWriter, disabled bool) *Appender {
	a := &Appender{repo: repo, ch: make(chan entry, 1000), disabled: disabled, dropped: map[string]int64{}}
	if !disabled {
		go a.loop()
	}
	return a
}

// Enqueue submits an entry for asynchronous appending.
// If the internal buffer is full the entry is dropped and a warning is logged.
func (a *Appender) Enqueue(tenantID, eventType, eventID string, payload map[string]any) {
	if a.disabled {
		return
	}
	frozen, err := freezeAppenderPayload(payload)
	if err != nil {
		a.recordDrop(tenantID)
		log.Printf("[audit_chain.appender] invalid payload rejected")
		return
	}
	select {
	case a.ch <- entry{tenantID, eventType, eventID, frozen}:
	default:
		a.recordDrop(tenantID)
		log.Printf("[audit_chain.appender] buffer full, dropped %s/%s", eventType, eventID)
	}
}

func (a *Appender) recordDrop(tenantID string) {
	a.dropMu.Lock()
	a.dropped[tenantID]++
	a.dropMu.Unlock()
}

// TakeDropped 返回自上次调用以来各租户丢失的审计记录数，并清零。
func (a *Appender) TakeDropped() map[string]int64 {
	if a == nil {
		return nil
	}
	a.dropMu.Lock()
	defer a.dropMu.Unlock()
	if len(a.dropped) == 0 {
		return nil
	}
	out := a.dropped
	a.dropped = map[string]int64{}
	return out
}

// AppendSync 同步写入审计链（带有界重试），用于不得丢失的关键事件。
// 审计链关闭或未配置存储时返回 ErrCriticalAuditUnavailable。
func (a *Appender) AppendSync(ctx context.Context, tenantID, eventType, eventID string, payload map[string]any) error {
	if a == nil || a.disabled || a.repo == nil {
		return ErrCriticalAuditUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	frozen, err := freezeAppenderPayload(payload)
	if err != nil {
		return errors.Join(ErrCriticalAuditUnavailable, err)
	}
	// 请求取消不能取消审计：关键操作已经生效，审计必须尽力落盘。
	base := context.WithoutCancel(ctx)
	var lastErr error
	for i := 0; i < 3; i++ {
		attemptCtx, cancel := context.WithTimeout(base, 5*time.Second)
		lastErr = a.repo.Append(attemptCtx, tenantID, eventType, eventID, frozen)
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}
	return errors.Join(ErrCriticalAuditUnavailable, lastErr)
}

func (a *Appender) loop() {
	for e := range a.ch {
		var lastErr error
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			lastErr = a.repo.Append(ctx, e.tenantID, e.eventType, e.eventID, e.payload)
			cancel()
			if lastErr == nil {
				break
			}
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
		}
		if lastErr != nil {
			a.recordDrop(e.tenantID)
			log.Printf("[audit_chain.appender] append failed after retries: %v", lastErr)
		}
	}
}

// AppendCritical is a synchronous, bounded-context durable append. It never
// enters the fire-and-forget queue and disabled/missing storage is an error.
func (a *Appender) AppendCritical(ctx context.Context, tenantID, eventID string, payload map[string]any) error {
	if a == nil || a.disabled || a.repo == nil {
		return ErrCriticalAuditUnavailable
	}
	repo, ok := a.repo.(criticalChainWriter)
	if !ok {
		return ErrCriticalAuditUnavailable
	}
	frozen, err := freezeAppenderPayload(payload)
	if err != nil {
		return errors.Join(ErrCriticalAuditUnavailable, err)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := repo.AppendHeaderContractConflictOnce(bounded, tenantID, eventID, frozen); err != nil {
		return errors.Join(ErrCriticalAuditUnavailable, err)
	}
	return nil
}

// No caller-owned maps, slices or custom marshalers survive enqueue/retry.
func freezeAppenderPayload(payload map[string]any) (map[string]any, error) {
	raw, err := CanonicalPayload(payload)
	if err != nil {
		return nil, err
	}
	return DecodePayload(raw)
}
