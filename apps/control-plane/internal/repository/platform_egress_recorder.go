package repository

import (
	"context"
	"sync"
	"time"
)

// PlatformEgressEventWindow 是平台出站拒绝事件的限频窗口：同一租户、同一类型、同一目标主机在窗口内
// 只记一条（与运行故障事件同口径），防止通知外发被拒→告警→再外发被拒形成循环。
const PlatformEgressEventWindow = 10 * time.Minute

// PlatformEgressEventRecorder 按“租户+类型+目标主机”限频写平台出站拒绝事件。判断通过后先在锁内占位
// （写入中），并发的同键调用直接跳过；写成功转为已登记，写失败删除占位，下次照常重试。
type PlatformEgressEventRecorder struct {
	db     platformEgressEventExecer
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	last     map[string]time.Time
	inflight map[string]bool
}

func NewPlatformEgressEventRecorder(db platformEgressEventExecer, window time.Duration) *PlatformEgressEventRecorder {
	if window <= 0 {
		window = PlatformEgressEventWindow
	}
	return &PlatformEgressEventRecorder{db: db, window: window, now: time.Now, last: map[string]time.Time{}, inflight: map[string]bool{}}
}

// Record 写一条事件；窗口内已记过、或同键正在写入时跳过并返回 false。
func (r *PlatformEgressEventRecorder) Record(ctx context.Context, tenantID, environmentScope, kind, target string) (bool, error) {
	if r == nil {
		return false, nil
	}
	key := tenantID + "\x1f" + kind + "\x1f" + target
	now := r.now()
	r.mu.Lock()
	if r.inflight[key] {
		r.mu.Unlock()
		return false, nil
	}
	if at, ok := r.last[key]; ok && now.Sub(at) < r.window {
		r.mu.Unlock()
		return false, nil
	}
	r.inflight[key] = true
	r.mu.Unlock()

	recorded := false
	// 占位无论成功、失败还是写库函数 panic 都在这里清掉；只有写成功（或没有项目、已打日志）才登记。
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.inflight, key)
		if !recorded {
			return
		}
		r.last[key] = now
		for k, at := range r.last {
			if now.Sub(at) >= r.window {
				delete(r.last, k)
			}
		}
	}()
	if _, err := RecordPlatformEgressDenied(ctx, r.db, tenantID, environmentScope, kind, target); err != nil {
		return false, err
	}
	recorded = true
	return true, nil
}
