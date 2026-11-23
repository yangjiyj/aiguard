package alert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeFPDispositions 模拟「有效期内被处置为误报」的告警组 group_key 集合来源,
// 镜像 AlertGroupRepository.ListFalsePositiveGroupKeys 的返回形状(租户→组键集合)。
type fakeFPDispositions struct {
	keys        map[string]map[string]bool
	err         error
	calls       int
	lastTenants []string
	lastSince   time.Time
}

func (f *fakeFPDispositions) ListFalsePositiveGroupKeys(ctx context.Context, tenantIDs []string, since time.Time) (map[string]map[string]bool, error) {
	f.calls++
	f.lastTenants = tenantIDs
	f.lastSince = since
	if f.err != nil {
		return nil, f.err
	}
	if f.keys == nil {
		return map[string]map[string]bool{}, nil
	}
	return f.keys, nil
}

// fpBridge 构造一个显式设定误报静默有效期(天)的桥,不依赖环境变量。
func fpBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, days int, fp *fakeFPDispositions) *SecEventBridge {
	b := gateBridge(src, inbox, notifier, 0.5)
	b.fpSuppressDays = days
	return b.WithFPDispositions(fp)
}

func TestSecEventBridge_FPDispositionSilencesSameGroup(t *testing.T) {
	// 组被人工处置为 false_positive 后,同 group_key 的后续事件在有效期内不再进收件箱、
	// 不通知、也不再开新告警组;但仍标记 processed(留证语义:security_events 照常落)。
	ev := secEventSha("fp_e1", "sha_fp")
	key := eventGroupKey(ev)
	fp := &fakeFPDispositions{keys: map[string]map[string]bool{"tenant_x": {key: true}}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}
	groups := &fakeAlertGrouper{}

	n, err := fpBridge(src, pusher, notifier, 30, fp).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted for fp-disposition silenced event, got %d", n)
	}
	if pusher.upserts != 0 || pusher.pushCalls != 0 {
		t.Fatalf("expected no inbox writes, got upserts=%d pushes=%d", pusher.upserts, pusher.pushCalls)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no external notify, got %d", notifier.calls)
	}
	if len(groups.inputs) != 0 {
		t.Fatalf("silenced event must not reopen an alert group, got %+v", groups.inputs)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "fp_e1" {
		t.Fatalf("expected fp_e1 marked alerted (evidence semantics), got %v", src.markedIDs)
	}
	// 查询窗口应为「现在 - 有效期天数」,且只查本轮涉及的租户。
	if fp.calls != 1 || len(fp.lastTenants) != 1 || fp.lastTenants[0] != "tenant_x" {
		t.Fatalf("expected one fp lookup for tenant_x, got calls=%d tenants=%v", fp.calls, fp.lastTenants)
	}
	wantSince := time.Now().UTC().AddDate(0, 0, -30)
	if d := fp.lastSince.Sub(wantSince); d < -time.Minute || d > time.Minute {
		t.Fatalf("expected since ≈ now-30d, got %v", fp.lastSince)
	}
}

func TestSecEventBridge_FPDispositionExpiredNotSilenced(t *testing.T) {
	// 处置已过有效期(SQL 按 false_positive_at >= since 过滤,过期组不在集合里)→ 恢复照常提升。
	fp := &fakeFPDispositions{keys: map[string]map[string]bool{}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{secEventSha("fp_e2", "sha_fp")}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}

	n, err := fpBridge(src, pusher, notifier, 30, fp).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 || notifier.calls != 1 {
		t.Fatalf("expected expired disposition to surface normally, got n=%d upserts=%d notify=%d", n, pusher.upserts, notifier.calls)
	}
}
func TestSecEventBridge_FPDispositionEnforcementPassesThrough(t *testing.T) {
	// 数据面动过手(block 等)的事件必须可审计,不受误报静默影响。
	ev := secEventWithFindings("fp_blk", "block", findingSha(0.90, "sha_fp_blk"))
	key := eventGroupKey(ev)
	fp := &fakeFPDispositions{keys: map[string]map[string]bool{"tenant_x": {key: true}}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}

	n, err := fpBridge(src, pusher, &fakeNotifier{}, 30, fp).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("expected enforcement event to pierce fp-disposition silence, got n=%d upserts=%d", n, pusher.upserts)
	}
}

func TestSecEventBridge_FPDispositionZeroDaysDisabled(t *testing.T) {
	// SECEVENT_FP_DISPOSITION_SUPPRESS_DAYS=0 → 整个静默闸关闭,连查询都不发。
	ev := secEventSha("fp_off", "sha_fp_off")
	key := eventGroupKey(ev)
	fp := &fakeFPDispositions{keys: map[string]map[string]bool{"tenant_x": {key: true}}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}

	n, err := fpBridge(src, pusher, &fakeNotifier{}, 0, fp).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if fp.calls != 0 {
		t.Fatalf("expected no fp lookup when disabled, got %d", fp.calls)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("expected event surfaced when gate disabled, got n=%d upserts=%d", n, pusher.upserts)
	}
}

func TestSecEventBridge_FPDispositionQueryErrorFailsOpen(t *testing.T) {
	// 集合查询失败 → fail open:宁可多报也不静默。
	fp := &fakeFPDispositions{err: errors.New("db down")}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{secEventSha("fp_err", "sha_fp_err")}}
	pusher := &fakeDedupPusher{}

	n, err := fpBridge(src, pusher, &fakeNotifier{}, 30, fp).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("expected fail-open surface on fp query error, got n=%d upserts=%d", n, pusher.upserts)
	}
}
