package alert

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeGrouperP1D 恒返回同一个已开组，供回填/重算路径断言用（区别于 fakeAlertGrouper：
// 后者按 upsert 序号切换 created，此处只关心组存在即可触发回填）。
type fakeGrouperP1D struct {
	upserts int
}

func (f *fakeGrouperP1D) UpsertOpen(ctx context.Context, input repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error) {
	f.upserts++
	return &repository.AlertGroup{ID: "ag_p1d_1", TenantID: input.TenantID}, true, nil
}

// fakeGroupCounters 记录回填与重算调用，并回吐固定主指标。桥是 at-least-once：
// 只该 COUNT(DISTINCT) 重算一次，绝不增量，故这里断言 recalced 恰一次。
type fakeGroupCounters struct {
	attached [][3]string // tenant, eventID, groupID
	recalced [][2]string // tenant, groupID
	occ      int
	users    int
}

func (f *fakeGroupCounters) AttachEvent(ctx context.Context, tenantID, eventID, groupID string) error {
	f.attached = append(f.attached, [3]string{tenantID, eventID, groupID})
	return nil
}

func (f *fakeGroupCounters) RecalcCounters(ctx context.Context, tenantID, groupID string) (int, int, error) {
	f.recalced = append(f.recalced, [2]string{tenantID, groupID})
	return f.occ, f.users, nil
}

func TestRunOnceAttachesEventAndRecalcsCounters(t *testing.T) {
	ev := sampleSecEvent("evt_p1d_1")
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	inbox := &fakePusher{}
	bridge := NewSecEventBridge(src, inbox, nil).
		WithAlertGroups(&fakeGrouperP1D{}).
		WithGroupCounters(&fakeGroupCounters{occ: 3, users: 2})
	// 关掉置信度闸避免样例事件被压制（与本包其它测试同做法）。
	bridge.minConfidence = 0

	if _, err := bridge.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	counters := bridge.groupCounters.(*fakeGroupCounters)
	if len(counters.attached) != 1 || counters.attached[0] != [3]string{ev.TenantID, ev.ID, "ag_p1d_1"} {
		t.Fatalf("应把事件回填进组: %+v", counters.attached)
	}
	if len(counters.recalced) != 1 {
		t.Fatalf("应对该组幂等重算一次: %+v", counters.recalced)
	}
}

func TestRunOnceNotifyTitleUsesNewPrimaryMetrics(t *testing.T) {
	ev := sampleSecEvent("evt_p1d_2")
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	inbox := &fakePusher{}
	notifier := &fakeNotifier{}
	bridge := NewSecEventBridge(src, inbox, notifier).
		WithAlertGroups(&fakeGrouperP1D{}).
		WithGroupCounters(&fakeGroupCounters{occ: 5, users: 4})
	bridge.minConfidence = 0

	if _, err := bridge.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notifier.lastTitle == "" || !strings.Contains(notifier.lastTitle, "独立事发 5 次") || !strings.Contains(notifier.lastTitle, "涉及 4 人") {
		t.Fatalf("通知标题应使用新主指标, got %q", notifier.lastTitle)
	}
}
