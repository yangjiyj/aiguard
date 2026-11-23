package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// P0（2026-09-27）：执行模式一旦变化就要告警。09-20 有一次绕过控制台的直接写库，
// 把生产切到了 protect，控制台审计没有触发。看门狗按"生效模式"比对，
// 不依赖变更入口，所以直接写库、改 env、控制台操作都能发现。
func TestModeWatcherBaselineDoesNotAlert(t *testing.T) {
	w := &executionModeWatcher{}
	if ev := w.observe("record", "user_admin", "admin_settings"); ev != nil {
		t.Fatalf("first observation must only record a baseline, got %#v", ev)
	}
	if ev := w.observe("record", "user_admin", "admin_settings"); ev != nil {
		t.Fatalf("unchanged mode must not alert, got %#v", ev)
	}
}

func TestModeWatcherAlertsOnChangeWithAttribution(t *testing.T) {
	w := &executionModeWatcher{}
	w.observe("record", "user_admin", "admin_settings")
	ev := w.observe("protect", "", "admin_settings")
	if ev == nil {
		t.Fatal("record -> protect must alert")
	}
	if ev.EventType != "security_mode_changed" || ev.Severity != "high" {
		t.Fatalf("unexpected event shape: %#v", ev)
	}
	s := ev.MatchedSummary
	if s["old_mode"] != "record" || s["new_mode"] != "protect" {
		t.Fatalf("event must record the transition: %#v", s)
	}
	if s["attributed"] != false {
		t.Fatalf("a change without a console user must be flagged unattributed: %#v", s)
	}
	if ev.ID == "" || ev.RequestID == "" || ev.TenantID == "" || ev.ProjectID == "" || ev.ActionTaken == "" {
		t.Fatalf("event must satisfy the repository's required fields: %#v", ev)
	}
	if again := w.observe("protect", "", "admin_settings"); again != nil {
		t.Fatal("the same new mode must not alert twice")
	}
}

func TestModeWatcherAttributedChangeIsStillReported(t *testing.T) {
	w := &executionModeWatcher{}
	w.observe("protect", "user_admin", "admin_settings")
	ev := w.observe("record", "user_admin", "admin_settings")
	if ev == nil || ev.MatchedSummary["attributed"] != true || ev.MatchedSummary["modified_by"] != "user_admin" {
		t.Fatalf("an attributed change must still be reported with its operator: %#v", ev)
	}
}

// 多副本控制面读到同一条持久化基线，观察到同一次变更时事件 ID 必须一致，
// Upsert 按 ID 去重只落一条。
func TestModeWatcherEventIDIsDeterministicAcrossReplicas(t *testing.T) {
	a, b := &executionModeWatcher{}, &executionModeWatcher{}
	a.restore("record", "2026-09-27T08:00:00Z")
	b.restore("record", "2026-09-27T08:00:00Z")
	ea := a.observe("protect", "", "admin_settings")
	eb := b.observe("protect", "", "admin_settings")
	if ea == nil || eb == nil || ea.ID != eb.ID {
		t.Fatalf("replicas must produce the same event id: %v vs %v", ea, eb)
	}
	c := &executionModeWatcher{}
	c.restore("record", "2026-09-27T09:00:00Z")
	if ec := c.observe("protect", "", "admin_settings"); ec == nil || ec.ID == ea.ID {
		t.Fatal("a later, separate transition must get its own event id")
	}
}

// 控制面停机期间发生的变更：重启后以持久化基线为准，仍要告警。
func TestModeWatcherRestoredBaselineAlertsOnChangeDuringDowntime(t *testing.T) {
	w := &executionModeWatcher{}
	w.restore("record", "2026-09-27T08:00:00Z")
	if ev := w.observe("protect", "", "admin_settings"); ev == nil {
		t.Fatal("a change made while the watcher was down must alert after restart")
	}
}

// 部署锁开着时生效模式不会变，但有人改了库里的配置值（09-20 同形态的直接写库）
// 仍是需要告警的越权变更：看门狗同时比对"配置值"。
func TestModeWatcherAlertsOnConfiguredChangeUnderDeploymentLock(t *testing.T) {
	w := &executionModeWatcher{}
	w.restore("record", "2026-09-27T08:00:00Z")
	ev := w.observeConfigured("record", "protect", "", "deployment")
	if ev == nil {
		t.Fatal("a configured-mode change must alert even when the effective mode is locked")
	}
	s := ev.MatchedSummary
	if s["new_configured_mode"] != "protect" || s["new_mode"] != "record" || s["attributed"] != false {
		t.Fatalf("event must show the locked effective mode and the attempted configuration: %#v", s)
	}
	if again := w.observeConfigured("record", "protect", "", "deployment"); again != nil {
		t.Fatal("the same configured value must not alert twice")
	}
}

// 线上验证发现：security_events.request_id 外键指向 request_logs，看门狗没有真实请求，
// 写安全事件会被外键拒绝。模式变更属于管理面配置变更，直接进告警收件箱（alert_groups），
// 其约束只需要租户与 group_key。这里的替身按真实表约束校验必填字段。
type strictModeAlertWriter struct {
	inputs []repository.AlertGroupUpsertInput
}

func (w *strictModeAlertWriter) UpsertOpen(_ context.Context, in repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error) {
	if in.TenantID == "" || in.GroupKey == "" || in.Title == "" || in.AlertType == "" || in.OccurredAt.IsZero() {
		return nil, false, fmt.Errorf("alert_groups constraint violated: %#v", in)
	}
	switch in.Severity {
	case "info", "warning", "low", "medium", "high", "critical":
	default:
		return nil, false, fmt.Errorf("alert_groups severity check violated: %q", in.Severity)
	}
	w.inputs = append(w.inputs, in)
	return &repository.AlertGroup{}, true, nil
}

func TestModeWatcherWritesChangeToAlertInbox(t *testing.T) {
	w := &executionModeWatcher{}
	w.restore("record", "2026-09-27T08:00:00Z")
	ev := w.observeConfigured("record", "protect", "", "deployment")
	if ev == nil {
		t.Fatal("expected a change")
	}
	sink := &strictModeAlertWriter{}
	if err := writeModeChangeAlert(context.Background(), sink, ev); err != nil {
		t.Fatalf("mode change alert must satisfy alert_groups constraints: %v", err)
	}
	got := sink.inputs[0]
	if got.AlertType != "security_mode_changed" || got.Severity != "high" || got.GroupKey != ev.ID || got.RequestID != "" {
		t.Fatalf("unexpected alert: %#v", got)
	}
	if got.BodyJSON["new_configured_mode"] != "protect" || got.BodyJSON["attributed"] != false {
		t.Fatalf("alert body must carry the transition: %#v", got.BodyJSON)
	}
}
