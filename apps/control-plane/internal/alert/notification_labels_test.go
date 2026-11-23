package alert

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 终端智能体风险、智能体身份不符这两类事件的类型名就是标题主体，不能是英文码。
func TestAgentEventTypesHaveChineseTitleSubjects(t *testing.T) {
	for eventType, want := range map[string]string{
		"agent_endpoint_risk":     "终端智能体风险",
		"agent_identity_mismatch": "智能体身份与凭据不符",
	} {
		ev := sampleSecEvent("subject-" + eventType)
		ev.EventType, ev.ActionTaken = eventType, "deny"
		ev.MatchedSummary = map[string]interface{}{}
		title := alertGroupTitle(ev, lifecycleFields{effectiveSeverity: "high"})
		if !strings.Contains(title, want) || strings.Contains(title, eventType) {
			t.Errorf("title %q must name %s as %q", title, eventType, want)
		}
	}
}

func runBridgeNotification(t *testing.T, ev *repository.SecurityEvent) (*fakeNotifier, *fakeAlertGrouper) {
	t.Helper()
	notifier, groups := &fakeNotifier{}, &fakeAlertGrouper{}
	_, err := NewSecEventBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, &fakePusher{}, notifier).
		WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notifier.calls != 1 || len(groups.inputs) != 1 {
		t.Fatalf("notifier calls=%d groups=%d, want 1 and 1", notifier.calls, len(groups.inputs))
	}
	return notifier, groups
}

// 外部通知正文补中文叫法，英文码原样保留给 Webhook 程序；收件箱与告警组里存的正文不加字段。
func TestNotificationBodyCarriesChineseLabelsBesideTheCodes(t *testing.T) {
	ev := sampleSecEvent("notify-endpoint")
	ev.EventType, ev.Severity, ev.ActionTaken = "agent_endpoint_risk", "high", "deny"
	ev.MatchedSummary = map[string]interface{}{}
	notifier, groups := runBridgeNotification(t, ev)
	body := notifier.lastBody
	if body["event_type_label"] != "终端智能体风险" || body["action_label"] != "已阻断" {
		t.Fatalf("labels event_type_label=%v action_label=%v", body["event_type_label"], body["action_label"])
	}
	if body["event_type"] != "agent_endpoint_risk" || body["action"] != "deny" {
		t.Fatalf("codes must stay for webhook consumers: event_type=%v action=%v", body["event_type"], body["action"])
	}
	stored := groups.inputs[0].BodyJSON
	if _, ok := stored["event_type_label"]; ok {
		t.Fatal("the stored alert body must not gain notification-only labels")
	}
	if _, ok := stored["action_label"]; ok {
		t.Fatal("the stored alert body must not gain notification-only labels")
	}
}

// 工具连续失败：处置码 tool_failure_loop 没有处置叫法（控制台同样省略），事件类型 security_check
// 对运行告警没有意义（标题已写明是工具连续失败），两行都不出。
func TestToolFailureLoopNotificationHasNoCodeOnlyLines(t *testing.T) {
	notifier, _ := runBridgeNotification(t, toolFailureLoopEvent("notify-loop"))
	if _, ok := notifier.lastBody["action_label"]; ok {
		t.Fatalf("tool_failure_loop has no disposition name, got %v", notifier.lastBody["action_label"])
	}
	if _, ok := notifier.lastBody["event_type_label"]; ok {
		t.Fatalf("a runtime alert carries no event type line, got %v", notifier.lastBody["event_type_label"])
	}
}
