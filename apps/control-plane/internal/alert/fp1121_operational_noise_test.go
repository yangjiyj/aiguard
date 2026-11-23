package alert

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 客户A 11-21：语义复核超时/预算超限是检测引擎的运行状况，不是内容风险。它照常落 security_events、
// 照常在告警组里按阶段+原因累计次数（运行指标/观察），但不进收件箱、不外发通知。
// 引擎不可用、熔断等真实故障仍照旧提醒运维。
func TestFP1121SemanticBudgetFaultsStayOutOfInbox(t *testing.T) {
	for _, reason := range []string{"judge_timeout", "window_timeout", "security_pipeline_timeout", "semantic_total_timeout",
		"triage_total_budget_exhausted", "window_budget_exceeded", "judge_capacity_deferred", "judge_capacity_overflow", "tier1_queue_timeout"} {
		ev := faultFixtureEvent("f-"+reason, "output", reason)
		src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
		inbox := &fakePusher{}
		notifier := &fakeNotifier{}
		groups := &fakeAlertGrouper{}
		if _, err := NewSecEventBridge(src, inbox, notifier).WithAlertGroups(groups).RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if len(inbox.pushedTypes) != 0 || notifier.calls != 0 {
			t.Fatalf("%s 不应进收件箱/外发通知: inbox=%v notify=%d", reason, inbox.pushedTypes, notifier.calls)
		}
		if len(groups.inputs) != 1 || groups.inputs[0].DispositionClass != "informational" || groups.inputs[0].AlertType != "runtime_fault" {
			t.Fatalf("%s 仍应记入运行故障告警组（观察）: %+v", reason, groups.inputs)
		}
		if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 1 {
			t.Fatalf("%s 处理后必须标记已告警，避免反复扫描: %v", reason, src.markedIDs)
		}
	}
	for _, reason := range []string{"breaker_open", "security_engine_unavailable", "judge_unavailable", ""} {
		ev := faultFixtureEvent("g-"+reason, "input", reason)
		inbox := &fakePusher{}
		notifier := &fakeNotifier{}
		if _, err := NewSecEventBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, inbox, notifier).RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if len(inbox.pushedTypes) != 1 || notifier.calls != 1 {
			t.Fatalf("真实故障 %q 必须照旧提醒: inbox=%v notify=%d", reason, inbox.pushedTypes, notifier.calls)
		}
	}
}

// 升级安装器自检（应用编号 project_upgrade_verify_ 前缀，只有安装器直接写库才能产生，控制台建应用一律是 proj_ 随机编号）
// 的检测样本：网关照常检测、阻断、落 security_events（升级脚本靠它验证检测链路），但不进客户收件箱、告警组与外发通知。
func TestFP1121UpgradeSelfTestStaysOutOfCustomerAlerts(t *testing.T) {
	ev := sampleSecEvent("selftest")
	ev.ProjectID = "project_upgrade_verify_0123456789abcdef"
	ev.UserID = ""
	ev.EventType = "security_check"
	ev.Severity = "critical"
	ev.ActionTaken = "block"
	ev.MatchedSummary = map[string]any{"category": "ssh_private_key", "findings": []any{map[string]any{
		"type": "secret", "category": "ssh_private_key", "severity": "critical", "action": "block", "confidence": 0.99,
		"rule_id": "rule_private_key", "redacted_evidence": "-----BEGIN RSA PRIVATE KEY-----",
	}}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	inbox := &fakePusher{}
	notifier := &fakeNotifier{}
	groups := &fakeAlertGrouper{}
	if _, err := NewSecEventBridge(src, inbox, notifier).WithAlertGroups(groups).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(inbox.pushedTypes) != 0 || notifier.calls != 0 || len(groups.inputs) != 0 {
		t.Fatalf("升级自检不应进客户告警: inbox=%v notify=%d groups=%d", inbox.pushedTypes, notifier.calls, len(groups.inputs))
	}
	if len(src.markedIDs) != 1 {
		t.Fatalf("自检事件必须标记已处理: %v", src.markedIDs)
	}

	// 同样内容出现在普通应用（含名字里带 upgrade_verify 的伪造应用）照常告警。
	for _, project := range []string{"proj_1a2b3c4d", "proj_upgrade_verify_x", "xproject_upgrade_verify_1"} {
		forged := *ev
		forged.ID = "forged-" + project
		forged.ProjectID = project
		src := &fakeSecEventSource{events: []*repository.SecurityEvent{&forged}}
		inbox := &fakePusher{}
		if _, err := NewSecEventBridge(src, inbox, &fakeNotifier{}).RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if len(inbox.pushedTypes) != 1 {
			t.Fatalf("应用 %s 的私钥阻断必须照常进收件箱: %v", project, inbox.pushedTypes)
		}
	}
}

func fp1121DestructiveEvent(id, severity, user string) *repository.SecurityEvent {
	finding := map[string]any{
		"type": "tool_destructive_intent", "action": "audit", "rule_id": "", "category": "destructive_change", "severity": severity,
		"rule_name": "Bash", "rule_type": "agentguard", "confidence": 1, "evidence_kind": "agent_tool_call",
		"evidence_reason": "destructive_alert_allow", "matched_location": "tool", "matched_text_preview": "filesystem_delete",
	}
	ev := sampleSecEvent(id)
	ev.ProjectID = "project_chat_152d12d55b95fb787fdc"
	ev.UserID = user
	ev.PrincipalKey = user
	ev.EventType = "tool_destructive_intent"
	ev.Severity = severity
	ev.ActionTaken = "alert"
	ev.RuleName = "Bash"
	ev.RuleType = "tool_destructive_intent"
	ev.MatchedSummary = map[string]any{"stage": "tool", "source": "gateway", "category": "destructive_change",
		"findings": []any{finding}, "primary_finding": finding, "rule_name": "Bash", "rule_type": "tool_destructive_intent"}
	return ev
}

// 客户A 11-21：同一应用的删除与破坏事件按“类别+类型”指纹并成一个告警组，组级别取历史最高（maxSeverity），
// 计数每来一条加一。10-23 起偶发的 10 条严重事件把组顶成【严重】后，3947 条高危事件一直往这个严重组上累加
// （现场 ag_ad33…：critical 10 + high 3947 = 3957）。修复后严重与高危分组：严重事件仍落原组（组键不变），
// 高危及以下另开一组，不再给严重组计数。
func TestFP1121DestructiveHighDoesNotAccumulateOnCriticalGroup(t *testing.T) {
	critical := fp1121DestructiveEvent("d-crit", "critical", "user_a")
	high := fp1121DestructiveEvent("d-high", "high", "user_b")
	high2 := fp1121DestructiveEvent("d-high2", "high", "user_c")
	legacyCritical := repository.ScopedAlertGroupKey(legacyEventGroupKey(critical), critical.ProjectID, alertStage(critical))
	if got := eventGroupKey(critical); got != legacyCritical {
		t.Fatalf("严重事件的组键必须保持不变，继续落原来的严重组: got %s want %s", got, legacyCritical)
	}
	if eventGroupKey(high) == eventGroupKey(critical) {
		t.Fatalf("高危删除与破坏事件不得再并入严重组: %s", eventGroupKey(high))
	}
	if eventGroupKey(high) != eventGroupKey(high2) {
		t.Fatalf("同应用的高危删除与破坏事件仍应并成一组: %s vs %s", eventGroupKey(high), eventGroupKey(high2))
	}

	src := &fakeSecEventSource{events: []*repository.SecurityEvent{critical, high, high2}}
	groups := &fakeAlertGrouper{}
	if _, err := NewSecEventBridge(src, &fakePusher{}, &fakeNotifier{}).WithAlertGroups(groups).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(groups.inputs) != 3 {
		t.Fatalf("三条事件都应记入告警组: %+v", groups.inputs)
	}
	for _, input := range groups.inputs {
		if input.GroupKey == legacyCritical && input.Severity != "critical" {
			t.Fatalf("严重组只能收严重事件，收到了 %s", input.Severity)
		}
	}

	// 其他类型（例如内容检测）的组键不受影响：级别不同仍是同一组。
	other := sampleSecEvent("c-high")
	otherCritical := *other
	otherCritical.ID = "c-crit"
	otherCritical.Severity = "critical"
	if eventGroupKey(other) != eventGroupKey(&otherCritical) {
		t.Fatalf("非删除与破坏事件的组键不应随级别变化")
	}
}
