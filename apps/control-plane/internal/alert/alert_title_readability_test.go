package alert

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 客户现场 2.9.15：消息中心最多的一类告警标题是「安全告警【高危】安全检测 · 独立事发 1 次 · 涉及 1 人」，
// 看标题不知道出了什么事。标题要带具体类别（中文）和发生位置。

func contentEvent(stage string, finding map[string]any) *repository.SecurityEvent {
	return &repository.SecurityEvent{
		ID: "evt_title", TenantID: "tenant_x", RequestID: "req_title", EventType: "security_check",
		Severity: "high", ActionTaken: "security_audit_only",
		MatchedSummary: map[string]any{"stage": stage, "findings": []any{finding}, "primary_finding": finding},
	}
}

func TestAlertTitleNamesTheDetectedCategoryAndWhereItHappened(t *testing.T) {
	lc := lifecycleFields{effectiveSeverity: "high"}
	cases := []struct {
		name    string
		stage   string
		finding map[string]any
		want    string
	}{
		{"catalog rule name", "input", map[string]any{"type": "catalog_policy", "category": "dos_regex_backtracking", "rule_name": "正则回溯攻击", "severity": "high"}, "正则回溯攻击（用户输入）"},
		{"customer rule name", "input", map[string]any{"type": "custom", "category": "customer_sensitive_data", "rule_name": "密钥相关", "severity": "high"}, "密钥相关（用户输入）"},
		{"no rule name", "output", map[string]any{"type": "code_config", "category": "env_file", "severity": "high"}, "环境变量文件内容（模型输出）"},
		{"generic custom name", "input", map[string]any{"type": "custom", "category": "keyword", "rule_name": "自定义", "severity": "high"}, "自定义关键词规则（用户输入）"},
		{"internal tier jargon", "input", map[string]any{"type": "semantic_attack", "category": "prompt_input_semantic_risk", "rule_name": "语义攻击·Tier1高置信风险", "severity": "high"}, "Prompt 注入语义风险（用户输入）"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			title := alertGroupTitle(contentEvent(tc.stage, tc.finding), lc)
			if !strings.Contains(title, tc.want) || strings.Contains(title, "安全检测") {
				t.Fatalf("title %q should contain %q instead of the generic 安全检测", title, tc.want)
			}
		})
	}
}

func TestCounterTitleKeepsTheSpecificSubject(t *testing.T) {
	ev := contentEvent("input", map[string]any{"type": "custom", "category": "customer_sensitive_data", "rule_name": "密钥相关", "severity": "high"})
	notifier := &fakeNotifier{}
	bridge := NewSecEventBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, &fakePusher{}, notifier).
		WithAlertGroups(&fakeGrouperP1D{}).
		WithGroupCounters(&fakeGroupCounters{occ: 1, users: 1})
	bridge.minConfidence = 0
	if _, err := bridge.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if notifier.lastTitle != "安全告警【高危】密钥相关（用户输入） · 独立事发 1 次 · 涉及 1 人" {
		t.Fatalf("got %q", notifier.lastTitle)
	}
}
