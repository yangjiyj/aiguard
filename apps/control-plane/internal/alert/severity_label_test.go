package alert

import (
	"strings"
	"testing"
)

func TestSeverityLabelsUseTheUnifiedNames(t *testing.T) {
	for in, want := range map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"} {
		if got := severityLabelCN(in); got != want {
			t.Fatalf("severityLabelCN(%q)=%q want %q", in, got, want)
		}
	}
}

func TestActionLabelsUseTheConsoleDispositionNames(t *testing.T) {
	for in, want := range map[string]string{
		"block": "已阻断", "security_blocked": "已阻断",
		"audit": "仅记录", "security_audit": "仅记录", "security_audit_only": "观察留痕放行",
		"mask": "已脱敏", "security_masked": "已脱敏",
		"allow":            "已放行",
		"security_replied": "安全代答",
	} {
		if got := actionLabelCN(in); got != want {
			t.Fatalf("actionLabelCN(%q)=%q want %q", in, got, want)
		}
	}
}

func TestActionLabelsCoverRealDispositionsAndNeverLeakEnglishCodes(t *testing.T) {
	for in, want := range map[string]string{
		"alert": "告警放行", "flagged": "告警放行",
		"confirm": "要求人工确认", "rewrite": "已改写", "reply": "安全代答", "redact": "已脱敏",
		"tool_audited": "仅记录", "tool_audit_only": "仅记录",
		"tool_blocked": "已阻断", "tool_attempt_blocked": "已阻断", "stream_blocked": "已阻断",
		"some_new_action": "其他处置",
	} {
		if got := actionLabelCN(in); got != want {
			t.Fatalf("actionLabelCN(%q)=%q want %q", in, got, want)
		}
	}
	if got := actionLabelCN(""); got != "未记录" {
		t.Fatalf("empty action keeps its label, got %q", got)
	}
}

func TestFlagAndDenyDispositionsReachTheTitleAsConsoleNames(t *testing.T) {
	for _, tc := range []struct{ eventType, action, want string }{
		{"tool_execution_risk", "flag", "处置：告警放行"},
		{"agent_identity_mismatch", "deny", "处置：已阻断"},
	} {
		ev := sampleSecEvent("disp-" + tc.action)
		ev.EventType, ev.Severity, ev.ActionTaken = tc.eventType, "high", tc.action
		ev.MatchedSummary = map[string]interface{}{}
		b := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
		if ok, reason := b.shouldSurface(ev); !ok {
			t.Fatalf("%s/%s must surface: %s", tc.eventType, tc.action, reason)
		}
		title := alertGroupTitle(ev, lifecycleFields{effectiveSeverity: "high"})
		if !strings.Contains(title, tc.want) {
			t.Fatalf("title %q must contain %q", title, tc.want)
		}
	}
}
