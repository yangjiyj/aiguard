package alert

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 执行模式变更告警在收件箱里必须显示中文，不能露出原始英文事件类型。
func TestExecutionModeChangeEventHasChineseLabelAndSurfaces(t *testing.T) {
	ev := &repository.SecurityEvent{
		EventType: "security_mode_changed", Severity: "high", ActionTaken: "audit",
		MatchedSummary: map[string]interface{}{"old_mode": "record", "new_mode": "protect", "mode_source": "admin_settings", "attributed": false},
	}
	if got := eventTypeLabelCN(ev.EventType); got != "执行模式变更" {
		t.Fatalf("label = %q", got)
	}
	if got := eventDisplayLabelCN(ev); got != "执行模式变更" {
		t.Fatalf("display label = %q", got)
	}
	b := &SecEventBridge{suppressSources: map[string]bool{"admin_settings": true}}
	if ok, reason := b.shouldSurface(ev); !ok {
		t.Fatalf("mode change must reach the inbox even with source suppression configured: %s", reason)
	}
}
