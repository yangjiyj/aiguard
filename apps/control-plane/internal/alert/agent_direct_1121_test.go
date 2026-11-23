package alert

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 客户现场：每条网关原生入口的安全事件都带一条 agent_direct_api_call（直接 API 调用）观察。
// 告警中心与消息中心：只有它的存量事件不出可处置告警；它与高危同现时，高危照常出告警且主命中是高危。
// 新事件里它改为 matched_summary.request_labels，不再是 finding，结论相同。

func siteAgentDirectFindingMap() map[string]any {
	return map[string]any{
		"type": "request_context", "category": "agent_direct_api_call", "severity": "low",
		"rule_id": "rule_29d445a2-29d0-4f04-be9a-7bf6da439135", "rule_type": "agent_detect",
		"confidence": 1.0, "action": "allow", "counts_as_security_finding": false,
		"triage": map[string]any{"disposition": "observation", "disposition_reason": "agent_inventory_metadata"},
	}
}

func siteHighCommandFindingMap() map[string]any {
	return map[string]any{
		"type": "content_safety", "category": "illegal_system_command_instructions", "severity": "high",
		"rule_id": "rule_high_cmd", "confidence": 0.95, "action": "audit",
	}
}

func TestLegacyAgentDirectOnlyEventDoesNotSurface(t *testing.T) {
	b := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
	ev := secEventWithFindings("direct-only", "security_audit", siteAgentDirectFindingMap())
	ev.Severity = "low"
	if ok, reason := b.shouldSurface(ev); ok {
		t.Fatalf("只有直接调用标签的事件不得进告警/消息中心, reason=%q", reason)
	}
}

func TestAgentDirectWithHighRiskStillSurfacesAsHighRisk(t *testing.T) {
	b := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
	legacy := secEventWithFindings("direct-high-legacy", "security_audit", siteAgentDirectFindingMap(), siteHighCommandFindingMap())
	legacy.Severity = "high"
	current := secEventWithFindings("direct-high", "security_audit", siteHighCommandFindingMap())
	current.Severity = "high"
	current.MatchedSummary["request_labels"] = []any{"agent_direct_api_call"}
	for name, ev := range map[string]*repository.SecurityEvent{"legacy": legacy, "current": current} {
		if ok, reason := b.shouldSurface(ev); !ok {
			t.Fatalf("%s: 高危命中不能因为同带直接调用标签被吞, reason=%q", name, reason)
		}
		if got := dominantCategory(ev); got != "illegal_system_command_instructions" {
			t.Fatalf("%s: 主命中必须是高危命中, got %q", name, got)
		}
		if fields := b.computeLifecycleFields(ev); fields.dispositionClass != "action_required" {
			t.Fatalf("%s: 高危应为需处置, got %+v", name, fields)
		}
	}
}
