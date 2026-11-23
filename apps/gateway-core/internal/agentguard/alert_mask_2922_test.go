package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 语料比对（旧突发阈值折算成 agent.burst=确认，现场托管 file.* 审计规则）发现：同一次调用里
// 突发确认被显式审计规则降成放行后，另一条告警放行的命中（名字像敏感文件）也不再告警，
// 2.9.21 与基点都会告警。告警放行的命中自己就要求通知，不被更严、但没生效的命中盖掉。
func TestAlert2922AlertAllowHitStillNotifiesWhenStricterHitIsDowngradedByExplicitRule(t *testing.T) {
	policy := burstPolicy(protection.Settings{"agent.burst": {Action: protection.ActionConfirm}}, nil)
	policy.Rules = []PolicyRule{{ID: "managed-file", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true}}
	in := benignRead(policy, NewBehaviorWindow(10*time.Second, BehaviorThresholds{}))
	in.Arguments = map[string]any{"file_path": "/home/dev/npu-gateway/internal/token/refresh.yaml"}
	got := AnalyzeToolCall(context.Background(), in)
	if got.EffectiveDecision != DecisionAudit {
		t.Fatalf("the explicit audit rule still wins: %+v", got)
	}
	alertHit := false
	for _, hit := range got.ProtectionHits {
		if hit.Reason == "sensitive_name_hint" && hit.Action == string(protection.ActionAlertAllow) {
			alertHit = true
		}
	}
	if !alertHit {
		t.Fatalf("fixture must carry an alert-allow hit: %+v", got.ProtectionHits)
	}
	if !got.NotificationRequired {
		t.Fatalf("an alert-allow hit must still notify: %+v", got)
	}
	recordOnly := in
	recordOnly.Mode = ModeAudit
	if got := AnalyzeToolCall(context.Background(), recordOnly); got.NotificationRequired {
		t.Fatalf("record-only callers still only record: %+v", got)
	}
}

func TestAlert2922ExceptedAlertHitDoesNotNotify(t *testing.T) {
	exception := []PolicyException{{ID: "e-name", RuleID: "agent.sensitive_name", ExpiresAt: time.Now().Add(time.Hour)}}
	policy := burstPolicy(protection.Settings{"agent.burst": {Action: protection.ActionConfirm}}, exception)
	policy.Rules = []PolicyRule{{ID: "managed-file", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true}}
	in := benignRead(policy, NewBehaviorWindow(10*time.Second, BehaviorThresholds{}))
	in.Arguments = map[string]any{"file_path": "/home/dev/npu-gateway/internal/token/refresh.yaml"}
	if got := AnalyzeToolCall(context.Background(), in); got.NotificationRequired {
		t.Fatalf("an alert-allow hit released by its exception does not notify: %+v", got)
	}
}
