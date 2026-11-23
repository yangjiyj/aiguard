package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 审查意见 1：2.9.21 的突发原因码按类别区分（behavior_file_read_burst 等），统一成 behavior_burst
// 后升级前写下的例外要照字面生效（D4）：旧码只放开对应类别的突发，新码与项键放开全部。
func TestBurst2922LegacyReasonExceptionsReleaseOnlyTheirKind(t *testing.T) {
	confirm := protection.Settings{"agent.burst": {Action: protection.ActionConfirm}}
	exception := func(ruleID string) []PolicyException {
		return []PolicyException{{ID: "e-" + ruleID, RuleID: ruleID, ExpiresAt: time.Now().Add(time.Hour)}}
	}
	read := func(ruleID string) Decision {
		return AnalyzeToolCall(context.Background(), benignRead(burstPolicy(confirm, exception(ruleID)), NewBehaviorWindow(10*time.Second, BehaviorThresholds{})))
	}
	egress := func(ruleID string) Decision {
		policy := burstPolicy(confirm, exception(ruleID))
		policy.Behavior = &BehaviorThresholds{NetworkEgressBurst: 1}
		return AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "WebFetch", ToolType: "network", Mode: ModeStrict,
			Arguments: map[string]any{"url": "https://docs.example.test/a"}, Policy: policy,
			Behavior: NewBehaviorWindow(10*time.Second, BehaviorThresholds{}), ActorKey: "tenant/p/u"})
	}
	for _, tc := range []struct {
		name     string
		got      Decision
		released bool
	}{
		{"file read released by its old code", read("behavior_file_read_burst"), true},
		{"file read kept by another kind's old code", read("behavior_network_egress_burst"), false},
		{"file read released by the new code", read("behavior_burst"), true},
		{"file read released by the item key", read("agent.burst"), true},
		{"egress released by its old code", egress("behavior_network_egress_burst"), true},
		{"egress kept by the file read old code", egress("behavior_file_read_burst"), false},
		{"egress kept by the command old code", egress("behavior_command_execute_burst"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.released {
				if tc.got.EffectiveDecision == DecisionConfirm || len(tc.got.ProtectionExceptionIDs()) != 1 {
					t.Fatalf("exception must release the burst: %+v", tc.got)
				}
				return
			}
			if tc.got.EffectiveDecision != DecisionConfirm {
				t.Fatalf("exception for another kind must not release the burst: %+v", tc.got)
			}
		})
	}
	if !isProtectionExceptionRule("behavior_file_delete_burst") {
		t.Fatal("all four old burst codes are protection exception rules")
	}
}
