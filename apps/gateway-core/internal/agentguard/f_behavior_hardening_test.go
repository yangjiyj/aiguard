package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22：突发是防护项 agent.burst 的命中，动作只看该项配置（不再看阈值是不是租户配的）。
// 原用例锁的是“默认阈值只记录、租户阈值按确认执行”，改为“默认告警放行、配成确认照确认、
// 无通道时按 agent.confirm_without_channel、观察留痕下只记录”。
func TestHardeningFConfiguredBurstsEnforceButDefaultWindowOnlyRecords(t *testing.T) {
	for _, kind := range []BehaviorKind{BehaviorFileRead, BehaviorNetworkEgress, BehaviorCommandExecute} {
		t.Run(string(kind), func(t *testing.T) {
			thresholds := BehaviorThresholds{FileReadBurst: 2, NetworkEgressBurst: 2, CommandExecuteBurst: 2}
			window := NewBehaviorWindow(10*time.Second, thresholds)
			event := BehaviorEvent{ActorKey: "default-actor", Kind: kind, Target: "example.test", Now: time.Now()}
			window.Record(event)
			raw := window.Record(event)
			if raw.Reason != behaviorBurstReason || len(raw.ProtectionHits) != 1 || raw.ConfiguredEnforcement {
				t.Fatalf("a burst is an agent.burst hit, not a verdict of its own: %+v", raw)
			}
			in := PolicyEvaluationInput{ToolName: "t", CallerMode: ModeStrict, Policy: &EffectivePolicy{Mode: ModeStrict}}
			if got := ApplyEffectivePolicy(raw, in); got.EffectiveDecision != DecisionAudit || !got.NotificationRequired {
				t.Fatalf("default agent.burst alerts and allows: %+v", got)
			}
			for _, confirmEnabled := range []bool{false, true} {
				want := DecisionBlock
				if confirmEnabled {
					want = DecisionConfirm
				}
				in.Policy = &EffectivePolicy{Mode: ModeStrict, ConfirmChannelEnabled: confirmEnabled, Protections: protection.Settings{
					"agent.burst": {Action: protection.ActionConfirm}, "agent.confirm_without_channel": {Action: protection.ActionBlock}}}
				if got := ApplyEffectivePolicy(raw, in); got.EffectiveDecision != want {
					t.Fatalf("agent.burst=confirm must confirm (or fall back): channel=%t got=%+v", confirmEnabled, got)
				}
			}
			in.CallerMode = ModeAudit
			if got := ApplyEffectivePolicy(raw, in); got.EffectiveDecision != DecisionAudit {
				t.Fatalf("record mode must retain hard lock: %+v", got)
			}
		})
	}
}

func TestHardeningFPolicyBurstThresholdFlowsThroughToolAnalysis(t *testing.T) {
	window := NewBehaviorWindow(time.Second, BehaviorThresholds{FileReadBurst: 100})
	input := ToolCallAnalysisInput{ToolName: "file.read", ToolType: "file", Arguments: map[string]any{"path": "/repo/readme.txt"}, ActorKey: "configured-tool", Behavior: window, Mode: ModeStrict, Policy: &EffectivePolicy{Mode: ModeStrict, Behavior: &BehaviorThresholds{FileReadBurst: 2},
		Protections: protection.Settings{"agent.burst": {Action: protection.ActionConfirm}, "agent.confirm_without_channel": {Action: protection.ActionBlock}}}}
	AnalyzeToolCall(context.Background(), input)
	got := AnalyzeToolCall(context.Background(), input)
	if got.EffectiveDecision != DecisionBlock || !got.ConfiguredEnforcement {
		t.Fatalf("tenant burst threshold with agent.burst=confirm must survive analyzer merging: %+v", got)
	}
	// 2.9.22 默认 agent.burst（告警放行）：租户阈值照算，命中只告警。原断言“配置的突发结论
	// 保留（ConfiguredEnforcement）”随突发改成防护项而改为“命中 agent.burst 并告警”。
	input.ActorKey = "configured-tool-default"
	input.Policy = &EffectivePolicy{Mode: ModeStrict, Behavior: &BehaviorThresholds{FileReadBurst: 2}}
	AnalyzeToolCall(context.Background(), input)
	if byDefault := AnalyzeToolCall(context.Background(), input); byDefault.EffectiveDecision != DecisionAudit || byDefault.ProtectionItem != "agent.burst" || !byDefault.NotificationRequired {
		t.Fatalf("default agent.burst must alert and allow: %+v", byDefault)
	}
}
