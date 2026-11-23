package handler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func TestHardeningFBehaviorConversionDistinguishesExplicitBurstsFromDefaults(t *testing.T) {
	// 2.9.22：配置的突发结论是确认；策略未开确认通道时按 agent.confirm_without_channel，
	// 经 protections 下发配成阻断时照拦，默认告警放行。
	const fallbackBlock = `{"agent.confirm_without_channel":{"action":"block","params":{}}}`
	// 2.9.22 批次 2B：突发改成防护项 agent.burst，动作只看该项（不再看阈值是不是租户配的）。
	// “explicit”行原来只靠租户阈值就确认，现补上 agent.burst=confirm。
	const burstConfirmFallbackBlock = `{"agent.burst":{"action":"confirm"},"agent.confirm_without_channel":{"action":"block","params":{}}}`
	for _, test := range []struct {
		name, behavior, protections string
		calls                       int
		want                        agentguard.DecisionAction
	}{
		{"explicit", `{"file_read_burst_10s":2}`, burstConfirmFallbackBlock, 2, agentguard.DecisionBlock},
		{"explicit-default-fallback-alerts", `{"file_read_burst_10s":2}`, `{}`, 2, agentguard.DecisionAudit},
		{"sequence-only-keeps-heuristic-default", `{"sensitive_read_egress_window_seconds":60}`, fallbackBlock, defaultAgentGuardBehaviorThresholds.FileReadBurst, agentguard.DecisionAudit},
		{"explicit-zero-disables-burst", `{"file_read_burst_10s":0}`, fallbackBlock, 2, agentguard.DecisionAllow},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data agentGuardPolicyData
			if err := json.Unmarshal([]byte(`{"mode":"strict","behavior":`+test.behavior+`,"protections":`+test.protections+`}`), &data); err != nil {
				t.Fatal(err)
			}
			policy := convertAgentGuardPolicy(&data)
			policy = cloneAgentGuardEffectivePolicy(policy)
			input := agentguard.ToolCallAnalysisInput{ToolName: "file.read", ToolType: "file", Arguments: map[string]any{"path": "/repo/readme.txt"}, ActorKey: "configured-source", Policy: policy, Behavior: agentguard.NewBehaviorWindow(10*time.Second, defaultAgentGuardBehaviorThresholds), Mode: agentguard.ModeStrict}
			var got agentguard.Decision
			for i := 0; i < test.calls; i++ {
				got = agentguard.AnalyzeToolCall(context.Background(), input)
			}
			if got.EffectiveDecision != test.want {
				t.Fatalf("behavior source must govern enforcement: got=%+v want=%s policy=%+v", got, test.want, policy.Behavior)
			}
		})
	}
}
