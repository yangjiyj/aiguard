package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 语料比对（旧突发阈值折算成 agent.burst=确认）发现：序列规则的“敏感”放宽成“命中任一敏感目标
// 防护项”后，没有突发类别的调用（如 Grep）因为命中而被当成读文件计入突发，比 2.9.21 多出确认。
// 突发的计数口径保持 2.9.21（只有受限文件或文件类工具的路径参数命中才补记读文件），放宽的“敏感”
// 只用来布防序列规则。
func TestBurst2922SensitiveHitWithoutKindArmsSequenceButDoesNotCountBurst(t *testing.T) {
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{})
	policy := &EffectivePolicy{ID: "p", Mode: ModeStrict, RuleMode: ModeStrict, ConfirmChannelEnabled: true,
		Behavior:    &BehaviorThresholds{FileReadBurst: 1, NetworkEgressBurst: 100, SensitiveReadEgressWindow: 5 * time.Minute},
		Protections: protection.Settings{"agent.burst": {Action: protection.ActionConfirm}}}
	// 合流 2A 后 Grep 的 pattern 是自由文本、不做路径判定（设计第 6 节），原来的 Grep "process.env"
	// 不再命中；改用没有突发类别、查询参数里带 .env 路径的 MCP 工具调用（MCP 参数照旧逐个扫描），
	// 仍是“命中但不按 2.9.21 计入突发”。
	lookup := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "kb_search", ToolType: "mcp", Mode: ModeStrict,
		Arguments: map[string]any{"query": "see /home/dev/app/.env"}, Policy: policy, Behavior: window, ActorKey: "a"})
	if len(lookup.ProtectionHits) == 0 {
		t.Fatalf("the fixture call must hit a sensitive target: %+v", lookup)
	}
	if lookup.EffectiveDecision == DecisionConfirm || lookup.Reason == behaviorBurstReason {
		t.Fatalf("a call without a burst kind must not count as a file read burst: %+v", lookup)
	}
	egress := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "WebFetch", ToolType: "network", Mode: ModeStrict,
		Arguments: map[string]any{"url": "https://paste.example/upload"}, Policy: policy, Behavior: window, ActorKey: "a"})
	if egress.Reason != behaviorReasonSensitiveReadEgress {
		t.Fatalf("the sensitive hit still arms the sequence rule: %+v", egress)
	}
}
