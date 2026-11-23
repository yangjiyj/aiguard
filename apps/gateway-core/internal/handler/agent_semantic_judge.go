package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// agentSemanticJudge 用 security-engine 的独立 agent 语义阶段判 Agent 工具调用。
// observe-only：只取 type=semantic_attack 的 finding，映射成钳到 audit 的 Decision；
// 其余 detector 命中（pii/secret/regex）一律忽略——它们走各自既有链路，不在语义裁判职责内。
// fail-open：阶段语义调用出错、能力缺失或无语义命中 → 返回 allow + nil error。
type agentSemanticJudge struct {
	checker  SecurityChecker
	envelope *modelrouter.RequestEnvelope
}

func (j agentSemanticJudge) Judge(ctx context.Context, toolName string, args map[string]any) (agentguard.Decision, error) {
	return j.JudgeWithContext(ctx, agentguard.SemanticJudgeRequest{ToolName: toolName, Arguments: args})
}

// JudgeWithContext 同 Judge，另附最近 K 轮对话摘要（W5 5.10）。
func (j agentSemanticJudge) JudgeWithContext(ctx context.Context, req agentguard.SemanticJudgeRequest) (agentguard.Decision, error) {
	allow := agentguard.Decision{RawDecision: agentguard.DecisionAllow, Reason: "tool_call_semantic_benign", RiskLevel: "low"}
	if j.checker == nil {
		return allow, nil
	}
	content := renderRecentTurnsForJudge(req.RecentTurns) + renderToolCallForJudge(req.ToolName, req.Arguments)
	stageChecker, ok := j.checker.(semanticStageChecker)
	if !ok {
		return allow, nil // 未实现阶段语义契约时不可冒充 Agent 语义已执行
	}
	findings, err := stageChecker.CheckSemanticStage(ctx, j.envelope, content, "agent")
	if err != nil {
		return allow, nil // fail-open
	}
	worst, ok := worstSemanticFinding(findings)
	if !ok {
		return allow, nil
	}
	return agentguard.Decision{
		RawDecision: agentguard.DecisionAudit, // observe-only：最高只到 audit
		Reason:      worst.Category,
		RiskLevel:   worst.Severity,
		Confidence:  worst.Confidence,
	}, nil
}

func renderToolCallForJudge(toolName string, args map[string]any) string {
	encoded, err := json.Marshal(args)
	if err != nil {
		encoded = []byte("{}")
	}
	return fmt.Sprintf("agent tool call: %s arguments: %s", toolName, string(encoded))
}

// worstSemanticFinding 取置信度最高的 semantic_attack finding。
func worstSemanticFinding(findings []SecurityFinding) (SecurityFinding, bool) {
	var worst SecurityFinding
	found := false
	for _, f := range findings {
		if f.Type != "semantic_attack" {
			continue
		}
		if !found || f.Confidence > worst.Confidence {
			worst = f
			found = true
		}
	}
	return worst, found
}
