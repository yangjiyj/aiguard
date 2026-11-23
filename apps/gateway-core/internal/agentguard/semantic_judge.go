package agentguard

import "context"

// SemanticJudge 对工具调用做大模型语义裁判（越狱/角色扮演/指令覆盖/数据外泄诱导）。
// 契约：error/超时 → 调用方按 fail-open 处理（裁判结果被忽略，等价 allow）。
// 实现方（handler 包）须保证裁判结果为 observe-only——绝不返回 block。
type SemanticJudge interface {
	Judge(ctx context.Context, toolName string, args map[string]any) (Decision, error)
}

// shouldConsultSemanticJudge 门控：仅在 provenance==tainted 或确定性层已非 allow
// （已 audit/confirm/block，即“不确定/有风险”）时才调用昂贵的大模型裁判。
func shouldConsultSemanticJudge(decision Decision) bool {
	if decision.Provenance == ProvenanceTainted {
		return true
	}
	return decision.RawDecision != DecisionAllow
}

// clampSemanticDecision 把裁判结果钳成 observe-only 语义贡献：
// block/confirm 降级为 audit（D1/D6 永不 enforcement）。
func clampSemanticDecision(judged Decision) Decision {
	switch judged.RawDecision {
	case DecisionBlock, DecisionConfirm:
		judged.RawDecision = DecisionAudit
	}
	return judged
}
