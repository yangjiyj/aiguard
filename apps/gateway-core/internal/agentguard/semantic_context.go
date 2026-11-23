package agentguard

import (
	"context"
	"strings"
)

// 语义裁判的对话上下文（W5 5.10）：只带最近 K 轮，逐条与总量都截断，
// 避免把整段对话塞给大模型裁判，也避免单条超长工具结果挤掉其它轮次。
const (
	SemanticJudgeContextTurns       = 6
	SemanticJudgeContextRunesPerMsg = 400
	SemanticJudgeContextTotalRunes  = 2000
)

// SemanticJudgeTurn 是交给裁判的一轮对话摘要。Trust 标明来源可信度，
// 裁判据此区分用户指令与工具返回/检索内容中夹带的指令。
type SemanticJudgeTurn struct {
	ID    string
	Trust Provenance
	Text  string
}

// SemanticJudgeRequest 是带对话上下文的裁判请求。
type SemanticJudgeRequest struct {
	ToolName    string
	Arguments   map[string]any
	RecentTurns []SemanticJudgeTurn
}

// ContextualSemanticJudge 是 SemanticJudge 的可选扩展：实现了它的裁判后端会收到
// 最近 K 轮对话摘要；没实现的继续走 Judge(toolName, args)，行为不变。
// 结果同样经 clampSemanticDecision 钳制，observe-only 语义不变。
type ContextualSemanticJudge interface {
	SemanticJudge
	JudgeWithContext(ctx context.Context, req SemanticJudgeRequest) (Decision, error)
}

// consultSemanticJudge 按裁判能力选择调用方式。
func consultSemanticJudge(ctx context.Context, judge SemanticJudge, toolName string, args map[string]any, fragments []ContextFragment) (Decision, error) {
	if contextual, ok := judge.(ContextualSemanticJudge); ok {
		return contextual.JudgeWithContext(ctx, SemanticJudgeRequest{
			ToolName:    toolName,
			Arguments:   args,
			RecentTurns: RecentSemanticJudgeTurns(fragments),
		})
	}
	return judge.Judge(ctx, toolName, args)
}

// RecentSemanticJudgeTurns 取最近 K 条非空片段，按原顺序返回；每条截到
// SemanticJudgeContextRunesPerMsg，总量超过 SemanticJudgeContextTotalRunes 时丢弃更早的轮次。
func RecentSemanticJudgeTurns(fragments []ContextFragment) []SemanticJudgeTurn {
	picked := make([]SemanticJudgeTurn, 0, SemanticJudgeContextTurns)
	total := 0
	for i := len(fragments) - 1; i >= 0 && len(picked) < SemanticJudgeContextTurns; i-- {
		text := strings.TrimSpace(fragments[i].Text)
		if text == "" {
			continue
		}
		text = truncateRunes(text, SemanticJudgeContextRunesPerMsg)
		n := len([]rune(text))
		if total+n > SemanticJudgeContextTotalRunes {
			break
		}
		total += n
		picked = append(picked, SemanticJudgeTurn{ID: fragments[i].ID, Trust: fragments[i].Trust, Text: text})
	}
	for l, r := 0, len(picked)-1; l < r; l, r = l+1, r-1 {
		picked[l], picked[r] = picked[r], picked[l]
	}
	return picked
}

func truncateRunes(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit]) + "..."
}
