package handler

import (
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// renderRecentTurnsForJudge 把最近 K 轮对话摘要渲染在工具调用之前（W5 5.10）。
// 每轮标注来源可信度，裁判据此区分用户指令与工具返回里夹带的指令。
// 没有上下文时返回空串，裁判输入与改造前完全一致。
func renderRecentTurnsForJudge(turns []agentguard.SemanticJudgeTurn) string {
	if len(turns) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("recent conversation (oldest first):\n")
	for _, turn := range turns {
		trust := string(turn.Trust)
		if trust == "" {
			trust = "unknown"
		}
		fmt.Fprintf(&b, "[%s] %s\n", trust, turn.Text)
	}
	b.WriteString("---\n")
	return b.String()
}
