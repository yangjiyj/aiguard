package handler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

const destructiveEvidenceMaxRunes = 200

var destructiveTargetCountPattern = regexp.MustCompile(`(\d+)-targets$`)

// agentGuardFindingEvidence 给告警写一段管理员看得懂的证据。破坏性操作写“做了什么：命令骨架”，
// 骨架取自闸门分析时记下的触发段（Decision.EvidenceSegments），只显示可执行文件、子命令、选项和破坏目标，
// 其余一律写 …；闸门没做破坏性分析、或拿不到触发段时写“做了什么（N 个目标）”，不写命令。
// 其它决策保持原来的规范化目标。
func agentGuardFindingEvidence(decision agentguard.Decision) string {
	if !isDestructiveGateDecision(decision) && decision.RiskCategory != agentguard.DestructiveRiskCategory {
		return decision.NormalizedTarget
	}
	if command := renderEvidenceSegments(decision.EvidenceSegments); command != "" {
		return destructiveSubcategoryLabel(decision) + "：" + command
	}
	return destructiveEvidenceWithoutCommand(decision)
}

func destructiveSubcategoryLabel(decision agentguard.Decision) string {
	if label := destructiveSubcategoryLabels[decision.RiskSubcategory]; label != "" {
		return label
	}
	return "破坏性操作"
}

// destructiveEvidenceWithoutCommand 写“做了什么（N 个目标）”，不含命令；拿不到触发段时作为证据兜底。
func destructiveEvidenceWithoutCommand(decision agentguard.Decision) string {
	label := destructiveSubcategoryLabel(decision)
	if match := destructiveTargetCountPattern.FindStringSubmatch(decision.NormalizedTarget); match != nil {
		if count, err := strconv.Atoi(match[1]); err == nil && count > 0 {
			return fmt.Sprintf("%s（%d 个目标）", label, count)
		}
	}
	return label
}

// renderEvidenceSegments 渲染每个触发段，多段用 " ; " 连接，渲染和纵深检测之后再按 rune 截断。
func renderEvidenceSegments(segments []agentguard.EvidenceSegment) string {
	return truncateEvidence(joinEvidenceSegments(segments, 0))
}

func joinEvidenceSegments(segments []agentguard.EvidenceSegment, depth int) string {
	rendered := make([]string, 0, len(segments))
	for _, segment := range segments {
		if text := renderEvidenceSegment(segment, depth); text != "" {
			rendered = append(rendered, text)
		}
	}
	return strings.Join(rendered, " ; ")
}

func truncateEvidence(text string) string {
	if runes := []rune(text); len(runes) > destructiveEvidenceMaxRunes {
		return string(runes[:destructiveEvidenceMaxRunes]) + "…"
	}
	return text
}
