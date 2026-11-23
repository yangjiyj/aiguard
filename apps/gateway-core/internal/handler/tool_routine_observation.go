package handler

import (
	"regexp"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2026-11-22 用户拍板：工具调用类告警只留真危险的，日常开发操作只留痕。
//
// 只留痕（ObservationOnly）：决策照常给出、工具日志照常写（含原因码、证据），但不写进入告警中心的安全事件、
// 不要求通知、最终动作记为“仅记录”。执行决策（放行/确认/阻断）和执行模式不动：只在“告警放行/只审计”的结果
// （生效决策是审计）上做，严格模式下已确认或阻断的调用原样处理。
//
// 算日常的：
//   - 清临时文件与构建产物、工作区里的具体文件或子目录、系统目录下的单个运行时文件（分析器标的 Routine）；
//   - 普通 shell 拼接、解释器调用、不含下载/解码/动态执行的变量插值；
//   - 只读查看类命令（cat/ls/grep…）被“不在放行名单”兜底；
//   - 非 shell 的只读工具（grep_search、Read 这类）参数解析失败的兜底命中。
//
// 凡命中防护项（敏感目标、凭据文件、受限文件、Skill 等）、带管理员配置的强制处置、严重级的调用，一律不算。
const routineObservationEvidence = "agent_routine_operation_trace_only"

var readOnlyToolNamePattern = regexp.MustCompile(`(?i)(?:^|[._-])(?:grep|search|glob|read|view|list|find|ls|cat|get|stat|lookup|fetch)(?:$|[._-])|^(?:grep|read|glob|ls|cat)$`)

// routineObservation 判断一条已经定好处置的结论是否只需留痕；返回的原因写进证据。
func routineObservation(input structuredToolCallInput, decision agentguard.Decision, analysis agentguard.DestructiveAnalysis) (string, bool) {
	if decision.EffectiveDecision != agentguard.DecisionAudit || decision.ConfiguredEnforcement || decision.RestrictedFileMatched {
		return "", false
	}
	switch {
	case parseRejectedOnReadOnlyTool(input, decision, analysis):
		return "parse_rejected_read_only_tool", true
	case len(decision.ProtectionHits) > 0:
		return "", false
	case analysis.Category != "":
		if analysis.Routine && analysis.RiskLevel != "critical" {
			return "routine_filesystem_operation", true
		}
	case decision.Reason == "shell_composition_observed" || decision.Reason == "shell_interpreter_observed":
		// 往外送数据、下载即执行的管道不算普通拼接，照常告警。
		if agentguard.CompositionSendsDataOut(input.Arguments) {
			return "", false
		}
		return "plain_shell_composition", true
	case decision.Reason == "shell_interpolation_requires_confirm" && decision.RiskLevel != "high" && decision.RiskLevel != "critical":
		// 变量/命令替换里带下载、解码、动态执行（curl/base64/eval…）时分析器标高危，那种不算普通插值，照常告警。
		return "plain_shell_interpolation", true
	case decision.Reason == "command_not_allowlisted" && agentguard.ReadOnlyInspectionCall(input.Arguments):
		return "read_only_inspection_command", true
	}
	return "", false
}

// parseRejectedOnReadOnlyTool：只读工具（非 shell、名字不含删除类动作）参数解析失败，命中的只有
// “参数无法解析”这一个兜底防护项；管理员显式配过这个防护项（动作、例外）的租户照其配置，不在这里吞掉。
func parseRejectedOnReadOnlyTool(input structuredToolCallInput, decision agentguard.Decision, analysis agentguard.DestructiveAnalysis) bool {
	if !input.ArgumentsParseRejected && !analysis.ParseRejected {
		return false
	}
	if len(decision.ProtectionHits) == 0 {
		return false
	}
	for _, hit := range decision.ProtectionHits {
		if hit.Reason != protection.ReasonParseRejected {
			return false
		}
	}
	if input.Policy != nil {
		if _, configured := input.Policy.Protections[protection.KeyParseRejected]; configured {
			return false
		}
	}
	name := strings.TrimSpace(input.ToolName)
	if !readOnlyToolNamePattern.MatchString(name) || structuredExecutionToolType(input.ToolType, input.Arguments) == "shell" {
		return false
	}
	return !strings.Contains(strings.ToLower(name), "delete") && !strings.Contains(strings.ToLower(name), "remove") &&
		!strings.Contains(strings.ToLower(name), "exec") && !strings.Contains(strings.ToLower(name), "run")
}

// applyRoutineObservation 把日常开发操作的结论改成只留痕。
func applyRoutineObservation(input structuredToolCallInput, decision agentguard.Decision, analysis agentguard.DestructiveAnalysis) agentguard.Decision {
	reason, ok := routineObservation(input, decision, analysis)
	if !ok {
		return decision
	}
	decision.ObservationOnly = true
	decision.NotificationRequired = false
	if decision.FinalAction == agentguard.DestructiveActionAlertAllow {
		decision.FinalAction = agentguard.DestructiveActionRecord
		decision.Mode = agentguard.ModeAudit
	}
	if decision.EffectiveReason == "destructive_alert_allow" {
		decision.EffectiveReason = "destructive_recorded"
	}
	decision.Evidence = append(append([]agentguard.Evidence(nil), decision.Evidence...), agentguard.Evidence{
		RuleID: routineObservationEvidence, Category: "agent_routine_operation", SourceField: "arguments", MaskedPreview: reason,
	})
	return decision
}
