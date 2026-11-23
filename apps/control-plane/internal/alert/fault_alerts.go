package alert

import (
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// agentToolFailureLoopCategory 与网关 handler.toolFailureLoopCategory 一致：智能体反复重试同一个
// 失败的工具。它是运行状况，不是检测故障，也不是安全风险。
const agentToolFailureLoopCategory = "agent_tool_failure_loop"

// agentToolFailureLoopTitleCN 与前端叫法一致：apps/web-console/src/utils/risk.ts 的 RISK_CATEGORY_LABELS
// 里 agent_tool_failure_loop 对应“智能体工具连续失败”。它不进 faultReasonLabelCN：
// 那张表与控制台「检测运行故障」原因表逐项对齐，工具连续失败不是检测原因。
const agentToolFailureLoopTitleCN = "智能体工具连续失败"

// faultReasonKeys are the matched_summary keys the engine uses for the same
// idea. semantic_reason is the current contract; inspection_reason is the older
// name that still appears on stored events and in the console's fallback read.
var faultReasonKeys = []string{"semantic_reason", "inspection_reason"}

// semanticFaultReason reads the engine's fault reason off an event. Empty means
// the engine did not classify the failure, which is itself worth telling an
// operator: the title falls back to a neutral label instead of leaking "".
func semanticFaultReason(ev *repository.SecurityEvent) string {
	if ev == nil {
		return ""
	}
	for _, key := range faultReasonKeys {
		if value, _ := ev.MatchedSummary[key].(string); strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if isInspectionFaultOnlyEvent(ev) {
		findings, _ := ev.MatchedSummary["findings"].([]any)
		for _, raw := range findings {
			f, _ := raw.(map[string]any)
			if isLegacyToolFailureLoopFinding(f, ev) {
				return agentToolFailureLoopCategory
			}
			if f["evidence_kind"] == "runtime" {
				if category, ok := f["category"].(string); ok {
					return category
				}
			}
		}
	}
	return ""
}

// faultGroupKey folds every runtime fault of one stage and reason onto a single
// alert group.
//
// The evidence that distinguishes two occurrences -- which host answered, which
// request tripped it, which rule version ran -- is exactly what must NOT split
// them. An operator wants one row saying "the judge breaker is open on input
// traffic", not one row per host that happened to fail. Callers still scope the
// key by project and stage (ScopedAlertGroupKey), so the same fault on input and
// output remains two rows.
//
// A missing reason falls back to the event type: two unclassified failures of
// different kinds are not obviously the same failure, and merging them would
// lose the distinction permanently.
func faultGroupKey(ev *repository.SecurityEvent) string {
	reason := semanticFaultReason(ev)
	if reason == "" {
		reason = ev.EventType
	}
	return "fault|" + alertStage(ev) + "|" + reason
}

// isToolFailureLoopEvent 识别新旧两种形态的工具连续失败（运行告警，原因 agent_tool_failure_loop）。
func isToolFailureLoopEvent(ev *repository.SecurityEvent) bool {
	return ev != nil && alertTypeForSecurityEvent(ev) == "runtime_fault" && semanticFaultReason(ev) == agentToolFailureLoopCategory
}

// alertStage 是告警分组键与组阶段用的阶段。工具连续失败一律是 tool：2.9.16 及更早的网关没给它标阶段，
// 落库成请求的 input 阶段，读取侧统一后新旧形态才落进同一个组。其它事件取 matched_summary.stage。
func alertStage(ev *repository.SecurityEvent) string {
	if isToolFailureLoopEvent(ev) {
		return "tool"
	}
	return eventStage(ev)
}

// faultAlertTitle is the operator-facing title for a runtime fault. A detection
// fault is not an attack, so the title must not read like one: it names the
// fault, the engine's reason in Chinese, and the pipeline stage it happened on.
func faultAlertTitle(ev *repository.SecurityEvent) string {
	if semanticFaultReason(ev) == agentToolFailureLoopCategory {
		return agentToolFailureLoopTitleCN
	}
	label := faultReasonLabel(semanticFaultReason(ev))
	stage := strings.TrimSpace(eventStage(ev))
	if stage == "" {
		return faultDisplayLabelCN + " · " + label
	}
	return fmt.Sprintf("%s · %s%s%s%s", faultDisplayLabelCN, label, faultStageParenOpen, stage, faultStageParenClose)
}

// alertGroupTitle builds the group title. Runtime faults get their own shape:
// the generic attack-shaped title ("security event [severity] ... disposition ...")
// describes an attack, and a fault has no attack to describe.
func alertGroupTitle(ev *repository.SecurityEvent, lc lifecycleFields) string {
	if alertTypeForSecurityEvent(ev) == "runtime_fault" {
		return faultAlertTitle(ev)
	}
	return fmt.Sprintf("安全事件【%s】%s · 处置：%s", severityLabelCN(lc.effectiveSeverity), alertSubjectCN(ev), actionLabelCN(ev.ActionTaken))
}

// alertSubjectCN 是告警标题的主体：具体类别 + 发生位置（工具事件为「智能体 · 工具」，
// 内容事件为用户输入 / 模型输出）。告警组标题、收件箱与外部通知标题共用。
func alertSubjectCN(ev *repository.SecurityEvent) string {
	label := eventDisplayLabelCN(ev)
	if suffix := toolEventContextSuffix(ev); suffix != "" {
		return label + suffix
	}
	if ev != nil && !strings.HasPrefix(strings.ToLower(ev.EventType), "tool_") {
		if where := contentStageLabelCN[eventStage(ev)]; where != "" {
			return label + "（" + where + "）"
		}
	}
	return label
}

var contentStageLabelCN = map[string]string{"input": "用户输入", "output": "模型输出"}

// genericContentEventTypes 的事件类型名（安全检测、数据安全…）说明不了出了什么事，
// 标题改用命中规则或类别的中文名。
var genericContentEventTypes = map[string]bool{
	"security_check": true, "data_security": true, "file_security": true, "prompt_guard": true,
}

// findingCategoryLabelCN 只收录命中规则名缺失、泛化或含内部术语时需要的类别中文名
// （与 web-console risk.ts 同口径）；其余优先用规则名。
var findingCategoryLabelCN = map[string]string{
	"prompt_input_semantic_risk": "Prompt 注入语义风险",
	"env_file":                   "环境变量文件内容",
	"config_file":                "配置文件内容",
	"keyword":                    "自定义关键词规则",
	"regex":                      "自定义正则规则",
	"customer_sensitive_data":    "客户敏感数据",
	"ssh_private_key":            "SSH 私钥",
	"openssh_private_key":        "SSH 私钥",
}

var genericRuleNames = map[string]bool{"自定义": true, "策略中心托管规则": true}

func specificFindingLabelCN(finding map[string]any) string {
	category, _ := finding["category"].(string)
	category = strings.ToLower(strings.TrimSpace(category))
	ruleName, _ := finding["rule_name"].(string)
	ruleName = strings.TrimSpace(ruleName)
	if label := findingCategoryLabelCN[category]; label != "" && (ruleName == "" || genericRuleNames[ruleName] || strings.Contains(strings.ToLower(ruleName), "tier")) {
		return label
	}
	if ruleName != "" && !genericRuleNames[ruleName] && containsHan(ruleName) {
		return ruleName
	}
	return findingCategoryLabelCN[category]
}

func containsHan(text string) bool {
	for _, r := range text {
		if r >= '\u4e00' && r <= '\u9fff' {
			return true
		}
	}
	return false
}

// toolEventContextSuffix gives tool-domain events a "（agent · tool）" context
// suffix so operators can tell which tool (and agent) produced the alert
// without opening the event. Only keys that actually exist in matched_summary
// are used — the gateway's tool write path records the tool name as the
// dominant finding's rule_name, the MCP path records tool_name/agent_type.
// No suffix is added when no tool identity is present (never fabricated).
func toolEventContextSuffix(ev *repository.SecurityEvent) string {
	if ev == nil || !strings.HasPrefix(strings.ToLower(ev.EventType), "tool_") {
		return ""
	}
	parts := make([]string, 0, 2)
	if agent := summaryKey(ev, "agent_type"); agent != "" {
		parts = append(parts, agent)
	}
	tool := summaryKey(ev, "tool_name")
	if tool == "" {
		tool = summaryKey(ev, "rule_name")
	}
	if tool != "" {
		parts = append(parts, tool)
	}
	if len(parts) == 0 {
		return ""
	}
	return "（" + strings.Join(parts, " · ") + "）"
}

func summaryKey(ev *repository.SecurityEvent, key string) string {
	if ev == nil {
		return ""
	}
	value, _ := ev.MatchedSummary[key].(string)
	return strings.TrimSpace(value)
}

// isLegacyToolFailureLoopFinding 识别 2.9.16 及更早写下的「工具连续失败」存量形态：高危、计入告警，
// finding type=tool_failure_loop，或 category=tool_risk 且事件/命中的 action 为 tool_failure_loop。
// 只认这两种，其它 tool_risk 告警不受影响。控制面读取侧据此把它当运行观察，数据库数据不改。
func isLegacyToolFailureLoopFinding(f map[string]any, ev *repository.SecurityEvent) bool {
	lower := func(v any) string { s, _ := v.(string); return strings.ToLower(strings.TrimSpace(s)) }
	if lower(f["type"]) == "tool_failure_loop" {
		return true
	}
	if lower(f["category"]) != "tool_risk" {
		return false
	}
	const loop = "tool_failure_loop"
	return lower(f["action_taken"]) == loop || lower(f["action"]) == loop || (ev != nil && strings.ToLower(strings.TrimSpace(ev.ActionTaken)) == loop)
}

// Only explicit inspection failures enter the operational lane. A sibling
// threat keeps the event in the security lane even if inspection also failed.
func isInspectionFaultOnlyEvent(ev *repository.SecurityEvent) bool {
	if ev == nil {
		return false
	}
	findings, _ := ev.MatchedSummary["findings"].([]any)
	failure := false
	for _, raw := range findings {
		f, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		if isLegacyToolFailureLoopFinding(f, ev) {
			failure = true
			continue
		}
		counts, exists := f["counts_as_security_finding"].(bool)
		if !exists || counts {
			return false
		}
		kind, _ := f["evidence_kind"].(string)
		category, _ := f["category"].(string)
		if kind == "runtime" && (category == "file_unknown_type" || category == "custom_regex_timeout" || category == "custom_scan_incomplete" || category == agentToolFailureLoopCategory) {
			failure = true
		}
	}
	return failure
}
