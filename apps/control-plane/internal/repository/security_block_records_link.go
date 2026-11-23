package repository

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// PolicyLink 告诉控制台“这条阻断/告警由哪条可配置的策略决定、去哪里改”。
// Kind=none 表示没有可配置的策略（如升级前写入、没有保存具体防护项的旧拦截记录），前端只显示名称；
// Kind=deleted 表示命中的策略已被删除，前端显示“该策略已删除”，不给链接；
// Kind=protection_item 表示由某个防护项决定，ItemKey 是注册表里的键，可在该防护项下加例外；
// Kind=protection_group 表示只能确定到防护项分组（如升级前的旧原因码），Group 是注册表里的分组，没有 ItemKey。
type PolicyLink struct {
	Kind    string `json:"kind"`
	Path    string `json:"path,omitempty"`
	Label   string `json:"label,omitempty"`
	ItemKey string `json:"item_key,omitempty"`
	Group   string `json:"group,omitempty"`
}

// rulesTableIDPrefix 是 rules 表编号的前缀（rule_<uuid 前 8 位> 等）。
// catalog_、semantic_ 等编号不在 rules 表里，不能据此判断“策略已删除”。
const rulesTableIDPrefix = "rule_"

func policyCenterLink(ruleID, label string) *PolicyLink {
	return &PolicyLink{Kind: "policy", Path: "/security/policies?policy=" + url.QueryEscape(ruleID), Label: label}
}

// agentBehaviorLink 指向「智能体行为」页的某个行为。没有对应的行为中文名时用 fallbackLabel，不输出空 label。
func agentBehaviorLink(key, fallbackLabel string) *PolicyLink {
	label := PolicyCenterAgentBehaviorLabels[key]
	if label == "" {
		label = fallbackLabel
	}
	return &PolicyLink{Kind: "agent_behavior", Path: "/security/agents?behavior=" + url.QueryEscape(key), Label: label}
}

// exceptionTargetMaxRunes 是预填到例外链接里的调用目标长度上限；超过的不带 target，
// 截断后的前缀会让例外匹配范围比原调用更宽。
const exceptionTargetMaxRunes = 200

var urlInTextPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// blockedCallTarget 取阻断详情里网关整理出的调用目标（详情形如 “Bash · curl https://x”，“ · ” 之后的部分）。
// 网关的例外按调用目标（地址、路径、命令）匹配，不是工具名。目标会进浏览器地址栏和历史记录，
// 所以去掉其中 URL 的账号口令、query、fragment；取不到、被截断（以“…”结尾）或过长时返回空。
func blockedCallTarget(detail string) string {
	_, target, found := strings.Cut(strings.TrimSpace(detail), " · ")
	target = strings.TrimSpace(target)
	if !found || target == "" || strings.HasSuffix(target, "…") || strings.HasSuffix(target, "...") {
		return ""
	}
	original := target
	hasCredentials := false
	target = urlInTextPattern.ReplaceAllStringFunc(target, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return raw
		}
		if parsed.User != nil {
			hasCredentials = true
		}
		parsed.User, parsed.RawQuery, parsed.Fragment, parsed.ForceQuery = nil, "", "", false
		return parsed.String()
	})
	// 网关按包含关系匹配调用目标；去掉账号口令后的文本不再是原调用的子串，预填的例外不会生效。
	// 去掉 query/fragment 后若不再是原目标的子串（如 URL 后面还有参数），预填的例外同样不会生效。
	if hasCredentials || !strings.Contains(original, target) || utf8.RuneCountInString(target) > exceptionTargetMaxRunes {
		return ""
	}
	return target
}

// skillAdmissionReasons 是 Skill 准入类的分析器风险原因（网关 agentguard/skill.go）：
// 由 Skill 准入决定，去「Skill 安全准入」页处理，不是放行例外。
var skillAdmissionReasons = map[string]bool{
	"skill_dangerous_command": true, "skill_version_quarantined": true, "skill_version_revoked": true,
	"skill_admission_unavailable": true, "skill_identity_misplaced": true, "skill_identity_invalid": true, "skill_identity_conflict": true,
}

// managedBehaviorKeyFromRuleID 解析托管规则编号 policy-center-<行为键>；不是托管编号或键未知时返回空。
// 阻断记录与告警共用这一处解析。
func managedBehaviorKeyFromRuleID(ruleID string) string {
	key, ok := strings.CutPrefix(strings.TrimSpace(ruleID), policyCenterManagedRulePrefix)
	if !ok || PolicyCenterAgentBehaviorLabels[key] == "" {
		return ""
	}
	return key
}

// managedBehaviorKey 找出阻断所属的托管智能体行为键：依次取网关写的 block.managed_behavior、
// 旧形态 rule_id 的 policy-center- 前缀、再用原始规则名反查行为中文名（现场 2.9.16 数据没有前两者）。
// 规则名反查只用于智能体工具层，避免内容规则恰好叫“系统命令”被当成行为。
func managedBehaviorKey(block, blocking map[string]any, layer string) string {
	str := func(source map[string]any, key string) string {
		value, _ := source[key].(string)
		return strings.TrimSpace(value)
	}
	if key := str(block, "managed_behavior"); PolicyCenterAgentBehaviorLabels[key] != "" {
		return key
	}
	for _, id := range []string{str(block, "rule_id"), str(blocking, "rule_id")} {
		if key := managedBehaviorKeyFromRuleID(id); key != "" {
			return key
		}
	}
	if layer == "agent_tool" {
		for _, name := range []string{str(block, "rule_name"), str(blocking, "rule_name")} {
			for key, label := range PolicyCenterAgentBehaviorLabels {
				if name != "" && name == label {
					return key
				}
			}
		}
	}
	return ""
}

// blockRuleIDCandidates 列出阻断记录可能指向的规则编号，顺序与 projectSecurityBlockAttribution 的取值一致。
func blockRuleIDCandidates(summary map[string]any, eventRuleID string) []string {
	str := func(source map[string]any, key string) string {
		value, _ := source[key].(string)
		return strings.TrimSpace(value)
	}
	block, _ := summary["block"].(map[string]any)
	blocking := blockingFindingFromSummary(summary)
	var out []string
	primary, _ := summary["primary_finding"].(map[string]any)
	for _, candidate := range []string{str(block, "rule_id"), str(blocking, "rule_id"), str(summary, "rule_id"), str(primary, "rule_id"), strings.TrimSpace(eventRuleID)} {
		if candidate != "" {
			out = append(out, candidate)
		}
	}
	return out
}

// blockFinalRuleID 是阻断记录最终展示的规则编号（第一个非空候选）。
func blockFinalRuleID(summary map[string]any, eventRuleID string) string {
	if candidates := blockRuleIDCandidates(summary, eventRuleID); len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// blockPolicyLink 按阻断位置与网关记录的处置原因推导跳转目标。
// eventRuleID 是 security_events.rule_id；ruleRowExists 表示最终规则编号在 rules 表中仍存在。
func blockPolicyLink(record *SecurityBlockRecord, summary map[string]any, eventRuleID string, ruleRowExists bool) *PolicyLink {
	str := func(source map[string]any, key string) string {
		value, _ := source[key].(string)
		return strings.TrimSpace(value)
	}
	block, _ := summary["block"].(map[string]any)
	rawRuleID := blockFinalRuleID(summary, eventRuleID)
	blocking := blockingFindingFromSummary(summary)
	origin := classifyAgentToolBlock(record, block, blocking)
	if link := origin.link(record); link != nil {
		return link
	}
	// MCP 代理阻断（网关 mcp_proxy_audit.go 写 source=gateway_mcp）：看 MCP 调用策略。
	if str(summary, "source") == "gateway_mcp" {
		return &PolicyLink{Kind: "mcp_tool", Path: "/mcp-gateway/policies", Label: "MCP 调用策略"}
	}
	managed := strings.HasPrefix(rawRuleID, policyCenterManagedRulePrefix)
	if key := managedBehaviorKey(block, blocking, record.Layer); key != "" {
		return agentBehaviorLink(key, record.RuleName)
	}
	switch record.Layer {
	case "restricted_file":
		return agentBehaviorLink("sensitive_resource", record.RuleName)
	case "destructive_operation":
		return agentBehaviorLink("destructive_operation", record.RuleName)
	case "mcp_tool": // 兜底：网关目前不写这个层，MCP 阻断靠 source 识别
		return &PolicyLink{Kind: "mcp_tool", Path: "/mcp-gateway/policies", Label: "MCP 调用策略"}
	case "agent_tool":
		// 自定义智能体高级规则：控制台没有编辑它的页面（高级规则页签是删除与破坏保护设置），只显示规则名。
		if rawRuleID != "" && !managed && !ruleRowExists {
			return &PolicyLink{Kind: "none", Label: record.RuleName}
		}
	}
	if rawRuleID != "" && strings.HasPrefix(rawRuleID, rulesTableIDPrefix) {
		if ruleRowExists {
			return policyCenterLink(rawRuleID, record.RuleName)
		}
		return &PolicyLink{Kind: "deleted", Label: record.RuleName}
	}
	if ruleRowExists && rawRuleID != "" {
		return policyCenterLink(rawRuleID, record.RuleName)
	}
	return &PolicyLink{Kind: "none", Label: record.RuleName}
}

// alertPolicyRuleTypes 是以 rules 表行存在的自定义规则类型；它们的 rule_id 就是策略中心里的编号。
var alertPolicyRuleTypes = map[string]bool{
	"regex": true, "keyword": true, "field_name": true, "secret": true, "edm": true, "file_fingerprint": true,
}

// alertPolicyLink 按告警命中推导跳转目标，没有可配置策略时返回 nil。只用网关写入的可靠字段：
//   - 删除与破坏：类型 tool_destructive_intent，或被阻断调用的 rule_id 为 destructive_operation；
//   - 被阻断的智能体工具调用：事件里网关记的托管行为键（ManagedBehavior）；
//   - tool_policy_alert：rule_id 为 policy-center-<行为键> 时指向该行为，自定义高级规则没有编辑页面，不给链接；
//   - 受限文件类别（网关固定写入，且不是自定义规则）指向“敏感资源访问”；
//   - 确认放行、策略加载失败等没有可对应的行为键，不给链接，也不按工具名猜。
//
// 前提：告警侧不看 block.cause，依赖网关 ApplyPolicy 下“高风险判定/防护项”与托管行为键不会同时出现
// （两者同时出现时阻断记录侧按 cause 优先，告警侧会给出行为链接）。
func alertPolicyLink(item *AlertOccurrence) *PolicyLink {
	ruleID := strings.TrimSpace(item.RuleID)
	switch {
	case item.Type == "tool_destructive_intent" || ruleID == "destructive_operation":
		return agentBehaviorLink("destructive_operation", item.RuleName)
	case item.Type == "tool_attempt_blocked":
		if key := strings.TrimSpace(item.ManagedBehavior); PolicyCenterAgentBehaviorLabels[key] != "" {
			return agentBehaviorLink(key, item.RuleName)
		}
		if key := managedBehaviorKeyFromRuleID(ruleID); key != "" {
			return agentBehaviorLink(key, item.RuleName)
		}
		return nil
	case item.Type == "tool_policy_alert" || strings.HasPrefix(ruleID, policyCenterManagedRulePrefix):
		if key := managedBehaviorKeyFromRuleID(ruleID); key != "" {
			return agentBehaviorLink(key, item.RuleName)
		}
		return nil
	case item.Category == "restricted_file_access" && strings.TrimSpace(item.RuleType) == "" && strings.TrimSpace(item.PolicyCode) == "":
		return agentBehaviorLink("sensitive_resource", item.RuleName)
	case ruleID == "" || strings.HasPrefix(ruleID, "catalog_") || strings.HasPrefix(ruleID, "semantic_"):
		return nil
	case strings.TrimSpace(item.PolicyCode) != "" || alertPolicyRuleTypes[strings.TrimSpace(item.RuleType)]:
		return policyCenterLink(ruleID, item.RuleName)
	}
	return nil
}
