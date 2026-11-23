package repository

import (
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 智能体工具调用阻断的“原因归类”：依据文案与跳转链接都只按这里的归类结果分支，
// 不再各自重复判断 cause / risk_reason，保证两者说的是同一处。

type originKind int

const (
	// originNone：不是智能体工具层（或没有可归类的处置原因），调用方走通用的规则/行为归因。
	originNone originKind = iota
	// originSkillAdmission：由 Skill 准入决定（skill_admission_floor、skill_invocation_risk 事件、
	// analyzer 阻断里注册表没有的 Skill 准入类原因）。
	originSkillAdmission
	// originRule：由规则决定（托管行为卡片、自定义规则、全局默认动作、确认通道）。
	originRule
	// originProtectionGroup：只能确定到防护项分组（升级前的旧敏感文件原因码）。
	originProtectionGroup
	// originProtectionItem：由注册表里的某个防护项决定。
	originProtectionItem
	// originUnknownProtection：网关说是防护项（protection_item），但对应不到注册表里的项。
	originUnknownProtection
	// originNeutral：不认识的非空处置原因（旧版本写入的底线类原因等），只给中性口径，
	// 不归到任何行为卡片（2.9.15 修过的误归因）。
	originNeutral
)

type agentBlockOrigin struct {
	kind       originKind
	item       protection.Item
	group      protection.Group
	cause      string
	riskReason string
}

const (
	neutralPolicyLabel     = "智能体行为策略"
	unknownProtectionLabel = "防护项"
	legacyTargetLabel      = "敏感目标"
	skillAdmissionLabel    = "Skill 准入"
)

// phaseProtectionKeys 是阶段项：网关在没有分析器原因码可对应时，按处置阶段（cause）决定的防护项，
// 优先于 risk_reason。
var phaseProtectionKeys = protection.PhaseCauseKeys()

// legacySensitiveTargetReason 是升级前记录里的原因码，注册表已拆成多张敏感目标卡片，
// 这里整体指向“敏感目标”分组。
const legacySensitiveTargetReason = "blocked_sensitive_local_file_path"

// groupPage 是防护项分组所在的控制台页面和依据文案前缀，页面路由以 web-console 的路由定义为准。
type groupPage struct {
	path        string
	basisPrefix string
}

const agentBehaviorBasisPrefix = "策略中心 → 智能体行为 → "

// protectionGroupPages 是分组 → 页面的唯一映射：链接与依据都从这里取。
var protectionGroupPages = map[protection.Group]groupPage{
	protection.GroupAgentTarget:     {"/security/agents", agentBehaviorBasisPrefix},
	protection.GroupAgentFallback:   {"/security/agents", agentBehaviorBasisPrefix},
	protection.GroupAgentRestricted: {"/security/agents", agentBehaviorBasisPrefix + "敏感资源访问 → "},
	protection.GroupSkill:           {"/security/skills", "Skill 安全准入 → "},
	protection.GroupMCP:             {"/mcp-gateway/policies", "MCP 调用策略 → "},
	// 端侧内置规则放在智能体行为页（控制台的端点页已迁出，是占位页）。
	protection.GroupEndpoint: {"/security/agents", agentBehaviorBasisPrefix + "端侧内置规则 → "},
}

// pageForGroup 返回分组所在页面；没有登记的分组返回 false，调用方按中性口径处理，不能借用别的页面。
func pageForGroup(group protection.Group) (groupPage, bool) {
	page, ok := protectionGroupPages[group]
	return page, ok
}

// ruleDrivenCause 是确认由规则（托管行为卡片或自定义规则）决定处置的原因：空表示没有记录原因。
func ruleDrivenCause(cause string) bool {
	switch cause {
	case "", "explicit_block", "explicit_confirm", "global_default", "confirm_channel_available":
		return true
	}
	return false
}

// explicitRuleCause 是处置由显式规则或默认动作决定的原因：即使 risk_reason 能对应防护项，也不覆盖规则归因。
func explicitRuleCause(cause string) bool {
	return cause == "explicit_block" || cause == "explicit_confirm" || cause == "global_default"
}

// isUnregisteredSkillAdmissionReason 判断是不是 Skill 准入类原因且不在防护项注册表里
// （skill_dangerous_command、skill_admission_unavailable 在注册表里，按防护项处理）。
func isUnregisteredSkillAdmissionReason(reason string) bool {
	if !skillAdmissionReasons[reason] {
		return false
	}
	_, registered := protection.ItemForReason(reason)
	return !registered
}

// classifyAgentToolBlock 归类一条阻断记录：cause 取 block.cause，旧记录取 finding.evidence_reason；
// 防护项优先看网关写下的 block.protection_item（2.9.22 起），再看阶段项（cause），最后看分析器
// 原因码（block.risk_reason：它可能是更强的非防护项原因，只看它会找不到防护项）。显式规则和
// 默认动作决定的处置仍归规则。只处理智能体工具层，其他层返回 originNone。
func classifyAgentToolBlock(record *SecurityBlockRecord, block, blocking map[string]any) agentBlockOrigin {
	str := func(source map[string]any, key string) string {
		value, _ := source[key].(string)
		return strings.TrimSpace(value)
	}
	if record.EventType == "skill_invocation_risk" {
		return agentBlockOrigin{kind: originSkillAdmission}
	}
	if record.Layer != "agent_tool" {
		return agentBlockOrigin{kind: originNone}
	}
	cause := str(block, "cause")
	if cause == "" {
		cause = str(blocking, "evidence_reason")
	}
	origin := agentBlockOrigin{cause: cause, riskReason: str(block, "risk_reason")}
	switch {
	case cause == "skill_admission_floor":
		origin.kind = originSkillAdmission
	case cause == protection.CauseAnalyzerHighRisk && isUnregisteredSkillAdmissionReason(origin.riskReason):
		origin.kind = originSkillAdmission
	case explicitRuleCause(cause):
		origin.kind = originRule
	case str(block, "protection_item") != "":
		item, found := protection.Lookup(str(block, "protection_item"))
		origin.kind, origin.item = originProtectionItem, item
		if _, mapped := pageForGroup(item.Group); !found || !mapped {
			origin.kind = originUnknownProtection // 网关写了键但注册表里查不到：不给链接
		}
	case origin.riskReason == legacySensitiveTargetReason:
		origin.kind, origin.group = originProtectionGroup, protection.GroupAgentTarget
	default:
		if key, ok := phaseProtectionKeys[cause]; ok {
			item, found := protection.Lookup(key)
			origin.kind, origin.item = originProtectionItem, item
			if _, mapped := pageForGroup(item.Group); !found || !mapped {
				origin.kind = originNeutral // 注册表里查不到或分组没有页面：不给链接，只说中性口径
			}
			return origin
		}
		if item, ok := protection.ItemForReason(origin.riskReason); ok {
			origin.kind, origin.item = originProtectionItem, item
			if _, mapped := pageForGroup(item.Group); !mapped {
				origin.kind = originNeutral
			}
			return origin
		}
		switch {
		case cause == "protection_item":
			origin.kind = originUnknownProtection
		case !ruleDrivenCause(cause):
			origin.kind = originNeutral
		default:
			origin.kind = originRule
		}
	}
	return origin
}

// label 是该归类在界面上的名称（规则名与链接标签共用）。
func (o agentBlockOrigin) label() string {
	switch o.kind {
	case originSkillAdmission:
		return skillAdmissionLabel
	case originProtectionGroup:
		return legacyTargetLabel
	case originProtectionItem:
		return o.item.Label
	case originUnknownProtection:
		return unknownProtectionLabel
	case originNeutral:
		return neutralPolicyLabel
	}
	return ""
}

// basis 是依据文案；action 是“阻断”或“人工确认”。
func (o agentBlockOrigin) basis(action string) string {
	switch o.kind {
	case originProtectionItem:
		page, _ := pageForGroup(o.item.Group)
		return page.basisPrefix + o.item.Label + " 动作为" + action
	case originProtectionGroup:
		page, _ := pageForGroup(o.group)
		return page.basisPrefix + legacyTargetLabel + " 动作为" + action
	case originUnknownProtection:
		return unknownProtectionLabel + "动作为" + action
	case originNeutral:
		return neutralPolicyLabel
	}
	return ""
}

// protectionQuery 生成指向防护项的完整查询串，extra 里是预填的规则、调用目标等。
func protectionQuery(key string, extra url.Values) string {
	query := url.Values{"protection": {key}}
	for name, values := range extra {
		query[name] = values
	}
	return query.Encode()
}

// link 是跳转链接；record 用来给高风险兜底预填“加例外”的规则和调用目标。
func (o agentBlockOrigin) link(record *SecurityBlockRecord) *PolicyLink {
	switch o.kind {
	case originSkillAdmission:
		return &PolicyLink{Kind: "skill", Path: "/security/skills", Label: skillAdmissionLabel}
	case originProtectionItem:
		page, _ := pageForGroup(o.item.Group)
		var extra url.Values
		if o.cause == protection.CauseAnalyzerHighRisk && o.riskReason != "" {
			extra = url.Values{"rule": {o.riskReason}}
			if target := blockedCallTarget(record.Detail); target != "" {
				extra.Set("target", target)
			}
		}
		return &PolicyLink{
			Kind: "protection_item", Label: o.item.Label, ItemKey: o.item.Key,
			Path: page.path + "?" + protectionQuery(o.item.Key, extra),
		}
	case originProtectionGroup:
		page, _ := pageForGroup(o.group)
		return &PolicyLink{
			Kind: "protection_group", Label: legacyTargetLabel, Group: string(o.group),
			Path: page.path + "?" + url.Values{"protection_group": {string(o.group)}}.Encode(),
		}
	case originUnknownProtection:
		return &PolicyLink{Kind: "none", Label: unknownProtectionLabel}
	case originNeutral:
		return &PolicyLink{Kind: "none", Label: neutralPolicyLabel}
	}
	return nil
}
