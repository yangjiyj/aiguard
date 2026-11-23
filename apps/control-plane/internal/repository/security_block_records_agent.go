package repository

import (
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// PolicyCenterAgentBehaviorLabels 是策略中心「智能体行为」各行为在策略页上的中文名，
// 键为托管规则 ID「policy-center-<key>」里的 key。handler 包的行为定义以此为准（有一致性测试）。
var PolicyCenterAgentBehaviorLabels = map[string]string{
	"destructive_operation": "删除与破坏",
	"system_command":        "系统命令",
	"sensitive_resource":    "敏感资源访问",
	"network_egress":        "网络外联",
	"database_change":       "数据库变更",
	"external_tool":         "外部工具（MCP）",
}

const policyCenterManagedRulePrefix = "policy-center-"

// agentToolRiskExplanations 把网关分析器的风险原因（Decision.Reason）翻成「这次调用为什么危险」。
// 只收录含义确定的原因；未收录的不展示，绝不编造。
var agentToolRiskExplanations = map[string]string{
	"high_confidence_secret_egress":        "调用参数里带有高置信度的密钥或凭据，执行后会被发送出去",
	"sensitive_personal_data_egress":       "调用参数里带有个人敏感信息，执行后会被发送出去",
	"blocked_cloud_metadata":               "访问云平台元数据地址，可能借此获取云主机的临时凭据",
	"blocked_cloud_metadata_hostname":      "访问云平台元数据地址，可能借此获取云主机的临时凭据",
	"blocked_loopback_or_private_ip":       "访问本机或内网地址，可能借此探测或访问内部服务",
	"blocked_cloud_credential_path":        "读取云平台凭据文件，可能泄露云账号访问密钥",
	"blocked_ssh_private_key_path":         "读取 SSH 私钥文件，可能泄露服务器登录凭据",
	"blocked_env_file":                     "读取 .env 文件，其中常存放数据库口令和接口密钥",
	"blocked_system_secret_file":           "读取系统口令文件或进程环境变量，可能泄露账号口令和运行时密钥",
	"blocked_secret_mount_path":            "读取容器里的密钥挂载目录，可能泄露集群或应用的凭据",
	"blocked_git_credentials_file":         "读取 git 保存的口令文件，可能泄露代码仓库的访问凭据",
	"sensitive_name_hint":                  "访问名字像密钥、口令、令牌的文件，里面很可能是敏感凭据",
	"blocked_sensitive_local_file_path":    "读取本机敏感文件（如环境变量、密码或令牌文件），可能泄露其中的凭据",
	"skill_dangerous_command":              "Skill 携带的命令包含高危操作",
	"skill_version_quarantined":            "调用的 Skill 版本已被隔离",
	"skill_version_revoked":                "调用的 Skill 版本已被吊销",
	"skill_admission_unavailable":          "Skill 准入状态暂时无法确认",
	"skill_identity_incomplete":            "无法确认调用的是哪个 Skill 版本",
	"blocked_destructive_sql":              "执行删除或破坏性 SQL 语句",
	"destructive_command_requires_confirm": "执行删除或破坏性命令",
	"blocked_git_credential_dump":          "读取 Git 保存的账号凭据，可能泄露代码仓库访问权限",
	"command_not_allowlisted":              "执行的命令不在允许清单内",
	"scoped_mutation_requires_confirm":     "执行带条件的数据修改语句，实际影响范围取决于条件",
	"shell_interpolation_requires_confirm": "命令里拼接了变量或子命令，实际执行内容无法预先确定",
	"shell_composition_observed":           "多条命令组合在一起执行，影响不止单条命令",
	"shell_interpreter_observed":           "通过解释器执行脚本，实际执行内容无法预先确定",
	"unknown_sql_requires_audit":           "执行无法识别类型的 SQL 语句",
	"tainted_irreversible_network_egress":  "调用参数取自网页、工具返回等外部内容，且会向外发送数据，发出后无法撤回",
}

// agentBehaviorLabel 把托管规则 ID 翻成策略页中文名；非托管规则返回空。
func agentBehaviorLabel(ruleID string) string {
	key := strings.TrimPrefix(strings.TrimSpace(ruleID), policyCenterManagedRulePrefix)
	if key == strings.TrimSpace(ruleID) {
		return ""
	}
	return PolicyCenterAgentBehaviorLabels[key]
}

func agentDecisionLabel(actionTaken string) string {
	if actionTaken == "confirm" {
		return "人工确认"
	}
	return "阻断"
}

// explainAgentToolBlock 按 classifyAgentToolBlock 的归类结果（来源于 block.cause，旧记录取 finding.evidence_reason，
// 以及 block.risk_reason）重写智能体工具调用阻断的规则名、原因与依据。旧网关写入的 block.basis 可能与真实原因不符，
// 读取时不能信它。
func explainAgentToolBlock(record *SecurityBlockRecord, block, blocking map[string]any) {
	if record.Layer != "agent_tool" || record.EventType == "skill_invocation_risk" {
		return
	}
	str := func(source map[string]any, key string) string {
		value, _ := source[key].(string)
		return strings.TrimSpace(value)
	}
	origin := classifyAgentToolBlock(record, block, blocking)
	behavior := PolicyCenterAgentBehaviorLabels[managedBehaviorKey(block, blocking, record.Layer)]
	if behavior == "" {
		behavior = agentBehaviorLabel(record.RuleID)
	}
	customRule := ""
	if behavior == "" && record.RuleID != "" && !strings.HasPrefix(record.RuleID, policyCenterManagedRulePrefix) {
		customRule = record.RuleName
		if customRule == "" || customRule == "策略中心托管规则" {
			customRule = record.RuleID
		}
	}
	action := agentDecisionLabel(record.ActionTaken)
	if explanation := agentToolRiskExplanations[str(block, "risk_reason")]; explanation != "" {
		record.Explanation = explanation
	}
	configured := func() string {
		switch {
		case behavior != "":
			record.RuleName = behavior
			return agentBehaviorBasisPrefix + behavior + " 动作为" + action
		case customRule != "":
			record.RuleName = customRule
			return "智能体行为高级规则「" + customRule + "」动作为" + action
		default:
			record.RuleName = neutralPolicyLabel
			return "智能体行为策略配置的动作为" + action
		}
	}

	switch origin.kind {
	case originSkillAdmission:
		record.RuleName = skillAdmissionLabel
		if origin.cause == "skill_admission_floor" {
			record.Reason = "调用的 Skill 未通过准入，需人工确认"
			record.Basis = "Skill 未通过准入时调用前须人工确认"
		} else {
			record.Reason = "调用的 Skill 未通过准入"
			record.Basis = skillAdmissionLabel
		}
	case originProtectionItem, originProtectionGroup:
		record.RuleName = origin.label()
		record.Basis = origin.basis(action)
		record.Reason = "智能体工具调用触及「" + origin.label() + "」防护项"
		if record.ActionTaken == "confirm" {
			record.Reason = "智能体工具调用触及「" + origin.label() + "」，需人工确认"
		}
		switch origin.item.Key {
		case protection.KeyHighRiskWithoutRule:
			record.Reason = "智能体工具调用被判定为高风险"
		case protection.KeyConfirmWithoutChannel:
			record.Reason = "需人工确认，但客户端不支持确认"
		}
	case originUnknownProtection:
		record.RuleName = origin.label()
		record.Reason = "智能体工具调用触及防护项"
		record.Basis = origin.basis(action)
	case originNeutral:
		// 不认识的处置原因（旧版本写入的底线类原因等）：不归到托管行为卡片，给中性口径。
		record.RuleName = origin.label()
		record.Reason = "智能体工具调用被智能体行为策略处置"
		record.Basis = origin.basis(action)
	default: // originRule
		switch origin.cause {
		case "explicit_block", "explicit_confirm":
			record.Reason = "智能体工具调用被行为策略阻断"
			record.Basis = configured()
		case "global_default":
			record.RuleName = "智能体行为默认动作"
			record.Basis = "智能体行为策略的默认动作为" + action
		case "confirm_channel_available":
			if behavior != "" {
				record.RuleName = behavior
			} else {
				record.RuleName = "人工确认"
			}
			record.Reason = "智能体工具调用需人工确认"
			record.Basis = "需人工确认后执行（未记录触发确认的规则）"
		default:
			if behavior != "" {
				record.RuleName = behavior
			} else if record.RuleName == "策略中心托管规则" {
				record.RuleName = neutralPolicyLabel
			}
			if internalCodePatternInText(record.Basis) {
				record.Basis = "智能体行为策略" + action
			}
		}
	}
	if record.ActionTaken == "confirm" && !strings.Contains(record.Reason, "确认") {
		record.Reason = "智能体工具调用需人工确认"
	}
	if behavior != "" || origin.kind != originRule {
		// 托管规则 ID 是内部编号，策略页上没有；中文名已经足够定位。
		record.RuleID = ""
	}
}

// internalCodePatternInText 识别依据里残留的 snake_case / kebab-case 内部代号。
func internalCodePatternInText(text string) bool {
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r >= utf8.RuneSelf || r == ' ' || r == '：' || r == '「' || r == '」' }) {
		if strings.ContainsAny(field, "_-") && strings.IndexFunc(field, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 {
			return true
		}
	}
	return false
}

// explainSkillInvocationBlock 补全 skill_invocation_risk 事件（控制面写入，无 block 归因）。
func explainSkillInvocationBlock(record *SecurityBlockRecord, summary map[string]any) {
	if record.EventType != "skill_invocation_risk" {
		return
	}
	skill, _ := summary["skill_name"].(string)
	skill = strings.TrimSpace(skill)
	version, _ := summary["skill_version"].(string)
	record.Layer = "agent_tool"
	record.RuleName = "Skill 调用管控"
	record.Detail = joinBlockParts("Skill", skill, strings.TrimSpace(version))
	name := "Skill "
	if skill != "" {
		name = "Skill「" + skill + "」"
	}
	if record.ActionTaken == "confirm" {
		record.Reason = "调用 " + name + "需人工确认"
		record.Basis = "Skill 调用风险判定为需人工确认（未记录判定原因）"
		return
	}
	record.Reason = "调用 " + name + "被拦截"
	record.Basis = "Skill 调用风险判定为阻断（未记录判定原因）"
}

func joinBlockParts(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " · ")
}

// legacyBlockDetailCutRunes 是没有截断标记的旧网关截断 block.detail 的长度：2.9.15 及更早截到 120 字，
// 2.9.16、2.9.17 截到落库上限 2000 字，末尾都补一个 …。
var legacyBlockDetailCutRunes = map[int]bool{120: true, 2000: true}

// fullerBlockDetail：网关只在命中内容超过落库上限（2000 字）时截断，末尾补 … 并写 block.detail_truncated。
// 有标记时，同一事件 finding 里留存的完整脱敏证据前缀一致就用它，最危险的末段不会丢。没有标记的旧记录
// 只认恰好截到上述长度再补 … 的形态；命令本身以 … 或 ... 结尾不是截断，原样保留。
func fullerBlockDetail(detail string, truncated bool, candidates ...string) string {
	prefix, cut := strings.CutSuffix(strings.TrimSpace(detail), "…")
	if !cut || (!truncated && !legacyBlockDetailCutRunes[utf8.RuneCountInString(prefix)]) {
		return detail
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if len(candidate) > len(prefix) && strings.HasPrefix(candidate, prefix) {
			return candidate
		}
	}
	return detail
}
