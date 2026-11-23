package agentguard

import (
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

const effectiveReasonProtectionItem = "protection_item"

const (
	protectionKeyHighRiskWithoutRule   = protection.KeyHighRiskWithoutRule
	protectionKeyConfirmWithoutChannel = protection.KeyConfirmWithoutChannel
)

// ProtectionHit 是一次敏感目标命中。分析器只记录命中，不定动作；
// 动作由 resolveProtectionHits 按租户配置统一给出。RiskLevel/Confidence 是命中
// 本身的风险与置信度，这条命中成为结论原因时随之写回决策。
type ProtectionHit struct {
	Reason     string  `json:"reason"`
	Target     string  `json:"target,omitempty"`
	RiskLevel  string  `json:"risk_level,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	// Action 是这条命中按租户配置（并套用指向该项的例外）定出的动作，ExceptionID 是
	// 套用的例外；都由 resolveProtectionHits 写入，分析器产出命中时为空。
	Action      string `json:"action,omitempty"`
	ExceptionID string `json:"exception_id,omitempty"`
	// MatchTarget 是只用于例外匹配的原始目标（Target 已脱敏时，例如受限文件），
	// 不序列化、不进证据和日志。
	MatchTarget string `json:"-"`
	// Subtype 是命中的细分（突发的调用类别 file_read 等），旧原因码例外按它区分。
	Subtype string `json:"subtype,omitempty"`
}

// sameHit 按原因码、目标与匹配用原始目标判断是否同一命中：两个不同文件的脱敏目标
// 可能相同（/x/plan.docx、/x/pxyz.docx 都是 /x/p****.docx），不能合成一条。
func (h ProtectionHit) sameHit(other ProtectionHit) bool {
	return h.Reason == other.Reason && h.Target == other.Target && h.MatchTarget == other.MatchTarget
}

func protectionFinding(reason, target, riskLevel string, evidence []Evidence) Decision {
	return protectionFindingWithConfidence(reason, target, riskLevel, 0.95, evidence)
}

func protectionFindingWithConfidence(reason, target, riskLevel string, confidence float64, evidence []Evidence) Decision {
	return protectionFindingFor(ProtectionHit{Reason: reason, Target: target, RiskLevel: riskLevel, Confidence: confidence}, evidence)
}

// targetFinding 由 AnalyzeTarget 的命中构造结论：目标是文件时另存一份未经 URL 解码的
// 原始路径供例外比对（判定本身仍按 AnalyzeTarget 的解码结果）。
func targetFinding(target TargetAnalysis, raw, riskLevel string, confidence float64, evidence []Evidence) Decision {
	hit := ProtectionHit{Reason: target.Reason, Target: target.NormalizedTarget, RiskLevel: riskLevel, Confidence: confidence}
	if target.Kind == TargetFile {
		hit.MatchTarget = filerestrict.ExceptionTarget(raw)
	}
	return protectionFindingFor(hit, evidence)
}

// protectionFindingFor 由一条命中构造分析器结论：RawDecision=audit，原因、目标、风险、
// 置信度取自命中。
func protectionFindingFor(hit ProtectionHit, evidence []Evidence) Decision {
	return Decision{
		RawDecision: DecisionAudit, Reason: hit.Reason, RiskLevel: hit.RiskLevel, Confidence: hit.Confidence,
		Evidence: evidence, NormalizedTarget: hit.Target,
		ProtectionHits: []ProtectionHit{hit},
	}
}

// mergeProtectionHits 合并两侧命中，按原因码、目标与匹配用原始路径（MatchTarget）去重。
func mergeProtectionHits(a, b []ProtectionHit) []ProtectionHit {
	if len(b) == 0 {
		return a
	}
	out := append([]ProtectionHit{}, a...)
	for _, hit := range b {
		dup := false
		for _, existing := range out {
			if existing.sameHit(hit) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, hit)
		}
	}
	return out
}

// adoptProtectionHit 让这条命中成为决策的原因：原因码、命中的置信度，风险取两者较高者。
func adoptProtectionHit(raw *Decision, hit ProtectionHit) {
	raw.Reason = hit.Reason
	if hit.Confidence > 0 {
		raw.Confidence = hit.Confidence
	}
	if destructiveRiskRank(hit.RiskLevel) > destructiveRiskRank(raw.RiskLevel) {
		raw.RiskLevel = hit.RiskLevel
	}
}

func protectionActionToDecision(a protection.Action) DecisionAction {
	switch a {
	case protection.ActionBlock:
		return DecisionBlock
	case protection.ActionConfirm:
		return DecisionConfirm
	default:
		return DecisionAudit
	}
}

// protectionEnforcement 是已定动作的防护项结论里需要执行的部分（确认或阻断）；
// 其他结论返回 allow，不构成下限。
func protectionEnforcement(decision Decision) DecisionAction {
	switch protection.Action(decision.ProtectionAction) {
	case protection.ActionBlock:
		return DecisionBlock
	case protection.ActionConfirm:
		return DecisionConfirm
	default:
		return DecisionAllow
	}
}

// protectionExceptionAction 是指向防护项或阶段项的例外的生效动作：例外的 allow 与 audit
// 一律记为“仅记录”（放行、记日志、不告警），不会出现“有项无动作”。
const protectionExceptionAction = protection.ActionRecord

func protectionSettingsOf(policy *EffectivePolicy) protection.Settings {
	if policy == nil {
		return nil
	}
	return policy.Protections
}

func itemAction(policy *EffectivePolicy, item protection.Item) protection.Action {
	if item.Key == protection.KeyRestrictedFile {
		if policy != nil && policy.RestrictedFiles != nil {
			switch strings.TrimSpace(policy.RestrictedFiles.Action) {
			case "record":
				return protection.ActionRecord
			case "alert_allow":
				return protection.ActionAlertAllow
			}
		}
		return protection.ActionBlock
	}
	return protectionSettingsOf(policy).ActionFor(item.Key)
}

// isProtectionExceptionRule 判断例外是否指向某个带原因码的防护项（原因码或项键）。
// 这类例外只在 resolveProtectionHits 里对该项生效，不参与通用例外匹配。阶段项
// （agent.high_risk_without_rule 等，没有原因码）走通用例外匹配，见 exceptionRuleMatches。
func isProtectionExceptionRule(ruleID string) bool {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return false
	}
	if _, ok := protection.ItemForReason(ruleID); ok {
		return true
	}
	if _, ok := legacyProtectionReasonAliases[ruleID]; ok {
		return true
	}
	item, ok := protection.Lookup(ruleID)
	return ok && len(item.Reasons) > 0
}

// legacyProtectionReasonAliases 把升级前的旧原因码映射到现在登记的原因码：升级前写下、
// 当时被底线忽略的例外，升级后照字面生效（用户决定 D4）。旧的“敏感本地文件”在 2.9.22
// 拆成了五个防护项，旧原因码的例外对五个都生效。
var legacyProtectionReasonAliases = map[string][]string{
	"blocked_sensitive_local_file_path": {
		targetReasonEnvFile, targetReasonSystemSecretFile, targetReasonSecretMount,
		targetReasonGitCredentialsFile, targetReasonSensitiveName,
	},
	// 2.9.21 的突发原因码按调用类别区分，统一成 behavior_burst 后旧码只放开对应类别（legacyAliasCoversHit）。
	"behavior_file_read_burst":       {behaviorBurstReason},
	"behavior_file_delete_burst":     {behaviorBurstReason},
	"behavior_network_egress_burst":  {behaviorBurstReason},
	"behavior_command_execute_burst": {behaviorBurstReason},
}

// exceptionNamesHit 判断例外的 rule_id 是否点名了这条命中：原因码、项键或旧原因码别名
// （旧突发原因码只放开同一调用类别的突发，见 legacyAliasCoversHit）。
func exceptionNamesHit(ruleID string, item protection.Item, hit ProtectionHit) bool {
	if ruleID == hit.Reason || ruleID == item.Key {
		return true
	}
	for _, alias := range legacyProtectionReasonAliases[ruleID] {
		if alias == hit.Reason && legacyAliasCoversHit(ruleID, hit) {
			return true
		}
	}
	return false
}

// exceptionNamesAny 判断 rule_id 是否点名了 names 之一，或是其中某个原因码的旧原因码别名
// （没有命中细节时用）。
func exceptionNamesAny(ruleID string, names ...string) bool {
	for _, name := range names {
		if name != "" && ruleID == name {
			return true
		}
	}
	for _, alias := range legacyProtectionReasonAliases[ruleID] {
		for _, name := range names {
			if alias == name {
				return true
			}
		}
	}
	return false
}

// resolveProtectionHits 按租户配置给全部防护项命中定动作，套用只针对该项的例外，
// 把每条命中的生效动作与例外写回命中，取最严者并入 raw。这是网关里唯一给敏感目标
// 定动作的地方。
func resolveProtectionHits(raw Decision, policy *EffectivePolicy) Decision {
	return resolveProtectionHitsIn(raw, policy, "")
}

// resolveProtectionHitsIn 同 resolveProtectionHits；scope 是 MCP 调用的 mcp:<服务>/<工具>，
// 指向某项、目标写成 mcp:<服务>[/<工具>] 的例外按它匹配。
func resolveProtectionHitsIn(raw Decision, policy *EffectivePolicy, scope string) Decision {
	if len(raw.ProtectionHits) == 0 {
		return raw
	}
	var exceptions []PolicyException
	if policy != nil {
		exceptions = policy.Exceptions
	}
	now := time.Now()
	hits := append([]ProtectionHit(nil), raw.ProtectionHits...)
	for i := range hits {
		hits[i].Action, hits[i].ExceptionID = "", ""
		item, ok := protection.ItemForReason(hits[i].Reason)
		if !ok {
			continue
		}
		action := itemAction(policy, item)
		if exc := matchingHitExceptionIn(exceptions, item, hits[i], now, scope); exc != nil {
			action = protectionExceptionAction
			hits[i].ExceptionID = exc.ID
		}
		hits[i].Action = string(action)
	}
	raw.ProtectionHits = hits
	winner, found := strictestProtectionHit(hits)
	if !found {
		return raw
	}
	raw.ProtectionItem, raw.ProtectionAction = protectionItemKey(winner.Reason), winner.Action
	decided := protectionActionToDecision(protection.Action(winner.Action))
	switch protection.Action(winner.Action) {
	case protection.ActionBlock, protection.ActionConfirm:
		if decisionRank(decided) >= decisionRank(raw.RawDecision) {
			raw.RawDecision = decided
			adoptProtectionHit(&raw, winner)
			if winner.Target != "" {
				raw.NormalizedTarget = winner.Target
			}
			raw.ConfiguredEnforcement = true
		}
		// 分析器自己的更严结论（未配置）不因防护项而变成“配置结论”：它仍按
		// agent.high_risk_without_rule 处理，防护项结论由 ApplyPolicy 作为下限保留。
	case protection.ActionAlertAllow:
		if decisionRank(raw.RawDecision) <= decisionRank(DecisionAudit) {
			raw.RawDecision = DecisionAudit
			adoptProtectionHit(&raw, winner)
		}
	}
	return raw
}

// strictestProtectionHit 返回已定动作的命中里动作最严的一条（同样严时取先出现的）。
func strictestProtectionHit(hits []ProtectionHit) (ProtectionHit, bool) {
	var winner ProtectionHit
	found := false
	for _, hit := range hits {
		if hit.Action == "" {
			continue
		}
		if !found || protection.Rank(protection.Action(hit.Action)) > protection.Rank(protection.Action(winner.Action)) {
			winner, found = hit, true
		}
	}
	return winner, found
}

func protectionItemKey(reason string) string {
	item, _ := protection.ItemForReason(reason)
	return item.Key
}

func matchingHitExceptionIn(exceptions []PolicyException, item protection.Item, hit ProtectionHit, now time.Time, scope string) *PolicyException {
	return firstMatchingException(exceptions, now,
		func(ruleID string) bool { return exceptionNamesHit(ruleID, item, hit) },
		func(pattern string) bool {
			return hitExceptionTargetMatches(pattern, hit) || exceptionScopeMatches(pattern, scope)
		})
}

// MatchingMCPException 是网关在 MCP 链路上自行判定（tools/list 剔除、红线）时找例外的唯一入口，与调用
// 路径（resolveProtectionHits）同一口径：未过期；rule_id 点名 names 之一（项键、原因码、红线名等）或是
// 其中某个原因码的旧原因码别名；目标为空、mcp:<服务>[/<工具>] 按段覆盖 target，或是 target 的子串。
// target 写成 mcp:<服务>/<工具>。
func MatchingMCPException(exceptions []PolicyException, names []string, target string, now time.Time) *PolicyException {
	hit := ProtectionHit{Target: target}
	return firstMatchingException(exceptions, now,
		func(ruleID string) bool { return exceptionNamesAny(ruleID, names...) },
		func(pattern string) bool {
			return hitExceptionTargetMatches(pattern, hit) || exceptionScopeMatches(pattern, target)
		})
}

// firstMatchingException 是找例外的公共循环：未过期、rule_id 被 named 认可、目标被 covers 认可。
func firstMatchingException(exceptions []PolicyException, now time.Time, named, covers func(string) bool) *PolicyException {
	for i := range exceptions {
		exc := &exceptions[i]
		if exc.ExpiresAt.IsZero() || !exc.ExpiresAt.After(now) {
			continue
		}
		if !named(strings.TrimSpace(exc.RuleID)) || !covers(exc.TargetPattern) {
			continue
		}
		return exc
	}
	return nil
}

// fileTargetReasons 是命中目标为文件路径的防护项原因码：例外按路径层级匹配（filerestrict）。其余
// （元数据、内网、密钥外发的 URL，Skill 名）保持子串口径。
var fileTargetReasons = map[string]bool{
	targetReasonSSHPrivateKey:      true,
	targetReasonCloudCredential:    true,
	targetReasonEnvFile:            true,
	targetReasonSystemSecretFile:   true,
	targetReasonSecretMount:        true,
	targetReasonGitCredentialsFile: true,
	targetReasonSensitiveName:      true,
	restrictedFileReason:           true,
	// 端侧内置规则里按文件路径命中的三条（handler 按命中路径写 MatchTarget）。
	protection.EndpointRuleEnvFiles:          true,
	protection.EndpointRuleSSHPrivateKeys:    true,
	protection.EndpointRuleSSHAuthorizedKeys: true,
}

// hitExceptionTargetMatches 判断指向防护项的例外目标是否覆盖这条命中。受限文件只认
// 规范化后的原始路径（MatchTarget），落不到单个文件时只有不限目标的例外能放开。
func hitExceptionTargetMatches(pattern string, hit ProtectionHit) bool {
	if !fileTargetReasons[hit.Reason] {
		target := hit.MatchTarget
		if target == "" {
			target = hit.Target
		}
		return exceptionTargetMatches(pattern, target, hit.Target)
	}
	// 文件类命中只认未经 URL 解码的原始路径（filerestrict.ExceptionTarget）；落不到确定文件时为空，
	// 只有不限目标的例外能放开。比对口径与独立代理的受限文件同一份实现。
	return filerestrict.ExceptionTargetMatches(pattern, hit.MatchTarget)
}

// withProtectionFields 只把 resolved 里的防护项字段带到 base 上，不改 base 的动作与原因。
func withProtectionFields(base, resolved Decision) Decision {
	base.ProtectionHits = resolved.ProtectionHits
	base.ProtectionItem = resolved.ProtectionItem
	base.ProtectionAction = resolved.ProtectionAction
	return base
}

// MergeProtectionFields 合并两份结论的防护项字段：命中取并集（同一命中只留一条），
// 防护项与动作取自动作最严的那条命中，告警由动作推出，三者同源。
func MergeProtectionFields(dst *Decision, a, b Decision) {
	hits := append([]ProtectionHit(nil), mergeProtectionHits(a.ProtectionHits, b.ProtectionHits)...)
	if len(hits) == 0 {
		hits = nil
	}
	dst.ProtectionHits = hits
	if winner, ok := strictestProtectionHit(hits); ok {
		dst.ProtectionItem, dst.ProtectionAction = protectionItemKey(winner.Reason), winner.Action
		return
	}
	source := a
	if protection.Rank(protection.Action(b.ProtectionAction)) > protection.Rank(protection.Action(a.ProtectionAction)) {
		source = b
	}
	dst.ProtectionItem, dst.ProtectionAction = source.ProtectionItem, source.ProtectionAction
}

// ProtectionAlert 表示防护项结论为“告警放行”。
func (d Decision) ProtectionAlert() bool {
	return protection.Action(d.ProtectionAction) == protection.ActionAlertAllow
}

// ProtectionExceptionIDs 是本次套用到防护项命中上的例外（去重，按命中顺序）。
func (d Decision) ProtectionExceptionIDs() []string {
	var ids []string
	for _, hit := range d.ProtectionHits {
		if hit.ExceptionID == "" {
			continue
		}
		known := false
		for _, id := range ids {
			if id == hit.ExceptionID {
				known = true
				break
			}
		}
		if !known {
			ids = append(ids, hit.ExceptionID)
		}
	}
	return ids
}

// ProtectionItemLabel 返回决定这次确认/阻断的防护项在策略中心的显示名；防护项结论
// 不是确认或阻断（只告警、只记录，动作由别的结论决定）时返回空串。
func ProtectionItemLabel(decision Decision) string {
	if protectionEnforcement(decision) == DecisionAllow {
		return ""
	}
	if item, ok := protection.Lookup(decision.ProtectionItem); ok {
		return item.Label
	}
	return ""
}

// ProtectionHitAction 返回本次调用里某个原因码命中的生效动作（同原因多条命中取最严）；
// 动作在 resolveProtectionHits 里已按租户配置和例外定好，这里只查找。没有这个命中时
// ok=false。
func ProtectionHitAction(decision Decision, reason string) (protection.Action, bool) {
	var strictest protection.Action
	found := false
	for _, hit := range decision.ProtectionHits {
		if hit.Reason != reason || hit.Action == "" {
			continue
		}
		action := protection.Action(hit.Action)
		if !found || protection.Rank(action) > protection.Rank(strictest) {
			strictest, found = action, true
		}
	}
	return strictest, found
}
