package agentguard

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentguardmatch"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

const effectiveReasonExceptionDowngrade = "exception_downgrade"

type EffectivePolicy struct {
	ID                    string                `json:"id"`
	Name                  string                `json:"name"`
	PolicyVersion         string                `json:"policy_version"`
	Mode                  Mode                  `json:"mode"`
	DefaultAction         DecisionAction        `json:"default_action"`
	FailPolicy            string                `json:"fail_policy"`
	ConfirmChannelEnabled bool                  `json:"confirm_channel_enabled"`
	Rules                 []PolicyRule          `json:"rules"`
	Exceptions            []PolicyException     `json:"exceptions"`
	Behavior              *BehaviorThresholds   `json:"behavior,omitempty"`
	Destructive           *DestructivePolicy    `json:"destructive,omitempty"`
	RestrictedFiles       *RestrictedFilePolicy `json:"restricted_files,omitempty"`
	ConfigSource          ConfigSource          `json:"config_source,omitempty"`
	// Protections 是租户保存的防护项配置（键 → 动作与参数）；缺键取注册表默认值。
	// 旧的 dlp.high_confidence_secret_egress 已由控制面下发时折算进
	// agent.secret_egress，网关不再读 dlp。
	Protections protection.Settings `json:"protections,omitempty"`
	// RuleMode, when set, replaces Mode for explicit AgentGuard rules. The console
	// exposes no AgentGuard policy mode: a rule saved as "block" is meant to block
	// whenever the global posture is protect, while Mode carries the destructive
	// policy's mode for the destructive-operation path.
	RuleMode Mode `json:"-"`
}

// RestrictedFilePolicy 是租户级受限文件模式：命中这些模式的文件禁止交给模型。
// 与 shared-go/filerestrict.Policy 同构，但定义在 agentguard 以避免策略层对共享包的
// 反向依赖；转换时由 handler 层编译为 filerestrict.Matcher。
type RestrictedFilePolicy struct {
	Patterns []string `json:"patterns"`
	Action   string   `json:"action"` // record | alert_allow | block
	// Scopes 是受限文件生效的环节（RestrictedFileScope*）。ScopesConfigured=false 表示控制面
	// 没有下发作用范围（升级前的控制面），三个环节都生效，与 2.9.21 一致。
	Scopes           []string `json:"scopes,omitempty"`
	ScopesConfigured bool     `json:"scopes_configured,omitempty"`
}

// 受限文件作用范围：工具调用、用户消息提及的文件、正向代理的模型输出。
const (
	RestrictedFileScopeToolCall    = "tool_call"
	RestrictedFileScopeUserMention = "user_mention"
	RestrictedFileScopeProxyOutput = "proxy_output"
)

// Applies 判断受限文件在某个环节是否生效。
func (p *RestrictedFilePolicy) Applies(scope string) bool {
	if p == nil {
		return false
	}
	if !p.ScopesConfigured {
		return true
	}
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type PolicyRule struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	ToolPattern        string         `json:"tool_pattern"`
	Action             DecisionAction `json:"action"`
	Enabled            bool           `json:"enabled"`
	PolicyCenterAction string         `json:"policy_center_action,omitempty"`
}

// UnmarshalJSON keeps legacy rules compatible while preserving an explicit
// enabled=false. Older snapshots omitted enabled and historically meant enabled.
func (r *PolicyRule) UnmarshalJSON(data []byte) error {
	var payload struct {
		ID                 string         `json:"id"`
		Name               string         `json:"name"`
		ToolPattern        string         `json:"tool_pattern"`
		Action             DecisionAction `json:"action"`
		Enabled            *bool          `json:"enabled"`
		PolicyCenterAction string         `json:"policy_center_action"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}
	*r = PolicyRule{
		ID: payload.ID, Name: payload.Name, ToolPattern: payload.ToolPattern,
		Action: payload.Action, Enabled: enabled,
		PolicyCenterAction: payload.PolicyCenterAction,
	}
	return nil
}

type PolicyException struct {
	ID            string         `json:"id"`
	RuleID        string         `json:"rule_id"`
	TargetPattern string         `json:"target_pattern"`
	Decision      DecisionAction `json:"decision"`
	ExpiresAt     time.Time      `json:"expires_at"`
}

type PolicyEvaluationInput struct {
	ToolName string
	ToolType string
	Target   string
	Policy   *EffectivePolicy
	// CallerMode 是调用方（网关）下发的执行模式，作为执行“上限”。SECURITY_AUDIT_ONLY=true
	// 时网关传入 ModeAudit，此模式必须钳制租户策略自带的 Mode——即便策略 strict，也不得
	// 真阻断。空值表示不钳制，退回策略自身 Mode（老行为）。
	CallerMode     Mode
	RiskCategory   string
	HighConfidence bool
	// 以下只用于破坏性分支（RiskCategory=destructive_change）。
	// DestructiveConfirmChannel：这次调用有没有确认通道（MCP 确认扩展或普通确认票据）；
	// 删除与破坏结论为确认而没有通道时按 agent.confirm_without_channel 处置。
	DestructiveConfirmChannel bool
	// General 是同一调用在通用判定路径上的生效结论（显式规则、防护项、Skill 隔离/撤销、
	// 配置的行为结论都已算进去）。破坏性结论与其中管理员配置的确认/阻断取严。
	General *Decision
	// ConfirmChannelOverride 是这次调用实际有没有确认通道（MCP 看客户端是否支持确认扩展）；非空时
	// 代替策略的 confirm_channel_enabled，同一次调用的各条判定分支口径一致。
	ConfirmChannelOverride *bool
	// ExceptionScope 是调用所属的 MCP 服务与工具（mcp:<服务>/<工具>）。例外的 target_pattern
	// 写成 mcp:<服务> 或 mcp:<服务>/<工具> 时按它匹配；例外仍只放开 rule_id 指向的那一项。
	ExceptionScope string
}

func ApplyEffectivePolicy(raw Decision, input PolicyEvaluationInput) Decision {
	if input.RiskCategory == DestructiveRiskCategory {
		return applyDestructiveBranch(raw, input)
	}
	if input.Policy == nil {
		// 没有租户策略：同一流程，防护项与阶段项取注册表默认值，调用方模式即执行模式。
		base := PolicyContext{Mode: input.CallerMode}
		if input.ConfirmChannelOverride != nil {
			base.ConfirmChannelEnabled = *input.ConfirmChannelOverride
		}
		return evaluatePolicy(raw, nil, input, base)
	}
	return evaluatePolicy(raw, input.Policy, input, PolicyContext{})
}

// evaluatePolicy 是有无租户策略共用的判定流程：防护项定动作 → 显式规则 → ApplyPolicy
// → 例外 → 托管卡片告警 → 防护项告警通知。policy 为 nil 时没有规则、例外，阶段项取
// 注册表默认值，base 给出模式等上下文。
func evaluatePolicy(raw Decision, policy *EffectivePolicy, input PolicyEvaluationInput, base PolicyContext) Decision {
	resolved := resolveProtectionHitsIn(raw, policy, input.ExceptionScope)
	ruleCtx := base
	var matchPolicy *EffectivePolicy
	if policy != nil {
		// 取“更宽松者”作为生效模式：audit_only（ModeAudit/ModeObserve）是绝对底线，
		// 永远压过策略里可能配置的 ModeStrict。
		ruleMode := policy.Mode
		if policy.RuleMode != "" {
			ruleMode = policy.RuleMode
		}
		matchPolicy = policy
		if raw.ConfiguredEnforcement || behaviorVerdictConfigured(resolved) {
			// 2.9.21 语义：分析器带来的配置结论（行为突发、序列规则、Skill 隔离/撤销、
			// MCP 准入等）不参与托管卡片匹配，非托管的显式规则照旧优先。其余防护项结论
			// 不走这里，它与卡片取严（ApplyPolicy 的 strictFloor）。
			matchPolicy = withoutManagedBehaviorRules(policy)
		}
		ruleCtx.Mode = clampModeToCeiling(ruleMode, input.CallerMode)
		ruleCtx.ConfirmChannelEnabled = policy.ConfirmChannelEnabled
		if input.ConfirmChannelOverride != nil {
			ruleCtx.ConfirmChannelEnabled = *input.ConfirmChannelOverride
		}
		ruleCtx.ExplicitAllow, ruleCtx.ExplicitAudit, ruleCtx.ExplicitConfirm, ruleCtx.ExplicitBlock, ruleCtx.MatchedRuleID =
			matchExplicitPolicyAction(matchPolicy, input.ToolName, input.ToolType)
		ruleCtx.GlobalDefault = policy.DefaultAction
		ruleCtx.PolicyVersion = policy.PolicyVersion
		ruleCtx.MatchedPolicyID = policy.ID
		ruleCtx.MatchedPolicyName = policy.Name
		ruleCtx.HighRiskAction = configuredStageAction(policy.Protections, protectionKeyHighRiskWithoutRule)
		ruleCtx.ConfirmFallback = configuredStageAction(policy.Protections, protectionKeyConfirmWithoutChannel)
	}
	decision := ApplyPolicy(resolved, ruleCtx)
	if policy != nil {
		decision.Evidence = withMatchedPolicyRuleEvidence(decision.Evidence, ruleCtx.MatchedRuleID)
		// Controlled exceptions relax explicit rules and ordinary analyzer verdicts.
		// An exception only releases what it points at: protection items it does not
		// name keep their configured conclusion (exceptions naming a protection item
		// were already applied to that item by resolveProtectionHits).
		if exception := matchingPolicyExceptionIn(policy.Exceptions, decision, input.Target, input.ExceptionScope); exception != nil {
			decision = reapplyWithException(resolved, ruleCtx, exception)
			decision.Evidence = withMatchedPolicyRuleEvidence(decision.Evidence, ruleCtx.MatchedRuleID)
		}
		for _, rule := range matchPolicy.Rules {
			if rule.ID == ruleCtx.MatchedRuleID && managedBehaviorAction(rule) == "alert_allow" &&
				!callerModeIsRecordOnly(input.CallerMode) &&
				decision.EffectiveDecision == DecisionAudit && raw.RawDecision != DecisionAllow &&
				(raw.RiskLevel == "high" || raw.RiskLevel == "critical") {
				decision.NotificationRequired = true
			}
		}
	}
	markProtectionAlert(&decision, input.CallerMode)
	return decision
}

// reapplyWithException 按一条例外重算。指向阶段项的例外只把该阶段项换成仅记录，其余
// 结论（显式规则、防护项）不变；通用例外清掉显式规则、把原结论换成例外动作重算，但
// 放不开它没点名的防护项结论和 Skill 隔离/撤销。
func reapplyWithException(resolved Decision, ruleCtx PolicyContext, exception *PolicyException) Decision {
	ctx := ruleCtx
	if stage, ok := stageItemFor(exception.RuleID); ok {
		stage.relax(&ctx)
		decision := ApplyPolicy(resolved, ctx)
		if decisionRank(decision.EffectiveDecision) <= decisionRank(DecisionAudit) {
			decision.EffectiveReason = effectiveReasonExceptionDowngrade
		}
		return decision
	}
	ctx.ExplicitAllow, ctx.ExplicitAudit, ctx.ExplicitConfirm, ctx.ExplicitBlock = false, false, false, false
	ctx.ReleasedRuleID = exception.RuleID
	relaxed := resolved
	relaxed.RawDecision = defaultExceptionDecision(exception.Decision)
	// 只保留下限要认的管理员 Skill 隔离/撤销标记；其余配置标记随原结论一起放开。下限只在
	// ApplyPolicy 里取一次（strictFloor），这里不另算。
	relaxed.ConfiguredEnforcement = resolved.ConfiguredEnforcement && skillAdministratorReason(resolved.Reason)
	decision := ApplyPolicy(relaxed, ctx)
	if decision.PolicyReason != effectiveReasonProtectionItem && decision.PolicyReason != effectiveReasonSkillAdministrator {
		// 没有被下限托住：例外生效。
		decision.Reason = effectiveReasonExceptionDowngrade
		decision.EffectiveReason = effectiveReasonExceptionDowngrade
		decision.ConfiguredEnforcement = false
	}
	return decision
}

func skillAdministratorReason(reason string) bool {
	return reason == reasonSkillVersionQuarantined || reason == reasonSkillVersionRevoked
}

// withoutManagedBehaviorRules 返回剔除托管卡片（策略中心“仅记录/告警放行”）后的策略副本。
func withoutManagedBehaviorRules(policy *EffectivePolicy) *EffectivePolicy {
	copied := *policy
	copied.Rules = make([]PolicyRule, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		if managedBehaviorAction(rule) != "" {
			continue
		}
		copied.Rules = append(copied.Rules, rule)
	}
	return &copied
}

func managedBehaviorAction(rule PolicyRule) string {
	if rule.Action == DecisionAudit && (rule.PolicyCenterAction == "record" || rule.PolicyCenterAction == "alert_allow") {
		return rule.PolicyCenterAction
	}
	return ""
}

// modeEnforcementRank 按“执行强度”给模式排序：observe < audit < strict。
// 数值越小越宽松（越不阻断）。用于把 audit_only（弱）作为对 strict（强）的上限钳制。
func modeEnforcementRank(mode Mode) int {
	switch normalizeMode(mode) {
	case ModeObserve:
		return 0
	case ModeAudit:
		return 1
	case ModeLight: // W5 5.11
		return 2
	case ModeStrict:
		return 3
	default:
		return 1
	}
}

// clampModeToCeiling 返回 policyMode 与 ceiling 中“更宽松”（执行强度更低）者。
// ceiling 为空（零值不是三种合法模式之一）时不钳制，直接用 policyMode。
// SECURITY_AUDIT_ONLY=true → ceiling=ModeAudit → strict 策略被钳到 audit，绝不真阻断。
func clampModeToCeiling(policyMode, ceiling Mode) Mode {
	switch ceiling {
	case ModeObserve, ModeAudit, ModeLight, ModeStrict:
		// 合法 ceiling：取更宽松者
	default:
		return policyMode // 未指定 ceiling，保持老行为
	}
	if modeEnforcementRank(ceiling) < modeEnforcementRank(policyMode) {
		return ceiling
	}
	return policyMode
}

func matchExplicitPolicyAction(policy *EffectivePolicy, toolName, toolType string) (bool, bool, bool, bool, string) {
	rules := make([]agentguardmatch.Rule, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		rules = append(rules, agentguardmatch.Rule{
			ID:      rule.ID,
			Pattern: rule.ToolPattern,
			Action:  string(rule.Action),
			Enabled: policyRuleEnabled(rule),
		})
	}
	matched := agentguardmatch.Evaluate(rules, toolName, toolType)
	switch DecisionAction(matched.Action) {
	case DecisionAllow:
		return true, false, false, false, matched.RuleID
	case DecisionAudit:
		return false, true, false, false, matched.RuleID
	case DecisionConfirm:
		return false, false, true, false, matched.RuleID
	case DecisionBlock:
		return false, false, false, true, matched.RuleID
	default:
		return false, false, false, false, ""
	}
}

func withMatchedPolicyRuleEvidence(evidence []Evidence, ruleID string) []Evidence {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return evidence
	}
	for _, item := range evidence {
		if strings.TrimSpace(item.RuleID) == ruleID {
			return evidence
		}
	}
	result := make([]Evidence, len(evidence), len(evidence)+1)
	copy(result, evidence)
	return append(result, Evidence{
		RuleID:   ruleID,
		Category: "policy_rule_match",
	})
}

func policyRuleEnabled(rule PolicyRule) bool {
	return rule.Enabled
}

func matchingPolicyException(exceptions []PolicyException, decision Decision, target string) *PolicyException {
	return matchingPolicyExceptionIn(exceptions, decision, target, "")
}

func matchingPolicyExceptionIn(exceptions []PolicyException, decision Decision, target, scope string) *PolicyException {
	now := time.Now()
	for i := range exceptions {
		exception := &exceptions[i]
		if exception.ExpiresAt.IsZero() || !exception.ExpiresAt.After(now) {
			continue
		}
		if isProtectionExceptionRule(exception.RuleID) {
			// 指向防护项的例外只放开该项，已在 resolveProtectionHits 里套用。
			continue
		}
		if !exceptionRuleMatches(exception.RuleID, decision) {
			continue
		}
		if !exceptionTargetMatches(exception.TargetPattern, target, decision.NormalizedTarget) &&
			!exceptionScopeMatches(exception.TargetPattern, scope) {
			continue
		}
		return exception
	}
	return nil
}

func exceptionRuleMatches(ruleID string, decision Decision) bool {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return false
	}
	if ruleID == decision.Reason || ruleID == decision.EffectiveReason {
		return true
	}
	// 阶段项没有原因码：按它产生的结论匹配（见 stageItems）。
	if stage, ok := stageItemFor(ruleID); ok {
		return stage.matches(decision)
	}
	for _, evidence := range decision.Evidence {
		if evidence.RuleID == ruleID {
			return true
		}
	}
	return false
}

func exceptionTargetMatches(pattern, target, normalizedTarget string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, mcpExceptionTargetPrefix) {
		return mcpExceptionTargetMatches(pattern, target) || mcpExceptionTargetMatches(pattern, normalizedTarget)
	}
	target = strings.ToLower(target)
	normalizedTarget = strings.ToLower(normalizedTarget)
	return strings.Contains(target, pattern) || strings.Contains(normalizedTarget, pattern)
}

func defaultExceptionDecision(action DecisionAction) DecisionAction {
	switch action {
	case DecisionAllow, DecisionAudit:
		return action
	default:
		return DecisionAudit
	}
}

// mcpExceptionTargetPrefix 标记 MCP 维度的例外目标：mcp:<服务名>/<工具名>，/<工具名> 可省。
// MCP 调用把 Target 记成 mcp:<服务名>/<工具名>（见网关 mcp_protection_items.go）。
const mcpExceptionTargetPrefix = "mcp:"

// mcpExceptionTargetMatches 精确匹配 MCP 例外目标：带工具名时服务和工具都相等；只写服务名时
// 匹配该服务下的全部工具（按 / 分段，files 不匹配 files2）。不区分大小写。
func mcpExceptionTargetMatches(pattern, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if !strings.HasPrefix(target, mcpExceptionTargetPrefix) {
		return false
	}
	if strings.Contains(strings.TrimPrefix(pattern, mcpExceptionTargetPrefix), "/") {
		return target == pattern
	}
	return target == pattern || strings.HasPrefix(target, pattern+"/")
}

// exceptionScopeMatches 判断写成 mcp:<服务>[/<工具>] 的例外目标是否覆盖本次 MCP 调用。
func exceptionScopeMatches(pattern, scope string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	return scope != "" && strings.HasPrefix(pattern, mcpExceptionTargetPrefix) && mcpExceptionTargetMatches(pattern, scope)
}
