package agentguard

import (
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

const (
	DestructiveRiskCategory = "destructive_change"
)

type DestructiveAction string

const (
	DestructiveActionRecord     DestructiveAction = "record"
	DestructiveActionAlertAllow DestructiveAction = "alert_allow"
	DestructiveActionConfirm    DestructiveAction = "confirm"
	DestructiveActionBlock      DestructiveAction = "block"
)

type ConfigSource string

const (
	ConfigSourceSystemDefault     ConfigSource = "system_default"
	ConfigSourceModePreset        ConfigSource = "mode_preset"
	ConfigSourceTenantPolicy      ConfigSource = "tenant_policy"
	ConfigSourceApplicationPolicy ConfigSource = "application_policy"
	ConfigSourceAgentPolicy       ConfigSource = "agent_policy"
	ConfigSourceLegacyEnvFallback ConfigSource = "legacy_env_fallback"
)

type DestructivePolicy struct {
	Mode             Mode              `json:"mode,omitempty"`
	Action           DestructiveAction `json:"action"`
	ScopeType        string            `json:"scope_type,omitempty"`
	ScopeRef         string            `json:"scope_ref,omitempty"`
	Protocol         string            `json:"protocol,omitempty"`
	DiscardablePaths []string          `json:"discardable_paths,omitempty"`
	NotifyChannelIDs []string          `json:"notify_channel_ids,omitempty"`
}

type DestructivePolicyResolutionInput struct {
	Mode          Mode
	ScopePolicy   *DestructivePolicy
	TenantPolicy  *DestructivePolicy
	SystemDefault DestructiveAction
}

func ResolveDestructivePolicy(input DestructivePolicyResolutionInput) (*DestructivePolicy, ConfigSource) {
	mode := normalizeDestructiveMode(input.Mode)
	if input.ScopePolicy != nil && validDestructiveAction(input.ScopePolicy.Action) {
		policy := copyDestructivePolicy(input.ScopePolicy, mode)
		if source, ok := scopeConfigSource(policy.ScopeType); ok {
			return policy, source
		}
	}
	if input.TenantPolicy != nil && validDestructiveAction(input.TenantPolicy.Action) {
		policy := copyDestructivePolicy(input.TenantPolicy, mode)
		policy.ScopeType = "tenant"
		policy.ScopeRef = ""
		return policy, ConfigSourceTenantPolicy
	}
	if preset, ok := destructiveModePreset(input.Mode); ok {
		return &DestructivePolicy{Mode: mode, Action: preset}, ConfigSourceModePreset
	}
	action := input.SystemDefault
	if !validDestructiveAction(action) {
		action = DestructiveActionRecord
	}
	return &DestructivePolicy{Mode: ModeAudit, Action: action}, ConfigSourceSystemDefault
}

func DestructiveActionSemantics(action DestructiveAction) (DecisionAction, bool) {
	switch action {
	case DestructiveActionAlertAllow:
		return DecisionAudit, true
	case DestructiveActionConfirm:
		return DecisionConfirm, true
	case DestructiveActionBlock:
		return DecisionBlock, true
	case DestructiveActionRecord:
		fallthrough
	default:
		return DecisionAudit, false
	}
}

func destructiveModePreset(mode Mode) (DestructiveAction, bool) {
	switch normalizeDestructiveMode(mode) {
	case ModeAudit:
		if mode == "" {
			return "", false
		}
		return DestructiveActionRecord, true
	case ModeLight:
		return DestructiveActionAlertAllow, true
	case ModeStrict:
		return DestructiveActionBlock, true
	default:
		return "", false
	}
}

func normalizeDestructiveMode(mode Mode) Mode {
	switch mode {
	case ModeObserve, ModeAudit:
		return ModeAudit
	case ModeLight:
		return ModeLight
	case ModeStrict:
		return ModeStrict
	default:
		return ModeAudit
	}
}

func validDestructiveAction(action DestructiveAction) bool {
	switch action {
	case DestructiveActionRecord, DestructiveActionAlertAllow, DestructiveActionConfirm, DestructiveActionBlock:
		return true
	default:
		return false
	}
}

func copyDestructivePolicy(policy *DestructivePolicy, fallbackMode Mode) *DestructivePolicy {
	copied := *policy
	if copied.Mode == "" {
		copied.Mode = fallbackMode
	} else {
		copied.Mode = normalizeDestructiveMode(copied.Mode)
	}
	copied.ScopeType = strings.ToLower(strings.TrimSpace(copied.ScopeType))
	copied.ScopeRef = strings.TrimSpace(copied.ScopeRef)
	return &copied
}

func scopeConfigSource(scopeType string) (ConfigSource, bool) {
	switch strings.ToLower(strings.TrimSpace(scopeType)) {
	case "agent":
		return ConfigSourceAgentPolicy, true
	case "application":
		return ConfigSourceApplicationPolicy, true
	default:
		return "", false
	}
}

func effectiveDestructivePolicy(input PolicyEvaluationInput) *EffectivePolicy {
	if input.Policy == nil {
		destructive, source := ResolveDestructivePolicy(DestructivePolicyResolutionInput{
			SystemDefault: DestructiveActionRecord,
		})
		return &EffectivePolicy{
			Mode:         destructive.Mode,
			Destructive:  destructive,
			ConfigSource: source,
		}
	}
	if input.Policy.Destructive != nil {
		return input.Policy
	}
	destructive, source := ResolveDestructivePolicy(DestructivePolicyResolutionInput{
		Mode:          input.Policy.Mode,
		SystemDefault: DestructiveActionRecord,
	})
	policy := *input.Policy
	policy.Mode = destructive.Mode
	policy.Destructive = destructive
	policy.ConfigSource = source
	return &policy
}

// DestructiveEffectiveReasonGlobalAuditOnly marks a destructive decision whose
// configured action was clamped to record by the global audit-only posture.
const DestructiveEffectiveReasonGlobalAuditOnly = "destructive_global_audit_only_recorded"

func applyDestructiveEffectivePolicy(raw Decision, input PolicyEvaluationInput) Decision {
	policy := effectiveDestructivePolicy(input)
	configured := policy.Destructive.Action
	modeDefault, ok := destructiveModePreset(policy.Mode)
	if !ok {
		modeDefault = DestructiveActionRecord
	}
	finalAction := configured
	if !validDestructiveAction(finalAction) {
		finalAction = modeDefault
	}
	if !input.HighConfidence {
		finalAction = DestructiveActionRecord
	}
	// The global audit-only posture is the same absolute ceiling every other
	// AgentGuard path honours (clampModeToCeiling): the policy center reports
	// "record" for every behaviour while it is on, so the gateway must not block,
	// confirm, or raise alerts behind that statement.
	globalAuditOnly := callerModeIsRecordOnly(input.CallerMode) && finalAction != DestructiveActionRecord
	if globalAuditOnly {
		finalAction = DestructiveActionRecord
	}
	execution, notify := DestructiveActionSemantics(finalAction)

	decision := raw
	decision.Mode = destructiveExecutionMode(finalAction)
	decision.EffectiveDecision = execution
	decision.EffectiveReason = destructiveEffectiveReason(finalAction, input.HighConfidence)
	if globalAuditOnly {
		decision.EffectiveReason = DestructiveEffectiveReasonGlobalAuditOnly
	}
	decision.PolicyVersion = policy.PolicyVersion
	decision.MatchedPolicyID = policy.ID
	decision.MatchedPolicyName = policy.Name
	decision.ConfigSource = policy.ConfigSource
	decision.ModeDefaultAction = modeDefault
	if isCustomDestructiveSource(policy.ConfigSource) {
		decision.CustomAction = configured
	}
	decision.FinalAction = finalAction
	decision.NotificationRequired = notify
	decision.NotifyChannelIDs = append([]string(nil), policy.Destructive.NotifyChannelIDs...)
	return decision
}

// destructiveCardKey 是策略中心“删除与破坏”卡片的键，例外的 rule_id 可以直接写它。
const destructiveCardKey = "destructive_operation"

// applyDestructiveBranch 是破坏性结论的判定：删除与破坏卡片的动作（套指向它的例外）→
// 确认通道 → 与防护项下限、通用路径上管理员配置的确认/阻断取严 → 告警。
func applyDestructiveBranch(raw Decision, input PolicyEvaluationInput) Decision {
	// 例外按调用所属的 MCP 服务与工具（ExceptionScope，批次 3）匹配，与通用路径同口径。
	resolved := resolveProtectionHitsIn(raw, input.Policy, input.ExceptionScope)
	decision := applyDestructiveEffectivePolicy(withProtectionFields(raw, resolved), input)
	if matchingDestructiveException(input.Policy, decision, input.Target) != nil {
		decision = releaseDestructiveCard(decision)
	}
	decision = applyDestructiveConfirmChannel(decision, input)
	decision = withDestructiveProtectionFloor(decision, resolved, input)
	decision = withConfiguredGeneralVerdict(decision, input.General)
	markProtectionAlert(&decision, input.CallerMode)
	return decision
}

// matchingDestructiveException 找放开删除与破坏卡片的例外：rule_id 是卡片键、风险类别、
// 破坏性子类或分析原因；目标为空、等于操作编号，或是调用目标/规范化目标的子串。
func matchingDestructiveException(policy *EffectivePolicy, decision Decision, target string) *PolicyException {
	if policy == nil {
		return nil
	}
	now := time.Now()
	for i := range policy.Exceptions {
		exception := &policy.Exceptions[i]
		if exception.ExpiresAt.IsZero() || !exception.ExpiresAt.After(now) {
			continue
		}
		switch rule := strings.TrimSpace(exception.RuleID); {
		case rule == "":
			continue
		case rule == destructiveCardKey, rule == DestructiveRiskCategory, rule == decision.RiskSubcategory, rule == decision.Reason:
		default:
			continue
		}
		pattern := strings.TrimSpace(exception.TargetPattern)
		if pattern != "" && pattern != decision.OperationID && !exceptionTargetMatches(pattern, target, decision.NormalizedTarget) {
			continue
		}
		return exception
	}
	return nil
}

// releaseDestructiveCard 把删除与破坏卡片的结论按例外降为仅记录。
func releaseDestructiveCard(decision Decision) Decision {
	decision.EffectiveDecision = DecisionAudit
	decision.EffectiveReason = effectiveReasonExceptionDowngrade
	decision.FinalAction = DestructiveActionRecord
	decision.Mode = destructiveExecutionMode(DestructiveActionRecord)
	decision.NotificationRequired = false
	return decision
}

// applyDestructiveConfirmChannel：卡片要求确认而这次调用没有确认通道时，按阶段项
// agent.confirm_without_channel 处置（指向它的例外把它换成仅记录）。
func applyDestructiveConfirmChannel(decision Decision, input PolicyEvaluationInput) Decision {
	if decision.EffectiveDecision != DecisionConfirm || input.DestructiveConfirmChannel {
		return decision
	}
	fallback := confirmFallbackAction(input.Policy)
	if stageExceptionApplies(input.Policy, protectionKeyConfirmWithoutChannel, input.Target, decision.NormalizedTarget) {
		fallback = protectionExceptionAction
	}
	switch fallback {
	case protection.ActionBlock:
		decision.EffectiveDecision, decision.EffectiveReason = DecisionBlock, effectiveReasonConfirmFailClosed
		decision.FinalAction = DestructiveActionBlock
	case protection.ActionAlertAllow:
		decision.EffectiveDecision, decision.EffectiveReason = DecisionAudit, effectiveReasonConfirmFallbackAudit
		decision.FinalAction, decision.NotificationRequired = DestructiveActionAlertAllow, true
	default:
		decision.EffectiveDecision, decision.EffectiveReason = DecisionAudit, effectiveReasonConfirmFallbackAudit
		decision.FinalAction, decision.NotificationRequired = DestructiveActionRecord, false
	}
	decision.Mode = destructiveExecutionMode(decision.FinalAction)
	return decision
}

// withDestructiveProtectionFloor 让防护项的确认/阻断（下限）与破坏性结论取严：按通用路径
// 同样的执行模式（全局观察留痕下只记录）和确认通道执行。
func withDestructiveProtectionFloor(decision, resolved Decision, input PolicyEvaluationInput) Decision {
	floor := protectionFloor(resolved)
	if floor == DecisionAllow {
		return decision
	}
	mode := input.CallerMode
	if input.Policy != nil {
		mode = input.Policy.Mode
		if input.Policy.RuleMode != "" {
			mode = input.Policy.RuleMode
		}
		mode = clampModeToCeiling(mode, input.CallerMode)
	}
	action, reason, notify := applyMode(floor, effectiveReasonProtectionItem, normalizeMode(mode), input.DestructiveConfirmChannel, confirmFallbackAction(input.Policy))
	if decisionRank(action) <= decisionRank(decision.EffectiveDecision) {
		return decision
	}
	decision.EffectiveDecision, decision.EffectiveReason, decision.PolicyReason = action, reason, effectiveReasonProtectionItem
	decision.ConfiguredEnforcement = true
	if notify {
		decision.NotificationRequired = true
	}
	escalateDestructiveFinalAction(&decision)
	return decision
}

// escalateDestructiveFinalAction：防护项下限或通用结论胜出、结论是确认/阻断时，删除与破坏的
// 最终动作与执行模式跟着改，工具日志、安全事件不把被拦或待确认的调用记成卡片原来的动作。
func escalateDestructiveFinalAction(decision *Decision) {
	switch decision.EffectiveDecision {
	case DecisionBlock:
		decision.FinalAction = DestructiveActionBlock
	case DecisionConfirm:
		decision.FinalAction = DestructiveActionConfirm
	default:
		return
	}
	decision.Mode = destructiveExecutionMode(decision.FinalAction)
}

// withConfiguredGeneralVerdict 保留通用路径上管理员配置的确认/阻断（显式规则、防护项、
// Skill 隔离/撤销、配置的行为结论）：它比破坏性结论更严时以它为准，带上破坏性证据。
func withConfiguredGeneralVerdict(decision Decision, general *Decision) Decision {
	if general == nil || !general.ConfiguredEnforcement {
		return decision
	}
	if general.EffectiveDecision != DecisionBlock && general.EffectiveDecision != DecisionConfirm {
		return decision
	}
	if decisionRank(general.EffectiveDecision) <= decisionRank(decision.EffectiveDecision) {
		return decision
	}
	kept := *general
	kept.Evidence = append(append([]Evidence(nil), general.Evidence...), decision.Evidence...)
	// 仍是一次删除与破坏调用：带上操作编号、风险类别与卡片的配置来源，最终动作按胜出的结论。
	kept.OperationID, kept.RiskCategory, kept.RiskSubcategory = decision.OperationID, decision.RiskCategory, decision.RiskSubcategory
	kept.ConfigSource, kept.ModeDefaultAction, kept.CustomAction = decision.ConfigSource, decision.ModeDefaultAction, decision.CustomAction
	escalateDestructiveFinalAction(&kept)
	return kept
}

func confirmFallbackAction(policy *EffectivePolicy) protection.Action {
	return protectionContextAction(configuredStageAction(protectionSettingsOf(policy), protectionKeyConfirmWithoutChannel), protectionKeyConfirmWithoutChannel)
}

// stageExceptionApplies 判断有没有生效中的例外点名了某个阶段项并覆盖这次调用的目标。
func stageExceptionApplies(policy *EffectivePolicy, key, target, normalizedTarget string) bool {
	if policy == nil {
		return false
	}
	now := time.Now()
	for _, exception := range policy.Exceptions {
		if exception.ExpiresAt.IsZero() || !exception.ExpiresAt.After(now) || strings.TrimSpace(exception.RuleID) != key {
			continue
		}
		if exceptionTargetMatches(exception.TargetPattern, target, normalizedTarget) {
			return true
		}
	}
	return false
}

func callerModeIsRecordOnly(mode Mode) bool {
	return mode == ModeAudit || mode == ModeObserve
}

// destructiveExecutionMode reports the enforcement actually applied, so an
// audit record never shows mode=audit next to a blocked operation.
func destructiveExecutionMode(action DestructiveAction) Mode {
	switch action {
	case DestructiveActionAlertAllow:
		return ModeLight
	case DestructiveActionConfirm, DestructiveActionBlock:
		return ModeStrict
	default:
		return ModeAudit
	}
}

func destructiveEffectiveReason(action DestructiveAction, highConfidence bool) string {
	if !highConfidence {
		return "destructive_confidence_record_only"
	}
	switch action {
	case DestructiveActionAlertAllow:
		return "destructive_alert_allow"
	case DestructiveActionConfirm:
		return "destructive_confirmation_required"
	case DestructiveActionBlock:
		return "destructive_blocked"
	default:
		return "destructive_recorded"
	}
}

func isCustomDestructiveSource(source ConfigSource) bool {
	switch source {
	case ConfigSourceApplicationPolicy, ConfigSourceAgentPolicy, ConfigSourceTenantPolicy:
		return true
	default:
		return false
	}
}
