package agentguard

import (
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

const (
	effectiveReasonExplicitBlock     = "explicit_block"
	effectiveReasonExplicitConfirm   = "explicit_confirm"
	effectiveReasonExplicitAudit     = "explicit_audit"
	effectiveReasonExplicitAllow     = "explicit_allow"
	effectiveReasonWouldBlock        = "would-block"
	effectiveReasonWouldConfirm      = "would-confirm"
	effectiveReasonConfirmFailClosed = protection.CauseConfirmWithoutChannelFailClosed
	// effectiveReasonConfirmFallbackAudit: confirmation was required but no
	// confirmation channel exists, and agent.confirm_without_channel lets the
	// call through (alert-allow or record).
	effectiveReasonConfirmFallbackAudit = "confirm_without_channel_audit"
	effectiveReasonStrictConfirm        = "confirm_channel_available"
	effectiveReasonAnalyzerDefault      = "analyzer_default"
	effectiveReasonGlobalDefault        = "global_default"
	effectiveReasonAnalyzerResult       = "analyzer_result"
	// effectiveReasonAnalyzerAlertOnly: an analyzer's own verdict with no
	// console rule behind it may raise an alert but never block or confirm.
	effectiveReasonAnalyzerAlertOnly = "analyzer_unconfigured_alert_only"
	// effectiveReasonAnalyzerHighRisk (W5 5.6, D3): a block-level analyzer
	// verdict without a console rule follows agent.high_risk_without_rule in
	// protect (strict) mode; record mode still only records, and an explicit
	// rule wins.
	effectiveReasonAnalyzerHighRisk = protection.CauseAnalyzerHighRisk
	// effectiveReasonSkillAdministrator: an administrator quarantined or
	// revoked this Skill version; a broader tool rule does not loosen it.
	effectiveReasonSkillAdministrator = "skill_administrator_action"
)

// ApplyPolicy resolves policy precedence first, then applies the rollout mode.
// Nothing here raises a verdict on its own: what may interrupt a call is an
// explicit rule, the policy's configured default action, a verdict carrying a
// console setting (ConfiguredEnforcement, protection items), and the two
// fallback items agent.high_risk_without_rule / agent.confirm_without_channel.
func ApplyPolicy(raw Decision, ctx PolicyContext) Decision {
	decision := raw
	decision.Mode = normalizeMode(ctx.Mode)
	usesConfiguredDefault := decision.RawDecision == "" && validDecisionAction(ctx.GlobalDefault)
	if decision.RawDecision == "" {
		decision.RawDecision = defaultDecision(ctx.GlobalDefault)
	}
	if decision.PolicyVersion == "" {
		decision.PolicyVersion = ctx.PolicyVersion
	}
	if decision.TraceID == "" {
		decision.TraceID = ctx.TraceID
	}
	if decision.MatchedRuleID == "" {
		decision.MatchedRuleID = ctx.MatchedRuleID
	}
	if decision.MatchedPolicyID == "" {
		decision.MatchedPolicyID = ctx.MatchedPolicyID
	}
	if decision.MatchedPolicyName == "" {
		decision.MatchedPolicyName = ctx.MatchedPolicyName
	}

	// 判定顺序：显式规则 → 分析器结论（未配置规则的高风险调用）→ 防护项与 Skill 下限
	// → 执行模式（含“需要确认但无法确认”）。
	candidate, effectiveReason, explicit := explicitCandidate(decision, ctx)
	if ctx.ExplicitBlock || ctx.ExplicitConfirm ||
		(usesConfiguredDefault && decisionRank(candidate) > decisionRank(DecisionAudit)) {
		decision.ConfiguredEnforcement = true
	}
	policyReason := effectiveReason

	// 分析器自己的结论（背后没有任何控制台配置）：块级结论按 agent.high_risk_without_rule，
	// 其余只告警。其他配置结论（行为突发、序列规则、MCP 准入等）带 ConfiguredEnforcement，
	// 照 2.9.21 原样执行，显式规则仍胜过它们。
	notify := false
	analyzerStage := decision.Mode == ModeStrict && !explicit && !usesConfiguredDefault && !decision.ConfiguredEnforcement &&
		decisionRank(candidate) > decisionRank(DecisionAudit)
	if analyzerStage {
		candidate, effectiveReason, policyReason, notify = applyHighRiskStage(decision.RawDecision, ctx, policyReason)
	}

	// 下限只在这里取一次：防护项的确认/阻断结论与管理员的 Skill 隔离/撤销不被更宽的规则、
	// 未配置结论的降级放松。
	if floor, floorReason := strictFloor(decision, ctx.ReleasedRuleID); decisionRank(floor) > decisionRank(candidate) {
		candidate, effectiveReason, policyReason = floor, floorReason, floorReason
		decision.ConfiguredEnforcement = true
	} else if !explicit && !analyzerStage && floor != DecisionAllow && candidate == floor {
		effectiveReason, policyReason = floorReason, floorReason
	}
	decision.PolicyReason = policyReason

	var fallbackNotify bool
	decision.EffectiveDecision, decision.EffectiveReason, fallbackNotify = applyMode(candidate, effectiveReason, decision.Mode, ctx.ConfirmChannelEnabled,
		protectionContextAction(ctx.ConfirmFallback, protectionKeyConfirmWithoutChannel))
	if notify || fallbackNotify {
		decision.NotificationRequired = true
	}
	return decision
}

// explicitCandidate 按显式规则（或策略默认动作）给出候选动作与原因。
func explicitCandidate(decision Decision, ctx PolicyContext) (DecisionAction, string, bool) {
	switch {
	case ctx.ExplicitBlock:
		return DecisionBlock, effectiveReasonExplicitBlock, true
	case ctx.ExplicitConfirm:
		return DecisionConfirm, effectiveReasonExplicitConfirm, true
	case ctx.ExplicitAudit:
		return DecisionAudit, effectiveReasonExplicitAudit, true
	case ctx.ExplicitAllow:
		return DecisionAllow, effectiveReasonExplicitAllow, true
	case decision.RawDecision != DecisionAllow:
		return decision.RawDecision, effectiveReasonAnalyzerDefault, false
	default:
		return decision.RawDecision, effectiveReasonAnalyzerResult, false
	}
}

// applyHighRiskStage 处理分析器自己的块级结论（agent.high_risk_without_rule）；非块级
// 结论只告警。返回候选动作、执行原因、处置原因和是否要求通知。
func applyHighRiskStage(raw DecisionAction, ctx PolicyContext, policyReason string) (DecisionAction, string, string, bool) {
	if raw != DecisionBlock {
		return DecisionAudit, effectiveReasonAnalyzerAlertOnly, policyReason, false
	}
	switch protectionContextAction(ctx.HighRiskAction, protectionKeyHighRiskWithoutRule) {
	case protection.ActionBlock:
		return DecisionBlock, effectiveReasonAnalyzerHighRisk, effectiveReasonAnalyzerHighRisk, false
	case protection.ActionConfirm:
		return DecisionConfirm, effectiveReasonAnalyzerHighRisk, effectiveReasonAnalyzerHighRisk, false
	case protection.ActionAlertAllow:
		return DecisionAudit, effectiveReasonAnalyzerAlertOnly, policyReason, true
	default:
		return DecisionAudit, effectiveReasonAnalyzerAlertOnly, policyReason, false
	}
}

// strictFloor 是更宽的规则放不开的下限：防护项的确认/阻断结论（已套用指向该项的例外，
// 行为结论类防护项除外，见 behaviorVerdictItems），以及管理员的 Skill 隔离/撤销（一律阻断；
// released 指向它时除外，供通用例外重算用）。返回下限动作和归因原因；没有下限时返回 allow。
func strictFloor(decision Decision, released string) (DecisionAction, string) {
	floor, reason := protectionFloor(decision), effectiveReasonProtectionItem
	if decision.ConfiguredEnforcement && skillAdministratorReason(decision.Reason) &&
		strings.TrimSpace(released) != decision.Reason &&
		decisionRank(DecisionBlock) > decisionRank(floor) {
		floor, reason = DecisionBlock, effectiveReasonSkillAdministrator
	}
	if floor == DecisionAllow {
		return DecisionAllow, ""
	}
	return floor, reason
}

// IsAnalyzerHighRiskBlock reports that the effective block came from the
// D3 high-risk rule, so the caller routes the exit through securityexit.
func IsAnalyzerHighRiskBlock(decision Decision) bool {
	return decision.EffectiveDecision == DecisionBlock && decision.EffectiveReason == effectiveReasonAnalyzerHighRisk
}

func normalizeMode(mode Mode) Mode {
	switch mode {
	case ModeObserve, ModeAudit, ModeLight, ModeStrict:
		return mode
	default:
		return ModeAudit
	}
}

func defaultDecision(globalDefault DecisionAction) DecisionAction {
	switch globalDefault {
	case DecisionAllow, DecisionAudit, DecisionConfirm, DecisionBlock:
		return globalDefault
	default:
		return DecisionAudit
	}
}

func applyMode(candidate DecisionAction, reason string, mode Mode, confirmChannelEnabled bool, confirmFallback protection.Action) (DecisionAction, string, bool) {
	switch mode {
	case ModeObserve:
		action, why := applyObserveMode(candidate)
		return action, why, false
	case ModeAudit:
		action, why := applyAuditMode(candidate)
		return action, why, false
	case ModeLight:
		// W5 5.11: light = alert and allow. It enforces like audit (never
		// blocks or confirms) but is reported as light, not audit.
		action, why := applyAuditMode(candidate)
		return action, why, false
	case ModeStrict:
		return applyStrictMode(candidate, reason, confirmChannelEnabled, confirmFallback)
	default:
		action, why := applyAuditMode(candidate)
		return action, why, false
	}
}

func applyObserveMode(candidate DecisionAction) (DecisionAction, string) {
	switch candidate {
	case DecisionBlock:
		return DecisionAudit, effectiveReasonWouldBlock
	case DecisionConfirm:
		return DecisionAudit, effectiveReasonWouldConfirm
	case DecisionAllow:
		return DecisionAllow, effectiveReasonAnalyzerResult
	case DecisionAudit:
		return DecisionAudit, effectiveReasonAnalyzerResult
	default:
		return DecisionAudit, effectiveReasonGlobalDefault
	}
}

func applyAuditMode(candidate DecisionAction) (DecisionAction, string) {
	switch candidate {
	case DecisionBlock:
		return DecisionAudit, effectiveReasonWouldBlock
	case DecisionConfirm:
		return DecisionAudit, effectiveReasonWouldConfirm
	case DecisionAllow:
		return DecisionAllow, effectiveReasonAnalyzerResult
	case DecisionAudit:
		return DecisionAudit, effectiveReasonAnalyzerResult
	default:
		return DecisionAudit, effectiveReasonGlobalDefault
	}
}

// applyStrictMode enforces the candidate. A confirmation without a
// confirmation channel follows agent.confirm_without_channel: block blocks,
// alert-allow lets it through with a notification, record only records.
func applyStrictMode(candidate DecisionAction, reason string, confirmChannelEnabled bool, confirmFallback protection.Action) (DecisionAction, string, bool) {
	switch candidate {
	case DecisionConfirm:
		if confirmChannelEnabled {
			return DecisionConfirm, effectiveReasonStrictConfirm, false
		}
		switch confirmFallback {
		case protection.ActionBlock:
			return DecisionBlock, effectiveReasonConfirmFailClosed, false
		case protection.ActionAlertAllow:
			return DecisionAudit, effectiveReasonConfirmFallbackAudit, true
		default:
			return DecisionAudit, effectiveReasonConfirmFallbackAudit, false
		}
	case DecisionAllow, DecisionAudit, DecisionBlock:
		return candidate, reason, false
	default:
		return DecisionAudit, effectiveReasonGlobalDefault, false
	}
}

func validDecisionAction(action DecisionAction) bool {
	switch action {
	case DecisionAllow, DecisionAudit, DecisionConfirm, DecisionBlock:
		return true
	default:
		return false
	}
}
