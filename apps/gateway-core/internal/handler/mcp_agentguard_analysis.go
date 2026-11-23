package handler

import (
	"context"
	"errors"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// evaluateMCPAgentGuardToolCall：首次调用与批准后的重放走同一套判定。通用分析（防护项、Skill 准入、
// 显式规则）与 MCP 权限结论按严重程度合并成 BaseDecision；结构化工具门在它之上判删除与破坏（与其中
// 管理员配置的确认/阻断取严，胜出时最终动作跟着改）和解析失败、身份异常两个兜底防护项；最后按工具
// 风险配置收口。各路证据都保留。
func (h *MCPProxyHandler) evaluateMCPAgentGuardToolCall(ctx context.Context, envelope *modelrouter.RequestEnvelope, qualified string, input structuredToolCallInput, permission agentguard.Decision, policyErr error) agentguard.Decision {
	var configured *ToolCheckResult
	if h.toolRiskClient != nil {
		configured, _ = h.toolRiskClient.CheckToolRisk(ctx, envelope.TenantID, qualified)
	}
	configuredType := ""
	if configured != nil && configured.Config != nil {
		configuredType = configured.Config.ToolType
	}
	input.ToolType = agentguard.ResolveToolType(input.ToolName, configuredType, "")
	analyzed := h.analyzeMCPCallArguments(ctx, envelope, input, policyErr)
	input.BaseDecision = mergeMCPToolDecisions(permission, analyzed)
	evaluation := evaluateStructuredToolCall(input)
	decision := mergeMCPToolDecisions(input.BaseDecision, evaluation.Decision)
	decision.OperationID = evaluation.OperationID
	return applyConfiguredToolCallPolicy(decision, configured, input.Mode)
}

func (h *MCPProxyHandler) analyzeMCPCallArguments(ctx context.Context, envelope *modelrouter.RequestEnvelope, input structuredToolCallInput, policyErr error) agentguard.Decision {
	domains, domainEvidence := toolAllowedDomains(ctx, h.db, envelope.TenantID, input.Arguments)
	admission := agentguard.SkillAdmissionUnverified
	identity := agentguard.SkillIdentity{}
	resolution := skillAdmissionResolution{}
	var admissionErr error
	exitMode := securityexit.Protect
	if input.Mode != agentguard.ModeStrict {
		exitMode = securityexit.Record
	}
	if input.ToolType == agentguard.ToolTypeSkill {
		identity = agentguard.ExtractSkillIdentity(input.Arguments)
		resolution, admission, admissionErr = resolveSkillAdmissionForAnalysis(ctx, h.toolRiskClient, nil, envelope, identity, exitMode)
	}
	analyzed := agentguard.AnalyzeToolCall(ctx, agentguard.ToolCallAnalysisInput{
		ToolName: input.ToolName, ToolType: input.ToolType, Arguments: input.Arguments,
		Mode: input.Mode, PolicyVersion: agentGuardPolicyVersion, TraceID: envelope.TraceID,
		// 只在没有租户策略时生效；有策略时通用分析按策略的 confirm_channel_enabled，删除与破坏、
		// 解析失败、身份异常分支按这次调用的确认扩展（structuredConfirmAllowed）。
		ConfirmChannelEnabled: input.ConfirmSupported, AllowedDomains: domains,
		CommandAllowlist: defaultAgentGuardCommandAllowlist(), Policy: input.Policy,
		Behavior: h.agentGuardBehavior, ActorKey: agentGuardActorKey(envelope), SkillAdmission: admission,
		ExceptionScope: input.ExceptionScope,
	})
	analyzed.TraceID = envelope.TraceID
	analyzed.Evidence = append(analyzed.Evidence, domainEvidence...)
	if input.ToolType == agentguard.ToolTypeSkill {
		analyzed.SkillAssetID, analyzed.SkillVersionID = resolution.AssetID, resolution.VersionID
		analyzed.SkillName, analyzed.SkillVersion = identity.CanonicalName, identity.Version
		analyzed.SkillBundleHash, analyzed.SkillSource = identity.BundleHash, identity.Source
		analyzed.SkillAdmission = resolution.Status
		analyzed.Evidence = append(analyzed.Evidence, agentguard.Evidence{
			RuleID: "skill_admission_" + resolution.Status, Category: "skill_admission",
			SourceField: "skill_version", Hash: identity.BundleHash, MaskedPreview: resolution.VersionID,
		})
		// 客户端在准入查询期间断开不是覆盖缺口：不追加缺口证据（与 chat 路径不写 skill_admission_coverage_gap 事件同口径）。
		// decision 里 admission 的状态沿用原有计算，拦截与否不变。
		if admissionErr != nil && !errors.Is(admissionErr, errClientGoneDuringSecurity) {
			analyzed = appendToolAnalysisGap(analyzed, "skill_admission_coverage_gap")
		}
	}
	if policyErr != nil {
		analyzed = appendToolAnalysisGap(analyzed, agentGuardPolicyLoadFailureReason)
		outcome := securityexit.DecideWithPolicy(exitMode, "block", securityexit.DetectionFailure, guardrailPolicy(ctx, h.toolRiskClient))
		if outcome.Enforce {
			analyzed.RawDecision, analyzed.EffectiveDecision = agentguard.DecisionBlock, agentguard.DecisionBlock
			analyzed.Reason, analyzed.EffectiveReason = agentGuardPolicyLoadFailureReason, agentGuardPolicyLoadFailureReason
			analyzed.ConfiguredEnforcement = true
		}
	}
	return analyzed
}

func mergeMCPToolDecisions(base, next agentguard.Decision) agentguard.Decision {
	decision := base
	baseStrength, nextStrength := mcpDecisionStrength(base.EffectiveDecision), mcpDecisionStrength(next.EffectiveDecision)
	if nextStrength > baseStrength || (nextStrength == baseStrength &&
		(next.FinalAction != "" || mcpDecisionStrength(next.RawDecision) > mcpDecisionStrength(base.RawDecision) ||
			(next.ConfiguredEnforcement && !base.ConfiguredEnforcement))) {
		decision = next
	}
	if mcpDecisionStrength(base.RawDecision) > mcpDecisionStrength(decision.RawDecision) {
		decision.RawDecision = base.RawDecision
	}
	if mcpDecisionStrength(next.RawDecision) > mcpDecisionStrength(decision.RawDecision) {
		decision.RawDecision = next.RawDecision
	}
	decision.Evidence = nil
	seen := map[agentguard.Evidence]bool{}
	for _, item := range append(append([]agentguard.Evidence{}, base.Evidence...), next.Evidence...) {
		if !seen[item] {
			seen[item] = true
			decision.Evidence = append(decision.Evidence, item)
		}
	}
	decision.ConfiguredEnforcement = base.ConfiguredEnforcement || next.ConfiguredEnforcement
	agentguard.MergeProtectionFields(&decision, base, next)
	decision.RestrictedFileMatched = base.RestrictedFileMatched || next.RestrictedFileMatched
	for _, source := range []agentguard.Decision{base, next} {
		for _, field := range []struct {
			destination *string
			value       string
		}{
			{&decision.SkillAssetID, source.SkillAssetID}, {&decision.SkillVersionID, source.SkillVersionID},
			{&decision.SkillName, source.SkillName}, {&decision.SkillVersion, source.SkillVersion},
			{&decision.SkillBundleHash, source.SkillBundleHash}, {&decision.SkillSource, source.SkillSource},
			{&decision.SkillAdmission, source.SkillAdmission}, {&decision.PolicyVersion, source.PolicyVersion},
		} {
			if *field.destination == "" {
				*field.destination = field.value
			}
		}
		if decision.Provenance == "" || decision.Provenance == agentguard.ProvenanceUnknown || source.Provenance == agentguard.ProvenanceTainted {
			decision.Provenance = source.Provenance
		}
	}
	decision.TaintedArguments = nil
	tainted := map[string]bool{}
	for _, field := range append(append([]string{}, base.TaintedArguments...), next.TaintedArguments...) {
		if !tainted[field] {
			tainted[field] = true
			decision.TaintedArguments = append(decision.TaintedArguments, field)
		}
	}
	if decision.RestrictedFilePattern == "" {
		decision.RestrictedFilePattern = base.RestrictedFilePattern
		if decision.RestrictedFilePattern == "" {
			decision.RestrictedFilePattern = next.RestrictedFilePattern
		}
	}
	if decision.TraceID == "" {
		decision.TraceID = base.TraceID
		if decision.TraceID == "" {
			decision.TraceID = next.TraceID
		}
	}
	return decision
}

func mcpDecisionStrength(action agentguard.DecisionAction) int {
	switch action {
	case agentguard.DecisionBlock:
		return 4
	case agentguard.DecisionConfirm:
		return 3
	case agentguard.DecisionAudit:
		return 2
	case agentguard.DecisionAllow:
		return 1
	default:
		return 0
	}
}
