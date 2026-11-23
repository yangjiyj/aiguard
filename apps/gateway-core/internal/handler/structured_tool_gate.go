package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

type structuredToolCallInput struct {
	// ExceptionScope 是 MCP 调用的 mcp:<服务>/<工具>（其他协议为空）。
	ExceptionScope string
	RequestID      string
	TenantID       string
	Protocol       string
	SessionID      string
	OutputItemID   string
	ToolCallID     string
	ToolName       string
	ToolType       string
	Arguments      map[string]interface{}
	// RawArguments is the undecoded tool-argument text; it is only consulted
	// when ArgumentsParseRejected is set.
	RawArguments             string
	ArgumentsParseRejected   bool
	ProtocolIdentityRejected bool
	AgentType                string
	Policy                   *agentguard.EffectivePolicy
	Mode                     agentguard.Mode
	ConfirmSupported         bool
	BaseDecision             agentguard.Decision
}

type structuredToolCallEvaluation struct {
	Decision    agentguard.Decision
	Destructive agentguard.DestructiveAnalysis
	OperationID string
}

// 解析失败、身份异常是兜底防护项 agent.parse_rejected、agent.identity_rejected 的原因码
// （名字沿用 2.9.21，动作不再跟“删除与破坏”卡片走）。
const (
	destructiveParseRejectedFailSafeReason = protection.ReasonParseRejected
	destructiveIdentityRejectedReason      = protection.ReasonIdentityRejected
	protectionKeyIdentityRejected          = protection.KeyIdentityRejected
)

// destructiveParseIncompleteNoSignalReason marks a call the gateway could not
// parse completely but whose raw text carries no destructive signal.
const destructiveParseIncompleteNoSignalReason = "destructive_parse_incomplete_no_signal"

// parseRejectionCarriesNoDestructiveSignal decides whether the parse-rejected
// fail-safe may stand down. Protocol identity tampering, unparseable SQL, a
// shell parse that still sees a destructive word, and a destructive signal
// beyond the 64KB parse limit keep it in force.
func parseRejectionCarriesNoDestructiveSignal(input structuredToolCallInput, analysis agentguard.DestructiveAnalysis) bool {
	if input.ArgumentsParseRejected {
		raw := strings.TrimSpace(input.RawArguments)
		return raw != "" && !agentguard.DestructiveArgumentsSignalPresent(raw)
	}
	return analysis.Category == "" && !analysis.OverflowSignal && strings.TrimSpace(analysis.SignalText) != "" &&
		!agentguard.DestructiveSignalPresent(analysis.SignalText)
}

// identityRejected 判断协议层身份异常是否算 agent.identity_rejected 的命中：可信客户端
// （防护项参数 trusted_agent_types，为空时用内置名单）的身份缺口不算。
func identityRejected(input structuredToolCallInput) bool {
	return input.ProtocolIdentityRejected && !trustedIdentityAgent(input)
}

func trustedIdentityAgent(input structuredToolCallInput) bool {
	var configured []string
	if input.Policy != nil {
		configured = input.Policy.Protections.StringListParam(protectionKeyIdentityRejected, protection.ParamTrustedAgentTypes)
	}
	if len(configured) == 0 {
		return isKnownFrameworkAgent(input.AgentType)
	}
	agent := agentdetect.NormalizeAgentType(input.AgentType)
	if agent == "" {
		return false
	}
	for _, trusted := range configured {
		if agentdetect.NormalizeAgentType(trusted) == agent {
			return true
		}
	}
	return false
}

// Known agent runtimes may have incomplete Responses item identity. Their
// identity gap must not be promoted to destructive intent, but deterministic
// command/SQL/resource analysis still runs below.
func isKnownFrameworkAgent(agentType string) bool {
	switch agentdetect.NormalizeAgentType(agentType) {
	case "openai-codex", "claude-code", "opencode", "workbuddy":
		return true
	default:
		return false
	}
}

type destructiveOperationIdentity struct {
	TenantID         string
	Protocol         string
	SessionID        string
	RequestID        string
	OutputItemID     string
	ToolCallID       string
	ToolName         string
	CanonicalArgs    string
	IdentityRejected bool
}

func operationID(identity destructiveOperationIdentity) string {
	parts := []string{
		strings.TrimSpace(identity.TenantID),
		strings.TrimSpace(identity.Protocol),
		strings.TrimSpace(identity.SessionID),
		strings.TrimSpace(identity.OutputItemID),
		strings.TrimSpace(identity.ToolCallID),
		strings.TrimSpace(identity.ToolName),
		strings.TrimSpace(identity.CanonicalArgs),
	}
	requestScoped := identity.IdentityRejected ||
		strings.TrimSpace(identity.TenantID) == "" ||
		strings.TrimSpace(identity.Protocol) == "" ||
		strings.TrimSpace(identity.SessionID) == "" ||
		strings.TrimSpace(identity.OutputItemID) == "" ||
		strings.TrimSpace(identity.ToolCallID) == ""
	if requestScoped {
		parts = append(parts, strings.TrimSpace(identity.RequestID))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "op_" + hex.EncodeToString(sum[:16])
}

func canonicalOperationArguments(arguments map[string]interface{}) string {
	if arguments == nil {
		return "{}"
	}
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func canonicalOperationArgumentsJSON(raw string) string {
	var value interface{}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return strings.TrimSpace(raw)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return string(encoded)
}

// evaluateStructuredToolCall 在 evaluateStructuredToolCallCore 给出的结论上，把日常开发操作改成只留痕
// （见 tool_routine_observation.go）；执行决策不变。
func evaluateStructuredToolCall(input structuredToolCallInput) structuredToolCallEvaluation {
	result := evaluateStructuredToolCallCore(input)
	result.Decision = applyRoutineObservation(input, result.Decision, result.Destructive)
	return result
}

func evaluateStructuredToolCallCore(input structuredToolCallInput) structuredToolCallEvaluation {
	args := input.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}
	analysis := agentguard.DestructiveAnalysis{}
	// 身份异常不再顶替破坏性分析：参数能解析时照常分析（删除与破坏卡片照常生效），身份异常
	// 另记 agent.identity_rejected 命中。只有参数本身解析失败才跳过分析。
	identity := identityRejected(input)
	if input.ArgumentsParseRejected {
		analysis = agentguard.DestructiveAnalysis{
			Confidence: "medium", Reason: "structured_arguments_parse_rejected",
			SuggestedAction: agentguard.DecisionAudit, ParseRejected: true,
		}
	} else {
		var discardablePaths []string
		if input.Policy != nil && input.Policy.Destructive != nil {
			discardablePaths = input.Policy.Destructive.DiscardablePaths
		}
		analysis = agentguard.AnalyzeDestructiveOperation(agentguard.DestructiveInput{
			ToolName: input.ToolName, ToolType: structuredExecutionToolType(input.ToolType, args),
			WorkingDirectory:    structuredStringArgument(args, "working_directory", "cwd", "workdir"),
			RepositoryRoot:      structuredStringArgument(args, "repository_root", "repo_root"),
			KnownFrameworkAgent: isKnownFrameworkAgent(input.AgentType),
			SQLDialect:          structuredStringArgument(args, "sql_dialect", "dialect"),
			Arguments:           args, DiscardablePaths: discardablePaths,
		})
	}
	result := structuredToolCallEvaluation{
		Decision:    input.BaseDecision,
		Destructive: analysis,
		OperationID: operationID(destructiveOperationIdentity{
			TenantID: input.TenantID, Protocol: input.Protocol, SessionID: input.SessionID, RequestID: input.RequestID,
			OutputItemID: input.OutputItemID, ToolCallID: input.ToolCallID, ToolName: input.ToolName,
			CanonicalArgs: canonicalOperationArguments(args), IdentityRejected: input.ProtocolIdentityRejected,
		}),
	}
	base := input.BaseDecision
	var identityReasons []string
	if identity {
		identityReasons = []string{destructiveIdentityRejectedReason}
	}
	if analysis.ParseRejected && !analysis.HighConfidence {
		if parseRejectionCarriesNoDestructiveSignal(input, analysis) {
			// The gateway could not parse the call, but nothing in the raw text can
			// delete, overwrite, or hide a command. It is recorded as an ordinary
			// tool call instead of being blocked as a destructive operation.
			decision := base
			if identity {
				decision = applyStructuredRejectionPolicy(input, decision, result.OperationID, analysis, identityReasons)
			}
			decision.Evidence = append(decision.Evidence, analysis.Evidence...)
			decision.Evidence = append(decision.Evidence, agentguard.Evidence{
				RuleID:      destructiveParseIncompleteNoSignalReason,
				Category:    agentguard.DestructiveRiskCategory,
				SourceField: "arguments",
			})
			decision.ReasonSummary = destructiveParseIncompleteNoSignalReason
			if input.BaseDecision.RestrictedFileMatched {
				decision.ReasonSummary += ";" + agentguard.RestrictedFileReason
			}
			result.Decision = decision
			return result
		}
		result.Decision = applyStructuredRejectionPolicy(input, base, result.OperationID, analysis,
			append([]string{destructiveParseRejectedFailSafeReason}, identityReasons...))
		return result
	}
	if identity {
		base = applyStructuredRejectionPolicy(input, base, result.OperationID, analysis, identityReasons)
	}
	if analysis.Category == "" {
		result.Decision = base
		return result
	}

	decision := base
	decision.OperationID = result.OperationID
	decision.Evidence = append(decision.Evidence, analysis.Evidence...)
	decision.NormalizedTarget = analysis.TargetSummary
	decision.EvidenceSegments = analysis.EvidenceSegments
	decision.Reason = analysis.Reason
	decision.RiskLevel = destructiveAnalysisRiskLevel(analysis)
	decision.Confidence = destructiveConfidence(analysis.Confidence)
	decision.RiskCategory = agentguard.DestructiveRiskCategory
	decision.RiskSubcategory = analysis.Subcategory
	decision.ReasonSummary = analysis.Reason
	if input.BaseDecision.RestrictedFileMatched {
		decision.ReasonSummary += ";" + agentguard.RestrictedFileReason
	}
	decision.DiscardablePathMatched = analysis.DiscardablePathMatched
	decision.DiscardablePathReason = analysis.DiscardablePathReason

	decision.RawDecision = analysis.SuggestedAction
	if decision.RawDecision == "" || decision.RawDecision == agentguard.DecisionAudit {
		decision.RawDecision = agentguard.DecisionBlock
	}
	general := base
	decision = agentguard.ApplyEffectivePolicy(decision, agentguard.PolicyEvaluationInput{
		ToolName:                  input.ToolName,
		ToolType:                  input.ToolType,
		Target:                    analysis.TargetSummary,
		ExceptionScope:            input.ExceptionScope,
		Policy:                    input.Policy,
		CallerMode:                input.Mode,
		RiskCategory:              agentguard.DestructiveRiskCategory,
		HighConfidence:            analysis.HighConfidence,
		DestructiveConfirmChannel: structuredConfirmAllowed(input),
		General:                   &general,
	})
	result.Decision = decision
	return result
}

// applyStructuredRejectionPolicy 处理解析失败与身份异常：它们是兜底防护项
// agent.parse_rejected、agent.identity_rejected 的命中，按租户配置（含例外、执行模式、
// 确认通道）定动作，再与同一调用的结论 base 取严。不再按“删除与破坏”卡片处置。
func applyStructuredRejectionPolicy(input structuredToolCallInput, base agentguard.Decision, operationID string, analysis agentguard.DestructiveAnalysis, reasons []string) agentguard.Decision {
	riskLevel := destructiveAnalysisRiskLevel(analysis)
	if riskLevel == "" || riskLevel == "low" {
		riskLevel = "medium"
	}
	confidence := destructiveConfidence(analysis.Confidence)
	finding := agentguard.Decision{
		RawDecision: agentguard.DecisionAudit, Reason: reasons[0], RiskLevel: riskLevel, Confidence: confidence,
		NormalizedTarget: analysis.TargetSummary, OperationID: operationID,
		Evidence: append([]agentguard.Evidence(nil), analysis.Evidence...),
	}
	for _, reason := range reasons {
		finding.ProtectionHits = append(finding.ProtectionHits, agentguard.ProtectionHit{
			Reason: reason, Target: analysis.TargetSummary, RiskLevel: riskLevel, Confidence: confidence,
		})
		finding.Evidence = append(finding.Evidence, agentguard.Evidence{RuleID: reason, Category: "agent_fallback", SourceField: "arguments"})
	}
	// 确认通道与同一调用的删除与破坏分支同一口径（MCP 看确认扩展）。
	confirmChannel := structuredConfirmAllowed(input)
	rejection := agentguard.ApplyEffectivePolicy(finding, agentguard.PolicyEvaluationInput{
		ToolName: input.ToolName, ToolType: input.ToolType, Target: analysis.TargetSummary, ExceptionScope: input.ExceptionScope,
		Policy: input.Policy, CallerMode: input.Mode, ConfirmChannelOverride: &confirmChannel,
	})
	decision := mergeStructuredRejection(base, rejection)
	decision.OperationID = operationID
	decision.ReasonSummary = reasons[0]
	if base.RestrictedFileMatched {
		decision.ReasonSummary += ";" + agentguard.RestrictedFileReason
	}
	return decision
}

// mergeStructuredRejection 把解析失败/身份异常的结论并进通用结论：它更严时以它的处置为准
// （保留通用结论里的工具、Skill、来源等信息），否则保留通用结论；两边的防护项命中合并，
// 告警要求取并集。
func mergeStructuredRejection(base, rejection agentguard.Decision) agentguard.Decision {
	out := base
	agentguard.MergeProtectionFields(&out, base, rejection)
	out.Evidence = append(append([]agentguard.Evidence(nil), base.Evidence...), rejection.Evidence...)
	if agentguard.DecisionRank(rejection.EffectiveDecision) > agentguard.DecisionRank(base.EffectiveDecision) {
		if agentguard.DecisionRank(rejection.RawDecision) > agentguard.DecisionRank(out.RawDecision) {
			out.RawDecision = rejection.RawDecision
		}
		out.EffectiveDecision, out.EffectiveReason, out.PolicyReason = rejection.EffectiveDecision, rejection.EffectiveReason, rejection.PolicyReason
		out.Reason, out.RiskLevel, out.Confidence = rejection.Reason, rejection.RiskLevel, rejection.Confidence
		out.Mode, out.ConfiguredEnforcement = rejection.Mode, rejection.ConfiguredEnforcement
		if rejection.MatchedRuleID != "" {
			out.MatchedRuleID = rejection.MatchedRuleID
		}
		if rejection.NormalizedTarget != "" {
			out.NormalizedTarget = rejection.NormalizedTarget
		}
	}
	if rejection.NotificationRequired {
		out.NotificationRequired = true
	}
	return out
}

func destructiveAnalysisRiskLevel(analysis agentguard.DestructiveAnalysis) string {
	switch analysis.RiskLevel {
	case "low", "medium", "high", "critical":
		return analysis.RiskLevel
	default:
		return analysis.Confidence
	}
}

// structuredConfirmAllowed 判断删除与破坏要求确认时这次调用有没有确认通道：MCP 走确认扩展，
// 其余协议走普通确认票据（租户策略打开了确认通道时，重试由控制面兑现一次批准）。
func structuredConfirmAllowed(input structuredToolCallInput) bool {
	if strings.EqualFold(strings.TrimSpace(input.Protocol), "mcp") {
		return input.ConfirmSupported
	}
	return input.Policy != nil && input.Policy.ConfirmChannelEnabled
}

func structuredExecutionToolType(toolType string, args map[string]interface{}) string {
	for _, key := range []string{"command", "cmd", "input"} {
		if value, ok := args[key].(string); ok && strings.TrimSpace(value) != "" {
			return "shell"
		}
	}
	// Codex argv shape: {"command":["bash","-lc","..."]} arrays count as shell too.
	if argv, ok := args["command"].([]interface{}); ok && len(argv) > 0 {
		return "shell"
	}
	if argv, ok := args["command"].([]string); ok && len(argv) > 0 {
		return "shell"
	}
	// Codex JS freeform: input hides exec_command( calls.
	if value, ok := args["input"].(string); ok && strings.Contains(value, "exec_command(") {
		return "shell"
	}
	if argv, ok := args["argv"].([]interface{}); ok && len(argv) > 0 {
		return "shell"
	}
	if argv, ok := args["argv"].([]string); ok && len(argv) > 0 {
		return "shell"
	}
	for _, key := range []string{"query", "sql", "statement"} {
		if value, ok := args[key].(string); ok && strings.TrimSpace(value) != "" {
			return agentguard.ToolTypeDatabase
		}
	}
	return toolType
}

func destructiveConfidence(confidence string) float64 {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return 1
	case "medium":
		return 0.6
	default:
		return 0.3
	}
}

func structuredStringArgument(args map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := args[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// isDestructiveGateDecision 判断结论是否出自删除与破坏卡片。解析失败、身份异常的原因码
// 虽以 destructive_ 开头，但它们是兜底防护项，按普通工具调用结论处理。
func isDestructiveGateDecision(decision agentguard.Decision) bool {
	if decision.FinalAction != "" || strings.HasPrefix(decision.EffectiveReason, "destructive_") {
		return true
	}
	if _, fallbackItem := protection.ItemForReason(decision.Reason); fallbackItem {
		return false
	}
	return strings.HasPrefix(decision.Reason, "destructive_")
}

func destructiveSafetyMessage(decision agentguard.Decision) string {
	if decision.EffectiveReason == protection.CauseConfirmWithoutChannelFailClosed {
		return "网关检测到模型准备调用删除或破坏性工具。当前客户端不支持 JJDGuard 确认扩展，调用已被网关阻断。"
	}
	return fmt.Sprintf("网关检测到模型准备调用删除或破坏性工具。调用已被网关阻断。操作编号：%s。", decision.OperationID)
}
