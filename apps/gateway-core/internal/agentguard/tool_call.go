package agentguard

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

type ToolCallAnalysisInput struct {
	// ExceptionScope 是 MCP 调用的 mcp:<服务>/<工具>，供例外按服务、工具维度匹配。
	ExceptionScope        string
	ToolName              string
	ToolType              string
	Arguments             map[string]any
	ContextFragments      []ContextFragment
	Mode                  Mode
	PolicyVersion         string
	TraceID               string
	ConfirmChannelEnabled bool
	AllowedDomains        []string
	CommandAllowlist      []CommandAllowRule
	Policy                *EffectivePolicy
	Behavior              *BehaviorWindow
	ActorKey              string
	SemanticJudge         SemanticJudge // nil = 关闭（默认），observe-only
	SkillAdmission        SkillAdmissionStatus
	// ToolFailureLoopCount 是调用方统计的同一 actor、同一工具在窗口内的失败次数，已达到
	// 防护项 agent.tool_failure_loop 的次数时传入（0 表示没有陷入失败循环）。分析器结论为
	// 放行时记一条 tool_failure_loop 命中，动作按防护项配置。
	ToolFailureLoopCount int
}

// AnalyzeToolCall combines provenance, target, command, SQL, and data-egress analyzers.
func AnalyzeToolCall(ctx context.Context, input ToolCallAnalysisInput) Decision {
	decision, target := AnalyzeToolCallFindings(ctx, input)
	return applyToolCallPolicy(decision, target, input)
}

// AnalyzeToolCallFindings 只跑分析器，返回未经策略判定的结论与用于例外比对的调用目标。
// 端侧 decide 在这之后并入端侧内置规则与授权结论，再统一走 ApplyEffectivePolicy。
func AnalyzeToolCallFindings(ctx context.Context, input ToolCallAnalysisInput) (Decision, string) {
	args := input.Arguments
	if args == nil {
		args = map[string]any{}
	}
	input.ToolType = strings.ToLower(strings.TrimSpace(input.ToolType))

	provenance := AnalyzeArgumentProvenance(args, input.ContextFragments)
	decision := Decision{
		RawDecision:      DecisionAllow,
		Reason:           "tool_call_no_risk",
		RiskLevel:        "low",
		Confidence:       0.7,
		Provenance:       provenance.Provenance,
		TaintedArguments: provenance.TaintedArguments,
		Evidence:         append([]Evidence(nil), provenance.Evidence...),
	}

	toolTypes := []string{input.ToolType}
	if input.ToolType == ToolTypeMCP || input.ToolType == ToolTypeUnknown || input.ToolType == "" {
		toolTypes = inferArgumentToolTypes(args)
	}
	for _, toolType := range toolTypes {
		switch toolType {
		case ToolTypeSkill:
			decision = mergeAnalyzerDecision(decision, analyzeSkillInvocation(input, provenance))
		case "system":
			decision = mergeAnalyzerDecision(decision, analyzeSystemToolCall(args, input.CommandAllowlist))
		case "database":
			decision = mergeAnalyzerDecision(decision, analyzeDatabaseToolCall(args))
		}
	}
	// Independent target and egress checks apply to every tool name and type.
	// Their bounded argument walker already handles nested maps and arrays.
	decision = mergeAnalyzerDecision(decision, analyzeNetworkToolCall(input.ToolName, args, input.AllowedDomains, provenance))
	decision = mergeAnalyzerDecision(decision, analyzeFileToolCall(input.ToolName, args, provenance, isMCPToolCall(input), shellCommandTexts(input, toolTypes, args)...))
	// 租户受限文件模式：在类型分派之后、行为分析之前合并，无策略时 analyzeRestrictedFiles 返回零值。
	decision = mergeAnalyzerDecision(decision, analyzeRestrictedFiles(input, args))

	target := getAnyStringArg(args, "url", "uri", "endpoint", "host", "target", "path", "file_path", "filepath", "file", "destination")
	if input.Behavior != nil {
		behaviorInput := input
		if len(toolTypes) > 0 && (input.ToolType == ToolTypeMCP || input.ToolType == ToolTypeUnknown || input.ToolType == "") {
			behaviorInput.ToolType = toolTypes[0]
		}
		decision = mergeAnalyzerDecision(decision, analyzeBehavior(behaviorInput, args, decision))
	}

	// 语义裁判（observe-only，fail-open）：门控通过且后端在位时才调用。
	if input.SemanticJudge != nil && shouldConsultSemanticJudge(decision) {
		if judged, err := consultSemanticJudge(ctx, input.SemanticJudge, input.ToolName, args, input.ContextFragments); err == nil && judged.RawDecision != "" {
			decision = mergeAnalyzerDecision(decision, clampSemanticDecision(judged))
		}
	}

	if input.ToolFailureLoopCount > 0 && decision.RawDecision == DecisionAllow {
		decision = mergeAnalyzerDecision(decision, toolFailureLoopFinding(input.ToolName, input.ToolFailureLoopCount))
	}
	return decision, target
}

// toolFailureLoopFinding 是防护项 agent.tool_failure_loop 的命中：同一工具在窗口内反复失败。
func toolFailureLoopFinding(toolName string, count int) Decision {
	return protectionFindingWithConfidence(ToolFailureLoopReason, "", "high", 0.8, []Evidence{{
		RuleID: ToolFailureLoopReason, Category: "behavior", SourceField: "tool_name",
		MaskedPreview: fmt.Sprintf("%s failed %d times", toolName, count),
	}})
}

func applyToolCallPolicy(decision Decision, target string, input ToolCallAnalysisInput) Decision {
	if input.Policy != nil {
		// SECURITY_AUDIT_ONLY 铁律：调用方模式（input.Mode）是执行上限。审计/观察模式下
		// 即便租户策略自带 strict，也绝不能真阻断——把调用方模式作为 CallerMode 传入，
		// ApplyEffectivePolicy 据此对策略 Mode 取“更宽松者”钳制。
		return ApplyEffectivePolicy(decision, PolicyEvaluationInput{ToolName: input.ToolName, ToolType: input.ToolType, Target: target, Policy: input.Policy, CallerMode: input.Mode, ExceptionScope: input.ExceptionScope})
	}

	// 无租户策略：走同一判定流程，防护项与两个阶段项一律取注册表默认值。
	return evaluatePolicy(decision, nil, PolicyEvaluationInput{ToolName: input.ToolName, ToolType: input.ToolType, Target: target, CallerMode: input.Mode, ExceptionScope: input.ExceptionScope}, PolicyContext{
		Mode:                  input.Mode,
		ConfirmChannelEnabled: input.ConfirmChannelEnabled,
		PolicyVersion:         input.PolicyVersion,
		TraceID:               input.TraceID,
	})
}

func analyzeBehavior(input ToolCallAnalysisInput, args map[string]any, current Decision) Decision {
	kind := behaviorKindForTool(input.ToolType, input.ToolName)
	sensitive := behaviorTouchesSensitiveTarget(current)
	sequenceOnly := false
	if kind == "" && sensitive {
		// A sensitive read through a tool without a burst category (e.g. a
		// generic file tool that is not named "read") still arms the
		// sensitive-read -> egress sequence rule (W5 5.5). Only the 2.9.21
		// cases (a restricted file, a file tool's sensitive path argument)
		// also count as a file-read burst; any other protection hit arms the
		// sequence rule without adding to the burst count.
		kind = BehaviorFileRead
		sequenceOnly = !legacyBurstCountsSensitiveRead(input.ToolType, args, current)
	}
	if kind == "" {
		return Decision{RawDecision: DecisionAllow, Reason: "behavior_not_applicable", RiskLevel: "low", Confidence: 0.5}
	}
	target := getAnyStringArg(args, "url", "uri", "endpoint", "host", "target", "path", "file_path", "filepath", "file", "destination", "command")
	event := BehaviorEvent{
		ActorKey: input.ActorKey, Kind: kind, Target: target,
		Sensitive:    sensitive,
		SequenceOnly: sequenceOnly,
		Egress:       kind == BehaviorCommandExecute && commandPerformsEgress(args),
	}
	thresholds := input.Behavior.Thresholds()
	if input.Policy != nil && input.Policy.Behavior != nil {
		thresholds = *input.Policy.Behavior
	}
	// 突发窗口取防护项 agent.burst 的 window_seconds（缺省 10 秒，与窗口默认值一致）。
	thresholds.Window = time.Duration(protectionSettingsOf(input.Policy).IntParam(protectionKeyBurst, protection.ParamWindowSeconds)) * time.Second
	return input.Behavior.RecordWithThresholds(event, thresholds)
}

// legacyBurstCountsSensitiveRead 是 2.9.21 把“没有突发类别的调用”补记为读文件突发的口径：受限文件
// 命中，或文件类工具的路径参数是敏感目标。
func legacyBurstCountsSensitiveRead(toolType string, args map[string]any, current Decision) bool {
	if current.RestrictedFileMatched {
		return true
	}
	if !strings.EqualFold(toolType, ToolTypeFile) {
		return false
	}
	path := getAnyStringArg(args, "path", "file_path", "filepath", "file", "target")
	if path == "" {
		return false
	}
	target := AnalyzeTarget(path)
	return target.Kind == TargetFile && target.Hit
}

// behaviorTouchesSensitiveTarget 判断这次调用是否触及敏感目标：只看是否命中敏感目标类
// 或受限文件防护项（与这些项配置成什么动作、是否被拦无关）。
func behaviorTouchesSensitiveTarget(current Decision) bool {
	if current.RestrictedFileMatched {
		return true
	}
	for _, hit := range current.ProtectionHits {
		item, ok := protection.ItemForReason(hit.Reason)
		if ok && (item.Group == protection.GroupAgentTarget || item.Group == protection.GroupAgentRestricted) {
			return true
		}
	}
	return false
}

// egressCommandPattern matches shell programs that move data off the host.
var egressCommandPattern = regexp.MustCompile(`(?i)(^|[\s;&|(])(curl|wget|scp|sftp|rsync|nc|ncat|netcat|socat|ftp|telnet)(\s|$)`)

// commandPerformsEgress reports whether a system tool's command sends data out.
func commandPerformsEgress(args map[string]any) bool {
	if executable := getAnyStringArg(args, "executable", "program", "bin"); executable != "" {
		return egressCommandPattern.MatchString(filepath.Base(executable) + " ")
	}
	commands, _ := filerestrict.ExtractCommandTexts(args)
	for _, command := range commands {
		if egressCommandPattern.MatchString(command) {
			return true
		}
	}
	return false
}

func behaviorKindForTool(toolType string, toolName string) BehaviorKind {
	switch strings.ToLower(toolType) {
	case "file":
		name := strings.ToLower(toolName)
		if strings.Contains(name, "read") {
			return BehaviorFileRead
		}
		for _, marker := range []string{"delete", "remove", "unlink", "trash", "rm_"} {
			if strings.Contains(name, marker) {
				return BehaviorFileDelete
			}
		}
	case "network":
		return BehaviorNetworkEgress
	case "system":
		return BehaviorCommandExecute
	}
	return ""
}

func analyzeSystemToolCall(args map[string]any, allowlist []CommandAllowRule) Decision {
	executable := getAnyStringArg(args, "executable", "program", "bin")
	argv := getAnyStringSliceArg(args, "args", "argv", "arguments")

	// executable+args 是结构化调用（allowlist 按 Executable+ArgsPrefix 匹配），
	// 不能折叠成 shell 文本，否则 "go test ./..." 会被整串送 allowlist 而误伤。
	if executable != "" {
		return AnalyzeCommand(CommandInvocation{
			Executable: executable,
			Args:       argv,
			Allowlist:  allowlist,
		})
	}

	// Codex/argv/JS shapes are normalized by the shared extractor first: bash -lc
	// arrays, powershell/cmd argv, and cmd:"..." literals inside JS blobs each
	// become an individual command to analyze.
	commands, _ := filerestrict.ExtractCommandTexts(args)
	if len(commands) == 0 {
		return Decision{RawDecision: DecisionAudit, Reason: "system_tool_without_command", RiskLevel: "medium", Confidence: 0.55}
	}
	decision := Decision{RawDecision: DecisionAllow, Reason: "command_no_risk", RiskLevel: "low", Confidence: 0.7}
	for _, command := range commands {
		decision = mergeAnalyzerDecision(decision, AnalyzeCommand(CommandInvocation{
			Command:   command,
			Allowlist: allowlist,
		}))
	}
	return decision
}

func analyzeDatabaseToolCall(args map[string]any) Decision {
	statement := getAnyStringArg(args, "query", "sql", "statement", "command")
	if statement == "" {
		return Decision{RawDecision: DecisionAudit, Reason: "database_tool_without_statement", RiskLevel: "medium", Confidence: 0.55}
	}
	return AnalyzeSQL(statement)
}

func analyzeNetworkToolCall(toolName string, args map[string]any, allowedDomains []string, provenance ProvenanceResult) Decision {
	target := getAnyStringArg(args, "url", "uri", "endpoint", "host", "target")
	if target == "" {
		// W5 5.8: the destination may live under any key.
		target = firstURLArgument(args)
	}
	body := getAnyArgumentTextArg(args, "body", "data", "payload", "content")
	if body == "" {
		// W5 5.8: the payload may live under any key.
		body = allArgumentText(args, target)
	}
	decision := Decision{RawDecision: DecisionAllow, Reason: "network_tool_no_risk", RiskLevel: "low", Confidence: 0.7}
	if target != "" {
		targetAnalysis := AnalyzeTarget(target)
		decision.NormalizedTarget = targetAnalysis.NormalizedTarget
		if targetAnalysis.Hit {
			decision = mergeAnalyzerDecision(decision, targetFinding(
				targetAnalysis, target, targetRiskLevel(targetAnalysis), 0.95, targetAnalysis.Evidence,
			))
		}
	}

	if extra, found := analyzeAllArgumentTargets(toolName, args, TargetURL, target, false); found {
		decision = mergeAnalyzerDecision(decision, extra) // W5 5.8
	}

	if target != "" && body != "" {
		decision = mergeAnalyzerDecision(decision, AnalyzeDataEgress(DataEgressInput{
			Target:         target,
			Body:           body,
			AllowedDomains: allowedDomains,
		}))
	}

	if provenance.Provenance == ProvenanceTainted && isIrreversibleNetworkTool(toolName, args) {
		// W5 5.6 (D3): tainted arguments driving an irreversible egress is a
		// high-risk verdict; protect mode blocks it directly.
		decision = mergeAnalyzerDecision(decision, Decision{
			RawDecision: DecisionBlock,
			Reason:      "tainted_irreversible_network_egress",
			RiskLevel:   "high",
			Confidence:  0.8,
			Evidence:    provenance.Evidence,
		})
	}

	return decision
}

// shellCommandTexts returns the command texts of a shell-type call (the same
// tool types restrictedFileCandidates treats as commands); other tools keep
// their arguments' path semantics.
func shellCommandTexts(input ToolCallAnalysisInput, toolTypes []string, args map[string]any) []string {
	shell := input.ToolType == "shell" || strings.EqualFold(input.ToolName, "exec")
	for _, toolType := range toolTypes {
		shell = shell || toolType == "system"
	}
	if !shell {
		return nil
	}
	commands, _ := filerestrict.ExtractCommandTexts(args)
	return commands
}

// isMCPToolCall: the call comes from an MCP server (type mcp, a name
// mcp__<server>__<tool>, or the MCP proxy's exception scope
// mcp:<server>/<tool>). Its arguments are all scanned (design section 6):
// the built-in tools' free-text and .env-write exemptions do not apply.
func isMCPToolCall(input ToolCallAnalysisInput) bool {
	return strings.EqualFold(strings.TrimSpace(input.ToolType), ToolTypeMCP) ||
		ClassifyToolType(input.ToolName) == ToolTypeMCP ||
		strings.HasPrefix(strings.TrimSpace(input.ExceptionScope), "mcp:")
}

func analyzeFileToolCall(toolName string, args map[string]any, provenance ProvenanceResult, mcp bool, shellCommands ...string) Decision {
	path := getAnyStringArg(args, "path", "file_path", "filepath", "file", "target", "destination")
	decision := Decision{RawDecision: DecisionAllow, Reason: "file_tool_no_risk", RiskLevel: "low", Confidence: 0.7}
	if path != "" {
		target := AnalyzeTarget(path)
		decision.NormalizedTarget = target.NormalizedTarget
		// .env 只算读：内置工具写和改它不算命中（设计 5.1）。私钥、云凭据等被写照旧算；MCP 工具和
		// 会回传文件内容或 diff 的工具不在此列（envWriteExempt）。
		if target.Hit && !(target.Reason == targetReasonEnvFile && envWriteExempt(toolName, mcp)) {
			decision = mergeAnalyzerDecision(decision, targetFinding(target, path, "critical", 0.95, target.Evidence))
		}
	}

	if extra, found := analyzeAllArgumentTargets(toolName, args, TargetFile, path, mcp, shellCommands...); found {
		decision = mergeAnalyzerDecision(decision, extra) // W5 5.8
	}
	if extra, found := analyzeScriptContent(toolName, path, args); found {
		decision = mergeAnalyzerDecision(decision, extra)
	}

	if provenance.Provenance == ProvenanceTainted && isIrreversibleFileTool(toolName, args) {
		decision = mergeAnalyzerDecision(decision, Decision{
			RawDecision: DecisionConfirm,
			Reason:      "tainted_irreversible_file_operation",
			RiskLevel:   "high",
			Confidence:  0.8,
			Evidence:    provenance.Evidence,
		})
	}

	return decision
}

// fileWriteToolNames are file tools that write or edit the file at their
// path argument (Claude Code, CodeBuddy, Cline, Gemini CLI, the MCP
// filesystem server and Copilot names).
var fileWriteToolNames = map[string]bool{
	"write": true, "edit": true, "multiedit": true, "notebookedit": true,
	"write_to_file": true, "replace_in_file": true, "write_file": true, "edit_file": true, "create_file": true,
}

// envWriteExemptToolNames write or edit a .env without showing the model what
// was in it. write_to_file and replace_in_file (Cline) answer with the final
// file content, edit_file (also with dryRun) with a diff: they are not exempt.
var envWriteExemptToolNames = map[string]bool{
	"write": true, "edit": true, "multiedit": true, "notebookedit": true, "write_file": true, "create_file": true,
}

// envWriteExempt: writing a .env with this tool is not a read of it. MCP tools
// are never exempt (their arguments and results are not known).
func envWriteExempt(toolName string, mcp bool) bool {
	return !mcp && envWriteExemptToolNames[strings.ToLower(strings.TrimSpace(toolName))]
}

// scriptContentArguments are the arguments that carry what a file-writing
// tool writes (not the text it replaces).
var scriptContentArguments = map[string]bool{
	"content": true, "new_string": true, "edits[].new_string": true, "edits[].newText": true, "diff": true,
}

// analyzeScriptContent judges, as shell commands, what a file-writing tool
// writes into a script or shell startup file (isShellStartupOrScript: *.sh,
// .bashrc, .zshrc, .profile, crontab ...): it runs later as commands. For a
// SEARCH/REPLACE diff only the replacement text counts.
func analyzeScriptContent(toolName, path string, args map[string]any) (Decision, bool) {
	if path == "" || !isShellStartupOrScript(path) || !fileWriteToolNames[strings.ToLower(egressActionName(toolName))] {
		return Decision{}, false
	}
	var merged Decision
	found := false
	for _, argument := range collectStringArguments(args) {
		if !scriptContentArguments[argument.Path] {
			continue
		}
		text := argument.Value
		if argument.Path == "diff" {
			text = replacementBlocks(text)
		}
		decision, hit := analyzeShellCommandTargets(text)
		if !hit {
			continue
		}
		decision.Evidence = withArgumentSource(decision.Evidence, argument.Path)
		if !found {
			merged, found = decision, true
			continue
		}
		merged = mergeAnalyzerDecision(merged, decision)
	}
	return merged, found
}

// replacementBlocks returns the REPLACE halves of a Cline SEARCH/REPLACE diff
// (the lines between "=======" and ">>>>>>> REPLACE"); a text without such
// blocks is returned whole.
func replacementBlocks(diff string) string {
	if !strings.Contains(diff, ">>>>>>> REPLACE") {
		return diff
	}
	var out []string
	inReplace := false
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "======="):
			inReplace = true
		case strings.HasPrefix(line, ">>>>>>> REPLACE"), strings.HasPrefix(line, "<<<<<<< SEARCH"):
			inReplace = false
		case inReplace:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// mergeAnalyzerDecision keeps the stronger analyzer verdict and merges the
// protection-item hits of both sides. The restricted-file flag is carried as
// metadata only; it no longer changes how the merged verdict is enforced.
func mergeAnalyzerDecision(current Decision, next Decision) Decision {
	hits := mergeProtectionHits(current.ProtectionHits, next.ProtectionHits)
	current.ProtectionHits, next.ProtectionHits = hits, hits
	if current.RestrictedFileMatched {
		next.RestrictedFileMatched = true
		if next.RestrictedFilePattern == "" {
			next.RestrictedFilePattern = current.RestrictedFilePattern
		}
	}
	if next.RestrictedFileMatched {
		current.RestrictedFileMatched = true
		if current.RestrictedFilePattern == "" {
			current.RestrictedFilePattern = next.RestrictedFilePattern
		}
	}
	if next.RawDecision == "" {
		return current
	}
	if shouldReplaceDecision(current, next) {
		mergedEvidence := append([]Evidence{}, current.Evidence...)
		mergedEvidence = append(mergedEvidence, next.Evidence...)
		next.Evidence = mergedEvidence
		if next.Provenance == "" || next.Provenance == ProvenanceUnknown {
			next.Provenance = current.Provenance
		}
		if len(next.TaintedArguments) == 0 {
			next.TaintedArguments = current.TaintedArguments
		}
		if next.NormalizedTarget == "" {
			next.NormalizedTarget = current.NormalizedTarget
		}
		return next
	}
	current.Evidence = append(current.Evidence, next.Evidence...)
	if current.NormalizedTarget == "" {
		current.NormalizedTarget = next.NormalizedTarget
	}
	if next.ConfiguredEnforcement && next.RawDecision == current.RawDecision {
		current.ConfiguredEnforcement = true
	}
	return current
}

func shouldReplaceDecision(current Decision, next Decision) bool {
	return decisionRank(next.RawDecision) > decisionRank(current.RawDecision)
}

// DecisionRank 是结论的严重程度排序（allow < audit < confirm < block，未知为 0），供 handler 合并结论用。
func DecisionRank(action DecisionAction) int {
	return decisionRank(action)
}

func decisionRank(action DecisionAction) int {
	switch action {
	case DecisionBlock:
		return 4
	case DecisionConfirm:
		return 3
	case DecisionAudit:
		return 2
	case DecisionAllow:
		return 1
	default:
		return 0
	}
}

func getAnyStringArg(args map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := args[key]; ok {
			if s, ok := value.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func getAnyArgumentTextArg(args map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := args[key]
		if !ok {
			continue
		}
		if text := argumentString(value); text != "" {
			return text
		}
	}
	return ""
}

func getAnyStringSliceArg(args map[string]any, keys ...string) []string {
	for _, key := range keys {
		value, ok := args[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			return append([]string(nil), typed...)
		case []any:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				result = append(result, fmt.Sprint(item))
			}
			return result
		}
	}
	return nil
}

// isIrreversibleNetworkTool 判断一次调用是否“不可逆地把数据发到外部”（W5 5.6 D3）。
// 判法与 2.9.20 相同（irreversibleNetworkSignal）。2.9.21 只在其上开一条窄例外
// （narrowEgressException，见 network_egress_tool.go）：合并请求/拉取请求类工具，在扫描
// 完整、没有外发目标、没有写方法、名字里没有发送类动词、参数看起来不带凭据时不算外发。
func isIrreversibleNetworkTool(toolName string, args map[string]any) bool {
	return irreversibleNetworkSignal(toolName, args) && !narrowEgressException(toolName, args)
}

// irreversibleNetworkSignal 是 2.9.20 的判法；只是子串 put 不再从 output 里认（2.9.22 现场重放：
// TaskOutput、get_output 读的是输出）。input（form_input、render_input）、computer、compute 里的
// put 仍算——2.9.21 第三轮按绕过审查收回过这类例外（computer-use、浏览器填表会把数据送出去）。
func irreversibleNetworkSignal(toolName string, args map[string]any) bool {
	lowerName := strings.ToLower(toolName)
	if strings.Contains(lowerName, "upload") || strings.Contains(lowerName, "post") || toolNameHasPutVerb(toolName) || strings.Contains(lowerName, "request") || strings.Contains(lowerName, "curl") {
		return true
	}
	method := strings.ToUpper(getAnyStringArg(args, "method", "http_method"))
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return getAnyStringArg(args, "body", "data", "payload", "content") != ""
}

// toolNameHasPutVerb: the tool name holds "put" outside the word "output"
// (put_object, putObject, s3Put, form_input, computer), so TaskOutput and
// get_output do not count.
func toolNameHasPutVerb(toolName string) bool {
	return strings.Contains(strings.ReplaceAll(strings.ToLower(toolName), "output", " "), "put")
}

func isIrreversibleFileTool(toolName string, args map[string]any) bool {
	lowerName := strings.ToLower(toolName)
	if strings.Contains(lowerName, "write") || strings.Contains(lowerName, "delete") || strings.Contains(lowerName, "edit") || strings.Contains(lowerName, "move") || strings.Contains(lowerName, "copy") {
		return true
	}
	action := strings.ToLower(getAnyStringArg(args, "mode", "action", "operation"))
	switch action {
	case "write", "delete", "edit", "move", "copy", "append", "overwrite":
		return true
	default:
		return false
	}
}

// Network admission and incident impact are distinct: private reachability
// remains denied, but credential/metadata access has the higher impact.
func targetRiskLevel(target TargetAnalysis) string {
	if target.Reason == targetReasonLoopbackOrPrivate {
		return "high"
	}
	return "critical"
}
