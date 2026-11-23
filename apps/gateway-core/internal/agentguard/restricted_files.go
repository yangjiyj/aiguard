package agentguard

import (
	"strings"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// RestrictedFileReason 是命中租户受限文件模式的决策 reason，安全事件与告警映射用它识别。
const RestrictedFileReason = "restricted_file_pattern"

const restrictedFileReason = RestrictedFileReason

// analyzeRestrictedFiles 按租户受限文件模式检查工具调用的文件访问目标。
// 候选来源：file 类工具的路径参数、Codex/argv/JS 形态抽出的命令、apply_patch 的文件行。
// 无策略（policy/RestrictedFiles/Patterns 任一为空）时返回零值，由 mergeAnalyzerDecision 跳过。
func analyzeRestrictedFiles(input ToolCallAnalysisInput, args map[string]any) Decision {
	if input.Policy == nil || input.Policy.RestrictedFiles == nil || len(input.Policy.RestrictedFiles.Patterns) == 0 ||
		!input.Policy.RestrictedFiles.Applies(RestrictedFileScopeToolCall) {
		return Decision{}
	}
	matcher, err := filerestrict.Compile(input.Policy.RestrictedFiles.Patterns)
	if err != nil {
		// convertAgentGuardPolicy 已校验，这里兜底：非法模式不阻断正常调用。
		return Decision{}
	}

	candidates := restrictedFileCandidates(input, args)
	var hits []filerestrict.Hit
	// 路径类候选走精确层。
	if paths := candidates.paths; len(paths) > 0 {
		hits = append(hits, matcher.MatchPaths(paths)...)
	}
	// 命令类候选：每条先精确层，无命中由 MatchCommand 内部回退粗略层。
	for _, command := range candidates.commands {
		hits = append(hits, matcher.MatchCommand(command)...)
	}
	// 整段粗略文本（JS/Python 代码包）在没有任何命中时补一层粗略匹配。
	if len(hits) == 0 && candidates.coarseText != "" {
		hits = append(hits, matcher.MatchText(candidates.coarseText)...)
	}
	if len(hits) == 0 {
		return Decision{}
	}

	// 受限文件是防护项 agent.restricted_file 的命中：动作（RestrictedFiles.Action）
	// 与例外都由 resolveProtectionHits 统一处理，这里只记命中。每个受限文件一条命中，
	// 例外按该文件的原始路径匹配（MatchTarget，不序列化）；证据与日志只用脱敏值。
	var decision Decision
	for i, hit := range restrictedFileSpecificHits(matcher, hits) {
		confidence := 0.95
		if hit.Precision == filerestrict.PrecisionCoarse {
			confidence = 0.75
		}
		target := filerestrict.RedactTarget(hit.Target)
		evidence := []Evidence{
			sanitizedEvidence(restrictedFileReason, "target", "pattern", hit.Pattern),
			sanitizedEvidence(restrictedFileReason, "target", "path", target),
		}
		finding := protectionFindingFor(ProtectionHit{
			Reason: restrictedFileReason, Target: target, RiskLevel: "high", Confidence: confidence, MatchTarget: hit.MatchTarget,
		}, evidence)
		finding.RestrictedFileMatched = true
		finding.RestrictedFilePattern = hit.Pattern
		if i == 0 {
			decision = finding
			continue
		}
		decision = mergeAnalyzerDecision(decision, finding)
	}
	return decision
}

// ResolveRestrictedFileHit 给工具调用以外环节（用户消息提及的文件）的一个受限文件命中定动作：
// 与工具调用同一口径（RestrictedFiles.Action，套指向受限文件的例外，路径按层级比对）。
// 返回生效动作与套用的例外编号。
func ResolveRestrictedFileHit(policy *EffectivePolicy, path string) (protection.Action, string) {
	resolved := resolveProtectionHits(Decision{ProtectionHits: []ProtectionHit{{
		Reason: restrictedFileReason, Target: filerestrict.RedactTarget(path), MatchTarget: filerestrict.ExceptionTarget(path),
	}}}, policy)
	hit := resolved.ProtectionHits[0]
	return protection.Action(hit.Action), hit.ExceptionID
}

// restrictedSpecificHit 是落到单个文件上的受限命中；MatchTarget 是该文件的原始路径，
// 为空表示命中无法落到单个文件（只能按脱敏值匹配例外，文件名例外放不开它）。
type restrictedSpecificHit struct {
	filerestrict.Hit
	MatchTarget string
}

// restrictedFileSpecificHits 把每个命中落到具体文件上。整段参数字符串（例如一整条命令、
// 一段说明文字）被当作路径候选时，Matcher 返回的 Target 是整段文本：按空白和常见分隔符
// 切开后逐个重新匹配，一个文件一条命中；切不出命中时保留原命中但不给原始路径，免得
// 文本里顺带出现的被例外文件名把整段放开。
func restrictedFileSpecificHits(matcher *filerestrict.Matcher, hits []filerestrict.Hit) []restrictedSpecificHit {
	out := make([]restrictedSpecificHit, 0, len(hits))
	seen := map[string]bool{}
	add := func(hit filerestrict.Hit, matchTarget string) {
		key := hit.Pattern + "\x00" + hit.Target + "\x00" + matchTarget
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, restrictedSpecificHit{Hit: hit, MatchTarget: matchTarget})
	}
	for _, hit := range hits {
		tokens := strings.FieldsFunc(hit.Target, func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune("\"'`()[]{},;|&<>=#", r)
		})
		if len(tokens) == 1 && tokens[0] == hit.Target {
			add(hit, filerestrict.ExceptionTarget(hit.Target))
			continue
		}
		found := false
		for _, token := range tokens {
			if tokenHit, ok := matcher.MatchPath(token); ok {
				tokenHit.Precision = hit.Precision
				add(tokenHit, filerestrict.ExceptionTarget(token))
				found = true
			}
		}
		if !found {
			add(hit, "")
		}
	}
	return out
}

// restrictedFileCandidates 聚合三类候选。
type restrictedFileCandidateSet struct {
	paths      []string
	commands   []string
	coarseText string
}

func restrictedFileCandidates(input ToolCallAnalysisInput, args map[string]any) restrictedFileCandidateSet {
	var out restrictedFileCandidateSet
	toolType := strings.ToLower(input.ToolType)
	// A custom tool or nested wrapper must not bypass tenant file restrictions.
	for _, argument := range collectStringArguments(args) {
		if !strings.ContainsAny(argument.Value, "\n") && looksLikeFileTarget(argument.Value) && !looksLikeURLArgument(argument.Value) {
			out.paths = append(out.paths, argument.Value)
		}
	}

	// file 类工具的路径参数（与 analyzeFileToolCall 同款键）。
	if toolType == ToolTypeFile {
		if path := getAnyStringArg(args, "path", "file_path", "filepath", "file", "target", "destination"); path != "" {
			out.paths = append(out.paths, path)
		}
		// apply_patch：从 patch 文本的文件行取路径。
		if patch := getAnyStringArg(args, "patch", "input"); patch != "" {
			out.paths = append(out.paths, applyPatchFilePaths(patch)...)
		}
	}

	// system 类工具：Codex/argv/JS 形态抽命令。
	if toolType == "system" || toolType == "shell" || strings.EqualFold(input.ToolName, "exec") {
		commands, coarse := filerestrict.ExtractCommandTexts(args)
		out.commands = append(out.commands, commands...)
		out.coarseText = coarse
	}

	return out
}

// applyPatchFilePaths 从 apply_patch 文本里取 *** Add/Update/Delete File: 与 *** Move to: 行的路径。
func applyPatchFilePaths(patch string) []string {
	var out []string
	for _, line := range strings.Split(patch, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"} {
			if strings.HasPrefix(trimmed, prefix) {
				path := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
				if path != "" {
					out = append(out, path)
				}
			}
		}
	}
	return out
}
