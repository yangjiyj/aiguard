package agentguard

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

const (
	destructiveCategory = "destructive_operation"
)

var (
	windowsAbsolutePattern       = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	driveRootPattern             = regexp.MustCompile(`(?i)^[a-z]:/$`)
	nonExecutingToolPattern      = regexp.MustCompile(`(?i)(?:^|[._-])(?:query|list|simulate|preview|dry[-_]?run)(?:$|[._-])`)
	destructiveToolActionPattern = regexp.MustCompile(`(?i)(?:^|[._-])(delete|destroy|remove|purge|truncate|format|reset)(?:$|[._-])`)
	windowsDriveSpecPattern      = regexp.MustCompile(`(?i)^[a-z]:$`)
	criticalFilesystemCommand    = regexp.MustCompile(`(?i)(?:\brm\s+-rf\s+/(?:\s*(?:$|[;&|]))|\brm\s+-rf\s+/(?:boot|etc)(?:/|\b)|\brm\s+-rf\s+/(?:home|root|usr)(?:/[^/\s;&|]*)?/?(?:\s|$|[;&|])|\brm\s+-rf\s+/var/log/audit(?:/|\b)|\bfind\s+/\s+-delete\b|\brm\s+--no-preserve-root\b|>\s*/(?:etc|boot|usr)(?:/|\b)|>\s*/var/log/audit(?:/|\b))`)
)

type DestructiveInput struct {
	ToolName            string
	ToolType            string
	WorkingDirectory    string
	RepositoryRoot      string
	KnownFrameworkAgent bool
	SQLDialect          string
	Arguments           map[string]any
	DiscardablePaths    []string
}

type DestructiveAnalysis struct {
	Category        string
	Subcategory     string
	RiskLevel       string
	Confidence      string
	Reason          string
	TargetSummary   string
	SuggestedAction DecisionAction
	HighConfidence  bool
	ParseRejected   bool
	// SignalText is the raw command text a shell parse could not handle. It is
	// set only when no destructive command was recognised, so the caller can
	// decide whether the parse-rejected fail-safe has anything to protect.
	SignalText string
	// OverflowSignal: the part of the command beyond the parse limit (64KB),
	// which neither the parse nor SignalText covers, carries a destructive
	// signal (signal words, file output redirect, or isDestructiveCommand).
	OverflowSignal         bool
	DiscardablePathMatched bool
	DiscardablePathReason  string
	// Routine：这条命令的全部发现都是日常开发操作（清临时文件、构建产物、工作区里的具体文件、系统目录下的
	// 单个运行时文件），只留痕、不进告警。严重级、解析不完整、含动态目标或其它类型的破坏动作一律不算。
	Routine  bool
	Evidence []Evidence
	// EvidenceSegments 是分析器判定为破坏性的那几段原文（解析后的词，未脱敏），供告警证据使用。
	// 拿不到触发段（无法解析、解析不完整、语句对不上）时为空。
	EvidenceSegments []EvidenceSegment
}

// AnalyzeDestructiveOperation analyzes only executable structured tool-call fields.
// Ordinary assistant text is deliberately outside this interface.
func AnalyzeDestructiveOperation(input DestructiveInput) DestructiveAnalysis {
	result := DestructiveAnalysis{
		Confidence:      "low",
		Reason:          "no_deterministic_destructive_operation",
		SuggestedAction: DecisionAudit,
	}

	if query, field := firstStringArgument(input.Arguments, "query", "sql", "statement"); query != "" && isDatabaseTool(input) {
		result = analyzeDestructiveSQL(query, field, normalizeDestructiveSQLDialect(input.SQLDialect))
		return result
	}

	if isCommandTool(input) {
		executables := executableInputs(input.Arguments)
		if len(executables) == 1 {
			return analyzeCommandSegments(input, executables[0])
		}
		if len(executables) > 1 {
			var merged DestructiveAnalysis
			highestRisk := ""
			var evidenceSegments []EvidenceSegment
			var evidence []Evidence
			parseRejected, overflowSignal := false, false
			routineAll := true
			signalTexts := make([]string, 0, len(executables))
			for _, executable := range executables {
				analysis := analyzeCommandSegments(input, executable)
				parseRejected = parseRejected || analysis.ParseRejected
				overflowSignal = overflowSignal || analysis.OverflowSignal
				if analysis.SignalText != "" {
					signalTexts = append(signalTexts, analysis.SignalText)
				}
				evidence = append(evidence, analysis.Evidence...)
				for _, segment := range analysis.EvidenceSegments {
					evidenceSegments = appendEvidenceSegment(evidenceSegments, segment)
				}
				if analysis.Category != "" && !analysis.Routine {
					routineAll = false
				}
				if analysis.Category != "" && destructiveRiskRank(analysis.RiskLevel) > destructiveRiskRank(highestRisk) {
					highestRisk = analysis.RiskLevel
				}
				if preferMergedAnalysis(analysis, merged) {
					merged = analysis
				}
			}
			if merged.Category != "" && destructiveRiskRank(highestRisk) > destructiveRiskRank(merged.RiskLevel) {
				merged.RiskLevel = highestRisk
			}
			merged.ParseRejected = parseRejected
			merged.OverflowSignal = overflowSignal
			merged.Routine = merged.Category != "" && routineAll && !parseRejected && merged.RiskLevel != "critical"
			merged.EvidenceSegments = evidenceSegments
			merged.Evidence = evidence
			if merged.Category == "" && parseRejected {
				merged.SignalText = strings.Join(signalTexts, "\n")
			}
			return merged
		}
	}

	if isExplicitNonExecuting(input) {
		return result
	}

	if result, targetResult, raw, field, ok := analyzeStructuredDestructive(input); ok {
		if len(targetResult.Targets) == 0 {
			return incompleteDestructive(result, raw, field)
		}
		result = finalizeDestructive(result, raw, field, len(targetResult.Targets))
		if targetResult.Exceeded {
			markDestructiveParseRejected(&result, raw, field)
		}
		if targetResult.Conflict {
			result.Evidence = append(result.Evidence, Evidence{
				RuleID:      "agent_destructive_target_conflict",
				Category:    destructiveCategory,
				SourceField: "arguments",
			})
		}
		if !targetResult.Exceeded && !targetResult.Conflict && canDowngradePath(result.Subcategory) {
			applyDiscardablePathDowngrade(&result, input, targetResult.Targets)
		}
		return result
	}

	return result
}

type destructiveCommandFinding struct {
	Analysis DestructiveAnalysis
	Targets  []string
	Command  bool
	// Shown 是证据里要显示、但不算破坏目标的词（redis-cli 的 FLUSHALL、mysqladmin 的 drop、az 的 delete-batch）。
	Shown []string
	// Extra 是附在这条命令后面的证据段（mysql -e、psql -c 里触发的 SQL 语句）。
	Extra []EvidenceSegment
}

func analyzeCommandSegments(input DestructiveInput, executable destructiveExecutableInput) DestructiveAnalysis {
	analysis := analyzeParsedCommandSegments(input, executable)
	if commandOverflowSignal(executable) {
		analysis.OverflowSignal = true
	}
	return analysis
}

// commandOverflowSignal checks the part of a command beyond the parse limit
// (from the word that crosses it) for a destructive signal, with the same
// vocabulary as a command the parser could not handle plus the
// isDestructiveCommand patterns: 64KB of padding must not hide "rm -rf /".
func commandOverflowSignal(executable destructiveExecutableInput) bool {
	tail := ""
	switch {
	case executable.Command != "":
		if len(executable.Command) <= maxDestructiveCommandBytes {
			return false
		}
		tail = executable.Command[overflowTailStart(executable.Command):]
	case len(executable.Argv) > 0:
		// boundedDestructiveArgv keeps maxDestructiveSyntaxNodes words and
		// maxDestructiveCommandBytes bytes; the rest starts at the word that
		// crosses either limit.
		remaining, first := maxDestructiveCommandBytes, -1
		for index, word := range executable.Argv {
			if index >= maxDestructiveSyntaxNodes || len(word) > remaining {
				first = index
				break
			}
			remaining -= len(word)
		}
		if first < 0 {
			return false
		}
		tail = strings.Join(executable.Argv[first:], " ")
	default:
		return false
	}
	return DestructiveSignalPresent(tail) || isDestructiveCommand(tail)
}

func analyzeParsedCommandSegments(input DestructiveInput, executable destructiveExecutableInput) DestructiveAnalysis {
	fallback := DestructiveAnalysis{Confidence: "low", Reason: "command_not_deterministically_destructive", SuggestedAction: DecisionAudit}
	simulated := false
	discardableDowngradeAllowed := true
	segments, reliable := executableCommandSegments(input, executable)
	parseRejected := !reliable

	var merged DestructiveAnalysis
	highestRisk := ""
	targets := make([]string, 0, 2)
	subcategories := make(map[string]struct{}, 2)
	targetSet := make(map[string]struct{}, 2)
	// deleteTargets 是文件删除发现的目标；sideFindingsLowImpact 表示其余发现都只是中危及以下的普通文件覆盖写，
	// 这时“删临时文件 + 写普通文件”的组合命令也按低影响删除定级。
	deleteTargets := make([]string, 0, 2)
	sideFindingsLowImpact := true
	tmpVars := tmpAssignedVariables(executableRaw(executable))
	routineOK := true
	var evidenceSegments []EvidenceSegment
	for _, segment := range segments {
		if segment.ParseRejected {
			parseRejected = true
		}
		segment = expandTmpVariableSegment(segment, tmpVars)
		if input.WorkingDirectory != "" {
			segment.BaseDirs = append(append([]string(nil), segment.BaseDirs...), input.WorkingDirectory)
		}
		for _, finding := range analyzeDestructiveCommand(segment) {
			if finding.Command && commandHasNonExecutingFlag(segment.Words) {
				simulated = true
				continue
			}
			if finding.Command && segment.DynamicArguments {
				discardableDowngradeAllowed = false
			}
			findingTargets := finding.Targets
			if len(findingTargets) == 0 && finding.Command {
				findingTargets = contextualCommandTargets(segment.Words, finding.Analysis.Subcategory, input)
			}
			if len(findingTargets) == 0 && commandNeedsExplicitTarget(finding.Analysis.Subcategory) {
				// 目标没解析出来的破坏动作（git reset --hard 这类）不能被同命令里的临时文件删除带着降级。
				sideFindingsLowImpact = false
				routineOK = false
				if fallback.Category == "" {
					fallback = incompleteDestructive(finding.Analysis, strings.Join(segment.Words, " "), executable.Field)
					if wholeTreeDeleteUnknown(executableRaw(executable), segment.Words) {
						// 整个工作区/家目录被删但目标写不出字面路径：处置口径不变（不拦、不确认），告警级别按整库高危。
						fallback.RiskLevel = "high"
					}
					fallback.EvidenceSegments = appendEvidenceSegment(nil, EvidenceSegment{Words: segment.Evidence, Lexical: segment.EvidenceLexical})
				}
				continue
			}
			evidenceSegments = appendEvidenceSegment(evidenceSegments, EvidenceSegment{
				Words: markEvidenceTargets(segment.Evidence, append(append([]string(nil), findingTargets...), finding.Shown...)), Lexical: segment.EvidenceLexical,
			})
			for _, extra := range finding.Extra {
				evidenceSegments = appendEvidenceSegment(evidenceSegments, extra)
			}
			if merged.Category == "" || preferDestructiveFinding(finding.Analysis, merged) {
				merged = finding.Analysis
			}
			if destructiveRiskRank(finding.Analysis.RiskLevel) > destructiveRiskRank(highestRisk) {
				highestRisk = finding.Analysis.RiskLevel
			}
			subcategories[finding.Analysis.Subcategory] = struct{}{}
			if !canDowngradePath(finding.Analysis.Subcategory) || len(findingTargets) == 0 {
				routineOK = false
			}
			for _, target := range findingTargets {
				if !lowImpactDeleteTarget(target) || credentialFileTarget(target) {
					routineOK = false
				}
			}
			switch {
			case finding.Analysis.Subcategory == "filesystem_delete":
				deleteTargets = append(deleteTargets, findingTargets...)
			case finding.Analysis.Subcategory != "filesystem_overwrite" || destructiveRiskRank(finding.Analysis.RiskLevel) > destructiveRiskRank("medium"):
				sideFindingsLowImpact = false
			}
			var withinLimit bool
			targets, withinLimit = appendUniqueTargets(targets, targetSet, findingTargets)
			if !withinLimit {
				parseRejected = true
				discardableDowngradeAllowed = false
			}
		}
	}
	if merged.Category != "" {
		// 子类按优先级选，严重级取所有发现中的最高者，避免高优先级子类压低同命令里的严重写入。
		if destructiveRiskRank(highestRisk) > destructiveRiskRank(merged.RiskLevel) {
			merged.RiskLevel = highestRisk
		}
		merged = finalizeDestructive(merged, executableRaw(executable), executable.Field, len(targets))
		merged.EvidenceSegments = evidenceSegments
		if parseRejected {
			markDestructiveParseRejected(&merged, executableRaw(executable), executable.Field)
		}
		if !parseRejected && discardableDowngradeAllowed && len(subcategories) == 1 && canDowngradePath(merged.Subcategory) {
			applyDiscardablePathDowngrade(&merged, input, targets)
		}
		if !parseRejected && discardableDowngradeAllowed && sideFindingsLowImpact {
			applyLowImpactDeleteLevel(&merged, deleteTargets, executable.Field, executableRaw(executable))
		}
		merged.Routine = !parseRejected && discardableDowngradeAllowed && routineOK && merged.RiskLevel != "critical"
		return merged
	}
	if fallback.Category != "" {
		if parseRejected {
			markDestructiveParseRejected(&fallback, executableRaw(executable), executable.Field)
		}
		return fallback
	}
	if parseRejected {
		return unreliableCommandAnalysis(executable)
	}
	if simulated {
		return DestructiveAnalysis{
			Confidence: "medium", Reason: "non_executing_command_flag", SuggestedAction: DecisionAudit,
			Evidence: []Evidence{sanitizedEvidence("agent_destructive_non_executing", destructiveCategory, executable.Field, executableRaw(executable))},
		}
	}
	return fallback
}

func appendUniqueTargets(targets []string, seen map[string]struct{}, additions []string) ([]string, bool) {
	for _, addition := range additions {
		if _, exists := seen[addition]; exists {
			continue
		}
		if len(targets) >= maxDestructiveTargets {
			return targets, false
		}
		seen[addition] = struct{}{}
		targets = append(targets, addition)
	}
	return targets, true
}

func destructiveRiskPriority(subcategory string) int {
	switch subcategory {
	case "block_device_destroy", "storage_destroy":
		return 5
	case "infrastructure_destroy", "cloud_resource_destroy", "cluster_destroy":
		return 4
	case "filesystem_delete", "container_destroy", "vcs_destroy", "resource_destroy":
		return 3
	case "filesystem_overwrite":
		return 2
	default:
		return 1
	}
}

func executableRaw(executable destructiveExecutableInput) string {
	if executable.Command != "" {
		if len(executable.Command) > maxDestructiveCommandBytes {
			return executable.Command[:maxDestructiveCommandBytes]
		}
		return executable.Command
	}
	var result strings.Builder
	result.Grow(maxDestructiveCommandBytes)
	for index, word := range executable.Argv {
		if index > 0 {
			if result.Len() >= maxDestructiveCommandBytes {
				break
			}
			result.WriteByte(' ')
		}
		remaining := maxDestructiveCommandBytes - result.Len()
		if len(word) > remaining {
			result.WriteString(word[:remaining])
			break
		}
		result.WriteString(word)
	}
	return result.String()
}

type destructiveSQLDialect uint8

const (
	destructiveSQLGeneric destructiveSQLDialect = iota
	destructiveSQLPostgres
	destructiveSQLMySQL
	destructiveSQLServer
	destructiveSQLite
)

func normalizeDestructiveSQLDialect(raw string) destructiveSQLDialect {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "postgres":
		return destructiveSQLPostgres
	case "mysql":
		return destructiveSQLMySQL
	case "sqlserver":
		return destructiveSQLServer
	case "sqlite":
		return destructiveSQLite
	default:
		return destructiveSQLGeneric
	}
}

func analyzeDestructiveSQL(query, field string, dialect destructiveSQLDialect) DestructiveAnalysis {
	boundedQuery := query
	parseRejected := false
	if len(boundedQuery) > maxDestructiveCommandBytes {
		boundedQuery = boundedQuery[:maxDestructiveCommandBytes]
		parseRejected = true
	}
	cleaned, syntaxClosed, ambiguous := sanitizeDestructiveSQL(boundedQuery, dialect)
	if !syntaxClosed || ambiguous {
		parseRejected = true
	}

	var confirmed, incomplete DestructiveAnalysis
	var confirmedOrdinals, incompleteOrdinals []int // 判定为破坏性的语句序号，供告警证据取原文
	statementCount := 0
	tokenCount := 0
	for offset := 0; offset <= len(cleaned); {
		end := len(cleaned)
		if separator := strings.IndexByte(cleaned[offset:], ';'); separator >= 0 {
			end = offset + separator
		}
		statement := cleaned[offset:end]
		if strings.TrimSpace(statement) != "" {
			statementCount++
			if statementCount > maxDestructiveTargets {
				parseRejected = true
				break
			}
			tokens, exceeded := boundedDestructiveSQLTokens(statement, maxDestructiveSyntaxNodes-tokenCount)
			tokenCount += len(tokens)
			if len(tokens) > 0 {
				if _, valid := executableSQLParts(tokens, 0); !valid {
					parseRejected = true
				}
				subcategory, complete := classifyDestructiveSQLStatement(tokens)
				if !syntaxClosed && end == len(cleaned) {
					complete = false
				}
				if subcategory != "" {
					if complete {
						confirmedOrdinals = append(confirmedOrdinals, statementCount)
					} else {
						incompleteOrdinals = append(incompleteOrdinals, statementCount)
					}
				}
				switch {
				case subcategory == "":
				case complete && confirmed.Category == "":
					confirmed = classification(subcategory)
				case !complete && incomplete.Category == "":
					incomplete = classification(subcategory)
				}
			}
			if exceeded {
				parseRejected = true
				break
			}
		}
		if end == len(cleaned) {
			break
		}
		offset = end + 1
	}

	var result DestructiveAnalysis
	switch {
	case ambiguous && confirmed.Category != "":
		result = incompleteDestructive(confirmed, boundedQuery, field)
	case ambiguous && incomplete.Category != "":
		result = incompleteDestructive(incomplete, boundedQuery, field)
	case ambiguous:
		result = DestructiveAnalysis{
			Confidence:      "medium",
			Reason:          "sql_dialect_ambiguous",
			SuggestedAction: DecisionAudit,
		}
	case confirmed.Category != "" && (!parseRejected || confirmed.Subcategory != "database_unscoped_mutation"):
		result = finalizeDestructive(confirmed, boundedQuery, field, 1)
	case confirmed.Category != "":
		result = incompleteDestructive(confirmed, boundedQuery, field)
	case incomplete.Category != "":
		result = incompleteDestructive(incomplete, boundedQuery, field)
	case parseRejected:
		result = DestructiveAnalysis{
			Confidence:      "medium",
			Reason:          "sql_parse_rejected",
			SuggestedAction: DecisionAudit,
		}
	default:
		return DestructiveAnalysis{Confidence: "low", Reason: "sql_not_deterministically_destructive", SuggestedAction: DecisionAudit}
	}
	if result.Category != "" {
		ordinals := confirmedOrdinals
		if confirmed.Category == "" {
			ordinals = incompleteOrdinals
		}
		// 触发的那几条语句：与分析时的语句序号对得上才写，对不上就不写。
		if raws := sqlEvidenceStatements(boundedQuery); len(raws) == statementCount {
			for _, ordinal := range ordinals {
				if ordinal >= 1 && ordinal <= len(raws) {
					result.EvidenceSegments = appendEvidenceSegment(result.EvidenceSegments, EvidenceSegment{SQL: raws[ordinal-1]})
				}
			}
		}
	}
	if parseRejected {
		markDestructiveSQLParseRejected(&result, boundedQuery, field)
	}
	return result
}

func boundedDestructiveSQLTokens(statement string, limit int) ([]string, bool) {
	tokens := make([]string, 0, min(limit, 8))
	var current strings.Builder
	flush := func() bool {
		if current.Len() == 0 {
			return true
		}
		if len(tokens) >= limit {
			return false
		}
		tokens = append(tokens, strings.ToUpper(current.String()))
		current.Reset()
		return true
	}
	for _, r := range statement {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			current.WriteRune(r)
			continue
		}
		if !flush() {
			return tokens, true
		}
		if r == '(' || r == ')' || r == ',' || r == ';' || r == '=' || r == '<' || r == '>' || r == '!' {
			if len(tokens) >= limit {
				return tokens, true
			}
			tokens = append(tokens, string(r))
		}
	}
	return tokens, !flush()
}

func markDestructiveSQLParseRejected(result *DestructiveAnalysis, raw, field string) {
	result.ParseRejected = true
	if raw != "" {
		result.Evidence = append(result.Evidence,
			sanitizedEvidence("agent_destructive_sql_parse_rejected", destructiveCategory, field, raw))
	}
}

func sanitizeDestructiveSQL(statement string, dialect destructiveSQLDialect) (string, bool, bool) {
	var out strings.Builder
	syntaxClosed := true
	ambiguous := false
	commentStack := make([]bool, 0, maxDestructiveShellDepth)
	commentStarts := make([]int, 0, maxDestructiveShellDepth)
	rejectedCommentSQL := func() string {
		sanitized := out.String()
		for index, executable := range commentStack {
			if executable {
				return sanitized[:commentStarts[index]]
			}
		}
		return sanitized
	}
	for index := 0; index < len(statement); index++ {
		ch := statement[index]
		if len(commentStack) > 0 && !commentStack[len(commentStack)-1] {
			switch {
			case ch == '/' && index+1 < len(statement) && statement[index+1] == '*':
				nested := dialect == destructiveSQLPostgres || dialect == destructiveSQLServer
				if dialect == destructiveSQLGeneric {
					ambiguous = true
					nested = true
				}
				if nested {
					if len(commentStack) >= maxDestructiveShellDepth {
						return rejectedCommentSQL(), false, ambiguous
					}
					commentStack = append(commentStack, false)
					commentStarts = append(commentStarts, out.Len())
				}
				out.WriteString("  ")
				index++
			case ch == '*' && index+1 < len(statement) && statement[index+1] == '/':
				commentStack = commentStack[:len(commentStack)-1]
				commentStarts = commentStarts[:len(commentStarts)-1]
				out.WriteString("  ")
				index++
			default:
				out.WriteByte(' ')
			}
			continue
		}
		if len(commentStack) > 0 && ch == '*' && index+1 < len(statement) && statement[index+1] == '/' {
			commentStack = commentStack[:len(commentStack)-1]
			commentStarts = commentStarts[:len(commentStarts)-1]
			out.WriteString("  ")
			index++
			continue
		}
		if ch == '/' && index+1 < len(statement) && statement[index+1] == '*' {
			if len(commentStack) >= maxDestructiveShellDepth {
				return rejectedCommentSQL(), false, ambiguous
			}
			mysqlExecutableMarker := index+2 < len(statement) && statement[index+2] == '!'
			if dialect == destructiveSQLGeneric && mysqlExecutableMarker {
				ambiguous = true
			}
			executable := dialect == destructiveSQLMySQL && mysqlExecutableMarker
			commentStack = append(commentStack, executable)
			commentStarts = append(commentStarts, out.Len())
			if !executable {
				out.WriteString("  ")
				index++
				continue
			}
			out.WriteString("   ")
			index += 2
			for index+1 < len(statement) {
				next := statement[index+1]
				if next < '0' || next > '9' {
					break
				}
				index++
				out.WriteByte(' ')
			}
			continue
		}
		if ch == '-' && index+1 < len(statement) && statement[index+1] == '-' {
			for index < len(statement) && statement[index] != '\n' {
				out.WriteByte(' ')
				index++
			}
			if index < len(statement) {
				out.WriteByte(statement[index])
			}
			continue
		}
		if ch == '#' {
			for index < len(statement) && statement[index] != '\n' {
				out.WriteByte(' ')
				index++
			}
			if index < len(statement) {
				out.WriteByte(statement[index])
			}
			continue
		}
		if ch == '$' {
			if delimiter, ok := sqlDollarQuoteDelimiter(statement, index); ok &&
				(dialect == destructiveSQLPostgres || dialect == destructiveSQLGeneric) {
				if dialect == destructiveSQLGeneric {
					ambiguous = true
				}
				closingStart := strings.Index(statement[index+len(delimiter):], delimiter)
				end := len(statement)
				if closingStart >= 0 {
					end = index + len(delimiter) + closingStart + len(delimiter)
				} else {
					syntaxClosed = false
				}
				for index < end {
					out.WriteByte(' ')
					index++
				}
				index--
				continue
			}
		}
		if ch == '\'' {
			backslashEscapes := dialect == destructiveSQLMySQL ||
				dialect == destructiveSQLPostgres && postgresEscapeStringPrefix(statement, index)
			out.WriteByte(' ')
			closed := false
			for index+1 < len(statement) {
				index++
				out.WriteByte(' ')
				if statement[index] == '\\' && index+1 < len(statement) {
					if dialect == destructiveSQLGeneric {
						ambiguous = true
					}
					if backslashEscapes || dialect == destructiveSQLGeneric {
						index++
						out.WriteByte(' ')
						continue
					}
				}
				if statement[index] == '\'' {
					if index+1 < len(statement) && statement[index+1] == '\'' {
						index++
						out.WriteByte(' ')
						continue
					}
					closed = true
					break
				}
			}
			if !closed {
				syntaxClosed = false
			}
			continue
		}
		if ch == '[' {
			hasIdentifier := false
			closed := false
			for index+1 < len(statement) {
				index++
				if statement[index] == ']' {
					if index+1 < len(statement) && statement[index+1] == ']' {
						hasIdentifier = true
						index++
						continue
					}
					closed = true
					break
				}
				hasIdentifier = true
			}
			if !closed {
				syntaxClosed = false
			}
			if closed && hasIdentifier {
				out.WriteString(" SQL_IDENTIFIER ")
			} else {
				out.WriteByte(' ')
			}
			continue
		}
		if ch == '"' || ch == 0x60 {
			quote := ch
			hasIdentifier := false
			closed := false
			for index+1 < len(statement) {
				index++
				if statement[index] == quote {
					if index+1 < len(statement) && statement[index+1] == quote {
						hasIdentifier = true
						index++
						continue
					}
					closed = true
					break
				}
				hasIdentifier = true
			}
			if !closed {
				syntaxClosed = false
			}
			if closed && hasIdentifier {
				out.WriteString(" SQL_IDENTIFIER ")
			} else {
				out.WriteByte(' ')
			}
			continue
		}
		out.WriteByte(ch)
	}
	if len(commentStack) > 0 {
		return rejectedCommentSQL(), false, ambiguous
	}
	return out.String(), syntaxClosed, ambiguous
}

func postgresEscapeStringPrefix(statement string, quoteIndex int) bool {
	if quoteIndex < 1 || statement[quoteIndex-1] != 'E' && statement[quoteIndex-1] != 'e' {
		return false
	}
	if quoteIndex == 1 {
		return true
	}
	previous := statement[quoteIndex-2]
	return previous != '_' &&
		(previous < '0' || previous > '9') &&
		(previous < 'a' || previous > 'z') &&
		(previous < 'A' || previous > 'Z')
}

func sqlDollarQuoteDelimiter(statement string, index int) (string, bool) {
	if index < 0 || index >= len(statement) || statement[index] != '$' {
		return "", false
	}
	end := index + 1
	for end < len(statement) && statement[end] != '$' {
		end++
	}
	if end >= len(statement) {
		return "", false
	}
	tag := statement[index+1 : end]
	for offset := 0; offset < len(tag); offset++ {
		ch := tag[offset]
		isStart := ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
		if offset == 0 && !isStart {
			return "", false
		}
		if offset > 0 && !isStart && (ch < '0' || ch > '9') {
			return "", false
		}
	}
	return statement[index : end+1], true
}

// executableSQLParts retains statement boundaries and CTE parentheses. A
// WHERE in the outer SELECT never scopes a mutation inside a data-modifying CTE.
func executableSQLParts(tokens []string, depth int) ([][]string, bool) {
	if len(tokens) == 0 {
		return nil, true
	}
	if depth > maxDestructiveShellDepth {
		return nil, false
	}
	if tokens[0] == "EXPLAIN" {
		i := 1
		execute := false
		if i < len(tokens) && tokens[i] == "(" {
			end, ok := sqlClosingParen(tokens, i)
			if !ok {
				return nil, false
			}
			for j := i + 1; j < end; j++ {
				if tokens[j] == "ANALYZE" || tokens[j] == "ANALYSE" {
					execute = true
					if j+1 < end && (tokens[j+1] == "FALSE" || tokens[j+1] == "OFF" || tokens[j+1] == "0") {
						execute = false
					}
				}
			}
			i = end + 1
		} else {
			for i < len(tokens) && (tokens[i] == "ANALYZE" || tokens[i] == "ANALYSE" || tokens[i] == "VERBOSE") {
				if tokens[i] != "VERBOSE" {
					execute = true
				}
				i++
			}
		}
		if !execute {
			return nil, true
		}
		return executableSQLParts(tokens[i:], depth+1)
	}
	if tokens[0] != "WITH" {
		return [][]string{tokens}, true
	}
	i := 1
	if i < len(tokens) && tokens[i] == "RECURSIVE" {
		i++
	}
	var parts [][]string
	for i < len(tokens) {
		i++ // CTE identifier
		if i < len(tokens) && tokens[i] == "(" {
			end, ok := sqlClosingParen(tokens, i)
			if !ok {
				return nil, false
			}
			i = end + 1
		}
		if i >= len(tokens) || tokens[i] != "AS" {
			return nil, false
		}
		i++
		if i < len(tokens) && tokens[i] == "NOT" {
			i++
		}
		if i < len(tokens) && tokens[i] == "MATERIALIZED" {
			i++
		}
		if i >= len(tokens) || tokens[i] != "(" {
			return nil, false
		}
		end, ok := sqlClosingParen(tokens, i)
		if !ok {
			return nil, false
		}
		nested, ok := executableSQLParts(tokens[i+1:end], depth+1)
		if !ok {
			return nil, false
		}
		parts = append(parts, nested...)
		i = end + 1
		if i < len(tokens) && tokens[i] == "," {
			i++
			continue
		}
		tail, ok := executableSQLParts(tokens[i:], depth+1)
		if !ok {
			return nil, false
		}
		return append(parts, tail...), i < len(tokens)
	}
	return nil, false
}
func sqlClosingParen(tokens []string, start int) (int, bool) {
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i] {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}
func sqlTopLevelContains(tokens []string, word string) bool {
	depth := 0
	for _, token := range tokens {
		switch token {
		case "(":
			depth++
		case ")":
			depth--
		default:
			if depth == 0 && token == word {
				return true
			}
		}
	}
	return false
}
func classifyDestructiveSQLStatement(tokens []string) (string, bool) {
	parts, ok := executableSQLParts(tokens, 0)
	if !ok {
		return "", false
	}
	best := ""
	complete := false
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		category := ""
		valid := false
		switch part[0] {
		case "DROP":
			category, valid = "database_destroy", sqlDropTargetPresent(part)
		case "TRUNCATE":
			category, valid = "database_destroy", sqlTruncateTargetPresent(part)
		case "DELETE":
			if !sqlTopLevelContains(part, "WHERE") || sqlWhereAlwaysTrue(part) {
				category, valid = "database_unscoped_mutation", sqlDeleteTargetPresent(part)
			}
		case "UPDATE":
			if !sqlTopLevelContains(part, "WHERE") || sqlWhereAlwaysTrue(part) {
				category, valid = "database_unscoped_mutation", sqlUpdateTargetPresent(part)
			}
		case "ALTER":
			if sqlTopLevelContains(part, "DROP") {
				category, valid = "database_schema_destroy", len(part) >= 5
			}
		}
		if category != "" && (best == "" || category == "database_destroy" || !complete && valid) {
			best, complete = category, valid
		}
	}
	return best, complete
}

// sqlWhereEnd 是结束 WHERE 子句的顶层关键字。
var sqlWhereEnd = map[string]bool{
	"ORDER": true, "LIMIT": true, "RETURNING": true, "GROUP": true, "HAVING": true, "UNION": true,
	"OFFSET": true, "FETCH": true, "WINDOW": true, "FOR": true, "OUTPUT": true,
}

// sqlWhereAlwaysTrue 判断顶层 WHERE 条件是否恒真（WHERE 1=1、… OR 1=1、WHERE TRUE），这等于没有条件。
// 只认数字字面量相等、TRUE 和非零数字；子查询里的条件不算。
func sqlWhereAlwaysTrue(tokens []string) bool {
	depth, start := 0, -1
	for index, token := range tokens {
		switch token {
		case "(":
			depth++
		case ")":
			depth--
		case "WHERE":
			if depth == 0 && start < 0 {
				start = index + 1
			}
		}
	}
	if start < 0 {
		return false
	}
	end := len(tokens)
	depth = 0
	for index := start; index < len(tokens); index++ {
		switch token := tokens[index]; {
		case token == "(":
			depth++
		case token == ")":
			depth--
		case depth == 0 && sqlWhereEnd[token]:
			end = index
		}
		if end != len(tokens) {
			break
		}
	}
	return sqlConditionAlwaysTrue(tokens[start:end], 0)
}

func sqlConditionAlwaysTrue(tokens []string, depth int) bool {
	if len(tokens) == 0 || depth > maxDestructiveShellDepth {
		return false
	}
	for _, disjunct := range sqlSplitTopLevel(tokens, "OR") {
		conjuncts := sqlSplitTopLevel(disjunct, "AND")
		all := len(conjuncts) > 0
		for _, conjunct := range conjuncts {
			if !sqlAtomAlwaysTrue(conjunct, depth) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func sqlAtomAlwaysTrue(tokens []string, depth int) bool {
	if len(tokens) >= 2 && tokens[0] == "(" {
		if end, ok := sqlClosingParen(tokens, 0); ok && end == len(tokens)-1 {
			return sqlConditionAlwaysTrue(tokens[1:end], depth+1)
		}
	}
	switch len(tokens) {
	case 1:
		return tokens[0] == "TRUE" || sqlNonZeroInteger(tokens[0])
	case 3:
		return tokens[1] == "=" && tokens[0] == tokens[2] && sqlInteger(tokens[0])
	}
	return false
}

func sqlSplitTopLevel(tokens []string, separator string) [][]string {
	var parts [][]string
	depth, start := 0, 0
	for index, token := range tokens {
		switch token {
		case "(":
			depth++
		case ")":
			depth--
		case separator:
			if depth == 0 {
				parts = append(parts, tokens[start:index])
				start = index + 1
			}
		}
	}
	return append(parts, tokens[start:])
}

func sqlInteger(token string) bool {
	for _, r := range token {
		if r < '0' || r > '9' {
			return false
		}
	}
	return token != ""
}

func sqlNonZeroInteger(token string) bool {
	return sqlInteger(token) && strings.Trim(token, "0") != ""
}

func sqlDropTargetPresent(tokens []string) bool {
	if len(tokens) < 3 {
		return false
	}
	index := 2
	if len(tokens) > index+1 && tokens[index] == "IF" && tokens[index+1] == "EXISTS" {
		index += 2
	}
	return sqlObjectTokenPresent(tokens, index)
}

func sqlTruncateTargetPresent(tokens []string) bool {
	index := 1
	if len(tokens) > index && tokens[index] == "TABLE" {
		index++
	}
	if len(tokens) > index && tokens[index] == "ONLY" {
		index++
	}
	return sqlObjectTokenPresent(tokens, index)
}

func sqlDeleteTargetPresent(tokens []string) bool {
	if len(tokens) < 3 || tokens[1] != "FROM" {
		return false
	}
	index := 2
	if len(tokens) > index && tokens[index] == "ONLY" {
		index++
	}
	return sqlObjectTokenPresent(tokens, index)
}

func sqlUpdateTargetPresent(tokens []string) bool {
	index := 1
	if len(tokens) > index && tokens[index] == "ONLY" {
		index++
	}
	return sqlObjectTokenPresent(tokens, index)
}

func sqlObjectTokenPresent(tokens []string, index int) bool {
	if index >= len(tokens) {
		return false
	}
	switch tokens[index] {
	case "WHERE", "SET", "CASCADE", "RESTRICT", "IF", "EXISTS", "ONLY", "TABLE":
		return false
	default:
		return true
	}
}

func analyzeDestructiveCommand(segment destructiveCommandSegment) []destructiveCommandFinding {
	findings := make([]destructiveCommandFinding, 0, 2)
	analysis, targets := analyzeDestructiveCommandAction(segment)
	if analysis.Category != "" {
		findings = append(findings, destructiveCommandFinding{Analysis: analysis, Targets: targets, Command: true})
	} else if finding, ok := analyzeDestructiveToolCommand(segment); ok {
		findings = append(findings, finding)
	}
	if segment.Redirect {
		kept := make([]string, 0, len(segment.Redirects)+len(segment.AppendRedirects))
		risk, subcategory := "", ""
		consider := func(targets []string, appendMode bool) {
			for _, target := range targets {
				targetRisk, targetSubcategory, keep := writeTargetRiskWithBases(target, appendMode, segment.BaseDirs)
				if !keep {
					continue
				}
				kept = append(kept, target)
				if destructiveRiskRank(targetRisk) > destructiveRiskRank(risk) {
					risk, subcategory = targetRisk, targetSubcategory
				}
			}
		}
		consider(segment.Redirects, false)
		consider(segment.AppendRedirects, true)
		resolved := len(segment.Redirects)+len(segment.AppendRedirects) > 0
		// 没有静态目标时：覆盖写目标无法解析（动态词、通配符等），保留原有兜底并按中危报告；
		// 追加写由 POSIX 解析阶段决定是否兜底，这里不产生发现。
		// 有静态目标时：空设备、标准流、临时目录和对普通文件的追加写都被丢弃，不产生发现。
		if len(kept) > 0 || (!resolved && !segment.AppendMode) {
			if risk == "" {
				risk = "medium"
			}
			if subcategory == "" {
				subcategory = "filesystem_overwrite"
			}
			analysis := classification(subcategory)
			// 级别只影响告警分级，处置由策略决定；finalizeDestructive 对系统路径仍会升为严重。
			analysis.RiskLevel = risk
			findings = append(findings, destructiveCommandFinding{Analysis: analysis, Targets: kept})
		}
	}
	return findings
}

func analyzeDestructiveCommandAction(segment destructiveCommandSegment) (DestructiveAnalysis, []string) {
	words := segment.Words
	if len(words) == 0 {
		return DestructiveAnalysis{Confidence: "low", SuggestedAction: DecisionAudit}, nil
	}

	commandWords := destructiveCommandWords(words)
	if len(commandWords) == 0 {
		return DestructiveAnalysis{Confidence: "low", SuggestedAction: DecisionAudit}, nil
	}
	command := strings.ToLower(commandWords[0])
	args := destructiveSubcommandArgs(command, commandWords[1:])
	commandWords = append([]string{commandWords[0]}, args...)

	switch {
	case command == "rm":
		return classification("filesystem_delete"), nonOptionWords(args)
	case command == "shred":
		return classification("filesystem_delete"), shredTargets(args)
	case command == "find" && hasCommandWord(args, "-delete"):
		return classification("filesystem_delete"), findDeleteTargets(commandWords)
	case command == "truncate":
		return classification("filesystem_overwrite"), truncateTargets(args)
	case command == "remove-item":
		return classification("filesystem_delete"), powershellFileTargets(args)
	case command == "clear-content":
		return classification("filesystem_overwrite"), powershellFileTargets(args)
	case command == "format-volume" || command == "clear-disk" || command == "remove-partition":
		return classification("storage_destroy"), powershellStorageTargets(commandWords[0], args)
	case command == "del" || command == "erase" || command == "rd" || command == "rmdir":
		return classification("filesystem_delete"), windowsCommandTargets(args)
	case command == "format":
		return classification("storage_destroy"), windowsFormatTargets(args)
	case command == "git" && wordAtEqualFold(args, 0, "reset") && hasCommandWord(args, "--hard"):
		return classification("vcs_destroy"), nil
	case command == "git" && wordAtEqualFold(args, 0, "clean"):
		return classification("vcs_destroy"), nil
	case command == "git" && wordAtEqualFold(args, 0, "push") && gitForcePush(args):
		return classification("vcs_destroy"), nil
	case composeDownRemovesVolumes(command, args):
		return classification("storage_destroy"), nil
	case command == "docker" && wordAtEqualFold(args, 0, "volume") && wordAtEqualFold(args, 1, "rm"):
		return classification("storage_destroy"), wordsAfter(commandWords, 3)
	case command == "docker" && wordAtEqualFold(args, 0, "system") && wordAtEqualFold(args, 1, "prune"):
		return classification("container_destroy"), nil
	case command == "docker" && wordAtEqualFold(args, 0, "rm"):
		return containerRemovalClassification(args[1:]), nonOptionWords(args[1:])
	case command == "kubectl" && wordAtEqualFold(args, 0, "delete"):
		return classification("cluster_destroy"), kubectlDeleteTargets(args[1:])
	case command == "helm" && (wordAtEqualFold(args, 0, "uninstall") || wordAtEqualFold(args, 0, "delete")):
		return classification("cluster_destroy"), helmUninstallTargets(args[1:])
	case (command == "terraform" || command == "tofu" || command == "pulumi") && wordAtEqualFold(args, 0, "destroy"):
		return classification("infrastructure_destroy"), nil
	case command == "fdisk" && !hasCommandWord(args, "-l") && !hasCommandWord(args, "--list"):
		return classification("block_device_destroy"), conservativeStorageTargets(args, nil)
	case command == "parted" && partedMutates(args):
		return classification("block_device_destroy"), conservativeStorageTargets(args, map[string]struct{}{"-s": {}, "--script": {}, "-f": {}, "--fix": {}})
	case command == "diskpart":
		// A script path is not evidence of which disk the script changes.
		return classification("block_device_destroy"), nil
	case command == "mkfs" || strings.HasPrefix(command, "mkfs."):
		return classification("block_device_destroy"), mkfsTargets(args)
	case command == "wipefs":
		return classification("block_device_destroy"), wipefsTargets(args)
	case command == "dd":
		for _, word := range args {
			if strings.HasPrefix(strings.ToLower(word), "of=/dev/") {
				return classification("block_device_destroy"), []string{strings.TrimPrefix(word, "of=")}
			}
		}
	}
	return DestructiveAnalysis{Confidence: "low", Reason: "command_not_deterministically_destructive", SuggestedAction: DecisionAudit}, nil
}

func analyzeStructuredDestructive(input DestructiveInput) (DestructiveAnalysis, structuredTargetResult, string, string, bool) {
	action, field := firstStringArgument(input.Arguments, "action", "operation")
	action = strings.ToLower(action)
	tool := strings.ToLower(input.ToolName)
	if !isStructuredDestructiveAction(action) {
		matches := destructiveToolActionPattern.FindStringSubmatch(tool)
		if len(matches) < 2 {
			return DestructiveAnalysis{}, structuredTargetResult{}, "", "", false
		}
		action = strings.ToLower(matches[1])
		field = "tool_name"
	}

	targets := structuredTargets(input.Arguments)
	raw := action
	if field == "tool_name" {
		raw = input.ToolName
	}
	resourceType := strings.ToLower(stringArgument(input.Arguments, "resource_type", "kind", "type"))
	typeHint := strings.ToLower(input.ToolType + " " + input.ToolName + " " + resourceType)
	subcategory := "resource_destroy"
	switch {
	case hintHasToken(typeHint, "source", "git", "vcs", "repository"):
		subcategory = "vcs_destroy"
	case hintHasToken(typeHint, "infrastructure", "terraform"):
		subcategory = "infrastructure_destroy"
	case hintHasToken(typeHint, "cloud", "aws", "azure", "gcp"):
		subcategory = "cloud_resource_destroy"
	case action == "format" || hintHasToken(typeHint, "storage", "volume", "snapshot", "disk", "partition"):
		subcategory = "storage_destroy"
	case action == "truncate":
		subcategory = "filesystem_overwrite"
	case hintHasToken(typeHint, "file", "path") || hasStringArgument(input.Arguments, "path"):
		subcategory = "filesystem_delete"
	}
	return classification(subcategory), targets, raw, field, true
}

func isStructuredDestructiveAction(action string) bool {
	switch strings.ToLower(action) {
	case "delete", "destroy", "remove", "purge", "truncate", "format", "reset":
		return true
	default:
		return false
	}
}

func hintHasToken(hint string, wanted ...string) bool {
	want := make(map[string]struct{}, len(wanted))
	for _, token := range wanted {
		want[token] = struct{}{}
	}
	for _, token := range strings.FieldsFunc(strings.ToLower(hint), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if _, ok := want[token]; ok {
			return true
		}
	}
	return false
}

func hasStringArgument(arguments map[string]any, keys ...string) bool {
	value, _ := firstStringArgument(arguments, keys...)
	return value != ""
}

func classification(subcategory string) DestructiveAnalysis {
	riskLevel := "high"
	switch subcategory {
	case "block_device_destroy", "storage_destroy", "database_destroy", "cluster_destroy", "infrastructure_destroy", "cloud_resource_destroy":
		riskLevel = "critical"
	}
	return DestructiveAnalysis{
		Category: destructiveCategory, Subcategory: subcategory,
		RiskLevel:  riskLevel,
		Confidence: "high", Reason: "deterministic_destructive_operation",
		SuggestedAction: DecisionConfirm, HighConfidence: true,
	}
}

func finalizeDestructive(result DestructiveAnalysis, raw, field string, targetCount int) DestructiveAnalysis {
	if destructiveTargetsAreCritical(result.Subcategory, raw) {
		result.RiskLevel = "critical"
	}
	result.TargetSummary = fmt.Sprintf("%s:%d-targets", result.Subcategory, targetCount)
	result.Evidence = []Evidence{sanitizedEvidence("agent_destructive_"+result.Subcategory, destructiveCategory, field, raw)}
	return result
}

func incompleteDestructive(result DestructiveAnalysis, raw, field string) DestructiveAnalysis {
	result.RiskLevel = "medium"
	result.Confidence = "medium"
	result.Reason = "destructive_target_incomplete"
	result.SuggestedAction = DecisionAudit
	result.HighConfidence = false
	result.TargetSummary = result.Subcategory + ":target-incomplete"
	if raw != "" {
		result.Evidence = []Evidence{sanitizedEvidence("agent_destructive_target_incomplete", destructiveCategory, field, raw)}
	}
	return result
}

func applyDiscardablePathDowngrade(result *DestructiveAnalysis, input DestructiveInput, targets []string) {
	if len(targets) != 1 {
		return
	}
	matched, reason := isDiscardableTarget(input.WorkingDirectory, input.RepositoryRoot, targets[0], input.DiscardablePaths)
	if !matched && input.KnownFrameworkAgent {
		matched, reason = isKnownFrameworkDiscardableTarget(input.WorkingDirectory, input.RepositoryRoot, targets[0], input.DiscardablePaths)
	}
	if !matched {
		return
	}
	result.DiscardablePathMatched = true
	result.DiscardablePathReason = reason
	result.Confidence = "medium"
	result.RiskLevel = "medium"
	result.Reason = "discardable_development_path"
	result.SuggestedAction = DecisionAudit
	result.HighConfidence = false
}

// lowImpactDeleteEvidence 标出“只删临时目录、工作目录相对路径或构建产物”而降为中危的删除，告警证据里能看到降级原因。
const lowImpactDeleteEvidence = "agent_destructive_low_impact_target"

// buildArtifactSegments 是常见构建产物、依赖缓存的目录名或文件名（大小写不敏感）；*.egg-info 另按后缀认。
var buildArtifactSegments = map[string]struct{}{
	"dist": {}, "build": {}, "target": {}, "cmakefiles": {}, "cmakecache.txt": {}, "node_modules": {}, ".cache": {}, "__pycache__": {},
	".pytest_cache": {}, ".mypy_cache": {}, ".ruff_cache": {}, ".tox": {}, ".next": {}, ".turbo": {}, ".parcel-cache": {},
}

// applyLowImpactDeleteLevel：一条删除的全部目标都是临时目录下的路径、工作目录相对路径或构建产物时，级别从高危降为中危。
// 只改级别（告警分级），不改子类、置信度、建议处置与原因码：策略配置的确认/阻断照常生效，工具审计照常记录。
// 严重级（系统目录、根目录）不降；有动态参数、解析不完整、混有中危普通文件覆盖写以外的发现时调用方不会进来。
// 同一命令里另有中危覆盖写时合并子类可能是覆盖写，级别按删除降下来后与覆盖写同为中危。
func applyLowImpactDeleteLevel(result *DestructiveAnalysis, targets []string, field, raw string) {
	if !canDowngradePath(result.Subcategory) || result.RiskLevel != "high" || len(targets) == 0 {
		return
	}
	for _, target := range targets {
		if !lowImpactDeleteTarget(target) {
			return
		}
	}
	result.RiskLevel = "medium"
	result.Evidence = append(result.Evidence, sanitizedEvidence(lowImpactDeleteEvidence, destructiveCategory, field, raw))
}

// lowImpactDeleteTarget：/tmp、/var/tmp 下的具体路径；工作目录里的具体相对路径；或 ~/、/home/<用户>/、/root/
// 下含构建产物目录且产物目录前至少还有一级项目目录（~/build、/home/u/dist 这类整块目录不认）。
// 含 ..、.git、变量、反斜杠，或产物目录之前出现通配符的一律不认。
func lowImpactDeleteTarget(target string) bool {
	if lowImpactBaseTarget(target) {
		return true
	}
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, "\x00\\$`") {
		return false
	}
	segments := strings.Split(target, "/")
	for _, segment := range segments {
		if segment == ".." || strings.EqualFold(segment, ".git") {
			return false
		}
	}
	return routineExtraTarget(segments)
}

// lowImpactBaseTarget 是 11-21 两次收窄定下的认定范围；日常开发的其余目标见 routineExtraTarget。
func lowImpactBaseTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, "\x00\\$`") {
		return false
	}
	segments := strings.Split(target, "/")
	for _, segment := range segments {
		if segment == ".." || strings.EqualFold(segment, ".git") {
			return false
		}
	}
	for _, root := range []string{"/tmp/", "/var/tmp/"} {
		if strings.HasPrefix(target, root) {
			return strings.Trim(target[len(root):], "/*?") != ""
		}
	}
	var rest []string
	minParents := 1
	switch {
	case strings.HasPrefix(target, "~/"):
		rest = segments[1:]
	case strings.HasPrefix(target, "/home/") && len(segments) > 3:
		rest = segments[3:]
	case strings.HasPrefix(target, "/root/"):
		rest = segments[2:]
	case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") || windowsAbsolutePattern.MatchString(target):
		return false
	default:
		// 工作目录里的具体相对路径（rm -rf lp3_cycle_mpirun_logs、rm -f .commit_msg.txt）：编程智能体
		// 日常清理自己生成的文件，降中危（用户 11-21 拍板）。. / ./ / 通配符仍按原级别。
		if workdirRelativeTarget(segments) {
			return true
		}
		rest, minParents = segments, 0
	}
	parents := 0
	for _, segment := range rest {
		if segment == "" || segment == "." {
			continue
		}
		lower := strings.ToLower(segment)
		_, artifact := buildArtifactSegments[lower]
		if artifact || strings.HasSuffix(lower, ".egg-info") {
			return parents >= minParents
		}
		if strings.ContainsAny(segment, "*?[]") {
			return false
		}
		parents++
	}
	return false
}

// workdirRelativeTarget：相对路径至少有一级具体名字，每一级都不是选项、~、花括号（.. 和 .git 调用方已排除）；
// 通配只允许出现在有具名父目录的最后一级、且带字面前缀（_deps/prebuild_caps_*），光秃秃的 *、logs/* 不认；
// 删的是工作目录顶层的整个源码目录（src、./lib、tests/）不认——整块删源码仍按高危。
func workdirRelativeTarget(segments []string) bool {
	var named []string
	for _, segment := range segments {
		if segment == "" || segment == "." {
			continue
		}
		if strings.HasPrefix(segment, "-") || strings.ContainsAny(segment, "{}~") {
			return false
		}
		named = append(named, segment)
	}
	if len(named) == 0 {
		return false
	}
	for i, segment := range named {
		if index := strings.IndexAny(segment, "*?["); index >= 0 && (i != len(named)-1 || i == 0 || index == 0) {
			return false
		}
	}
	if len(named) == 1 {
		_, source := sourceRootSegments[strings.ToLower(named[0])]
		return !source
	}
	return true
}

// tmpAssignmentPattern：同一条命令里 VAR=$(mktemp -d …)、VAR=$(ls -d /tmp/…)、VAR=/tmp/… 这类把变量指到临时目录的赋值。
var tmpAssignmentPattern = regexp.MustCompile(`(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=(?:"?\$\(\s*mktemp\s+-d[^)$` + "`" + `;&|]*\)"?|"?\$\(\s*ls\s+-d\s+(/(?:var/)?tmp/[A-Za-z0-9._-]+)\s*\)"?|"?(/(?:var/)?tmp/[A-Za-z0-9._-]+)"?)(?:\s|;|&|$)`)

var anyAssignmentPattern = regexp.MustCompile(`(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=`)

// tmpAssignedVariables 返回只被赋值成临时目录的变量（变量名→临时目录）。同名变量另有其它赋值、或命令里有
// read/for 等也会写它的写法时不认，交给原级别。
func tmpAssignedVariables(raw string) map[string]string {
	out := map[string]string{}
	for _, match := range tmpAssignmentPattern.FindAllStringSubmatch(raw, -1) {
		dir := "/tmp/mktemp.dir"
		if match[2] != "" {
			dir = match[2]
		} else if match[3] != "" {
			dir = match[3]
		}
		if previous, ok := out[match[1]]; ok && previous != dir {
			out[match[1]] = ""
			continue
		}
		out[match[1]] = dir
	}
	counts := map[string]int{}
	for _, match := range anyAssignmentPattern.FindAllStringSubmatch(raw, -1) {
		counts[match[1]]++
	}
	tmpCounts := map[string]int{}
	for _, match := range tmpAssignmentPattern.FindAllStringSubmatch(raw, -1) {
		tmpCounts[match[1]]++
	}
	for name, dir := range out {
		rebinding := regexp.MustCompile(`\b(?:read|for|local|declare|typeset|export\s+-n)\s+(?:-\w+\s+)*` + regexp.QuoteMeta(name) + `\b`)
		if dir == "" || counts[name] != tmpCounts[name] || rebinding.MatchString(raw) {
			delete(out, name)
		}
	}
	return out
}

// expandTmpVariableSegment：段里的动态参数全是同命令里赋成临时目录的变量（rm -rf $T、rm -f "$T/x"）时，
// 换成字面路径再走常规分析（..、系统目录等判定照常）；有任何一个展开不了就原样返回。
func expandTmpVariableSegment(segment destructiveCommandSegment, vars map[string]string) destructiveCommandSegment {
	if !segment.DynamicArguments || len(vars) == 0 || segment.EvidenceLexical {
		return segment
	}
	words := make([]string, 0, len(segment.Evidence))
	var redirects, appendRedirects []string
	literal, op := 0, ""
	for _, word := range segment.Evidence {
		switch word.Kind {
		case EvidenceArg:
		case EvidenceRedirectOp:
			op = word.Text
			continue
		case EvidenceRedirectTarget:
			if !word.Dynamic {
				continue
			}
			expanded := expandTmpVariable(word.Text, vars)
			if strings.ContainsAny(expanded, "$`") {
				return segment
			}
			switch {
			case strings.Contains(op, ">>"):
				appendRedirects = append(appendRedirects, expanded)
			case strings.Contains(op, ">"):
				redirects = append(redirects, expanded)
			}
			continue
		default:
			if word.Dynamic {
				return segment
			}
			continue
		}
		if !word.Dynamic {
			if literal >= len(segment.Words) || segment.Words[literal] != word.Text {
				return segment
			}
			literal++
			words = append(words, word.Text)
			continue
		}
		expanded := expandTmpVariable(word.Text, vars)
		if strings.ContainsAny(expanded, "$`") {
			return segment
		}
		words = append(words, expanded)
	}
	if literal != len(segment.Words) {
		return segment
	}
	segment.Words = words
	segment.RawWords = nil
	if len(redirects)+len(appendRedirects) > 0 {
		segment.Redirect = true
		segment.Redirects = append(append([]string(nil), segment.Redirects...), redirects...)
		segment.AppendRedirects = append(append([]string(nil), segment.AppendRedirects...), appendRedirects...)
		segment.RawRedirects, segment.RawAppendRedirects = nil, nil
	}
	segment.DynamicArguments = false
	return segment
}

// expandTmpVariable 把 $T、${T}、"$T"/sub 里的临时目录变量换成目录本身；不是这类变量就原样返回。
func expandTmpVariable(target string, vars map[string]string) string {
	if len(vars) == 0 {
		return target
	}
	trimmed := strings.Trim(target, `"'`)
	for name, dir := range vars {
		for _, ref := range []string{"${" + name + "}", "$" + name} {
			if !strings.HasPrefix(trimmed, ref) {
				continue
			}
			rest := trimmed[len(ref):]
			if rest != "" && !strings.HasPrefix(rest, "/") {
				continue
			}
			return dir + rest
		}
	}
	return target
}

// sourceRootSegments 是常见的源码/配置根目录名：删除目标正好是这一级时不降级。
var sourceRootSegments = map[string]struct{}{
	"src": {}, "source": {}, "sources": {}, "lib": {}, "libs": {}, "app": {}, "apps": {}, "cmd": {}, "pkg": {},
	"internal": {}, "packages": {}, "include": {}, "test": {}, "tests": {}, "docs": {}, "scripts": {},
	"config": {}, "configs": {}, "deploy": {}, "migrations": {}, ".github": {}, ".claude": {}, ".codex": {},
}

// containerRemovalClassification：docker rm 删的是容器本身（镜像、命名卷都还在），按中危；
// 带 -v/--volumes 一并删匿名卷时保持高危。
func containerRemovalClassification(args []string) DestructiveAnalysis {
	analysis := classification("container_destroy")
	for _, arg := range args {
		if arg == "--" {
			break
		}
		lower := strings.ToLower(arg)
		if strings.HasPrefix(lower, "--volumes") || (strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg, 'v')) {
			return analysis
		}
	}
	analysis.RiskLevel = "medium"
	return analysis
}

func destructiveTargetsAreCritical(subcategory, raw string) bool {
	if subcategory != "filesystem_delete" && subcategory != "filesystem_overwrite" {
		return false
	}
	normalized := strings.ReplaceAll(raw, "\\", "/")
	return criticalFilesystemCommand.MatchString(normalized)
}

func isDiscardableTarget(cwd, repo, target string, configured []string) (bool, string) {
	if containsUnsafePathSyntax(target) {
		return false, ""
	}
	normCWD, cwdStyle, ok := normalizeCrossPlatformPath(cwd)
	if !ok {
		return false, ""
	}
	normRepo, repoStyle, ok := normalizeCrossPlatformPath(repo)
	if !ok || repoStyle != cwdStyle || isRootPath(normRepo) {
		return false, ""
	}
	normTarget, targetStyle, ok := normalizeCrossPlatformPath(target)
	if !ok || targetStyle != repoStyle {
		return false, ""
	}
	if !pathWithin(normRepo, normCWD) || !pathWithin(normRepo, normTarget) || normTarget == normRepo {
		return false, ""
	}
	if isRootPath(normTarget) || isHomePath(normTarget) || hasPathSegment(normTarget, ".git") {
		return false, ""
	}

	allowed := []string{"node_modules", "dist", "build", ".cache", "tmp", "test-output"}
	for _, candidate := range configured {
		candidate = strings.TrimSpace(strings.ReplaceAll(candidate, "\\", "/"))
		if candidate != "" && !strings.Contains(candidate, "/") && candidate != "." && candidate != ".." && !strings.ContainsAny(candidate, "*?[]") {
			allowed = append(allowed, candidate)
		}
	}
	for _, segment := range allowed {
		if hasPathSegment(normTarget, segment) {
			return true, "target_within_discardable_development_directory"
		}
	}
	return false, ""
}

func normalizeCrossPlatformPath(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || containsUnsafePathSyntax(value) {
		return "", "", false
	}
	style := "unix"
	if windowsAbsolutePattern.MatchString(value) {
		style = "windows"
		value = strings.ToLower(strings.ReplaceAll(value, "\\", "/"))
	} else if strings.HasPrefix(value, "/") {
		value = strings.ReplaceAll(value, "\\", "/")
	} else {
		return "", "", false
	}
	if value == "/" || driveRootPattern.MatchString(value) {
		return value, style, true
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == "" {
		return "", "", false
	}
	return strings.TrimSuffix(cleaned, "/"), style, true
}

func containsUnsafePathSyntax(value string) bool {
	normalized := strings.ReplaceAll(value, "\\", "/")
	for _, segment := range strings.Split(normalized, "/") {
		if segment == ".." {
			return true
		}
	}
	return strings.ContainsAny(value, "*?[]") || strings.ContainsRune(value, '\x00')
}

func pathWithin(root, candidate string) bool {
	return candidate == root || strings.HasPrefix(candidate, strings.TrimSuffix(root, "/")+"/")
}

func isRootPath(value string) bool {
	return value == "/" || driveRootPattern.MatchString(value)
}

func isHomePath(value string) bool {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if len(parts) == 2 && (strings.EqualFold(parts[0], "home") || strings.EqualFold(parts[0], "users")) && parts[1] != "" {
		return true
	}
	if len(parts) == 3 && windowsDriveSpecPattern.MatchString(parts[0]) && strings.EqualFold(parts[1], "users") && parts[2] != "" {
		return true
	}
	return len(parts) == 1 && strings.HasSuffix(parts[0], ":")
}

func hasPathSegment(value, want string) bool {
	for _, segment := range strings.Split(strings.Trim(value, "/"), "/") {
		if strings.EqualFold(segment, want) {
			return true
		}
	}
	return false
}

func commandHasNonExecutingFlag(words []string) bool {
	words = destructiveCommandWords(words)
	if len(words) == 0 {
		return false
	}
	command := strings.ToLower(words[0])
	args := destructiveSubcommandArgs(command, words[1:])
	words = append([]string{words[0]}, args...)
	if command == "git" && wordAtEqualFold(args, 0, "push") {
		for _, arg := range gitPushOptionWords(args[1:]) {
			if arg == "--" {
				break
			}
			if arg == "--dry-run" || shortFlagInCluster(arg, 'n', "fuvqn46", "") {
				return true
			}
		}
	}
	allowDryRun := command == "kubectl" && wordAtEqualFold(words, 1, "delete") ||
		command == "helm" && (wordAtEqualFold(words, 1, "uninstall") || wordAtEqualFold(words, 1, "delete")) ||
		composeDownRemovesVolumes(command, words[1:])
	if command == "pulumi" && wordAtEqualFold(words, 1, "destroy") && hasCommandWord(words, "--preview-only") {
		return true
	}
	allowWhatIf := command == "remove-item" || command == "clear-content" || command == "set-content" || command == "format-volume" || command == "clear-disk" || command == "remove-partition"
	optionsTerminated := false
	for index := 1; index < len(words); index++ {
		word := words[index]
		if word == "--" {
			optionsTerminated = true
			continue
		}
		if optionsTerminated {
			continue
		}
		if allowWhatIf {
			option, value, hasValue := strings.Cut(word, ":")
			if strings.EqualFold(option, "-WhatIf") {
				if !hasValue || strings.EqualFold(value, "$true") {
					return true
				}
				continue
			}
		}
		if allowDryRun && word == "--dry-run" {
			if index+1 < len(words) && isExplicitDryRunValue(words[index+1]) {
				index++
				if dryRunValueExecutes(words[index]) {
					continue
				}
			}
			return true
		}
		if allowDryRun {
			option, value, ok := strings.Cut(word, "=")
			if !ok || option != "--dry-run" {
				continue
			}
			if dryRunValueExecutes(value) {
				continue
			}
			return true
		}
	}
	return false
}

func isExplicitDryRunValue(value string) bool {
	switch strings.ToLower(value) {
	case "client", "server", "true", "none", "false", "0":
		return true
	default:
		return false
	}
}

func dryRunValueExecutes(value string) bool {
	switch strings.ToLower(value) {
	case "none", "false", "0":
		return true
	default:
		return false
	}
}

// executableInputs preserves the legacy command/argv path and unwraps only
// structured command arrays or agent JavaScript envelopes.
func executableInputs(arguments map[string]any) []destructiveExecutableInput {
	field := ""
	switch arguments["command"].(type) {
	case []string, []any:
		field = "command"
	}
	// Explicit plain command/cmd keeps its historical precedence.
	if command, _ := firstStringArgument(arguments, "command", "cmd"); command != "" && field == "" && !strings.Contains(command, "exec_command(") && !strings.Contains(command, "tools.") {
		executable, _ := executableInput(arguments)
		return []destructiveExecutableInput{executable}
	}
	if field == "" {
		for _, key := range []string{"input", "code", "script", "source"} {
			raw, _ := arguments[key].(string)
			if strings.Contains(raw, "exec_command(") || strings.Contains(raw, "tools.") || strings.Contains(raw, "write_stdin(") {
				field = key
				break
			}
		}
	}
	if field == "" {
		if executable, ok := executableInput(arguments); ok {
			return []destructiveExecutableInput{executable}
		}
		return nil
	}
	scripts := filerestrict.ExtractCommandScripts(arguments)
	result := make([]destructiveExecutableInput, 0, len(scripts))
	for _, script := range scripts {
		result = append(result, destructiveExecutableInput{
			Command: script.Text, Field: field, Lexical: script.Interpreter == filerestrict.InterpreterPowerShell,
		})
	}
	return result
}

func executableInput(arguments map[string]any) (destructiveExecutableInput, bool) {
	if value, field := firstStringArgument(arguments, "command", "cmd", "input"); value != "" {
		return destructiveExecutableInput{Command: value, Field: field}, true
	}
	if values, ok := arguments["argv"].([]string); ok && len(values) > 0 {
		return destructiveExecutableInput{Argv: append([]string(nil), values...), Field: "argv"}, true
	}
	if values, ok := arguments["argv"].([]any); ok && len(values) > 0 {
		words := make([]string, 0, len(values))
		for _, value := range values {
			word, ok := value.(string)
			if !ok {
				return destructiveExecutableInput{}, false
			}
			words = append(words, word)
		}
		return destructiveExecutableInput{Argv: words, Field: "argv"}, true
	}
	return destructiveExecutableInput{}, false
}

func firstStringArgument(arguments map[string]any, keys ...string) (string, string) {
	for _, key := range keys {
		if value, ok := arguments[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), key
		}
	}
	return "", ""
}

func stringArgument(arguments map[string]any, keys ...string) string {
	value, _ := firstStringArgument(arguments, keys...)
	return strings.ToLower(value)
}

func isExplicitNonExecuting(input DestructiveInput) bool {
	if isNonExecutingOperation(stringArgument(input.Arguments, "action", "operation", "mode")) {
		return true
	}
	for _, key := range []string{"dry_run", "dry-run", "simulate"} {
		if value, ok := input.Arguments[key].(bool); ok && value {
			return true
		}
	}
	if isStructuredDestructiveAction(stringArgument(input.Arguments, "action", "operation")) {
		return false
	}
	tool := strings.ToLower(input.ToolName)
	isDestructiveTool := destructiveToolActionPattern.MatchString(tool)
	return !isDestructiveTool && nonExecutingToolPattern.MatchString(tool)
}

func isNonExecutingOperation(operation string) bool {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "dry-run", "dry_run", "query", "get", "list", "describe", "status", "simulate", "preview", "plan":
		return true
	default:
		return false
	}
}

func isCommandTool(input DestructiveInput) bool {
	hint := strings.ToLower(input.ToolName + " " + input.ToolType)
	return strings.Contains(hint, "shell") ||
		strings.Contains(hint, "exec") ||
		strings.Contains(hint, "command") ||
		strings.Contains(hint, "terminal") ||
		strings.Contains(hint, "powershell") ||
		strings.TrimSpace(hint) == "cmd"
}

func isPOSIXCommandTool(input DestructiveInput) bool {
	hint := input.ToolName + " " + input.ToolType
	return !hintHasToken(hint, "powershell", "pwsh", "cmd")
}
func isDatabaseTool(input DestructiveInput) bool {
	if strings.EqualFold(strings.TrimSpace(input.ToolType), "database") {
		return true
	}
	return hintHasToken(input.ToolName+" "+input.ToolType, "sql", "database", "db")
}

func canDowngradePath(subcategory string) bool {
	return subcategory == "filesystem_delete" || subcategory == "filesystem_overwrite"
}

func contextualCommandTargets(words []string, subcategory string, input DestructiveInput) []string {
	words = destructiveCommandWords(words)
	if len(words) > 0 {
		words = append([]string{words[0]}, destructiveSubcommandArgs(strings.ToLower(words[0]), words[1:])...)
	}
	switch {
	case subcategory == "vcs_destroy":
		if target, ok := reliableRepositoryTarget(input.WorkingDirectory, input.RepositoryRoot); ok {
			return []string{target}
		}
	case subcategory == "infrastructure_destroy":
		if target, _ := firstStringArgument(input.Arguments, "target", "workspace", "resource_address"); target != "" && !strings.ContainsAny(target, "*?[]\r\n") {
			return []string{target}
		}
		if target, ok := reliableWorkingDirectoryTarget(input.WorkingDirectory, input.RepositoryRoot); ok {
			return []string{target}
		}
	case subcategory == "storage_destroy" && (wordAtEqualFold(words, 0, "docker-compose") || wordAtEqualFold(words, 0, "docker") && wordAtEqualFold(words, 1, "compose")):
		if target, _ := firstStringArgument(input.Arguments, "project", "project_name", "compose_project"); target != "" && !strings.ContainsAny(target, "*?[]\r\n") {
			return []string{target}
		}
		if target, ok := reliableWorkingDirectoryTarget(input.WorkingDirectory, input.RepositoryRoot); ok {
			return []string{target}
		}
	case subcategory == "container_destroy" && wordAtEqualFold(words, 0, "docker") && wordAtEqualFold(words, 1, "system") && wordAtEqualFold(words, 2, "prune"):
		if target, _ := firstStringArgument(input.Arguments, "context", "daemon", "docker_context"); target != "" {
			return []string{target}
		}
	}
	return nil
}

func reliableRepositoryTarget(cwd, repo string) (string, bool) {
	normCWD, cwdStyle, ok := normalizeCrossPlatformPath(cwd)
	if !ok || isRootPath(normCWD) || isHomePath(normCWD) {
		return "", false
	}
	normRepo, repoStyle, ok := normalizeCrossPlatformPath(repo)
	if !ok || repoStyle != cwdStyle || isRootPath(normRepo) || isHomePath(normRepo) || !pathWithin(normRepo, normCWD) {
		return "", false
	}
	return normRepo, true
}

func reliableWorkingDirectoryTarget(cwd, repo string) (string, bool) {
	normCWD, cwdStyle, ok := normalizeCrossPlatformPath(cwd)
	if !ok || isRootPath(normCWD) || isHomePath(normCWD) {
		return "", false
	}
	if strings.TrimSpace(repo) == "" {
		return normCWD, true
	}
	normRepo, repoStyle, ok := normalizeCrossPlatformPath(repo)
	if !ok || repoStyle != cwdStyle || isRootPath(normRepo) || !pathWithin(normRepo, normCWD) {
		return "", false
	}
	return normCWD, true
}

func commandNeedsExplicitTarget(subcategory string) bool {
	return canDowngradePath(subcategory) || subcategory == "block_device_destroy" ||
		subcategory == "storage_destroy" || subcategory == "container_destroy" || subcategory == "cluster_destroy" ||
		subcategory == "vcs_destroy" || subcategory == "infrastructure_destroy"
}

func hasCommandWord(words []string, wanted string) bool {
	for _, word := range words {
		if strings.EqualFold(word, wanted) {
			return true
		}
	}
	return false
}

func gitForcePush(args []string) bool {
	for _, arg := range gitPushOptionWords(args) {
		if arg == "--" {
			break
		}
		option, _ := splitOptionValue(strings.ToLower(arg))
		if shortFlagInCluster(arg, 'f', "fuvqn46", "") || option == "--force" || option == "--force-with-lease" {
			return true
		}
	}
	return false
}

func gitPushOptionWords(args []string) []string {
	var options []string
	for index := 0; index < len(args); index++ {
		word := args[index]
		if word == "--" {
			break
		}
		option, value := splitOptionValue(word)
		switch option {
		case "-o", "--push-option", "--receive-pack", "--exec", "--repo":
			if value == "" {
				index++
			}
			continue
		}
		options = append(options, word)
	}
	return options
}

func composeDownRemovesVolumes(command string, args []string) bool {
	if command == "docker" && wordAtEqualFold(args, 0, "compose") {
		args = args[1:]
	} else if command != "docker-compose" {
		return false
	}
	for index := 0; index < len(args); index++ {
		word := args[index]
		if !strings.HasPrefix(word, "-") {
			if !strings.EqualFold(word, "down") {
				return false
			}
			for _, option := range args[index+1:] {
				if option == "--" {
					break
				}
				if option == "--volumes" || option == "--volumes=true" || shortFlagInCluster(option, 'v', "vt", "t") {
					return true
				}
			}
			return false
		}
		option, value := splitOptionValue(strings.ToLower(word))
		switch option {
		case "-f", "--file", "-p", "--project-name", "--project-directory", "--env-file", "--profile", "--ansi", "--progress", "--parallel":
			if value == "" {
				index++
			}
		}
	}
	return false
}

// Only recognized value-taking global options may consume the next word.
// This keeps an option value named "destroy" from becoming a subcommand.
func destructiveSubcommandArgs(command string, args []string) []string {
	var values string
	switch command {
	case "git":
		values = "-C -c --git-dir --work-tree --namespace --config-env --super-prefix"
	case "docker":
		values = "-H --host -c --context --config --tlscacert --tlscert --tlskey -l --log-level"
	case "helm":
		values = "-n --namespace --kube-context --kubeconfig --kube-apiserver --kube-token --kube-as-user --kube-as-group --burst-limit --qps --registry-config --repository-cache --repository-config"
	case "pulumi":
		values = "-C --cwd -s --stack --color --profiling --tracing"
	case "terraform", "tofu":
		values = "-chdir"
	case "kubectl":
		values = "-n --namespace --context --kubeconfig -s --server --token --user --cluster --request-timeout"
	default:
		return args
	}
	options := strings.Fields(values)
	for index := 0; index < len(args); index++ {
		word := args[index]
		if word == "--" {
			return args[index+1:]
		}
		if !strings.HasPrefix(word, "-") {
			return args[index:]
		}
		option, value := splitOptionValue(word)
		for _, known := range options {
			if option == known && value == "" {
				index++
				break
			}
		}
	}
	return nil
}

func shortFlagInCluster(word string, wanted byte, allowed, takesValue string) bool {
	if len(word) < 2 || word[0] != '-' || word[1] == '-' {
		return false
	}
	found := false
	for index := 1; index < len(word); index++ {
		flag := word[index]
		if !strings.ContainsRune(allowed, rune(flag)) {
			return false
		}
		if flag == wanted {
			found = true
		}
		if strings.ContainsRune(takesValue, rune(flag)) {
			return found
		}
	}
	return found
}

func partedMutates(args []string) bool {
	for _, arg := range args {
		switch strings.ToLower(arg) {
		case "mklabel", "mktable", "mkpart", "rm", "resizepart", "rescue", "name", "set", "toggle":
			return true
		}
	}
	// An invocation without a command enters an interactive disk editor.
	return !hasCommandWord(args, "print") && !hasCommandWord(args, "align-check") && len(args) <= 1
}

func shredTargets(words []string) []string {
	var targets []string
	for index := 0; index < len(words); index++ {
		word := words[index]
		option, value := splitOptionValue(strings.ToLower(word))
		if option == "-n" || option == "--iterations" || option == "-s" || option == "--size" || option == "--random-source" {
			if value == "" {
				index++
			}
			continue
		}
		if word != "" && !strings.HasPrefix(word, "-") {
			targets = append(targets, word)
		}
	}
	return targets
}

func helmUninstallTargets(words []string) []string {
	var targets []string
	for index := 0; index < len(words); index++ {
		word := words[index]
		if !strings.HasPrefix(word, "-") {
			targets = append(targets, word)
			continue
		}
		option, value := splitOptionValue(strings.ToLower(word))
		switch option {
		case "-n", "--namespace", "--kube-context", "--kubeconfig", "--timeout", "--cascade", "--description",
			"--kube-apiserver", "--kube-token", "--kube-as-user", "--kube-as-group", "--kube-ca-file", "--kube-tls-server-name",
			"--burst-limit", "--qps", "--registry-config", "--repository-cache", "--repository-config":
			if value == "" {
				index++
			}
		}
	}
	return targets
}

func wordAtEqualFold(words []string, index int, wanted string) bool {
	return index >= 0 && index < len(words) && strings.EqualFold(words[index], wanted)
}

func findDeleteTargets(words []string) []string {
	findIndex := -1
	for index, word := range words {
		if strings.EqualFold(word, "find") {
			findIndex = index
			break
		}
	}
	if findIndex < 0 {
		return nil
	}
	targets := make([]string, 0, 1)
	for _, word := range words[findIndex+1:] {
		if strings.HasPrefix(word, "-") || word == "!" || word == "(" {
			break
		}
		_, style, ok := normalizeCrossPlatformPath(word)
		if !ok || style != "unix" {
			return nil
		}
		targets = append(targets, word)
	}
	return targets
}

func nonOptionWords(words []string) []string {
	result := make([]string, 0, len(words))
	for _, word := range words {
		if word != "" && !strings.HasPrefix(word, "-") {
			result = append(result, word)
		}
	}
	return result
}

func mkfsTargets(words []string) []string {
	return conservativeStorageTargets(words, map[string]struct{}{
		"-f": {}, "-q": {}, "-v": {}, "--help": {}, "--version": {},
	})
}

func wipefsTargets(words []string) []string {
	return conservativeStorageTargets(words, map[string]struct{}{
		"-a": {}, "--all": {}, "-f": {}, "--force": {}, "-n": {}, "--no-act": {},
		"-q": {}, "--quiet": {}, "-h": {}, "--help": {}, "-v": {}, "--version": {},
	})
}

func conservativeStorageTargets(words []string, noValueOptions map[string]struct{}) []string {
	targets := make([]string, 0, 1)
	for index := 0; index < len(words); index++ {
		word := words[index]
		if strings.HasPrefix(word, "-") {
			option, inlineValue := splitOptionValue(strings.ToLower(word))
			if inlineValue != "" {
				continue
			}
			if _, ok := noValueOptions[option]; ok {
				continue
			}
			if index+1 < len(words) && !strings.HasPrefix(words[index+1], "-") {
				index++
			}
			continue
		}
		normalized, style, ok := normalizeCrossPlatformPath(word)
		if !ok || style != "unix" || isRootPath(normalized) {
			continue
		}
		targets = append(targets, word)
	}
	return targets
}

func windowsFormatTargets(words []string) []string {
	for _, word := range words {
		lower := strings.ToLower(word)
		if windowsDriveSpecPattern.MatchString(word) || strings.HasPrefix(lower, `\\?\volume{`) || strings.HasPrefix(lower, `\?volume{`) {
			return []string{word}
		}
	}
	return nil
}

func truncateTargets(words []string) []string {
	result := make([]string, 0, 1)
	for index := 0; index < len(words); index++ {
		word := words[index]
		lower := strings.ToLower(word)
		switch {
		case lower == "-s" || lower == "--size":
			index++
		case strings.HasPrefix(lower, "--size="):
		case strings.HasPrefix(word, "-"):
		default:
			result = append(result, word)
		}
	}
	return result
}

// powershellFileTargets 取 -Path、-LiteralPath 的值，或第一个位置参数（Remove-Item 的第二个位置参数是 -Filter，
// Set-Content 的是 -Value，都不是目标）；a, b 这样的数组一并取。(…)、$(…) 子表达式整体跳过，里面的词不当目标。
func powershellFileTargets(words []string) []string {
	targetOptions := map[string]struct{}{
		"-path": {}, "-literalpath": {}, "-inputobject": {},
	}
	booleanOptions := map[string]struct{}{
		"-recurse": {}, "-force": {}, "-whatif": {}, "-confirm": {},
		"-verbose": {}, "-debug": {}, "-nonewline": {}, "-passthru": {}, "-asbytestream": {},
	}
	targets := make([]string, 0, 1)
	positionalTaken := false
	optionsTerminated := false
	takeArray := func(index int) int {
		targets = append(targets, words[index])
		for strings.HasSuffix(words[index], ",") && index+1 < len(words) {
			index++
			targets = append(targets, words[index])
		}
		return index
	}
	for index := 0; index < len(words); index++ {
		word := words[index]
		if end, ok := powershellGroupEnd(words, index); ok {
			index = end
			continue
		}
		if word == "--" {
			optionsTerminated = true
			continue
		}
		if optionsTerminated || !strings.HasPrefix(word, "-") {
			if !positionalTaken {
				index = takeArray(index)
				positionalTaken = true
			}
			continue
		}
		option, inlineValue := splitOptionValue(strings.ToLower(word))
		if _, ok := booleanOptions[option]; ok {
			continue
		}
		if inlineValue != "" || index+1 >= len(words) || strings.HasPrefix(words[index+1], "-") {
			if _, ok := targetOptions[option]; ok && inlineValue != "" {
				targets = append(targets, inlineValue)
			}
			continue
		}
		if end, ok := powershellGroupEnd(words, index+1); ok {
			index = end
			continue
		}
		if _, ok := targetOptions[option]; ok {
			index = takeArray(index + 1)
			continue
		}
		index++ // 其它选项的值
	}
	return targets
}

func powershellStorageTargets(command string, words []string) []string {
	targetOptions := map[string]struct{}{
		"-path": {}, "-literalpath": {}, "-inputobject": {},
	}
	switch strings.ToLower(command) {
	case "format-volume":
		targetOptions["-driveletter"] = struct{}{}
		targetOptions["-objectid"] = struct{}{}
	case "clear-disk":
		targetOptions["-number"] = struct{}{}
		targetOptions["-disknumber"] = struct{}{}
		targetOptions["-uniqueid"] = struct{}{}
	case "remove-partition":
		targetOptions["-driveletter"] = struct{}{}
		targetOptions["-disknumber"] = struct{}{}
		targetOptions["-partitionnumber"] = struct{}{}
		targetOptions["-accesspath"] = struct{}{}
	}

	booleanOptions := map[string]struct{}{
		"-force": {}, "-confirm": {}, "-whatif": {}, "-full": {}, "-compress": {},
		"-removedata": {}, "-removeoem": {}, "-passthru": {}, "-asjob": {}, "-verbose": {}, "-debug": {},
	}
	targets := make([]string, 0, 2)
	for index := 0; index < len(words); index++ {
		word := words[index]
		if !strings.HasPrefix(word, "-") {
			targets = append(targets, word)
			continue
		}
		option, inlineValue := splitOptionValue(strings.ToLower(word))
		if _, ok := targetOptions[option]; ok {
			if inlineValue != "" {
				targets = append(targets, inlineValue)
			} else if index+1 < len(words) && !strings.HasPrefix(words[index+1], "-") {
				index++
				targets = append(targets, words[index])
			}
			continue
		}
		if _, ok := booleanOptions[option]; ok {
			continue
		}
		if inlineValue == "" && index+1 < len(words) && !strings.HasPrefix(words[index+1], "-") {
			index++
		}
	}
	return targets
}

func splitOptionValue(option string) (string, string) {
	for _, separator := range []string{"=", ":"} {
		if index := strings.Index(option, separator); index > 0 {
			return option[:index], option[index+1:]
		}
	}
	return option, ""
}

func kubectlDeleteTargets(words []string) []string {
	optionsWithValues := map[string]struct{}{
		"-n": {}, "--namespace": {}, "--context": {}, "-l": {}, "--selector": {},
		"--grace-period": {}, "--timeout": {}, "--token": {}, "--kubeconfig": {}, "-s": {}, "--server": {},
		"--user": {}, "--cluster": {}, "--as": {}, "--as-group": {}, "--as-uid": {}, "--request-timeout": {},
		"-o": {}, "--output": {}, "--field-selector": {}, "--cache-dir": {}, "--certificate-authority": {},
		"--client-certificate": {}, "--client-key": {}, "--tls-server-name": {}, "--username": {}, "--password": {},
	}
	operands := make([]string, 0, 2)
	manifests := make([]string, 0, 1)
	all := false
	for index := 0; index < len(words); index++ {
		word := words[index]
		if !strings.HasPrefix(word, "-") {
			operands = append(operands, word)
			continue
		}
		optionRaw, inlineValue := splitOptionValue(word)
		option := strings.ToLower(optionRaw)
		switch option {
		case "-f", "--filename":
			if inlineValue != "" {
				manifests = append(manifests, inlineValue)
			} else if index+1 < len(words) && !strings.HasPrefix(words[index+1], "-") {
				index++
				manifests = append(manifests, words[index])
			}
		case "--all":
			all = true
		default:
			if _, ok := optionsWithValues[option]; ok && inlineValue == "" && index+1 < len(words) {
				index++
			}
		}
	}
	if len(manifests) > 0 {
		return manifests
	}
	if len(operands) >= 2 {
		return operands[1:]
	}
	if len(operands) == 1 && all {
		return operands
	}
	return nil
}

func windowsCommandTargets(words []string) []string {
	result := make([]string, 0, len(words))
	for _, word := range words {
		lower := strings.ToLower(word)
		if lower == "/s" || lower == "/q" || lower == "/f" {
			continue
		}
		result = append(result, word)
	}
	return result
}

func wordsAfter(words []string, count int) []string {
	if len(words) <= count {
		return nil
	}
	return nonOptionWords(words[count:])
}

type structuredTargetResult struct {
	Targets   []string
	Malformed bool
	Conflict  bool
	Exceeded  bool
}

func structuredTargets(arguments map[string]any) structuredTargetResult {
	return structuredTargetsWithObserver(arguments, nil)
}

func structuredTargetsWithObserver(arguments map[string]any, observe func(any)) structuredTargetResult {
	result := structuredTargetResult{Targets: make([]string, 0, 2)}
	seen := make(map[string]struct{}, 2)
	appendTarget := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			result.Malformed = true
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		if len(result.Targets) >= maxDestructiveTargets {
			result.Exceeded = true
			return
		}
		seen[value] = struct{}{}
		result.Targets = append(result.Targets, value)
	}
	for _, key := range []string{"path", "target", "resource_id", "resource", "id", "volume_id", "snapshot_id", "disk_id", "partition_id", "repository_id", "source_id"} {
		raw, exists := arguments[key]
		if !exists {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			result.Malformed = true
			continue
		}
		appendTarget(value)
	}

	pluralInspected := 0
	inspectPlural := func(value any) bool {
		if pluralInspected >= maxDestructiveTargets+1 {
			result.Exceeded = true
			return false
		}
		pluralInspected++
		if observe != nil {
			observe(value)
		}
		if pluralInspected > maxDestructiveTargets {
			result.Exceeded = true
		}
		return true
	}

pluralFields:
	for _, key := range []string{"paths", "file_paths", "targets", "ids", "resource_ids"} {
		raw, exists := arguments[key]
		if !exists {
			continue
		}
		switch values := raw.(type) {
		case []string:
			if len(values) == 0 {
				result.Malformed = true
			}
			for _, value := range values {
				if !inspectPlural(value) {
					break pluralFields
				}
				appendTarget(value)
				if pluralInspected > maxDestructiveTargets {
					break pluralFields
				}
			}
		case []any:
			if len(values) == 0 {
				result.Malformed = true
			}
			for _, rawValue := range values {
				if !inspectPlural(rawValue) {
					break pluralFields
				}
				value, ok := rawValue.(string)
				if !ok {
					result.Malformed = true
				} else {
					appendTarget(value)
				}
				if pluralInspected > maxDestructiveTargets {
					break pluralFields
				}
			}
		default:
			result.Malformed = true
		}
	}
	result.Conflict = result.Malformed && len(result.Targets) > 0
	return result
}

func executableCommandSegments(input DestructiveInput, executable destructiveExecutableInput) ([]destructiveCommandSegment, bool) {
	argv := executable.Argv
	argvReliable := true
	if argv != nil {
		argv, argvReliable = boundedDestructiveArgv(argv)
	}
	if isPOSIXCommandTool(input) && !executable.Lexical {
		if argv != nil {
			segments, reliable := parsePOSIXArgv(argv)
			return segments, argvReliable && reliable
		}
		return parsePOSIXCommand(executable.Command)
	}
	var segments []destructiveCommandSegment
	reliable := true
	if argv != nil {
		segments, reliable = []destructiveCommandSegment{argvCommandSegment(argv)}, argvReliable
	} else {
		segments, reliable = parseShellCommand(executable.Command)
	}
	for index := range segments {
		segments[index].EvidenceLexical = true
	}
	return segments, reliable
}

func boundedDestructiveArgv(argv []string) ([]string, bool) {
	result := make([]string, 0, min(len(argv), maxDestructiveSyntaxNodes))
	remaining := maxDestructiveCommandBytes
	reliable := true
	for index, word := range argv {
		if index >= maxDestructiveSyntaxNodes {
			reliable = false
			break
		}
		if len(word) > remaining {
			if remaining > 0 {
				result = append(result, word[:remaining])
			}
			reliable = false
			break
		}
		result = append(result, word)
		remaining -= len(word)
	}
	return result, reliable
}

func unreliableCommandAnalysis(executable destructiveExecutableInput) DestructiveAnalysis {
	raw := executableRaw(executable)
	result := DestructiveAnalysis{
		Confidence:      "medium",
		Reason:          "command_parse_incomplete",
		SuggestedAction: DecisionAudit,
		ParseRejected:   true,
		SignalText:      raw,
	}
	if raw != "" {
		result.Evidence = []Evidence{
			sanitizedEvidence("agent_destructive_command_parse_incomplete", destructiveCategory, executable.Field, raw),
		}
	}
	return result
}

func markDestructiveParseRejected(result *DestructiveAnalysis, raw, field string) {
	result.ParseRejected = true
	if raw != "" {
		result.Evidence = append(result.Evidence,
			sanitizedEvidence("agent_destructive_command_parse_rejected", destructiveCategory, field, raw))
	}
}

// isKnownFrameworkDiscardableTarget is the conservative fallback for known
// coding agents whose tool protocol omitted cwd/repository_root. Only relative
// paths inside an explicitly discardable development directory qualify; an
// absolute path, traversal, wildcard, .git, or any non-discardable target stays
// high risk because the gateway cannot prove the workspace boundary.
func isKnownFrameworkDiscardableTarget(cwd, repo, target string, configured []string) (bool, string) {
	if strings.TrimSpace(cwd) != "" || strings.TrimSpace(repo) != "" {
		return false, ""
	}
	normalized := strings.TrimSpace(strings.ReplaceAll(target, "\\", "/"))
	if normalized == "" || containsUnsafePathSyntax(normalized) ||
		strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "~") ||
		windowsAbsolutePattern.MatchString(target) || strings.Contains(normalized, ":") {
		return false, ""
	}
	if hasPathSegment(normalized, ".git") || isHomePath(normalized) {
		return false, ""
	}
	allowed := []string{"node_modules", "dist", "build", ".cache", "tmp", "test-output"}
	for _, candidate := range configured {
		candidate = strings.TrimSpace(strings.ReplaceAll(candidate, "\\", "/"))
		if candidate != "" && !strings.Contains(candidate, "/") && candidate != "." && candidate != ".." && !strings.ContainsAny(candidate, "*?[]") {
			allowed = append(allowed, candidate)
		}
	}
	for _, segment := range allowed {
		if hasPathSegment(normalized, segment) {
			return true, "known_framework_agent_discardable_relative_path"
		}
	}
	return false, ""
}

func pathUnder(value string, roots ...string) bool {
	for _, root := range roots {
		if value == root || strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}

func destructiveRiskRank(level string) int {
	switch level {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

// preferDestructiveFinding 判断 candidate 是否应取代 current：优先级更高者胜，
// 同优先级取风险等级更高者，避免中危重定向压低同级的高危 truncate。
func preferDestructiveFinding(candidate, current DestructiveAnalysis) bool {
	candidatePriority := destructiveRiskPriority(candidate.Subcategory)
	currentPriority := destructiveRiskPriority(current.Subcategory)
	if candidatePriority != currentPriority {
		return candidatePriority > currentPriority
	}
	return destructiveRiskRank(candidate.RiskLevel) > destructiveRiskRank(current.RiskLevel)
}

// sensitiveLiteralFragment 判断动态目标里的字面片段是否指向敏感路径，与静态目标共用同一张敏感表。
func sensitiveLiteralFragment(fragment string) bool {
	return classifyWriteTarget(fragment, true).Level != ""
}

// preferMergedAnalysis 判断多个 executable 的合并结果里 analysis 是否应取代 merged：
// 先看有无结果和可丢弃目录，再按子类优先级、置信度，最后同级取风险等级更高者。
func preferMergedAnalysis(analysis, merged DestructiveAnalysis) bool {
	if merged.Reason == "" {
		return true
	}
	if analysis.Category == "" {
		return merged.Category == "" && analysis.ParseRejected
	}
	if merged.Category == "" {
		return true
	}
	if merged.DiscardablePathMatched && !analysis.DiscardablePathMatched {
		return true
	}
	candidatePriority := destructiveRiskPriority(analysis.Subcategory)
	currentPriority := destructiveRiskPriority(merged.Subcategory)
	if !analysis.DiscardablePathMatched && candidatePriority > currentPriority {
		return true
	}
	if candidatePriority != currentPriority {
		return merged.Category == "" && analysis.ParseRejected
	}
	if analysis.HighConfidence != merged.HighConfidence {
		return analysis.HighConfidence
	}
	return destructiveRiskRank(analysis.RiskLevel) > destructiveRiskRank(merged.RiskLevel)
}
