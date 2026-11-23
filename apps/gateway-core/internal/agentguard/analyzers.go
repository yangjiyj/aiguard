package agentguard

import (
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	reasonSensitiveDataOut        = "sensitive_personal_data_egress"
	reasonShellComposition        = "shell_composition_observed"
	reasonShellInterpolation      = "shell_interpolation_requires_confirm"
	reasonShellInterpreter        = "shell_interpreter_observed"
	reasonDestructiveCommand      = "destructive_command_requires_confirm"
	reasonCommandAllowed          = "command_allowlisted"
	reasonCommandNotAllowlisted   = "command_not_allowlisted"
	reasonSQLReadOnly             = "readonly_sql"
	reasonDestructiveSQL          = "blocked_destructive_sql"
	reasonScopedMutationSQL       = "scoped_mutation_requires_confirm"
	reasonUnknownSQL              = "unknown_sql_requires_audit"
	reasonHighConfidenceSecretOut = "high_confidence_secret_egress"
	reasonNoSecretEgress          = "no_high_confidence_secret_egress"
)

var highConfidenceSecretPatterns = []secretPattern{
	{kind: "aws_access_key_id", category: "secret", pattern: regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), action: DecisionBlock, riskLevel: "critical", confidence: 0.9},
	{kind: "private_key", category: "secret", pattern: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), action: DecisionBlock, riskLevel: "critical", confidence: 0.95},
	{kind: "github_token", category: "secret", pattern: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`), action: DecisionBlock, riskLevel: "critical", confidence: 0.9},
	{kind: "openai_api_key", category: "secret", pattern: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{32,}\b`), action: DecisionBlock, riskLevel: "critical", confidence: 0.9},
	{kind: "canary_token", category: "secret", pattern: regexp.MustCompile(`\bcanary-[A-Za-z0-9_-]*(?:token|secret|credential)[A-Za-z0-9_-]*\b`), action: DecisionBlock, riskLevel: "critical", confidence: 0.9},
	{kind: "high_entropy_token", category: "secret", pattern: regexp.MustCompile(`\b[A-Za-z0-9+/=_-]{48,}\b`), action: DecisionBlock, riskLevel: "critical", confidence: 0.8},
	{kind: "cn_id_card", category: "pii", pattern: regexp.MustCompile(`\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b`), action: DecisionConfirm, riskLevel: "high", confidence: 0.8},
	{kind: "cn_phone", category: "pii", pattern: regexp.MustCompile(`\b1[3-9]\d{9}\b`), action: DecisionConfirm, riskLevel: "high", confidence: 0.75},
	{kind: "email", category: "pii", pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), action: DecisionConfirm, riskLevel: "medium", confidence: 0.7},
}

var destructiveCommandPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:^|[;&|]\s*)rm\s+(?:-[a-z]*r[a-z]*\s+)+/(?:\s|$|\*)`),
	regexp.MustCompile(`(?i)(?:^|[;&|]\s*)(?:mkfs(?:\.[a-z0-9]+)?|shutdown|reboot)(?:\s|$)`),
	regexp.MustCompile(`(?i)(?:^|[;&|]\s*)dd\s+[^;&|]*\bof=/dev/`),
}

type CommandInvocation struct {
	Command    string
	Executable string
	Args       []string
	Allowlist  []CommandAllowRule
}

type CommandAllowRule struct {
	Executable string   `json:"executable"`
	ArgsPrefix []string `json:"args_prefix"`
}

type SecretFinding struct {
	Kind       string         `json:"kind"`
	Category   string         `json:"category"`
	Action     DecisionAction `json:"action"`
	RiskLevel  string         `json:"risk_level"`
	Confidence float64        `json:"confidence"`
	Evidence   Evidence       `json:"evidence"`
}

type DataEgressInput struct {
	Target         string
	Body           string
	AllowedDomains []string
}

type secretPattern struct {
	kind       string
	category   string
	pattern    *regexp.Regexp
	action     DecisionAction
	riskLevel  string
	confidence float64
}

// AnalyzeCommand enforces no-shell command semantics and exact argv allowlist matching.
func AnalyzeCommand(invocation CommandInvocation) Decision {
	executable, args := normalizeInvocation(invocation)
	rawCommand := commandEvidenceValue(invocation, executable, args)

	// 破坏性命令先判：rm -rf "$(pwd)" 这类要按破坏性给出依据，不被命令替换的依据盖住。
	if isDestructiveCommand(rawCommand) {
		return Decision{
			RawDecision: DecisionConfirm,
			Reason:      reasonDestructiveCommand,
			RiskLevel:   "high",
			Confidence:  0.9,
			Evidence:    []Evidence{sanitizedEvidence("command_destructive", "command", "command", rawCommand)},
		}
	}

	if hasSuspiciousShellInterpolation(rawCommand) || anyHasSuspiciousShellInterpolation(args) {
		// 编程智能体的 Bash 里 d=$(mktemp -d)、"${PIPESTATUS[0]}" 极常见，本身不是风险（客户A 11-21：
		// 3 天 241 条普通命令被标高危）。决策仍是需确认（执行模式下行为不变），风险级别只在替换里
		// 有下载/解码/动态执行时才算高。
		risk, confidence := "low", 0.6
		if hasRemoteOrDynamicExecution(rawCommand) || anyHasRemoteOrDynamicExecution(args) {
			risk, confidence = "high", 0.8
		}
		return Decision{
			RawDecision: DecisionConfirm,
			Reason:      reasonShellInterpolation,
			RiskLevel:   risk,
			Confidence:  confidence,
			Evidence:    []Evidence{sanitizedEvidence("command_shell_interpolation", "command", "command", rawCommand)},
		}
	}

	if hasShellComposition(rawCommand) || anyHasShellComposition(args) {
		return Decision{
			RawDecision: DecisionAudit,
			Reason:      reasonShellComposition,
			RiskLevel:   "low",
			Confidence:  0.55,
			Evidence:    []Evidence{sanitizedEvidence("command_shell_composition", "command", "command", rawCommand)},
		}
	}

	if isShellInterpreter(executable) && hasShellCommandFlag(args) {
		return Decision{
			RawDecision: DecisionAudit,
			Reason:      reasonShellInterpreter,
			RiskLevel:   "low",
			Confidence:  0.6,
			Evidence:    []Evidence{sanitizedEvidence("command_shell_interpreter", "command", "command", rawCommand)},
		}
	}

	if matchesCommandAllowlist(executable, args, invocation.Allowlist) {
		return Decision{RawDecision: DecisionAllow, Reason: reasonCommandAllowed, RiskLevel: "low", Confidence: 0.9}
	}

	return Decision{
		RawDecision: DecisionConfirm,
		Reason:      reasonCommandNotAllowlisted,
		RiskLevel:   "high",
		Confidence:  0.75,
		Evidence:    []Evidence{sanitizedEvidence("command_not_allowlisted", "command", "command", rawCommand)},
	}
}

// AnalyzeSQL provides lightweight statement classification without relying on brittle regex matching.
func AnalyzeSQL(statement string) Decision {
	analysis := analyzeDestructiveSQL(statement, "statement", destructiveSQLGeneric)
	if analysis.Category != "" {
		d := destructiveSQLDecision(statement)
		d.RiskLevel = analysis.RiskLevel
		if d.RiskLevel == "" {
			d.RiskLevel = "high"
		}
		return d
	}
	if analysis.ParseRejected {
		return Decision{RawDecision: DecisionAudit, Reason: reasonUnknownSQL, RiskLevel: "medium", Confidence: 0.5, Evidence: []Evidence{sanitizedEvidence("sql_parse_incomplete", "sql", "statement", statement)}}
	}
	cleaned, closed, ambiguous := sanitizeDestructiveSQL(statement, destructiveSQLGeneric)
	tokens, exceeded := boundedDestructiveSQLTokens(cleaned, maxDestructiveSyntaxNodes)
	if len(tokens) == 0 {
		return Decision{RawDecision: DecisionAudit, Reason: reasonUnknownSQL, RiskLevel: "low", Confidence: 0.5}
	}
	var parts [][]string
	valid := true
	start := 0
	for i := 0; i <= len(tokens); i++ {
		if i == len(tokens) || tokens[i] == ";" {
			items, ok := executableSQLParts(tokens[start:i], 0)
			valid = valid && ok
			parts = append(parts, items...)
			start = i + 1
		}
	}
	if !closed || ambiguous || exceeded || !valid || analysis.ParseRejected {
		return Decision{RawDecision: DecisionAudit, Reason: reasonUnknownSQL, RiskLevel: "medium", Confidence: 0.5, Evidence: []Evidence{sanitizedEvidence("sql_parse_incomplete", "sql", "statement", statement)}}
	}
	mutation, unknown := false, false
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		switch part[0] {
		case "SELECT", "SHOW", "DESCRIBE":
			// No mutation in this executable statement.
		case "INSERT", "UPSERT", "MERGE", "CREATE", "ALTER", "DELETE", "UPDATE":
			mutation = true
		default:
			unknown = true
		}
	}
	if mutation {
		return Decision{RawDecision: DecisionConfirm, Reason: reasonScopedMutationSQL, RiskLevel: "high", Confidence: 0.8, Evidence: []Evidence{sanitizedEvidence("sql_mutation", "sql", "statement", statement)}}
	}
	if unknown {
		return Decision{RawDecision: DecisionAudit, Reason: reasonUnknownSQL, RiskLevel: "medium", Confidence: 0.55}
	}
	return Decision{RawDecision: DecisionAllow, Reason: reasonSQLReadOnly, RiskLevel: "low", Confidence: 0.85}
}

func destructiveSQLDecision(statement string) Decision {
	return Decision{
		RawDecision: DecisionBlock,
		Reason:      reasonDestructiveSQL,
		RiskLevel:   "critical",
		Confidence:  0.9,
		Evidence:    []Evidence{sanitizedEvidence("sql_destructive", "sql", "statement", statement)},
	}
}

// DetectHighConfidenceSecrets covers narrow high-confidence secrets plus PII signals that require confirmation.
func DetectHighConfidenceSecrets(text string) []SecretFinding {
	var findings []SecretFinding
	seen := map[string]struct{}{}
	for _, candidate := range highConfidenceSecretPatterns {
		matches := candidate.pattern.FindAllString(text, -1)
		for _, match := range matches {
			if !keepSecretCandidate(candidate, match) {
				continue
			}
			key := candidate.kind + ":" + match
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, SecretFinding{
				Kind:       candidate.kind,
				Category:   candidate.category,
				Action:     candidate.action,
				RiskLevel:  candidate.riskLevel,
				Confidence: candidate.confidence,
				Evidence:   sanitizedEvidence(candidate.category+"_high_confidence", candidate.category, candidate.kind, match),
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Kind < findings[j].Kind })
	return findings
}

func keepSecretCandidate(candidate secretPattern, value string) bool {
	if candidate.kind != "high_entropy_token" {
		return true
	}
	return looksHighEntropyToken(value)
}

func looksHighEntropyToken(value string) bool {
	if len(value) < 48 {
		return false
	}
	classes := 0
	if strings.IndexFunc(value, unicode.IsLower) >= 0 {
		classes++
	}
	if strings.IndexFunc(value, unicode.IsUpper) >= 0 {
		classes++
	}
	if strings.IndexFunc(value, unicode.IsDigit) >= 0 {
		classes++
	}
	if strings.IndexFunc(value, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) >= 0 {
		classes++
	}
	return classes >= 2 && shannonEntropy(value) >= 4.0
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range value {
		counts[r]++
	}
	length := float64(len([]rune(value)))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// AnalyzeDataEgress records high-confidence secrets (protection item
// agent.secret_egress) and PII sent outside the domain allowlist.
func AnalyzeDataEgress(input DataEgressInput) Decision {
	target := AnalyzeTarget(input.Target)
	if target.Hit {
		return targetFinding(target, input.Target, "critical", 0.95, target.Evidence)
	}

	findings := DetectHighConfidenceSecrets(input.Body)
	if len(findings) == 0 || targetDomainAllowed(input.Target, input.AllowedDomains) {
		return Decision{
			RawDecision:      DecisionAllow,
			Reason:           reasonNoSecretEgress,
			RiskLevel:        "low",
			Confidence:       0.85,
			NormalizedTarget: target.NormalizedTarget,
		}
	}

	evidence := make([]Evidence, 0, len(findings))
	secret := false
	riskLevel := "high"
	confidence := 0.75
	for _, finding := range findings {
		evidence = append(evidence, finding.Evidence)
		if finding.Action == DecisionBlock {
			secret = true
			riskLevel = finding.RiskLevel
			confidence = finding.Confidence
		}
	}
	if secret {
		// 高可信密钥外发是防护项 agent.secret_egress 的命中，动作由租户配置决定。
		return protectionFindingWithConfidence(reasonHighConfidenceSecretOut, target.NormalizedTarget, riskLevel, confidence, evidence)
	}
	return Decision{
		RawDecision:      DecisionConfirm,
		Reason:           reasonSensitiveDataOut,
		RiskLevel:        riskLevel,
		Confidence:       confidence,
		Evidence:         evidence,
		NormalizedTarget: target.NormalizedTarget,
	}
}

func normalizeInvocation(invocation CommandInvocation) (string, []string) {
	executable := strings.TrimSpace(invocation.Executable)
	args := append([]string(nil), invocation.Args...)
	if executable != "" {
		return normalizeExecutable(executable), args
	}

	parts := strings.Fields(invocation.Command)
	if len(parts) == 0 {
		return "", nil
	}
	return normalizeExecutable(parts[0]), parts[1:]
}

func commandEvidenceValue(invocation CommandInvocation, executable string, args []string) string {
	if strings.TrimSpace(invocation.Command) != "" {
		return strings.TrimSpace(invocation.Command)
	}
	return strings.TrimSpace(strings.Join(append([]string{executable}, args...), " "))
}

func normalizeExecutable(executable string) string {
	base := filepath.Base(strings.TrimSpace(executable))
	return strings.ToLower(base)
}

func isDestructiveCommand(value string) bool {
	for _, pattern := range destructiveCommandPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func hasSuspiciousShellInterpolation(value string) bool {
	markers := []string{"`", "$(", "${", "$IFS"}
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

var remoteOrDynamicExecutionPattern = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_.-])(?:curl|wget|nc|ncat|socat|base64|xxd|eval|iex|invoke-expression|invoke-webrequest|iwr|irm)(?:$|[^A-Za-z0-9_-])|/dev/tcp/`)

// hasRemoteOrDynamicExecution：命令里有下载、反连、解码或动态执行（curl/wget/nc/base64/eval…），
// 与命令替换同现时才把替换当高风险。
func hasRemoteOrDynamicExecution(value string) bool {
	return remoteOrDynamicExecutionPattern.MatchString(value)
}

func anyHasRemoteOrDynamicExecution(values []string) bool {
	for _, value := range values {
		if hasRemoteOrDynamicExecution(value) {
			return true
		}
	}
	return false
}

func anyHasSuspiciousShellInterpolation(values []string) bool {
	for _, value := range values {
		if hasSuspiciousShellInterpolation(value) {
			return true
		}
	}
	return false
}

func hasShellComposition(value string) bool {
	shellMarkers := []string{";", "&&", "||", "|", ">", "<", "\n", "\r"}
	for _, marker := range shellMarkers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func anyHasShellComposition(values []string) bool {
	for _, value := range values {
		if hasShellComposition(value) {
			return true
		}
	}
	return false
}

func isShellInterpreter(executable string) bool {
	switch normalizeExecutable(executable) {
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	default:
		return false
	}
}

func hasShellCommandFlag(args []string) bool {
	for _, arg := range args {
		switch strings.ToLower(arg) {
		case "-c", "/c", "-command", "-encodedcommand":
			return true
		}
	}
	return false
}

func matchesCommandAllowlist(executable string, args []string, rules []CommandAllowRule) bool {
	normalizedExecutable := normalizeExecutable(executable)
	for _, rule := range rules {
		if normalizeExecutable(rule.Executable) != normalizedExecutable {
			continue
		}
		if len(args) < len(rule.ArgsPrefix) {
			continue
		}
		matched := true
		for i, expected := range rule.ArgsPrefix {
			if args[i] != expected {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func sqlTokens(statement string) []string {
	cleaned := stripSQLCommentsAndStrings(statement)
	var tokens []string
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, strings.ToUpper(current.String()))
		current.Reset()
	}
	for _, r := range cleaned {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			current.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func stripSQLCommentsAndStrings(statement string) string {
	var out strings.Builder
	for i := 0; i < len(statement); i++ {
		ch := statement[i]
		if ch == '-' && i+1 < len(statement) && statement[i+1] == '-' {
			for i < len(statement) && statement[i] != '\n' {
				out.WriteByte(' ')
				i++
			}
			if i < len(statement) {
				out.WriteByte(statement[i])
			}
			continue
		}
		if ch == '/' && i+1 < len(statement) && statement[i+1] == '*' {
			out.WriteString("  ")
			i += 2
			for i < len(statement) {
				if statement[i] == '*' && i+1 < len(statement) && statement[i+1] == '/' {
					out.WriteString("  ")
					i++
					break
				}
				out.WriteByte(' ')
				i++
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote := ch
			out.WriteByte(' ')
			for i+1 < len(statement) {
				i++
				out.WriteByte(' ')
				if statement[i] == quote {
					if i+1 < len(statement) && statement[i+1] == quote {
						i++
						out.WriteByte(' ')
						continue
					}
					break
				}
			}
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

func containsSQLToken(tokens []string, needle string) bool {
	for _, token := range tokens {
		if token == needle {
			return true
		}
	}
	return false
}

func targetDomainAllowed(target string, allowedDomains []string) bool {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	for _, domain := range allowedDomains {
		normalizedDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if normalizedDomain == "" {
			continue
		}
		if host == normalizedDomain || strings.HasSuffix(host, "."+normalizedDomain) {
			return true
		}
	}
	return false
}
