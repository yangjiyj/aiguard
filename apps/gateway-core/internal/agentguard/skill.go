package agentguard

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentguardmatch"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

const (
	ToolTypeSkill    = "skill"
	ToolTypeFile     = "file"
	ToolTypeNetwork  = "network"
	ToolTypeDatabase = "database"
	ToolTypeMCP      = "mcp"
	ToolTypeSystem   = "system"
	ToolTypeUnknown  = "unknown"
)

const (
	reasonSkillVersionQuarantined = "skill_version_quarantined"
	reasonSkillVersionRevoked     = "skill_version_revoked"
	reasonSkillDangerousCommand   = "skill_dangerous_command"
	reasonSkillAdmissionUnavail   = protection.ReasonSkillAdmissionUnavailable
)

type SkillAdmissionStatus string

const (
	SkillAdmissionUnknown     SkillAdmissionStatus = "unknown"
	SkillAdmissionUnverified  SkillAdmissionStatus = "unverified"
	SkillAdmissionApproved    SkillAdmissionStatus = "approved"
	SkillAdmissionQuarantined SkillAdmissionStatus = "quarantined"
	SkillAdmissionRevoked     SkillAdmissionStatus = "revoked"
	// SkillAdmissionUnavailable 表示准入查询本身失败（控制面不可用）且处于 fail-closed。
	// 与"查询成功但版本未验证"不同：后者只记录，前者是防护项 skill.admission_unavailable 的命中。
	SkillAdmissionUnavailable SkillAdmissionStatus = "unavailable"
)

type SkillIdentity struct {
	CanonicalName string
	Version       string
	BundleHash    string
	Source        string
	Issue         string
}

func (i SkillIdentity) Complete() bool {
	return i.CanonicalName != "" && i.Version != "" && validSkillBundleHash(i.BundleHash)
}

func ClassifyToolType(name string) string {
	return agentguardmatch.ClassifyToolType(name)
}

func containsAny(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func ExtractSkillIdentity(args map[string]any) SkillIdentity {
	identity := SkillIdentity{}
	rawSkill, hasSkill := args["skill"]
	nestedSkillKeys := countNestedSkillKeys(args)
	if !hasSkill {
		if nestedSkillKeys > 0 {
			identity.Issue = "skill_identity_misplaced"
		}
		return identity
	}
	skillName, ok := rawSkill.(string)
	if !ok {
		identity.Issue = "skill_identity_invalid"
		return identity
	}
	identity.CanonicalName = CanonicalSkillName(skillName)
	if identity.CanonicalName == "" {
		identity.Issue = "skill_identity_invalid"
		return identity
	}
	if nestedSkillKeys > 0 {
		identity.Issue = "skill_identity_conflict"
		return identity
	}
	if value, exists := args["version"]; exists {
		text, valid := value.(string)
		if !valid || strings.TrimSpace(text) == "" {
			identity.Issue = "skill_identity_invalid"
			return identity
		}
		identity.Version = boundedSkillValue(text, 255)
	}
	if value, exists := args["bundle_hash"]; exists {
		text, valid := value.(string)
		text = strings.ToLower(strings.TrimSpace(text))
		if !valid || !validSkillBundleHash(text) {
			identity.Issue = "skill_identity_invalid"
			return identity
		}
		identity.BundleHash = text
	}
	if value, exists := args["source"]; exists {
		text, valid := value.(string)
		if !valid || (strings.TrimSpace(text) != "" && sanitizeDeclaredSkillSource(text) == "") {
			identity.Issue = "skill_identity_invalid"
			return identity
		}
		identity.Source = sanitizeDeclaredSkillSource(text)
	}
	for _, alias := range []string{"skill_name", "canonical_name", "skill_version", "declared_version", "tree_hash", "skill_hash"} {
		if _, exists := args[alias]; exists {
			identity.Issue = "skill_identity_conflict"
			return identity
		}
	}
	return identity
}

func countNestedSkillKeys(args map[string]any) int {
	count, nodes := 0, 0
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 8 || nodes >= 2048 {
			return
		}
		nodes++
		switch typed := value.(type) {
		case map[string]any:
			for key, item := range typed {
				normalized := normalizeSkillKey(key)
				if normalized == "skill" ||
					normalized == "skill_name" ||
					normalized == "canonical_name" {
					count++
				}
				walk(item, depth+1)
			}
		case []any:
			for _, item := range typed {
				walk(item, depth+1)
			}
		}
	}
	for key, value := range args {
		if key != "skill" {
			walk(value, 1)
		}
	}
	return count
}

func normalizeSkillKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func CanonicalSkillName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var out []rune
	dash := false
	for _, char := range value {
		switch {
		case unicode.IsLetter(char) || unicode.IsDigit(char):
			out = append(out, char)
			dash = false
		case char == '.' || char == '/' || char == '@' || char == '+':
			out = append(out, char)
			dash = false
		default:
			if len(out) > 0 && !dash {
				out = append(out, '-')
				dash = true
			}
		}
		if len(out) >= 255 {
			break
		}
	}
	return strings.Trim(string(out), "-./+")
}

func sanitizeDeclaredSkillSource(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "git+https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return boundedSkillValue(parsed.String(), 2048)
}

func boundedSkillValue(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

var skillBundleHashPattern = regexp.MustCompile("^[0-9a-f]{64}$")
var destructiveSkillCommandPattern = regexp.MustCompile("(?i)(^|[;&|[:space:]])(?:rm[[:space:]]+-[a-z]*r[a-z]*f|mkfs(?:\\.|[[:space:]])|dd[[:space:]]+if=|shutdown|reboot)([;&|[:space:]]|$)")

func validSkillBundleHash(value string) bool {
	return skillBundleHashPattern.MatchString(strings.TrimSpace(value))
}

func analyzeSkillInvocation(input ToolCallAnalysisInput, provenance ProvenanceResult) Decision {
	identity := ExtractSkillIdentity(input.Arguments)
	if identity.Issue != "" {
		// 身份异常是防护项 skill.identity_invalid 的命中，动作由租户配置决定。
		return protectionFindingWithConfidence(identity.Issue, identity.CanonicalName, "critical", 1, []Evidence{sanitizedEvidence(
			identity.Issue, "skill_supply_chain", "skill", identity.CanonicalName,
		)})
	}
	decision := skillAdmissionDecision(input.SkillAdmission, identity)

	flat := flattenSkillArguments(input.Arguments)
	if command := getAnyStringArg(flat, "command"); command != "" {
		if destructiveSkillCommandPattern.MatchString(command) {
			decision = mergeAnalyzerDecision(decision, protectionFinding(
				reasonSkillDangerousCommand, identity.CanonicalName, "critical",
				[]Evidence{sanitizedEvidence(reasonSkillDangerousCommand, "command", "command", command)},
			))
		} else {
			decision = mergeAnalyzerDecision(decision, analyzeSystemToolCall(flat, input.CommandAllowlist))
		}
	}
	if getAnyStringArg(flat, "query") != "" {
		decision = mergeAnalyzerDecision(decision, analyzeDatabaseToolCall(flat))
	}
	if getAnyStringArg(flat, "path") != "" {
		decision = mergeAnalyzerDecision(decision, analyzeFileToolCall(input.ToolName, flat, provenance, isMCPToolCall(input)))
	}
	if getAnyStringArg(flat, "url") != "" {
		decision = mergeAnalyzerDecision(decision, analyzeNetworkToolCall(
			input.ToolName, flat, input.AllowedDomains, provenance,
		))
	}
	return decision
}

func skillAdmissionDecision(status SkillAdmissionStatus, identity SkillIdentity) Decision {
	// Hotfix 2.9.11-skill-admission-audit: mainstream agent runtimes (e.g.
	// Claude Code's Skill tool) only send {skill, args}; they never declare a
	// version or bundle hash. Treating that as a confirm-level admission floor
	// silently blocked every Skill call in protect mode. Incomplete identity
	// and not-yet-approved versions are now recorded (audit) only; explicit
	// administrator actions (quarantine/revoke) and dangerous nested behavior
	// remain enforced.
	if !identity.Complete() {
		return Decision{
			RawDecision: DecisionAudit,
			Reason:      "skill_identity_incomplete",
			RiskLevel:   "medium",
			Confidence:  0.9,
			Evidence: []Evidence{sanitizedEvidence(
				"skill_identity_incomplete", "skill_supply_chain", "skill", identity.CanonicalName,
			)},
		}
	}
	switch status {
	case SkillAdmissionApproved:
		return Decision{RawDecision: DecisionAllow, Reason: "skill_version_approved", RiskLevel: "low", Confidence: 0.95}
	case SkillAdmissionQuarantined:
		return Decision{
			RawDecision: DecisionBlock, Reason: reasonSkillVersionQuarantined,
			RiskLevel: "critical", Confidence: 1,
			// Quarantine and revocation are administrator actions on the Skill page.
			ConfiguredEnforcement: true,
			Evidence: []Evidence{sanitizedEvidence(
				reasonSkillVersionQuarantined, "skill_supply_chain", "skill", identity.CanonicalName,
			)},
		}
	case SkillAdmissionRevoked:
		return Decision{
			RawDecision: DecisionBlock, Reason: reasonSkillVersionRevoked,
			RiskLevel: "critical", Confidence: 1,
			// Quarantine and revocation are administrator actions on the Skill page.
			ConfiguredEnforcement: true,
			Evidence: []Evidence{sanitizedEvidence(
				reasonSkillVersionRevoked, "skill_supply_chain", "skill", identity.CanonicalName,
			)},
		}
	case SkillAdmissionUnavailable:
		// 准入服务不可用（SKILL_ADMISSION_FAIL_MODE 默认 fail-closed）：防护项
		// skill.admission_unavailable 的命中，动作由租户配置决定。
		return protectionFindingWithConfidence(reasonSkillAdmissionUnavail, identity.CanonicalName, "high", 0.9, []Evidence{sanitizedEvidence(
			reasonSkillAdmissionUnavail, "skill_supply_chain", "skill", identity.CanonicalName,
		)})
	default:
		return Decision{
			RawDecision: DecisionAudit, Reason: "skill_version_unverified",
			RiskLevel: "medium", Confidence: 0.9,
			Evidence: []Evidence{sanitizedEvidence(
				"skill_version_unverified", "skill_supply_chain", "skill", identity.CanonicalName,
			)},
		}
	}
}

func flattenSkillArguments(args map[string]any) map[string]any {
	flat := map[string]any{}
	var bodyParts []string
	nodes := 0
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 8 || nodes >= 2048 {
			return
		}
		nodes++
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				item := typed[key]
				if text, ok := item.(string); ok {
					text = boundedSkillValue(text, 65536)
					switch normalizeSkillKey(key) {
					case "command", "cmd", "script", "shell":
						setFlatSkillValue(flat, "command", text)
					case "path", "file", "file_path", "filepath", "destination":
						setFlatSkillValue(flat, "path", text)
					case "url", "uri", "endpoint", "host", "target":
						setFlatSkillValue(flat, "url", text)
					case "query", "sql", "statement":
						setFlatSkillValue(flat, "query", text)
					case "body", "data", "payload", "content", "input":
						setFlatSkillValue(flat, "body", text)
					}
					if len(bodyParts) < 128 {
						bodyParts = append(bodyParts, text)
					}
				}
				walk(item, depth+1)
			}
		case []any:
			for _, item := range typed {
				walk(item, depth+1)
			}
		}
	}
	walk(args, 0)
	if _, exists := flat["body"]; !exists && len(bodyParts) > 0 {
		flat["body"] = boundedSkillValue(strings.Join(bodyParts, "\n"), 65536)
	}
	return flat
}

func setFlatSkillValue(flat map[string]any, key, value string) {
	if value == "" {
		return
	}
	if _, exists := flat[key]; !exists {
		flat[key] = value
	}
}
