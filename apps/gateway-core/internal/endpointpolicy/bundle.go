package endpointpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Bundle mirrors the canonical control-plane endpoint bundle. Field order and
// json tags are part of the checksum contract shared with hookd.
type Bundle struct {
	SchemaVersion  string          `json:"schema_version"`
	Version        int64           `json:"version"`
	Checksum       string          `json:"checksum"`
	GeneratedAt    string          `json:"generated_at"`
	ModeDefault    string          `json:"mode_default"`
	DerivedFrom    Sources         `json:"derived_from,omitempty"`
	Rules          []Rule          `json:"rules"`
	SecretPatterns []SecretPattern `json:"secret_patterns"`
	Allowlists     Allowlist       `json:"allowlists"`
}

type Sources struct {
	AgentGuardPolicyVersion string `json:"agentguard_policy_version,omitempty"`
	ToolRiskConfigVersion   string `json:"tool_risk_config_version,omitempty"`
}

type Rule struct {
	ID       string `json:"id"`
	Match    Match  `json:"match"`
	Decision string `json:"decision"`
	Risk     string `json:"risk"`
	Enabled  bool   `json:"enabled"`
}

type Match struct {
	ToolType          string   `json:"tool_type,omitempty"`
	ToolNameRegex     string   `json:"tool_name_regex,omitempty"`
	CommandRegex      string   `json:"command_regex,omitempty"`
	PathGlob          []string `json:"path_glob,omitempty"`
	ArgsSecretPattern bool     `json:"args_secret_pattern,omitempty"`
}

type SecretPattern struct {
	Kind  string `json:"kind"`
	Regex string `json:"regex"`
}

type Allowlist struct {
	Commands   []any    `json:"commands,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	MCPServers []string `json:"mcp_servers,omitempty"`
	Paths      []string `json:"paths,omitempty"`
}

type ToolInput struct {
	Name      string
	Type      string
	Arguments map[string]any
}

type Hit struct {
	RuleID   string
	Decision string
	Risk     string
	// Paths 是按路径匹配（PathGlob）的规则确定命中的参数路径（原样，按出现顺序去重），供例外按路径层级比对。
	Paths []string
}

type Evaluation struct {
	Hit     Hit
	Matched bool
	Unknown []Hit
	// Hits 是全部确定命中的规则（按策略包顺序）；Hit 是其中最严的一条。
	Hits []Hit
}

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9_]{3,64}$`)

// DecodeAndValidate rejects unknown JSON fields, invalid matcher programs, and
// any bundle whose checksum does not match the CP/hookd canonical encoding.
func DecodeAndValidate(data []byte) (Bundle, error) {
	var bundle Bundle
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Bundle{}, errors.New("trailing bundle data")
	}
	if !strings.HasPrefix(bundle.SchemaVersion, "1.") || bundle.Version < 1 {
		return Bundle{}, errors.New("unsupported bundle schema or version")
	}
	if bundle.ModeDefault != "monitor" && bundle.ModeDefault != "would_block" && bundle.ModeDefault != "block" {
		return Bundle{}, errors.New("invalid bundle mode")
	}
	if len(bundle.Rules) > 500 || len(bundle.SecretPatterns) > 100 {
		return Bundle{}, errors.New("bundle size limit")
	}
	if !validChecksum(bundle.Checksum) || bundle.Checksum != Checksum(bundle) {
		return Bundle{}, errors.New("bundle checksum mismatch")
	}
	for _, secret := range bundle.SecretPatterns {
		if strings.TrimSpace(secret.Kind) == "" || secret.Regex == "" || len(secret.Regex) > 1024 {
			return Bundle{}, errors.New("invalid secret pattern")
		}
		if _, err := regexp.Compile(secret.Regex); err != nil {
			return Bundle{}, fmt.Errorf("invalid secret pattern regex: %w", err)
		}
	}
	for _, rule := range bundle.Rules {
		if !ruleIDPattern.MatchString(rule.ID) || !validDecision(rule.Decision) || !validRisk(rule.Risk) {
			return Bundle{}, fmt.Errorf("invalid rule %q", rule.ID)
		}
		if len(rule.Match.ToolNameRegex) > 256 || len(rule.Match.CommandRegex) > 512 {
			return Bundle{}, fmt.Errorf("rule %q exceeds matcher limit", rule.ID)
		}
		if rule.Match.ToolNameRegex != "" {
			if _, err := regexp.Compile(rule.Match.ToolNameRegex); err != nil {
				return Bundle{}, fmt.Errorf("rule %q name regex: %w", rule.ID, err)
			}
		}
		if rule.Match.CommandRegex != "" {
			if _, err := regexp.Compile(rule.Match.CommandRegex); err != nil {
				return Bundle{}, fmt.Errorf("rule %q command regex: %w", rule.ID, err)
			}
		}
		if len(rule.Match.PathGlob) > 64 {
			return Bundle{}, fmt.Errorf("rule %q exceeds path glob limit", rule.ID)
		}
		for _, pattern := range rule.Match.PathGlob {
			if len(pattern) > 1024 {
				return Bundle{}, fmt.Errorf("rule %q path glob exceeds matcher limit", rule.ID)
			}
			if !strings.HasPrefix(normalizePath(pattern), "~/") {
				if _, err := compileGlob(pattern); err != nil {
					return Bundle{}, fmt.Errorf("rule %q path glob: %w", rule.ID, err)
				}
			}
		}
	}
	return bundle, nil
}

// Checksum returns the endpoint-bundle checksum: sha256 over the canonical
// JSON representation with the checksum field empty.
func Checksum(bundle Bundle) string {
	bundle.Checksum = ""
	data, _ := json.Marshal(bundle)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validChecksum(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validDecision(value string) bool {
	switch value {
	case "allow", "audit", "confirm", "block":
		return true
	default:
		return false
	}
}

func validRisk(value string) bool {
	switch value {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// Evaluate ports the current CP-generated rule subset from hookd's matcher.
// Unknown is returned when a redacted argument or client-home glob could alter
// the match. Callers must not claim a successful evaluation when that unknown
// can affect the selected rule or the merged decision.
func Evaluate(bundle Bundle, input ToolInput) Evaluation {
	result := Evaluation{}
	secretRegexps := make([]*regexp.Regexp, 0, len(bundle.SecretPatterns))
	for _, pattern := range bundle.SecretPatterns {
		if compiled, err := regexp.Compile(pattern.Regex); err == nil {
			secretRegexps = append(secretRegexps, compiled)
		}
	}
	for _, rule := range bundle.Rules {
		if !rule.Enabled {
			continue
		}
		state, paths := matchRule(rule, input, secretRegexps)
		hit := Hit{RuleID: rule.ID, Decision: rule.Decision, Risk: rule.Risk, Paths: paths}
		switch state {
		case matchYes:
			result.Hits = append(result.Hits, hit)
			if !result.Matched || stricterHit(hit, result.Hit) {
				result.Hit = hit
				result.Matched = true
			}
		case matchUnknown:
			result.Unknown = append(result.Unknown, hit)
		}
	}
	return result
}

func UnknownMayChange(e Evaluation, finalDecision, finalRisk string) bool {
	// A known bundle block is the maximum action and is sufficient even if an
	// unresolved, lower-confidence matcher branch also exists.
	if e.Matched && e.Hit.Decision == "block" {
		return false
	}
	if len(e.Unknown) == 0 {
		return false
	}
	if !e.Matched {
		// Without a known winner, an unresolved candidate could change both the
		// decision and the rule ID returned to hookd.
		return true
	}
	for _, possible := range e.Unknown {
		if decisionRank(possible.Decision) > decisionRank(e.Hit.Decision) ||
			(decisionRank(possible.Decision) == decisionRank(e.Hit.Decision) && riskRank(possible.Risk) >= riskRank(e.Hit.Risk)) {
			return true
		}
		if decisionRank(possible.Decision) > decisionRank(finalDecision) || riskRank(possible.Risk) > riskRank(finalRisk) {
			return true
		}
	}
	return false
}

type matchState int

const (
	matchNo matchState = iota
	matchYes
	matchUnknown
)

func matchRule(rule Rule, input ToolInput, secrets []*regexp.Regexp) (matchState, []string) {
	m := rule.Match
	if m.ToolType != "" && m.ToolType != input.Type {
		return matchNo, nil
	}
	if m.ToolNameRegex != "" {
		name, _ := regexp.Compile(m.ToolNameRegex)
		if name == nil || !name.MatchString(input.Name) {
			return matchNo, nil
		}
	}
	unknown := false
	command := stringArg(input.Arguments, "command")
	if m.CommandRegex != "" {
		if hasRedactedValue(command) {
			unknown = true
		} else {
			pattern, _ := regexp.Compile(m.CommandRegex)
			if pattern == nil || !pattern.MatchString(command) {
				return matchNo, nil
			}
		}
	}
	var matchedPaths []string
	if len(m.PathGlob) > 0 {
		paths := argumentPaths(input.Arguments)
		if len(paths) == 0 {
			return matchNo, nil
		}
		knownMatch := false
		unknownPath := false
		homeUnknown := false
		for _, pattern := range m.PathGlob {
			if rest, ok := strings.CutPrefix(normalizePath(pattern), "~/"); ok {
				// 网关不知道端点的家目录，~/x 只在路径可能落在某个家目录下时才算“无法评估”：
				// 展开后的 ~/x 一定也被 **/x 命中，**/x 都不命中的路径就是确定不命中。
				if homeGlobMayMatch(rest, paths) {
					homeUnknown = true
				}
				continue
			}
			compiled, err := compileGlob(pattern)
			if err != nil {
				unknownPath = true
				continue
			}
			for _, candidate := range paths {
				if hasRedactedValue(candidate) || pathCaseAmbiguous(pattern, candidate) {
					unknownPath = true
					continue
				}
				if compiled.MatchString(normalizePath(candidate)) {
					knownMatch = true
					matchedPaths = appendUniquePath(matchedPaths, candidate)
				}
			}
		}
		if !knownMatch {
			if homeUnknown || unknownPath {
				unknown = true
			} else {
				return matchNo, nil
			}
		}
	}
	if m.ArgsSecretPattern {
		if len(secrets) == 0 {
			return matchNo, nil
		}
		if hasRedactedValue(input.Arguments) {
			unknown = true
		} else {
			data, err := json.Marshal(input.Arguments)
			if err != nil {
				unknown = true
			} else {
				matched := false
				for _, pattern := range secrets {
					if pattern.Match(data) {
						matched = true
						break
					}
				}
				if !matched {
					return matchNo, nil
				}
			}
		}
	}
	if unknown {
		return matchUnknown, nil
	}
	return matchYes, matchedPaths
}

// homeGlobMayMatch 判断 ~/rest 是否可能命中这些路径：按 **/rest 求值（展开后的家目录路径是它的子集），
// 编译不了或路径已脱敏时保守地算可能命中。
func homeGlobMayMatch(rest string, paths []string) bool {
	compiled, err := compileGlob("**/" + rest)
	if err != nil {
		return true
	}
	for _, candidate := range paths {
		if hasRedactedValue(candidate) || compiled.MatchString(normalizePath(candidate)) {
			return true
		}
	}
	return false
}

func appendUniquePath(paths []string, path string) []string {
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func stringArg(args map[string]any, key string) string {
	if value, ok := args[key].(string); ok {
		return value
	}
	return ""
}

func argumentPaths(args map[string]any) []string {
	var paths []string
	for _, key := range []string{"file_path", "path", "directory", "folder"} {
		if value := stringArg(args, key); value != "" {
			paths = append(paths, value)
		}
	}
	for _, key := range []string{"paths", "file_paths"} {
		switch values := args[key].(type) {
		case []any:
			for _, value := range values {
				if text, ok := value.(string); ok && text != "" {
					paths = append(paths, text)
				}
			}
		case []string:
			for _, value := range values {
				if value != "" {
					paths = append(paths, value)
				}
			}
		}
	}
	return paths
}

func hasRedactedValue(value any) bool {
	switch typed := value.(type) {
	case string:
		text := typed
		for i := 0; i < 4; i++ {
			if strings.Contains(strings.ToLower(text), "<redacted") {
				return true
			}
			query, queryErr := url.QueryUnescape(text)
			path, pathErr := url.PathUnescape(text)
			if queryErr != nil && pathErr != nil {
				break
			}
			if queryErr == nil && query != text {
				text = query
				continue
			}
			if pathErr == nil && path != text {
				text = path
				continue
			}
			break
		}
	case map[string]any:
		for _, child := range typed {
			if hasRedactedValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if hasRedactedValue(child) {
				return true
			}
		}
	}
	return false
}

func pathCaseAmbiguous(pattern, candidate string) bool {
	pattern = normalizePath(pattern)
	candidate = normalizePath(candidate)
	if len(pattern) >= 2 && pattern[1] == ':' && len(candidate) >= 2 && candidate[1] == ':' {
		return pattern[0] != candidate[0] && strings.EqualFold(pattern[:1], candidate[:1])
	}
	return false
}

func normalizePath(value string) string {
	return filepath.ToSlash(strings.ReplaceAll(value, "\\", "/"))
}

func compileGlob(pattern string) (*regexp.Regexp, error) {
	pattern = normalizePath(pattern)
	if strings.HasPrefix(pattern, "~/") {
		return nil, errors.New("client home glob is not evaluable by gateway")
	}
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

func stricterHit(left, right Hit) bool {
	if decisionRank(left.Decision) != decisionRank(right.Decision) {
		return decisionRank(left.Decision) > decisionRank(right.Decision)
	}
	return riskRank(left.Risk) > riskRank(right.Risk)
}

func decisionRank(value string) int {
	switch value {
	case "block":
		return 4
	case "confirm":
		return 3
	case "audit":
		return 2
	case "allow":
		return 1
	default:
		return 0
	}
}

func riskRank(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
