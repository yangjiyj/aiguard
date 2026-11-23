package agentendpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

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
type Sources struct {
	AgentGuardPolicyVersion string `json:"agentguard_policy_version,omitempty"`
	ToolRiskConfigVersion   string `json:"tool_risk_config_version,omitempty"`
}
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

// Checksum is SHA-256 over the complete JSON bundle with checksum set to an
// empty string. This is the hookd policy.Checksum contract; field and array order
// are stable because the bundle is represented by structs and sources are sorted.
func BuildBundle(version int64, mode string, rules []Rule, allow Allowlist, sources Sources, at time.Time) ([]byte, string, error) {
	if version < 1 {
		return nil, "", fmt.Errorf("invalid bundle version")
	}
	if mode != "monitor" && mode != "would_block" && mode != "block" {
		return nil, "", fmt.Errorf("invalid mode %q", mode)
	}
	if len(rules) > 500 {
		return nil, "", fmt.Errorf("too many rules: %d", len(rules))
	}
	if rules == nil {
		rules = []Rule{}
	}
	for _, rule := range rules {
		if !regexp.MustCompile(`^[a-z0-9_]{3,64}$`).MatchString(rule.ID) || !ValidDecision(rule.Decision) || !ValidRisk(rule.Risk) {
			return nil, "", fmt.Errorf("invalid rule %q", rule.ID)
		}
		if len(rule.Match.ToolNameRegex) > 256 || len(rule.Match.CommandRegex) > 512 {
			return nil, "", fmt.Errorf("rule %q exceeds regex limit", rule.ID)
		}
	}
	secrets := BuiltinSecretPatterns()
	if allow.Commands == nil {
		allow.Commands = []any{}
	}
	if allow.Domains == nil {
		allow.Domains = []string{}
	}
	if allow.MCPServers == nil {
		allow.MCPServers = []string{}
	}
	if allow.Paths == nil {
		allow.Paths = []string{}
	}
	bundle := Bundle{"1.0", version, "", at.UTC().Format(time.RFC3339Nano), mode, sources, rules, secrets, allow}
	canonical, err := json.Marshal(bundle)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	bundle.Checksum = "sha256:" + hex.EncodeToString(sum[:])
	data, err := json.Marshal(bundle)
	return data, bundle.Checksum, err
}

// ToolPatternMatches expands the gateway matcher candidates (name and
// type.name). A type.* wildcard also matches every non-empty name of that
// type, independently of the path.Match branch. Endpoint rules are ORed.
// The endpoint must normalize names/types to lower-case trimmed strings as
// agentguardmatch.Matches does; otherwise exact equivalence is unavailable.
// Ambiguous patterns are rejected rather than silently broadened.
func ToolPatternMatches(pattern string) ([]Match, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return nil, fmt.Errorf("empty tool glob")
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	if pattern == "*" {
		return []Match{{ToolNameRegex: "^.+$"}}, nil
	}
	wildcard := strings.IndexAny(pattern, "*?[")
	prefix := pattern
	if wildcard >= 0 {
		prefix = pattern[:wildcard]
	}
	for _, typ := range []string{"system", "file", "network", "database", "mcp", "skill", "agent", "browser", "other"} {
		if wildcard >= 0 && !strings.HasPrefix(pattern, typ+".") && strings.HasPrefix(typ+".", prefix) {
			return nil, fmt.Errorf("ambiguous qualified glob %q", pattern)
		}
	}
	// An unqualified literal can also match a type.name candidate if it is
	// prefixed by a known type; that path is expanded below.
	expression, err := globRE2(pattern)
	if err != nil {
		return nil, err
	}
	matches := []Match{{ToolNameRegex: expression}}
	for _, typ := range []string{"system", "file", "network", "database", "mcp", "skill", "agent", "browser", "other"} {
		if pattern == typ+".*" {
			matches = append(matches, Match{ToolType: typ})
			continue
		}
		// Only derive a type-qualified branch when its literal suffix cannot
		// accidentally match a name already carrying that type prefix.
		qualified, e := qualifiedGlobRE2(pattern, typ)
		if e != nil {
			return nil, e
		}
		if qualified != "" {
			matches = append(matches, Match{ToolType: typ, ToolNameRegex: qualified})
		}
	}
	return matches, nil
}

func qualifiedGlobRE2(pattern, typ string) (string, error) {
	// Derive names n for which path.Match(pattern, typ+"."+n) succeeds.
	// If n itself starts with typ+".", the gateway tests n unchanged; the
	// name-only expression above covers that branch.
	prefix := typ + "."
	if !strings.HasPrefix(pattern, prefix) {
		return "", nil
	}
	suffix := strings.TrimPrefix(pattern, prefix)
	if suffix == "" {
		return "", nil
	}
	wildcard := strings.IndexAny(suffix, "*?")
	literal := suffix
	if wildcard >= 0 {
		literal = suffix[:wildcard]
	}
	// A name already beginning with typ." skips the gateway's qualified
	// candidate. RE2 has no lookahead to exclude it, so reject only when the
	// suffix glob could itself match a typ-qualified name.
	if strings.HasPrefix(prefix, literal) || strings.HasPrefix(suffix, prefix) {
		return "", fmt.Errorf("qualified glob %q cannot preserve gateway candidate semantics", pattern)
	}
	expression, err := globRE2(suffix)
	if err != nil {
		return "", err
	}
	return expression, nil
}

func globRE2(pattern string) (string, error) {
	var result strings.Builder
	result.WriteString("(?i)^")
	escaped := false
	for _, r := range pattern {
		if escaped {
			result.WriteString(regexp.QuoteMeta(string(r)))
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '*':
			result.WriteString("[^/]*")
		case '?':
			result.WriteString("[^/]")
		case '[', ']':
			return "", fmt.Errorf("glob class %q cannot be translated safely", pattern)
		default:
			result.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	if escaped {
		return "", fmt.Errorf("dangling glob escape %q", pattern)
	}
	result.WriteByte('$')
	if result.Len() > 256 {
		return "", fmt.Errorf("tool glob %q exceeds regex limit", pattern)
	}
	return result.String(), nil
}
func ValidDecision(s string) bool {
	switch s {
	case "allow", "audit", "confirm", "block":
		return true
	}
	return false
}
func ValidRisk(s string) bool {
	switch s {
	case "low", "medium", "high", "critical":
		return true
	}
	return false
}
func ValidToolType(s string) bool {
	switch s {
	case "system", "file", "network", "database", "mcp", "skill", "agent", "browser", "other":
		return true
	}
	return false
}
func RuleID(source string) string {
	sum := sha256.Sum256([]byte(source))
	return "src_" + hex.EncodeToString(sum[:16])
}
