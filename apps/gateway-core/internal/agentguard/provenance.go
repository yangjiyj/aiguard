package agentguard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const minTaintNeedleLength = 4

var base64TokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{12,}`)

// ContextFragment is a source text that may have influenced a tool call.
type ContextFragment struct {
	ID    string     `json:"id"`
	Trust Provenance `json:"trust"`
	Text  string     `json:"text"`
}

// ProvenanceResult describes argument-level taint found in a tool call.
type ProvenanceResult struct {
	Provenance       Provenance `json:"provenance"`
	TaintedArguments []string   `json:"tainted_arguments,omitempty"`
	Evidence         []Evidence `json:"evidence_json,omitempty"`
}

// AnalyzeArgumentProvenance flags tool arguments whose concrete values appear in untrusted context.
func AnalyzeArgumentProvenance(arguments map[string]any, fragments []ContextFragment) ProvenanceResult {
	trustedSeen, untrustedSeen := classifyFragments(fragments)
	untrustedCorpus := buildUntrustedCorpus(fragments)

	var tainted []string
	var evidence []Evidence
	for _, name := range sortedArgumentNames(arguments) {
		if lowInformationArgument(arguments[name]) {
			continue
		}
		value := argumentString(arguments[name])
		if value == "" {
			continue
		}
		if argumentMatchesCorpus(value, untrustedCorpus) {
			tainted = append(tainted, name)
			evidence = append(evidence, sanitizedEvidence("argument_tainted", "provenance", name, value))
		}
	}

	if len(tainted) > 0 {
		return ProvenanceResult{Provenance: ProvenanceTainted, TaintedArguments: tainted, Evidence: evidence}
	}

	switch {
	case trustedSeen && untrustedSeen:
		return ProvenanceResult{Provenance: ProvenanceMixed}
	case untrustedSeen:
		return ProvenanceResult{Provenance: ProvenanceUntrusted}
	case trustedSeen:
		return ProvenanceResult{Provenance: ProvenanceTrusted}
	default:
		return ProvenanceResult{Provenance: ProvenanceUnknown}
	}
}

// lowInformationArgument：布尔、空值、数字，以及写成字符串的纯数字和 true/false 这类字面量。
// 这类值在工具结果里随处可见，模型照抄项目编号、合并请求编号是正常用法，记成“参数来自
// 不可信内容”只会误报（2026-11-21 客户现场 MCP gitlab 的 project_id "7936"、
// merge_request_iid 60480、remove_source_branch false）。URL、路径、主机名、命令、按钮引用
// （ref_31）等带字母的值照旧比对。
func lowInformationArgument(value any) bool {
	switch typed := value.(type) {
	case nil, bool, float64, float32, int, int64, int32, uint, uint64, uint32, json.Number:
		return true
	case string:
		text := strings.TrimSpace(typed)
		switch strings.ToLower(text) {
		case "true", "false", "null", "none", "yes", "no":
			return true
		}
		digits := text != ""
		for _, r := range text {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		return digits
	}
	return false
}

func classifyFragments(fragments []ContextFragment) (trustedSeen bool, untrustedSeen bool) {
	for _, fragment := range fragments {
		switch fragment.Trust {
		case ProvenanceTrusted:
			trustedSeen = true
		case ProvenanceUntrusted, ProvenanceMixed, ProvenanceTainted:
			untrustedSeen = true
		}
	}
	return trustedSeen, untrustedSeen
}

func buildUntrustedCorpus(fragments []ContextFragment) string {
	var parts []string
	for _, fragment := range fragments {
		if fragment.Text == "" || !isUntrusted(fragment.Trust) {
			continue
		}
		parts = append(parts, strings.ToLower(fragment.Text))
		for _, decoded := range decodeBase64Tokens(fragment.Text) {
			parts = append(parts, strings.ToLower(decoded))
		}
	}
	return strings.Join(parts, "\n")
}

func isUntrusted(trust Provenance) bool {
	switch trust {
	case ProvenanceUntrusted, ProvenanceMixed, ProvenanceTainted:
		return true
	default:
		return false
	}
}

func sortedArgumentNames(arguments map[string]any) []string {
	names := make([]string, 0, len(arguments))
	for name := range arguments {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func argumentString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case nil:
		return ""
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return strings.TrimSpace(fmt.Sprint(typed))
		}
		return strings.TrimSpace(string(encoded))
	}
}

func argumentMatchesCorpus(value string, corpus string) bool {
	if corpus == "" {
		return false
	}
	for _, needle := range argumentNeedles(value) {
		if len(needle) < minTaintNeedleLength {
			continue
		}
		if strings.Contains(corpus, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func argumentNeedles(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	needles := []string{trimmed}

	if parsed, err := url.Parse(trimmed); err == nil && parsed.Host != "" {
		needles = append(needles, parsed.Host)
		if parsed.Path != "" && parsed.Path != "/" {
			needles = append(needles, parsed.Path)
			needles = append(needles, parsed.Host+parsed.Path)
		}
	}

	cleaned := filepath.Clean(trimmed)
	if cleaned != "." && cleaned != trimmed {
		needles = append(needles, cleaned)
	}
	base := filepath.Base(cleaned)
	if base != "." && base != "/" && base != cleaned {
		needles = append(needles, base)
	}

	return uniqueStrings(needles)
}

func decodeBase64Tokens(text string) []string {
	tokens := base64TokenPattern.FindAllString(text, -1)
	var decoded []string
	for _, token := range tokens {
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			bytes, err := encoding.DecodeString(token)
			if err != nil || !mostlyPrintable(bytes) {
				continue
			}
			decoded = append(decoded, string(bytes))
			break
		}
	}
	return uniqueStrings(decoded)
}

func mostlyPrintable(bytes []byte) bool {
	if len(bytes) == 0 {
		return false
	}
	printable := 0
	for _, b := range bytes {
		if b == '\n' || b == '\r' || b == '\t' || unicode.IsPrint(rune(b)) {
			printable++
		}
	}
	return printable*100/len(bytes) >= 85
}

func sanitizedEvidence(ruleID string, category string, sourceField string, rawValue string) Evidence {
	digest := sha256.Sum256([]byte(rawValue))
	return Evidence{
		RuleID:        ruleID,
		Category:      category,
		SourceField:   sourceField,
		MaskedPreview: fmt.Sprintf("<redacted:%d>", len(rawValue)),
		Hash:          hex.EncodeToString(digest[:]),
		Length:        len(rawValue),
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
