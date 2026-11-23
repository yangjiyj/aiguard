package agentdetect

import (
	"net/http"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aiadapters"
	"github.com/yangjiyj/aiguard/packages/shared-go/headercompat"
)

type Rule struct {
	Type     string
	Aliases  []string
	Patterns []string
}

// Detection keeps the AI product identity separate from the client runtime.
// A generic Code/Electron user agent is runtime evidence, not proof that the
// calling AI product is Visual Studio Code.
//
// Role records the caller's declared invocation role (main, auxiliary,
// compaction, ...). A role describes what the call is for, never which product
// made it, so it is kept beside Product instead of being promoted into it.
type Detection struct {
	Product, Runtime, Source, Role string
	Confidence                     float64
}

// genericAgentIdentities are call roles and placeholder identities that clients
// put into agent-type headers. They are not agent products: attribution must
// keep looking at the User-Agent and message content instead of trusting them.
var genericAgentIdentities = map[string]struct{}{
	"": {}, "main": {}, "default": {}, "agent": {}, "assistant": {}, "unknown": {},
	"auxiliary": {}, "compaction": {}, "subagent": {}, "sub-agent": {}, "title": {}, "summary": {},
}

// IsGenericAgentIdentity reports whether value is empty, a placeholder or a
// call role rather than a concrete agent product.
func IsGenericAgentIdentity(value string) bool {
	_, ok := genericAgentIdentities[NormalizeAgentType(value)]
	return ok
}

// GenericAgentIdentities returns the generic/role names in stable order so SQL
// that must mirror IsGenericAgentIdentity can be generated from the same list.
// The empty placeholder is excluded: SQL callers test emptiness separately.
func GenericAgentIdentities() []string {
	out := make([]string, 0, len(genericAgentIdentities))
	for name := range genericAgentIdentities {
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// upgradeableRuntimeIdentities 是"只说明运行环境、不说明产品"的值：它们可以被后到的
// 具体产品纠正，但自身不是产品。请求行回填（BackfillRequestAgentType）、会话 upsert、
// 历史回填共用这一份名单。
var upgradeableRuntimeIdentities = []string{"agent-tool-call", "vscode"}

// UpgradeableRuntimeIdentities 返回可被具体产品覆盖的运行时值（已归一化、顺序稳定）。
func UpgradeableRuntimeIdentities() []string {
	return append([]string(nil), upgradeableRuntimeIdentities...)
}

// IsUpgradeableRuntimeIdentity 报告 value（归一化后）是否是可被具体产品覆盖的运行时值。
func IsUpgradeableRuntimeIdentity(value string) bool {
	key := NormalizeAgentType(value)
	for _, name := range upgradeableRuntimeIdentities {
		if key == name {
			return true
		}
	}
	return false
}

// IsConcreteAgentProduct 报告 value 是否是具体产品：非空、非通用角色、非可升级运行时值。
func IsConcreteAgentProduct(value string) bool {
	return NormalizeAgentType(value) != "" && !IsGenericAgentIdentity(value) && !IsUpgradeableRuntimeIdentity(value)
}

// SessionOverwritableIdentities 是会话已存值"可被具体产品覆盖"的完整名单：
// 空串 + 通用角色 + 可升级运行时值。SQL 以 = ANY($n::text[]) 方式参数化使用，
// 比较前 SQL 侧做同样的归一化（小写、空白/下划线转连字符）。
func SessionOverwritableIdentities() []string {
	out := []string{""}
	out = append(out, GenericAgentIdentities()...)
	return append(out, upgradeableRuntimeIdentities...)
}

var Rules = loadRules()
var aliasToType = buildAliasMap()

func loadRules() []Rule {
	adapterRules := aiadapters.AgentRules()
	out := make([]Rule, 0, len(adapterRules))
	for _, rule := range adapterRules {
		out = append(out, Rule{Type: rule.Type, Aliases: rule.Aliases, Patterns: rule.Patterns})
	}
	return out
}

func buildAliasMap() map[string]string {
	m := map[string]string{}
	for _, rule := range Rules {
		m[strings.ToLower(rule.Type)] = rule.Type
		for _, alias := range rule.Aliases {
			m[normalize(alias)] = rule.Type
		}
	}
	return m
}

func normalize(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.ReplaceAll(v, "_", "-")
	v = strings.Join(strings.Fields(v), "-")
	return v
}

func Label(agentType string) string {
	return aiadapters.Label(agentType)
}

func NormalizeAgentType(value string) string {
	key := normalize(value)
	if key == "" {
		return ""
	}
	if typ, ok := aliasToType[key]; ok {
		return typ
	}
	return key
}

// ProductPatterns 返回某个产品在 agent-registry.json 里登记的请求头特征（小写副本）。
// SQL 回填与投影按 strpos(lower(ua), pattern) 使用它，保证与网关识别同源、不再各写一份正则。
func ProductPatterns(product string) []string {
	product = NormalizeAgentType(product)
	for _, rule := range Rules {
		if rule.Type != product {
			continue
		}
		out := make([]string, 0, len(rule.Patterns))
		for _, pattern := range rule.Patterns {
			if pattern = strings.ToLower(strings.TrimSpace(pattern)); pattern != "" {
				out = append(out, pattern)
			}
		}
		return out
	}
	return nil
}

func InferFromText(text string) string {
	lower := strings.ToLower(text)
	if strings.TrimSpace(lower) == "" {
		return ""
	}
	for _, rule := range Rules {
		for _, pattern := range rule.Patterns {
			if strings.Contains(lower, strings.ToLower(pattern)) {
				return rule.Type
			}
		}
	}
	return ""
}

// InferFromTrustedText is for protocol-owned system/developer content. Unlike
// header fingerprints, prose must match a bounded product name and the most
// specific identity signal wins; an equally specific conflict fails closed.
func InferFromTrustedText(text string) string {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return ""
	}
	scores := make(map[string]int, len(Rules))
	assertedTypes := make(map[string]struct{}, 1)
	for _, rule := range Rules {
		for _, pattern := range rule.Patterns {
			pattern = strings.ToLower(strings.TrimSpace(pattern))
			for _, start := range boundedPatternIndexes(lower, pattern) {
				score := len(pattern)
				if trustedIdentityAssertion(lower[:start]) {
					score += 1 << 20
					assertedTypes[rule.Type] = struct{}{}
				}
				if score > scores[rule.Type] {
					scores[rule.Type] = score
				}
			}
		}
	}
	if len(assertedTypes) > 1 {
		return ""
	}
	bestType, bestScore, ambiguous := "", 0, false
	for agentType, score := range scores {
		switch {
		case score > bestScore:
			bestType, bestScore, ambiguous = agentType, score, false
		case score == bestScore && score > 0 && agentType != bestType:
			ambiguous = true
		}
	}
	if ambiguous {
		return ""
	}
	return bestType
}

// InferFromContentRole 是内容兜底的唯一入口：只看协议自有的 system / developer 角色，
// 在其中按有边界的产品名匹配（"You are X" 这类断言加分，最具体的信号胜出，同等强度冲突则
// 放弃）。注意它并不要求必须是断言：system 里非断言的提及（如 "The user is using Windsurf
// today."）当前也会命中，这是有意保留的现状，与网关 inferAgentTypeFromProtocolMessages 对
// system 的语义一致。user / assistant / tool 等角色的正文提到产品名属于话题，一律不算。
func InferFromContentRole(role, content string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "system", "developer":
		return InferFromTrustedText(content)
	default:
		return ""
	}
}

func boundedPatternIndexes(text, pattern string) []int {
	if text == "" || pattern == "" {
		return nil
	}
	indexes := []int{}
	for offset := 0; offset <= len(text)-len(pattern); {
		relative := strings.Index(text[offset:], pattern)
		if relative < 0 {
			break
		}
		start := offset + relative
		end := start + len(pattern)
		leftOK := start == 0 || !isASCIIWordByte(pattern[0]) || !isASCIIWordByte(text[start-1])
		rightOK := end == len(text) || !isASCIIWordByte(pattern[len(pattern)-1]) || !isASCIIWordByte(text[end])
		if leftOK && rightOK {
			indexes = append(indexes, start)
		}
		offset = start + 1
	}
	return indexes
}

func isASCIIWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func trustedIdentityAssertion(prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	for _, marker := range []string{"you are", "you are a", "you are an", "you are the", "你是", "你的身份是"} {
		if strings.HasSuffix(prefix, marker) {
			return true
		}
	}
	return false
}

func headerRuntime(header http.Header) string {
	var parts []string
	for _, key := range []string{"User-Agent", "X-IDE-Name"} {
		parts = append(parts, header.Values(key)...)
	}
	text := strings.ToLower(strings.Join(parts, " "))
	switch {
	case strings.Contains(text, "code/"), strings.Contains(text, "visual studio code"), strings.Contains(text, "vscode"):
		return "vscode"
	case strings.Contains(text, "electron/"):
		return "electron"
	default:
		return ""
	}
}

func DetectFromHeaders(header http.Header) (Detection, error) {
	runtime := headerRuntime(header)
	value, _, err := headercompat.Resolve(header, "X-JJDGuard-Agent-Type", "X-NewAPI-Agent-Type")
	if err != nil {
		return Detection{}, err
	}
	if value != "" {
		return Detection{Product: NormalizeAgentType(value), Runtime: runtime, Source: "explicit_header", Confidence: 1}, nil
	}
	role := ""
	for _, key := range []string{"X-UAG-Agent-Type", "X-Agent-Type", "X-AI-Agent"} {
		value, _, err = headercompat.Resolve(header, key, "")
		if err != nil {
			return Detection{}, err
		}
		if v := NormalizeAgentType(value); v != "" {
			if IsGenericAgentIdentity(v) {
				if role == "" {
					role = v
				}
				continue
			}
			return Detection{Product: v, Runtime: runtime, Source: "client_header", Role: role, Confidence: 0.95}, nil
		}
	}
	var parts []string
	for _, key := range []string{"User-Agent", "X-App-Name", "X-Client-Name", "X-Client-Version", "X-IDE-Name", "X-Code-Assistant"} {
		for _, v := range header.Values(key) {
			if v = strings.Trim(v, " \t"); v != "" {
				parts = append(parts, v)
			}
		}
	}
	// Codex 官方客户端另发 originator 头（codex_cli_rs、codex-tui、codex_vscode、Codex Desktop…），
	// 取值与 UA 的产品段相同；补上 "/" 后与 UA 走同一组产品段特征，UA 被改写时仍可识别。
	for _, v := range header.Values("Originator") {
		if v = strings.Trim(v, " \t"); v != "" && !strings.Contains(v, "/") {
			parts = append(parts, v+"/")
		}
	}
	text := strings.Join(parts, " ")
	product := InferFromText(text)
	if product == "vscode" && runtime == "vscode" {
		return Detection{Runtime: "vscode", Source: "user_agent_runtime", Role: role, Confidence: 0.35}, nil
	}
	if product != "" {
		return Detection{Product: product, Runtime: runtime, Source: "user_agent", Role: role, Confidence: 0.85}, nil
	}
	return Detection{Runtime: runtime, Source: "user_agent_runtime", Role: role, Confidence: 0.35}, nil
}

// InferFromHeaders preserves the legacy one-field contract for callers that
// have not yet adopted structured attribution.
func InferFromHeaders(header http.Header) (string, error) {
	detection, err := DetectFromHeaders(header)
	if detection.Product != "" {
		return detection.Product, err
	}
	return detection.Runtime, err
}
