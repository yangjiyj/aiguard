package provider

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// anthropicModelProfile 描述某一代 Claude 模型对 Messages 请求面的硬约束。
// Anthropic 在各代之间改过接受的参数：把 Chat 客户端的字段原样透传，
// 上游会直接 400（max_tokens 超上限、非默认 temperature、budget_tokens 等）。
// 零值表示未知模型；Anthropic 适配器会另加通用输出上限。
type anthropicModelProfile struct {
	// MaxOutputTokens 是模型允许的最大 max_tokens；0 表示未知、不钳制。
	MaxOutputTokens int
	// RejectsSampling 为 true 时非默认 temperature/top_p/top_k 会被上游 400
	// （Opus 4.7+、Sonnet 5、Fable/Mythos）。
	RejectsSampling bool
	// AdaptiveThinking 为 true 时模型用 adaptive thinking + effort，
	// thinking.type=enabled + budget_tokens 已被移除或弃用（4.6 及以后）。
	AdaptiveThinking bool
	// ThinkingAlwaysOn 为 true 时 thinking 不能关闭，显式 disabled 会 400（Fable/Mythos）。
	ThinkingAlwaysOn bool
	// LegacyThinking 为 true 时模型只认 thinking.type=enabled + budget_tokens，
	// 且不支持 output_config.effort（Haiku 4.5、Sonnet 4.5、Opus 4.5 及更早）。
	// 表外的 claude-* 新模型不设此标记，按当前一代（adaptive + effort）处理。
	LegacyThinking bool
	// ThinkingOff 描述模型接受的「关闭思考」写法；零值 thinkingOffUnknown 表示未验证，
	// 原生 Messages 路径对这类模型不改写 disabled / between_tools，保持客户端原样。
	ThinkingOff anthropicThinkingOff
	// RejectsBudgetTokens 为 true 时 thinking.type=enabled + budget_tokens 会被上游 400
	// （Opus 4.7/4.8/5/5.5、Sonnet 5/5.5、Haiku 5.5、Fable/Mythos）。Opus/Sonnet 4.6 只是弃用、
	// 仍可用，不设此标记，避免无谓改写客户端显式给出的预算。
	RejectsBudgetTokens bool
}

// anthropicThinkingOff 是模型接受的关闭思考方式。
type anthropicThinkingOff int

const (
	// thinkingOffUnknown：未验证，不改写。
	thinkingOffUnknown anthropicThinkingOff = iota
	// thinkingOffDisabled：接受 {"type":"disabled"}，不接受 between_tools。
	thinkingOffDisabled
	// thinkingOffBetweenTools：不接受 disabled，关闭须发 {"type":"between_tools"}（目前仅 Sonnet 5.5）。
	thinkingOffBetweenTools
	// thinkingOffOmit：disabled 与 between_tools 都不接受，也没有关闭方式，只能省略 thinking 字段。
	thinkingOffOmit
)

func (p anthropicModelProfile) legacyThinking() bool {
	return p.LegacyThinking
}

// anthropicModelProfiles 按模型名前缀匹配，顺序即优先级；前缀要写到能区分
// claude-opus-4-5 与 claude-opus-5 这类同前缀家族。
var anthropicModelProfiles = []struct {
	prefix  string
	profile anthropicModelProfile
}{
	// 思考关闭方式与 budget_tokens 支持情况的依据：
	//   - 5.5 三个模型：2026-10-22 客户现场经网关实测（opus-5-5 无关闭方式；sonnet-5-5 只认 between_tools；
	//     haiku-5-5 认 disabled、不认 between_tools；三者都拒 enabled+budget_tokens）。
	//   - 其余型号：按官方迁移文档；现场未逐一实测，见 docs/operations/gateway-anthropic-output-limits.md。
	{"claude-fable-", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingAlwaysOn: true, ThinkingOff: thinkingOffOmit, RejectsBudgetTokens: true}},
	{"claude-mythos-", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingAlwaysOn: true, ThinkingOff: thinkingOffOmit, RejectsBudgetTokens: true}},
	{"claude-opus-5-5", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingAlwaysOn: true, ThinkingOff: thinkingOffOmit, RejectsBudgetTokens: true}},
	{"claude-sonnet-5-5", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingAlwaysOn: true, ThinkingOff: thinkingOffBetweenTools, RejectsBudgetTokens: true}},
	{"claude-haiku-5-5", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingAlwaysOn: true, ThinkingOff: thinkingOffDisabled, RejectsBudgetTokens: true}},
	{"claude-opus-5", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingOff: thinkingOffDisabled, RejectsBudgetTokens: true}},
	{"claude-opus-4-8", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingOff: thinkingOffDisabled, RejectsBudgetTokens: true}},
	{"claude-opus-4-7", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingOff: thinkingOffDisabled, RejectsBudgetTokens: true}},
	{"claude-sonnet-5", anthropicModelProfile{MaxOutputTokens: 128000, RejectsSampling: true, AdaptiveThinking: true, ThinkingOff: thinkingOffDisabled, RejectsBudgetTokens: true}},
	{"claude-opus-4-6", anthropicModelProfile{MaxOutputTokens: 128000, AdaptiveThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-sonnet-4-6", anthropicModelProfile{MaxOutputTokens: 128000, AdaptiveThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-haiku-4-5", anthropicModelProfile{MaxOutputTokens: 64000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-sonnet-4-5", anthropicModelProfile{MaxOutputTokens: 64000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-opus-4-5", anthropicModelProfile{MaxOutputTokens: 64000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	// 兜底整代：claude-opus-4-1 / claude-opus-4-20250514 / claude-sonnet-4-20250514 等。
	{"claude-opus-4", anthropicModelProfile{MaxOutputTokens: 32000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-sonnet-4", anthropicModelProfile{MaxOutputTokens: 64000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-haiku-4", anthropicModelProfile{MaxOutputTokens: 64000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	{"claude-3-7-sonnet", anthropicModelProfile{MaxOutputTokens: 64000, LegacyThinking: true, ThinkingOff: thinkingOffDisabled}},
	// claude-3-5 及更早不支持 thinking，关闭方式留空（不改写）。
	{"claude-3-5-haiku", anthropicModelProfile{MaxOutputTokens: 8192, LegacyThinking: true}},
	{"claude-3-5-sonnet", anthropicModelProfile{MaxOutputTokens: 8192, LegacyThinking: true}},
	{"claude-3-", anthropicModelProfile{MaxOutputTokens: 4096, LegacyThinking: true}},
	// 表外的新 claude-* 模型（例如尚未收录的 claude-opus-6）不设任何关闭方式 / 预算拒绝标记：
	// 原生 Messages 路径对它们不改写 thinking，宁可保持现状，也不按旧代际猜测去改客户端请求。
}

// 未知 Anthropic 上游仅施加输出兜底，不假设采样和思考能力。
const anthropicGenericMaxOutputTokens = 128000
const anthropicMaxOutputTokensEnv = "UAG_ANTHROPIC_MAX_OUTPUT_TOKENS"
const anthropicMaxOutputTokensDefaultEnv = "UAG_ANTHROPIC_MAX_OUTPUT_TOKENS_DEFAULT"

type anthropicOutputOverride struct {
	prefix string
	limit  int
}

var (
	anthropicMaxOutputOverridesOnce sync.Once
	anthropicMaxOutputOverrides     []anthropicOutputOverride
	anthropicDefaultMaxOutputTokens = anthropicGenericMaxOutputTokens
	anthropicUnknownModelWarnings   sync.Map
	anthropicBedrockVersionSuffix   = regexp.MustCompile(`-v[0-9]+:[0-9]+$`)
)

// normalizeAnthropicModelName 去掉路由路径、供应商标识和平台版本后缀，仅用于匹配。
func normalizeAnthropicModelName(candidate string) string {
	name := strings.ToLower(strings.TrimSpace(candidate))
	if index := strings.LastIndex(name, "/"); index >= 0 {
		name = name[index+1:]
	}
	for _, prefix := range []string{"us.anthropic.", "eu.anthropic.", "apac.anthropic.", "global.anthropic.", "anthropic."} {
		if strings.HasPrefix(name, prefix) {
			name = strings.TrimPrefix(name, prefix)
			break
		}
	}
	name, _, _ = strings.Cut(name, "@")
	return anthropicBedrockVersionSuffix.ReplaceAllString(name, "")
}

func loadAnthropicMaxOutputOverrides() {
	anthropicMaxOutputOverrides = nil
	anthropicDefaultMaxOutputTokens = anthropicGenericMaxOutputTokens
	if raw := strings.TrimSpace(os.Getenv(anthropicMaxOutputTokensDefaultEnv)); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			log.Printf("警告：%s 必须是正整数，使用默认上限", anthropicMaxOutputTokensDefaultEnv)
		} else {
			anthropicDefaultMaxOutputTokens = limit
		}
	}
	raw := strings.TrimSpace(os.Getenv(anthropicMaxOutputTokensEnv))
	if raw == "" {
		return
	}
	add := func(key, value string) {
		key = strings.ToLower(strings.TrimSpace(key))
		limit, err := strconv.Atoi(strings.TrimSpace(value))
		if key == "" || err != nil || limit <= 0 {
			log.Printf("警告：%s 的条目 %q 无效，必须配置非空前缀和正整数上限", anthropicMaxOutputTokensEnv, key)
			return
		}
		anthropicMaxOutputOverrides = append(anthropicMaxOutputOverrides, anthropicOutputOverride{key, limit})
	}
	if strings.HasPrefix(raw, "{") {
		var entries map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			log.Printf("警告：%s JSON 对象解析失败，忽略覆盖配置", anthropicMaxOutputTokensEnv)
			return
		}
		for key, value := range entries {
			add(key, string(value))
		}
	} else {
		for _, entry := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(entry, "=")
			if !ok {
				log.Printf("警告：%s 的条目缺少等号，已忽略", anthropicMaxOutputTokensEnv)
				continue
			}
			add(key, value)
		}
	}
	// 长前缀优先；相同长度按字典序，避免 JSON 对象遍历顺序影响匹配结果。
	sort.SliceStable(anthropicMaxOutputOverrides, func(i, j int) bool {
		a, b := anthropicMaxOutputOverrides[i].prefix, anthropicMaxOutputOverrides[j].prefix
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})
}

func anthropicOutputOverrideFor(candidate string) (int, bool) {
	raw := strings.ToLower(strings.TrimSpace(candidate))
	name := normalizeAnthropicModelName(candidate)
	for _, override := range anthropicMaxOutputOverrides {
		if raw != "" && (strings.HasPrefix(raw, override.prefix) || strings.HasPrefix(name, override.prefix)) {
			return override.limit, true
		}
	}
	return 0, false
}

// resolveAnthropicModelProfile 优先识别上游模型，其次识别客户端模型。
func resolveAnthropicModelProfile(candidates ...string) anthropicModelProfile {
	anthropicMaxOutputOverridesOnce.Do(loadAnthropicMaxOutputOverrides)
	for _, candidate := range candidates {
		profile, ok := lookupAnthropicModelProfile(normalizeAnthropicModelName(candidate))
		if !ok {
			continue
		}
		if limit, overridden := anthropicOutputOverrideFor(candidate); overridden {
			profile.MaxOutputTokens = limit
		}
		return profile
	}
	for _, candidate := range candidates {
		if limit, ok := anthropicOutputOverrideFor(candidate); ok {
			return anthropicModelProfile{MaxOutputTokens: limit}
		}
	}
	return anthropicModelProfile{}
}

func lookupAnthropicModelProfile(name string) (anthropicModelProfile, bool) {
	for _, entry := range anthropicModelProfiles {
		if strings.HasPrefix(name, entry.prefix) {
			return entry.profile, true
		}
	}
	return anthropicModelProfile{}, false
}

// anthropicRequestModelProfile 只在 Anthropic 适配器中使用；别名也必须受兜底上限约束。
func anthropicRequestModelProfile(candidates ...string) anthropicModelProfile {
	profile := resolveAnthropicModelProfile(candidates...)
	if profile.MaxOutputTokens > 0 {
		return profile
	}
	model := ""
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) != "" {
			model = candidate
			break
		}
	}
	if _, loaded := anthropicUnknownModelWarnings.LoadOrStore(model, struct{}{}); !loaded {
		log.Printf("警告：未知 Anthropic 模型 %q，使用通用输出上限 %d", model, anthropicDefaultMaxOutputTokens)
	}
	profile.MaxOutputTokens = anthropicDefaultMaxOutputTokens
	return profile
}

// clampAnthropicMaxTokens 把请求里的 max_tokens 收敛到模型输出上限。
// 客户端（WorkBuddy、Codex）不认识模型时会把自己的上下文窗口当 max_tokens 发
// （对 claude-opus-5 发 1000000），Anthropic 直接 400 "max_tokens: 1000000 > 128000"。
// 返回值表示是否发生了钳制。
func clampAnthropicMaxTokens(request map[string]any, profile anthropicModelProfile) bool {
	if profile.MaxOutputTokens <= 0 {
		return false
	}
	requested, ok := anthropicIntValue(request["max_tokens"])
	if !ok || requested <= int64(profile.MaxOutputTokens) {
		return false
	}
	request["max_tokens"] = profile.MaxOutputTokens
	return true
}

// anthropicIntValue 把 JSON 解码出来的数字（json.Number / float64 / int）读成整数。
func anthropicIntValue(raw any) (int64, bool) {
	switch value := raw.(type) {
	case json.Number:
		if parsed, err := value.Int64(); err == nil {
			return parsed, true
		}
		if parsed, err := value.Float64(); err == nil {
			return int64(parsed), true
		}
		return 0, false
	case float64:
		return int64(value), true
	case float32:
		return int64(value), true
	case int:
		return int64(value), true
	case int64:
		return value, true
	case int32:
		return int64(value), true
	default:
		return 0, false
	}
}

func anthropicFloatValue(raw any) (float64, bool) {
	switch value := raw.(type) {
	case json.Number:
		parsed, err := value.Float64()
		return parsed, err == nil
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	default:
		return 0, false
	}
}
