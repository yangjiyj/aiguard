package billingmedia

import (
	"regexp"
	"strings"
)

type ImageVariantUsage struct {
	Size    string `json:"size"`
	Quality string `json:"quality"`
	Count   int64  `json:"count"`
}

var dimensionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,79}$`)

func Dimension(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func ValidDimension(value string, allowWildcard bool) bool {
	value = Dimension(value)
	return value == "" || allowWildcard && value == "*" || dimensionPattern.MatchString(value)
}

type ImageModelTemplate struct {
	ID             string   `json:"id"`
	ModelPatterns  []string `json:"model_patterns"`
	Label          string   `json:"label"`
	Mode           string   `json:"mode"`
	Sizes          []string `json:"sizes"`
	Qualities      []string `json:"qualities"`
	DefaultSize    string   `json:"default_size"`
	DefaultQuality string   `json:"default_quality"`
	Basis          string   `json:"basis"`
	Reference      string   `json:"reference"`
}

type ToolCapability struct {
	ReferencePricePerThousandMicros *int64   `json:"reference_price_per_thousand_micros,omitempty"`
	ReferenceCurrency               string   `json:"reference_currency,omitempty"`
	ReferenceURL                    string   `json:"reference_url,omitempty"`
	ReferenceBasis                  string   `json:"reference_basis,omitempty"`
	ReferenceKey                    string   `json:"reference_key,omitempty"`
	Name                            string   `json:"name"`
	Label                           string   `json:"label"`
	Unit                            string   `json:"unit"`
	Evidence                        []string `json:"evidence"`
	Support                         string   `json:"support"`
}

func ImageTemplates() []ImageModelTemplate {
	const reference = "https://github.com/QuantumNous/new-api/blob/1d4328e97417a043a161a0dd30a5b129be3ace49/"
	return []ImageModelTemplate{
		{ID: "gpt-image-token", ModelPatterns: []string{"gpt-image-1", "gpt-image-1-mini", "gpt-image-1.5", "gpt-image-2", "gpt-image-2.5-sunburst", "gpt-image-2.5-flare"}, Label: "GPT Image · 多模态 Token", Mode: "token", Sizes: []string{"auto", "1024x1024", "1536x1024", "1024x1536"}, Qualities: []string{"auto", "low", "medium", "high"}, DefaultSize: "auto", DefaultQuality: "auto", Basis: "文本输入、图像输入、缓存和图像输出分别按实际 Token 计费；尺寸和质量影响实际用量。具体可用参数以渠道为准。", Reference: reference + "setting/billing_setting/builtin_billing.go"},
		{ID: "dall-e-3-legacy", ModelPatterns: []string{"dall-e-3"}, Label: "DALL·E 3 · 兼容渠道按张", Mode: "per_image", Sizes: []string{"1024x1024", "1024x1792", "1792x1024"}, Qualities: []string{"standard", "hd"}, DefaultSize: "1024x1024", DefaultQuality: "standard", Basis: "兼容旧模型：按尺寸、质量分别配置每张价；OpenAI 已退役该模型，仅用于仍支持的渠道。", Reference: reference + "relaykit/dto/legacy_dalle_image.go"},
		{ID: "dall-e-2-legacy", ModelPatterns: []string{"dall-e-2", "dall-e"}, Label: "DALL·E 2 · 兼容渠道按张", Mode: "per_image", Sizes: []string{"256x256", "512x512", "1024x1024"}, Qualities: []string{"standard"}, DefaultSize: "1024x1024", DefaultQuality: "standard", Basis: "兼容旧模型：分尺寸配置每张价；仅用于仍支持的渠道。", Reference: reference + "relaykit/dto/legacy_dalle_image.go"},
		{ID: "custom-image", ModelPatterns: []string{}, Label: "自定义生图渠道", Mode: "per_image", Sizes: []string{}, Qualities: []string{}, Basis: "按渠道合同选择 Token 或按张规格计费；结构模板不预填金额。", Reference: ""},
	}
}

func SuggestedImageTemplate(model string) (string, bool) {
	model = Dimension(model)
	for _, v := range ImageTemplates() {
		for _, pattern := range v.ModelPatterns {
			if pattern == model || strings.HasSuffix(pattern, "*") && strings.HasPrefix(model, strings.TrimSuffix(pattern, "*")) {
				return v.ID, true
			}
		}
	}
	return "custom-image", false
}

func ToolCapabilities() []ToolCapability {
	native := map[string][]string{
		"web_search":                    {"usage.tool_calls", "Anthropic server_tool_use.web_search_requests", "Responses web_search_call"},
		"web_search_preview":            {"usage.tool_calls", "Responses web_search_preview_call"},
		"file_search":                   {"usage.tool_calls", "Responses file_search_call"},
		"image_generation":              {"usage.tool_calls", "Responses image_generation_call"},
		"google_search":                 {"usage.tool_calls", "Gemini groundingMetadata.webSearchQueries"},
		"google_search_grounded_prompt": {"usage.tool_calls", "Gemini groundingMetadata 命中 prompt"},
		"web_fetch":                     {"usage.tool_calls", "Anthropic server_tool_use.web_fetch_requests"},
		"bing_web_search":               {"Responses tool_usage.web_search.num_requests"},
	}
	names := [][2]string{{"web_search", "联网搜索"}, {"web_search_preview", "联网搜索预览"}, {"file_search", "文件检索"}, {"image_generation", "内置图片生成"}, {"google_search", "Google 搜索查询"}, {"google_search_grounded_prompt", "Google 搜索增强请求"}, {"web_fetch", "网页读取"}, {"bing_web_search", "Bing 搜索"}, {"search_std", "智谱标准搜索"}, {"search_pro", "智谱高级搜索"}, {"search_pro_sogou", "智谱搜狗搜索"}, {"search_pro_quark", "智谱夸克搜索"}, {"search_strategy_turbo", "阿里搜索 Turbo"}, {"search_strategy_max", "阿里搜索 Max"}, {"search_strategy_agent", "阿里搜索 Agent"}, {"search_strategy_agent_max", "阿里搜索 Agent Max"}, {"x_search_posts", "xAI 帖子搜索"}, {"x_search_profiles", "xAI 用户搜索"}}
	result := make([]ToolCapability, 0, len(names))
	for _, v := range names {
		evidence, supported := native[v[0]]
		support := "native"
		if !supported {
			evidence = []string{"usage.tool_calls 中上游实际执行次数"}
			support = "usage_counter"
		}
		unit := "per_thousand_calls"
		if v[0] == "google_search_grounded_prompt" {
			unit = "per_thousand_grounded_prompts"
		}
		result = append(result, ToolCapability{Name: v[0], Label: v[1], Unit: unit, Evidence: evidence, Support: support})
	}
	return result
}

// Static defaults audited against this New API commit. These are references,
// never provider capability promises or automatically active gateway prices.
func ToolCapabilitiesForModel(model string) []ToolCapability {
	model = strings.ToLower(strings.TrimSpace(model))
	defaults := map[string]int64{
		"web_search": 10_000_000, "web_search_preview": 10_000_000,
		"file_search": 2_500_000, "google_search": 14_000_000,
		"image_generation": 150_000_000, "bing_web_search": 14_000_000,
		"search_std": 10_000_000, "search_pro": 30_000_000,
		"search_pro_sogou": 50_000_000, "search_pro_quark": 50_000_000,
		"search_strategy_turbo": 3_000_000, "search_strategy_max": 4_000_000,
		"search_strategy_agent": 4_000_000, "search_strategy_agent_max": 4_000_000,
		"x_search_posts": 5_000_000, "x_search_profiles": 10_000_000,
	}
	type override struct {
		tool, prefix string
		amount       int64
	}
	overrides := []override{
		{"web_search_preview", "gpt-4o", 25_000_000},
		{"web_search_preview", "gpt-4.1", 25_000_000},
		{"web_search_preview", "gpt-4o-mini", 25_000_000},
		{"web_search_preview", "gpt-4.1-mini", 25_000_000},
		{"web_search", "grok", 5_000_000},
		{"google_search", "gemini-1.5", 0}, {"google_search", "gemini-2.0", 0}, {"google_search", "gemini-2.5", 0},
		{"google_search_grounded_prompt", "gemini-1.5", 35_000_000},
		{"google_search_grounded_prompt", "gemini-2.0", 35_000_000},
		{"google_search_grounded_prompt", "gemini-2.5", 35_000_000},
	}
	result := ToolCapabilities()
	for i := range result {
		tool := &result[i]
		amount, found := defaults[tool.Name]
		key := tool.Name
		longest := 0
		for _, rule := range overrides {
			if rule.tool == tool.Name && strings.HasPrefix(model, rule.prefix) && len(rule.prefix) > longest {
				amount, found, key, longest = rule.amount, true, tool.Name+":"+rule.prefix+"*", len(rule.prefix)
			}
		}
		if !found {
			continue
		}
		tool.ReferencePricePerThousandMicros = &amount
		tool.ReferenceCurrency = "USD"
		if strings.HasPrefix(tool.Name, "search_") {
			tool.ReferenceCurrency = "CNY"
		}
		tool.ReferenceURL = "https://github.com/QuantumNous/new-api/blob/1d4328e97417a043a161a0dd30a5b129be3ace49/setting/operation_setting/tools.go"
		tool.ReferenceKey = key
		tool.ReferenceBasis = "NewAPI 通用默认；实际工具可用性和合同价以渠道为准。显式采用后才计费，不转换币种。"
		if longest > 0 {
			tool.ReferenceBasis = "NewAPI 模型前缀覆盖规则；实际工具可用性和合同价以渠道为准。显式采用后才计费，不转换币种。"
		}
	}
	return result
}
