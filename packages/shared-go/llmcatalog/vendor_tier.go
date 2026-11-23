package llmcatalog

import (
	"sort"
	"strings"
)

// ThirdPartyLabel 是非大厂上游在客户可见审计页的统一脱敏展示名。
//
// 面向客户交付时，「服务商」只暴露主流大厂的真实厂商名；其余上游（自营/第三方
// 中转、聚合平台、小众服务）一律显示为「第三方」，避免把中转品牌暴露给客户。
const ThirdPartyLabel = "第三方"

// bigVendorProviders 是保留真实厂商名的「大厂」白名单（provider id，全小写）。
//
// 口径：主流大模型厂商与云厂商。白名单之外的一律按第三方脱敏。增删厂商只改这一处；
// 这里的 provider id 对应 aiadapters/adapters/*.json 里的 "provider" 字段
// （vendor_tier_test.go 有护栏，确保每个 id 都能在 catalog 里找到对应条目）。
var bigVendorProviders = map[string]struct{}{
	// 海外主流大模型厂商 / 云
	"openai":    {},
	"anthropic": {},
	"google":    {},
	"microsoft": {},
	"meta":      {},
	"xai":       {},
	"mistral":   {},
	// 国内主流大模型厂商 / 云
	"tencent":     {},
	"alibaba":     {},
	"baidu":       {},
	"bytedance":   {},
	"huawei":      {},
	"iflytek":     {},
	"deepseek":    {},
	"moonshot":    {},
	"zhipu":       {},
	"minimax":     {},
	"stepfun":     {},
	"lingyiwanwu": {},
	"baichuan":    {},
	"kunlun":      {},
	"qihoo360":    {},
	"wps":         {},
}

func normalizeProviderID(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

// IsBigVendor 判断 provider id 是否属于保留真名的大厂白名单（大小写/空白不敏感）。
func IsBigVendor(provider string) bool {
	_, ok := bigVendorProviders[normalizeProviderID(provider)]
	return ok
}

// IsMaskedProvider 判断某上游是否应脱敏为「第三方」：
// 有明确 provider 标识、非 unknown、且不在大厂白名单内。
//
// 空 / unknown 不脱敏——那代表「未识别 / 直连调用」，语义与「第三方中转」不同，
// 前端另有展示（直连调用），不应被并入第三方桶。
func IsMaskedProvider(provider string) bool {
	p := normalizeProviderID(provider)
	if p == "" || p == "unknown" {
		return false
	}
	return !IsBigVendor(p)
}

// BigVendorProviders 返回大厂白名单的 provider id 列表（全小写、已排序），
// 供 SQL NOT IN 之类需要枚举白名单的场景使用（顺序确定，便于测试与缓存）。
func BigVendorProviders() []string {
	out := make([]string, 0, len(bigVendorProviders))
	for id := range bigVendorProviders {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
