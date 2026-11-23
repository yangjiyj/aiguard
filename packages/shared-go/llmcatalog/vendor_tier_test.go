package llmcatalog

import "testing"

func TestBigVendorsKeepRealNameAndAreNotMasked(t *testing.T) {
	bigVendors := []string{
		"tencent", "alibaba", "baidu", "bytedance", "huawei", "iflytek",
		"deepseek", "moonshot", "zhipu", "minimax", "stepfun", "lingyiwanwu",
		"baichuan", "kunlun", "qihoo360", "wps",
		"openai", "anthropic", "google", "microsoft", "meta", "xai", "mistral",
		// 大小写 / 空白不敏感
		"TENCENT", " OpenAI ",
	}
	for _, v := range bigVendors {
		if !IsBigVendor(v) {
			t.Errorf("IsBigVendor(%q) = false, want true", v)
		}
		if IsMaskedProvider(v) {
			t.Errorf("IsMaskedProvider(%q) = true, want false（大厂保留真名，不脱敏）", v)
		}
	}
}

func TestNonBigVendorsAreMasked(t *testing.T) {
	// examplegw（自营中转）是最初诉求点；cursor/perplexity/openrouter/siliconflow/
	// github/midjourney 等一切非大厂上游同样按「第三方」脱敏。
	masked := []string{
		"examplegw", "Huoxianbao", "cursor", "perplexity", "openrouter",
		"siliconflow", "github", "midjourney", "poe", "together", "replicate",
	}
	for _, v := range masked {
		if IsBigVendor(v) {
			t.Errorf("IsBigVendor(%q) = true, want false", v)
		}
		if !IsMaskedProvider(v) {
			t.Errorf("IsMaskedProvider(%q) = false, want true（非大厂应脱敏为第三方）", v)
		}
	}
}

func TestEmptyAndUnknownAreNotMasked(t *testing.T) {
	// 空/unknown 语义是「未识别 / 直连调用」，不是第三方中转，绝不能并入第三方。
	for _, v := range []string{"", "   ", "unknown", "UNKNOWN"} {
		if IsMaskedProvider(v) {
			t.Errorf("IsMaskedProvider(%q) = true, want false（空/unknown 不脱敏）", v)
		}
	}
}

func TestBigVendorAllowlistEntriesExistInCatalog(t *testing.T) {
	// 护栏：白名单里的每个 provider id 都必须在 catalog 里有对应条目，
	// 否则说明是拼写错误或该 adapter 已被移除，白名单会静默失效。
	catalogProviders := map[string]bool{}
	for _, e := range Catalog() {
		catalogProviders[e.Provider] = true
	}
	for _, id := range BigVendorProviders() {
		if !catalogProviders[id] {
			t.Errorf("大厂白名单 id %q 在 catalog 中找不到对应条目（拼写错误或 adapter 已移除？）", id)
		}
	}
}

func TestThirdPartyLabelStable(t *testing.T) {
	if ThirdPartyLabel != "第三方" {
		t.Fatalf("ThirdPartyLabel = %q, want 第三方", ThirdPartyLabel)
	}
}
