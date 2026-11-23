package repository

import (
	"strings"
	"testing"
)

func TestEnrichForwardProxyCatalogLabelsMasksThirdPartyProvider(t *testing.T) {
	// examplegw：自营第三方中转 → 服务商与产品名都脱敏为「第三方」，域名保留供审计。
	item := ForwardProxyAccessRecord{
		Provider:   "examplegw",
		TargetHost: "api.example-gateway.com",
		TargetPath: "/v1/responses",
	}
	enrichForwardProxyCatalogLabels(&item)

	if item.ProviderCN != "第三方" {
		t.Errorf("ProviderCN = %q, want 第三方", item.ProviderCN)
	}
	if item.ProductCN != "第三方" {
		t.Errorf("ProductCN = %q, want 第三方（产品名也脱敏）", item.ProductCN)
	}
	if item.TargetHost != "api.example-gateway.com" {
		t.Errorf("TargetHost = %q, want 保留域名 api.example-gateway.com", item.TargetHost)
	}
}

func TestEnrichForwardProxyCatalogLabelsKeepsBigVendorName(t *testing.T) {
	// 腾讯：大厂白名单 → 保留真实厂商名与产品名，绝不脱敏。
	item := ForwardProxyAccessRecord{
		Provider:   "tencent",
		TargetHost: "yuanbao.tencent.com",
		TargetPath: "/",
	}
	enrichForwardProxyCatalogLabels(&item)

	if item.ProviderCN != "腾讯" {
		t.Errorf("ProviderCN = %q, want 腾讯", item.ProviderCN)
	}
	if item.ProductCN == "第三方" || item.ProductCN == "" {
		t.Errorf("ProductCN = %q, want 保留腾讯产品名", item.ProductCN)
	}
}

func TestEnrichForwardProxyCatalogLabelsLeavesUnknownDirectUnmasked(t *testing.T) {
	// 无 provider、无 catalog 匹配 → 不脱敏（前端显示「直连调用」，语义不同于第三方）。
	item := ForwardProxyAccessRecord{
		Provider:   "",
		TargetHost: "example.internal",
		TargetPath: "/",
	}
	enrichForwardProxyCatalogLabels(&item)

	if item.ProviderCN == "第三方" {
		t.Errorf("ProviderCN = %q, 未识别/直连上游不应被脱敏为第三方", item.ProviderCN)
	}
}

func TestBuildForwardProxyWhereThirdPartyBucketExcludesBigVendorsAndUnknown(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		Provider: "第三方",
	})
	joined := strings.Join(where, "\n")

	if !strings.Contains(joined, "NOT IN") {
		t.Fatalf("第三方 筛选应使用 NOT IN(大厂白名单) 而非等值匹配:\n%s", joined)
	}
	if !strings.Contains(joined, "'unknown'") {
		t.Fatalf("第三方 筛选应同时排除 unknown/直连:\n%s", joined)
	}
	// 大厂 id 应作为 NOT IN 的参数出现（例如 tencent / openai）。
	var hasTencent, hasOpenAI bool
	for _, a := range args {
		if s, ok := a.(string); ok {
			switch s {
			case "tencent":
				hasTencent = true
			case "openai":
				hasOpenAI = true
			}
		}
	}
	if !hasTencent || !hasOpenAI {
		t.Fatalf("第三方 筛选参数应包含大厂 id 供 NOT IN 排除: %#v", args)
	}
}

func TestBuildForwardProxyWhereExactProviderStillUsesEquality(t *testing.T) {
	where, args := buildForwardProxyWhere("tenant_default", ForwardProxyAccessFilter{
		Provider: "tencent",
	})
	joined := strings.Join(where, "\n")

	if strings.Contains(joined, "NOT IN") {
		t.Fatalf("大厂精确筛选不应退化成 NOT IN:\n%s", joined)
	}
	if !strings.Contains(joined, "= $") {
		t.Fatalf("大厂精确筛选应使用等值匹配:\n%s", joined)
	}
	var found bool
	for _, a := range args {
		if s, ok := a.(string); ok && s == "tencent" {
			found = true
		}
	}
	if !found {
		t.Fatalf("精确筛选参数应包含 'tencent': %#v", args)
	}
}
