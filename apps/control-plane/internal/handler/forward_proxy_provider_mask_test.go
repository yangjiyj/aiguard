package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestMaskForwardProxyProvidersMergesNonBigVendorsIntoThirdParty(t *testing.T) {
	in := []repository.ForwardProxyAccessDimension{
		{Name: "tencent", Count: 10, RiskCount: 1},
		{Name: "examplegw", Count: 5, RiskCount: 2},
		{Name: "cursor", Count: 3, RiskCount: 0},
		{Name: "openai", Count: 8, RiskCount: 0},
		{Name: "unknown", Count: 4, RiskCount: 0},
	}
	out := maskForwardProxyProviders(in)

	byName := map[string]repository.ForwardProxyAccessDimension{}
	for _, d := range out {
		if _, dup := byName[d.Name]; dup {
			t.Fatalf("输出中出现重复维度 %q: %+v", d.Name, out)
		}
		byName[d.Name] = d
	}

	// 大厂原样保留
	if byName["tencent"].Count != 10 || byName["openai"].Count != 8 {
		t.Errorf("大厂维度未保留: %+v", out)
	}
	// unknown 单独保留，不并入第三方
	if byName["unknown"].Count != 4 {
		t.Errorf("unknown 应单独保留: %+v", out)
	}
	// examplegw(5) + cursor(3) 合并进「第三方」
	third, ok := byName["第三方"]
	if !ok {
		t.Fatalf("应合并出「第三方」桶, got %+v", out)
	}
	if third.Count != 8 || third.RiskCount != 2 {
		t.Errorf("第三方 桶 = count %d risk %d, want count 8 risk 2", third.Count, third.RiskCount)
	}
	// 原始品牌名不得残留
	if _, leaked := byName["examplegw"]; leaked {
		t.Errorf("examplegw 品牌名泄露在维度里: %+v", out)
	}
	if _, leaked := byName["cursor"]; leaked {
		t.Errorf("cursor 品牌名泄露在维度里: %+v", out)
	}
	// 按 count 降序
	for i := 1; i < len(out); i++ {
		if out[i-1].Count < out[i].Count {
			t.Errorf("输出未按 count 降序: %+v", out)
			break
		}
	}
}

func TestMaskForwardProxyProvidersNoThirdPartyWhenAllBigVendors(t *testing.T) {
	in := []repository.ForwardProxyAccessDimension{
		{Name: "tencent", Count: 3},
		{Name: "openai", Count: 2},
	}
	out := maskForwardProxyProviders(in)
	for _, d := range out {
		if d.Name == "第三方" {
			t.Fatalf("全大厂时不应凭空造出第三方桶: %+v", out)
		}
	}
	if len(out) != 2 {
		t.Fatalf("全大厂应原样保留两格, got %+v", out)
	}
}
