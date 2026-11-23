package handler

import "testing"

// 行业值由 UpdateTenant 接收并驱动「叠加哪些内置数据安全规则包」，属多租户配置安全面
// （AGENTS.md 强制测试）：非白名单输入绝不能落库，否则会让租户挂载到非预期/不存在的
// 行业包，造成漏检或越权读取他行业规则。normalizeIndustry 是唯一收敛点。
func TestNormalizeIndustryWhitelist(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"generic", "generic"},
		{"medical_imaging", "medical_imaging"},
		{"finance", "finance"},
		{"", "generic"},                 // 空 → 通用兜底
		{"  medical_imaging  ", "medical_imaging"}, // 容忍首尾空白
		{"MEDICAL_IMAGING", "generic"},  // 大小写不匹配 → 拒绝兜底（白名单为小写权威）
		{"healthcare", "generic"},       // 近似但非白名单 → 拒绝
		{"'; DROP TABLE tenants;--", "generic"}, // 注入样本 → 拒绝
	}
	for _, c := range cases {
		if got := normalizeIndustry(c.in); got != c.want {
			t.Errorf("normalizeIndustry(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
