package repository

import "testing"

func TestNormalizeAlertGroupListLimit(t *testing.T) {
	// limit>0 透传；超上限 cap 到 2000（P0-C：告警列表需一次性载入以支持按类概览）。
	cases := []struct{ in, want int }{
		{0, 50},      // 未传 → 默认
		{-5, 50},     // 非法 → 默认
		{10, 10},     // 正常透传
		{500, 500},   // 200 以上不再回落，正常透传
		{2000, 2000}, // 上限
		{5000, 2000}, // 超上限 → cap 到 2000
	}
	for _, c := range cases {
		if got := normalizeAlertGroupListLimit(c.in); got != c.want {
			t.Fatalf("normalizeAlertGroupListLimit(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
