package repository

import "testing"

// TestClampWindowHours 覆盖 ListSemanticSince 的时间窗兜底逻辑：
// 非法窗（h<=0 或 h>8760，即超过一年）回落默认 24 小时；合法窗原样透传。
// 该纯逻辑无需真 PG，故独立单测（真 DB 集成路径由 CP-2 fake + 端到端另测，
// 遵循 audit.go 现状：List 无独立单测）。
func TestClampWindowHours(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"zero_fallback", 0, 24},
		{"negative_fallback", -5, 24},
		{"passthrough_default", 24, 24},
		{"over_year_fallback", 9000, 24},
		{"passthrough_small", 12, 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clampWindowHours(c.in); got != c.want {
				t.Fatalf("clampWindowHours(%d) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}
