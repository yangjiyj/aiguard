package config

import (
	"testing"
	"time"
)

func TestStreamKeepaliveIntervalParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", DefaultStreamKeepaliveInterval}, // 默认开启，开箱支持 Dify
		{"0", 0},                             // 显式关闭
		{"0s", 0},
		{"false", 0}, // 常见的"关"写法都按关闭处理，不会误开
		{"OFF", 0},
		{"disabled", 0},
		{"no", 0},
		{"15s", 15 * time.Second},
		{"1m", time.Minute},
		{"15", DefaultStreamKeepaliveInterval},    // 漏单位：告警后用默认值，不是 15ns 也不悄悄关掉
		{"-5s", DefaultStreamKeepaliveInterval},   // 负值：默认值
		{"bogus", DefaultStreamKeepaliveInterval}, // 非法：默认值
		{"10ms", time.Second},                     // 过小：抬到 1s
	}
	for _, c := range cases {
		t.Setenv("GATEWAY_STREAM_KEEPALIVE_INTERVAL", c.raw)
		if got := streamKeepaliveInterval(); got != c.want {
			t.Errorf("raw=%q got %v want %v", c.raw, got, c.want)
		}
	}
}
