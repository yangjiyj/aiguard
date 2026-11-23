package handler

import (
	"os"
	"testing"
)

// TestStreamLLMResponsesEnabled_DefaultOff 锁定流式回写开关契约：
// 默认（env 未设/为空）必须关闭——关闭时 handleMITM 恒走原 buffer 路径，行为与改动前逐字节一致；
// 仅 "true"/"1"（大小写不敏感）开启；其它值一律关闭（避免误开启高风险流式分支）。
func TestStreamLLMResponsesEnabled_DefaultOff(t *testing.T) {
	const key = "PROXY_STREAM_LLM_RESPONSES"
	orig, had := os.LookupEnv(key)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, orig)
		} else {
			_ = os.Unsetenv(key)
		}
	})

	cases := map[string]bool{
		"":      false, // 未设/空 → 默认关闭
		"false": false,
		"0":     false,
		"no":    false,
		"off":   false,
		"yes":   false,
		"true":  true,
		"TRUE":  true,
		" True ": true, // 前后空白被 TrimSpace
		"1":     true,
	}
	for val, want := range cases {
		if val == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, val)
		}
		if got := streamLLMResponsesEnabled(); got != want {
			t.Errorf("streamLLMResponsesEnabled() with %q=%q = %v, want %v", key, val, got, want)
		}
	}
}
