package llmcatalog

import "testing"

func TestABChatGPTTelemetryPathIsExact(t *testing.T) {
	for _, tc := range []struct {
		host, path string
		want       bool
	}{
		{"ab.chatgpt.com", "/v1/rgstr", true}, {"chatgpt.com", "/ces/v1/rgstr", true},
		// Statsig experiment bootstrap: SDK/device metadata, no dialogue content.
		{"ab.chatgpt.com", "/v1/initialize", true}, {"ab.chatgpt.com", "/v1/initialize/extra", false},
		{"ab.chatgpt.com", "/v1/responses", false}, {"ab.chatgpt.com.evil.test", "/v1/rgstr", false},
		{"ab.chatgpt.com", "/v1/rgstr/conversation", false},
		// 2026-09 实测：Codex/ChatGPT 客户端的 OTLP 指标与 SDK 异常上报此前被当
		// unknown 对话流量入队（16 分片/分钟 × 24h），与 rgstr/initialize 同属遥测。
		{"ab.chatgpt.com", "/v1/sdk_exception", true},
		{"ab.chatgpt.com", "/otlp/v1/metrics", true},
		{"ab.chatgpt.com", "/otlp/v1/traces", true},
		{"ab.chatgpt.com", "/otlp/v1/logs", true},
		// 对话端点哪怕长得像遥测也不得放行：路径混淆防护
		{"ab.chatgpt.com", "/v1/sdk_exception/messages", false},
		{"ab.chatgpt.com", "/otlp/v1/metrics/chat", false},
	} {
		if got := IsTelemetry(tc.host, tc.path); got != tc.want {
			t.Errorf("%s%s=%v", tc.host, tc.path, got)
		}
	}
}
