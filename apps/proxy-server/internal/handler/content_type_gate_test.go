package handler

import "testing"

// TestIsModelReplyContentType_GatesOutputDLP 锁定输出 DLP 内容类型闸的契约：
// 会话回复正文(JSON/SSE/NDJSON/纯文本/未知)必须进检测；厂商前端 App 交付字节
// (导航 HTML、JS/CSS、图片/字体/wasm/二进制)必须放行——它们曾被 secret_openai_key
// 在压缩 JS 词碎片上误报为「critical OpenAI key 泄露」→403 拦死豆包/Kimi 页面。
func TestIsModelReplyContentType_GatesOutputDLP(t *testing.T) {
	cases := map[string]bool{
		// 模型回复正文 → 检测
		"text/event-stream":                true,
		"text/event-stream; charset=utf-8": true,
		"application/json":                 true,
		"application/json; charset=utf-8":  true,
		"application/connect+json":         true, // Kimi 流式会话体（走默认检测分支，须命中流式回写）
		"application/x-ndjson":             true,
		"text/plain; charset=utf-8":        true,
		"":                                 true,
		"application/something-unknown":    true,
		// App 交付 / 静态资源 / 二进制 → 放行(不进输出 DLP)
		"text/html":                             false,
		"text/html; charset=utf-8":              false,
		"application/javascript":                false,
		"application/javascript; charset=utf-8": false,
		"text/javascript":                       false,
		"text/css":                              false,
		"image/png":                             false,
		"image/webp":                            false,
		"font/woff2":                            false,
		"application/wasm":                      false,
		"application/octet-stream":              false,
	}
	for ct, want := range cases {
		if got := isModelReplyContentType(ct); got != want {
			t.Errorf("isModelReplyContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}
