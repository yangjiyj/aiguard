package handler

import "testing"

func TestShouldBypassMITM(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// 存储/二进制 host → 直通
		{"ride3storage.blob.core.windows.net:443", true},
		{"blob.core.windows.net:443", true},
		{"foo.blob.core.windows.net", true},
		// CodeBuddy 自有云后端:keep-alive 上线后已摘除直通,重新走 MITM 留证 → 不直通
		{"ride-3-live-webapp.azurewebsites.net:443", false},
		// 普通 LLM/对话 host → 必须仍 MITM(不直通)
		{"chat.deepseek.com:443", false},
		{"www.doubao.com:443", false},
		{"copilot.tencent.com:443", false},
		// azurewebsites 子域不直通(blob 才直通,azurewebsites 走 MITM)
		{"other-app.azurewebsites.net:443", false},
		// 安全:相近但不同的域不得误命中
		{"evilblob.core.windows.net:443", false},
		{"blob.core.windows.net.attacker.com:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := shouldBypassMITM(c.host); got != c.want {
			t.Errorf("shouldBypassMITM(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestShouldBypassMITM_EnvExtension(t *testing.T) {
	t.Setenv("PROXY_MITM_BYPASS_SUFFIXES", ".example-cdn.com, downloads.foo.com")
	if !shouldBypassMITM("assets.example-cdn.com:443") {
		t.Error("env suffix .example-cdn.com should bypass subdomain")
	}
	if !shouldBypassMITM("downloads.foo.com:443") {
		t.Error("env exact host downloads.foo.com should bypass")
	}
	// env 不应放进 LLM 域——这里仅验证 env 解析生效,默认 LLM 域仍不命中
	if shouldBypassMITM("chat.deepseek.com:443") {
		t.Error("LLM host must never bypass")
	}
}
