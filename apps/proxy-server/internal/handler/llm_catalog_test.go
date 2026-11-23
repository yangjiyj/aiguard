package handler

import "testing"

func TestDetectLLMProvider_CodeBuddyObservedStudioEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		path       string
		wantRetain string
	}{
		{"chat prediction", "copilot.tencent.com", "/v2/chat/prediction", "summary"},
		{"traces", "copilot.tencent.com", "/v1/traces", "summary"},
		{"portal summary", "copilot.tencent.com", "/portal/abc/message/summary", "summary"},
		{"download host fallback", "download.codebuddy.cn", "/releases/stable/win32-x64/CodeBuddySetup.exe", "summary"},
		{"stream", "ride-3-live-webapp.azurewebsites.net", "/api/stream", "content"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectLLMProvider(tt.host, tt.path)
			if !got.Known {
				t.Fatalf("detectLLMProvider(%q, %q) not known", tt.host, tt.path)
			}
			if got.Provider != "tencent" || got.Product != "codebuddy" || got.RiskProfile != "ai_ide_agent" || got.RetainLevel != tt.wantRetain {
				t.Fatalf("detectLLMProvider(%q, %q) = provider=%q product=%q retain=%q risk=%q, want tencent/codebuddy/%s/ai_ide_agent", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, got.RiskProfile, tt.wantRetain)
			}
		})
	}
}

func TestDetectLLMProvider_PublicModelHostsAndPaths(t *testing.T) {
	tests := []struct {
		host         string
		path         string
		wantProvider string
	}{
		{"api.openai.com:443", "/v1/responses", "openai"},
		{"api.anthropic.com", "/v1/messages", "anthropic"},
		{"ark.cn-beijing.volces.com", "/api/v3/chat/completions", "bytedance"},
		{"dashscope.aliyuncs.com", "/compatible-mode/v1/chat/completions", "alibaba"},
		{"dashscope.aliyuncs.com", "/api/v1/services/aigc/text-generation/generation", "alibaba"},
		{"hunyuan.tencentcloudapi.com", "/", "tencent"},
		{"maas-cn-southwest-2.modelarts-maas.com", "/v1/chat/completions", "huawei"},
		{"api.moonshot.cn", "/v1/chat/completions", "moonshot"},
		{"open.bigmodel.cn", "/api/paas/v4/chat/completions", "zhipu"},
		{"generativelanguage.googleapis.com", "/v1beta/models/gemini-pro:generateContent", "google"},
		{"api.deepseek.com:443", "/", "deepseek"},
		{"chat.deepseek.com", "/api/v0/chat/completion", "deepseek"},
		{"www.kimi.com", "/apiv2/session/Chat", "moonshot"},
		{"gator.volces.com", "/list", "bytedance"},
		{"chat2.qianwen.com", "/", "alibaba"},
		{"chat2-api.qianwen.com", "/api/chat/completions", "alibaba"},
		{"api.qianwen.com", "/api/chat/completions", "alibaba"},
		{"a-api.anthropic.com", "/api/organizations", "anthropic"},
	}

	for _, tt := range tests {
		got := detectLLMProvider(tt.host, tt.path)
		if got.Provider != tt.wantProvider {
			t.Fatalf("detectLLMProvider(%q, %q) provider = %q, want %q", tt.host, tt.path, got.Provider, tt.wantProvider)
		}
		if !got.Known {
			t.Fatalf("detectLLMProvider(%q, %q) Known = false", tt.host, tt.path)
		}
	}
}

func TestDetectLLMProvider_RejectsUnknownRegularSites(t *testing.T) {
	got := detectLLMProvider("example.com", "/news")
	if got.Known || got.Provider != "" {
		t.Fatalf("regular site detected as LLM: %+v", got)
	}
}

func TestProxyHandlerIsLLMRequestUsesHostAndPath(t *testing.T) {
	h := &ProxyHandler{}
	if !h.isLLMRequest("ark.cn-beijing.volces.com", "/api/v3/chat/completions") {
		t.Fatal("doubao API should be recognized as LLM request")
	}
	if !h.isLLMRequest("dashscope.aliyuncs.com", "/api/v1/services/aigc/text-generation/generation") {
		t.Fatal("qwen API should be recognized as LLM request")
	}
	if h.isLLMRequest("example.com", "/v1/models") {
		t.Fatal("generic regular site should not be recognized from path alone")
	}
}

func TestDetectLLMProvider_CustomerMatrixRetention(t *testing.T) {
	content := []struct {
		name        string
		host        string
		path        string
		wantProduct string
	}{
		{"DeepSeek web chat", "chat.deepseek.com", "/api/v0/chat/completion", "deepseek_chat"},
		{"Doubao web chat", "www.doubao.com", "/samantha/chat/completion", "doubao"},
		{"Kimi web chat", "www.kimi.com", "/apiv2/session/Chat", "kimi"},
		{"Qwen web chat", "chat2-api.qianwen.com", "/api/chat/completions", "qwen_chat"},
		{"ChatGPT web conversation", "chatgpt.com", "/backend-api/f/conversation", "chatgpt"},
		{"Gemini stream generate", "gemini.google.com", "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate", "gemini"},
		{"Claude web completion", "a-api.anthropic.com", "/api/organizations/org/chat_conversations/c1/completion", "claude"},
		{"Codex company gateway", "api.example-gateway.com", "/v1/responses", "examplegw_gateway"},
		{"WorkBuddy official chat", "copilot.tencent.com", "/v2/chat/completions", "codebuddy"},
		{"WorkBuddy invoke chat", "ride-3-live-webapp.azurewebsites.net", "/api/invoke", "codebuddy"},
		{"WorkBuddy invoke chat double slash", "ride-3-live-webapp.azurewebsites.net", "//api/invoke", "codebuddy"},
		{"CodeBuddy IDE chat", "copilot.tencent.com", "/v1/chat/completions", "codebuddy"},
	}
	for _, tt := range content {
		got := detectLLMProvider(tt.host, tt.path)
		if !got.Known || got.RetainLevel != "content" || got.Product != tt.wantProduct {
			t.Fatalf("%s: detectLLMProvider(%q, %q) = known=%v product=%q retain=%q, want product=%q retain=content", tt.name, tt.host, tt.path, got.Known, got.Product, got.RetainLevel, tt.wantProduct)
		}
	}

	summary := []struct {
		name string
		host string
		path string
	}{
		{"Doubao static JS", "www.doubao.com", "/chat/static/js/async-app.js"},
		{"Doubao conversation info", "www.doubao.com", "/im/conversation/info"},
		{"Doubao CDN static JS", "lf-flow-web-cdn.doubao.com", "/obj/flow-doubao/doubao/chat/static/js/async/async-message.js"},
		{"Qwen telemetry", "dw-data-channel.qianwen.com", "/api/v1/web/report"},
		{"WorkBuddy growth ping", "copilot.tencent.com", "/v2/activity/growth/buddy/info"},
		{"CodeBuddy download host fallback", "download.codebuddy.cn", "/releases/stable/win32-x64/CodeBuddySetup.exe"},
		{"VS Code marketplace", "main.vscode-cdn.net", "/extensions/marketplace.json"},
	}
	for _, tt := range summary {
		got := detectLLMProvider(tt.host, tt.path)
		if got.RetainLevel == "content" {
			t.Fatalf("%s: detectLLMProvider(%q, %q) retain=%q, want non-content noise", tt.name, tt.host, tt.path, got.RetainLevel)
		}
	}
}

func TestDeepSeekFileFetchSuppressedToSummary(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		path       string
		wantRetain string
	}{
		// fetch_files 轮询：降级 summary（不再写 content 留证行）。
		{"fetch_files poll suppressed", "chat.deepseek.com", "/api/v0/file/fetch_files?file_ids=x", "summary"},
		// upload_file：保留 content（唯一的上传文件真字节证据，绝不能被一起降级）。
		{"upload_file kept content", "chat.deepseek.com", "/api/v0/file/upload_file", "content"},
		// chat 问答：不受影响，仍 content。
		{"chat completion content", "chat.deepseek.com", "/api/v0/chat/completion", "content"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLLMProvider(tc.host, tc.path)
			if got.Provider != "deepseek" {
				t.Fatalf("detectLLMProvider(%q,%q) provider=%q, want deepseek", tc.host, tc.path, got.Provider)
			}
			if got.RetainLevel != tc.wantRetain {
				t.Fatalf("detectLLMProvider(%q,%q) retain=%q, want %q", tc.host, tc.path, got.RetainLevel, tc.wantRetain)
			}
		})
	}
}

func TestDefaultLLMHostPatternsIncludeDomesticProviders(t *testing.T) {
	for _, want := range []string{"*.volces.com", "*.doubao.com", "dashscope.aliyuncs.com", "hunyuan.tencentcloudapi.com", "*.modelarts-maas.com", "api.moonshot.cn", "*.kimi.com", "gator.volces.com", "*.qianwen.com", "open.bigmodel.cn", "yuanbao.tencent.com", "api.siliconflow.cn"} {
		if !containsDefaultHostPattern(want) {
			t.Fatalf("default LLM host patterns missing %s", want)
		}
	}
}
