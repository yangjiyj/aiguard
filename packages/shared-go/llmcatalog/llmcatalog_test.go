package llmcatalog

import "testing"

func TestMatchCodeBuddyObservedStudioEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		path       string
		wantRetain string
	}{
		{"chat completions", "copilot.tencent.com", "/v2/chat/completions", "content"},
		{"chat prediction", "copilot.tencent.com", "/v2/chat/prediction", "summary"},
		{"traces", "copilot.tencent.com", "/v1/traces", "summary"},
		{"portal message summary", "copilot.tencent.com", "/portal/abc/message/summary", "summary"},
		{"download host fallback", "download.codebuddy.cn", "/releases/stable/win32-x64/CodeBuddySetup.exe", "summary"},
		{"invoke", "ride-3-live-webapp.azurewebsites.net", "/api/invoke", "content"},
		{"double slash invoke", "ride-3-live-webapp.azurewebsites.net", "//api/invoke", "content"},
		{"stream", "ride-3-live-webapp.azurewebsites.net", "/api/stream", "content"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.host, tt.path)
			if !got.Known {
				t.Fatalf("Match(%q, %q) not known", tt.host, tt.path)
			}
			if got.Provider != "tencent" || got.Product != "codebuddy" || got.RiskProfile != "ai_ide_agent" || got.RetainLevel != tt.wantRetain {
				t.Fatalf("Match(%q, %q) = provider=%q product=%q retain=%q risk=%q, want tencent/codebuddy/%s/ai_ide_agent", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, got.RiskProfile, tt.wantRetain)
			}
		})
	}
}

func TestMatchRecognizesBroadPublicLLMProviders(t *testing.T) {
	tests := []struct {
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantCategory string
	}{
		{"chatgpt.com", "/", "openai", "chatgpt", "chat"},
		{"api.openai.com", "/v1/responses", "openai", "openai_api", "api"},
		{"claude.ai", "/chat", "anthropic", "claude", "chat"},
		{"gemini.google.com", "/app", "google", "gemini", "chat"},
		{"gemini.google.com", "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate", "google", "gemini", "chat"},
		{"copilot.microsoft.com", "/", "microsoft", "copilot", "chat"},
		{"api.githubcopilot.com", "/", "github", "github_copilot", "coding"},
		{"api.deepseek.com", "/v1/chat/completions", "deepseek", "deepseek_api", "api"},
		{"chat.qwen.ai", "/c/abc", "alibaba", "qwen_chat", "chat"},
		{"dashscope.aliyuncs.com", "/compatible-mode/v1/chat/completions", "alibaba", "dashscope", "api"},
		{"www.doubao.com", "/chat/", "bytedance", "doubao", "chat"},
		{"ark.cn-beijing.volces.com", "/api/v3/chat/completions", "bytedance", "volcengine_ark", "api"},
		{"kimi.moonshot.cn", "/", "moonshot", "kimi", "chat"},
		{"api.moonshot.cn", "/v1/chat/completions", "moonshot", "moonshot_api", "api"},
		{"platform.kimi.com", "/v1/chat/completions", "moonshot", "moonshot_api", "api"},
		{"open.bigmodel.cn", "/api/paas/v4/chat/completions", "zhipu", "bigmodel_api", "api"},
		{"yuanbao.tencent.com", "/", "tencent", "yuanbao", "chat"},
		{"hunyuan.tencentcloudapi.com", "/", "tencent", "hunyuan_api", "api"},
		{"yiyan.baidu.com", "/", "baidu", "wenxin_yiyan", "chat"},
		{"qianfan.baidubce.com", "/v2/chat/completions", "baidu", "qianfan_api", "api"},
		{"xinghuo.xfyun.cn", "/", "iflytek", "spark", "chat"},
		{"hailuoai.com", "/", "minimax", "hailuo", "chat"},
		{"api.minimax.chat", "/v1/text/chatcompletion_v2", "minimax", "minimax_api", "api"},
		{"metaso.cn", "/", "metaso", "metaso", "search"},
		{"siliconflow.cn", "/", "siliconflow", "siliconflow", "model-platform"},
		{"api.siliconflow.cn", "/v1/chat/completions", "siliconflow", "siliconflow_api", "api"},
		{"openrouter.ai", "/api/v1/chat/completions", "openrouter", "openrouter_api", "router"},
		{"api.together.xyz", "/v1/chat/completions", "together", "together_api", "api"},
		{"api.mistral.ai", "/v1/chat/completions", "mistral", "mistral_api", "api"},
		{"grok.com", "/", "xai", "grok", "chat"},
		{"api.x.ai", "/v1/chat/completions", "xai", "xai_api", "api"},
		{"poe.com", "/", "poe", "poe", "chat"},
		{"perplexity.ai", "/", "perplexity", "perplexity", "search"},
		{"api.perplexity.ai", "/chat/completions", "perplexity", "perplexity_api", "api"},
		{"v0.dev", "/", "vercel", "v0", "coding"},
		{"cursor.com", "/", "cursor", "cursor", "coding"},
		{"midjourney.com", "/", "midjourney", "midjourney", "image"},
		{"runwayml.com", "/", "runway", "runway", "video"},
		{"suno.com", "/", "suno", "suno", "audio"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("Match(%q, %q) not known", tt.host, tt.path)
		}
		if got.Provider != tt.wantProvider || got.Product != tt.wantProduct || got.Category != tt.wantCategory {
			t.Fatalf("Match(%q, %q) = provider=%q product=%q category=%q, want provider=%q product=%q category=%q", tt.host, tt.path, got.Provider, got.Product, got.Category, tt.wantProvider, tt.wantProduct, tt.wantCategory)
		}
	}
}

func TestMatchRecognizesAIDevelopmentToolTraffic(t *testing.T) {
	tests := []struct {
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantRisk     string
	}{
		{"api2.cursor.sh", "/aiserver.v1.HealthService/StreamSSE", "cursor", "cursor_api", "ai_ide_agent"},
		{"api5.cursor.sh", "/aiserver.v1.AgentService/StreamBidi", "cursor", "cursor_agent", "ai_ide_agent"},
		{"agent.api5.cursor.sh", "/", "cursor", "cursor_agent", "ai_ide_agent"},
		{"repo42.cursor.sh", "/", "cursor", "cursor_codebase_indexing", "ai_ide_agent"},
		{"copilot-proxy.githubusercontent.com", "/", "github", "github_copilot", "ai_ide_agent"},
		{"tenant.business.githubcopilot.com", "/", "github", "github_copilot", "ai_ide_agent"},
		{"api.example-gateway.com", "/v1/responses", "examplegw", "examplegw_gateway", "ai_ide_agent"},
		{"copilot.tencent.com", "/v2/chat/completions", "tencent", "codebuddy", "ai_ide_agent"},
		{"download.codebuddy.cn", "/releases/stable/win32-x64/CodeBuddySetup.exe", "tencent", "codebuddy", "ai_ide_agent"},
		{"ride-3-live-webapp.azurewebsites.net", "/api/invoke", "tencent", "codebuddy", "ai_ide_agent"},
		{"ride-3-live-webapp.azurewebsites.net", "//api/invoke", "tencent", "codebuddy", "ai_ide_agent"},
		{"main.vscode-cdn.net", "/extensions/chat.json", "microsoft", "vscode_marketplace", "ai_ide_agent"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("Match(%q, %q) not known", tt.host, tt.path)
		}
		if got.Provider != tt.wantProvider || got.Product != tt.wantProduct || got.RiskProfile != tt.wantRisk || got.Category != "coding" {
			t.Fatalf("Match(%q, %q) = provider=%q product=%q category=%q risk=%q, want provider=%q product=%q category=coding risk=%q", tt.host, tt.path, got.Provider, got.Product, got.Category, got.RiskProfile, tt.wantProvider, tt.wantProduct, tt.wantRisk)
		}
	}
}

func TestCustomerAcceptanceMatrixKeepsChatContentAndNoiseSeparate(t *testing.T) {
	content := []struct {
		name    string
		host    string
		path    string
		product string
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
		{"CodeBuddy IDE chat", "copilot.tencent.com", "/v1/chat/completions", "codebuddy"},
	}
	for _, tt := range content {
		got := Match(tt.host, tt.path)
		if !got.Known || got.RetainLevel != "content" || got.Product != tt.product {
			t.Fatalf("%s: Match(%q, %q) = known=%v product=%q retain=%q, want product=%q retain=content", tt.name, tt.host, tt.path, got.Known, got.Product, got.RetainLevel, tt.product)
		}
	}

	summary := []struct {
		name string
		host string
		path string
	}{
		{"Doubao static JS", "www.doubao.com", "/chat/static/js/async-app.js"},
		{"Qwen telemetry", "dw-data-channel.qianwen.com", "/api/v1/web/report"},
		{"WorkBuddy growth ping", "copilot.tencent.com", "/v2/activity/growth/buddy/info"},
		{"CodeBuddy download host fallback", "download.codebuddy.cn", "/releases/stable/win32-x64/CodeBuddySetup.exe"},
		{"VS Code marketplace", "main.vscode-cdn.net", "/extensions/marketplace.json"},
	}
	for _, tt := range summary {
		got := Match(tt.host, tt.path)
		if got.RetainLevel == "content" {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want non-content noise", tt.name, tt.host, tt.path, got.RetainLevel)
		}
	}
}

func TestMatchRecognizesWorkBuddySupportTrafficAsSummary(t *testing.T) {
	tests := []struct {
		host       string
		path       string
		wantRetain string
	}{
		{"copilot.tencent.com", "/v2/update", "summary"},
		{"copilot.tencent.com", "/v2/activity/growth/buddy/info", "summary"},
		{"copilot.tencent.com", "/v2/report", "summary"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("Match(%q, %q) not known", tt.host, tt.path)
		}
		if got.Provider != "tencent" || got.Product != "codebuddy" || got.RetainLevel != tt.wantRetain || got.RiskProfile != "ai_ide_agent" {
			t.Fatalf("Match(%q, %q) = provider=%q product=%q retain=%q risk=%q, want tencent/codebuddy/%s/ai_ide_agent", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, got.RiskProfile, tt.wantRetain)
		}
	}
}

func TestMatchRecognizesModelWebBackendSubdomainsWithRetentionPolicy(t *testing.T) {
	tests := []struct {
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantRetain   string
	}{
		{"chatgpt.com", "/c/abc", "openai", "chatgpt", "summary"},
		{"claude.ai", "/new", "anthropic", "claude", "summary"},
		{"gemini.google.com", "/extensions", "google", "gemini", "summary"},
		{"www.kimi.com", "/apiv2/session/Chat", "moonshot", "kimi", "content"},
		{"www.kimi.com", "/apiv2/session/ListChats", "moonshot", "kimi", "summary"},
		{"statics.moonshot.cn", "/web/assets/app.js", "moonshot", "kimi", "summary"},
		{"gator.volces.com", "/list", "bytedance", "doubao", "summary"},
		{"mcs.doubao.com", "/collect", "bytedance", "doubao", "summary"},
		// 注：DeepSeek 配置拉取 /api/v0/client/settings?scope=model 原本在此期望
		// summary，SP1 把 deepseek catalog 的 path_rules 从 null（全兜底）收窄到真
		// chat/file 路径白名单后，这类配置/遥测噪声路径已不再被识别为可审计 LLM 行
		// （Known=false）。对应的“不再匹配”断言见 TestMatchScopesContentToMainRequests
		// 与 TestMatchRejectsDeepSeekNoisePathsAfterCatalogNarrowing。
		{"chat.openai.com", "/ces/v1/telemetry/intake", "openai", "chatgpt", "summary"},
		// 注：DeepSeek 反爬/遥测子域 hif-dliq.deepseek.com /query 原本在此期望 summary，
		// 同属 SP1 收窄后不再被识别为可审计 deepseek 行（Known=false）的噪声路径，
		// 其“不再匹配”断言并入 TestMatchRejectsDeepSeekNoisePathsAfterCatalogNarrowing。
		{"a-api.anthropic.com", "/api/organizations", "anthropic", "claude", "summary"},
		{"assets-proxy.anthropic.com", "/api/asset", "anthropic", "claude", "summary"},
		{"www.tongyi.aliyun.com", "/chat", "alibaba", "qwen_chat", "content"},
		{"chat2.qianwen.com", "/", "alibaba", "qwen_chat", "content"},
		{"chat2-api.qianwen.com", "/api/chat/completions", "alibaba", "qwen_chat", "content"},
		{"api.qianwen.com", "/api/chat/completions", "alibaba", "qwen_chat", "content"},
		{"workspace-zb-cdn.qianwen.com", "/assets/app.js", "alibaba", "qwen_chat", "summary"},
		{"chat.z.ai", "/chat", "zhipu", "chatglm", "content"},
		{"www.perplexity.ai", "/search/new", "perplexity", "perplexity", "content"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("Match(%q, %q) not known", tt.host, tt.path)
		}
		if got.Provider != tt.wantProvider || got.Product != tt.wantProduct || got.RetainLevel != tt.wantRetain {
			t.Fatalf("Match(%q, %q) = provider=%q product=%q retain=%q, want provider=%q product=%q retain=%q", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, tt.wantProvider, tt.wantProduct, tt.wantRetain)
		}
	}
}

func TestMatchRecognizesMoreModelWebFrontendsAndUploadEndpoints(t *testing.T) {
	tests := []struct {
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantRetain   string
		wantKind     string
	}{
		{"chat.baidu.com", "/chat", "baidu", "wenxin_yiyan", "content", "chat"},
		{"bot.360.com", "/chat", "qihoo360", "360_ai", "content", "chat"},
		{"www.n.cn", "/chat", "nami", "nami_ai", "content", "chat"},
		{"monica.im", "/chat", "monica", "monica", "content", "chat"},
		{"pi.ai", "/talk", "inflection", "pi", "content", "chat"},
		{"duck.ai", "/duckchat/v1/chat", "duckduckgo", "duck_ai", "content", "chat"},
		{"www.kimi.com", "/api/file/upload", "moonshot", "kimi", "content", "file"},
		{"www.doubao.com", "/upload/image", "bytedance", "doubao", "content", "file"},
		{"chat.deepseek.com", "/api/v0/file/upload", "deepseek", "deepseek_chat", "content", "file"},
		{"yuanbao.tencent.com", "/api/chat/upload", "tencent", "yuanbao", "content", "file"},
		{"chat.qwen.ai", "/api/file/upload", "alibaba", "qwen_chat", "content", "file"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("Match(%q, %q) not known", tt.host, tt.path)
		}
		if got.Provider != tt.wantProvider || got.Product != tt.wantProduct || got.RetainLevel != tt.wantRetain || got.EndpointKind != tt.wantKind {
			t.Fatalf("Match(%q, %q) = provider=%q product=%q retain=%q kind=%q, want provider=%q product=%q retain=%q kind=%q", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, got.EndpointKind, tt.wantProvider, tt.wantProduct, tt.wantRetain, tt.wantKind)
		}
	}
}

func TestMatchRejectsRegularPublicSites(t *testing.T) {
	got := Match("www.baidu.com", "/s?wd=deepseek")
	if got.Known || got.Provider != "" {
		t.Fatalf("regular public site detected as LLM: %+v", got)
	}
}

// TestMatchRejectsDeepSeekNoisePathsAfterCatalogNarrowing 校验 SP1 收窄的预期结果：
// deepseek catalog（deepseek_web_support）的 path_rules 从 null（全兜底）收窄到真
// chat/file 路径白名单后，配置拉取 /api/v0/client/settings、带查询的同一路径以及
// PoW 反爬质询 /api/v0/chat/create_pow_challenge 这类配置/遥测/反爬噪声路径不再被
// 识别为可审计 deepseek 行（Known=false、Provider 为空），与 www.baidu.com 这类非
// LLM 站点同样的“未识别”写法。注意：真正的会话补全 /api/v0/chat/completion 与文件
// 上传 /api/v0/file/upload 仍须 content（回归护栏见 TestMatchScopesContentToMainRequests
// 与 TestMatchRecognizesMoreModelWebFrontendsAndUploadEndpoints）。
func TestMatchRejectsDeepSeekNoisePathsAfterCatalogNarrowing(t *testing.T) {
	noise := []struct {
		host string
		path string
	}{
		{"chat.deepseek.com", "/api/v0/client/settings"},
		{"chat.deepseek.com", "/api/v0/client/settings?scope=model"},
		{"chat.deepseek.com", "/api/v0/chat/create_pow_challenge"},
		// 反爬/遥测子域同属噪声，SP1 收窄后亦不再匹配。
		{"hif-dliq.deepseek.com", "/query"},
	}
	for _, tt := range noise {
		got := Match(tt.host, tt.path)
		if got.Known || got.Provider != "" {
			t.Fatalf("SP1 收窄后噪声路径不应再被识别为可审计 deepseek 行：Match(%q, %q) = %+v", tt.host, tt.path, got)
		}
	}
}

func TestCatalogIsVisibleAndSeeded(t *testing.T) {
	items := Catalog()
	if len(items) < 45 {
		t.Fatalf("catalog should seed broad public LLM services, got %d", len(items))
	}
	if len(ProviderOptions()) < 25 {
		t.Fatalf("provider options should expose broad filter choices, got %d", len(ProviderOptions()))
	}
}

func TestMatchRecognizesAIDevelopmentToolTelemetryAsSummary(t *testing.T) {
	tests := []struct {
		host        string
		path        string
		provider    string
		product     string
		retainLevel string
	}{
		{"collector.github.com", "/github/collect", "github", "github_copilot_telemetry", "summary"},
		{"copilot-reports-prod.b01.azurefd.net", "/report", "github", "github_copilot_reports", "summary"},
		{"usagereportswestus.blob.core.windows.net", "/copilot/report.json", "github", "github_copilot_reports", "summary"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("%s should be recognized", tt.host)
		}
		if got.Provider != tt.provider || got.Product != tt.product || got.RetainLevel != tt.retainLevel {
			t.Fatalf("Match(%s, %s) = provider=%s product=%s retain=%s", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel)
		}
	}
}

func TestMatchRecognizesAdditionalAICodingAssistants(t *testing.T) {
	tests := []struct {
		host     string
		path     string
		provider string
		product  string
	}{
		{"server.codeium.com", "/exa.language_server_pb.LanguageServerService/GetCompletions", "codeium", "windsurf_codeium"},
		{"api.tabnine.com", "/", "tabnine", "tabnine"},
		{"api.jetbrains.ai", "/llm/v1/chat", "jetbrains", "jetbrains_ai"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("%s should be recognized", tt.host)
		}
		if got.Provider != tt.provider || got.Product != tt.product || got.RiskProfile != "ai_ide_agent" {
			t.Fatalf("Match(%s, %s) = provider=%s product=%s risk=%s", tt.host, tt.path, got.Provider, got.Product, got.RiskProfile)
		}
	}
}

// TestMatchScopesContentToMainRequests 校验：只有真正承载会话/补全正文的主请求
// 才保留 content，配置轮询、反爬质询、token 刷新、增长信息上报等辅助请求降级为
// summary。同时验证此前完全识别不到的主补全端点（GitHub Copilot 的
// /chat/completions、腾讯 CodeBuddy）能被正确归类。断言只覆盖
// Known/Provider/Product/RetainLevel，刻意不约束 EndpointKind（窄化路径后
// classifyEndpointKind 行为脆弱，留给后续单独打磨）。
// TestMatchScopesGeminiContentToRealChatTurns 校验 Gemini 网页版只把真正的对话轮次
// （BardFrontendService/StreamGenerate，请求自带 prompt、响应自带完整答复）保留为
// content；而 batchexecute 这条多路复用的辅助 RPC 总线（历史标题列表、建议气泡、
// UI 导航、标题派生、同步等，reqlen=0 纯前端噪声）以及 SPA 外壳导航（/、/app）必须
// 降级 summary —— 否则「啥也没做」也会刷出一堆 access_content_logs 条目，历史列表页
// 加载还会被误当成一次对话写入。回归护栏：StreamGenerate 真轮次仍须 content。
func TestMatchScopesGeminiContentToRealChatTurns(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantRetain   string
	}{
		// 真正的对话轮次：请求体自带 prompt，响应体自带完整模型答复 —— 必须 content
		{"gemini 对话轮次 StreamGenerate", "gemini.google.com", "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate", "google", "gemini", "content"},
		// 辅助 RPC 总线：历史标题列表/建议气泡/UI 导航/标题派生/同步，reqlen=0 纯噪声 —— 必须 summary
		{"gemini 历史列表 batchexecute", "gemini.google.com", "/_/BardChatUi/data/batchexecute?rpcids=MaZiqc", "google", "gemini", "summary"},
		{"gemini 建议气泡 batchexecute", "gemini.google.com", "/_/BardChatUi/data/batchexecute?rpcids=ku4Jyf", "google", "gemini", "summary"},
		// SPA 外壳导航：页面加载，不是对话轮次 —— 必须 summary
		{"gemini 外壳导航 /app", "gemini.google.com", "/app", "google", "gemini", "summary"},
		{"gemini 首页加载 /", "gemini.google.com", "/", "google", "gemini", "summary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.host, tt.path)
			if !got.Known {
				t.Fatalf("Match(%q, %q) 未识别（Known=false），期望 provider=%s product=%s retain=%s", tt.host, tt.path, tt.wantProvider, tt.wantProduct, tt.wantRetain)
			}
			if got.Provider != tt.wantProvider {
				t.Errorf("Match(%q, %q) Provider=%q，期望 %q", tt.host, tt.path, got.Provider, tt.wantProvider)
			}
			if got.Product != tt.wantProduct {
				t.Errorf("Match(%q, %q) Product=%q，期望 %q", tt.host, tt.path, got.Product, tt.wantProduct)
			}
			if got.RetainLevel != tt.wantRetain {
				t.Errorf("Match(%q, %q) RetainLevel=%q，期望 %q", tt.host, tt.path, got.RetainLevel, tt.wantRetain)
			}
		})
	}
}

func TestMatchScopesContentToMainRequests(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantRetain   string
	}{
		// ChatGPT：真正的会话补全保留正文；会话列表轮询与反爬质询降级摘要
		{"chatgpt 会话补全", "chatgpt.com", "/backend-api/f/conversation", "openai", "chatgpt", "content"},
		{"chatgpt 会话列表轮询", "chatgpt.com", "/backend-api/conversations", "openai", "chatgpt", "summary"},
		{"chatgpt 反爬质询", "chatgpt.com", "/backend-api/sentinel/chat-requirements", "openai", "chatgpt", "summary"},

		// Claude：组织下的会话补全保留正文；组织信息轮询降级摘要
		{"claude 会话补全", "a-api.anthropic.com", "/api/organizations/o1/chat_conversations/c1/completion", "anthropic", "claude", "content"},
		{"claude 组织信息轮询", "a-api.anthropic.com", "/api/organizations", "anthropic", "claude", "summary"},

		// 豆包：会话补全保留正文；message 预处理等辅助请求降级摘要
		{"doubao 会话补全", "www.doubao.com", "/samantha/chat/completion", "bytedance", "doubao", "content"},
		{"doubao message 预处理", "www.doubao.com", "/alice/message/pre_handle_v2", "bytedance", "doubao", "summary"},
		{"doubao 会话信息建议", "www.doubao.com", "/im/conversation/info", "bytedance", "doubao", "summary"},
		{"doubao CDN 静态 JS", "lf-flow-web-cdn.doubao.com", "/obj/flow-doubao/doubao/chat/static/js/async/async-message.js", "bytedance", "doubao", "summary"},

		// DeepSeek：补全请求保留正文。SP1 把 deepseek catalog 的 path_rules 从 null
		// （全兜底）收窄到真 chat/file 路径白名单后，配置拉取 /api/v0/client/settings
		// 与 PoW 质询 /api/v0/chat/create_pow_challenge 这类噪声路径已不再被分类为可审计
		// deepseek 行（Known=false），其“不再匹配”断言见
		// TestMatchRejectsDeepSeekNoisePathsAfterCatalogNarrowing。
		{"deepseek 会话补全", "chat.deepseek.com", "/api/v0/chat/completion", "deepseek", "deepseek_chat", "content"},

		// GitHub Copilot：/responses（真实 Chat 对话）保留正文；/chat/completions 已降为
		// summary（辅助后台调用：标题生成/intent 判断等噪音；真实对话已迁移至 /responses）；
		// token 刷新等内部请求降级摘要。
		{"github copilot responses 对话", "api.githubcopilot.com", "/responses", "github", "github_copilot", "content"},
		{"github copilot chat_completions 辅助降噪", "api.githubcopilot.com", "/chat/completions", "github", "github_copilot", "summary"},
		{"github copilot token 刷新", "api.githubcopilot.com", "/copilot_internal/v2/token", "github", "github_copilot", "summary"},

		// 腾讯 CodeBuddy：补全请求保留正文；增长信息上报降级摘要
		{"codebuddy 补全", "copilot.tencent.com", "/v2/chat/completions", "tencent", "codebuddy", "content"},
		{"workbuddy invoke 双斜杠", "ride-3-live-webapp.azurewebsites.net", "//api/invoke", "tencent", "codebuddy", "content"},
		{"codebuddy 增长信息上报", "copilot.tencent.com", "/v2/activity/growth/buddy/info", "tencent", "codebuddy", "summary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.host, tt.path)
			if !got.Known {
				t.Fatalf("Match(%q, %q) 未识别（Known=false），期望 provider=%s product=%s retain=%s", tt.host, tt.path, tt.wantProvider, tt.wantProduct, tt.wantRetain)
			}
			if got.Provider != tt.wantProvider {
				t.Errorf("Match(%q, %q) Provider=%q，期望 %q", tt.host, tt.path, got.Provider, tt.wantProvider)
			}
			if got.Product != tt.wantProduct {
				t.Errorf("Match(%q, %q) Product=%q，期望 %q", tt.host, tt.path, got.Product, tt.wantProduct)
			}
			if got.RetainLevel != tt.wantRetain {
				t.Errorf("Match(%q, %q) RetainLevel=%q，期望 %q", tt.host, tt.path, got.RetainLevel, tt.wantRetain)
			}
		})
	}
}

func TestMatchRetainsChatGPTHistoryAndCanvasContent(t *testing.T) {
	// 正向代理审计 ChatGPT 网页版时，会话历史回放 GET /backend-api/conversation/{id}
	// 与 Canvas 文档 /textdocs 同样承载用户真实正文。CANON 用 paths ["/","/backend-api/"]
	// 把整段 backend-api 收为 content，后续收窄到 suffix:/conversation 后这两类正文跌到
	// 优先级 80 的 *_support（nil paths）被降级为 summary —— 相对 CANON 构成能力回退，
	// 审计记录拿不到历史与画布正文。这两类必须保留为 content。
	tests := []struct {
		name         string
		host         string
		path         string
		wantProvider string
		wantProduct  string
		wantRetain   string
	}{
		{"会话历史回放", "chatgpt.com", "/backend-api/conversation/abc-123-def", "openai", "chatgpt", "content"},
		{"Canvas 文档", "chatgpt.com", "/backend-api/textdocs", "openai", "chatgpt", "content"},
		{"Canvas 文档更新", "chatgpt.com", "/backend-api/textdocs/abc/update", "openai", "chatgpt", "content"},
		// 回归护栏：列表轮询/反爬质询/欢迎页仍须是 summary，不能因放宽而误收为 content。
		{"会话列表轮询仍 summary", "chatgpt.com", "/backend-api/conversations", "openai", "chatgpt", "summary"},
		{"反爬质询仍 summary", "chatgpt.com", "/backend-api/sentinel/chat-requirements", "openai", "chatgpt", "summary"},
		{"分享页仍 summary", "chatgpt.com", "/c/abc", "openai", "chatgpt", "summary"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("%s: Match(%q, %q) not known", tt.name, tt.host, tt.path)
		}
		if got.Provider != tt.wantProvider || got.Product != tt.wantProduct || got.RetainLevel != tt.wantRetain {
			t.Fatalf("%s: Match(%q, %q) = provider=%q product=%q retain=%q, want provider=%q product=%q retain=%q", tt.name, tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, tt.wantProvider, tt.wantProduct, tt.wantRetain)
		}
	}
}

func TestMatchRetainsChatGPTUploadContent(t *testing.T) {
	// ChatGPT 网页版上传文件 POST /backend-api/files 承载用户上传的真实内容（图片/文档），
	// 与 deepseek/qwen/doubao/kimi/yuanbao 的 *_upload 同级，应保留 content 且 EndpointKind=file。
	// CANON ["/","/backend-api/"] 时整段 backend-api 已是 content；收窄 openai_chatgpt 后上传
	// 路径跌到优先级 80 的 *_support → summary —— 相对 CANON 的能力回退，上传正文漏审。
	tests := []struct {
		name       string
		host       string
		path       string
		wantRetain string
		wantKind   string
	}{
		{"文件上传创建", "chatgpt.com", "/backend-api/files", "content", "file"},
		{"文件上传分片", "chatgpt.com", "/backend-api/files/abc/process_upload", "content", "file"},
	}

	for _, tt := range tests {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("%s: Match(%q, %q) not known", tt.name, tt.host, tt.path)
		}
		if got.Provider != "openai" || got.Product != "chatgpt" {
			t.Fatalf("%s: Match(%q, %q) = provider=%q product=%q, want openai/chatgpt", tt.name, tt.host, tt.path, got.Provider, got.Product)
		}
		if got.RetainLevel != tt.wantRetain {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want %q", tt.name, tt.host, tt.path, got.RetainLevel, tt.wantRetain)
		}
		if got.EndpointKind != tt.wantKind {
			t.Fatalf("%s: Match(%q, %q) kind=%q, want %q", tt.name, tt.host, tt.path, got.EndpointKind, tt.wantKind)
		}
	}
}

func TestMatchRetainsChatGPTAuthoringContent(t *testing.T) {
	// ChatGPT 网页版若干端点承载用户亲手编写的真实正文：
	//   - /backend-api/gizmos/{id}/upsert  GPT Builder 保存（用户写的 system prompt / instructions）
	//   - /backend-api/gizmo_creator       GPT 创建草稿
	//   - /backend-api/memories            用户记忆（用户写入/读回的个人文本）
	//   - /backend-api/edit_message        用户改写已发消息
	// CANON ["/","/backend-api/"] 时整段 backend-api 已是 content；收窄 openai_chatgpt 压制噪声后，
	// 这些路径跌到优先级 80 的 *_support（nil paths）→ summary —— 相对 CANON 的能力回退，
	// 正向代理审计拿不到用户亲手写的正文。注意：gen_title（服务端派生的短标题）不在保留之列。
	content := []struct {
		name string
		host string
		path string
	}{
		{"GPT Builder 保存", "chatgpt.com", "/backend-api/gizmos/g-abc/upsert"},
		{"GPT 创建草稿", "chatgpt.com", "/backend-api/gizmo_creator"},
		{"用户记忆", "chatgpt.com", "/backend-api/memories"},
		{"改写已发消息", "chatgpt.com", "/backend-api/edit_message"},
	}
	for _, tt := range content {
		got := Match(tt.host, tt.path)
		if !got.Known || got.Provider != "openai" || got.Product != "chatgpt" {
			t.Fatalf("%s: Match(%q, %q) = known=%v provider=%q product=%q, want openai/chatgpt", tt.name, tt.host, tt.path, got.Known, got.Provider, got.Product)
		}
		if got.RetainLevel != "content" {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want content", tt.name, tt.host, tt.path, got.RetainLevel)
		}
	}

	// 回归护栏：噪声/辅助/派生请求必须保持 summary，收窄不能因为新增锚点而被破坏。
	summary := []struct {
		name string
		host string
		path string
	}{
		{"会话列表轮询", "chatgpt.com", "/backend-api/conversations"},
		{"反爬质询", "chatgpt.com", "/backend-api/sentinel/chat-requirements"},
		{"分享页", "chatgpt.com", "/c/abc"},
		{"GPT 商店发现", "chatgpt.com", "/backend-api/gizmos/discovery"},
		{"GPT 引导", "chatgpt.com", "/backend-api/gizmos/bootstrap"},
		{"服务端派生标题", "chatgpt.com", "/backend-api/gen_title"},
	}
	for _, tt := range summary {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("%s: Match(%q, %q) not known", tt.name, tt.host, tt.path)
		}
		if got.RetainLevel != "summary" {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want summary（回归护栏）", tt.name, tt.host, tt.path, got.RetainLevel)
		}
	}
}

func TestMatchRetainsGitHubCopilotResponsesAPIContent(t *testing.T) {
	// GitHub Copilot / VS Code Copilot Chat 已迁移到 OpenAI Responses API：
	// 实际对话请求落在 *.individual.githubcopilot.com 的 POST /responses（SSE），
	// 不再走 /chat/completions。github_copilot（content, 优先级 92）的 PathRules
	// 仅有 "contains:/completions"，导致 /responses 路径在路径匹配处落空，跌到优先级 80
	// 的 github_copilot_support（nil paths → 匹配全部路径）→ summary →
	// content_retained=false → 正文抽取被 proxy.go 跳过 → 后台「看不见内容」。
	// openai_api（/v1/responses）、volcengine_ark（/api/v3/responses）已把 Responses API
	// 视为承载正文；此处对齐，让 Copilot 的 /responses 同样保留 content。
	content := []struct {
		name string
		host string
		path string
	}{
		{"VS Code/Copilot 对话 Responses API", "api.individual.githubcopilot.com", "/responses"},
		{"企业版主机 Responses API", "api.githubcopilot.com", "/responses"},
		{"business 租户 Responses API", "tenant.business.githubcopilot.com", "/responses"},
	}
	for _, tt := range content {
		got := Match(tt.host, tt.path)
		if !got.Known || got.Provider != "github" || got.Product != "github_copilot" {
			t.Fatalf("%s: Match(%q, %q) = known=%v provider=%q product=%q, want github/github_copilot", tt.name, tt.host, tt.path, got.Known, got.Provider, got.Product)
		}
		if got.RetainLevel != "content" {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want content（Copilot 对话正文须保留）", tt.name, tt.host, tt.path, got.RetainLevel)
		}
		if got.EndpointKind != "chat" {
			t.Fatalf("%s: Match(%q, %q) kind=%q, want chat", tt.name, tt.host, tt.path, got.EndpointKind)
		}
	}

	// /chat/completions 已降为 summary：VS Code Copilot Chat 后台辅助调用
	// （标题生成/intent 判断）走此路径，真实对话已迁移至 /responses。
	// catalog 层无法区分 inline completion 和辅助调用，以降噪为优先。
	chatCompletionsSummary := []struct {
		name string
		host string
		path string
	}{
		{"传统 /chat/completions 降噪为 summary", "api.githubcopilot.com", "/chat/completions"},
		{"individual 租户 /chat/completions 降噪", "api.individual.githubcopilot.com", "/chat/completions"},
	}
	for _, tt := range chatCompletionsSummary {
		got := Match(tt.host, tt.path)
		if !got.Known || got.Provider != "github" {
			t.Fatalf("%s: Match(%q, %q) = known=%v provider=%q, want github", tt.name, tt.host, tt.path, got.Known, got.Provider)
		}
		if got.RetainLevel != "summary" {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want summary（辅助噪音降级）", tt.name, tt.host, tt.path, got.RetainLevel)
		}
	}

	// 回归护栏：内部/会话管理/遥测/令牌刷新请求必须保持 summary，
	// 不能因为放宽 /responses 而把 model 列表、token 刷新等噪声误收为 content。
	summary := []struct {
		name string
		host string
		path string
	}{
		{"模型会话探测", "api.individual.githubcopilot.com", "/models/session"},
		{"模型会话意图", "api.individual.githubcopilot.com", "/models/session/intent"},
		{"token 刷新", "api.githubcopilot.com", "/copilot_internal/v2/token"},
		{"遥测上报", "telemetry.individual.githubcopilot.com", "/telemetry"},
	}
	for _, tt := range summary {
		got := Match(tt.host, tt.path)
		if !got.Known {
			t.Fatalf("%s: Match(%q, %q) not known", tt.name, tt.host, tt.path)
		}
		if got.RetainLevel != "summary" {
			t.Fatalf("%s: Match(%q, %q) retain=%q, want summary（回归护栏）", tt.name, tt.host, tt.path, got.RetainLevel)
		}
	}
}

func TestMatchRoutesCopilotTelemetrySubdomainsToTelemetryEntry(t *testing.T) {
	// telemetry.<租户>.githubcopilot.com 此前只被 github_copilot_support 兜底
	// (priority 80, product=github_copilot)接住,打点上报被当成正文全量送检,
	// telemetry 里的 "cmd"/"/c" 碎片曾刷出海量 illegal_system_command 误报。
	// 归位到 github_copilot_telemetry(priority 96)后由 telemetry decoder 承接。
	hosts := []string{
		"telemetry.individual.githubcopilot.com",
		"telemetry.business.githubcopilot.com",
		"telemetry.enterprise.githubcopilot.com",
		"telemetry.githubcopilot.com",
	}
	for _, host := range hosts {
		got := Match(host, "/telemetry")
		if !got.Known {
			t.Fatalf("Match(%q) not known", host)
		}
		if got.Product != "github_copilot_telemetry" {
			t.Fatalf("Match(%q) product = %q, want github_copilot_telemetry", host, got.Product)
		}
		if got.RetainLevel != "summary" {
			t.Fatalf("Match(%q) retain = %q, want summary", host, got.RetainLevel)
		}
	}
}
