package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

func TestNewProxyAuditRecordSummarizesRegularPublicURL(t *testing.T) {
	req := httptest.NewRequest("GET", "https://www.baidu.com/s?wd=patient_name&token=secret", nil)
	req.RemoteAddr = "10.0.0.10:54321"

	record, err := NewProxyAuditRecord("req_regular", "tenant_default", "www.baidu.com:443", req, LLMProviderMatch{}, true)

	if err != nil {
		t.Fatal(err)
	}

	if record.AccessType != "normal_public" {
		t.Fatalf("AccessType = %q, want normal_public", record.AccessType)
	}
	if record.RetentionLevel != "summary" {
		t.Fatalf("RetentionLevel = %q, want summary", record.RetentionLevel)
	}
	if strings.Contains(record.TargetPath, "wd=") || strings.Contains(record.TargetPath, "token=") {
		t.Fatalf("regular public target path leaked query: %q", record.TargetPath)
	}
	if record.PathTemplate != "/s" {
		t.Fatalf("PathTemplate = %q, want /s", record.PathTemplate)
	}
	if record.URLHash == "" {
		t.Fatal("URLHash should be stored for regular public URL reconstruction checks")
	}
	if record.ContentRetained {
		t.Fatal("regular public access should not retain content")
	}
}

func TestNewProxyAuditRecordRetainsLLMPathAndContentFlag(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions?trace=abc", nil)
	match := detectLLMProvider("api.deepseek.com", "/v1/chat/completions")

	record, err := NewProxyAuditRecord("req_llm", "tenant_default", "api.deepseek.com:443", req, match, true)

	if err != nil {
		t.Fatal(err)
	}

	if record.AccessType != "llm" {
		t.Fatalf("AccessType = %q, want llm", record.AccessType)
	}
	if record.Provider != "deepseek" || record.Product == "" {
		t.Fatalf("LLM provider/product not populated: %+v", record)
	}
	if record.RetentionLevel != "content" || !record.ContentRetained {
		t.Fatalf("LLM request should retain content, got level=%q retained=%v", record.RetentionLevel, record.ContentRetained)
	}
	if !strings.Contains(record.TargetPath, "trace=abc") {
		t.Fatalf("LLM path should keep full access path, got %q", record.TargetPath)
	}
}

func TestNewProxyAuditRecordClassifiesAIDevelopmentTools(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api5.cursor.sh/aiserver.v1.AgentService/StreamBidi", strings.NewReader(`{"prompt":"scan repo"}`))
	match := detectLLMProvider("api5.cursor.sh", "/aiserver.v1.AgentService/StreamBidi")

	record, err := NewProxyAuditRecord("req_cursor_agent", "tenant_default", "api5.cursor.sh:443", req, match, true)

	if err != nil {
		t.Fatal(err)
	}

	if record.AccessType != "ai_ide" {
		t.Fatalf("AccessType = %q, want ai_ide", record.AccessType)
	}
	if record.Provider != "cursor" || record.Product != "cursor_agent" {
		t.Fatalf("AI IDE provider/product not populated: %+v", record)
	}
	if record.RetentionLevel != "content" || !record.ContentRetained {
		t.Fatalf("AI IDE request should retain content, got level=%q retained=%v", record.RetentionLevel, record.ContentRetained)
	}
}

func TestNewProxyAuditRecordClassifiesHuoxianbaoCodexAsAIDevelopmentTool(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.example-gateway.com/v1/responses", strings.NewReader(`{"input":"scan this repo"}`))
	req.Header.Set("User-Agent", "Codex Desktop/0.140.0-alpha.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.609.41114)")
	match := detectLLMProvider("api.example-gateway.com", "/v1/responses")

	record, err := NewProxyAuditRecord("req_codex", "tenant_default", "api.example-gateway.com:443", req, match, true)

	if err != nil {
		t.Fatal(err)
	}

	if record.AccessType != "ai_ide" {
		t.Fatalf("AccessType = %q, want ai_ide", record.AccessType)
	}
	if record.Provider != "examplegw" || record.Product != "examplegw_gateway" {
		t.Fatalf("Codex provider/product not populated: %+v", record)
	}
	if record.AgentType != "openai-codex" {
		t.Fatalf("AgentType = %q, want openai-codex", record.AgentType)
	}
	if record.RetentionLevel != "content" || !record.ContentRetained {
		t.Fatalf("Codex request should retain content, got level=%q retained=%v", record.RetentionLevel, record.ContentRetained)
	}
}

func TestBuildAccessContentLogPayloadSkipsWorkBuddyTopicTitleGeneration(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_workbuddy_title",
		TenantID:        "tenant_default",
		AgentType:       "workbuddy",
		TargetHost:      "copilot.tencent.com",
		TargetPath:      "/v2/chat/completions?source=title",
		RequestBytes:    1309,
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	requestContent := ExtractedContent{Text: `<session> @image#1:Clipboard_Screenshot.png 本地电脑的codex坏了 </session>`, Model: "deepseek-v4-flash"}
	responseContent := ExtractedContent{Text: `{"isNewTopic": true, "title": "修复本地codex故障"}`}

	if payload, ok := buildAccessContentLogPayload(record, requestContent, responseContent); ok {
		t.Fatalf("WorkBuddy 标题生成调用不应写内容留证: %+v", payload)
	}
}

func TestBuildAccessContentLogPayloadSkipsCodeBuddyTopicTitleGeneration(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_codebuddy_title",
		TenantID:        "tenant_default",
		AgentType:       "codebuddy",
		TargetHost:      "copilot.tencent.com",
		TargetPath:      "/v2/chat/completions?source=title",
		RequestBytes:    1086,
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	requestContent := ExtractedContent{Text: "Q: 来吧\nA: 工作区目前是空的。你想做什么呢？", Model: "deepseek-v4-pro"}
	responseContent := ExtractedContent{Text: "空工作区的开始"}

	if payload, ok := buildAccessContentLogPayload(record, requestContent, responseContent); ok {
		t.Fatalf("CodeBuddy 标题生成调用不应写内容留证: %+v", payload)
	}
}

func TestBuildAccessContentLogPayloadKeepsCodeBuddyShortFollowUpWithoutTitleModelFingerprint(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_codebuddy_follow_up",
		TenantID:        "tenant_default",
		AgentType:       "codebuddy",
		TargetHost:      "copilot.tencent.com",
		TargetPath:      "/v2/chat/completions",
		RequestBytes:    29759,
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	requestContent := ExtractedContent{Text: "Q: 这个接口是什么？\nA: 上一轮回答。", Model: "auto"}
	responseContent := ExtractedContent{Text: "这是业务接口。"}

	if _, ok := buildAccessContentLogPayload(record, requestContent, responseContent); !ok {
		t.Fatal("普通 CodeBuddy 短跟进对话不能因 Q/A 形态和短回复被误删")
	}
}

func TestBuildAccessContentLogPayloadKeepsOrdinaryCodeBuddyQPrompt(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_codebuddy_question",
		TenantID:        "tenant_default",
		AgentType:       "codebuddy",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	requestContent := ExtractedContent{Text: "Q: 这个接口是什么意思？"}
	responseContent := ExtractedContent{Text: "这是业务接口。"}

	if _, ok := buildAccessContentLogPayload(record, requestContent, responseContent); !ok {
		t.Fatal("普通 CodeBuddy Q: 用户问题不能被误判为内部标题生成")
	}
}

func TestBuildAccessContentLogPayloadKeepsRegularWorkBuddyJSONResponse(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_workbuddy_regular",
		TenantID:        "tenant_default",
		AgentType:       "workbuddy",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	requestContent := ExtractedContent{Text: "请返回 JSON"}
	responseContent := ExtractedContent{Text: `{"title": "用户要求的业务结果"}`}

	payload, ok := buildAccessContentLogPayload(record, requestContent, responseContent)
	if !ok {
		t.Fatal("普通 WorkBuddy JSON 回复必须正常留证")
	}
	if payload.ResponseContentRedacted != responseContent.Text {
		t.Fatalf("响应正文不一致: %q", payload.ResponseContentRedacted)
	}
}

func TestBuildAccessContentLogPayloadKeepsWorkBuddyBusinessJSONWithTopicFields(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_workbuddy_business_json",
		TenantID:        "tenant_default",
		AgentType:       "workbuddy",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	responseContent := ExtractedContent{Text: `{"isNewTopic": true, "title": "业务结果", "items": [1]}`}

	if _, ok := buildAccessContentLogPayload(record, ExtractedContent{Text: "返回主题分析"}, responseContent); !ok {
		t.Fatal("含额外业务字段的 WorkBuddy JSON 不能被误判为内部标题生成")
	}
}

func TestBuildAccessContentLogPayloadKeepsSameShapeForOtherAgents(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_other_agent_title",
		TenantID:        "tenant_default",
		AgentType:       "openai-codex",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	responseContent := ExtractedContent{Text: `{"isNewTopic": true, "title": "业务响应"}`}

	if _, ok := buildAccessContentLogPayload(record, ExtractedContent{Text: "生成业务标题"}, responseContent); !ok {
		t.Fatal("非 WorkBuddy 客户端的同形 JSON 不能被误过滤")
	}
}

func TestNormalizeAccessContentRetentionDays(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		fallback int
		want     int
	}{
		{name: "valid", raw: "120", fallback: 90, want: 120},
		{name: "trim spaces", raw: " 30 ", fallback: 90, want: 30},
		{name: "zero falls back", raw: "0", fallback: 90, want: 90},
		{name: "negative falls back", raw: "-1", fallback: 90, want: 90},
		{name: "invalid falls back", raw: "abc", fallback: 90, want: 90},
		{name: "too large clamps to max", raw: "3651", fallback: 90, want: 3650},
		// 与 control-plane 清理任务同一口径：低于 30 天一律按 30 天写 retention_until。
		{name: "below floor clamps to 30", raw: "1", fallback: 90, want: 30},
		{name: "29 clamps to 30", raw: "29", fallback: 90, want: 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAccessContentRetentionDays(tc.raw, tc.fallback); got != tc.want {
				t.Fatalf("normalizeAccessContentRetentionDays(%q) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}
}

func TestAuditWriterDefaultsAccessContentRetentionDaysWithoutDB(t *testing.T) {
	writer := NewAuditWriter(nil)
	if got := writer.accessContentRetentionDays(nil); got != defaultAccessContentRetentionDays {
		t.Fatalf("accessContentRetentionDays without DB = %d, want %d", got, defaultAccessContentRetentionDays)
	}
}

func TestBuildAccessContentLogKeepsOnlyCustomerVisibleAssistantText(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID: "r-visible", TenantID: "t-visible", Provider: "openai",
		Product: "codex", ContentRetained: true, RetentionLevel: "content",
	}
	request := ExtractedContent{Messages: []ConvMessage{{
		Role: "user", Source: aimsg.SourceUser, Content: "检查这个问题",
	}}}
	response := ExtractedContent{Text: "[reasoning] private thought\n正在检查。\n" +
		"<oai-mem-citation><citation_entries>MEMORY.md:1</citation_entries></oai-mem-citation>\n已完成。"}
	payload, ok := buildAccessContentLogPayload(record, request, response)
	if !ok {
		t.Fatal("应产出内容留证")
	}
	if payload.ResponseContentRedacted != "正在检查。\n已完成。" {
		t.Fatalf("模型留证应只含客户可见正文: %q", payload.ResponseContentRedacted)
	}
	for _, forbidden := range []string{"[reasoning]", "oai-mem-citation", "MEMORY.md"} {
		if strings.Contains(payload.ResponseContentRedacted, forbidden) {
			t.Fatalf("模型内部内容泄漏 %q: %q", forbidden, payload.ResponseContentRedacted)
		}
	}
}

func TestBuildAccessContentLogUsesVerifiedVisibleAssistantProjection(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID: "r-tool", TenantID: "t-tool", Provider: "anthropic",
		Product: "codebuddy", ContentRetained: true, RetentionLevel: "content",
	}
	request := ExtractedContent{Messages: []ConvMessage{{
		Role: "user", Source: aimsg.SourceUser, Content: "检查配置",
	}}}
	response := ExtractedContent{
		Text:             "正在检查配置。\n{\"command\":\"cat private.conf\"}",
		VisibleText:      "正在检查配置。",
		VisibleTextKnown: true,
	}
	payload, ok := buildAccessContentLogPayload(record, request, response)
	if !ok || payload.ResponseContentRedacted != "正在检查配置。" {
		t.Fatalf("工具入参不得进入客户可见模型回复: ok=%v payload=%+v", ok, payload)
	}
}

func TestBuildAccessContentLogNormalizesFlatAgentRequest(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID: "r-flat", TenantID: "t-flat", Provider: "github",
		Product: "github_copilot", ContentRetained: true, RetentionLevel: "content",
	}
	request := ExtractedContent{Text: "<prompt>\nGWRETENTION-VSCODE 请只回复：VSCODE-OK\n</prompt>"}
	response := ExtractedContent{Text: "VSCODE-OK"}
	payload, ok := buildAccessContentLogPayload(record, request, response)
	if !ok || payload.RequestContentRedacted != "GWRETENTION-VSCODE 请只回复：VSCODE-OK" {
		t.Fatalf("平铺 Agent 请求也必须走统一客户投影: ok=%v payload=%+v", ok, payload)
	}
}

func TestBuildAccessContentLogPayloadProjectsCodexInAppBrowserContext(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID: "r-codex-browser", TenantID: "t-codex-browser", Provider: "examplegw",
		Product: "examplegw_gateway", ContentRetained: true, RetentionLevel: "content",
	}
	raw := `<in-app-browser-context source="ambient-ui-state">
This block is automatically supplied ambient UI state, not part of the user's request.
# In app browser:
- Current URL: http://127.0.0.1:13001/dashboard
</in-app-browser-context>

## My request:
发完了`
	request := ExtractedContent{Messages: []ConvMessage{{
		Role: "user", Source: aimsg.SourceUser, Content: raw,
	}}}
	response := ExtractedContent{VisibleText: "收到。", VisibleTextKnown: true}
	payload, ok := buildAccessContentLogPayload(record, request, response)
	if !ok || payload.RequestContentRedacted != "发完了" {
		t.Fatalf("Codex browser context projection failed: ok=%v payload=%+v", ok, payload)
	}
	for _, forbidden := range []string{"in-app-browser-context", "ambient-ui-state", "127.0.0.1", "My request"} {
		if strings.Contains(payload.RequestContentRedacted, forbidden) {
			t.Fatalf("Codex browser metadata leaked %q: %q", forbidden, payload.RequestContentRedacted)
		}
	}
}
