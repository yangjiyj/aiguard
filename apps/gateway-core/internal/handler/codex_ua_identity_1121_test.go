package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

// 客户现场：codex-tui / codex_vscode 的 UA 没识别出产品，内容兜底把 899+13 个请求判成了
// dify-coze（agent_detection_source=content）。真实 UA 是 Codex 时，正文提到 Dify/Coze 不能改类型。
var siteCodexUserAgents = []string{
	"codex-tui/0.155.0 (Windows 10.0.19045; x86_64) WindowsTerminal (codex-tui; 0.155.0)",
	"codex_vscode/0.164.0-alpha.11.1 (Windows 10.0.19045; x86_64) unknown (VS Code; 26.1021.22027)",
	"Codex Desktop/0.169.0-alpha.11.1 (Windows 10.0.19045; x86_64) unknown (Codex Desktop; 26.1111.21308)",
}

func TestSiteCodexUserAgentWinsOverDifyMentionsInContent(t *testing.T) {
	messages := []Message{
		{Role: "developer", Content: jsonQuote("工作区里有一个 Dify 工作流和 Coze 插件的源码，按 AGENTS.md 修改。")},
		{Role: "user", Content: jsonQuote("# AGENTS.md instructions for D:\\work\\dify-app\n\n<INSTRUCTIONS>\n本项目是 Dify 插件，Coze 版本在 coze/ 目录。\n</INSTRUCTIONS>")},
		{Role: "user", Content: jsonQuote("帮我把 Dify 的 API 调用改成 Coze 的")},
	}
	for _, ua := range siteCodexUserAgents {
		detection, err := agentdetect.DetectFromHeaders(http.Header{"User-Agent": {ua}})
		if err != nil {
			t.Fatal(err)
		}
		info := &auth.AuthInfo{AgentType: detection.Product, AgentDetectionSource: detection.Source}
		refineChatAgentAttribution(info, messages)
		if info.AgentType != "openai-codex" || info.AgentDetectionSource != "user_agent" {
			t.Errorf("%q: agent=%q source=%q, want openai-codex/user_agent", ua, info.AgentType, info.AgentDetectionSource)
		}
		for _, m := range messages {
			if m.Role == "user" {
				if got := inferAgentTypeFromContent(m.Role, messageText(m.Content)); got != "" {
					t.Errorf("user content must not backfill agent type, got %q", got)
				}
			}
		}
	}
}

func TestSiteCodexUserAgentWinsOnReverseProxyPath(t *testing.T) {
	body := `{"instructions":"You maintain a Dify and Coze integration.","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"Dify 和 Coze 怎么接"}]}]}`
	for _, ua := range siteCodexUserAgents {
		req := httptest.NewRequest("POST", "/v1/responses", nil)
		req.Header.Set("User-Agent", ua)
		got, err := inferReverseProxyAgentType(req, llmcatalog.MatchResult{}, []byte(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != "openai-codex" {
			t.Errorf("%q: reverse proxy agent=%q, want openai-codex", ua, got)
		}
	}
}
