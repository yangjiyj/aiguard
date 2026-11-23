package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

// 反向代理的内容兜底只看请求体里协议自有的 system / developer 提示词；
// 用户文本、响应体、目录匹配（match.*）都不再参与。
func TestInferReverseProxyAgentTypeContentFallbackOnlyTrustsSystemPrompts(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	cases := []struct {
		name     string
		request  string
		response string
		match    llmcatalog.MatchResult
		want     string
	}{
		{
			name:    "user 文本提到 cursor 不算",
			request: `{"model":"m","input":[{"role":"user","content":"我在 cursor 里写代码，顺便比较一下"}]}`,
			want:    "",
		},
		{
			name:     "响应体提到 cursor 不算",
			request:  `{"model":"m","input":[{"role":"user","content":"hi"}]}`,
			response: `{"choices":[{"message":{"content":"You are probably using Cursor"}}]}`,
			want:     "",
		},
		{
			name:    "目录匹配里的产品名不参与",
			request: `{"model":"m","input":[{"role":"user","content":"hi"}]}`,
			match:   llmcatalog.MatchResult{Provider: "Cursor", Product: "Cursor", ProductCN: "Cursor"},
			want:    "",
		},
		{
			name:    "顶层 system 字符串 You are Claude Code",
			request: `{"model":"m","system":"You are Claude Code, Anthropic official CLI for Claude.","input":"hi"}`,
			want:    "claude-code",
		},
		{
			name:    "顶层 system 文本块数组",
			request: `{"model":"m","system":[{"type":"text","text":"You are Claude Code."}],"input":"hi"}`,
			want:    "claude-code",
		},
		{
			name:    "Responses instructions You are Codex",
			request: `{"model":"m","instructions":"You are Codex CLI, a coding agent.","input":[{"role":"user","content":"hi"}]}`,
			want:    "openai-codex",
		},
		{
			name:    "input 里 developer 项（文本块用 input_text）",
			request: `{"model":"m","input":[{"role":"developer","content":[{"type":"input_text","text":"You are Claude Code."}]},{"role":"user","content":"hi"}]}`,
			want:    "claude-code",
		},
		{
			name:    "input 里 user 项的断言不算",
			request: `{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":"You are Claude Code."}]}]}`,
			want:    "",
		},
		{
			name:    "Gemini systemInstruction parts",
			request: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":{"parts":[{"text":"You are Claude Code."}]}}`,
			want:    "claude-code",
		},
		{
			name:    "Gemini system_instruction 蛇形键",
			request: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"system_instruction":{"parts":[{"text":"You are Claude Code."}]}}`,
			want:    "claude-code",
		},
		{
			name:    "instructions 与 developer 各断言不同产品时取先出现的一段，不因拼接变歧义",
			request: `{"model":"m","instructions":"You are Codex CLI, a coding agent.","input":[{"role":"developer","content":"You are Claude Code."},{"role":"user","content":"hi"}]}`,
			want:    "openai-codex",
		},
		{
			name:    "超过 16KB 的请求体、system 提示词在末尾仍能识别（解析完整 body）",
			request: `{"model":"m","input":[{"role":"user","content":"` + strings.Repeat("a", 20*1024) + `"},{"role":"system","content":"You are Claude Code."}]}`,
			want:    "claude-code",
		},
		{
			name:    "非 JSON 请求体不判",
			request: `You are Claude Code`,
			want:    "",
		},
	}
	for _, tc := range cases {
		got, err := inferReverseProxyAgentType(req, tc.match, []byte(tc.request), []byte(tc.response))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
