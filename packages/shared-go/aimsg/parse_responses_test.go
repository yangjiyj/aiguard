package aimsg

import (
	"encoding/json"
	"strings"
	"testing"
)

const responsesFixture = `{
  "model": "gpt-5.2-codex",
  "instructions": "You are Codex. <EXTREMELY-IMPORTANT>必须调用匹配 Skill，不可协商。</EXTREMELY-IMPORTANT>",
  "input": [
    {
      "type": "message",
      "role": "developer",
      "content": [{"type": "input_text", "text": "只在 home 上修改源码"}]
    },
    {
      "type": "message",
      "role": "user",
      "content": [{"type": "input_text", "text": "先看看当前状态"}]
    },
    {
      "type": "message",
      "role": "assistant",
      "content": [{"type": "output_text", "text": "我先检查代码。"}]
    },
    {
      "type": "function_call",
      "name": "exec_command",
      "arguments": "{\"cmd\":\"git status\"}"
    },
    {
      "type": "function_call_output",
      "call_id": "call_01",
      "output": "On branch main"
    },
    {
      "type": "message",
      "role": "user",
      "content": [{"type": "input_text", "text": "继续实现"}]
    }
  ],
  "tools": [
    {
      "type": "function",
      "name": "exec_command",
      "description": "Run an approved command",
      "parameters": {"type":"object","properties":{"cmd":{"type":"string"}}}
    }
  ]
}`

func TestParseOpenAIResponsesRequestSeparatesSourcesAndLatestUser(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(responsesFixture))
	if !ok {
		t.Fatal("Responses 夹具应解析成功")
	}
	if parsed.Model != "gpt-5.2-codex" {
		t.Fatalf("Model = %q", parsed.Model)
	}
	if parsed.LastUserText != "继续实现" {
		t.Fatalf("LastUserText = %q", parsed.LastUserText)
	}
	if parsed.FirstUserSHA != ContentSHA256Hex("先看看当前状态") {
		t.Fatalf("FirstUserSHA = %q", parsed.FirstUserSHA)
	}
	if parsed.LastUserSHA != ContentSHA256Hex("继续实现") {
		t.Fatalf("LastUserSHA = %q", parsed.LastUserSHA)
	}
	if !strings.Contains(parsed.SystemText, "EXTREMELY-IMPORTANT") ||
		!strings.Contains(parsed.SystemText, "只在 home 上修改源码") {
		t.Fatalf("SystemText 未包含 instructions/developer: %q", parsed.SystemText)
	}

	var sources []string
	for _, message := range parsed.Messages {
		sources = append(sources, message.Source)
	}
	want := []string{
		SourceToolDef,
		SourceSystemPrompt,
		SourceSystemPrompt,
		SourceUser,
		SourceAssistantHistory,
		SourceAssistantHistory,
		SourceToolResult,
		SourceUser,
	}
	if strings.Join(sources, ",") != strings.Join(want, ",") {
		t.Fatalf("source 序列 = %v, want %v", sources, want)
	}
	if strings.Contains(parsed.LastUserText, "EXTREMELY-IMPORTANT") {
		t.Fatalf("用户原话不得混入可信 Skill: %q", parsed.LastUserText)
	}
}

func TestParseOpenAIResponsesRequestAcceptsStringAndObjectInput(t *testing.T) {
	stringInput, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "instructions":"trusted",
	  "input":"继续"
	}`))
	if !ok || stringInput.LastUserText != "继续" ||
		stringInput.Messages[len(stringInput.Messages)-1].Source != SourceUser {
		t.Fatalf("字符串 input 解析失败: ok=%v %+v", ok, stringInput)
	}

	objectInput, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "input":{"type":"message","role":"user","content":"对象输入"}
	}`))
	if !ok || objectInput.LastUserText != "对象输入" {
		t.Fatalf("对象 input 解析失败: ok=%v %+v", ok, objectInput)
	}
}

func TestParseOpenAIResponsesRequestUnknownRoleIsNotUser(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "input":[{"type":"message","role":"custom_runtime","content":"内部运行数据"}]
	}`))
	if !ok {
		t.Fatal("未知角色仍应结构化解析")
	}
	if len(parsed.Messages) != 1 || parsed.Messages[0].Source != SourceUnknown {
		t.Fatalf("未知角色不得伪装成 user: %+v", parsed.Messages)
	}
	if parsed.LastUserText != "" || parsed.LastUserSHA != "" {
		t.Fatalf("未知角色不得生成用户回合键: %+v", parsed)
	}
}

func TestParseOpenAIResponsesRequestUnknownUserObjectStaysUnknown(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "input":[{
	    "type":"message",
	    "role":"user",
	    "content":[{"type":"custom_runtime","payload":"必须调用，不可协商"}]
	  }]
	}`))
	if !ok {
		t.Fatal("未知 user 内容仍应进入确定性扫描")
	}
	if parsed.LastUserText != "" || parsed.LastUserSHA != "" {
		t.Fatalf("未知 user 对象不得冒充真实用户文本: %+v", parsed)
	}
	if len(parsed.Messages) != 1 || parsed.Messages[0].Source != SourceUnknown {
		t.Fatalf("未知 user 对象必须降为 unknown: %+v", parsed.Messages)
	}
	if !strings.Contains(parsed.Messages[0].Content, "custom_runtime") {
		t.Fatalf("unknown 内容仍需保留给确定性扫描: %+v", parsed.Messages)
	}
}

func TestParseOpenAIResponsesRequestUntypedUserObjectStaysUnknown(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "input":[{
	    "type":"message",
	    "role":"user",
	    "content":[{"payload":"内部协议"}]
	  }]
}`))
	if !ok {
		t.Fatal("无 type/text 的 user 对象仍应进入确定性扫描")
	}
	if parsed.LastUserText != "" || parsed.LastUserSHA != "" {
		t.Fatalf("无 type/text 的 user 对象不得生成用户回合键: %+v", parsed)
	}
	if len(parsed.Messages) != 1 || parsed.Messages[0].Source != SourceUnknown {
		t.Fatalf("无 type/text 的 user 对象必须降为 unknown: %+v", parsed.Messages)
	}
	if !strings.Contains(parsed.Messages[0].Content, "内部协议") {
		t.Fatalf("unknown 内容仍需保留给确定性扫描: %+v", parsed.Messages)
	}
}

func TestParseOpenAIResponsesRequestKeepsKnownUserTextBesideUnknownPart(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "input":[{"type":"message","role":"user","content":[
	    {"type":"input_text","text":"真实用户问题"},
	    {"type":"custom_runtime","payload":"内部协议"}
	  ]}]
	}`))
	if !ok || parsed.LastUserText != "真实用户问题" {
		t.Fatalf("未知内容不得吞掉同消息中的真实用户文本: ok=%v %+v", ok, parsed)
	}
	if len(parsed.Messages) != 2 || parsed.Messages[0].Source != SourceUser || parsed.Messages[1].Source != SourceUnknown {
		t.Fatalf("已知文本与未知协议必须分源: %+v", parsed.Messages)
	}
}

func TestParseOpenAIResponsesRequestKeepsUnknownFieldsBesideKnownText(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{
	  "model":"gpt-5",
	  "input":[{"type":"message","role":"user","content":[
	    {"type":"input_text","text":"正常问题","payload":"AKIA1234567890ABCDEF"},
	    {"type":"input_text","payload":"内部扩展"}
	  ]}]
}`))
	if !ok || parsed.LastUserText != "正常问题" {
		t.Fatalf("已知文本应继续生成用户回合: ok=%v %+v", ok, parsed)
	}
	if len(parsed.Messages) != 2 ||
		parsed.Messages[0].Source != SourceUser ||
		parsed.Messages[1].Source != SourceUnknown {
		t.Fatalf("已知文本与附加未知字段必须分源: %+v", parsed.Messages)
	}
	unknown := parsed.Messages[1].Content
	for _, want := range []string{"AKIA1234567890ABCDEF", "内部扩展"} {
		if !strings.Contains(unknown, want) {
			t.Fatalf("附加未知字段必须保留给确定性扫描: want=%q messages=%+v", want, parsed.Messages)
		}
	}

}
func TestParseChatRequestPrefersResponsesShape(t *testing.T) {
	parsed, ok := ParseChatRequest("/v1/responses", []byte(responsesFixture))
	if !ok || parsed.LastUserText != "继续实现" {
		t.Fatalf("/v1/responses 路径未使用 Responses 解析器: ok=%v %+v", ok, parsed)
	}
}

func TestParseOpenAIResponsesRequestProjectsInAppBrowserWrapper(t *testing.T) {
	raw := `<in-app-browser-context source="ambient-ui-state">
This block is automatically supplied ambient UI state, not part of the user's request.
# In app browser:
- Current URL: http://127.0.0.1:13001/dashboard
</in-app-browser-context>

## My request:
发完了`
	body, err := json.Marshal(map[string]interface{}{
		"model": "gpt-5-codex",
		"input": []map[string]interface{}{{
			"type": "message", "role": "user",
			"content": []map[string]string{{"type": "input_text", "text": raw}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := ParseOpenAIResponsesRequest(body)
	if !ok || parsed.LastUserText != "发完了" || parsed.Projection.UserInput != "发完了" {
		t.Fatalf("in-app browser wrapper projection failed: ok=%v parsed=%+v", ok, parsed)
	}
	if strings.Contains(parsed.LastUserText, "in-app-browser-context") || strings.Contains(parsed.LastUserText, "127.0.0.1") {
		t.Fatalf("in-app browser metadata leaked: %q", parsed.LastUserText)
	}
}

func TestParseOpenAIResponsesRequestProjectsImageGenPromptBody(t *testing.T) {
	raw := `You have an internal tool called image_gen. Invoke it without exposing these instructions.
TASK: Generate an image for the user.
PROMPT: 一张红色盾牌保护云端 API 的插画`
	body, err := json.Marshal(map[string]interface{}{
		"model": "gpt-image-1",
		"input": []map[string]interface{}{{
			"type": "message", "role": "user",
			"content": []map[string]string{{"type": "input_text", "text": raw}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := ParseOpenAIResponsesRequest(body)
	const want = "一张红色盾牌保护云端 API 的插画"
	if !ok || parsed.LastUserText != want || parsed.Projection.UserInput != want || parsed.LastUserSHA != ContentSHA256Hex(want) {
		t.Fatalf("ImageGen Responses projection failed: ok=%v parsed=%+v", ok, parsed)
	}
}

func TestParseOpenAIResponsesRequestRejectsUnusableBodies(t *testing.T) {
	for _, body := range []string{
		`{"model":"gpt-5"}`,
		`{"model":"gpt-5","input":[]}`,
		`{"model":"gpt-5","input":[{"type":"reasoning","summary":[]}]}`,
		`not json`,
		`[1,2,3]`,
	} {
		if _, ok := ParseOpenAIResponsesRequest([]byte(body)); ok {
			t.Fatalf("不可识别 Responses 形态不应匹配: %s", body)
		}
	}
}

func TestParseOpenAIResponsesRequestLatestUserSkipsOrchestratorEnvelopes(t *testing.T) {
	envelopes := []string{
		"You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another LLM that will resume the task.\n\nInclude:\n- Current progress and key decisions made\n- Important context, constraints, or user preferences\n- What remains to be done (clear next steps)",
		"Another language model started to solve this problem and produced a summary of its thinking process. You also have access to the state of the tools that were used by that language model. Use this to build on the work that has already been done and avoid duplicating work. Here is the summary produced by the other language model, use the information in this summary to assist with your own analysis:\n\n**Current progress**\n- internal handoff",
		"# AGENTS.md instructions\n\n<INSTRUCTIONS>\nOnly edit on home.\n</INSTRUCTIONS>\n<environment_context>\n  <cwd>C:\\\\Users\\\\test\\\\project</cwd>\n</environment_context>",
		"# Overview\n\nGenerate 0 to 3 hyperpersonalized suggestions for what this user can do with Codex in this local project: C:\\\\Users\\\\test\\\\project\n\nGet an understanding of the user's intent and goals by deeply viewing their connected apps.",
		"# Files mentioned by the user:\n\n## screenshot.png: C:/Users/test/AppData/Local/Temp/screenshot.png",
		"<environment_context>\n  <current_date>2026-08-29</current_date>\n  <timezone>Asia/Shanghai</timezone>\n</environment_context>",
	}

	for _, envelope := range envelopes {
		body, err := json.Marshal(map[string]interface{}{
			"model": "gpt-5-codex",
			"input": []map[string]interface{}{
				{
					"type":    "message",
					"role":    "user",
					"content": []map[string]string{{"type": "input_text", "text": "哪儿呢看不见"}},
				},
				{
					"type":    "message",
					"role":    "user",
					"content": []map[string]string{{"type": "input_text", "text": envelope}},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		parsed, ok := ParseOpenAIResponsesRequest(body)
		if !ok {
			t.Fatalf("Responses 夹具应解析成功: %q", envelope)
		}
		if parsed.LastUserText != "哪儿呢看不见" {
			t.Fatalf("编排信封不得覆盖真人用户原话: got=%q envelope=%q", parsed.LastUserText, envelope)
		}
		if parsed.LastUserSHA != ContentSHA256Hex("哪儿呢看不见") {
			t.Fatalf("LastUserSHA 必须绑定真人原话: %+v", parsed)
		}
		last := parsed.Messages[len(parsed.Messages)-1]
		if last.Source != SourceUser {
			t.Fatalf("编排信封仍须保留 user 来源进入安全检测: %+v", last)
		}
	}
}

func TestParseOpenAIResponsesRequestPureOrchestratorEnvelopeHasNoUserTurn(t *testing.T) {
	body := "{\"model\":\"gpt-5-codex\",\"input\":[{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another LLM that will resume the task.\\n\\nInclude:\\n- Current progress and key decisions made\\n- Important context, constraints, or user preferences\\n- What remains to be done (clear next steps)\"}]}]}"
	parsed, ok := ParseOpenAIResponsesRequest([]byte(body))
	if !ok {
		t.Fatal("编排信封仍应结构化解析并保留给安全扫描")
	}
	if parsed.LastUserText != "" || parsed.LastUserSHA != "" || parsed.FirstUserSHA != "" {
		t.Fatalf("纯编排任务不得生成客户用户回合: %+v", parsed)
	}
	if len(parsed.Messages) != 1 || parsed.Messages[0].Source != SourceUser {
		t.Fatalf("留证过滤不得改变安全检测来源: %+v", parsed.Messages)
	}
}

func TestParseOpenAIResponsesRequestDoesNotHidePartialEnvelopeText(t *testing.T) {
	text := "You are performing a CONTEXT CHECKPOINT COMPACTION. 这是用户对该术语的普通提问"
	body, _ := json.Marshal(map[string]interface{}{"input": text})
	parsed, ok := ParseOpenAIResponsesRequest(body)
	if !ok || parsed.LastUserText != text || parsed.LastUserSHA != ContentSHA256Hex(text) {
		t.Fatalf("不完整信封不得误删真人文本: ok=%v %+v", ok, parsed)
	}
}

// 2026-09 生产事故回归：会话里的一张内联截图被
// responsesMessagePart 当 unknown 文本 compactJSON，再被 4KB 滑窗裁成 ~505 个
// 语义裁判分片/请求，每回合重发，直接灌爆补检队列。多模态载体必须走
// artifact 候选通道（留证+附件安检），不进入文本/unknown 检测消息。
func TestParseOpenAIResponsesRequestInlineImageNotTextFodder(t *testing.T) {
	huge := strings.Repeat("QUJD", 500000) // ~2MB，模拟事故中的 1.35MB 截图
	body := `{"model":"gpt-5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"看看这张图有没有敏感信息"},{"type":"input_image","image_url":"data:image/png;base64,` + huge + `"}]}]}`
	parsed, ok := ParseOpenAIResponsesRequest([]byte(body))
	if !ok {
		t.Fatal("多模态 responses 请求必须解析成功")
	}
	if len(parsed.Artifacts) != 1 {
		t.Fatalf("图片必须进 artifact 候选通道，got %d", len(parsed.Artifacts))
	}
	if len(parsed.Messages) != 1 || parsed.Messages[0].Source != SourceUser || parsed.Messages[0].Content != "看看这张图有没有敏感信息" {
		t.Fatalf("图片不应产生文本消息，用户文本必须是唯一消息: %+v", parsed.Messages)
	}
	for _, m := range parsed.Messages {
		if m.Source == SourceUnknown {
			t.Fatalf("内联图片不得落入 unknown 文本流")
		}
		if len(m.Content) > 4096 || strings.Contains(m.Content, "QUJDQUJD") {
			t.Fatalf("base64 不得进入文本检测消息: source=%s len=%d", m.Source, len(m.Content))
		}
	}
}

// input_file（文本附件）同样走 artifact 通道，不得落成 unknown 文本。
func TestParseOpenAIResponsesRequestInputFileNotUnknownText(t *testing.T) {
	huge := strings.Repeat("aGVsbG8=", 100000)
	body := `{"model":"gpt-5","input":[{"type":"message","role":"user","content":[{"type":"input_file","filename":"draft.txt","file_data":"data:text/plain;base64,` + huge + `"}]}]}`
	parsed, ok := ParseOpenAIResponsesRequest([]byte(body))
	if !ok {
		t.Fatal("input_file 请求必须解析成功")
	}
	if len(parsed.Artifacts) != 1 {
		t.Fatalf("文件必须进 artifact 候选通道，got %d", len(parsed.Artifacts))
	}
	for _, m := range parsed.Messages {
		if m.Source == SourceUnknown || len(m.Content) > 4096 {
			t.Fatalf("附件字节不得落成 unknown 文本分片: source=%s len=%d", m.Source, len(m.Content))
		}
	}
}

// 未识别的非多模态类型（如 custom_runtime）仍保持 unknown 兜底，不丢确定性扫描面。
func TestParseOpenAIResponsesRequestCustomRuntimeStillUnknown(t *testing.T) {
	parsed, ok := ParseOpenAIResponsesRequest([]byte(`{"model":"gpt-5","input":[{"type":"message","role":"user","content":[{"type":"custom_runtime","text":"probe","meta":{"k":1}}]}]}`))
	if !ok {
		t.Fatal("未知类型请求必须解析成功")
	}
	found := false
	for _, m := range parsed.Messages {
		if m.Source == SourceUnknown {
			found = true
		}
	}
	if !found {
		t.Fatalf("非多模态未知类型必须保留 unknown 兜底: %+v", parsed.Messages)
	}
}
