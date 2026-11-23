package handler

import (
	"regexp"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// simulateFrontendCollapse 复刻前端 collapseSystemSections 的折叠：按 \n\n 分段，
// 折叠"所有"带【系统】/【工具】前缀的段（不只开头），非系统段作正文。返回正文与折叠段数。
func simulateFrontendCollapse(text string) (body string, collapsed int) {
	rolePrefix := regexp.MustCompile(`^【(system|tool|developer|系统|工具|其它)】`)
	paras := regexp.MustCompile(`\n\n+`).Split(strings.TrimSpace(text), -1)
	var head, bodyParas []string
	for _, p := range paras {
		if rolePrefix.MatchString(strings.TrimSpace(p)) {
			head = append(head, p)
		} else {
			bodyParas = append(bodyParas, p)
		}
	}
	if len(head) == 0 || len(bodyParas) == 0 {
		return text, 0
	}
	return strings.Join(bodyParas, "\n\n"), len(head)
}

// TestMessagesToRetentionTextFoldsAgentNoise WorkBuddy 场景：巨型系统提示词（含内部空行）
// + 工具定义 + 短用户消息"真的吗"。渲染后前端折叠应把系统/工具段折掉，只显"真的吗"。
func TestMessagesToRetentionTextFoldsAgentNoise(t *testing.T) {
	bigSystem := "You are WorkBuddy agent.\n\nTool schema follows.\n\n{\"query\": \"restate the current ask\"}"
	msgs := []ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: bigSystem},
		{Role: "tool", Source: aimsg.SourceToolDef, Content: "Name for the spawned agent. SendMessage(...)"},
		{Role: "tool", Source: aimsg.SourceToolDef, Content: "Optional start date for filtering conversations."},
		{Role: "user", Source: aimsg.SourceUser, Content: "真的吗"},
	}
	text := messagesToRetentionText(msgs)

	// 系统段内部空行已归并成单段（否则折叠会在段内空行处断裂）。
	if strings.Contains(text, "You are WorkBuddy agent.\n\nTool schema") {
		t.Fatalf("系统段内部空行未归并，会破坏折叠:\n%s", text)
	}
	// 前端折叠模拟：系统+2个工具段被折，正文只剩"真的吗"。
	body, collapsed := simulateFrontendCollapse(text)
	if collapsed != 3 {
		t.Fatalf("应折叠 3 段(系统+2工具)，实折 %d\n%s", collapsed, text)
	}
	if strings.TrimSpace(body) != "真的吗" {
		t.Fatalf("展开正文应只剩'真的吗'，实得 %q", body)
	}
	// 折叠≠删除：系统提示词仍在全文里（可展开），证据不减量。
	if !strings.Contains(text, "You are WorkBuddy agent") {
		t.Fatal("系统提示词不应从留证文本里消失（证据不减量）")
	}
}

// TestMessagesToRetentionTextFoldsAgentMetaInUserRole WorkBuddy/Claude Code 把系统提示词
// （agent 类型说明/技能清单）塞进 user 角色消息发（Source=user），仍应按【系统】折叠，只显真实提问。
func TestMessagesToRetentionTextFoldsAgentMetaInUserRole(t *testing.T) {
	agentMeta := "The Agent tool launches specialized agents (subprocesses) that autonomously handle complex tasks.\n\n" +
		"Available agent types and the tools they have access to:\n" +
		"- general-purpose: General-purpose agent for researching complex questions.\n\n" +
		"<available_skills>\n- 多模态内容生成: 支持文生视频、文生3D模型。\n</available_skills>\n" +
		strings.Repeat("more agent instructions padding. ", 20)
	msgs := []ConvMessage{
		{Role: "tool", Source: aimsg.SourceToolDef, Content: "[tool_def:present_files] Present files."},
		{Role: "user", Source: aimsg.SourceUser, Content: agentMeta}, // 系统提示词塞在 user 里
		{Role: "user", Source: aimsg.SourceUser, Content: "行啊"},      // 真实用户消息
	}
	text := messagesToRetentionText(msgs)
	body, collapsed := simulateFrontendCollapse(text)
	if collapsed != 2 {
		t.Fatalf("应折叠 2 段(工具+user角色的agent指令)，实折 %d\n%s", collapsed, text)
	}
	if strings.TrimSpace(body) != "行啊" {
		t.Fatalf("展开正文应只剩'行啊'，实得 %q", body)
	}
}

// TestMessagesToRetentionTextExtractsUserQuery WorkBuddy 抓包实证结构：一条 user 消息 =
// [<system-reminder>工作目录上下文] + [<system-reminder>user_info/memory + <user_query>真实消息</user_query>]。
// openAIMessageText 把多个 text part 拼成一条 user content。留证必须剥出 <user_query> 里的真实消息显示，
// 其余 system-reminder 上下文折叠——否则整条（含真实消息）命中 <system-reminder> 特征被一起折没。
func TestMessagesToRetentionTextExtractsUserQuery(t *testing.T) {
	// 复刻抓包：part0(工作目录) + part1(user_info/memory + <user_query>五年】</user_query>)，用 \n 拼接。
	part0 := "<system-reminder><current-working-directory>\nCurrent working directory: C:\\Users\\dev\\WorkBuddy\n" +
		strings.Repeat("always use relative paths. ", 20) + "</current-working-directory></system-reminder>"
	part1 := "<system-reminder data-role=\"user-context\">\n<user_info>\nOS Version: win32\n</user_info>\n" +
		strings.Repeat("memory and skills reminder padding. ", 30) +
		"</system-reminder>\n<user_query>五年】</user_query>"
	userContent := part0 + "\n" + part1

	msgs := []ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "This conversation is powered by Auto. You are WorkBuddy."},
		{Role: "tool", Source: aimsg.SourceToolDef, Content: "[tool_def:Bash] Run a bash command."},
		{Role: "user", Source: aimsg.SourceUser, Content: userContent},
	}
	text := messagesToRetentionText(msgs)

	// 真实消息"五年】"必须出现在留证里（此前 position=0 完全缺失）。
	if !strings.Contains(text, "五年】") {
		t.Fatalf("真实用户消息'五年】'必须留证，实得:\n%s", text)
	}
	// 且在最前（对话在前、防 64KB 截断）。
	if !strings.HasPrefix(text, "五年】") {
		t.Fatalf("真实对话应在最前，实得开头: %q", text[:min(60, len(text))])
	}
	// 前端折叠后正文只剩真实消息，system-reminder 上下文/系统/工具都折掉。
	body, collapsed := simulateFrontendCollapse(text)
	if strings.TrimSpace(body) != "五年】" {
		t.Fatalf("展开正文应只剩'五年】'，实得 %q", body)
	}
	if collapsed < 3 {
		t.Fatalf("应折叠系统提示词+工具+user上下文（≥3段），实折 %d\n%s", collapsed, text)
	}
	// 折叠≠删除：system-reminder 上下文仍在全文可展开。
	if !strings.Contains(text, "OS Version: win32") {
		t.Fatal("system-reminder 上下文不应从留证消失（证据不减量）")
	}
}

// TestSplitUserQuery 直接验证 <user_query> 剥离：多轮、无标签回退、带属性。
func TestSplitUserQuery(t *testing.T) {
	q, rest := splitUserQuery("<system-reminder>ctx</system-reminder>\n<user_query>行</user_query>")
	if q != "行" {
		t.Fatalf("应剥出'行'，实得 %q", q)
	}
	if !strings.Contains(rest, "ctx") || strings.Contains(rest, "行") {
		t.Fatalf("rest 应含上下文、不含真实消息，实得 %q", rest)
	}
	// 多个 user_query（多轮）换行拼接。
	q2, _ := splitUserQuery("<user_query>问一</user_query>中间\n<user_query>问二</user_query>")
	if q2 != "问一\n问二" {
		t.Fatalf("多轮应拼接，实得 %q", q2)
	}
	// 无标签 → 空 query（调用方回退）。
	if q3, _ := splitUserQuery("just a normal message"); q3 != "" {
		t.Fatalf("无 user_query 应返回空，实得 %q", q3)
	}
	// 带属性的标签也能匹配。
	if q4, _ := splitUserQuery(`<user_query data-x="1">带属性</user_query>`); q4 != "带属性" {
		t.Fatalf("带属性标签应匹配，实得 %q", q4)
	}
}

// TestIsAgentMetaContentGuards 真实用户提问（短，或长但无 agent 特征）不误判为噪音。
func TestIsAgentMetaContentGuards(t *testing.T) {
	if isAgentMetaContent("行啊") {
		t.Fatal("短用户消息不该判为 agent-meta")
	}
	longReal := strings.Repeat("我想请你帮我分析一下这段业务代码的性能问题，具体是这样的场景。", 20)
	if isAgentMetaContent(longReal) {
		t.Fatal("长但无 agent 特征的真实提问不该判为 agent-meta")
	}
	if !isAgentMetaContent("You are Claude Code. " + strings.Repeat("x ", 300)) {
		t.Fatal("含 agent 特征的大段应判为 agent-meta")
	}
}

// TestMessagesToRetentionTextHandlesCRLF WorkBuddy(Windows)用 \r\n 换行，工具定义内部空行
// 必须归并成单段，否则前端按 \n\n 分段折叠会断在工具描述与 schema 之间（实测 653 行只折 7 段）。
func TestMessagesToRetentionTextHandlesCRLF(t *testing.T) {
	// 一个带 CRLF 内部空行的工具定义（描述 + 空行 + schema）。
	toolCRLF := "[tool_def:present_files] Present files to the user.\r\n\r\n- Local files are shown as cards.\r\n\r\n{\"type\":\"object\"}"
	msgs := []ConvMessage{
		{Role: "tool", Source: aimsg.SourceToolDef, Content: toolCRLF},
		{Role: "user", Source: aimsg.SourceUser, Content: "行啊"},
	}
	text := messagesToRetentionText(msgs)
	// 工具段归并为单段（无 \n\n 断裂）→ 前端只折 1 段，正文只剩"行啊"。
	body, collapsed := simulateFrontendCollapse(text)
	if collapsed != 1 {
		t.Fatalf("CRLF 工具段应归并成 1 段折叠，实折 %d\n%q", collapsed, text)
	}
	if strings.TrimSpace(body) != "行啊" {
		t.Fatalf("展开正文应只剩'行啊'，实得 %q", body)
	}
}

// TestMessagesToRetentionTextPlainConversation 纯对话（无系统/工具）不加前缀、不折叠。
func TestMessagesToRetentionTextPlainConversation(t *testing.T) {
	msgs := []ConvMessage{
		{Role: "user", Source: aimsg.SourceUser, Content: "好啊"},
		{Role: "assistant", Source: aimsg.SourceAssistantHistory, Content: "那我就当你这句好啊是暗号啦"},
	}
	text := messagesToRetentionText(msgs)
	if strings.Contains(text, "【系统】") || strings.Contains(text, "【工具】") {
		t.Fatalf("纯对话不应有角色前缀: %q", text)
	}
	_, collapsed := simulateFrontendCollapse(text)
	if collapsed != 0 {
		t.Fatalf("纯对话不应折叠，实折 %d", collapsed)
	}
}

// TestBuildAccessContentLogUsesStructuredWhenMessages 有 Messages 时留证走结构化渲染 + v3
// （v3 = v2 之上补了工具轮【工具】段与 tool_call_metadata_json）。
func TestBuildAccessContentLogUsesStructuredWhenMessages(t *testing.T) {
	req := ExtractedContent{
		Text: "You are WorkBuddy...\n真的吗", // 旧平铺（不该被用）
		Messages: []ConvMessage{
			{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "You are WorkBuddy agent big prompt"},
			{Role: "user", Source: aimsg.SourceUser, Content: "真的吗"},
		},
	}
	payload, ok := buildAccessContentLogPayload(ProxyAuditRecord{RequestID: "r1", TenantID: "t1", Provider: "tencent", Product: "codebuddy", ContentRetained: true, RetentionLevel: "content"}, req, ExtractedContent{})
	if !ok {
		t.Fatal("应产出留证 payload")
	}
	if payload.DecoderVersion != "v3" {
		t.Fatalf("有 Messages 应标 decoder_version=v3，实得 %q", payload.DecoderVersion)
	}
	if payload.RequestContentRedacted != "真的吗" {
		t.Fatalf("客户留证只能保留当前真实用户输入，实得 %q", payload.RequestContentRedacted)
	}
	if strings.Contains(payload.RequestContentRedacted, "WorkBuddy") || strings.Contains(payload.RequestContentRedacted, "【系统】") {
		t.Fatalf("客户留证不得包含系统提示词: %q", payload.RequestContentRedacted)
	}
}

func TestInferStructuredAgentTypeUsesSystemPromptOnly(t *testing.T) {
	messages := []ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "You are Cline, an autonomous coding agent."},
		{Role: "user", Source: aimsg.SourceUser, Content: "普通用户问题"},
	}
	if got := inferStructuredAgentType(messages); got != "cline" {
		t.Fatalf("structured system prompt should identify Cline, got %q", got)
	}

	userOnly := []ConvMessage{{Role: "user", Source: aimsg.SourceUser, Content: "请解释 Cline 是什么"}}
	if got := inferStructuredAgentType(userOnly); got != "" {
		t.Fatalf("user text must not spoof agent identity, got %q", got)
	}

	declinePolicy := []ConvMessage{{
		Role: "system", Source: aimsg.SourceSystemPrompt,
		Content: "You must decline unsafe requests.",
	}}
	if got := inferStructuredAgentType(declinePolicy); got != "" {
		t.Fatalf("substring in system prose must not identify Cline, got %q", got)
	}
}
